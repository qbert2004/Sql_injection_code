"""Pure WSGI adapter for SQL injection protection."""

import asyncio
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs

from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Decision
from sql_injection_protector.layers.request.context import RequestContext


class WSGIProtector:
    """
    Pure WSGI middleware for SQL injection protection.

    Usage:
        from sql_injection_protector.layers.request.adapters.wsgi import wrap_wsgi

        # Wrap any WSGI application
        protected_app = wrap_wsgi(app, config=config)
    """

    def __init__(
        self,
        app: Callable,
        config: Optional[Settings] = None,
        exclude_paths: Optional[List[str]] = None,
        exclude_methods: Optional[List[str]] = None,
    ):
        """
        Initialize WSGI protector.

        Args:
            app: WSGI application to wrap
            config: Application settings
            exclude_paths: Paths to exclude from protection
            exclude_methods: HTTP methods to exclude
        """
        self.app = app
        self.config = config
        self.exclude_paths = exclude_paths or []
        self.exclude_methods = exclude_methods or ["OPTIONS"]
        self._agent = None
        self._loop = None

    def __call__(
        self,
        environ: Dict[str, Any],
        start_response: Callable,
    ) -> Iterable[bytes]:
        """WSGI interface."""
        # Check if should skip
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")

        if self._should_skip(path, method):
            return self.app(environ, start_response)

        # Run async processing
        try:
            should_continue, response_data = self._run_async(
                self._process_request(environ)
            )

            if not should_continue and response_data:
                return self._send_response(
                    start_response,
                    response_data["status"],
                    response_data["headers"],
                    response_data["body"],
                )

        except Exception as e:
            # Fail open on error
            import logging
            logging.getLogger(__name__).error(f"SQLi protection error: {e}")

        return self.app(environ, start_response)

    def _should_skip(self, path: str, method: str) -> bool:
        """Check if request should skip protection."""
        if method.upper() in [m.upper() for m in self.exclude_methods]:
            return True

        for excluded in self.exclude_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True

        return False

    def _run_async(self, coro: Any) -> Any:
        """Run async code in sync context."""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()

        return self._loop.run_until_complete(coro)

    async def _process_request(self, environ: Dict[str, Any]) -> Tuple[bool, Optional[Dict]]:
        """Process request asynchronously."""
        # Initialize agent
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self.config)
            await self._agent.initialize()

        # Extract context
        context = self._extract_context(environ)

        # Analyze
        decision = await self._agent.analyze_request(context)

        # Handle decision
        if decision.should_block():
            return False, {
                "status": f"{decision.response_code} Forbidden",
                "headers": list(decision.response_headers.items()),
                "body": (decision.response_body or "Request blocked").encode("utf-8"),
            }

        if decision.should_challenge():
            return False, {
                "status": f"{decision.response_code} Too Many Requests",
                "headers": list(decision.response_headers.items()),
                "body": (decision.response_body or "Challenge required").encode("utf-8"),
            }

        return True, None

    def _extract_context(self, environ: Dict[str, Any]) -> RequestContext:
        """Extract RequestContext from WSGI environ."""
        # Get headers
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[key.replace("_", "-").title()] = value

        # Get client IP
        client_ip = self._get_client_ip(environ, headers)

        # Get query params
        query_string = environ.get("QUERY_STRING", "")
        query_params = {}
        if query_string:
            for key, values in parse_qs(query_string).items():
                query_params[key] = values[0] if len(values) == 1 else values

        # Get body
        body = b""
        body_text = ""
        content_length = environ.get("CONTENT_LENGTH")
        if content_length:
            try:
                length = int(content_length)
                body = environ["wsgi.input"].read(length)
                body_text = body.decode("utf-8", errors="ignore")
            except (ValueError, TypeError):
                pass

        # Get cookies
        cookies = {}
        cookie_header = environ.get("HTTP_COOKIE", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    cookies[key] = value

        # Build URL
        scheme = environ.get("wsgi.url_scheme", "http")
        host = environ.get("HTTP_HOST", environ.get("SERVER_NAME", "localhost"))
        path = environ.get("PATH_INFO", "/")
        full_url = f"{scheme}://{host}{path}"
        if query_string:
            full_url += f"?{query_string}"

        return RequestContext(
            client_ip=client_ip,
            client_port=int(environ.get("REMOTE_PORT", 0) or 0),
            user_agent=environ.get("HTTP_USER_AGENT", ""),
            method=environ.get("REQUEST_METHOD", "GET"),
            path=path,
            full_url=full_url,
            protocol=environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            headers=headers,
            query_params=query_params,
            query_string=query_string,
            body=body,
            body_text=body_text,
            content_type=environ.get("CONTENT_TYPE", ""),
            cookies=cookies,
        )

    def _get_client_ip(self, environ: Dict[str, Any], headers: Dict[str, str]) -> str:
        """Get client IP from environ/headers."""
        # Check proxy headers
        for header in ["X-Forwarded-For", "X-Real-Ip"]:
            value = headers.get(header)
            if value:
                return value.split(",")[0].strip()

        return environ.get("REMOTE_ADDR", "")

    def _send_response(
        self,
        start_response: Callable,
        status: str,
        headers: List[Tuple[str, str]],
        body: bytes,
    ) -> Iterable[bytes]:
        """Send HTTP response."""
        # Ensure Content-Type and Content-Length are present
        header_dict = dict(headers)
        if "Content-Type" not in header_dict:
            headers.append(("Content-Type", "text/html; charset=utf-8"))
        if "Content-Length" not in header_dict:
            headers.append(("Content-Length", str(len(body))))

        start_response(status, headers)
        return [body]


def wrap_wsgi(
    app: Callable,
    config: Optional[Settings] = None,
    **kwargs,
) -> WSGIProtector:
    """
    Wrap a WSGI application with SQL injection protection.

    Args:
        app: WSGI application to wrap
        config: Application settings
        **kwargs: Additional arguments for WSGIProtector

    Returns:
        Protected WSGI application
    """
    return WSGIProtector(app, config=config, **kwargs)


# Compatibility alias
SQLInjectionWSGIMiddleware = WSGIProtector
