"""Pure ASGI adapter for SQL injection protection."""

from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Decision
from sql_injection_protector.layers.request.context import RequestContext


class ASGIProtector:
    """
    Pure ASGI middleware for SQL injection protection.

    Usage:
        from sql_injection_protector.layers.request.adapters.asgi import wrap_asgi

        # Wrap any ASGI application
        protected_app = wrap_asgi(app, config=config)
    """

    def __init__(
        self,
        app: Callable,
        config: Optional[Settings] = None,
        exclude_paths: Optional[List[str]] = None,
        exclude_methods: Optional[List[str]] = None,
    ):
        """
        Initialize ASGI protector.

        Args:
            app: ASGI application to wrap
            config: Application settings
            exclude_paths: Paths to exclude from protection
            exclude_methods: HTTP methods to exclude
        """
        self.app = app
        self.config = config
        self.exclude_paths = exclude_paths or []
        self.exclude_methods = exclude_methods or ["OPTIONS"]
        self._agent = None

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable,
        send: Callable,
    ) -> None:
        """ASGI interface."""
        # Only handle HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if should skip
        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        if self._should_skip(path, method):
            await self.app(scope, receive, send)
            return

        # Process request
        try:
            should_continue, response_data = await self._process_request(scope, receive)

            if not should_continue and response_data:
                await self._send_response(send, response_data)
                return

        except Exception as e:
            # Fail open on error
            import logging
            logging.getLogger(__name__).error(f"SQLi protection error: {e}")

        await self.app(scope, receive, send)

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

    async def _process_request(
        self,
        scope: Dict[str, Any],
        receive: Callable,
    ) -> Tuple[bool, Optional[Dict]]:
        """Process request."""
        # Initialize agent
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self.config)
            await self._agent.initialize()

        # Extract context
        context = await self._extract_context(scope, receive)

        # Analyze
        decision = await self._agent.analyze_request(context)

        # Handle decision
        if decision.should_block():
            return False, {
                "status": decision.response_code,
                "headers": decision.response_headers,
                "body": (decision.response_body or "Request blocked").encode("utf-8"),
            }

        if decision.should_challenge():
            return False, {
                "status": decision.response_code,
                "headers": decision.response_headers,
                "body": (decision.response_body or "Challenge required").encode("utf-8"),
            }

        return True, None

    async def _extract_context(
        self,
        scope: Dict[str, Any],
        receive: Callable,
    ) -> RequestContext:
        """Extract RequestContext from ASGI scope."""
        # Get headers
        headers = {}
        for key, value in scope.get("headers", []):
            headers[key.decode("latin-1")] = value.decode("latin-1")

        # Get client info
        client = scope.get("client", ("", 0))
        client_ip = self._get_client_ip(headers, client[0] if client else "")
        client_port = client[1] if client else 0

        # Get query params
        query_string = scope.get("query_string", b"").decode("utf-8")
        query_params = {}
        if query_string:
            for key, values in parse_qs(query_string).items():
                query_params[key] = values[0] if len(values) == 1 else values

        # Get body
        body = b""
        body_text = ""
        method = scope.get("method", "GET")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            body = await self._read_body(receive)
            body_text = body.decode("utf-8", errors="ignore")

        # Get cookies
        cookies = {}
        cookie_header = headers.get("cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                if "=" in part:
                    key, value = part.strip().split("=", 1)
                    cookies[key] = value

        # Build URL
        scheme = scope.get("scheme", "http")
        host = headers.get("host", "localhost")
        path = scope.get("path", "/")
        full_url = f"{scheme}://{host}{path}"
        if query_string:
            full_url += f"?{query_string}"

        return RequestContext(
            client_ip=client_ip,
            client_port=client_port,
            user_agent=headers.get("user-agent", ""),
            method=method,
            path=path,
            full_url=full_url,
            protocol=f"HTTP/{scope.get('http_version', '1.1')}",
            headers=headers,
            query_params=query_params,
            query_string=query_string,
            body=body,
            body_text=body_text,
            content_type=headers.get("content-type", ""),
            cookies=cookies,
        )

    async def _read_body(self, receive: Callable) -> bytes:
        """Read request body."""
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        return body

    def _get_client_ip(self, headers: Dict[str, str], default: str) -> str:
        """Get client IP from headers."""
        for header in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
            value = headers.get(header)
            if value:
                return value.split(",")[0].strip()
        return default

    async def _send_response(self, send: Callable, response_data: Dict) -> None:
        """Send HTTP response."""
        status = response_data.get("status", 403)
        body = response_data.get("body", b"")
        headers_dict = response_data.get("headers", {})

        # Build headers
        headers = [
            (b"content-type", headers_dict.get("Content-Type", "text/html").encode()),
            (b"content-length", str(len(body)).encode()),
        ]

        for key, value in headers_dict.items():
            if key.lower() not in ("content-type", "content-length"):
                headers.append((key.lower().encode(), str(value).encode()))

        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })

        await send({
            "type": "http.response.body",
            "body": body,
        })


def wrap_asgi(
    app: Callable,
    config: Optional[Settings] = None,
    **kwargs,
) -> ASGIProtector:
    """
    Wrap an ASGI application with SQL injection protection.

    Args:
        app: ASGI application to wrap
        config: Application settings
        **kwargs: Additional arguments for ASGIProtector

    Returns:
        Protected ASGI application
    """
    return ASGIProtector(app, config=config, **kwargs)


# Compatibility alias
SQLInjectionASGIMiddleware = ASGIProtector
