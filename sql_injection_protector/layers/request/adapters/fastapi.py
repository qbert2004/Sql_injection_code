"""FastAPI middleware adapter."""

from typing import Any, Callable, Optional
from urllib.parse import parse_qs

from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Decision
from sql_injection_protector.layers.request.context import RequestContext
from sql_injection_protector.layers.request.adapters.base import MiddlewareBase


class SQLIProtectorMiddleware(MiddlewareBase):
    """
    FastAPI/Starlette middleware for SQL injection protection.

    Usage:
        from fastapi import FastAPI
        from sql_injection_protector.layers.request.adapters.fastapi import SQLIProtectorMiddleware

        app = FastAPI()
        app.add_middleware(SQLIProtectorMiddleware, config=config)
    """

    def __init__(
        self,
        app: Any,
        config: Optional[Settings] = None,
        exclude_paths: Optional[list[str]] = None,
        exclude_methods: Optional[list[str]] = None,
        on_block: Optional[Callable] = None,
        on_allow: Optional[Callable] = None,
    ):
        """
        Initialize FastAPI middleware.

        Args:
            app: FastAPI/Starlette application
            config: Application settings
            exclude_paths: Paths to exclude (supports wildcards)
            exclude_methods: HTTP methods to exclude
            on_block: Callback when request is blocked
            on_allow: Callback when request is allowed
        """
        super().__init__(
            app=app,
            config=config,
            exclude_paths=exclude_paths,
            exclude_methods=exclude_methods,
            on_block=on_block,
            on_allow=on_allow,
        )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if should skip
        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        if self.should_skip(path, method):
            await self.app(scope, receive, send)
            return

        # Extract context and process
        context = await self._extract_from_scope(scope, receive)
        should_continue, response, context, decision = await self.process_request_from_context(context)

        if not should_continue and response:
            await self._send_response(send, response)
            return

        await self.app(scope, receive, send)

    async def _extract_from_scope(self, scope: dict, receive: Callable) -> RequestContext:
        """Extract RequestContext from ASGI scope."""
        # Get headers
        headers = {}
        for key, value in scope.get("headers", []):
            headers[key.decode("latin-1")] = value.decode("latin-1")

        # Get query params
        query_string = scope.get("query_string", b"").decode("utf-8")
        query_params = {}
        if query_string:
            for key, values in parse_qs(query_string).items():
                query_params[key] = values[0] if len(values) == 1 else values

        # Get client info
        client = scope.get("client", ("", 0))
        client_ip = self.get_client_ip(headers, client[0] if client else "")
        client_port = client[1] if client else 0

        # Read body
        body = b""
        body_text = ""
        if scope.get("method", "GET") in ("POST", "PUT", "PATCH"):
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

        return RequestContext(
            client_ip=client_ip,
            client_port=client_port,
            user_agent=headers.get("user-agent", ""),
            method=scope.get("method", "GET"),
            path=scope.get("path", "/"),
            full_url=f"{scope.get('scheme', 'http')}://{headers.get('host', 'localhost')}{scope.get('path', '/')}",
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

    async def process_request_from_context(
        self,
        context: RequestContext,
    ) -> tuple[bool, Optional[dict], RequestContext, Optional[Decision]]:
        """Process request using pre-extracted context."""
        # Get agent
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self.config)
            await self._agent.initialize()

        # Analyze
        decision = await self._agent.analyze_request(context)

        # Handle decision
        if decision.should_block():
            response = {
                "status_code": decision.response_code,
                "body": decision.response_body or "Request blocked",
                "headers": decision.response_headers,
            }
            if self.on_block:
                self.on_block(context, decision)
            return False, response, context, decision

        if decision.should_challenge():
            response = {
                "status_code": decision.response_code,
                "body": decision.response_body or "Challenge required",
                "headers": decision.response_headers,
            }
            return False, response, context, decision

        if self.on_allow:
            self.on_allow(context, decision)

        return True, None, context, decision

    async def _send_response(self, send: Callable, response: dict) -> None:
        """Send HTTP response."""
        status_code = response.get("status_code", 403)
        body = response.get("body", "").encode("utf-8")
        headers = response.get("headers", {})

        # Build headers
        header_list = [
            (b"content-type", headers.get("Content-Type", "text/html").encode()),
            (b"content-length", str(len(body)).encode()),
        ]
        for key, value in headers.items():
            if key.lower() not in ("content-type", "content-length"):
                header_list.append((key.lower().encode(), value.encode()))

        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": header_list,
        })

        await send({
            "type": "http.response.body",
            "body": body,
        })

    async def extract_context(self, request: Any) -> RequestContext:
        """Extract context from FastAPI Request object."""
        # For direct Request object usage
        headers = dict(request.headers)
        client = request.client

        query_params = dict(request.query_params)

        body = b""
        body_text = ""
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            body_text = body.decode("utf-8", errors="ignore")

        cookies = dict(request.cookies)

        return RequestContext(
            client_ip=self.get_client_ip(headers, client.host if client else ""),
            client_port=client.port if client else 0,
            user_agent=headers.get("user-agent", ""),
            method=request.method,
            path=request.url.path,
            full_url=str(request.url),
            headers=headers,
            query_params=query_params,
            query_string=str(request.url.query),
            body=body,
            body_text=body_text,
            content_type=headers.get("content-type", ""),
            cookies=cookies,
        )

    async def create_blocked_response(
        self,
        decision: Decision,
        context: RequestContext,
    ) -> Any:
        """Create FastAPI Response for blocked request."""
        from starlette.responses import HTMLResponse

        return HTMLResponse(
            content=decision.response_body or "Request blocked",
            status_code=decision.response_code,
            headers=decision.response_headers,
        )

    async def create_challenge_response(
        self,
        decision: Decision,
        context: RequestContext,
    ) -> Any:
        """Create FastAPI Response for challenge."""
        from starlette.responses import HTMLResponse

        return HTMLResponse(
            content=decision.response_body or "Challenge required",
            status_code=decision.response_code,
            headers=decision.response_headers,
        )


def create_middleware(
    config: Optional[Settings] = None,
    **kwargs,
) -> type:
    """
    Factory function to create configured middleware class.

    Usage:
        middleware_class = create_middleware(config=my_config)
        app.add_middleware(middleware_class)
    """

    class ConfiguredMiddleware(SQLIProtectorMiddleware):
        def __init__(self, app: Any):
            super().__init__(app, config=config, **kwargs)

    return ConfiguredMiddleware
