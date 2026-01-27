"""Django middleware adapter."""

import asyncio
from typing import Any, Callable, Optional

from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Decision
from sql_injection_protector.layers.request.context import RequestContext
from sql_injection_protector.layers.request.adapters.base import MiddlewareBase


class SQLIProtectorMiddleware:
    """
    Django middleware for SQL injection protection.

    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'sql_injection_protector.layers.request.adapters.django.SQLIProtectorMiddleware',
            ...
        ]

    Configuration via Django settings:
        SQLI_PROTECTOR_CONFIG = {
            'exclude_paths': ['/admin/*', '/static/*'],
            'exclude_methods': ['OPTIONS'],
        }
    """

    def __init__(self, get_response: Callable):
        """
        Initialize Django middleware.

        Args:
            get_response: Django's get_response callable
        """
        self.get_response = get_response
        self._agent = None
        self._config = None
        self._exclude_paths = []
        self._exclude_methods = []

        # Load configuration from Django settings
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from Django settings."""
        try:
            from django.conf import settings as django_settings

            config_dict = getattr(django_settings, "SQLI_PROTECTOR_CONFIG", {})

            self._exclude_paths = config_dict.get("exclude_paths", [])
            self._exclude_methods = config_dict.get("exclude_methods", [])

            # Load full config if provided
            if "config" in config_dict:
                from sql_injection_protector.core.config import load_config
                self._config = load_config(config_dict["config"])

        except Exception:
            pass

    def __call__(self, request: Any) -> Any:
        """
        Process the request.

        Django middleware is synchronous by default.
        We run async code in a new event loop.
        """
        # Check if should skip
        if self._should_skip(request):
            return self.get_response(request)

        # Run async processing
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                should_continue, response = loop.run_until_complete(
                    self._process_request(request)
                )
            finally:
                loop.close()

            if not should_continue:
                return response

        except Exception as e:
            # On error, allow request through (fail open)
            import logging
            logging.getLogger(__name__).error(f"SQLi protection error: {e}")

        return self.get_response(request)

    def _should_skip(self, request: Any) -> bool:
        """Check if request should skip protection."""
        # Check excluded methods
        if request.method in self._exclude_methods:
            return True

        # Check excluded paths
        path = request.path
        for excluded in self._exclude_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True

        return False

    async def _process_request(self, request: Any) -> tuple[bool, Any]:
        """Process request asynchronously."""
        # Initialize agent
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self._config)
            await self._agent.initialize()

        # Extract context
        context = self._extract_context(request)

        # Analyze
        decision = await self._agent.analyze_request(context)

        # Handle decision
        if decision.should_block():
            return False, self._create_blocked_response(decision)

        if decision.should_challenge():
            return False, self._create_challenge_response(decision)

        return True, None

    def _extract_context(self, request: Any) -> RequestContext:
        """Extract RequestContext from Django request."""
        # Get headers
        headers = {}
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                # Convert HTTP_CONTENT_TYPE to Content-Type
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[key.replace("_", "-").title()] = value

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Get query params
        query_params = dict(request.GET)
        # Flatten single-value lists
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

        # Get body
        body = request.body
        body_text = body.decode("utf-8", errors="ignore") if body else ""

        # Get cookies
        cookies = dict(request.COOKIES)

        return RequestContext(
            client_ip=client_ip,
            client_port=0,
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            method=request.method,
            path=request.path,
            full_url=request.build_absolute_uri(),
            protocol=f"HTTP/{request.META.get('SERVER_PROTOCOL', '1.1').split('/')[-1]}",
            headers=headers,
            query_params=query_params,
            query_string=request.META.get("QUERY_STRING", ""),
            body=body,
            body_text=body_text,
            content_type=request.content_type or "",
            cookies=cookies,
            session_id=request.session.session_key if hasattr(request, "session") else None,
            user_id=str(request.user.id) if hasattr(request, "user") and request.user.is_authenticated else None,
        )

    def _get_client_ip(self, request: Any) -> str:
        """Get client IP from Django request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()

        x_real_ip = request.META.get("HTTP_X_REAL_IP")
        if x_real_ip:
            return x_real_ip

        return request.META.get("REMOTE_ADDR", "")

    def _create_blocked_response(self, decision: Decision) -> Any:
        """Create Django HttpResponse for blocked request."""
        from django.http import HttpResponse

        response = HttpResponse(
            content=decision.response_body or "Request blocked",
            status=decision.response_code,
            content_type=decision.response_headers.get("Content-Type", "text/html"),
        )

        for key, value in decision.response_headers.items():
            if key.lower() != "content-type":
                response[key] = value

        return response

    def _create_challenge_response(self, decision: Decision) -> Any:
        """Create Django HttpResponse for challenge."""
        from django.http import HttpResponse

        response = HttpResponse(
            content=decision.response_body or "Challenge required",
            status=decision.response_code,
            content_type=decision.response_headers.get("Content-Type", "text/html"),
        )

        for key, value in decision.response_headers.items():
            if key.lower() != "content-type":
                response[key] = value

        return response


class AsyncSQLIProtectorMiddleware:
    """
    Async Django middleware for SQL injection protection.

    For Django 3.1+ with ASGI.

    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'sql_injection_protector.layers.request.adapters.django.AsyncSQLIProtectorMiddleware',
            ...
        ]
    """

    async_capable = True
    sync_capable = False

    def __init__(self, get_response: Callable):
        """Initialize async middleware."""
        self.get_response = get_response
        self._agent = None
        self._config = None
        self._exclude_paths = []
        self._exclude_methods = []
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from Django settings."""
        try:
            from django.conf import settings as django_settings

            config_dict = getattr(django_settings, "SQLI_PROTECTOR_CONFIG", {})
            self._exclude_paths = config_dict.get("exclude_paths", [])
            self._exclude_methods = config_dict.get("exclude_methods", [])

            if "config" in config_dict:
                from sql_injection_protector.core.config import load_config
                self._config = load_config(config_dict["config"])

        except Exception:
            pass

    async def __call__(self, request: Any) -> Any:
        """Process the request asynchronously."""
        # Check if should skip
        if self._should_skip(request):
            return await self.get_response(request)

        try:
            should_continue, response = await self._process_request(request)

            if not should_continue:
                return response

        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"SQLi protection error: {e}")

        return await self.get_response(request)

    def _should_skip(self, request: Any) -> bool:
        """Check if request should skip protection."""
        if request.method in self._exclude_methods:
            return True

        path = request.path
        for excluded in self._exclude_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True

        return False

    async def _process_request(self, request: Any) -> tuple[bool, Any]:
        """Process request."""
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self._config)
            await self._agent.initialize()

        context = await self._extract_context(request)
        decision = await self._agent.analyze_request(context)

        if decision.should_block():
            return False, self._create_blocked_response(decision)

        if decision.should_challenge():
            return False, self._create_challenge_response(decision)

        return True, None

    async def _extract_context(self, request: Any) -> RequestContext:
        """Extract RequestContext from async Django request."""
        # Similar to sync version but can await body
        headers = {}
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value

        client_ip = self._get_client_ip(request)
        query_params = {k: v[0] if len(v) == 1 else v for k, v in dict(request.GET).items()}

        body = request.body
        body_text = body.decode("utf-8", errors="ignore") if body else ""

        return RequestContext(
            client_ip=client_ip,
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            method=request.method,
            path=request.path,
            full_url=request.build_absolute_uri(),
            headers=headers,
            query_params=query_params,
            query_string=request.META.get("QUERY_STRING", ""),
            body=body,
            body_text=body_text,
            cookies=dict(request.COOKIES),
        )

    def _get_client_ip(self, request: Any) -> str:
        """Get client IP."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")

    def _create_blocked_response(self, decision: Decision) -> Any:
        """Create blocked response."""
        from django.http import HttpResponse
        return HttpResponse(
            content=decision.response_body or "Request blocked",
            status=decision.response_code,
        )

    def _create_challenge_response(self, decision: Decision) -> Any:
        """Create challenge response."""
        from django.http import HttpResponse
        return HttpResponse(
            content=decision.response_body or "Challenge required",
            status=decision.response_code,
        )
