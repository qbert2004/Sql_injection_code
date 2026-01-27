"""API Gateway - Entry point for request processing."""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from sql_injection_protector.core.agent import SQLInjectionAgent
from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Action, Decision
from sql_injection_protector.layers.request.context import RequestContext


logger = logging.getLogger(__name__)


class APIGateway:
    """
    API Gateway for SQL Injection Protection.

    Acts as the entry point for all request processing, coordinating
    between the protection agent and the application.

    Features:
    - Request interception and analysis
    - Path-based exclusions
    - Method-based exclusions
    - Configurable callbacks for block/allow events
    - Health check endpoints
    - Metrics endpoints

    Usage:
        gateway = APIGateway(config=settings)
        await gateway.initialize()

        # In your middleware
        decision = await gateway.process_request(context)
        if decision.should_block():
            return blocked_response
    """

    def __init__(
        self,
        config: Optional[Settings] = None,
        agent: Optional[SQLInjectionAgent] = None,
        exclude_paths: Optional[List[str]] = None,
        exclude_methods: Optional[List[str]] = None,
        on_block: Optional[Callable[[RequestContext, Decision], Any]] = None,
        on_allow: Optional[Callable[[RequestContext, Decision], Any]] = None,
        on_challenge: Optional[Callable[[RequestContext, Decision], Any]] = None,
        on_error: Optional[Callable[[RequestContext, Exception], Any]] = None,
    ):
        """
        Initialize API Gateway.

        Args:
            config: Application settings
            agent: Pre-configured agent (optional)
            exclude_paths: Paths to exclude from protection
            exclude_methods: HTTP methods to exclude
            on_block: Callback when request is blocked
            on_allow: Callback when request is allowed
            on_challenge: Callback when challenge is required
            on_error: Callback when error occurs
        """
        self.config = config or Settings()
        self._agent = agent
        self.exclude_paths = exclude_paths or []
        self.exclude_methods = exclude_methods or ["OPTIONS"]

        # Callbacks
        self.on_block = on_block
        self.on_allow = on_allow
        self.on_challenge = on_challenge
        self.on_error = on_error

        self._initialized = False

        # Built-in exclusions
        self._builtin_exclude_paths = [
            "/health",
            "/healthz",
            "/ready",
            "/readyz",
            "/live",
            "/livez",
            "/metrics",
            "/favicon.ico",
        ]

    async def initialize(self) -> None:
        """Initialize the gateway and agent."""
        if self._initialized:
            return

        logger.info("Initializing API Gateway...")

        # Initialize agent
        if self._agent is None:
            self._agent = SQLInjectionAgent(settings=self.config)

        await self._agent.initialize()

        self._initialized = True
        logger.info("API Gateway initialized")

    async def process_request(
        self,
        context: RequestContext,
    ) -> Decision:
        """
        Process an incoming request.

        Args:
            context: Request context

        Returns:
            Decision with action to take
        """
        if not self._initialized:
            await self.initialize()

        try:
            # Check exclusions
            if self._should_skip(context):
                return Decision(
                    action=Action.ALLOW,
                    confidence=1.0,
                    reason="Excluded path or method",
                )

            # Analyze request
            decision = await self._agent.analyze_request(context)

            # Execute callbacks
            await self._execute_callbacks(context, decision)

            return decision

        except Exception as e:
            logger.error(f"Gateway error: {e}")

            if self.on_error:
                try:
                    await self._safe_callback(self.on_error, context, e)
                except Exception as callback_error:
                    logger.error(f"Error callback failed: {callback_error}")

            # Fail open
            return Decision(
                action=Action.ALLOW,
                confidence=0.0,
                reason=f"Gateway error: {e}",
            )

    def _should_skip(self, context: RequestContext) -> bool:
        """Check if request should skip protection."""
        # Check method exclusions
        if context.method.upper() in [m.upper() for m in self.exclude_methods]:
            return True

        path = context.path

        # Check built-in exclusions
        for excluded in self._builtin_exclude_paths:
            if path == excluded or path.startswith(excluded + "/"):
                return True

        # Check configured exclusions
        for excluded in self.exclude_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif excluded.endswith("**"):
                prefix = excluded[:-2]
                if path.startswith(prefix):
                    return True
            elif path == excluded:
                return True

        return False

    async def _execute_callbacks(
        self,
        context: RequestContext,
        decision: Decision,
    ) -> None:
        """Execute appropriate callbacks based on decision."""
        try:
            if decision.action == Action.BLOCK and self.on_block:
                await self._safe_callback(self.on_block, context, decision)
            elif decision.action == Action.CHALLENGE and self.on_challenge:
                await self._safe_callback(self.on_challenge, context, decision)
            elif decision.action == Action.ALLOW and self.on_allow:
                await self._safe_callback(self.on_allow, context, decision)
        except Exception as e:
            logger.error(f"Callback error: {e}")

    async def _safe_callback(
        self,
        callback: Callable,
        *args,
        **kwargs,
    ) -> Any:
        """Safely execute a callback (sync or async)."""
        if asyncio.iscoroutinefunction(callback):
            return await callback(*args, **kwargs)
        else:
            return callback(*args, **kwargs)

    async def shutdown(self) -> None:
        """Shutdown the gateway."""
        logger.info("Shutting down API Gateway...")

        if self._agent:
            await self._agent.shutdown()

        self._initialized = False
        logger.info("API Gateway shutdown complete")


class GatewayBuilder:
    """
    Builder for API Gateway configuration.

    Usage:
        gateway = (
            GatewayBuilder()
            .with_config(settings)
            .exclude_paths(["/static/*", "/public/*"])
            .exclude_methods(["OPTIONS", "HEAD"])
            .on_block(lambda ctx, dec: log_blocked(ctx))
            .build()
        )
    """

    def __init__(self):
        self._config: Optional[Settings] = None
        self._agent: Optional[SQLInjectionAgent] = None
        self._exclude_paths: List[str] = []
        self._exclude_methods: List[str] = ["OPTIONS"]
        self._on_block: Optional[Callable] = None
        self._on_allow: Optional[Callable] = None
        self._on_challenge: Optional[Callable] = None
        self._on_error: Optional[Callable] = None

    def with_config(self, config: Settings) -> "GatewayBuilder":
        """Set configuration."""
        self._config = config
        return self

    def with_agent(self, agent: SQLInjectionAgent) -> "GatewayBuilder":
        """Set pre-configured agent."""
        self._agent = agent
        return self

    def exclude_paths(self, paths: List[str]) -> "GatewayBuilder":
        """Add paths to exclude."""
        self._exclude_paths.extend(paths)
        return self

    def exclude_methods(self, methods: List[str]) -> "GatewayBuilder":
        """Set methods to exclude."""
        self._exclude_methods = methods
        return self

    def on_block(self, callback: Callable) -> "GatewayBuilder":
        """Set block callback."""
        self._on_block = callback
        return self

    def on_allow(self, callback: Callable) -> "GatewayBuilder":
        """Set allow callback."""
        self._on_allow = callback
        return self

    def on_challenge(self, callback: Callable) -> "GatewayBuilder":
        """Set challenge callback."""
        self._on_challenge = callback
        return self

    def on_error(self, callback: Callable) -> "GatewayBuilder":
        """Set error callback."""
        self._on_error = callback
        return self

    def build(self) -> APIGateway:
        """Build the gateway."""
        return APIGateway(
            config=self._config,
            agent=self._agent,
            exclude_paths=self._exclude_paths,
            exclude_methods=self._exclude_methods,
            on_block=self._on_block,
            on_allow=self._on_allow,
            on_challenge=self._on_challenge,
            on_error=self._on_error,
        )


class ProtectionProxy:
    """
    Protection proxy for wrapping application endpoints.

    Provides a decorator-based approach to protection.

    Usage:
        proxy = ProtectionProxy(gateway)

        @proxy.protect
        async def my_endpoint(request):
            return {"data": "value"}

        # Or with custom options
        @proxy.protect(sanitize=True, log_allowed=True)
        async def another_endpoint(request):
            return {"data": "value"}
    """

    def __init__(self, gateway: APIGateway):
        self.gateway = gateway

    def protect(
        self,
        func: Optional[Callable] = None,
        *,
        sanitize: bool = False,
        log_allowed: bool = False,
        custom_block_response: Optional[Callable] = None,
    ):
        """
        Decorator to protect an endpoint.

        Args:
            func: Function to protect
            sanitize: Whether to sanitize inputs instead of blocking
            log_allowed: Whether to log allowed requests
            custom_block_response: Custom response generator for blocks
        """
        def decorator(f: Callable) -> Callable:
            async def wrapper(*args, **kwargs):
                # Extract request context from args
                context = self._extract_context(args, kwargs)

                if context:
                    decision = await self.gateway.process_request(context)

                    if decision.should_block():
                        if custom_block_response:
                            return custom_block_response(context, decision)
                        raise BlockedRequestError(decision)

                    if decision.should_challenge():
                        raise ChallengeRequiredError(decision)

                    if log_allowed and logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Allowed: {context.path}")

                return await f(*args, **kwargs)

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    def _extract_context(
        self,
        args: tuple,
        kwargs: dict,
    ) -> Optional[RequestContext]:
        """Extract RequestContext from function arguments."""
        # Check for explicit context
        if "context" in kwargs:
            ctx = kwargs["context"]
            if isinstance(ctx, RequestContext):
                return ctx

        # Check for request object (FastAPI/Starlette)
        if "request" in kwargs:
            return self._context_from_request(kwargs["request"])

        # Check positional args
        for arg in args:
            if isinstance(arg, RequestContext):
                return arg
            if hasattr(arg, "url") and hasattr(arg, "method"):
                return self._context_from_request(arg)

        return None

    def _context_from_request(self, request: Any) -> Optional[RequestContext]:
        """Convert a request object to RequestContext."""
        try:
            return RequestContext(
                client_ip=getattr(request.client, "host", "") if hasattr(request, "client") else "",
                method=request.method,
                path=str(request.url.path) if hasattr(request.url, "path") else str(request.url),
                full_url=str(request.url),
                headers=dict(request.headers) if hasattr(request, "headers") else {},
                query_params=dict(request.query_params) if hasattr(request, "query_params") else {},
            )
        except Exception as e:
            logger.warning(f"Failed to extract context: {e}")
            return None


class BlockedRequestError(Exception):
    """Raised when a request is blocked."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Request blocked: {decision.reason}")


class ChallengeRequiredError(Exception):
    """Raised when a challenge is required."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Challenge required: {decision.reason}")


# Convenience function for quick setup
async def create_gateway(
    config: Optional[Settings] = None,
    config_path: Optional[str] = None,
    **kwargs,
) -> APIGateway:
    """
    Create and initialize an API Gateway.

    Args:
        config: Settings object
        config_path: Path to YAML config
        **kwargs: Additional gateway options

    Returns:
        Initialized APIGateway
    """
    from sql_injection_protector.core.config import load_config

    if config is None and config_path:
        config = load_config(config_path)

    gateway = APIGateway(config=config, **kwargs)
    await gateway.initialize()
    return gateway
