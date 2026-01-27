"""Base adapter interface for framework integration."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from sql_injection_protector.core.config import Settings
from sql_injection_protector.core.result import Decision
from sql_injection_protector.layers.request.context import RequestContext


class BaseAdapter(ABC):
    """
    Abstract base class for framework adapters.

    All framework-specific adapters should inherit from this class
    and implement the required methods.
    """

    def __init__(
        self,
        config: Optional[Settings] = None,
        on_block: Optional[Callable[[RequestContext, Decision], Any]] = None,
        on_allow: Optional[Callable[[RequestContext, Decision], Any]] = None,
    ):
        """
        Initialize the adapter.

        Args:
            config: Application settings
            on_block: Callback when request is blocked
            on_allow: Callback when request is allowed
        """
        self.config = config
        self.on_block = on_block
        self.on_allow = on_allow
        self._agent = None

    @abstractmethod
    async def extract_context(self, request: Any) -> RequestContext:
        """
        Extract RequestContext from framework-specific request.

        Args:
            request: Framework-specific request object

        Returns:
            RequestContext with extracted information
        """
        pass

    @abstractmethod
    async def create_blocked_response(
        self,
        decision: Decision,
        context: RequestContext,
    ) -> Any:
        """
        Create a blocked response for the framework.

        Args:
            decision: Decision with block details
            context: Request context

        Returns:
            Framework-specific response object
        """
        pass

    @abstractmethod
    async def create_challenge_response(
        self,
        decision: Decision,
        context: RequestContext,
    ) -> Any:
        """
        Create a challenge response for the framework.

        Args:
            decision: Decision with challenge details
            context: Request context

        Returns:
            Framework-specific response object
        """
        pass

    async def process_request(
        self,
        request: Any,
    ) -> tuple[bool, Optional[Any], RequestContext, Optional[Decision]]:
        """
        Process a request through the protection pipeline.

        Args:
            request: Framework-specific request object

        Returns:
            Tuple of (should_continue, response, context, decision)
            - should_continue: True if request should proceed
            - response: Response to return if blocked (None if allowed)
            - context: Extracted request context
            - decision: Decision made (None if error)
        """
        # Extract context
        context = await self.extract_context(request)

        # Get agent (lazy initialization)
        if self._agent is None:
            from sql_injection_protector.core.agent import SQLInjectionAgent
            self._agent = SQLInjectionAgent(settings=self.config)
            await self._agent.initialize()

        # Analyze request
        decision = await self._agent.analyze_request(context)

        # Handle based on decision
        if decision.should_block():
            response = await self.create_blocked_response(decision, context)
            if self.on_block:
                self.on_block(context, decision)
            return False, response, context, decision

        if decision.should_challenge():
            response = await self.create_challenge_response(decision, context)
            return False, response, context, decision

        if self.on_allow:
            self.on_allow(context, decision)

        return True, None, context, decision

    def set_agent(self, agent: Any) -> None:
        """Set the SQL injection agent instance."""
        self._agent = agent


class MiddlewareBase(BaseAdapter):
    """
    Base class for middleware-style adapters.

    Provides common functionality for middleware implementations.
    """

    def __init__(
        self,
        app: Any = None,
        exclude_paths: Optional[list[str]] = None,
        exclude_methods: Optional[list[str]] = None,
        **kwargs,
    ):
        """
        Initialize middleware.

        Args:
            app: The wrapped application
            exclude_paths: Paths to exclude from protection
            exclude_methods: HTTP methods to exclude
            **kwargs: Additional arguments for BaseAdapter
        """
        super().__init__(**kwargs)
        self.app = app
        self.exclude_paths = exclude_paths or []
        self.exclude_methods = exclude_methods or []

    def should_skip(self, path: str, method: str) -> bool:
        """
        Check if request should skip protection.

        Args:
            path: Request path
            method: HTTP method

        Returns:
            True if request should be skipped
        """
        # Check excluded methods
        if method.upper() in [m.upper() for m in self.exclude_methods]:
            return True

        # Check excluded paths
        for excluded in self.exclude_paths:
            if excluded.endswith("*"):
                if path.startswith(excluded[:-1]):
                    return True
            elif path == excluded:
                return True

        return False

    def get_client_ip(self, headers: dict[str, str], default: str = "") -> str:
        """
        Extract client IP from headers.

        Handles common proxy headers.

        Args:
            headers: Request headers
            default: Default value if not found

        Returns:
            Client IP address
        """
        # Check common proxy headers
        for header in ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]:
            value = headers.get(header)
            if value:
                # X-Forwarded-For may contain multiple IPs
                return value.split(",")[0].strip()

        return default
