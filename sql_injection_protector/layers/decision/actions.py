"""Action definitions and handlers for the decision engine."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional


class ActionType(Enum):
    """Types of actions that can be taken."""

    ALLOW = auto()
    SANITIZE = auto()
    BLOCK = auto()
    CHALLENGE = auto()
    ALERT = auto()
    HONEYPOT = auto()
    RATE_LIMIT = auto()
    LOG_ONLY = auto()


class ChallengeType(Enum):
    """Types of challenges for suspicious requests."""

    CAPTCHA = "captcha"
    JAVASCRIPT = "javascript"
    PROOF_OF_WORK = "proof_of_work"
    TWO_FACTOR = "two_factor"


@dataclass
class ActionResult:
    """Result of executing an action."""

    action_type: ActionType
    success: bool
    response_code: int = 200
    response_body: Optional[str] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    modified_input: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_type": self.action_type.name,
            "success": self.success,
            "response_code": self.response_code,
            "response_body": self.response_body,
            "response_headers": self.response_headers,
            "modified_input": self.modified_input,
            "metadata": self.metadata,
        }


class ActionHandler:
    """
    Handler for executing actions based on detection results.

    Provides default implementations for each action type.
    Custom handlers can be registered for specific actions.
    """

    def __init__(self):
        """Initialize action handler."""
        self._handlers: dict[ActionType, Callable] = {
            ActionType.ALLOW: self._handle_allow,
            ActionType.SANITIZE: self._handle_sanitize,
            ActionType.BLOCK: self._handle_block,
            ActionType.CHALLENGE: self._handle_challenge,
            ActionType.ALERT: self._handle_alert,
            ActionType.HONEYPOT: self._handle_honeypot,
            ActionType.RATE_LIMIT: self._handle_rate_limit,
            ActionType.LOG_ONLY: self._handle_log_only,
        }
        self._custom_handlers: dict[ActionType, Callable] = {}

    def register_handler(
        self,
        action_type: ActionType,
        handler: Callable[..., ActionResult],
    ) -> None:
        """Register a custom handler for an action type."""
        self._custom_handlers[action_type] = handler

    async def execute(
        self,
        action_type: ActionType,
        context: Optional[dict[str, Any]] = None,
        **kwargs,
    ) -> ActionResult:
        """
        Execute an action.

        Args:
            action_type: Type of action to execute
            context: Request context and detection results
            **kwargs: Additional arguments for the handler

        Returns:
            ActionResult with execution details
        """
        context = context or {}

        # Use custom handler if registered
        if action_type in self._custom_handlers:
            handler = self._custom_handlers[action_type]
        else:
            handler = self._handlers.get(action_type, self._handle_allow)

        return await handler(context, **kwargs)

    async def _handle_allow(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle ALLOW action - let request through."""
        return ActionResult(
            action_type=ActionType.ALLOW,
            success=True,
            response_code=200,
            metadata={"reason": "Request allowed"},
        )

    async def _handle_sanitize(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle SANITIZE action - clean the input."""
        original_input = context.get("input", "")
        sanitized = kwargs.get("sanitized_input", original_input)

        return ActionResult(
            action_type=ActionType.SANITIZE,
            success=True,
            response_code=200,
            modified_input=sanitized,
            metadata={
                "reason": "Input sanitized",
                "original_length": len(original_input),
                "sanitized_length": len(sanitized),
            },
        )

    async def _handle_block(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle BLOCK action - reject the request."""
        reason = kwargs.get("reason", "Request blocked due to security policy")
        score = context.get("score", 0.0)

        return ActionResult(
            action_type=ActionType.BLOCK,
            success=True,
            response_code=403,
            response_body=self._get_block_page(reason),
            response_headers={
                "Content-Type": "text/html; charset=utf-8",
                "X-Block-Reason": "sql-injection-detected",
            },
            metadata={
                "reason": reason,
                "score": score,
            },
        )

    async def _handle_challenge(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle CHALLENGE action - present a challenge."""
        challenge_type = kwargs.get("challenge_type", ChallengeType.JAVASCRIPT)

        return ActionResult(
            action_type=ActionType.CHALLENGE,
            success=True,
            response_code=429,
            response_body=self._get_challenge_page(challenge_type),
            response_headers={
                "Content-Type": "text/html; charset=utf-8",
                "X-Challenge-Type": challenge_type.value,
            },
            metadata={
                "challenge_type": challenge_type.value,
            },
        )

    async def _handle_alert(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle ALERT action - allow but generate alert."""
        return ActionResult(
            action_type=ActionType.ALERT,
            success=True,
            response_code=200,
            metadata={
                "reason": "Alert generated",
                "alert_sent": True,
                "score": context.get("score", 0.0),
            },
        )

    async def _handle_honeypot(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle HONEYPOT action - serve fake response."""
        fake_data = kwargs.get("fake_data", self._get_honeypot_response())

        return ActionResult(
            action_type=ActionType.HONEYPOT,
            success=True,
            response_code=200,
            response_body=fake_data,
            response_headers={
                "Content-Type": "application/json",
            },
            metadata={
                "reason": "Honeypot triggered",
                "collected_payload": True,
            },
        )

    async def _handle_rate_limit(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle RATE_LIMIT action - reject due to rate limiting."""
        retry_after = kwargs.get("retry_after", 60)

        return ActionResult(
            action_type=ActionType.RATE_LIMIT,
            success=True,
            response_code=429,
            response_body="Rate limit exceeded. Please try again later.",
            response_headers={
                "Content-Type": "text/plain",
                "Retry-After": str(retry_after),
                "X-RateLimit-Remaining": "0",
            },
            metadata={
                "reason": "Rate limit exceeded",
                "retry_after": retry_after,
            },
        )

    async def _handle_log_only(
        self, context: dict[str, Any], **kwargs
    ) -> ActionResult:
        """Handle LOG_ONLY action - allow but log for analysis."""
        return ActionResult(
            action_type=ActionType.LOG_ONLY,
            success=True,
            response_code=200,
            metadata={
                "reason": "Logged for analysis",
                "learning_mode": True,
            },
        )

    def _get_block_page(self, reason: str) -> str:
        """Generate HTML block page."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        h1 {{ color: #c00; }}
        p {{ color: #666; }}
    </style>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>Your request has been blocked by the security system.</p>
    <p>If you believe this is an error, please contact the administrator.</p>
    <p><small>Reference: {reason[:50]}</small></p>
</body>
</html>"""

    def _get_challenge_page(self, challenge_type: ChallengeType) -> str:
        """Generate HTML challenge page."""
        if challenge_type == ChallengeType.JAVASCRIPT:
            return """<!DOCTYPE html>
<html>
<head>
    <title>Security Check</title>
    <script>
        // Simple JS challenge
        document.cookie = "challenge=" + btoa(Date.now().toString());
        setTimeout(function() { location.reload(); }, 1000);
    </script>
</head>
<body>
    <h1>Security Check</h1>
    <p>Please wait while we verify your request...</p>
</body>
</html>"""
        else:
            return """<!DOCTYPE html>
<html>
<head><title>Security Check</title></head>
<body>
    <h1>Security Check Required</h1>
    <p>Please complete the security challenge to continue.</p>
</body>
</html>"""

    def _get_honeypot_response(self) -> str:
        """Generate fake honeypot response."""
        import json
        return json.dumps({
            "status": "success",
            "data": {
                "users": [
                    {"id": 1, "username": "admin", "email": "admin@example.com"},
                    {"id": 2, "username": "user", "email": "user@example.com"},
                ]
            }
        })
