"""Decision engine for determining actions based on detection results."""

import ipaddress
import logging
import time
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sql_injection_protector.core.result import (
    Action,
    Decision,
    DetectionResult,
    DetectorScore,
    DetectorType,
    RateLimitInfo,
    ThreatLevel,
)
from sql_injection_protector.layers.decision.actions import ActionHandler, ActionResult, ActionType
from sql_injection_protector.layers.decision.policies import DecisionPolicy, PolicyMode
from sql_injection_protector.layers.request.context import RequestContext

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    Engine for making decisions based on detection results.

    Responsibilities:
    - Combine scores from multiple detectors
    - Apply policy rules and thresholds
    - Consider behavioral factors
    - Determine appropriate action
    - Execute action and return decision
    """

    def __init__(
        self,
        policy: Optional[DecisionPolicy] = None,
        action_handler: Optional[ActionHandler] = None,
    ):
        """
        Initialize decision engine.

        Args:
            policy: Decision policy configuration
            action_handler: Custom action handler
        """
        self.policy = policy or DecisionPolicy()
        self.action_handler = action_handler or ActionHandler()

    def calculate_final_score(
        self,
        detector_scores: list[DetectorScore],
        behavioral_multiplier: float = 1.0,
    ) -> float:
        """
        Calculate final score from detector scores.

        Args:
            detector_scores: Scores from individual detectors
            behavioral_multiplier: Multiplier based on behavioral analysis

        Returns:
            Final combined score (0-1)
        """
        if not detector_scores:
            return 0.0

        weights = self.policy.weights.normalize()

        # Map detector types to weights
        type_weights = {
            DetectorType.SIGNATURE: weights.signature,
            DetectorType.HEURISTIC: weights.heuristic,
            DetectorType.ML_TFIDF: weights.ml,
            DetectorType.ML_TRANSFORMER: weights.ml,
            DetectorType.BEHAVIORAL: 0.0,  # Applied separately
            DetectorType.ENSEMBLE: 1.0,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for score in detector_scores:
            weight = type_weights.get(score.detector_type, 0.1)
            weighted_sum += score.score * weight * score.confidence
            total_weight += weight

        if total_weight == 0:
            return 0.0

        base_score = weighted_sum / total_weight

        # Apply behavioral multiplier
        final_score = base_score * behavioral_multiplier

        return min(1.0, max(0.0, final_score))

    def get_behavioral_multiplier(
        self,
        request_context: Optional[RequestContext] = None,
        behavioral_features: Optional[dict[str, float]] = None,
    ) -> float:
        """
        Calculate behavioral multiplier based on session/request patterns.

        Args:
            request_context: Current request context
            behavioral_features: Pre-computed behavioral features

        Returns:
            Multiplier (1.0 = neutral, >1.0 = more suspicious)
        """
        if not self.policy.behavior.enabled:
            return 1.0

        multiplier = 1.0

        if behavioral_features:
            # New session sensitivity
            session_age = behavioral_features.get("session_age_seconds", 0)
            if session_age < 60:  # Less than 1 minute
                multiplier *= self.policy.behavior.new_session_sensitivity

            # High request rate
            rpm = behavioral_features.get("requests_per_minute", 0)
            if rpm > 30:
                multiplier *= self.policy.behavior.high_rate_sensitivity

            # Previously blocked
            blocked_count = behavioral_features.get("blocked_count", 0)
            if blocked_count > 0:
                repeat_mult = 1.0 + (blocked_count * 0.1)
                multiplier *= min(repeat_mult, self.policy.behavior.repeat_offender_multiplier)

            # Rate anomaly
            anomaly_score = behavioral_features.get("rate_anomaly_score", 0)
            if anomaly_score > 0.3:
                multiplier *= 1.0 + anomaly_score

        return min(2.0, multiplier)

    def should_bypass(
        self,
        request_context: RequestContext,
    ) -> bool:
        """
        Check if request should bypass security checks.

        Args:
            request_context: Current request context

        Returns:
            True if request should be allowed without checks
        """
        if not self.policy.bypass_internal_ips:
            return False

        client_ip = request_context.client_ip
        if not client_ip:
            return False

        try:
            ip = ipaddress.ip_address(client_ip)

            for ip_range in self.policy.internal_ip_ranges:
                if "/" in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    if ip in network:
                        return True
                elif client_ip == ip_range:
                    return True

        except ValueError:
            pass

        return False

    async def decide(
        self,
        detection_result: DetectionResult,
        request_context: Optional[RequestContext] = None,
        behavioral_features: Optional[dict[str, float]] = None,
        rate_limit_info: Optional[RateLimitInfo] = None,
    ) -> Decision:
        """
        Make a decision based on detection results.

        Args:
            detection_result: Result from detection layer
            request_context: Current request context
            behavioral_features: Behavioral analysis features
            rate_limit_info: Rate limiting information

        Returns:
            Decision with recommended action
        """
        start_time = time.perf_counter()

        # Check for bypass
        if request_context and self.should_bypass(request_context):
            return self._create_allow_decision(detection_result)

        # Check for honeypot
        if request_context and request_context.is_honeypot:
            return await self._handle_honeypot(detection_result, request_context)

        # Check rate limiting first
        if rate_limit_info and rate_limit_info.is_limited:
            return await self._handle_rate_limited(detection_result, rate_limit_info)

        # Calculate final score with behavioral multiplier
        behavioral_multiplier = self.get_behavioral_multiplier(
            request_context, behavioral_features
        )

        final_score = self.calculate_final_score(
            detection_result.detector_scores,
            behavioral_multiplier,
        )

        # Update detection result with final score
        detection_result.final_score = final_score
        detection_result.threat_level = ThreatLevel.from_score(final_score)

        # Determine action
        action_type = self.policy.get_action_for_score(final_score)

        # Execute action
        context = {
            "input": detection_result.raw_input,
            "score": final_score,
            "detection_result": detection_result,
            "request_context": request_context,
        }

        action_result = await self.action_handler.execute(action_type, context)

        # Build decision
        decision = Decision(
            action=self._map_action_type(action_type),
            detection_result=detection_result,
            rate_limit_info=rate_limit_info,
            response_code=action_result.response_code,
            response_body=action_result.response_body,
            response_headers=action_result.response_headers,
            sanitized_input=action_result.modified_input,
            block_reason=action_result.metadata.get("reason") if action_type == ActionType.BLOCK else None,
        )

        processing_time = (time.perf_counter() - start_time) * 1000
        detection_result.processing_time_ms += processing_time

        return decision

    async def _handle_honeypot(
        self,
        detection_result: DetectionResult,
        request_context: RequestContext,
    ) -> Decision:
        """Handle honeypot request."""
        context = {
            "input": detection_result.raw_input,
            "request_context": request_context,
        }

        action_result = await self.action_handler.execute(ActionType.HONEYPOT, context)

        return Decision(
            action=Action.HONEYPOT,
            detection_result=detection_result,
            response_code=action_result.response_code,
            response_body=action_result.response_body,
            response_headers=action_result.response_headers,
            honeypot_triggered=True,
        )

    async def _handle_rate_limited(
        self,
        detection_result: DetectionResult,
        rate_limit_info: RateLimitInfo,
    ) -> Decision:
        """Handle rate-limited request."""
        retry_after = (
            int((rate_limit_info.reset_at - datetime.utcnow()).total_seconds())
            if rate_limit_info.reset_at
            else rate_limit_info.window_seconds
        )

        action_result = await self.action_handler.execute(
            ActionType.RATE_LIMIT,
            {},
            retry_after=max(1, retry_after),
        )

        return Decision(
            action=Action.RATE_LIMIT,
            detection_result=detection_result,
            rate_limit_info=rate_limit_info,
            response_code=action_result.response_code,
            response_body=action_result.response_body,
            response_headers=action_result.response_headers,
            block_reason="Rate limit exceeded",
        )

    def _create_allow_decision(
        self,
        detection_result: DetectionResult,
    ) -> Decision:
        """Create an ALLOW decision."""
        return Decision(
            action=Action.ALLOW,
            detection_result=detection_result,
            response_code=200,
        )

    def _map_action_type(self, action_type: ActionType) -> Action:
        """Map internal ActionType to core Action enum."""
        mapping = {
            ActionType.ALLOW: Action.ALLOW,
            ActionType.SANITIZE: Action.SANITIZE,
            ActionType.BLOCK: Action.BLOCK,
            ActionType.CHALLENGE: Action.CHALLENGE,
            ActionType.ALERT: Action.ALERT,
            ActionType.HONEYPOT: Action.HONEYPOT,
            ActionType.RATE_LIMIT: Action.RATE_LIMIT,
            ActionType.LOG_ONLY: Action.ALERT,
        }
        return mapping.get(action_type, Action.ALLOW)

    def update_policy(self, policy: DecisionPolicy) -> None:
        """Update the decision policy."""
        self.policy = policy

    def set_mode(self, mode: PolicyMode) -> None:
        """Change the policy mode."""
        self.policy.mode = mode
        self.policy.thresholds = self.policy.thresholds.for_mode(mode)

    def get_policy_info(self) -> dict[str, Any]:
        """Get current policy information."""
        return self.policy.to_dict()
