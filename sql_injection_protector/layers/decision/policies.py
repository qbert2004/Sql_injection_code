"""Decision policies for the decision engine."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

from sql_injection_protector.layers.decision.actions import ActionType


class PolicyMode(Enum):
    """Operating modes for the decision policy."""

    STRICT = auto()      # Block all suspicious requests
    STANDARD = auto()    # Balance between security and usability
    PERMISSIVE = auto()  # Allow more, alert on suspicious
    LEARNING = auto()    # Log only, no blocking
    CUSTOM = auto()      # Use custom thresholds


@dataclass
class ThresholdConfig:
    """Configuration for decision thresholds."""

    block: float = 0.8
    challenge: float = 0.6
    alert: float = 0.4
    sanitize: float = 0.3
    log: float = 0.1

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            "block": self.block,
            "challenge": self.challenge,
            "alert": self.alert,
            "sanitize": self.sanitize,
            "log": self.log,
        }

    @classmethod
    def for_mode(cls, mode: PolicyMode) -> "ThresholdConfig":
        """Get threshold config for a policy mode."""
        if mode == PolicyMode.STRICT:
            return cls(block=0.6, challenge=0.4, alert=0.2, sanitize=0.1, log=0.05)
        elif mode == PolicyMode.PERMISSIVE:
            return cls(block=0.95, challenge=0.8, alert=0.6, sanitize=0.5, log=0.3)
        elif mode == PolicyMode.LEARNING:
            return cls(block=2.0, challenge=2.0, alert=0.3, sanitize=2.0, log=0.1)
        else:  # STANDARD
            return cls(block=0.8, challenge=0.6, alert=0.4, sanitize=0.3, log=0.1)


@dataclass
class DetectorWeights:
    """Weights for combining detector scores."""

    signature: float = 0.3
    heuristic: float = 0.2
    ml: float = 0.5

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            "signature": self.signature,
            "heuristic": self.heuristic,
            "ml": self.ml,
        }

    def normalize(self) -> "DetectorWeights":
        """Normalize weights to sum to 1.0."""
        total = self.signature + self.heuristic + self.ml
        if total == 0:
            return DetectorWeights(1/3, 1/3, 1/3)
        return DetectorWeights(
            signature=self.signature / total,
            heuristic=self.heuristic / total,
            ml=self.ml / total,
        )


@dataclass
class RateLimitPolicy:
    """Rate limiting policy configuration."""

    enabled: bool = True
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    ban_threshold: int = 5  # Blocked requests before ban
    ban_duration_seconds: int = 3600


@dataclass
class BehaviorPolicy:
    """Behavioral analysis policy configuration."""

    enabled: bool = True
    new_session_sensitivity: float = 1.2  # Multiplier for new sessions
    high_rate_sensitivity: float = 1.3    # Multiplier for high request rates
    repeat_offender_multiplier: float = 1.5  # Multiplier for previously blocked


@dataclass
class DecisionPolicy:
    """
    Complete decision policy configuration.

    Defines how detection results are translated into actions.
    """

    mode: PolicyMode = PolicyMode.STANDARD
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    weights: DetectorWeights = field(default_factory=DetectorWeights)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    behavior: BehaviorPolicy = field(default_factory=BehaviorPolicy)

    # Action preferences
    enable_sanitize: bool = True
    enable_challenge: bool = True
    enable_honeypot: bool = True

    # Challenge settings
    challenge_on_suspicious: bool = True
    challenge_type: str = "javascript"

    # Learning mode
    learning_mode: bool = False
    collect_payloads: bool = True

    # Bypass rules
    bypass_internal_ips: bool = True
    internal_ip_ranges: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    )

    def __post_init__(self):
        """Apply mode-specific defaults."""
        if self.mode != PolicyMode.CUSTOM:
            self.thresholds = ThresholdConfig.for_mode(self.mode)

        if self.mode == PolicyMode.LEARNING:
            self.learning_mode = True

    def get_action_for_score(self, score: float) -> ActionType:
        """
        Determine action based on score and thresholds.

        Args:
            score: Detection score (0-1)

        Returns:
            Recommended action type
        """
        if self.learning_mode:
            if score >= self.thresholds.alert:
                return ActionType.LOG_ONLY
            return ActionType.ALLOW

        if score >= self.thresholds.block:
            return ActionType.BLOCK
        elif score >= self.thresholds.challenge and self.enable_challenge:
            return ActionType.CHALLENGE
        elif score >= self.thresholds.alert:
            return ActionType.ALERT
        elif score >= self.thresholds.sanitize and self.enable_sanitize:
            return ActionType.SANITIZE
        elif score >= self.thresholds.log:
            return ActionType.LOG_ONLY
        else:
            return ActionType.ALLOW

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mode": self.mode.name,
            "thresholds": self.thresholds.to_dict(),
            "weights": self.weights.to_dict(),
            "rate_limit": {
                "enabled": self.rate_limit.enabled,
                "requests_per_minute": self.rate_limit.requests_per_minute,
                "requests_per_hour": self.rate_limit.requests_per_hour,
                "ban_threshold": self.rate_limit.ban_threshold,
                "ban_duration_seconds": self.rate_limit.ban_duration_seconds,
            },
            "behavior": {
                "enabled": self.behavior.enabled,
                "new_session_sensitivity": self.behavior.new_session_sensitivity,
                "high_rate_sensitivity": self.behavior.high_rate_sensitivity,
                "repeat_offender_multiplier": self.behavior.repeat_offender_multiplier,
            },
            "enable_sanitize": self.enable_sanitize,
            "enable_challenge": self.enable_challenge,
            "enable_honeypot": self.enable_honeypot,
            "learning_mode": self.learning_mode,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DecisionPolicy":
        """Create from dictionary."""
        mode = PolicyMode[data.get("mode", "STANDARD")]

        thresholds = ThresholdConfig(**data.get("thresholds", {}))
        weights = DetectorWeights(**data.get("weights", {}))

        rate_limit_data = data.get("rate_limit", {})
        rate_limit = RateLimitPolicy(**rate_limit_data)

        behavior_data = data.get("behavior", {})
        behavior = BehaviorPolicy(**behavior_data)

        return cls(
            mode=mode,
            thresholds=thresholds,
            weights=weights,
            rate_limit=rate_limit,
            behavior=behavior,
            enable_sanitize=data.get("enable_sanitize", True),
            enable_challenge=data.get("enable_challenge", True),
            enable_honeypot=data.get("enable_honeypot", True),
            learning_mode=data.get("learning_mode", False),
            collect_payloads=data.get("collect_payloads", True),
        )


# Preset policies
STRICT_POLICY = DecisionPolicy(mode=PolicyMode.STRICT)
STANDARD_POLICY = DecisionPolicy(mode=PolicyMode.STANDARD)
PERMISSIVE_POLICY = DecisionPolicy(mode=PolicyMode.PERMISSIVE)
LEARNING_POLICY = DecisionPolicy(mode=PolicyMode.LEARNING)


def get_policy_by_name(name: str) -> DecisionPolicy:
    """Get a preset policy by name."""
    policies = {
        "strict": STRICT_POLICY,
        "standard": STANDARD_POLICY,
        "permissive": PERMISSIVE_POLICY,
        "learning": LEARNING_POLICY,
    }
    return policies.get(name.lower(), STANDARD_POLICY)
