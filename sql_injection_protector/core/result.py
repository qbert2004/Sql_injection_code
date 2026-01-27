"""Detection results and decision dataclasses."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Optional


class Action(Enum):
    """Actions that can be taken on a request."""

    ALLOW = auto()
    SANITIZE = auto()
    BLOCK = auto()
    CHALLENGE = auto()
    ALERT = auto()
    HONEYPOT = auto()
    RATE_LIMIT = auto()


class ThreatLevel(Enum):
    """Threat level classification."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_score(cls, score: float) -> "ThreatLevel":
        """Convert a 0-1 score to threat level."""
        if score < 0.2:
            return cls.NONE
        elif score < 0.4:
            return cls.LOW
        elif score < 0.6:
            return cls.MEDIUM
        elif score < 0.8:
            return cls.HIGH
        else:
            return cls.CRITICAL


class DetectorType(Enum):
    """Types of detectors."""

    SIGNATURE = "signature"
    HEURISTIC = "heuristic"
    ML_TFIDF = "ml_tfidf"
    ML_TRANSFORMER = "ml_transformer"
    BEHAVIORAL = "behavioral"
    ENSEMBLE = "ensemble"


@dataclass
class DetectorScore:
    """Score from a single detector."""

    detector_type: DetectorType
    score: float
    is_malicious: bool
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)
    matched_patterns: list[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


@dataclass
class FeatureVector:
    """Feature vector for ML models."""

    static_features: dict[str, float] = field(default_factory=dict)
    behavioral_features: dict[str, float] = field(default_factory=dict)
    raw_text: str = ""
    normalized_text: str = ""
    tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "static": self.static_features,
            "behavioral": self.behavioral_features,
            "raw_text": self.raw_text,
            "normalized_text": self.normalized_text,
            "tokens": self.tokens,
        }


@dataclass
class DetectionResult:
    """Complete detection result from all detectors."""

    request_id: str
    timestamp: datetime
    is_malicious: bool
    final_score: float
    threat_level: ThreatLevel
    detector_scores: list[DetectorScore] = field(default_factory=list)
    feature_vector: Optional[FeatureVector] = None
    raw_input: str = ""
    normalized_input: str = ""
    processing_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_highest_score(self) -> Optional[DetectorScore]:
        """Get the detector score with highest confidence."""
        if not self.detector_scores:
            return None
        return max(self.detector_scores, key=lambda x: x.score)

    def get_matched_patterns(self) -> list[str]:
        """Get all matched patterns from all detectors."""
        patterns = []
        for score in self.detector_scores:
            patterns.extend(score.matched_patterns)
        return list(set(patterns))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "is_malicious": self.is_malicious,
            "final_score": self.final_score,
            "threat_level": self.threat_level.name,
            "detector_scores": [
                {
                    "detector_type": s.detector_type.value,
                    "score": s.score,
                    "is_malicious": s.is_malicious,
                    "confidence": s.confidence,
                    "details": s.details,
                    "matched_patterns": s.matched_patterns,
                    "processing_time_ms": s.processing_time_ms,
                }
                for s in self.detector_scores
            ],
            "raw_input": self.raw_input,
            "normalized_input": self.normalized_input,
            "processing_time_ms": self.processing_time_ms,
            "matched_patterns": self.get_matched_patterns(),
            "metadata": self.metadata,
        }


@dataclass
class RateLimitInfo:
    """Rate limit information."""

    is_limited: bool
    remaining: int
    limit: int
    reset_at: Optional[datetime] = None
    window_seconds: int = 60


@dataclass
class Decision:
    """Final decision on how to handle a request."""

    action: Action
    detection_result: DetectionResult
    rate_limit_info: Optional[RateLimitInfo] = None
    response_code: int = 200
    response_body: Optional[str] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    sanitized_input: Optional[str] = None
    block_reason: Optional[str] = None
    challenge_type: Optional[str] = None
    honeypot_triggered: bool = False
    logged: bool = False
    alert_sent: bool = False

    def should_block(self) -> bool:
        """Check if request should be blocked."""
        return self.action in (Action.BLOCK, Action.RATE_LIMIT)

    def should_challenge(self) -> bool:
        """Check if request should be challenged."""
        return self.action == Action.CHALLENGE

    def should_sanitize(self) -> bool:
        """Check if input should be sanitized."""
        return self.action == Action.SANITIZE

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "action": self.action.name,
            "response_code": self.response_code,
            "block_reason": self.block_reason,
            "detection": self.detection_result.to_dict(),
        }
        if self.rate_limit_info:
            result["rate_limit"] = {
                "is_limited": self.rate_limit_info.is_limited,
                "remaining": self.rate_limit_info.remaining,
                "limit": self.rate_limit_info.limit,
                "reset_at": (
                    self.rate_limit_info.reset_at.isoformat()
                    if self.rate_limit_info.reset_at
                    else None
                ),
            }
        return result
