"""Auto and manual labeling for collected payloads."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sql_injection_protector.layers.learning.collector import CollectedPayload
from sql_injection_protector.layers.detection.signature import SignatureDetector
from sql_injection_protector.layers.detection.heuristic import HeuristicAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class LabelingResult:
    """Result of a labeling operation."""

    payload_hash: str
    label: bool  # True = malicious, False = benign
    confidence: float
    labeler: str  # 'auto_signature', 'auto_heuristic', 'auto_ensemble', 'manual'
    reasons: list[str]
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload_hash": self.payload_hash,
            "label": self.label,
            "confidence": self.confidence,
            "labeler": self.labeler,
            "reasons": self.reasons,
            "timestamp": self.timestamp.isoformat(),
        }


class AutoLabeler:
    """
    Automatic labeling using detection ensemble.

    Uses high-confidence detection results to automatically
    label payloads for training data.
    """

    def __init__(
        self,
        signature_detector: Optional[SignatureDetector] = None,
        heuristic_analyzer: Optional[HeuristicAnalyzer] = None,
        high_confidence_threshold: float = 0.9,
        low_confidence_threshold: float = 0.1,
    ):
        """
        Initialize auto labeler.

        Args:
            signature_detector: Signature-based detector
            heuristic_analyzer: Heuristic analyzer
            high_confidence_threshold: Above this = definitely malicious
            low_confidence_threshold: Below this = definitely benign
        """
        self.signature_detector = signature_detector or SignatureDetector()
        self.heuristic_analyzer = heuristic_analyzer or HeuristicAnalyzer()
        self.high_threshold = high_confidence_threshold
        self.low_threshold = low_confidence_threshold

    async def label(self, payload: CollectedPayload) -> Optional[LabelingResult]:
        """
        Attempt to auto-label a payload.

        Only labels if confidence is high enough (above high_threshold
        or below low_threshold).

        Args:
            payload: Payload to label

        Returns:
            LabelingResult or None if confidence too low
        """
        reasons = []

        # Run signature detection
        sig_result = await self.signature_detector.detect(payload.payload)
        sig_score = sig_result.score

        # Run heuristic analysis
        heur_result = await self.heuristic_analyzer.detect(payload.payload)
        heur_score = heur_result.score

        # Combine scores
        combined_score = (sig_score * 0.6 + heur_score * 0.4)

        # Collect reasons
        if sig_result.matched_patterns:
            reasons.extend([f"sig:{p}" for p in sig_result.matched_patterns[:5]])
        if heur_result.matched_patterns:
            reasons.extend([f"heur:{p}" for p in heur_result.matched_patterns[:5]])

        # Determine label
        if combined_score >= self.high_threshold:
            return LabelingResult(
                payload_hash=payload.payload_hash,
                label=True,
                confidence=combined_score,
                labeler="auto_ensemble",
                reasons=reasons,
                timestamp=datetime.utcnow(),
            )
        elif combined_score <= self.low_threshold:
            return LabelingResult(
                payload_hash=payload.payload_hash,
                label=False,
                confidence=1.0 - combined_score,
                labeler="auto_ensemble",
                reasons=["no_patterns_matched"],
                timestamp=datetime.utcnow(),
            )

        # Confidence too low for auto-labeling
        return None

    async def label_batch(
        self,
        payloads: list[CollectedPayload],
    ) -> tuple[list[LabelingResult], list[CollectedPayload]]:
        """
        Label a batch of payloads.

        Args:
            payloads: List of payloads to label

        Returns:
            Tuple of (labeled_results, unlabeled_payloads)
        """
        labeled = []
        unlabeled = []

        for payload in payloads:
            result = await self.label(payload)
            if result:
                payload.is_labeled = True
                payload.label = result.label
                payload.labeler = result.labeler
                payload.confidence = result.confidence
                labeled.append(result)
            else:
                unlabeled.append(payload)

        logger.info(f"Auto-labeled {len(labeled)} payloads, {len(unlabeled)} need manual review")

        return labeled, unlabeled


class ManualLabeler:
    """
    Manual labeling interface for human review.

    Provides methods for presenting payloads to reviewers
    and recording their labels.
    """

    def __init__(self, reviewer_id: str = "default"):
        """
        Initialize manual labeler.

        Args:
            reviewer_id: Identifier for the reviewer
        """
        self.reviewer_id = reviewer_id
        self._pending_reviews: list[CollectedPayload] = []
        self._completed_reviews: list[LabelingResult] = []

    def add_for_review(self, payloads: list[CollectedPayload]) -> int:
        """
        Add payloads to the review queue.

        Args:
            payloads: Payloads to review

        Returns:
            Number added
        """
        self._pending_reviews.extend(payloads)
        return len(payloads)

    def get_next_for_review(self) -> Optional[CollectedPayload]:
        """Get the next payload for review."""
        if not self._pending_reviews:
            return None
        return self._pending_reviews[0]

    def submit_label(
        self,
        payload_hash: str,
        label: bool,
        confidence: float = 1.0,
        reasons: Optional[list[str]] = None,
    ) -> Optional[LabelingResult]:
        """
        Submit a manual label.

        Args:
            payload_hash: Hash of the payload being labeled
            label: True = malicious, False = benign
            confidence: Reviewer confidence (0-1)
            reasons: Reasons for the label

        Returns:
            LabelingResult or None if payload not found
        """
        # Find the payload
        payload = None
        for i, p in enumerate(self._pending_reviews):
            if p.payload_hash == payload_hash:
                payload = self._pending_reviews.pop(i)
                break

        if not payload:
            return None

        # Create result
        result = LabelingResult(
            payload_hash=payload_hash,
            label=label,
            confidence=confidence,
            labeler=f"manual:{self.reviewer_id}",
            reasons=reasons or [],
            timestamp=datetime.utcnow(),
        )

        # Update payload
        payload.is_labeled = True
        payload.label = label
        payload.labeler = result.labeler
        payload.confidence = confidence

        self._completed_reviews.append(result)

        return result

    def get_review_stats(self) -> dict[str, Any]:
        """Get review statistics."""
        malicious_count = sum(1 for r in self._completed_reviews if r.label)
        benign_count = len(self._completed_reviews) - malicious_count

        return {
            "pending": len(self._pending_reviews),
            "completed": len(self._completed_reviews),
            "malicious_count": malicious_count,
            "benign_count": benign_count,
            "reviewer_id": self.reviewer_id,
        }

    def export_completed(self) -> list[dict[str, Any]]:
        """Export completed reviews."""
        return [r.to_dict() for r in self._completed_reviews]


class HybridLabeler:
    """
    Hybrid labeling combining auto and manual labeling.

    Auto-labels high-confidence cases, routes low-confidence
    cases to manual review.
    """

    def __init__(
        self,
        auto_labeler: Optional[AutoLabeler] = None,
        manual_labeler: Optional[ManualLabeler] = None,
    ):
        """Initialize hybrid labeler."""
        self.auto_labeler = auto_labeler or AutoLabeler()
        self.manual_labeler = manual_labeler or ManualLabeler()

    async def process_batch(
        self,
        payloads: list[CollectedPayload],
    ) -> dict[str, Any]:
        """
        Process a batch of payloads with hybrid labeling.

        Args:
            payloads: Payloads to process

        Returns:
            Processing statistics
        """
        # First, try auto-labeling
        auto_labeled, needs_manual = await self.auto_labeler.label_batch(payloads)

        # Route uncertain cases to manual review
        self.manual_labeler.add_for_review(needs_manual)

        return {
            "total": len(payloads),
            "auto_labeled": len(auto_labeled),
            "sent_to_manual": len(needs_manual),
            "auto_malicious": sum(1 for r in auto_labeled if r.label),
            "auto_benign": sum(1 for r in auto_labeled if not r.label),
        }
