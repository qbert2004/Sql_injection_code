"""Payload collector for gathering training data."""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sql_injection_protector.core.result import DetectionResult
from sql_injection_protector.storage.redis import RedisClient

logger = logging.getLogger(__name__)


@dataclass
class CollectedPayload:
    """A collected payload for analysis/training."""

    payload_hash: str
    payload: str
    timestamp: datetime
    source: str  # 'blocked', 'allowed', 'honeypot', 'manual'
    detection_score: float
    is_labeled: bool = False
    label: Optional[bool] = None  # True = malicious, False = benign
    labeler: Optional[str] = None  # 'auto', 'manual', 'ensemble'
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload_hash": self.payload_hash,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "detection_score": self.detection_score,
            "is_labeled": self.is_labeled,
            "label": self.label,
            "labeler": self.labeler,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectedPayload":
        """Create from dictionary."""
        data = data.copy()
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


class PayloadCollector:
    """
    Collects payloads for training data and analysis.

    Features:
    - Deduplication using content hashing
    - Source tracking (blocked, allowed, honeypot)
    - Redis queue for processing
    - Sampling for high-volume scenarios
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        max_payload_length: int = 10000,
        sample_rate: float = 1.0,
        deduplicate: bool = True,
    ):
        """
        Initialize payload collector.

        Args:
            redis_client: Redis client for storage
            max_payload_length: Maximum payload length to store
            sample_rate: Sampling rate (1.0 = collect all)
            deduplicate: Whether to deduplicate payloads
        """
        self.redis = redis_client
        self.max_payload_length = max_payload_length
        self.sample_rate = sample_rate
        self.deduplicate = deduplicate
        self._local_payloads: list[CollectedPayload] = []
        self._seen_hashes: set[str] = set()

    def _hash_payload(self, payload: str) -> str:
        """Generate hash for payload deduplication."""
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _should_sample(self) -> bool:
        """Determine if this request should be sampled."""
        if self.sample_rate >= 1.0:
            return True
        import random
        return random.random() < self.sample_rate

    async def collect(
        self,
        payload: str,
        detection_result: Optional[DetectionResult] = None,
        source: str = "detected",
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[CollectedPayload]:
        """
        Collect a payload for training.

        Args:
            payload: The payload text
            detection_result: Detection result if available
            source: Source of the payload
            metadata: Additional metadata

        Returns:
            CollectedPayload if collected, None if skipped
        """
        # Check sampling
        if not self._should_sample():
            return None

        # Truncate if needed
        if len(payload) > self.max_payload_length:
            payload = payload[:self.max_payload_length]

        # Generate hash
        payload_hash = self._hash_payload(payload)

        # Check deduplication
        if self.deduplicate and payload_hash in self._seen_hashes:
            return None

        # Create collected payload
        collected = CollectedPayload(
            payload_hash=payload_hash,
            payload=payload,
            timestamp=datetime.utcnow(),
            source=source,
            detection_score=detection_result.final_score if detection_result else 0.0,
            metadata=metadata or {},
        )

        # Add detection details
        if detection_result:
            collected.metadata["request_id"] = detection_result.request_id
            collected.metadata["threat_level"] = detection_result.threat_level.name
            collected.metadata["matched_patterns"] = detection_result.get_matched_patterns()

        # Store
        await self._store(collected)
        self._seen_hashes.add(payload_hash)

        logger.debug(f"Collected payload: {payload_hash} from {source}")

        return collected

    async def collect_from_result(
        self,
        detection_result: DetectionResult,
        was_blocked: bool,
    ) -> Optional[CollectedPayload]:
        """
        Collect payload from detection result.

        Args:
            detection_result: The detection result
            was_blocked: Whether the request was blocked

        Returns:
            CollectedPayload if collected
        """
        source = "blocked" if was_blocked else "allowed"

        return await self.collect(
            payload=detection_result.raw_input,
            detection_result=detection_result,
            source=source,
            metadata={"was_blocked": was_blocked},
        )

    async def _store(self, payload: CollectedPayload) -> None:
        """Store collected payload."""
        self._local_payloads.append(payload)

        # Keep local list bounded
        if len(self._local_payloads) > 10000:
            self._local_payloads = self._local_payloads[-10000:]

        # Store in Redis
        if self.redis and self.redis.is_connected:
            await self.redis.payload_push(
                payload=payload.payload,
                metadata=payload.to_dict(),
                queue_name="collected_payloads",
            )

    async def get_unlabeled(self, limit: int = 100) -> list[CollectedPayload]:
        """Get unlabeled payloads for manual review."""
        unlabeled = [p for p in self._local_payloads if not p.is_labeled]
        return unlabeled[:limit]

    async def get_by_source(self, source: str, limit: int = 100) -> list[CollectedPayload]:
        """Get payloads by source."""
        return [p for p in self._local_payloads if p.source == source][:limit]

    async def get_high_confidence_unlabeled(
        self,
        min_score: float = 0.9,
        limit: int = 100,
    ) -> list[CollectedPayload]:
        """Get high-confidence unlabeled payloads (good for auto-labeling)."""
        high_conf = [
            p for p in self._local_payloads
            if not p.is_labeled and p.detection_score >= min_score
        ]
        return high_conf[:limit]

    async def get_stats(self) -> dict[str, Any]:
        """Get collection statistics."""
        total = len(self._local_payloads)
        labeled = sum(1 for p in self._local_payloads if p.is_labeled)
        by_source = {}
        for p in self._local_payloads:
            by_source[p.source] = by_source.get(p.source, 0) + 1

        return {
            "total_collected": total,
            "labeled": labeled,
            "unlabeled": total - labeled,
            "by_source": by_source,
            "unique_hashes": len(self._seen_hashes),
        }

    async def export_for_training(
        self,
        labeled_only: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Export payloads for training.

        Args:
            labeled_only: Only export labeled payloads

        Returns:
            List of payload dictionaries
        """
        payloads = self._local_payloads
        if labeled_only:
            payloads = [p for p in payloads if p.is_labeled]

        return [p.to_dict() for p in payloads]

    def clear_local(self) -> int:
        """Clear local storage. Returns number cleared."""
        count = len(self._local_payloads)
        self._local_payloads = []
        self._seen_hashes = set()
        return count
