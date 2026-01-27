"""Base detector protocol and abstract class."""

from abc import ABC, abstractmethod
from typing import Optional, Protocol, runtime_checkable

from sql_injection_protector.core.result import DetectorScore, DetectorType, FeatureVector


@runtime_checkable
class DetectorProtocol(Protocol):
    """Protocol defining the detector interface."""

    @property
    def detector_type(self) -> DetectorType:
        """Return the detector type."""
        ...

    @property
    def name(self) -> str:
        """Return the detector name."""
        ...

    @property
    def weight(self) -> float:
        """Return the weight for ensemble scoring."""
        ...

    async def detect(
        self,
        text: str,
        feature_vector: Optional[FeatureVector] = None,
    ) -> DetectorScore:
        """
        Analyze text for SQL injection.

        Args:
            text: Normalized input text to analyze
            feature_vector: Optional pre-computed feature vector

        Returns:
            DetectorScore with detection results
        """
        ...

    async def initialize(self) -> None:
        """Initialize the detector (load models, compile patterns, etc.)."""
        ...

    async def shutdown(self) -> None:
        """Cleanup resources."""
        ...


class Detector(ABC):
    """Abstract base class for all detectors."""

    def __init__(
        self,
        detector_type: DetectorType,
        name: str,
        weight: float = 1.0,
    ):
        self._detector_type = detector_type
        self._name = name
        self._weight = weight
        self._initialized = False

    @property
    def detector_type(self) -> DetectorType:
        """Return the detector type."""
        return self._detector_type

    @property
    def name(self) -> str:
        """Return the detector name."""
        return self._name

    @property
    def weight(self) -> float:
        """Return the weight for ensemble scoring."""
        return self._weight

    @weight.setter
    def weight(self, value: float) -> None:
        """Set the weight for ensemble scoring."""
        if not 0.0 <= value <= 1.0:
            raise ValueError("Weight must be between 0.0 and 1.0")
        self._weight = value

    @property
    def is_initialized(self) -> bool:
        """Check if detector is initialized."""
        return self._initialized

    @abstractmethod
    async def detect(
        self,
        text: str,
        feature_vector: Optional[FeatureVector] = None,
    ) -> DetectorScore:
        """
        Analyze text for SQL injection.

        Args:
            text: Normalized input text to analyze
            feature_vector: Optional pre-computed feature vector

        Returns:
            DetectorScore with detection results
        """
        pass

    async def initialize(self) -> None:
        """Initialize the detector. Override in subclasses if needed."""
        self._initialized = True

    async def shutdown(self) -> None:
        """Cleanup resources. Override in subclasses if needed."""
        self._initialized = False

    def _create_score(
        self,
        score: float,
        is_malicious: bool,
        confidence: float,
        details: Optional[dict] = None,
        matched_patterns: Optional[list[str]] = None,
        processing_time_ms: float = 0.0,
    ) -> DetectorScore:
        """Helper to create a DetectorScore."""
        return DetectorScore(
            detector_type=self._detector_type,
            score=score,
            is_malicious=is_malicious,
            confidence=confidence,
            details=details or {},
            matched_patterns=matched_patterns or [],
            processing_time_ms=processing_time_ms,
        )
