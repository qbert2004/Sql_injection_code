"""Base ML detector protocol and abstract class."""

from abc import abstractmethod
from pathlib import Path
from typing import Optional, Protocol, Tuple, runtime_checkable

from sql_injection_protector.core.exceptions import ModelLoadError
from sql_injection_protector.core.result import DetectorScore, DetectorType, FeatureVector
from sql_injection_protector.layers.detection.base import Detector


@runtime_checkable
class MLDetectorProtocol(Protocol):
    """Protocol for ML-based detectors."""

    @property
    def model_path(self) -> str:
        """Return the model path."""
        ...

    @property
    def model_version(self) -> str:
        """Return the model version."""
        ...

    async def predict(self, text: str) -> Tuple[bool, float]:
        """
        Make a prediction on input text.

        Args:
            text: Input text to classify

        Returns:
            Tuple of (is_malicious, confidence_score)
        """
        ...

    async def predict_batch(self, texts: list[str]) -> list[Tuple[bool, float]]:
        """
        Make predictions on a batch of inputs.

        Args:
            texts: List of input texts to classify

        Returns:
            List of (is_malicious, confidence_score) tuples
        """
        ...

    async def load_model(self, path: str) -> None:
        """Load model from path."""
        ...

    async def save_model(self, path: str) -> None:
        """Save model to path."""
        ...


class MLDetector(Detector):
    """Abstract base class for ML-based detectors."""

    def __init__(
        self,
        detector_type: DetectorType,
        name: str,
        model_path: str,
        weight: float = 1.0,
    ):
        super().__init__(detector_type, name, weight)
        self._model_path = model_path
        self._model_version = "unknown"
        self._model = None

    @property
    def model_path(self) -> str:
        """Return the model path."""
        return self._model_path

    @property
    def model_version(self) -> str:
        """Return the model version."""
        return self._model_version

    @abstractmethod
    async def predict(self, text: str) -> Tuple[bool, float]:
        """
        Make a prediction on input text.

        Args:
            text: Input text to classify

        Returns:
            Tuple of (is_malicious, confidence_score)
        """
        pass

    async def predict_batch(self, texts: list[str]) -> list[Tuple[bool, float]]:
        """
        Make predictions on a batch of inputs.

        Default implementation calls predict() sequentially.
        Override for more efficient batch processing.

        Args:
            texts: List of input texts to classify

        Returns:
            List of (is_malicious, confidence_score) tuples
        """
        results = []
        for text in texts:
            results.append(await self.predict(text))
        return results

    @abstractmethod
    async def load_model(self, path: str) -> None:
        """Load model from path."""
        pass

    async def save_model(self, path: str) -> None:
        """Save model to path. Override if model saving is supported."""
        raise NotImplementedError("Model saving not implemented for this detector")

    async def initialize(self) -> None:
        """Initialize by loading the model."""
        path = Path(self._model_path)
        if not path.exists():
            raise ModelLoadError(
                f"Model path does not exist: {self._model_path}",
                model_path=self._model_path,
            )
        await self.load_model(self._model_path)
        self._initialized = True

    async def detect(
        self,
        text: str,
        feature_vector: Optional[FeatureVector] = None,
    ) -> DetectorScore:
        """
        Analyze text for SQL injection using ML model.

        Args:
            text: Normalized input text to analyze
            feature_vector: Optional pre-computed feature vector

        Returns:
            DetectorScore with detection results
        """
        import time

        start_time = time.perf_counter()

        is_malicious, confidence = await self.predict(text)

        processing_time = (time.perf_counter() - start_time) * 1000

        return self._create_score(
            score=confidence,
            is_malicious=is_malicious,
            confidence=confidence,
            details={
                "model_version": self._model_version,
                "model_type": self._detector_type.value,
            },
            processing_time_ms=processing_time,
        )

    def get_model_info(self) -> dict:
        """Get information about the loaded model."""
        return {
            "name": self._name,
            "type": self._detector_type.value,
            "version": self._model_version,
            "path": self._model_path,
            "initialized": self._initialized,
        }
