"""Feature vector builder combining static and behavioral features."""

from dataclasses import dataclass, field
from typing import Any, Optional

from sql_injection_protector.core.result import FeatureVector
from sql_injection_protector.layers.features.static import StaticFeatureExtractor
from sql_injection_protector.layers.features.behavioral import BehavioralFeatureExtractor
from sql_injection_protector.layers.preprocessing.pipeline import PreprocessingResult
from sql_injection_protector.storage.redis import RedisClient


@dataclass
class FeatureExtractionResult:
    """Complete feature extraction result."""

    vector: FeatureVector
    static_features: dict[str, float]
    behavioral_features: dict[str, float]
    combined_vector: list[float]
    feature_names: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "static_features": self.static_features,
            "behavioral_features": self.behavioral_features,
            "combined_vector_length": len(self.combined_vector),
            "metadata": self.metadata,
        }


class FeatureVectorBuilder:
    """
    Builds combined feature vectors from static and behavioral features.

    Orchestrates:
    1. Static feature extraction
    2. Behavioral feature extraction (if Redis available)
    3. Feature combination and normalization
    """

    def __init__(
        self,
        redis_client: Optional[RedisClient] = None,
        static_extractor: Optional[StaticFeatureExtractor] = None,
        behavioral_extractor: Optional[BehavioralFeatureExtractor] = None,
        include_behavioral: bool = True,
    ):
        """
        Initialize feature vector builder.

        Args:
            redis_client: Redis client for behavioral tracking
            static_extractor: Custom static feature extractor
            behavioral_extractor: Custom behavioral feature extractor
            include_behavioral: Whether to include behavioral features
        """
        self.static_extractor = static_extractor or StaticFeatureExtractor()
        self.include_behavioral = include_behavioral

        if include_behavioral:
            self.behavioral_extractor = behavioral_extractor or BehavioralFeatureExtractor(
                redis_client=redis_client
            )
        else:
            self.behavioral_extractor = None

    async def build(
        self,
        text: str,
        client_id: Optional[str] = None,
        preprocessing_result: Optional[PreprocessingResult] = None,
        endpoint: Optional[str] = None,
    ) -> FeatureExtractionResult:
        """
        Build complete feature vector.

        Args:
            text: Raw input text
            client_id: Client identifier for behavioral tracking
            preprocessing_result: Pre-computed preprocessing result
            endpoint: Current request endpoint

        Returns:
            FeatureExtractionResult with all features
        """
        # Use preprocessed text if available
        normalized_text = None
        if preprocessing_result:
            normalized_text = preprocessing_result.normalized

        # Extract static features
        static_features = self.static_extractor.extract(text, normalized_text)

        # Extract behavioral features
        behavioral_features = {}
        if self.include_behavioral and self.behavioral_extractor and client_id:
            behavioral_features = await self.behavioral_extractor.extract(
                client_id=client_id,
                endpoint=endpoint,
                payload=text,
                update_state=True,
            )

        # Build combined vector
        feature_names = self._get_feature_names()
        combined_vector = self._build_combined_vector(
            static_features, behavioral_features
        )

        # Build FeatureVector for detection
        tokens = []
        if preprocessing_result:
            tokens = [str(t) for t in preprocessing_result.tokens[:100]]

        feature_vector = FeatureVector(
            static_features=static_features,
            behavioral_features=behavioral_features,
            raw_text=text,
            normalized_text=normalized_text or text,
            tokens=tokens,
        )

        return FeatureExtractionResult(
            vector=feature_vector,
            static_features=static_features,
            behavioral_features=behavioral_features,
            combined_vector=combined_vector,
            feature_names=feature_names,
            metadata={
                "has_behavioral": bool(behavioral_features),
                "client_id": client_id,
                "endpoint": endpoint,
            },
        )

    def build_sync(
        self,
        text: str,
        preprocessing_result: Optional[PreprocessingResult] = None,
    ) -> FeatureExtractionResult:
        """
        Build feature vector synchronously (static features only).

        Args:
            text: Raw input text
            preprocessing_result: Pre-computed preprocessing result

        Returns:
            FeatureExtractionResult with static features only
        """
        normalized_text = None
        if preprocessing_result:
            normalized_text = preprocessing_result.normalized

        static_features = self.static_extractor.extract(text, normalized_text)

        feature_names = self.static_extractor.get_feature_names()
        combined_vector = [static_features.get(name, 0.0) for name in feature_names]

        tokens = []
        if preprocessing_result:
            tokens = [str(t) for t in preprocessing_result.tokens[:100]]

        feature_vector = FeatureVector(
            static_features=static_features,
            behavioral_features={},
            raw_text=text,
            normalized_text=normalized_text or text,
            tokens=tokens,
        )

        return FeatureExtractionResult(
            vector=feature_vector,
            static_features=static_features,
            behavioral_features={},
            combined_vector=combined_vector,
            feature_names=feature_names,
            metadata={"has_behavioral": False},
        )

    def _get_feature_names(self) -> list[str]:
        """Get all feature names in order."""
        names = self.static_extractor.get_feature_names()
        if self.include_behavioral and self.behavioral_extractor:
            names.extend(self.behavioral_extractor.get_feature_names())
        return names

    def _build_combined_vector(
        self,
        static_features: dict[str, float],
        behavioral_features: dict[str, float],
    ) -> list[float]:
        """Build combined feature vector."""
        vector = []

        # Static features
        for name in self.static_extractor.get_feature_names():
            vector.append(static_features.get(name, 0.0))

        # Behavioral features
        if self.include_behavioral and self.behavioral_extractor:
            for name in self.behavioral_extractor.get_feature_names():
                vector.append(behavioral_features.get(name, 0.0))

        return vector

    def get_feature_count(self) -> int:
        """Get total number of features."""
        return len(self._get_feature_names())


class NormalizedFeatureVectorBuilder(FeatureVectorBuilder):
    """
    Feature vector builder with normalization.

    Applies min-max or z-score normalization to features.
    """

    def __init__(
        self,
        normalization: str = "minmax",
        feature_ranges: Optional[dict[str, tuple[float, float]]] = None,
        **kwargs,
    ):
        """
        Initialize normalized feature vector builder.

        Args:
            normalization: Normalization method ('minmax' or 'zscore')
            feature_ranges: Pre-computed min/max ranges for features
            **kwargs: Arguments passed to FeatureVectorBuilder
        """
        super().__init__(**kwargs)
        self.normalization = normalization
        self.feature_ranges = feature_ranges or self._default_ranges()

    def _default_ranges(self) -> dict[str, tuple[float, float]]:
        """Get default feature ranges for normalization."""
        return {
            # Length features
            "length": (0, 10000),
            "length_log": (0, 10),
            "word_count": (0, 500),
            "avg_word_length": (0, 50),
            # Ratios (already 0-1)
            "alpha_ratio": (0, 1),
            "digit_ratio": (0, 1),
            "special_ratio": (0, 1),
            "whitespace_ratio": (0, 1),
            "uppercase_ratio": (0, 1),
            # Counts
            "keyword_count": (0, 50),
            "function_count": (0, 20),
            "operator_count": (0, 30),
            "string_count": (0, 20),
            "number_count": (0, 50),
            "single_quote_count": (0, 20),
            "double_quote_count": (0, 20),
            "comment_count": (0, 10),
            "suspicious_pattern_count": (0, 10),
            # Binary features (already 0-1)
            "has_union_select": (0, 1),
            "has_or_true": (0, 1),
            "has_comment_injection": (0, 1),
            "has_stacked_query": (0, 1),
            "has_time_based": (0, 1),
            # Scores
            "entropy": (0, 8),
            "normalized_entropy": (0, 1),
            "dangerous_keyword_score": (0, 5),
            # Structural
            "paren_depth": (0, 20),
            "semicolon_count": (0, 10),
            # Behavioral
            "requests_per_minute": (0, 200),
            "requests_per_hour": (0, 2000),
            "session_age_seconds": (0, 86400),
            "session_age_minutes": (0, 1440),
            "avg_request_interval": (0, 60),
            "request_interval_variance": (0, 1000),
            "unique_endpoints": (0, 100),
            "unique_params": (0, 500),
            "payload_length_variance": (0, 10000),
            "payload_length_avg": (0, 1000),
            "blocked_count": (0, 100),
            "rate_anomaly_score": (0, 1),
        }

    def normalize_value(self, name: str, value: float) -> float:
        """Normalize a single feature value."""
        if name not in self.feature_ranges:
            return value

        min_val, max_val = self.feature_ranges[name]

        if self.normalization == "minmax":
            if max_val == min_val:
                return 0.0
            return (value - min_val) / (max_val - min_val)
        else:
            # Z-score (would need mean/std, simplified here)
            return (value - min_val) / (max_val - min_val)

    async def build(self, *args, **kwargs) -> FeatureExtractionResult:
        """Build and normalize feature vector."""
        result = await super().build(*args, **kwargs)

        # Normalize static features
        normalized_static = {
            name: self.normalize_value(name, value)
            for name, value in result.static_features.items()
        }

        # Normalize behavioral features
        normalized_behavioral = {
            name: self.normalize_value(name, value)
            for name, value in result.behavioral_features.items()
        }

        # Rebuild combined vector
        normalized_vector = self._build_combined_vector(
            normalized_static, normalized_behavioral
        )

        return FeatureExtractionResult(
            vector=result.vector,
            static_features=normalized_static,
            behavioral_features=normalized_behavioral,
            combined_vector=normalized_vector,
            feature_names=result.feature_names,
            metadata={**result.metadata, "normalized": True},
        )
