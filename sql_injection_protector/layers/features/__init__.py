"""Feature extraction layer - Layer 3: Feature Extraction."""

from sql_injection_protector.layers.features.static import (
    StaticFeatureExtractor,
    extract_static_features,
)
from sql_injection_protector.layers.features.behavioral import (
    BehavioralFeatureExtractor,
    SessionMetrics,
)
from sql_injection_protector.layers.features.vector import (
    FeatureVectorBuilder,
    NormalizedFeatureVectorBuilder,
    FeatureExtractionResult,
)

__all__ = [
    "StaticFeatureExtractor",
    "extract_static_features",
    "BehavioralFeatureExtractor",
    "SessionMetrics",
    "FeatureVectorBuilder",
    "NormalizedFeatureVectorBuilder",
    "FeatureExtractionResult",
]
