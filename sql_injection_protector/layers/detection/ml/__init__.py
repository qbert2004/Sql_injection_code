"""Machine Learning detection module."""

from sql_injection_protector.layers.detection.ml.base import MLDetector, MLDetectorProtocol
from sql_injection_protector.layers.detection.ml.tfidf import TFIDFDetector
from sql_injection_protector.layers.detection.ml.transformer import (
    TransformerDetector,
    LightweightTransformerDetector,
    ONNXTransformerDetector,
)
from sql_injection_protector.layers.detection.ml.versioning import (
    ModelVersion,
    ModelVersionManager,
)

__all__ = [
    "MLDetector",
    "MLDetectorProtocol",
    "TFIDFDetector",
    "TransformerDetector",
    "LightweightTransformerDetector",
    "ONNXTransformerDetector",
    "ModelVersion",
    "ModelVersionManager",
]
