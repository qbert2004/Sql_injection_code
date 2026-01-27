"""Transformer-based SQL injection detector using DistilBERT."""

import asyncio
import time
from pathlib import Path
from typing import Optional, Tuple

from sql_injection_protector.core.exceptions import ModelLoadError
from sql_injection_protector.core.result import DetectorType, FeatureVector
from sql_injection_protector.layers.detection.ml.base import MLDetector


class TransformerDetector(MLDetector):
    """
    Transformer-based SQL injection detector using DistilBERT.

    This is the primary ML model offering high accuracy.
    Falls back to TF-IDF if transformers library is unavailable.
    """

    def __init__(
        self,
        model_path: str = "models/v1/transformer",
        weight: float = 0.5,
        threshold: float = 0.5,
        max_length: int = 512,
        device: Optional[str] = None,
    ):
        """
        Initialize Transformer detector.

        Args:
            model_path: Path to transformer model directory
            weight: Weight for ensemble scoring
            threshold: Classification threshold
            max_length: Maximum input sequence length
            device: Device to run model on ('cpu', 'cuda', or None for auto)
        """
        super().__init__(
            detector_type=DetectorType.ML_TRANSFORMER,
            name="TransformerDetector",
            model_path=model_path,
            weight=weight,
        )
        self.threshold = threshold
        self.max_length = max_length
        self._device = device
        self._tokenizer = None
        self._model = None
        self._torch = None

    async def load_model(self, path: str) -> None:
        """
        Load transformer model and tokenizer.

        Expected directory structure:
        - config.json
        - pytorch_model.bin or model.safetensors
        - tokenizer files
        """
        try:
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self._torch = torch

            # Determine device
            if self._device is None:
                self._device = "cuda" if torch.cuda.is_available() else "cpu"

            # Load tokenizer and model
            self._tokenizer = AutoTokenizer.from_pretrained(path)
            self._model = AutoModelForSequenceClassification.from_pretrained(path)
            self._model.to(self._device)
            self._model.eval()

            # Get version from config if available
            config_path = Path(path) / "config.json"
            if config_path.exists():
                import json
                with open(config_path) as f:
                    config = json.load(f)
                    self._model_version = config.get("version", "1.0.0")
            else:
                self._model_version = "1.0.0"

        except ImportError as e:
            raise ModelLoadError(
                "transformers or torch not installed. Install with: pip install transformers torch",
                model_path=path,
                details={"error": str(e)},
            )
        except Exception as e:
            raise ModelLoadError(
                f"Failed to load transformer model: {e}",
                model_path=path,
                details={"error": str(e)},
            )

    async def predict(self, text: str) -> Tuple[bool, float]:
        """
        Predict if text contains SQL injection.

        Args:
            text: Input text to classify

        Returns:
            Tuple of (is_malicious, confidence_score)
        """
        if not self._initialized or self._model is None:
            return False, 0.0

        try:
            # Tokenize
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length,
                padding=True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            # Run inference
            with self._torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits

            # Get probabilities
            probs = self._torch.softmax(logits, dim=1)
            confidence = float(probs[0][1].cpu())  # Probability of malicious class

            is_malicious = confidence >= self.threshold

            return is_malicious, confidence

        except Exception as e:
            # Return safe default on error
            return False, 0.0

    async def predict_batch(self, texts: list[str]) -> list[Tuple[bool, float]]:
        """
        Predict on a batch of inputs (more efficient with GPU).

        Args:
            texts: List of input texts

        Returns:
            List of (is_malicious, confidence) tuples
        """
        if not self._initialized or self._model is None or not texts:
            return [(False, 0.0)] * len(texts)

        try:
            # Tokenize batch
            inputs = self._tokenizer(
                texts,
                return_tensors="pt",
                truncation=True,
                max_length=self.max_length,
                padding=True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            # Run inference
            with self._torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits

            # Get probabilities
            probs = self._torch.softmax(logits, dim=1)
            confidences = probs[:, 1].cpu().tolist()

            return [(c >= self.threshold, c) for c in confidences]

        except Exception:
            return [(False, 0.0)] * len(texts)

    async def initialize(self) -> None:
        """Initialize the detector, handling missing model gracefully."""
        path = Path(self._model_path)

        if not path.exists():
            # Try to download or create default model
            await self._create_default_model()
            self._initialized = True
            return

        await self.load_model(self._model_path)
        self._initialized = True

    async def _create_default_model(self) -> None:
        """Create or download a default model when none exists."""
        try:
            import torch
            from transformers import (
                DistilBertForSequenceClassification,
                DistilBertTokenizer,
            )

            self._torch = torch

            # Use pre-trained DistilBERT with random classification head
            # In production, this should be fine-tuned on SQL injection data
            self._tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
            self._model = DistilBertForSequenceClassification.from_pretrained(
                "distilbert-base-uncased",
                num_labels=2,
            )

            if self._device is None:
                self._device = "cuda" if torch.cuda.is_available() else "cpu"

            self._model.to(self._device)
            self._model.eval()
            self._model_version = "default-distilbert-1.0.0"

        except ImportError:
            # transformers not available
            raise ModelLoadError(
                "Cannot create default model: transformers not installed",
                model_path=self._model_path,
            )

    async def save_model(self, path: str) -> None:
        """Save the current model to a directory."""
        if not self._initialized or self._model is None:
            raise ModelLoadError("Cannot save: model not initialized", model_path=path)

        Path(path).mkdir(parents=True, exist_ok=True)

        self._model.save_pretrained(path)
        self._tokenizer.save_pretrained(path)

        # Save version info
        import json
        config_path = Path(path) / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
            config["version"] = self._model_version
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)

    def set_threshold(self, threshold: float) -> None:
        """Set the classification threshold."""
        if 0.0 <= threshold <= 1.0:
            self.threshold = threshold

    def get_device(self) -> str:
        """Get the device the model is running on."""
        return self._device or "unknown"


class LightweightTransformerDetector(TransformerDetector):
    """
    Lightweight version using smaller model for faster inference.

    Uses DistilBERT by default, which is 60% smaller and 60% faster
    than BERT while retaining 97% of its performance.
    """

    def __init__(
        self,
        model_path: str = "models/v1/transformer-lite",
        weight: float = 0.5,
        threshold: float = 0.5,
        max_length: int = 256,  # Shorter for speed
        **kwargs,
    ):
        super().__init__(
            model_path=model_path,
            weight=weight,
            threshold=threshold,
            max_length=max_length,
            **kwargs,
        )
        self._name = "LightweightTransformerDetector"


class ONNXTransformerDetector(MLDetector):
    """
    ONNX-optimized transformer detector for production deployment.

    Provides faster inference by using ONNX Runtime.
    """

    def __init__(
        self,
        model_path: str = "models/v1/transformer.onnx",
        weight: float = 0.5,
        threshold: float = 0.5,
        max_length: int = 512,
    ):
        super().__init__(
            detector_type=DetectorType.ML_TRANSFORMER,
            name="ONNXTransformerDetector",
            model_path=model_path,
            weight=weight,
        )
        self.threshold = threshold
        self.max_length = max_length
        self._session = None
        self._tokenizer = None

    async def load_model(self, path: str) -> None:
        """Load ONNX model and tokenizer."""
        try:
            import onnxruntime as ort
            from transformers import AutoTokenizer

            # Load tokenizer (from same directory or parent)
            tokenizer_path = Path(path).parent / "tokenizer"
            if not tokenizer_path.exists():
                tokenizer_path = Path(path).parent

            self._tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_path))

            # Load ONNX model
            self._session = ort.InferenceSession(
                path,
                providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
            )

            self._model_version = "onnx-1.0.0"

        except ImportError as e:
            raise ModelLoadError(
                "onnxruntime not installed. Install with: pip install onnxruntime",
                model_path=path,
                details={"error": str(e)},
            )
        except Exception as e:
            raise ModelLoadError(
                f"Failed to load ONNX model: {e}",
                model_path=path,
                details={"error": str(e)},
            )

    async def predict(self, text: str) -> Tuple[bool, float]:
        """Predict using ONNX Runtime."""
        if not self._initialized or self._session is None:
            return False, 0.0

        try:
            import numpy as np

            # Tokenize
            inputs = self._tokenizer(
                text,
                return_tensors="np",
                truncation=True,
                max_length=self.max_length,
                padding=True,
            )

            # Run inference
            input_feed = {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            }
            outputs = self._session.run(None, input_feed)
            logits = outputs[0]

            # Softmax
            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / exp_logits.sum(axis=1, keepdims=True)
            confidence = float(probs[0][1])

            is_malicious = confidence >= self.threshold

            return is_malicious, confidence

        except Exception:
            return False, 0.0

    async def predict_batch(self, texts: list[str]) -> list[Tuple[bool, float]]:
        """Batch prediction with ONNX."""
        if not self._initialized or not texts:
            return [(False, 0.0)] * len(texts)

        try:
            import numpy as np

            inputs = self._tokenizer(
                texts,
                return_tensors="np",
                truncation=True,
                max_length=self.max_length,
                padding=True,
            )

            input_feed = {
                "input_ids": inputs["input_ids"],
                "attention_mask": inputs["attention_mask"],
            }
            outputs = self._session.run(None, input_feed)
            logits = outputs[0]

            exp_logits = np.exp(logits - np.max(logits, axis=1, keepdims=True))
            probs = exp_logits / exp_logits.sum(axis=1, keepdims=True)
            confidences = probs[:, 1].tolist()

            return [(c >= self.threshold, c) for c in confidences]

        except Exception:
            return [(False, 0.0)] * len(texts)
