"""TF-IDF based SQL injection detector (fallback model)."""

import pickle
import time
from pathlib import Path
from typing import Optional, Tuple

import numpy as np

from sql_injection_protector.core.exceptions import ModelLoadError
from sql_injection_protector.core.result import DetectorType, FeatureVector
from sql_injection_protector.layers.detection.ml.base import MLDetector


class TFIDFDetector(MLDetector):
    """
    TF-IDF + Logistic Regression based SQL injection detector.

    This is a lightweight fallback model when Transformer is unavailable.
    Uses scikit-learn for vectorization and classification.
    """

    def __init__(
        self,
        model_path: str = "models/v1/tfidf_fallback.pkl",
        weight: float = 0.5,
        threshold: float = 0.5,
    ):
        """
        Initialize TF-IDF detector.

        Args:
            model_path: Path to pickled model file
            weight: Weight for ensemble scoring
            threshold: Classification threshold
        """
        super().__init__(
            detector_type=DetectorType.ML_TFIDF,
            name="TFIDFDetector",
            model_path=model_path,
            weight=weight,
        )
        self.threshold = threshold
        self._vectorizer = None
        self._classifier = None

    async def load_model(self, path: str) -> None:
        """
        Load TF-IDF vectorizer and classifier from pickle file.

        Expected format: {'vectorizer': TfidfVectorizer, 'classifier': LogisticRegression, 'version': str}
        """
        try:
            with open(path, "rb") as f:
                model_data = pickle.load(f)

            if isinstance(model_data, dict):
                self._vectorizer = model_data.get("vectorizer")
                self._classifier = model_data.get("classifier")
                self._model_version = model_data.get("version", "1.0.0")
            else:
                # Legacy format - assume it's just the classifier
                self._classifier = model_data
                self._vectorizer = None
                self._model_version = "legacy"

            if self._classifier is None:
                raise ModelLoadError(
                    "Invalid model file: missing classifier",
                    model_path=path,
                )

        except FileNotFoundError:
            raise ModelLoadError(
                f"Model file not found: {path}",
                model_path=path,
            )
        except Exception as e:
            raise ModelLoadError(
                f"Failed to load model: {e}",
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
        if not self._initialized:
            # Return safe default if not initialized
            return False, 0.0

        try:
            # Vectorize input
            if self._vectorizer:
                features = self._vectorizer.transform([text])
            else:
                # Fallback: use simple feature extraction
                features = self._extract_simple_features(text)

            # Get prediction probability
            if hasattr(self._classifier, "predict_proba"):
                proba = self._classifier.predict_proba(features)[0]
                # Assuming binary classification: [prob_benign, prob_malicious]
                confidence = float(proba[1]) if len(proba) > 1 else float(proba[0])
            else:
                # Fallback to decision function
                decision = self._classifier.decision_function(features)[0]
                confidence = 1 / (1 + np.exp(-decision))  # Sigmoid

            is_malicious = confidence >= self.threshold

            return is_malicious, confidence

        except Exception as e:
            # Log error and return safe default
            return False, 0.0

    async def predict_batch(self, texts: list[str]) -> list[Tuple[bool, float]]:
        """
        Predict on a batch of inputs (more efficient).

        Args:
            texts: List of input texts

        Returns:
            List of (is_malicious, confidence) tuples
        """
        if not self._initialized or not texts:
            return [(False, 0.0)] * len(texts)

        try:
            # Vectorize all inputs at once
            if self._vectorizer:
                features = self._vectorizer.transform(texts)
            else:
                features = np.array([self._extract_simple_features(t) for t in texts])

            # Get predictions
            if hasattr(self._classifier, "predict_proba"):
                probas = self._classifier.predict_proba(features)
                confidences = [float(p[1]) if len(p) > 1 else float(p[0]) for p in probas]
            else:
                decisions = self._classifier.decision_function(features)
                confidences = [1 / (1 + np.exp(-d)) for d in decisions]

            return [(c >= self.threshold, c) for c in confidences]

        except Exception:
            return [(False, 0.0)] * len(texts)

    def _extract_simple_features(self, text: str) -> np.ndarray:
        """
        Extract simple features when vectorizer is unavailable.

        This is a fallback that creates basic n-gram features.
        """
        # Simple character n-gram features
        features = []

        # Length features
        features.append(len(text))
        features.append(len(text.split()))

        # Character counts
        features.append(text.count("'"))
        features.append(text.count('"'))
        features.append(text.count("-"))
        features.append(text.count(";"))
        features.append(text.count("="))
        features.append(text.count("("))
        features.append(text.count(")"))

        # Keyword indicators
        text_lower = text.lower()
        keywords = ["select", "union", "insert", "update", "delete", "drop", "or", "and"]
        for kw in keywords:
            features.append(1 if kw in text_lower else 0)

        return np.array(features).reshape(1, -1)

    async def initialize(self) -> None:
        """Initialize the detector, handling missing model gracefully."""
        path = Path(self._model_path)

        if not path.exists():
            # Create a simple default model
            await self._create_default_model()
            self._initialized = True
            return

        await self.load_model(self._model_path)
        self._initialized = True

    async def _create_default_model(self) -> None:
        """Create a simple default model when no trained model exists."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression

            # Minimal training data for default model
            train_texts = [
                "SELECT * FROM users",
                "1 OR 1=1",
                "'; DROP TABLE users--",
                "UNION SELECT password FROM users",
                "hello world",
                "normal search query",
                "user@example.com",
                "john doe",
                "product id 12345",
                "simple text input",
            ]
            train_labels = [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]

            self._vectorizer = TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 4),
                max_features=1000,
            )
            features = self._vectorizer.fit_transform(train_texts)

            self._classifier = LogisticRegression(
                C=1.0,
                max_iter=1000,
                class_weight="balanced",
            )
            self._classifier.fit(features, train_labels)

            self._model_version = "default-1.0.0"

        except ImportError:
            # sklearn not available, use simple rule-based fallback
            self._vectorizer = None
            self._classifier = SimpleRuleClassifier()
            self._model_version = "rule-based-1.0.0"

    async def save_model(self, path: str) -> None:
        """Save the current model to a file."""
        if not self._initialized:
            raise ModelLoadError("Cannot save: model not initialized", model_path=path)

        model_data = {
            "vectorizer": self._vectorizer,
            "classifier": self._classifier,
            "version": self._model_version,
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(model_data, f)

    def set_threshold(self, threshold: float) -> None:
        """Set the classification threshold."""
        if 0.0 <= threshold <= 1.0:
            self.threshold = threshold


class SimpleRuleClassifier:
    """Simple rule-based classifier as ultimate fallback."""

    def __init__(self):
        self.sql_patterns = [
            "select", "union", "insert", "update", "delete", "drop",
            "or 1=1", "or '1'='1", "or \"1\"=\"1\"",
            "--", "/*", "*/", ";--",
            "exec", "execute", "xp_",
        ]

    def predict_proba(self, X) -> list:
        """Return probabilities based on pattern matching."""
        results = []
        for text in X:
            if isinstance(text, str):
                text_lower = text.lower()
            else:
                text_lower = str(text).lower()

            score = 0.0
            for pattern in self.sql_patterns:
                if pattern in text_lower:
                    score += 0.15

            score = min(1.0, score)
            results.append([1.0 - score, score])

        return results

    def decision_function(self, X) -> list:
        """Return decision scores."""
        probas = self.predict_proba(X)
        return [p[1] - 0.5 for p in probas]
