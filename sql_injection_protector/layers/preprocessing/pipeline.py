"""Preprocessing pipeline that orchestrates all normalization steps."""

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from sql_injection_protector.core.config import PreprocessingSettings
from sql_injection_protector.layers.preprocessing.decoder import Decoder
from sql_injection_protector.layers.preprocessing.normalizer import Normalizer, SQLNormalizer
from sql_injection_protector.layers.preprocessing.tokenizer import SQLTokenizer, Token


@dataclass
class PreprocessingResult:
    """Result of preprocessing pipeline."""

    original: str
    decoded: str
    normalized: str
    tokens: list[Token]
    token_counts: dict[str, int]

    # Metadata
    encoding_detected: dict[str, bool] = field(default_factory=dict)
    encoding_depth: int = 0
    transformations_applied: list[str] = field(default_factory=list)
    processing_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original": self.original,
            "decoded": self.decoded,
            "normalized": self.normalized,
            "tokens": [str(t) for t in self.tokens[:20]],  # Limit for readability
            "token_counts": self.token_counts,
            "encoding_detected": self.encoding_detected,
            "encoding_depth": self.encoding_depth,
            "transformations_applied": self.transformations_applied,
            "processing_time_ms": self.processing_time_ms,
        }


class PreprocessingPipeline:
    """
    Orchestrates the full preprocessing pipeline.

    Pipeline stages:
    1. Decoding (URL, HTML, Base64, Unicode, Hex)
    2. Normalization (Unicode NFKC, control chars, whitespace, case)
    3. Tokenization (SQL-aware lexer)

    The original input is preserved for logging/auditing.
    """

    def __init__(
        self,
        settings: Optional[PreprocessingSettings] = None,
        decoder: Optional[Decoder] = None,
        normalizer: Optional[Normalizer] = None,
        tokenizer: Optional[SQLTokenizer] = None,
    ):
        """
        Initialize the preprocessing pipeline.

        Args:
            settings: Preprocessing settings
            decoder: Custom decoder instance
            normalizer: Custom normalizer instance
            tokenizer: Custom tokenizer instance
        """
        self.settings = settings or PreprocessingSettings()

        self.decoder = decoder or Decoder(
            max_iterations=self.settings.max_decode_iterations
        )

        self.normalizer = normalizer or Normalizer(
            normalize_unicode=self.settings.normalize_unicode,
            remove_null_bytes=self.settings.remove_null_bytes,
            normalize_whitespace=True,
            lowercase=self.settings.lowercase,
            strip_sql_comments=False,  # Keep comments for detection
        )

        self.tokenizer = tokenizer or SQLTokenizer()

    def process(self, text: str) -> PreprocessingResult:
        """
        Process input through the full pipeline.

        Args:
            text: Raw input text

        Returns:
            PreprocessingResult with all processing stages
        """
        start_time = time.perf_counter()
        transformations = []

        # Handle empty input
        if not text:
            return PreprocessingResult(
                original="",
                decoded="",
                normalized="",
                tokens=[],
                token_counts={},
                processing_time_ms=0.0,
            )

        original = text

        # Stage 1: Detect and track encoding
        encoding_info = self.decoder.has_encoding(text)
        encoding_depth = self.decoder.get_encoding_depth(text)

        # Stage 2: Decode all encodings
        decoded = self.decoder.decode_all(text, include_base64=False)
        if decoded != text:
            transformations.append("decoded")

        # Stage 3: Normalize
        normalized = self.normalizer.normalize(decoded)
        if normalized != decoded:
            transformations.append("normalized")

        # Stage 4: Tokenize
        tokens = self.tokenizer.tokenize(normalized)
        token_counts = self.tokenizer.get_token_counts(normalized)

        processing_time = (time.perf_counter() - start_time) * 1000

        return PreprocessingResult(
            original=original,
            decoded=decoded,
            normalized=normalized,
            tokens=tokens,
            token_counts=token_counts,
            encoding_detected=encoding_info,
            encoding_depth=encoding_depth,
            transformations_applied=transformations,
            processing_time_ms=processing_time,
        )

    def process_batch(self, texts: list[str]) -> list[PreprocessingResult]:
        """
        Process multiple inputs.

        Args:
            texts: List of raw input texts

        Returns:
            List of PreprocessingResults
        """
        return [self.process(text) for text in texts]

    def decode_only(self, text: str) -> str:
        """
        Apply only decoding (no normalization).

        Useful when you need decoded but case-preserved output.

        Args:
            text: Raw input text

        Returns:
            Decoded text
        """
        return self.decoder.decode_all(text, include_base64=False)

    def normalize_only(self, text: str) -> str:
        """
        Apply only normalization (no decoding).

        Useful when input is already decoded.

        Args:
            text: Pre-decoded text

        Returns:
            Normalized text
        """
        return self.normalizer.normalize(text)

    def tokenize_only(self, text: str) -> list[Token]:
        """
        Apply only tokenization.

        Useful when input is already preprocessed.

        Args:
            text: Preprocessed text

        Returns:
            List of tokens
        """
        return self.tokenizer.tokenize(text)

    def get_suspicious_indicators(self, result: PreprocessingResult) -> dict[str, Any]:
        """
        Extract suspicious indicators from preprocessing result.

        Args:
            result: Preprocessing result

        Returns:
            Dictionary of suspicious indicators
        """
        indicators = {
            "high_encoding_depth": result.encoding_depth >= 2,
            "url_encoded": result.encoding_detected.get("url_encoded", False),
            "has_comments": result.token_counts.get("LINE_COMMENT", 0) > 0
            or result.token_counts.get("BLOCK_COMMENT", 0) > 0,
            "has_keywords": result.token_counts.get("KEYWORD", 0) > 0,
            "has_functions": result.token_counts.get("FUNCTION", 0) > 0,
            "has_operators": result.token_counts.get("OPERATOR", 0) > 0,
            "unmatched_quotes": (
                result.token_counts.get("SINGLE_QUOTE", 0)
                + result.token_counts.get("DOUBLE_QUOTE", 0)
            )
            > 0,
            "keyword_count": result.token_counts.get("KEYWORD", 0),
            "function_count": result.token_counts.get("FUNCTION", 0),
        }

        # Check token sequence
        is_suspicious, reason = self.tokenizer.has_suspicious_sequence(result.normalized)
        indicators["suspicious_sequence"] = is_suspicious
        indicators["suspicious_reason"] = reason

        return indicators


class AggressivePreprocessingPipeline(PreprocessingPipeline):
    """
    More aggressive preprocessing for high-security environments.

    Includes:
    - SQL comment stripping
    - More aggressive normalization
    - Base64 decoding attempts
    """

    def __init__(self, settings: Optional[PreprocessingSettings] = None):
        settings = settings or PreprocessingSettings()

        # Use SQL normalizer with comment stripping
        normalizer = SQLNormalizer(
            normalize_unicode=True,
            remove_null_bytes=True,
            normalize_whitespace=True,
            lowercase=True,
            strip_sql_comments=True,
        )

        super().__init__(settings=settings, normalizer=normalizer)

    def process(self, text: str) -> PreprocessingResult:
        """
        Process with aggressive settings.

        Also attempts Base64 decoding.
        """
        start_time = time.perf_counter()
        transformations = []

        if not text:
            return PreprocessingResult(
                original="",
                decoded="",
                normalized="",
                tokens=[],
                token_counts={},
                processing_time_ms=0.0,
            )

        original = text

        # Detect encoding
        encoding_info = self.decoder.has_encoding(text)
        encoding_depth = self.decoder.get_encoding_depth(text)

        # Aggressive decode including Base64
        decoded = self.decoder.decode_all(text, include_base64=True)
        if decoded != text:
            transformations.append("decoded")

        # Aggressive normalize (includes comment stripping)
        normalized = self.normalizer.normalize(decoded)
        if normalized != decoded:
            transformations.append("normalized")

        # SQL operator normalization
        if isinstance(self.normalizer, SQLNormalizer):
            normalized = self.normalizer.normalize_sql_operators(normalized)
            transformations.append("sql_normalized")

        # Tokenize
        tokens = self.tokenizer.tokenize(normalized)
        token_counts = self.tokenizer.get_token_counts(normalized)

        processing_time = (time.perf_counter() - start_time) * 1000

        return PreprocessingResult(
            original=original,
            decoded=decoded,
            normalized=normalized,
            tokens=tokens,
            token_counts=token_counts,
            encoding_detected=encoding_info,
            encoding_depth=encoding_depth,
            transformations_applied=transformations,
            processing_time_ms=processing_time,
        )


def preprocess(text: str) -> PreprocessingResult:
    """Convenience function for standard preprocessing."""
    pipeline = PreprocessingPipeline()
    return pipeline.process(text)


def preprocess_aggressive(text: str) -> PreprocessingResult:
    """Convenience function for aggressive preprocessing."""
    pipeline = AggressivePreprocessingPipeline()
    return pipeline.process(text)
