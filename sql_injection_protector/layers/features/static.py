"""Static feature extraction for SQL injection detection."""

import math
import re
from collections import Counter
from typing import Any, Optional

from sql_injection_protector.layers.preprocessing.tokenizer import SQLTokenizer, TokenType


class StaticFeatureExtractor:
    """
    Extracts static features from input text for ML models.

    Features include:
    - Length and character metrics
    - SQL keyword/function/operator counts
    - Quote and comment indicators
    - Entropy and randomness metrics
    - Encoding indicators
    - Structural patterns
    """

    # SQL injection signature patterns
    SUSPICIOUS_PATTERNS = {
        "union_select": re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE),
        "or_true": re.compile(r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", re.IGNORECASE),
        "and_true": re.compile(r"\band\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", re.IGNORECASE),
        "or_false": re.compile(r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?2['\"]?", re.IGNORECASE),
        "comment_injection": re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE),
        "stacked_query": re.compile(r";\s*(select|insert|update|delete|drop|create)", re.IGNORECASE),
        "time_based": re.compile(r"\b(sleep|benchmark|waitfor|pg_sleep)\b", re.IGNORECASE),
        "info_gathering": re.compile(r"\b(information_schema|sysobjects|syscolumns)\b", re.IGNORECASE),
        "hex_encoding": re.compile(r"0x[0-9a-fA-F]+"),
        "char_function": re.compile(r"\bchar\s*\(\s*\d+", re.IGNORECASE),
    }

    # Dangerous SQL keywords (ordered by severity)
    DANGEROUS_KEYWORDS = [
        "union", "select", "insert", "update", "delete", "drop", "create",
        "alter", "truncate", "exec", "execute", "xp_", "sp_", "declare",
        "cast", "convert", "load_file", "into_outfile", "information_schema",
    ]

    def __init__(self, tokenizer: Optional[SQLTokenizer] = None):
        """Initialize feature extractor."""
        self.tokenizer = tokenizer or SQLTokenizer()

    def extract(self, text: str, normalized_text: Optional[str] = None) -> dict[str, float]:
        """
        Extract all static features from text.

        Args:
            text: Raw input text
            normalized_text: Optional pre-normalized text

        Returns:
            Dictionary of feature names to values
        """
        if not text:
            return self._empty_features()

        analyze_text = normalized_text or text

        features = {}

        # Length features
        features.update(self._extract_length_features(text))

        # Character ratio features
        features.update(self._extract_char_ratio_features(text))

        # Token-based features
        features.update(self._extract_token_features(analyze_text))

        # Pattern-based features
        features.update(self._extract_pattern_features(text))

        # Entropy features
        features.update(self._extract_entropy_features(text))

        # Structural features
        features.update(self._extract_structural_features(text))

        return features

    def _empty_features(self) -> dict[str, float]:
        """Return empty feature set for empty input."""
        return {
            "length": 0.0,
            "length_log": 0.0,
            "word_count": 0.0,
            "avg_word_length": 0.0,
            "alpha_ratio": 0.0,
            "digit_ratio": 0.0,
            "special_ratio": 0.0,
            "whitespace_ratio": 0.0,
            "uppercase_ratio": 0.0,
            "keyword_count": 0.0,
            "function_count": 0.0,
            "operator_count": 0.0,
            "string_count": 0.0,
            "number_count": 0.0,
            "single_quote_count": 0.0,
            "double_quote_count": 0.0,
            "comment_count": 0.0,
            "suspicious_pattern_count": 0.0,
            "has_union_select": 0.0,
            "has_or_true": 0.0,
            "has_comment": 0.0,
            "has_stacked_query": 0.0,
            "has_time_based": 0.0,
            "entropy": 0.0,
            "normalized_entropy": 0.0,
            "paren_depth": 0.0,
            "semicolon_count": 0.0,
            "dangerous_keyword_score": 0.0,
        }

    def _extract_length_features(self, text: str) -> dict[str, float]:
        """Extract length-related features."""
        length = len(text)
        words = text.split()

        return {
            "length": float(length),
            "length_log": math.log1p(length),
            "word_count": float(len(words)),
            "avg_word_length": sum(len(w) for w in words) / len(words) if words else 0.0,
        }

    def _extract_char_ratio_features(self, text: str) -> dict[str, float]:
        """Extract character ratio features."""
        if not text:
            return {
                "alpha_ratio": 0.0,
                "digit_ratio": 0.0,
                "special_ratio": 0.0,
                "whitespace_ratio": 0.0,
                "uppercase_ratio": 0.0,
            }

        length = len(text)
        alpha_count = sum(1 for c in text if c.isalpha())
        digit_count = sum(1 for c in text if c.isdigit())
        whitespace_count = sum(1 for c in text if c.isspace())
        special_count = length - alpha_count - digit_count - whitespace_count
        uppercase_count = sum(1 for c in text if c.isupper())

        return {
            "alpha_ratio": alpha_count / length,
            "digit_ratio": digit_count / length,
            "special_ratio": special_count / length,
            "whitespace_ratio": whitespace_count / length,
            "uppercase_ratio": uppercase_count / alpha_count if alpha_count else 0.0,
        }

    def _extract_token_features(self, text: str) -> dict[str, float]:
        """Extract token-based features using SQL tokenizer."""
        tokens = self.tokenizer.tokenize(text)
        token_counts = Counter(t.type for t in tokens)

        return {
            "keyword_count": float(token_counts.get(TokenType.KEYWORD, 0)),
            "function_count": float(token_counts.get(TokenType.FUNCTION, 0)),
            "operator_count": float(token_counts.get(TokenType.OPERATOR, 0)),
            "string_count": float(token_counts.get(TokenType.STRING, 0)),
            "number_count": float(
                token_counts.get(TokenType.NUMBER, 0)
                + token_counts.get(TokenType.HEX_NUMBER, 0)
            ),
            "single_quote_count": float(token_counts.get(TokenType.SINGLE_QUOTE, 0)),
            "double_quote_count": float(token_counts.get(TokenType.DOUBLE_QUOTE, 0)),
            "comment_count": float(
                token_counts.get(TokenType.LINE_COMMENT, 0)
                + token_counts.get(TokenType.BLOCK_COMMENT, 0)
            ),
        }

    def _extract_pattern_features(self, text: str) -> dict[str, float]:
        """Extract pattern-based features."""
        pattern_matches = 0
        features = {}

        for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
            match = pattern.search(text)
            if match:
                pattern_matches += 1
                features[f"has_{pattern_name}"] = 1.0
            else:
                features[f"has_{pattern_name}"] = 0.0

        features["suspicious_pattern_count"] = float(pattern_matches)

        # Dangerous keyword score
        text_lower = text.lower()
        dangerous_score = 0.0
        for i, keyword in enumerate(self.DANGEROUS_KEYWORDS):
            if keyword in text_lower:
                # Higher weight for more dangerous keywords (early in list)
                dangerous_score += 1.0 / (i + 1)

        features["dangerous_keyword_score"] = dangerous_score

        return features

    def _extract_entropy_features(self, text: str) -> dict[str, float]:
        """Extract entropy-based features."""
        if not text:
            return {"entropy": 0.0, "normalized_entropy": 0.0}

        # Character frequency
        freq = Counter(text)
        length = len(text)

        # Shannon entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        # Normalized entropy (0-1 scale)
        max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

        return {
            "entropy": entropy,
            "normalized_entropy": normalized_entropy,
        }

    def _extract_structural_features(self, text: str) -> dict[str, float]:
        """Extract structural features."""
        # Parenthesis depth
        max_depth = 0
        current_depth = 0
        for char in text:
            if char == "(":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == ")":
                current_depth = max(0, current_depth - 1)

        # Semicolon count (potential stacked queries)
        semicolon_count = text.count(";")

        return {
            "paren_depth": float(max_depth),
            "semicolon_count": float(semicolon_count),
        }

    def get_feature_names(self) -> list[str]:
        """Get list of all feature names in order."""
        sample = self._empty_features()
        return list(sample.keys())

    def extract_as_vector(self, text: str) -> list[float]:
        """
        Extract features as a fixed-order vector.

        Args:
            text: Input text

        Returns:
            List of feature values in consistent order
        """
        features = self.extract(text)
        names = self.get_feature_names()
        return [features.get(name, 0.0) for name in names]


def extract_static_features(text: str) -> dict[str, float]:
    """Convenience function for static feature extraction."""
    extractor = StaticFeatureExtractor()
    return extractor.extract(text)
