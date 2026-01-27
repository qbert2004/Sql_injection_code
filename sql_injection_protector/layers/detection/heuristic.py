"""Heuristic-based SQL injection detection using statistical analysis."""

import math
import time
from typing import Optional

from sql_injection_protector.core.result import DetectorScore, DetectorType, FeatureVector
from sql_injection_protector.layers.detection.base import Detector
from sql_injection_protector.layers.features.static import StaticFeatureExtractor


class HeuristicAnalyzer(Detector):
    """
    Heuristic analyzer using statistical features and rules.

    Analyzes:
    - Character distribution and entropy
    - SQL syntax patterns
    - Structural anomalies
    - Length and complexity metrics

    This detector is fast and doesn't require ML models.
    """

    def __init__(
        self,
        weight: float = 0.2,
        feature_extractor: Optional[StaticFeatureExtractor] = None,
    ):
        """
        Initialize heuristic analyzer.

        Args:
            weight: Weight for ensemble scoring
            feature_extractor: Custom feature extractor
        """
        super().__init__(
            detector_type=DetectorType.HEURISTIC,
            name="HeuristicAnalyzer",
            weight=weight,
        )
        self.feature_extractor = feature_extractor or StaticFeatureExtractor()

        # Heuristic thresholds
        self.thresholds = {
            "min_keyword_count": 2,
            "suspicious_special_ratio": 0.15,
            "high_entropy": 4.5,
            "low_entropy": 1.5,
            "max_paren_depth": 3,
            "suspicious_length": 100,
        }

    async def detect(
        self,
        text: str,
        feature_vector: Optional[FeatureVector] = None,
    ) -> DetectorScore:
        """
        Analyze text using heuristics.

        Args:
            text: Input text to analyze
            feature_vector: Optional pre-computed feature vector

        Returns:
            DetectorScore with heuristic analysis results
        """
        start_time = time.perf_counter()

        if not text:
            return self._create_score(
                score=0.0,
                is_malicious=False,
                confidence=1.0,
                processing_time_ms=0.0,
            )

        # Get features (use provided or extract)
        if feature_vector and feature_vector.static_features:
            features = feature_vector.static_features
        else:
            features = self.feature_extractor.extract(text)

        # Calculate component scores
        scores = []
        triggered_rules = []

        # 1. Keyword density analysis
        keyword_score, keyword_rules = self._analyze_keywords(features)
        scores.append(("keywords", keyword_score))
        triggered_rules.extend(keyword_rules)

        # 2. Special character analysis
        special_score, special_rules = self._analyze_special_chars(features)
        scores.append(("special_chars", special_score))
        triggered_rules.extend(special_rules)

        # 3. Entropy analysis
        entropy_score, entropy_rules = self._analyze_entropy(features)
        scores.append(("entropy", entropy_score))
        triggered_rules.extend(entropy_rules)

        # 4. Structural analysis
        struct_score, struct_rules = self._analyze_structure(features)
        scores.append(("structure", struct_score))
        triggered_rules.extend(struct_rules)

        # 5. Pattern-based analysis
        pattern_score, pattern_rules = self._analyze_patterns(features)
        scores.append(("patterns", pattern_score))
        triggered_rules.extend(pattern_rules)

        # 6. Length anomaly
        length_score, length_rules = self._analyze_length(features)
        scores.append(("length", length_score))
        triggered_rules.extend(length_rules)

        # Calculate final score (weighted average)
        weights = {
            "keywords": 0.25,
            "special_chars": 0.15,
            "entropy": 0.10,
            "structure": 0.15,
            "patterns": 0.25,
            "length": 0.10,
        }

        final_score = sum(
            weights.get(name, 0.1) * score for name, score in scores
        )
        final_score = min(1.0, final_score)

        # Determine if malicious
        is_malicious = final_score >= 0.5 or len(triggered_rules) >= 3

        processing_time = (time.perf_counter() - start_time) * 1000

        return self._create_score(
            score=final_score,
            is_malicious=is_malicious,
            confidence=self._calculate_confidence(scores, triggered_rules),
            details={
                "component_scores": dict(scores),
                "triggered_rule_count": len(triggered_rules),
            },
            matched_patterns=triggered_rules,
            processing_time_ms=processing_time,
        )

    def _analyze_keywords(self, features: dict) -> tuple[float, list[str]]:
        """Analyze SQL keyword presence."""
        rules = []
        score = 0.0

        keyword_count = features.get("keyword_count", 0)
        function_count = features.get("function_count", 0)
        dangerous_score = features.get("dangerous_keyword_score", 0)

        # Multiple SQL keywords
        if keyword_count >= self.thresholds["min_keyword_count"]:
            score += min(0.4, keyword_count * 0.1)
            rules.append(f"multiple_keywords({keyword_count})")

        # SQL functions present
        if function_count > 0:
            score += min(0.3, function_count * 0.1)
            rules.append(f"sql_functions({function_count})")

        # Dangerous keywords
        if dangerous_score > 0:
            score += min(0.5, dangerous_score * 0.2)
            rules.append(f"dangerous_keywords({dangerous_score:.2f})")

        return min(1.0, score), rules

    def _analyze_special_chars(self, features: dict) -> tuple[float, list[str]]:
        """Analyze special character distribution."""
        rules = []
        score = 0.0

        special_ratio = features.get("special_ratio", 0)
        single_quotes = features.get("single_quote_count", 0)
        double_quotes = features.get("double_quote_count", 0)
        operator_count = features.get("operator_count", 0)

        # High special character ratio
        if special_ratio > self.thresholds["suspicious_special_ratio"]:
            score += min(0.4, special_ratio * 2)
            rules.append(f"high_special_ratio({special_ratio:.2f})")

        # Unmatched quotes (potential injection)
        if single_quotes % 2 != 0:
            score += 0.3
            rules.append("unmatched_single_quotes")

        if double_quotes % 2 != 0:
            score += 0.2
            rules.append("unmatched_double_quotes")

        # Many operators
        if operator_count > 3:
            score += min(0.3, operator_count * 0.05)
            rules.append(f"many_operators({operator_count})")

        return min(1.0, score), rules

    def _analyze_entropy(self, features: dict) -> tuple[float, list[str]]:
        """Analyze character entropy."""
        rules = []
        score = 0.0

        entropy = features.get("entropy", 0)
        normalized_entropy = features.get("normalized_entropy", 0)

        # Very high entropy (possible obfuscation)
        if entropy > self.thresholds["high_entropy"]:
            score += 0.3
            rules.append(f"high_entropy({entropy:.2f})")

        # Very low entropy (repetitive patterns)
        elif entropy < self.thresholds["low_entropy"] and entropy > 0:
            score += 0.2
            rules.append(f"low_entropy({entropy:.2f})")

        # Abnormal normalized entropy
        if normalized_entropy > 0.9:
            score += 0.2
            rules.append("very_high_normalized_entropy")

        return min(1.0, score), rules

    def _analyze_structure(self, features: dict) -> tuple[float, list[str]]:
        """Analyze structural patterns."""
        rules = []
        score = 0.0

        paren_depth = features.get("paren_depth", 0)
        semicolon_count = features.get("semicolon_count", 0)
        comment_count = features.get("comment_count", 0)

        # Deep nesting
        if paren_depth > self.thresholds["max_paren_depth"]:
            score += min(0.4, paren_depth * 0.1)
            rules.append(f"deep_nesting({paren_depth})")

        # Multiple statements
        if semicolon_count > 0:
            score += min(0.5, semicolon_count * 0.2)
            rules.append(f"multiple_statements({semicolon_count})")

        # Comments present
        if comment_count > 0:
            score += min(0.4, comment_count * 0.2)
            rules.append(f"sql_comments({comment_count})")

        return min(1.0, score), rules

    def _analyze_patterns(self, features: dict) -> tuple[float, list[str]]:
        """Analyze known suspicious patterns."""
        rules = []
        score = 0.0

        # Check pattern flags from features
        pattern_mappings = [
            ("has_union_select", 0.8, "union_select_detected"),
            ("has_or_true", 0.7, "or_true_detected"),
            ("has_and_true", 0.6, "and_true_detected"),
            ("has_comment_injection", 0.5, "comment_injection_detected"),
            ("has_stacked_query", 0.8, "stacked_query_detected"),
            ("has_time_based", 0.9, "time_based_detected"),
            ("has_info_gathering", 0.7, "info_gathering_detected"),
            ("has_hex_encoding", 0.4, "hex_encoding_detected"),
            ("has_char_function", 0.5, "char_function_detected"),
        ]

        for feature_name, weight, rule_name in pattern_mappings:
            if features.get(feature_name, 0) > 0:
                score += weight
                rules.append(rule_name)

        # Suspicious pattern count
        pattern_count = features.get("suspicious_pattern_count", 0)
        if pattern_count > 0:
            score += min(0.3, pattern_count * 0.1)

        return min(1.0, score), rules

    def _analyze_length(self, features: dict) -> tuple[float, list[str]]:
        """Analyze input length anomalies."""
        rules = []
        score = 0.0

        length = features.get("length", 0)
        avg_word_length = features.get("avg_word_length", 0)

        # Very long input
        if length > self.thresholds["suspicious_length"]:
            score += min(0.3, (length - 100) / 1000)
            rules.append(f"long_input({length})")

        # Abnormal average word length
        if avg_word_length > 15:
            score += 0.2
            rules.append(f"long_avg_word({avg_word_length:.1f})")

        return min(1.0, score), rules

    def _calculate_confidence(
        self, scores: list[tuple[str, float]], rules: list[str]
    ) -> float:
        """Calculate confidence in the detection."""
        if not rules:
            return 1.0  # High confidence it's clean

        # More triggered rules = higher confidence in detection
        rule_confidence = min(1.0, len(rules) * 0.15)

        # Higher individual scores = higher confidence
        avg_score = sum(s for _, s in scores) / len(scores) if scores else 0
        score_confidence = min(1.0, avg_score * 1.5)

        return (rule_confidence + score_confidence) / 2

    def set_threshold(self, name: str, value: float) -> None:
        """Set a threshold value."""
        if name in self.thresholds:
            self.thresholds[name] = value

    def get_thresholds(self) -> dict:
        """Get all threshold values."""
        return self.thresholds.copy()
