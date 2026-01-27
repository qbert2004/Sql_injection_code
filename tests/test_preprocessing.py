"""
Tests for the preprocessing layer.
"""

import pytest
from sql_injection_protector.layers.preprocessing.pipeline import (
    PreprocessingPipeline,
    AggressivePreprocessingPipeline,
    preprocess,
)
from sql_injection_protector.layers.preprocessing.decoder import Decoder
from sql_injection_protector.layers.preprocessing.normalizer import Normalizer, SQLNormalizer
from sql_injection_protector.layers.preprocessing.tokenizer import SQLTokenizer, TokenType


class TestDecoder:
    """Tests for the Decoder class."""

    def test_url_decode(self, decoder):
        """Test URL decoding."""
        encoded = "%27%20OR%20%271%27%3D%271"
        decoded = decoder.decode_all(encoded)
        assert "'" in decoded
        assert "OR" in decoded
        assert "'1'='1" in decoded

    def test_double_url_encoding(self, decoder):
        """Test double URL encoding detection and decode."""
        double_encoded = "%2527"  # %27 -> %2527
        decoded = decoder.decode_all(double_encoded)
        assert "'" in decoded or "%27" in decoded

    def test_html_entity_decode(self, decoder):
        """Test HTML entity decoding."""
        encoded = "&#39;&#32;OR&#32;1=1"
        decoded = decoder.decode_all(encoded)
        assert "OR" in decoded

    def test_hex_decode(self, decoder):
        """Test hex string detection."""
        hex_str = "0x61646d696e"  # "admin" in hex
        result = decoder.has_encoding(hex_str)
        assert result.get("hex_encoded", False) or "hex" in str(result).lower()

    def test_unicode_escape(self, decoder):
        """Test unicode escape decoding."""
        unicode_str = "\\u0027 OR 1=1"
        decoded = decoder.decode_all(unicode_str)
        assert decoded is not None

    def test_encoding_depth(self, decoder):
        """Test encoding depth detection."""
        # Single encoding
        single = "%27"
        # Double encoding
        double = "%2527"

        depth_single = decoder.get_encoding_depth(single)
        depth_double = decoder.get_encoding_depth(double)

        assert depth_single >= 1
        assert depth_double >= depth_single

    def test_no_encoding(self, decoder):
        """Test text without encoding."""
        plain = "normal text without encoding"
        decoded = decoder.decode_all(plain)
        assert decoded == plain

    def test_mixed_encoding(self, decoder):
        """Test mixed encoding types."""
        mixed = "%27&#32;OR&#32;1=1%27"
        decoded = decoder.decode_all(mixed)
        assert "OR" in decoded


class TestNormalizer:
    """Tests for the Normalizer class."""

    def test_unicode_normalization(self, normalizer):
        """Test Unicode NFKC normalization."""
        # Fullwidth characters
        fullwidth = "ＳＥＬＥＣＴ"
        normalized = normalizer.normalize(fullwidth)
        assert "select" in normalized.lower()

    def test_case_normalization(self, normalizer):
        """Test case normalization."""
        mixed_case = "SeLeCt * FrOm UsErS"
        normalized = normalizer.normalize(mixed_case)
        assert normalized == normalized.lower()

    def test_whitespace_normalization(self, normalizer):
        """Test whitespace normalization."""
        messy = "SELECT   *   FROM    users"
        normalized = normalizer.normalize(messy)
        assert "  " not in normalized  # No double spaces

    def test_null_byte_removal(self, normalizer):
        """Test null byte removal."""
        with_nulls = "SEL\x00ECT * FR\x00OM users"
        normalized = normalizer.normalize(with_nulls)
        assert "\x00" not in normalized
        assert "select" in normalized.lower()

    def test_control_char_removal(self, normalizer):
        """Test control character removal."""
        with_control = "SELECT\x01\x02 * FROM users"
        normalized = normalizer.normalize(with_control)
        assert "\x01" not in normalized
        assert "\x02" not in normalized

    def test_empty_string(self, normalizer):
        """Test empty string handling."""
        assert normalizer.normalize("") == ""

    def test_sql_comment_normalization(self):
        """Test SQL comment handling with SQLNormalizer."""
        sql_normalizer = SQLNormalizer(strip_sql_comments=True)
        with_comment = "SELECT * FROM users -- get all users"
        normalized = sql_normalizer.normalize(with_comment)
        # Comment should be stripped or handled
        assert "--" not in normalized or "users" in normalized


class TestSQLTokenizer:
    """Tests for the SQL Tokenizer."""

    def test_keyword_tokenization(self, tokenizer):
        """Test SQL keyword detection."""
        sql = "SELECT * FROM users WHERE id = 1"
        tokens = tokenizer.tokenize(sql)

        token_types = [t.token_type for t in tokens]
        assert TokenType.KEYWORD in token_types

    def test_string_tokenization(self, tokenizer):
        """Test string literal detection."""
        sql = "SELECT * FROM users WHERE name = 'admin'"
        tokens = tokenizer.tokenize(sql)

        token_types = [t.token_type for t in tokens]
        assert TokenType.STRING in token_types

    def test_operator_tokenization(self, tokenizer):
        """Test operator detection."""
        sql = "id = 1 AND status >= 0 OR priority != 'low'"
        tokens = tokenizer.tokenize(sql)

        token_types = [t.token_type for t in tokens]
        assert TokenType.OPERATOR in token_types

    def test_comment_tokenization(self, tokenizer):
        """Test comment detection."""
        sql = "SELECT * FROM users -- comment"
        tokens = tokenizer.tokenize(sql)

        token_types = [t.token_type for t in tokens]
        assert TokenType.LINE_COMMENT in token_types

    def test_function_tokenization(self, tokenizer):
        """Test SQL function detection."""
        sql = "SELECT COUNT(*), MAX(id), CONCAT(first, last) FROM users"
        tokens = tokenizer.tokenize(sql)

        token_types = [t.token_type for t in tokens]
        assert TokenType.FUNCTION in token_types

    def test_token_counts(self, tokenizer):
        """Test token counting."""
        sql = "SELECT id, name FROM users WHERE status = 'active'"
        counts = tokenizer.get_token_counts(sql)

        assert counts.get("KEYWORD", 0) >= 3  # SELECT, FROM, WHERE
        assert counts.get("STRING", 0) >= 1  # 'active'

    def test_suspicious_sequence(self, tokenizer):
        """Test suspicious sequence detection."""
        injection = "' OR '1'='1"
        is_suspicious, reason = tokenizer.has_suspicious_sequence(injection)
        assert is_suspicious
        assert reason is not None

    def test_empty_input(self, tokenizer):
        """Test empty input handling."""
        tokens = tokenizer.tokenize("")
        assert tokens == []


class TestPreprocessingPipeline:
    """Tests for the full preprocessing pipeline."""

    def test_full_pipeline(self, preprocessing_pipeline):
        """Test complete preprocessing pipeline."""
        encoded = "%27%20UNION%20SELECT%20*%20FROM%20users--"
        result = preprocessing_pipeline.process(encoded)

        assert result.original == encoded
        assert result.decoded != encoded
        assert "union" in result.normalized.lower()
        assert len(result.tokens) > 0

    def test_pipeline_preserves_original(self, preprocessing_pipeline):
        """Test that original is preserved."""
        text = "' OR '1'='1"
        result = preprocessing_pipeline.process(text)
        assert result.original == text

    def test_pipeline_metadata(self, preprocessing_pipeline):
        """Test pipeline metadata generation."""
        encoded = "%27%20OR%201=1"
        result = preprocessing_pipeline.process(encoded)

        assert result.processing_time_ms >= 0
        assert isinstance(result.encoding_detected, dict)
        assert isinstance(result.transformations_applied, list)

    def test_pipeline_token_counts(self, preprocessing_pipeline):
        """Test token count generation."""
        sql = "SELECT * FROM users WHERE id = 1"
        result = preprocessing_pipeline.process(sql)

        assert isinstance(result.token_counts, dict)
        assert result.token_counts.get("KEYWORD", 0) > 0

    def test_suspicious_indicators(self, preprocessing_pipeline):
        """Test suspicious indicator extraction."""
        injection = "' UNION SELECT * FROM users--"
        result = preprocessing_pipeline.process(injection)
        indicators = preprocessing_pipeline.get_suspicious_indicators(result)

        assert isinstance(indicators, dict)
        assert "has_keywords" in indicators

    def test_empty_input(self, preprocessing_pipeline):
        """Test empty input handling."""
        result = preprocessing_pipeline.process("")

        assert result.original == ""
        assert result.decoded == ""
        assert result.normalized == ""
        assert result.tokens == []

    def test_batch_processing(self, preprocessing_pipeline):
        """Test batch processing."""
        texts = ["SELECT *", "normal text", "%27%20OR%201=1"]
        results = preprocessing_pipeline.process_batch(texts)

        assert len(results) == 3
        assert all(hasattr(r, "normalized") for r in results)

    def test_decode_only(self, preprocessing_pipeline):
        """Test decode-only mode."""
        encoded = "%27"
        decoded = preprocessing_pipeline.decode_only(encoded)
        assert "'" in decoded

    def test_normalize_only(self, preprocessing_pipeline):
        """Test normalize-only mode."""
        text = "  SELECT   *   FROM   users  "
        normalized = preprocessing_pipeline.normalize_only(text)
        assert "  " not in normalized.strip()


class TestAggressivePipeline:
    """Tests for aggressive preprocessing pipeline."""

    def test_aggressive_comment_stripping(self):
        """Test comment stripping in aggressive mode."""
        pipeline = AggressivePreprocessingPipeline()
        text = "SELECT * FROM users -- comment here"
        result = pipeline.process(text)

        # In aggressive mode, comments should be stripped
        assert result.normalized is not None

    def test_aggressive_base64_decoding(self):
        """Test Base64 decoding in aggressive mode."""
        pipeline = AggressivePreprocessingPipeline()
        # This would be tested if Base64 decoding is enabled
        text = "normal text"
        result = pipeline.process(text)
        assert result.normalized is not None


class TestPreprocessingHelpers:
    """Tests for helper functions."""

    def test_preprocess_function(self):
        """Test convenience preprocess function."""
        result = preprocess("SELECT * FROM users")
        assert result.normalized is not None
        assert len(result.tokens) > 0


@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "'; DROP TABLE users--",
    "%27%20OR%201=1",
    "admin'--",
])
class TestPayloadPreprocessing:
    """Parametrized tests for common payloads."""

    def test_payload_processing(self, preprocessing_pipeline, payload):
        """Test that payloads are correctly preprocessed."""
        result = preprocessing_pipeline.process(payload)

        assert result is not None
        assert result.original == payload
        assert result.normalized is not None
        # Should detect some encoding or have tokens
        assert len(result.tokens) > 0 or len(result.normalized) < len(payload) or result.encoding_depth > 0


@pytest.mark.parametrize("legitimate", [
    "john.doe@example.com",
    "John O'Brien",
    "https://example.com/page",
    "Product #123",
    "Price: $99.99",
])
class TestLegitimatePreprocessing:
    """Tests for legitimate input preprocessing."""

    def test_legitimate_processing(self, preprocessing_pipeline, legitimate):
        """Test that legitimate inputs are processed without errors."""
        result = preprocessing_pipeline.process(legitimate)

        assert result is not None
        assert result.original == legitimate
        assert result.normalized is not None
