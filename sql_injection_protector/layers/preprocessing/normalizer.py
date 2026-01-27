"""Text normalization for SQL injection detection."""

import re
import unicodedata
from typing import Optional


class Normalizer:
    """
    Text normalizer for consistent input processing.

    Handles:
    - Unicode normalization (NFKC)
    - Null byte and control character removal
    - Whitespace normalization
    - Case normalization
    - SQL comment stripping
    """

    def __init__(
        self,
        normalize_unicode: bool = True,
        remove_null_bytes: bool = True,
        normalize_whitespace: bool = True,
        lowercase: bool = True,
        strip_sql_comments: bool = False,
    ):
        """
        Initialize normalizer.

        Args:
            normalize_unicode: Apply NFKC normalization
            remove_null_bytes: Remove null bytes and control characters
            normalize_whitespace: Collapse multiple whitespace
            lowercase: Convert to lowercase
            strip_sql_comments: Remove SQL comments
        """
        self.normalize_unicode = normalize_unicode
        self.remove_null_bytes = remove_null_bytes
        self.normalize_whitespace = normalize_whitespace
        self.lowercase = lowercase
        self.strip_sql_comments = strip_sql_comments

        # Patterns
        self._control_char_pattern = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
        self._whitespace_pattern = re.compile(r"\s+")
        self._sql_line_comment = re.compile(r"--[^\n]*")
        self._sql_block_comment = re.compile(r"/\*.*?\*/", re.DOTALL)
        self._mysql_comment = re.compile(r"#[^\n]*")

        # Homoglyph mappings for common SQL injection characters
        self._homoglyphs = {
            "\u2018": "'",  # Left single quotation
            "\u2019": "'",  # Right single quotation
            "\u201c": '"',  # Left double quotation
            "\u201d": '"',  # Right double quotation
            "\u2010": "-",  # Hyphen
            "\u2011": "-",  # Non-breaking hyphen
            "\u2012": "-",  # Figure dash
            "\u2013": "-",  # En dash
            "\u2014": "-",  # Em dash
            "\uff07": "'",  # Fullwidth apostrophe
            "\uff02": '"',  # Fullwidth quotation
            "\uff1d": "=",  # Fullwidth equals
            "\uff08": "(",  # Fullwidth left paren
            "\uff09": ")",  # Fullwidth right paren
            "\uff3b": "[",  # Fullwidth left bracket
            "\uff3d": "]",  # Fullwidth right bracket
            "\u0027": "'",  # Apostrophe
        }

    def normalize_unicode_text(self, text: str) -> str:
        """
        Apply Unicode NFKC normalization and homoglyph replacement.

        NFKC decomposes characters and then recomposes by compatibility,
        which helps detect Unicode-based evasion attempts.

        Args:
            text: Input text

        Returns:
            Normalized text
        """
        if not text:
            return text

        # Apply NFKC normalization
        normalized = unicodedata.normalize("NFKC", text)

        # Replace known homoglyphs
        for homoglyph, replacement in self._homoglyphs.items():
            normalized = normalized.replace(homoglyph, replacement)

        return normalized

    def remove_control_characters(self, text: str) -> str:
        """
        Remove null bytes and other control characters.

        Args:
            text: Input text

        Returns:
            Text without control characters
        """
        if not text:
            return text

        return self._control_char_pattern.sub("", text)

    def normalize_whitespace_text(self, text: str) -> str:
        """
        Normalize whitespace (collapse multiple spaces, trim).

        Args:
            text: Input text

        Returns:
            Text with normalized whitespace
        """
        if not text:
            return text

        # Replace various whitespace with single space
        normalized = self._whitespace_pattern.sub(" ", text)
        return normalized.strip()

    def strip_comments(self, text: str) -> str:
        """
        Remove SQL comments from text.

        Handles:
        - Line comments: -- and #
        - Block comments: /* */

        Note: This is aggressive and may affect legitimate input.
        Use with caution.

        Args:
            text: Input text

        Returns:
            Text without SQL comments
        """
        if not text:
            return text

        result = text

        # Remove block comments first
        result = self._sql_block_comment.sub(" ", result)

        # Remove line comments
        result = self._sql_line_comment.sub(" ", result)
        result = self._mysql_comment.sub(" ", result)

        return result

    def normalize(self, text: str) -> str:
        """
        Apply all configured normalizations.

        Args:
            text: Input text

        Returns:
            Fully normalized text
        """
        if not text:
            return text

        result = text

        # Unicode normalization
        if self.normalize_unicode:
            result = self.normalize_unicode_text(result)

        # Remove control characters
        if self.remove_null_bytes:
            result = self.remove_control_characters(result)

        # Strip SQL comments (before whitespace normalization)
        if self.strip_sql_comments:
            result = self.strip_comments(result)

        # Normalize whitespace
        if self.normalize_whitespace:
            result = self.normalize_whitespace_text(result)

        # Lowercase
        if self.lowercase:
            result = result.lower()

        return result

    def get_transformations(self, text: str) -> dict[str, str]:
        """
        Get intermediate results of each transformation step.

        Useful for debugging and understanding what changed.

        Args:
            text: Input text

        Returns:
            Dictionary with transformation results
        """
        results = {"original": text}

        current = text

        if self.normalize_unicode:
            current = self.normalize_unicode_text(current)
            results["unicode_normalized"] = current

        if self.remove_null_bytes:
            current = self.remove_control_characters(current)
            results["control_chars_removed"] = current

        if self.strip_sql_comments:
            current = self.strip_comments(current)
            results["comments_stripped"] = current

        if self.normalize_whitespace:
            current = self.normalize_whitespace_text(current)
            results["whitespace_normalized"] = current

        if self.lowercase:
            current = current.lower()
            results["lowercased"] = current

        results["final"] = current
        return results


class SQLNormalizer(Normalizer):
    """
    SQL-specific normalizer with additional transformations.

    Extends base normalizer with SQL-aware processing.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # SQL-specific patterns
        self._multiple_spaces_pattern = re.compile(r" {2,}")
        self._string_literal_pattern = re.compile(r"'[^']*'|\"[^\"]*\"")

    def normalize_sql_operators(self, text: str) -> str:
        """
        Normalize SQL operator spacing.

        Args:
            text: Input text

        Returns:
            Text with normalized operators
        """
        if not text:
            return text

        result = text

        # Normalize common operators
        operators = ["=", "<>", "!=", "<=", ">=", "<", ">", "||", "&&"]
        for op in operators:
            # Add spaces around operators (but not inside strings)
            result = re.sub(
                rf"(?<!['\"])\s*{re.escape(op)}\s*(?!['\"])",
                f" {op} ",
                result,
            )

        # Collapse multiple spaces
        result = self._multiple_spaces_pattern.sub(" ", result)

        return result.strip()

    def extract_string_literals(self, text: str) -> list[str]:
        """
        Extract string literals from SQL-like text.

        Args:
            text: Input text

        Returns:
            List of extracted string literals
        """
        return self._string_literal_pattern.findall(text)

    def mask_string_literals(
        self, text: str, mask: str = "STRING_LITERAL"
    ) -> tuple[str, list[str]]:
        """
        Replace string literals with placeholders.

        Useful for pattern matching that should ignore string content.

        Args:
            text: Input text
            mask: Replacement string

        Returns:
            Tuple of (masked text, list of original literals)
        """
        literals = []

        def replacer(match: re.Match) -> str:
            literals.append(match.group(0))
            return mask

        masked = self._string_literal_pattern.sub(replacer, text)
        return masked, literals


def normalize_text(
    text: str,
    unicode_normalize: bool = True,
    remove_control: bool = True,
    normalize_ws: bool = True,
    lowercase: bool = True,
) -> str:
    """Convenience function for text normalization."""
    normalizer = Normalizer(
        normalize_unicode=unicode_normalize,
        remove_null_bytes=remove_control,
        normalize_whitespace=normalize_ws,
        lowercase=lowercase,
    )
    return normalizer.normalize(text)
