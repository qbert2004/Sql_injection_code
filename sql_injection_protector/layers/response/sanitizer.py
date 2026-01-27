"""Input sanitizer for SQL injection prevention."""

import html
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional


class SanitizationMode(Enum):
    """Sanitization mode."""

    ESCAPE = auto()      # Escape dangerous characters
    REMOVE = auto()      # Remove dangerous patterns
    PARAMETERIZE = auto()  # Convert to parameterized format


@dataclass
class SanitizationResult:
    """Result of sanitization."""

    original: str
    sanitized: str
    changes_made: list[str]
    is_modified: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original": self.original,
            "sanitized": self.sanitized,
            "changes_made": self.changes_made,
            "is_modified": self.is_modified,
        }


class InputSanitizer:
    """
    Context-aware input sanitizer for SQL injection prevention.

    Features:
    - Multiple sanitization modes
    - Context-aware escaping
    - Preserves legitimate input where possible
    - Detailed change tracking
    """

    # Characters that need escaping in SQL
    SQL_ESCAPE_CHARS = {
        "'": "''",
        "\\": "\\\\",
        "\x00": "",
        "\n": "\\n",
        "\r": "\\r",
        "\x1a": "\\Z",
    }

    # Patterns to remove in REMOVE mode
    DANGEROUS_PATTERNS = [
        (re.compile(r"--\s*$|--\s+", re.MULTILINE), ""),  # Line comments
        (re.compile(r"/\*.*?\*/", re.DOTALL), ""),  # Block comments
        (re.compile(r"#\s*$|#\s+", re.MULTILINE), ""),  # MySQL comments
        (re.compile(r";\s*$", re.MULTILINE), ""),  # Trailing semicolons
        (re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE), ""),  # UNION SELECT
        (re.compile(r"\bexec\s*\(", re.IGNORECASE), ""),  # EXEC
        (re.compile(r"\bxp_\w+", re.IGNORECASE), ""),  # xp_ procedures
    ]

    def __init__(
        self,
        mode: SanitizationMode = SanitizationMode.ESCAPE,
        max_length: int = 10000,
        preserve_case: bool = True,
    ):
        """
        Initialize sanitizer.

        Args:
            mode: Default sanitization mode
            max_length: Maximum input length
            preserve_case: Whether to preserve original case
        """
        self.mode = mode
        self.max_length = max_length
        self.preserve_case = preserve_case

    def sanitize(
        self,
        text: str,
        mode: Optional[SanitizationMode] = None,
        context: str = "general",
    ) -> SanitizationResult:
        """
        Sanitize input text.

        Args:
            text: Input text to sanitize
            mode: Sanitization mode (uses default if None)
            context: Context for context-aware sanitization

        Returns:
            SanitizationResult with sanitized text
        """
        if not text:
            return SanitizationResult(
                original="",
                sanitized="",
                changes_made=[],
                is_modified=False,
            )

        mode = mode or self.mode
        changes = []

        # Truncate if too long
        if len(text) > self.max_length:
            text = text[:self.max_length]
            changes.append(f"truncated to {self.max_length} chars")

        if mode == SanitizationMode.ESCAPE:
            sanitized = self._escape_sql(text, changes)
        elif mode == SanitizationMode.REMOVE:
            sanitized = self._remove_dangerous(text, changes)
        elif mode == SanitizationMode.PARAMETERIZE:
            sanitized = self._parameterize(text, changes)
        else:
            sanitized = text

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )

    def _escape_sql(self, text: str, changes: list[str]) -> str:
        """Escape SQL special characters."""
        result = text

        for char, escaped in self.SQL_ESCAPE_CHARS.items():
            if char in result:
                count = result.count(char)
                result = result.replace(char, escaped)
                changes.append(f"escaped '{repr(char)}' ({count}x)")

        return result

    def _remove_dangerous(self, text: str, changes: list[str]) -> str:
        """Remove dangerous SQL patterns."""
        result = text

        for pattern, replacement in self.DANGEROUS_PATTERNS:
            if pattern.search(result):
                result = pattern.sub(replacement, result)
                changes.append(f"removed pattern: {pattern.pattern[:30]}")

        # Remove multiple spaces
        result = re.sub(r"\s+", " ", result).strip()
        if result != text.strip():
            changes.append("normalized whitespace")

        return result

    def _parameterize(self, text: str, changes: list[str]) -> str:
        """Convert to parameterized format (placeholder)."""
        # This is a simplified version - real parameterization
        # should be done at the database layer
        result = text

        # Replace potential injection points with placeholders
        # This is mainly for logging/analysis purposes
        patterns = [
            (re.compile(r"'[^']*'"), "?"),
            (re.compile(r"\d+"), "?"),
        ]

        for pattern, placeholder in patterns:
            matches = pattern.findall(result)
            if matches:
                result = pattern.sub(placeholder, result)
                changes.append(f"parameterized {len(matches)} values")

        return result

    def escape_for_like(self, text: str) -> str:
        """
        Escape text for use in LIKE patterns.

        Escapes %, _, and \ characters.
        """
        text = text.replace("\\", "\\\\")
        text = text.replace("%", "\\%")
        text = text.replace("_", "\\_")
        return text

    def escape_identifier(self, identifier: str) -> str:
        """
        Escape a SQL identifier (table/column name).

        Uses backticks for MySQL compatibility.
        """
        # Remove any existing backticks and escape
        cleaned = identifier.replace("`", "``")
        return f"`{cleaned}`"

    def sanitize_dict(
        self,
        data: dict[str, str],
        mode: Optional[SanitizationMode] = None,
    ) -> dict[str, SanitizationResult]:
        """
        Sanitize all string values in a dictionary.

        Args:
            data: Dictionary with string values
            mode: Sanitization mode

        Returns:
            Dictionary mapping keys to SanitizationResults
        """
        results = {}
        for key, value in data.items():
            if isinstance(value, str):
                results[key] = self.sanitize(value, mode)
        return results

    def is_safe(self, text: str) -> bool:
        """
        Check if text appears safe (no dangerous patterns).

        This is a quick check, not a guarantee of safety.
        """
        if not text:
            return True

        # Check for obvious dangerous patterns
        dangerous_indicators = [
            "'",
            '"',
            "--",
            "/*",
            "*/",
            ";",
            "union",
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "exec",
        ]

        text_lower = text.lower()
        return not any(indicator in text_lower for indicator in dangerous_indicators)


class ContextAwareSanitizer(InputSanitizer):
    """
    Advanced sanitizer that considers the context of the input.

    Different contexts (URL, form field, JSON, etc.) require
    different sanitization strategies.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._context_handlers = {
            "url_param": self._sanitize_url_param,
            "form_field": self._sanitize_form_field,
            "json_value": self._sanitize_json_value,
            "header": self._sanitize_header,
            "cookie": self._sanitize_cookie,
        }

    def sanitize(
        self,
        text: str,
        mode: Optional[SanitizationMode] = None,
        context: str = "general",
    ) -> SanitizationResult:
        """Sanitize with context awareness."""
        if context in self._context_handlers:
            return self._context_handlers[context](text, mode)
        return super().sanitize(text, mode, context)

    def _sanitize_url_param(
        self,
        text: str,
        mode: Optional[SanitizationMode],
    ) -> SanitizationResult:
        """Sanitize URL parameter value."""
        from urllib.parse import quote

        changes = []

        # URL encode special characters
        sanitized = quote(text, safe="")
        if sanitized != text:
            changes.append("URL encoded")

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )

    def _sanitize_form_field(
        self,
        text: str,
        mode: Optional[SanitizationMode],
    ) -> SanitizationResult:
        """Sanitize form field value."""
        changes = []
        sanitized = text

        # HTML encode to prevent XSS
        sanitized = html.escape(sanitized)
        if sanitized != text:
            changes.append("HTML escaped")

        # Then apply SQL escaping
        for char, escaped in self.SQL_ESCAPE_CHARS.items():
            if char in sanitized:
                sanitized = sanitized.replace(char, escaped)
                changes.append(f"SQL escaped '{repr(char)}'")

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )

    def _sanitize_json_value(
        self,
        text: str,
        mode: Optional[SanitizationMode],
    ) -> SanitizationResult:
        """Sanitize JSON string value."""
        import json

        changes = []

        # Use JSON encoding for proper escaping
        try:
            # Encode and decode to get properly escaped string
            sanitized = json.dumps(text)[1:-1]  # Remove surrounding quotes
            if sanitized != text:
                changes.append("JSON escaped")
        except Exception:
            sanitized = text

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )

    def _sanitize_header(
        self,
        text: str,
        mode: Optional[SanitizationMode],
    ) -> SanitizationResult:
        """Sanitize HTTP header value."""
        changes = []
        sanitized = text

        # Remove newlines (header injection prevention)
        if "\n" in sanitized or "\r" in sanitized:
            sanitized = sanitized.replace("\r", "").replace("\n", "")
            changes.append("removed newlines")

        # Remove null bytes
        if "\x00" in sanitized:
            sanitized = sanitized.replace("\x00", "")
            changes.append("removed null bytes")

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )

    def _sanitize_cookie(
        self,
        text: str,
        mode: Optional[SanitizationMode],
    ) -> SanitizationResult:
        """Sanitize cookie value."""
        changes = []
        sanitized = text

        # Remove semicolons (cookie injection)
        if ";" in sanitized:
            sanitized = sanitized.replace(";", "")
            changes.append("removed semicolons")

        # Apply header sanitization
        header_result = self._sanitize_header(sanitized, mode)
        sanitized = header_result.sanitized
        changes.extend(header_result.changes_made)

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            changes_made=changes,
            is_modified=sanitized != text,
        )
