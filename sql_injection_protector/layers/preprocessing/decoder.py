"""Decoders for URL, HTML, Base64, and other encodings."""

import base64
import html
import re
from typing import Optional
from urllib.parse import unquote, unquote_plus


class Decoder:
    """
    Multi-format decoder with iterative decoding support.

    Handles:
    - URL encoding (percent encoding)
    - HTML entities
    - Base64 encoding
    - Unicode escape sequences
    - Hex encoding
    - Double/triple encoding attacks
    """

    def __init__(self, max_iterations: int = 5):
        """
        Initialize decoder.

        Args:
            max_iterations: Maximum decoding iterations to prevent infinite loops
        """
        self.max_iterations = max_iterations

        # Patterns for detection
        self._url_encoded_pattern = re.compile(r"%[0-9A-Fa-f]{2}")
        self._html_entity_pattern = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|\w+);")
        self._base64_pattern = re.compile(
            r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
        )
        self._unicode_escape_pattern = re.compile(r"\\u[0-9A-Fa-f]{4}")
        self._hex_pattern = re.compile(r"(?:0x|\\x)[0-9A-Fa-f]{2}")

    def decode_url(self, text: str, plus_as_space: bool = True) -> str:
        """
        Decode URL-encoded string iteratively.

        Args:
            text: URL-encoded string
            plus_as_space: Treat + as space (form encoding)

        Returns:
            Decoded string
        """
        if not text:
            return text

        decoded = text
        for _ in range(self.max_iterations):
            if plus_as_space:
                new_decoded = unquote_plus(decoded)
            else:
                new_decoded = unquote(decoded)

            if new_decoded == decoded:
                break
            decoded = new_decoded

        return decoded

    def decode_html_entities(self, text: str) -> str:
        """
        Decode HTML entities.

        Args:
            text: String with HTML entities

        Returns:
            Decoded string
        """
        if not text:
            return text

        decoded = text
        for _ in range(self.max_iterations):
            new_decoded = html.unescape(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded

        return decoded

    def decode_base64(self, text: str) -> Optional[str]:
        """
        Attempt to decode Base64 string.

        Args:
            text: Potential Base64 string

        Returns:
            Decoded string or None if not valid Base64
        """
        if not text or len(text) < 4:
            return None

        # Check if it looks like Base64
        cleaned = text.strip()
        if not self._base64_pattern.match(cleaned):
            return None

        try:
            # Add padding if needed
            padding = 4 - (len(cleaned) % 4)
            if padding != 4:
                cleaned += "=" * padding

            decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")

            # Only return if result is printable
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return decoded
        except Exception:
            pass

        return None

    def decode_unicode_escapes(self, text: str) -> str:
        """
        Decode Unicode escape sequences (\\uXXXX).

        Args:
            text: String with Unicode escapes

        Returns:
            Decoded string
        """
        if not text or "\\u" not in text:
            return text

        def replace_unicode(match: re.Match) -> str:
            try:
                code_point = int(match.group(0)[2:], 16)
                return chr(code_point)
            except (ValueError, OverflowError):
                return match.group(0)

        return self._unicode_escape_pattern.sub(replace_unicode, text)

    def decode_hex(self, text: str) -> str:
        """
        Decode hex-encoded characters (0xXX or \\xXX).

        Args:
            text: String with hex encoding

        Returns:
            Decoded string
        """
        if not text:
            return text

        def replace_hex(match: re.Match) -> str:
            try:
                hex_str = match.group(0)
                if hex_str.startswith("0x"):
                    byte_val = int(hex_str[2:], 16)
                else:  # \x
                    byte_val = int(hex_str[2:], 16)
                return chr(byte_val)
            except (ValueError, OverflowError):
                return match.group(0)

        return self._hex_pattern.sub(replace_hex, text)

    def decode_all(self, text: str, include_base64: bool = False) -> str:
        """
        Apply all decoders in sequence.

        Args:
            text: String to decode
            include_base64: Whether to attempt Base64 decoding

        Returns:
            Fully decoded string
        """
        if not text:
            return text

        decoded = text

        for _ in range(self.max_iterations):
            previous = decoded

            # URL decoding (most common)
            decoded = self.decode_url(decoded)

            # HTML entities
            decoded = self.decode_html_entities(decoded)

            # Unicode escapes
            decoded = self.decode_unicode_escapes(decoded)

            # Hex encoding
            decoded = self.decode_hex(decoded)

            # Base64 (optional, can produce false positives)
            if include_base64:
                base64_decoded = self.decode_base64(decoded)
                if base64_decoded:
                    decoded = base64_decoded

            # Stop if no changes
            if decoded == previous:
                break

        return decoded

    def has_encoding(self, text: str) -> dict[str, bool]:
        """
        Check what types of encoding are present.

        Args:
            text: String to check

        Returns:
            Dictionary of encoding types and their presence
        """
        return {
            "url_encoded": bool(self._url_encoded_pattern.search(text)),
            "html_entities": bool(self._html_entity_pattern.search(text)),
            "base64": bool(self._base64_pattern.match(text.strip())),
            "unicode_escapes": bool(self._unicode_escape_pattern.search(text)),
            "hex_encoded": bool(self._hex_pattern.search(text)),
        }

    def get_encoding_depth(self, text: str) -> int:
        """
        Estimate the depth of encoding (for detecting evasion).

        Args:
            text: String to analyze

        Returns:
            Estimated encoding depth (0 = no encoding)
        """
        depth = 0
        current = text

        for _ in range(self.max_iterations):
            decoded = self.decode_all(current, include_base64=False)
            if decoded == current:
                break
            current = decoded
            depth += 1

        return depth


def decode_url_iterative(text: str, max_iterations: int = 5) -> str:
    """Convenience function for URL decoding."""
    decoder = Decoder(max_iterations=max_iterations)
    return decoder.decode_url(text)


def decode_all(text: str, max_iterations: int = 5) -> str:
    """Convenience function for full decoding."""
    decoder = Decoder(max_iterations=max_iterations)
    return decoder.decode_all(text)
