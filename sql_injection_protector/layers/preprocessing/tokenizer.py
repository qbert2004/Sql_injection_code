"""SQL-aware tokenizer for input analysis."""

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator, Optional


class TokenType(Enum):
    """Types of tokens recognized by the SQL tokenizer."""

    # Literals
    STRING = auto()
    NUMBER = auto()
    HEX_NUMBER = auto()

    # SQL Keywords
    KEYWORD = auto()
    FUNCTION = auto()
    OPERATOR = auto()

    # Delimiters
    PAREN_OPEN = auto()
    PAREN_CLOSE = auto()
    BRACKET_OPEN = auto()
    BRACKET_CLOSE = auto()
    COMMA = auto()
    SEMICOLON = auto()

    # Quotes
    SINGLE_QUOTE = auto()
    DOUBLE_QUOTE = auto()
    BACKTICK = auto()

    # Comments
    LINE_COMMENT = auto()
    BLOCK_COMMENT = auto()

    # Special
    WILDCARD = auto()
    IDENTIFIER = auto()
    WHITESPACE = auto()
    UNKNOWN = auto()


@dataclass
class Token:
    """Represents a single token."""

    type: TokenType
    value: str
    position: int
    length: int

    def __str__(self) -> str:
        return f"{self.type.name}({self.value!r})"


class SQLTokenizer:
    """
    SQL-aware tokenizer that recognizes SQL syntax elements.

    Used for:
    - Feature extraction (counting keywords, operators, etc.)
    - Pattern matching that respects SQL structure
    - Identifying suspicious token sequences
    """

    # SQL Keywords (subset for detection purposes)
    SQL_KEYWORDS = frozenset(
        [
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "create",
            "alter",
            "truncate",
            "from",
            "where",
            "and",
            "or",
            "not",
            "in",
            "like",
            "between",
            "is",
            "null",
            "true",
            "false",
            "union",
            "all",
            "except",
            "intersect",
            "join",
            "inner",
            "outer",
            "left",
            "right",
            "full",
            "cross",
            "on",
            "using",
            "group",
            "by",
            "having",
            "order",
            "asc",
            "desc",
            "limit",
            "offset",
            "as",
            "distinct",
            "case",
            "when",
            "then",
            "else",
            "end",
            "exists",
            "any",
            "some",
            "into",
            "values",
            "set",
            "table",
            "index",
            "view",
            "database",
            "schema",
            "grant",
            "revoke",
            "exec",
            "execute",
            "declare",
            "begin",
            "commit",
            "rollback",
            "savepoint",
            "transaction",
            "procedure",
            "function",
            "trigger",
            "cursor",
            "fetch",
            "open",
            "close",
            "deallocate",
            "top",
            "percent",
            "with",
            "recursive",
            "over",
            "partition",
            "row",
            "rows",
            "range",
            "preceding",
            "following",
            "current",
            "unbounded",
            "window",
            "filter",
        ]
    )

    # SQL Functions (dangerous ones highlighted)
    SQL_FUNCTIONS = frozenset(
        [
            # String functions
            "concat",
            "substring",
            "substr",
            "left",
            "right",
            "trim",
            "ltrim",
            "rtrim",
            "upper",
            "lower",
            "length",
            "len",
            "char",
            "chr",
            "ascii",
            "unicode",
            "replace",
            "reverse",
            "repeat",
            "space",
            "stuff",
            # Numeric functions
            "abs",
            "ceil",
            "floor",
            "round",
            "mod",
            "power",
            "sqrt",
            "rand",
            "random",
            # Date functions
            "now",
            "curdate",
            "curtime",
            "date",
            "time",
            "datetime",
            "timestamp",
            "dateadd",
            "datediff",
            "year",
            "month",
            "day",
            "hour",
            "minute",
            "second",
            # Aggregate functions
            "count",
            "sum",
            "avg",
            "min",
            "max",
            "group_concat",
            "string_agg",
            # Dangerous functions (SQLi indicators)
            "sleep",
            "benchmark",
            "waitfor",
            "delay",
            "pg_sleep",
            "load_file",
            "into_outfile",
            "into_dumpfile",
            "sys_eval",
            "sys_exec",
            "xp_cmdshell",
            "sp_executesql",
            "openrowset",
            "opendatasource",
            "bulk",
            "dbms_pipe",
            "utl_http",
            "utl_file",
            "utl_inaddr",
            # Information schema
            "version",
            "database",
            "user",
            "current_user",
            "session_user",
            "system_user",
            "schema",
            "table_name",
            "column_name",
            # Type conversion
            "cast",
            "convert",
            "coalesce",
            "nullif",
            "ifnull",
            "nvl",
            "isnull",
            # Conditional
            "if",
            "iff",
            "case",
            "decode",
        ]
    )

    # SQL Operators
    SQL_OPERATORS = frozenset(
        [
            "=",
            "<>",
            "!=",
            "<",
            ">",
            "<=",
            ">=",
            "+",
            "-",
            "*",
            "/",
            "%",
            "||",
            "&&",
            "|",
            "&",
            "^",
            "~",
            "<<",
            ">>",
            ":=",
            "+=",
            "-=",
            "*=",
            "/=",
        ]
    )

    def __init__(self):
        """Initialize tokenizer with compiled patterns."""
        # Token patterns (order matters - more specific first)
        self._patterns = [
            # Comments
            (TokenType.LINE_COMMENT, re.compile(r"--[^\n]*|#[^\n]*")),
            (TokenType.BLOCK_COMMENT, re.compile(r"/\*.*?\*/", re.DOTALL)),
            # Strings (with escape handling)
            (TokenType.STRING, re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")),
            # Numbers
            (TokenType.HEX_NUMBER, re.compile(r"0x[0-9A-Fa-f]+")),
            (TokenType.NUMBER, re.compile(r"\d+\.?\d*(?:[eE][+-]?\d+)?")),
            # Operators (multi-char first)
            (TokenType.OPERATOR, re.compile(r"<>|!=|<=|>=|:=|\|\||&&|<<|>>|\+=|-=|\*=|/=")),
            (TokenType.OPERATOR, re.compile(r"[=<>+\-*/%|&^~]")),
            # Delimiters
            (TokenType.PAREN_OPEN, re.compile(r"\(")),
            (TokenType.PAREN_CLOSE, re.compile(r"\)")),
            (TokenType.BRACKET_OPEN, re.compile(r"\[")),
            (TokenType.BRACKET_CLOSE, re.compile(r"\]")),
            (TokenType.COMMA, re.compile(r",")),
            (TokenType.SEMICOLON, re.compile(r";")),
            # Quotes (unmatched)
            (TokenType.SINGLE_QUOTE, re.compile(r"'")),
            (TokenType.DOUBLE_QUOTE, re.compile(r'"')),
            (TokenType.BACKTICK, re.compile(r"`")),
            # Wildcard
            (TokenType.WILDCARD, re.compile(r"\*")),
            # Identifiers/Keywords
            (TokenType.IDENTIFIER, re.compile(r"[A-Za-z_][A-Za-z0-9_]*")),
            # Whitespace
            (TokenType.WHITESPACE, re.compile(r"\s+")),
        ]

    def tokenize(self, text: str, skip_whitespace: bool = True) -> list[Token]:
        """
        Tokenize input text.

        Args:
            text: Input text to tokenize
            skip_whitespace: Whether to exclude whitespace tokens

        Returns:
            List of tokens
        """
        tokens = []
        pos = 0

        while pos < len(text):
            matched = False

            for token_type, pattern in self._patterns:
                match = pattern.match(text, pos)
                if match:
                    value = match.group(0)

                    # Classify identifiers as keywords/functions
                    if token_type == TokenType.IDENTIFIER:
                        lower_value = value.lower()
                        if lower_value in self.SQL_KEYWORDS:
                            token_type = TokenType.KEYWORD
                        elif lower_value in self.SQL_FUNCTIONS:
                            token_type = TokenType.FUNCTION

                    if not (skip_whitespace and token_type == TokenType.WHITESPACE):
                        tokens.append(
                            Token(
                                type=token_type,
                                value=value,
                                position=pos,
                                length=len(value),
                            )
                        )

                    pos = match.end()
                    matched = True
                    break

            if not matched:
                # Unknown character
                tokens.append(
                    Token(
                        type=TokenType.UNKNOWN,
                        value=text[pos],
                        position=pos,
                        length=1,
                    )
                )
                pos += 1

        return tokens

    def tokenize_iter(
        self, text: str, skip_whitespace: bool = True
    ) -> Iterator[Token]:
        """
        Tokenize input text as an iterator (memory efficient).

        Args:
            text: Input text to tokenize
            skip_whitespace: Whether to exclude whitespace tokens

        Yields:
            Token objects
        """
        pos = 0

        while pos < len(text):
            matched = False

            for token_type, pattern in self._patterns:
                match = pattern.match(text, pos)
                if match:
                    value = match.group(0)

                    # Classify identifiers
                    if token_type == TokenType.IDENTIFIER:
                        lower_value = value.lower()
                        if lower_value in self.SQL_KEYWORDS:
                            token_type = TokenType.KEYWORD
                        elif lower_value in self.SQL_FUNCTIONS:
                            token_type = TokenType.FUNCTION

                    if not (skip_whitespace and token_type == TokenType.WHITESPACE):
                        yield Token(
                            type=token_type,
                            value=value,
                            position=pos,
                            length=len(value),
                        )

                    pos = match.end()
                    matched = True
                    break

            if not matched:
                yield Token(
                    type=TokenType.UNKNOWN,
                    value=text[pos],
                    position=pos,
                    length=1,
                )
                pos += 1

    def get_token_counts(self, text: str) -> dict[str, int]:
        """
        Get counts of each token type.

        Args:
            text: Input text

        Returns:
            Dictionary mapping token type names to counts
        """
        counts: dict[str, int] = {}
        for token in self.tokenize(text):
            type_name = token.type.name
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts

    def get_keywords(self, text: str) -> list[str]:
        """Extract SQL keywords from text."""
        return [
            token.value.lower()
            for token in self.tokenize(text)
            if token.type == TokenType.KEYWORD
        ]

    def get_functions(self, text: str) -> list[str]:
        """Extract SQL functions from text."""
        return [
            token.value.lower()
            for token in self.tokenize(text)
            if token.type == TokenType.FUNCTION
        ]

    def has_suspicious_sequence(self, text: str) -> tuple[bool, Optional[str]]:
        """
        Check for suspicious token sequences.

        Returns:
            Tuple of (is_suspicious, reason)
        """
        tokens = self.tokenize(text)

        # Check for UNION SELECT
        for i, token in enumerate(tokens[:-1]):
            if (
                token.type == TokenType.KEYWORD
                and token.value.lower() == "union"
            ):
                next_token = tokens[i + 1]
                if (
                    next_token.type == TokenType.KEYWORD
                    and next_token.value.lower() in ("select", "all")
                ):
                    return True, "UNION SELECT detected"

        # Check for OR/AND 1=1 patterns
        for i, token in enumerate(tokens[:-2]):
            if (
                token.type == TokenType.KEYWORD
                and token.value.lower() in ("or", "and")
            ):
                if (
                    tokens[i + 1].type == TokenType.NUMBER
                    and tokens[i + 2].type == TokenType.OPERATOR
                    and tokens[i + 2].value == "="
                ):
                    if i + 3 < len(tokens) and tokens[i + 3].type == TokenType.NUMBER:
                        return True, "OR/AND number=number pattern detected"

        # Check for comment injection
        if any(t.type in (TokenType.LINE_COMMENT, TokenType.BLOCK_COMMENT) for t in tokens):
            return True, "SQL comment detected"

        # Check for dangerous functions
        dangerous_funcs = {
            "sleep",
            "benchmark",
            "waitfor",
            "load_file",
            "into_outfile",
            "xp_cmdshell",
            "sys_eval",
        }
        for token in tokens:
            if token.type == TokenType.FUNCTION and token.value.lower() in dangerous_funcs:
                return True, f"Dangerous function detected: {token.value}"

        return False, None


def tokenize(text: str) -> list[Token]:
    """Convenience function for tokenization."""
    tokenizer = SQLTokenizer()
    return tokenizer.tokenize(text)
