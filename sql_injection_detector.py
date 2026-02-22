"""
SQL Injection Detector — Production Module (v3.1)
===================================================
Multi-layer ensemble detection with semantic validation, attack typing,
explainability, and SIEM-ready output.

Architecture:
    Layer 0: Input Normalization (Unicode NFKC, recursive URL decode, null strip)
    Layer 1: Lexical Pre-filter (fast-path SAFE exit)
    Layer 2: ML Ensemble (RF + CNN, 2-model weighted voting)
    Layer 3: SQL Semantic Validation (structural validity + attack typing)
    Layer 4: Decision Engine (constrained by semantic gating invariant)
    Layer 5: Severity & Action Mapping (attack-type-aware)
    Layer 6: Explainability Module (per-layer decision trace + SIEM fields)

Critical Invariant:
    ML alone CANNOT classify as INJECTION without semantic_score >= tau_semantic_min.
    Semantic alone CAN override ML when semantic_score >= tau_semantic_override.

Usage:
    from sql_injection_detector import SQLInjectionEnsemble

    detector = SQLInjectionEnsemble()
    result = detector.detect("' OR '1'='1")

    print(result['decision'])          # INJECTION
    print(result['severity'])          # MEDIUM
    print(result['attack_type'])       # BOOLEAN_BASED
    print(result['explanation'])       # Full decision trace
"""

import hashlib
import html
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from logger import ensure_logging, get_logger

ensure_logging()
log = get_logger("sqli_detector")

MODULE_DIR = Path(__file__).parent


# ═══════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════

class Decision(Enum):
    SAFE = "SAFE"
    INVALID = "INVALID"
    SUSPICIOUS = "SUSPICIOUS"
    INJECTION = "INJECTION"


class Action(Enum):
    ALLOW = "ALLOW"
    LOG = "LOG"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"
    ALERT = "ALERT"


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(Enum):
    NONE = "NONE"
    BOOLEAN_BASED = "BOOLEAN_BASED"
    UNION_BASED = "UNION_BASED"
    STACKED_QUERY = "STACKED_QUERY"
    TIME_BASED = "TIME_BASED"
    ERROR_BASED = "ERROR_BASED"
    COMMENT_TRUNCATION = "COMMENT_TRUNCATION"
    OUT_OF_BAND = "OUT_OF_BAND"
    OS_COMMAND = "OS_COMMAND"


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

@dataclass
class EnsembleConfig:
    """Configuration for ensemble decision thresholds."""
    # Model weights for 2-model ensemble (RF + CNN)
    w_rf: float = 0.35
    w_cnn: float = 0.65

    # Decision thresholds
    tau_high: float = 0.60
    tau_low: float = 0.40
    tau_safe: float = 0.30

    # Single-model override thresholds
    tau_cnn_override: float = 0.75
    tau_rf_strong: float = 0.70

    # Semantic gating (CRITICAL: enforces the architectural invariant)
    tau_semantic_min: float = 2.0
    tau_semantic_override: float = 6.0

    # Model agreement
    tau_model_divergence: float = 0.40
    agreement_bonus: float = 0.10

    # Input limits
    max_input_length: int = 10000


# ═══════════════════════════════════════════════════════════════════
# LAYER 0: INPUT NORMALIZATION
# ═══════════════════════════════════════════════════════════════════

class InputNormalizer:
    """
    Multi-stage input normalization to defeat encoding-based evasion.

    Pipeline:
        1. Length validation
        2. Unicode NFKC normalization (fullwidth → ASCII)
        3. Strip zero-width / invisible characters
        4. Strip combining diacritics from ASCII-range base characters
        5. Recursive URL decode (max depth=3)
        6. HTML entity decode
        7. Null byte stripping
        8. Lowercase
        9. MySQL conditional comment expansion: /*!UNION*/ → UNION
       10. Inline comment removal: UN/**/ION → UNION
       11. Whitespace collapse
    """

    # Comprehensive homoglyph mappings (fullwidth/special → ASCII)
    HOMOGLYPH_MAP = str.maketrans({
        # Fullwidth uppercase A-Z (U+FF21 to U+FF3A)
        **{chr(0xFF21 + i): chr(ord('A') + i) for i in range(26)},
        # Fullwidth lowercase a-z (U+FF41 to U+FF5A)
        **{chr(0xFF41 + i): chr(ord('a') + i) for i in range(26)},
        # Fullwidth digits 0-9 (U+FF10 to U+FF19)
        **{chr(0xFF10 + i): chr(ord('0') + i) for i in range(10)},
        # Fullwidth punctuation
        '\uff07': "'", '\uff02': '"', '\uff1b': ';', '\uff0d': '-',
        '\uff08': '(', '\uff09': ')', '\uff1d': '=', '\uff1c': '<',
        '\uff1e': '>', '\uff0c': ',', '\uff0e': '.', '\uff3b': '[',
        '\uff3d': ']', '\uff5b': '{', '\uff5d': '}', '\uff0f': '/',
        '\uff20': '@', '\uff03': '#', '\uff04': '$', '\uff05': '%',
        '\uff06': '&', '\uff0a': '*', '\uff0b': '+', '\uff3f': '_',
        # Smart quotes and special quote chars
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u00b4': "'", '\u0060': "'", '\u02b9': "'", '\u02bc': "'",
    })

    # Zero-width and invisible characters used for keyword splitting bypass
    _ZERO_WIDTH_RE = re.compile(
        '['
        '\u200b'   # zero-width space
        '\u200c'   # zero-width non-joiner
        '\u200d'   # zero-width joiner
        '\u200e'   # left-to-right mark
        '\u200f'   # right-to-left mark
        '\u2060'   # word joiner
        '\u2061'   # function application
        '\u2062'   # invisible times
        '\u2063'   # invisible separator
        '\u2064'   # invisible plus
        '\ufeff'   # BOM / zero-width no-break space
        '\u00ad'   # soft hyphen
        '\u034f'   # combining grapheme joiner
        '\u061c'   # arabic letter mark
        '\u115f'   # hangul choseong filler
        '\u1160'   # hangul jungseong filler
        '\u17b4'   # khmer vowel inherent aq
        '\u17b5'   # khmer vowel inherent aa
        '\u180e'   # mongolian vowel separator
        # Bidirectional override / isolate characters (Fix E — bypass via RTL/LTR)
        '\u202a'   # left-to-right embedding
        '\u202b'   # right-to-left embedding
        '\u202c'   # pop directional formatting
        '\u202d'   # left-to-right override  ← primary bypass vector
        '\u202e'   # right-to-left override  ← primary bypass vector
        '\u2066'   # left-to-right isolate
        '\u2067'   # right-to-left isolate
        '\u2068'   # first strong isolate
        '\u2069'   # pop directional isolate
        ']+'
    )

    # Math styled letter blocks → ASCII (Bold, Italic, Script, Fraktur, etc.)
    @staticmethod
    def _build_math_styled_map() -> dict[int, str]:
        """Build translation table for Mathematical Alphanumeric Symbols."""
        table = {}
        # Each block: (start_codepoint, ascii_start_char, count)
        math_blocks = [
            (0x1D400, 'A', 26),  # Bold uppercase
            (0x1D41A, 'a', 26),  # Bold lowercase
            (0x1D434, 'A', 26),  # Italic uppercase
            (0x1D44E, 'a', 26),  # Italic lowercase
            (0x1D468, 'A', 26),  # Bold Italic uppercase
            (0x1D482, 'a', 26),  # Bold Italic lowercase
            (0x1D49C, 'A', 26),  # Script uppercase
            (0x1D4B6, 'a', 26),  # Script lowercase
            (0x1D4D0, 'A', 26),  # Bold Script uppercase
            (0x1D4EA, 'a', 26),  # Bold Script lowercase
            (0x1D504, 'A', 26),  # Fraktur uppercase
            (0x1D51E, 'a', 26),  # Fraktur lowercase
            (0x1D56C, 'A', 26),  # Bold Fraktur uppercase
            (0x1D586, 'a', 26),  # Bold Fraktur lowercase
            (0x1D5A0, 'A', 26),  # Sans-Serif uppercase
            (0x1D5BA, 'a', 26),  # Sans-Serif lowercase
            (0x1D5D4, 'A', 26),  # Sans-Serif Bold uppercase
            (0x1D5EE, 'a', 26),  # Sans-Serif Bold lowercase
            (0x1D608, 'A', 26),  # Sans-Serif Italic uppercase
            (0x1D622, 'a', 26),  # Sans-Serif Italic lowercase
            (0x1D63C, 'A', 26),  # Sans-Serif Bold Italic uppercase
            (0x1D656, 'a', 26),  # Sans-Serif Bold Italic lowercase
            (0x1D670, 'A', 26),  # Monospace uppercase
            (0x1D68A, 'a', 26),  # Monospace lowercase
            (0x1D7CE, '0', 10),  # Bold digits
            (0x1D7D8, '0', 10),  # Double-struck digits
            (0x1D7E2, '0', 10),  # Sans-Serif digits
            (0x1D7EC, '0', 10),  # Sans-Serif Bold digits
            (0x1D7F6, '0', 10),  # Monospace digits
        ]
        for start, ascii_start, count in math_blocks:
            for i in range(count):
                table[start + i] = chr(ord(ascii_start) + i)
        return table

    MATH_STYLED_MAP = str.maketrans(_build_math_styled_map.__func__())

    @staticmethod
    def _strip_combining_marks(text: str) -> str:
        """Remove combining diacritical marks from ASCII base characters.

        Handles evasion like S̀ELECT (S + combining grave accent) by stripping
        the combining marks while preserving the base ASCII character.
        Only strips marks that follow ASCII characters (0x00-0x7F) to avoid
        destroying legitimate non-Latin text.
        """
        result = []
        i = 0
        while i < len(text):
            ch = text[i]
            result.append(ch)
            # If current char is ASCII, skip any combining marks that follow
            if ord(ch) < 128:
                i += 1
                while i < len(text) and unicodedata.category(text[i]) == 'Mn':
                    i += 1
            else:
                i += 1
        return ''.join(result)

    @classmethod
    def normalize(cls, text: str, max_length: int = 10000) -> tuple[str, dict[str, Any]]:
        """
        Normalize input through the full pipeline.

        Returns:
            Tuple of (normalized_text, normalization_metadata)
        """
        metadata = {
            'original_length': len(text),
            'transformations': [],
            'was_truncated': False,
        }

        # 1. Length validation
        if len(text) > max_length:
            text = text[:max_length]
            metadata['was_truncated'] = True
            metadata['transformations'].append('truncated')

        # 2. Unicode NFKC normalization
        normalized = unicodedata.normalize('NFKC', text)
        if normalized != text:
            metadata['transformations'].append('unicode_nfkc')
        text = normalized

        # 3. Homoglyph mapping (fullwidth → ASCII)
        mapped = text.translate(cls.HOMOGLYPH_MAP)
        if mapped != text:
            metadata['transformations'].append('homoglyph_map')
        text = mapped

        # 4. Math styled Unicode → ASCII (Bold/Italic/Script/Fraktur/Monospace)
        math_mapped = text.translate(cls.MATH_STYLED_MAP)
        if math_mapped != text:
            metadata['transformations'].append('math_styled_map')
        text = math_mapped

        # 5. Strip zero-width / invisible characters
        stripped = cls._ZERO_WIDTH_RE.sub('', text)
        if len(stripped) != len(text):
            metadata['transformations'].append('zero_width_strip')
        text = stripped

        # 6. Strip combining diacritical marks from ASCII base chars
        no_diacritics = cls._strip_combining_marks(text)
        if no_diacritics != text:
            metadata['transformations'].append('combining_mark_strip')
        text = no_diacritics

        # 7. Recursive URL decode (max depth=3)
        for depth in range(3):
            decoded = urllib.parse.unquote(text)
            if decoded == text:
                break
            text = decoded
            metadata['transformations'].append(f'url_decode_depth_{depth + 1}')

        # 8. HTML entity decode — loop until stable to handle double-encoded entities
        # e.g. &#x26;#x27; → &#x27; (pass 1) → ' (pass 2). Cap at 4 iterations. (Fix D)
        _html_decode_count = 0
        for _html_depth in range(4):
            html_decoded = html.unescape(text)
            if html_decoded == text:
                break
            text = html_decoded
            _html_decode_count += 1
        if _html_decode_count > 0:
            metadata['transformations'].append('html_entity_decode')
            if _html_decode_count > 1:
                metadata['transformations'].append(f'html_entity_double_decode_{_html_decode_count}x')

        # 9. Null byte stripping
        if '\x00' in text:
            text = text.replace('\x00', '')
            metadata['transformations'].append('null_byte_strip')

        # 10. Lowercase
        text = text.lower()

        # 11. MySQL conditional comment expansion: /*!UNION*/ → UNION
        # Must run BEFORE general comment stripping so content is preserved.
        # Handles /*!UNION*/, /*!50000UNION*/, and multi-word /*!50000UNION SELECT*/
        expanded = re.sub(r'/\*!(\d*)(.*?)\*/', r'\2', text)
        if expanded != text:
            metadata['transformations'].append('mysql_conditional_expand')
        text = expanded

        # 12. Inline comment removal (reassembles split keywords:
        # UN/**/ION → UNION, DR/**/OP → DROP)
        # Use a callback to insert a space when comment sits between two
        # word-characters (prevents SELECT/*a*/FROM → SELECTFROM merging)
        # but remove entirely when touching non-word (DR/**/OP → DROP).
        # Iterative stripping handles nested comments: UN/*/**/*/ION
        _sql_keywords_for_merge = {
            'select', 'union', 'insert', 'update', 'delete',
            'drop', 'truncate', 'alter', 'create', 'exec',
            'execute', 'table', 'from', 'where', 'having',
            'group', 'order', 'sleep', 'benchmark', 'waitfor',
            'concat', 'char', 'ascii', 'substring', 'between',
            'values', 'into', 'like', 'null', 'grant', 'revoke',
            'shutdown', 'schema', 'database', 'version',
            # Dialect keywords needed for fragment reassembly (Fix A)
            'pragma', 'bulk', 'load', 'reconfigure', 'openrowset', 'openquery',
            # Intermediate 3-4 fragment merge steps (Fix 1)
            # Allows multi-pass pair-merging of 3-4 fragment keyword splits.
            # e.g. SE/**/L/**/ECT: pass1 se+l='sel'(in set)→ SEL ECT,
            #                      pass2 sel+ect='select'(in set)→ SELECT
            'sel', 'se',          # SELECT: SE + L + ECT
            'dro',                # DROP:   DR + O + P
            'del',                # DELETE: DE + L + ETE
            'ins',                # INSERT: IN + S + ERT
            'un', 'uni', 'unio',  # UNION:  U  + N + I + ON
            'tab',                # TABLE:  TA + B + LE
            'fro',                # FROM:   FR + O + M
            'int',                # INTO:   IN + T + O
        }
        had_comments = False
        for _ in range(10):  # increased from 5 → 10 to handle 6-7 nesting levels (Fix B)
            current_text = text

            def _comment_replacer(m: re.Match, _src=current_text) -> str:
                start, end = m.start(), m.end()
                left_is_word = start > 0 and _src[start - 1].isalnum()
                right_is_word = end < len(_src) and _src[end].isalnum()
                if left_is_word and right_is_word:
                    left_frag = _src[max(0, start - 10):start]
                    right_frag = _src[end:end + 10]
                    left_word = re.search(r'(\w+)$', left_frag)
                    right_word = re.search(r'^(\w+)', right_frag)
                    if left_word and right_word:
                        merged = (left_word.group(1) + right_word.group(1)).lower()
                        if merged in _sql_keywords_for_merge:
                            return ''  # Merge: DR + OP → DROP
                    return ' '  # Keep separated: SELECT + username → SELECT username
                return ''  # Non-word boundary: remove entirely

            text = re.sub(r'/\*.*?\*/', _comment_replacer, text)
            if text == current_text:
                break  # No more comments to strip
            had_comments = True

        if had_comments:
            metadata['transformations'].append('comment_strip')
            # Strip orphan comment markers left by nested comment evasion
            # (e.g. UN/*/**/*/ION → UN/*/ION → strip /*/ → UNION)
            # Fix 2: Also strip word-adjacent /* debris from deep-nested patterns.
            # e.g. SE/*/*/*/*/LECT → loop leaves se**/lect → strip */ → se*lect
            # The (?<=\w)[/*]+(?=\w) removes stray * and / chars between word chars.
            # SELECT * FROM is safe: space before * means lookbehind fails (space not \w).
            text = re.sub(r'/\*|\*/|(?<=\w)[/*]+(?=\w)', '', text)

            # Fix A: Reassemble multi-fragment keyword splits produced by successive
            # comment removals. After the loop, "UN/**/I/**/ON" may remain as
            # "UN I ON" because each 2-fragment merge check failed (UNI, ION not keywords).
            # Scan for space-separated token pairs whose concatenation IS a SQL keyword
            # and collapse them. Loop until stable (handles 4+ fragment chains).
            #
            # Pre-collapse multiple spaces to single space so that space-padded
            # comments like "UN /**/ ION" → "UN  ION" → "UN ION" before merging.
            # The \b(\w+) (\w+)\b pattern only matches a single space between words.
            text = re.sub(r' {2,}', ' ', text)
            _kw_merge_re = re.compile(r'\b(\w+) (\w+)\b')
            for _frag_pass in range(8):
                _prev_text = text
                def _fragment_joiner(m: re.Match, _kws=_sql_keywords_for_merge) -> str:
                    merged = (m.group(1) + m.group(2)).lower()
                    return (m.group(1) + m.group(2)) if merged in _kws else m.group(0)
                text = _kw_merge_re.sub(_fragment_joiner, text)
                if text == _prev_text:
                    break

            # Fix 1b: Handle "consumed fragment" residuals that pair-merger can't reach
            # because a preceding word "consumed" one member of the pair.
            # e.g. after merging DROP, the pair "tab le" is adjacent but DROP already
            # consumed "tab"'s left neighbour in the non-overlapping scan.
            _leftover_pairs = [
                (r'\btab le\b', 'table'),   # TA/**/B/**/LE residual
                (r'\bfro m\b', 'from'),     # FR/**/O/**/M residual
                (r'\bint o\b', 'into'),     # IN/**/T/**/O residual (post-insert)
            ]
            for _lp_pat, _lp_rep in _leftover_pairs:
                text = re.sub(_lp_pat, _lp_rep, text, flags=re.I)
            # One final pass after targeted fixes to catch any newly created mergeable pairs
            for _frag_pass2 in range(4):
                _prev2 = text
                text = _kw_merge_re.sub(_fragment_joiner, text)
                if text == _prev2:
                    break

        text_no_comments = text

        # 13. Whitespace collapse
        text_no_comments = re.sub(r'\s+', ' ', text_no_comments).strip()

        metadata['normalized_length'] = len(text_no_comments)

        return text_no_comments, metadata


# ═══════════════════════════════════════════════════════════════════
# LAYER 1: LEXICAL PRE-FILTER
# ═══════════════════════════════════════════════════════════════════

class LexicalPreFilter:
    """
    Fast lexical scan to provide early SAFE exit for clean input.

    IMPORTANT: This layer NEVER classifies as INJECTION.
    It only produces: is_sql_like (bool) + lexical_score + matched_patterns.
    """

    # Keywords that indicate SQL context when present
    SQL_INDICATORS = re.compile(
        r"(?i)\b(select|union|insert|update|delete|drop|truncate|alter|create|"
        r"exec|execute|grant|revoke|shutdown|xp_|sp_)\b"
    )

    LOGIC_INDICATORS = re.compile(
        r"(?i)\b(or|and)\b"
    )

    SQL_FUNCTIONS = re.compile(
        r"(?i)(sleep|benchmark|waitfor|pg_sleep|load_file|"
        r"concat|char|ascii|substring|substr|mid|version|database|"
        r"user|current_user|schema|extractvalue|updatexml|"
        r"dbms_pipe|utl_inaddr|utl_http|utl_file|"
        r"xp_cmdshell|xp_dirtree|xp_regread|sp_configure|"
        r"sp_executesql|sp_makewebtask|get_host_address)\s*\("
    )

    STRUCTURAL_MARKERS = re.compile(
        r"(--|/\*|#|\x27|\x22|;|=.*=|\|\||&&)"
    )

    @classmethod
    def scan(cls, normalized_text: str) -> dict[str, Any]:
        """
        Fast lexical scan of normalized input.

        Returns:
            Dict with is_sql_like, lexical_score, matched_keywords, matched_patterns
        """
        score = 0
        matched_keywords = []
        matched_patterns = []

        # SQL keywords
        for m in cls.SQL_INDICATORS.finditer(normalized_text):
            score += 3
            kw = m.group(1).lower()
            if kw not in matched_keywords:
                matched_keywords.append(kw)

        # Logic operators (only +1 each, need context)
        for m in cls.LOGIC_INDICATORS.finditer(normalized_text):
            score += 1
            kw = m.group(1).lower()
            if kw not in matched_keywords:
                matched_keywords.append(kw)

        # SQL functions
        for m in cls.SQL_FUNCTIONS.finditer(normalized_text):
            score += 4
            fn = m.group(0).strip().rstrip('(')
            if fn not in matched_patterns:
                matched_patterns.append(f"function:{fn}")

        # Structural markers
        struct_count = len(cls.STRUCTURAL_MARKERS.findall(normalized_text))
        if struct_count >= 2:
            score += 1
            matched_patterns.append(f"structural_markers:{struct_count}")

        return {
            'is_sql_like': score > 0,
            'lexical_score': score,
            'matched_keywords': matched_keywords,
            'matched_patterns': matched_patterns,
        }


# ═══════════════════════════════════════════════════════════════════
# LAYER 3: SQL SEMANTIC ANALYZER (with attack typing)
# ═══════════════════════════════════════════════════════════════════

class SQLSemanticAnalyzer:
    """
    Rule-based SQL semantic validation with context-aware scoring and attack typing.

    Key principle: Real SQL injection has SQL SEMANTICS, not just special characters.

    Improvements over v2:
        - Context-aware quote analysis (O'Brien → safe, ' OR 1=1 → SQL)
        - Keyword proximity scoring (keywords only count near SQL structure)
        - Attack type classification
        - Structural validity check
    """

    # High-risk SQL keywords (direct query manipulation)
    HIGH_RISK_KEYWORDS = [
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'truncate', 'exec', 'execute', 'xp_', 'sp_',
        'shutdown', 'create', 'alter', 'grant', 'revoke',
        # Dialect keywords for SQLite, MSSQL, MySQL, PostgreSQL (Fix F)
        'pragma', 'bulk', 'reconfigure', 'openrowset', 'openquery',
        'lo_export', 'dblink',
    ]

    # Medium-risk keywords (logic manipulation / query structure)
    MEDIUM_RISK_KEYWORDS = [
        'or', 'and', 'where', 'from', 'having', 'group', 'order',
        'like', 'between', 'in', 'is', 'null', 'not', 'exists',
        'table', 'into', 'values', 'set',
    ]

    # SQL functions (with opening paren to avoid false match)
    SQL_FUNCTIONS = [
        'sleep(', 'benchmark(', 'waitfor', 'delay', 'pg_sleep(',
        'load_file(', 'into outfile', 'into dumpfile',
        'concat(', 'char(', 'ascii(', 'substring(', 'substr(', 'mid(',
        'version(', 'database(', 'user(', 'current_user(', 'schema(',
        'dbms_pipe', 'utl_inaddr', 'utl_http', 'utl_file',
        'xp_dirtree', 'xp_cmdshell', 'xp_regread', 'xp_servicecontrol',
        'sp_configure', 'sp_executesql', 'sp_makewebtask',
        'receive_message', 'get_host_address',
        'extractvalue(', 'updatexml(', 'exp(', 'json_keys(',
        'gtid_subset(', 'row(', 'group_concat(', 'ifnull('
    ]

    # Dangerous OS-level functions
    OS_FUNCTIONS = [
        'xp_cmdshell', 'load_file(', 'into outfile', 'into dumpfile',
        'utl_http', 'utl_file', 'xp_dirtree',
    ]

    @classmethod
    def _is_quote_in_sql_context(cls, text: str, quote_pos: int) -> bool:
        """Check if a quote at given position is part of SQL injection context."""
        after_quote = text[quote_pos + 1:].strip()
        before_quote = text[:quote_pos]

        # Quote followed by SQL boolean operator + comparison → SQL context
        if re.match(r'\s*(or|and)\s+.+[=<>]', after_quote, re.I):
            return True

        # Quote followed by comment marker → SQL context
        if re.match(r'\s*(--|#|/\*)', after_quote):
            return True

        # Quote followed by semicolon + SQL keyword → SQL context
        if re.match(r'\s*;\s*(select|drop|insert|update|delete|exec|truncate|create|alter|shutdown)',
                     after_quote, re.I):
            return True

        # Quote followed by UNION → SQL context
        if re.match(r'\s*union\b', after_quote, re.I):
            return True

        # Quote in a name-like context (letter'letter) → NOT SQL
        if before_quote and before_quote[-1].isalpha() and after_quote and len(after_quote) > 0 and after_quote[0].isalpha():
            return False  # O'Brien, it's, don't

        return False

    @classmethod
    def _keyword_in_sql_context(cls, keyword: str, text: str) -> bool:
        """Check if a SQL keyword appears in SQL structural context (not English prose).

        A keyword is considered "in SQL context" when it appears near SQL
        structural operators (=, ;, quotes, parentheses, --) OR near a
        sufficient density of other SQL keywords.  Plain English sentences
        that happen to contain several SQL keywords (e.g. "Please select
        items from the drop-down list and update or delete entries") must
        NOT trigger this check.

        Heuristics applied:
            1. SQL operators within a ±30-char window → immediate SQL context.
            2. ≥2 other SQL keywords in window → SQL context.
            3. Only 1 other SQL keyword in window → SQL context ONLY if
               the text is short (≤60 chars) — long prose naturally
               accumulates SQL keywords without being an attack.
        """
        pattern = re.compile(rf'\b{re.escape(keyword)}\b', re.I)
        is_long_text = len(text) > 60

        for m in pattern.finditer(text):
            pos = m.start()
            window_start = max(0, pos - 30)
            window_end = min(len(text), pos + len(keyword) + 30)
            window = text[window_start:window_end]

            # Keyword near SQL operators (=, <>, ', ;, --, (,))
            if re.search(r"[=;'\"()\-]{2}", window):
                return True

            # Keyword near other SQL keywords — require higher density
            # for longer text to avoid false positives on English prose
            other_sql = ['select', 'from', 'where', 'union', 'insert', 'update',
                         'delete', 'drop', 'or', 'and', 'table', 'into', 'values',
                         'set', 'exec', 'null', 'sleep', 'benchmark']
            nearby_count = sum(1 for k in other_sql
                               if k != keyword.lower() and re.search(rf'\b{k}\b', window, re.I))

            # For long text: require ≥2 nearby SQL keywords (single co-occurrence
            # in prose is normal, e.g. "select ... from the list")
            min_nearby = 2 if is_long_text else 1
            if nearby_count >= min_nearby:
                return True

        return False

    @classmethod
    def analyze(cls, text: str) -> dict[str, Any]:
        """
        Compute SQL semantic score with attack type classification.

        Returns:
            Dict with: score, attack_type, structural_validity, evidence, breakdown
        """
        text_lower = text.lower()

        # Pre-normalize: URL decode + strip inline comments
        text_clean = urllib.parse.unquote(text_lower)
        text_normalized = re.sub(r'/\*.*?\*/', '', text_clean)

        score = 0.0
        attack_type = AttackType.NONE
        structural_validity = False
        evidence = []
        breakdown = {
            'high_risk_keywords': [],
            'medium_risk_keywords': [],
            'sql_functions': [],
            'comment_patterns': [],
            'injection_patterns': [],
        }

        # ═══ HIGH-RISK SQL KEYWORDS (+3 each, context-checked) ═══
        for kw in cls.HIGH_RISK_KEYWORDS:
            if re.search(rf'\b{re.escape(kw)}\b', text_normalized, re.I) and cls._keyword_in_sql_context(kw, text_normalized):
                score += 3
                breakdown['high_risk_keywords'].append(kw)

        # ═══ MEDIUM-RISK KEYWORDS (+1 each, max +3, context-checked) ═══
        medium_count = 0
        for kw in cls.MEDIUM_RISK_KEYWORDS:
            if re.search(rf'\b{re.escape(kw)}\b', text_normalized, re.I) and cls._keyword_in_sql_context(kw, text_normalized):
                medium_count += 1
                breakdown['medium_risk_keywords'].append(kw)
        score += min(medium_count, 3)

        # ═══ SQL FUNCTIONS (+4 each) ═══
        for fn in cls.SQL_FUNCTIONS:
            if fn in text_normalized:
                score += 4
                breakdown['sql_functions'].append(fn)
                # Classify attack type from function
                if fn in ('sleep(', 'benchmark(', 'waitfor', 'pg_sleep(', 'delay'):
                    attack_type = AttackType.TIME_BASED
                elif fn in ('extractvalue(', 'updatexml(', 'exp(', 'json_keys(', 'gtid_subset(', 'row('):
                    attack_type = AttackType.ERROR_BASED
                elif fn in cls.OS_FUNCTIONS:
                    attack_type = AttackType.OS_COMMAND

        # ═══ ALTERNATIVE LOGIC OPERATORS (+3) ═══
        if re.search(r"'\s*\|\|\s*'", text_clean):
            score += 3
            breakdown['injection_patterns'].append("concat-operator")
        if re.search(r"'\s*&&\s*'", text_clean):
            score += 3
            breakdown['injection_patterns'].append("and-operator")

        # ═══ COMMENT PATTERNS (+2 each, context-checked) ═══
        # Only count -- if preceded by quote or SQL structure
        if '--' in text_clean and re.search(r"['\w;)]\s*--", text_clean):
            score += 2
            breakdown['comment_patterns'].append('--')
        if '/*' in text_clean or '*/' in text_clean:
            score += 2
            breakdown['comment_patterns'].append('/*...*/')
        if re.search(r"['\w]\s*#", text_clean):
            score += 2
            breakdown['comment_patterns'].append('#')

        # ═══ INJECTION-SPECIFIC PATTERNS ═══

        # Pattern: ' OR '1'='1 / ' AND '1'='1 (classic tautology)
        if re.search(r"'\s*(or|and)\s+['\d]", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("quote-logic-quote")
            evidence.append("Quote + boolean operator + value pattern detected")

        # Pattern: OR/AND followed by quoted comparison ('x'='x')
        if re.search(r"(or|and)\s+'\w*'\s*=\s*'\w*'", text_clean, re.I):
            score += 2
            structural_validity = True
            breakdown['injection_patterns'].append("quote-equals-quote")
            evidence.append("String tautology comparison detected")

        # Pattern: Numeric tautology (1=1, 2=2) in SQL context
        if re.search(r"(^|or|and|where|\s)(\d)\s*=\s*\2(\s|$|;|--)", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("tautology-numeric")
            evidence.append("Numeric tautology in SQL context")

        # Pattern: Numeric comparison tautology — extended operators (Fix C)
        # Matches: 2>1, 0<1, 3!=2, 3<>2, 2>=1, 0<=1 preceded by SQL context anchor.
        # Anchor excludes prose: "Version 2>1 is newer" won't match (no OR/AND/'/; before it).
        if re.search(
            r"(?:'|;|\b(?:or|and|where|having)\b)\s*-?\d+\s*(?:!=|<>|>=|<=|>|<)\s*-?\d+",
            text_clean, re.I
        ):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("tautology-numeric-comparison")
            evidence.append("Numeric comparison tautology (!=, <>, >, <, >=, <=) in SQL context")

        # Pattern: HAVING clause tautology — HAVING 1>0, HAVING COUNT(*)>0 (Fix C)
        if re.search(
            r"\bhaving\b.{0,30}(?:\d+\s*(?:>|<|>=|<=|!=|<>)\s*\d+|count\s*\()",
            text_clean, re.I
        ):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("having-tautology")
            evidence.append("HAVING clause with numeric/aggregate tautology")

        # Pattern: String tautology with OR/AND context
        if re.search(r"(or|and)\s+'(\w+)'\s*=\s*'\2'", text_clean, re.I):
            score += 3
            structural_validity = True
            breakdown['injection_patterns'].append("tautology-string")
            evidence.append("String tautology with boolean operator")

        # Pattern: Parenthesis-wrapped tautology — ') or ('1'='1
        if re.search(r"\)\s*(or|and)\s*\(", text_clean, re.I) and re.search(r"['\d]\s*=\s*['\d]", text_clean):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("paren-tautology")
            evidence.append("Parenthesis-wrapped tautology bypass detected")

        # Pattern: Weird equals obfuscation — '=' 'or'='
        if re.search(r"'\s*=\s*'.*?(or|and)\s*'?\s*=\s*'?", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("equals-obfuscation")
            evidence.append("Obfuscated equals-based tautology detected")

        # Pattern: Bare equals between quotes — '=' ' or '= ' (minimal auth bypass)
        # Matches various spacings: '='  ,  ' = ' ,  ' =' etc.
        # Guard: only when there are exactly 2-3 quotes total (avoids ''''=''' garbage)
        _quote_count = text_clean.count("'")
        if re.search(r"'\s*=\s*'", text_clean) and len(text_clean.strip()) <= 10 and _quote_count <= 3:
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("bare-equals-bypass")
            evidence.append("Bare quote-equals-quote auth bypass")

        # Pattern: Comment-truncation after quote — admin'-- (login bypass)
        if re.search(r"'\s*--\s*$", text_clean):
            score += 2
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.COMMENT_TRUNCATION
            breakdown['injection_patterns'].append("quote-comment-truncation")
            evidence.append("Quote followed by comment truncation (login bypass)")

        # Pattern: UNION SELECT
        # Guard: In natural-language text, "union" and "select" may both appear
        # as normal English words (e.g. "The European Union voted to select...").
        # Heuristic: if the gap between them contains only non-SQL English words
        # (no digits, no parens, no commas, no *, no null) AND the overall text
        # is long (>40 chars), treat as prose.  SQL UNION SELECT payloads use
        # "union select col1,col2" or "union all select" patterns where the gap
        # is either whitespace, "all", or nothing.
        _union_select_match = re.search(r'\bunion\b(.*?)\bselect\b', text_clean, re.I)
        if _union_select_match:
            _gap_text = _union_select_match.group(1).strip()
            _gap_is_sql = (
                _gap_text == ''
                or re.match(r'^(all\s*)?$', _gap_text, re.I)
                or re.search(r'[0-9()*,]', _gap_text)
                # Fix G: short gap (≤3 words) + injection context (quote/comment) = attack not prose.
                # "' UNION then SELECT 1--" has quote → gap_is_sql=True.
                # "The EU (European Union) chose to select..." has no quote/comment → stays prose.
                or (len(_gap_text.split()) <= 3 and (
                    "'" in text_clean or '"' in text_clean
                    or re.search(r'(--|#|/\*)', text_clean)
                ))
            )
            _is_prose = len(text_clean) > 40 and not _gap_is_sql
            if not _is_prose:
                score += 4
                structural_validity = True
                attack_type = AttackType.UNION_BASED
                breakdown['injection_patterns'].append("union-select")
                evidence.append("UNION SELECT data extraction attempt")
        elif re.search(r'union\s*select', text_normalized, re.I):
            score += 4
            structural_validity = True
            attack_type = AttackType.UNION_BASED
            breakdown['injection_patterns'].append("union-select-obfuscated")
            evidence.append("Obfuscated UNION SELECT detected")

        # Pattern: Stacked queries ('; SQL_KEYWORD) — includes dialect keywords (Fix F)
        stacked_match = re.search(
            r"['\w]\s*;\s*(select|insert|update|delete|drop|truncate|"
            r"create|alter|exec|shutdown|waitfor|copy|"
            r"pragma|bulk|reconfigure|openrowset|openquery|grant|revoke|"
            r"load\s+data|load\s+local|lo_export|dblink|sp_addlinkedserver)",
            text_clean, re.I
        )
        if stacked_match:
            score += 3
            structural_validity = True
            stacked_kw = stacked_match.group(1).lower().split()[0]  # "load data" → "load"
            if stacked_kw in ('drop', 'delete', 'truncate', 'alter', 'shutdown',
                              'reconfigure', 'bulk', 'grant', 'revoke'):
                attack_type = AttackType.STACKED_QUERY
            elif stacked_kw in ('exec', 'openrowset', 'openquery',
                                'sp_addlinkedserver', 'lo_export', 'dblink', 'load'):
                attack_type = AttackType.OS_COMMAND
            elif attack_type == AttackType.NONE:
                attack_type = AttackType.STACKED_QUERY
            breakdown['injection_patterns'].append("stacked-query")
            evidence.append(f"Stacked query with {stacked_kw.upper()}")
            # Fix 4: Dialect stacked keyword bonus.
            # PRAGMA, RECONFIGURE, LOAD DATA etc. fail _keyword_in_sql_context
            # (no SQL operator neighbours) so their keyword score is 0.
            # Total semantic after stacked = 3.0, below tau_semantic_override=6.0.
            # Adding +3 here brings total to 6.0 → semantic override fires → BLOCK.
            # FP guard: only fires when stacked regex already matched (requires ['\w];keyword).
            _dialect_high_danger = {
                'pragma', 'reconfigure', 'bulk', 'load',
                'lo_export', 'dblink', 'openrowset', 'openquery', 'sp_addlinkedserver',
            }
            if stacked_kw in _dialect_high_danger:
                score += 3
                evidence.append(f"Dialect stacked keyword {stacked_kw.upper()} — elevated risk")

        # Pattern: Quote followed by OR/AND + digit
        if re.search(r"'\s*(or|and)\s+\d", text_clean, re.I):
            score += 2
            breakdown['injection_patterns'].append("quote-keyword")

        # Pattern: No-space obfuscation 'OR'1'='1
        if re.search(r"'(or|and)'[^']*'='", text_clean, re.I):
            score += 4
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("no-space-obfuscation")
            evidence.append("No-space obfuscation pattern")

        # Pattern: Comment truncation after injection context
        if re.search(r"'\s*--", text_clean) and score >= 2:
            if attack_type == AttackType.NONE:
                attack_type = AttackType.COMMENT_TRUNCATION
            evidence.append("Comment-based query truncation")

        # Pattern: Double-quote injection (" OR "1"="1)
        if re.search(r'"\s*(or|and)\s+"', text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("double-quote-logic")
            evidence.append("Double-quote boolean injection pattern detected")

        # Pattern: Double-quote tautology ("1"="1, "a"="a)
        if re.search(r'(or|and)\s+"(\w+)"\s*=\s*"\2"', text_clean, re.I):
            score += 3
            structural_validity = True
            breakdown['injection_patterns'].append("double-quote-tautology")
            evidence.append("Double-quote tautology detected")

        # Pattern: Bracket-delimited tautology — [1]=[1], [a]=[a] (MSSQL style)
        if re.search(r"(or|and)\s+\[([^\]]+)\]\s*=\s*\[\2\]", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("bracket-tautology")
            evidence.append("Bracket-delimited tautology (MSSQL style)")

        # Pattern: Subquery comparison — (SELECT ...)=value (blind injection)
        # Fix 5: Allow one level of nested parens inside the subquery so that
        # aggregate functions like COUNT(*), MAX(id) are handled correctly.
        # Old pattern [^)]* stopped at the first ')' inside COUNT(*),
        # preventing the outer ')>' from being matched.
        # New: (?:[^)(]|\([^)]*\))* = any non-paren char OR a balanced (...)pair.
        if re.search(r"\(\s*select\b(?:[^)(]|\([^)]*\))*\)\s*[=<>!]", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("subquery-comparison")
            evidence.append("Subquery used in comparison (blind injection)")

        # Pattern: EXISTS subquery — WHERE EXISTS(SELECT ...)
        if re.search(r"\bexists\s*\(\s*select\b", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("exists-subquery")
            evidence.append("EXISTS subquery injection")

        # Pattern: LIKE with wildcard after injection break-in — ' OR col LIKE '%
        if re.search(r"(or|and)\s+\w+\s+like\s+['\"]%", text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("like-wildcard")
            evidence.append("LIKE with wildcard pattern (match-all bypass)")

        # Pattern: IF/IIF conditional tautology — IF(1=1,...) used for blind injection
        if re.search(r"\b(if|iif)\s*\(\s*\d+\s*=\s*\d+\s*,", text_clean, re.I):
            score += 4
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.BOOLEAN_BASED
            breakdown['injection_patterns'].append("if-tautology")
            evidence.append("IF/IIF conditional tautology (blind injection)")

        # Pattern: ORDER BY injection (column enumeration)
        if re.search(r'\border\s+by\s+\d+\s*(--|#|/\*)', text_clean, re.I):
            score += 3
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.UNION_BASED
            breakdown['injection_patterns'].append("order-by-injection")
            evidence.append("ORDER BY column enumeration (pre-UNION recon)")

        # Pattern: ORDER BY injection without comment (context: after semicolon or quote)
        if re.search(r"[';]\s*order\s+by\s+\d+", text_clean, re.I):
            score += 2
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.UNION_BASED
            breakdown['injection_patterns'].append("order-by-after-break")
            evidence.append("ORDER BY after query break point")

        # Pattern: OUT-OF-BAND indicators
        if re.search(r'(load_file|into\s+outfile|into\s+dumpfile|utl_http|xp_dirtree)\b', text_clean, re.I):
            if attack_type in (AttackType.NONE, AttackType.OS_COMMAND):
                attack_type = AttackType.OUT_OF_BAND
            evidence.append("Out-of-band data exfiltration technique")

        # ═══ STANDALONE SQL STATEMENT DETECTION ═══
        # A bare SQL statement (e.g. "SELECT * FROM users WHERE id = 1") without
        # any injection break-in context (no quotes before keywords, no stacked
        # query separator, no tautology) is likely documentation or educational
        # content, NOT an injection attempt.  Downgrade score in this case.
        #
        # Exception: comment truncation (--) with destructive keywords (DROP,
        # DELETE, TRUNCATE) IS an injection pattern, not documentation.
        #
        # Fix 6: Detect whether all apostrophes are possessive/contraction forms
        # (O'Brien's, it's, don't) with no injection-context apostrophe present.
        # Only when ALL apostrophes are possessive AND no other injection markers
        # exist should we treat the text as non-injection.
        # This is targeted: "O'Brien's SQL tutorial SELECT UNION" → purely
        # possessive → _has_injection_apostrophe=False → score capped → SAFE.
        # Regular attacks "'OR 1=1", "admin'--" → apostrophe is NOT purely
        # possessive → _has_injection_apostrophe=True → normal detection.
        def _is_purely_possessive(apos_pos: int, txt: str) -> bool:
            """Return True if apostrophe at apos_pos is a possessive/contraction
            (letter'letter or letter's) and not an injection break-in."""
            before = txt[:apos_pos]
            after = txt[apos_pos + 1:]
            # Must have a letter immediately before
            if not before or not before[-1].isalpha():
                return False
            # Must have a letter immediately after (it's, don't, O'Brien)
            if not after or not after[0].isalpha():
                return False
            return True

        _apostrophe_positions = [i for i, c in enumerate(text_clean) if c == "'"]
        # _has_injection_apostrophe = True unless ALL apostrophes are possessive
        if _apostrophe_positions:
            _has_injection_apostrophe = not all(
                _is_purely_possessive(pos, text_clean)
                for pos in _apostrophe_positions
            )
        else:
            _has_injection_apostrophe = False

        has_break_in = (
            _has_injection_apostrophe or '"' in text_clean
            or re.search(
                r';\s*(select|drop|delete|insert|update|exec|truncate|shutdown|'
                r'pragma|bulk|reconfigure|openrowset|openquery|grant|revoke|load)',
                text_clean, re.I
            )  # extended with dialect keywords (Fix F)
            or len(breakdown['injection_patterns']) > 0
            or len(breakdown['sql_functions']) > 0
        )
        # DML/DDL SQL keyword + comment truncation = attack, not documentation.
        # Fix 3: Extended to include select/union/insert/update — these keywords
        # with a trailing comment marker are injection probes (e.g. after comment-strip
        # normalization of SE/**/L/**/ECT * FROM users-- → SELECT * FROM users--).
        # FP guard: requires BOTH high_risk_keywords hit (context-checked) AND a comment
        # marker. Prose with SQL words has no comment markers; CLI --flags have no SQL keywords.
        destructive_with_comment = (
            any(kw in ('drop', 'delete', 'truncate', 'alter', 'shutdown', 'exec', 'execute',
                       'select', 'union', 'insert', 'update')
                for kw in breakdown['high_risk_keywords'])
            and len(breakdown['comment_patterns']) > 0
        )
        if destructive_with_comment:
            has_break_in = True
            structural_validity = True
            if attack_type == AttackType.NONE:
                attack_type = AttackType.STACKED_QUERY
            evidence.append("Destructive SQL keyword with comment truncation")

        if score >= 2 and not has_break_in and not structural_validity:
            # Pure SQL keywords without injection context → documentation
            score = min(score, 1.0)
            evidence.append("Standalone SQL statement (no injection break-in context)")

        # Fix H: Long prose cap — if there are no structural SQL markers at all
        # (no quotes, no semicolon, no comment markers, no injection patterns, no functions),
        # cap the semantic score below tau_semantic_override (6.0) to prevent legitimate
        # prose with incidental SQL keywords from triggering the semantic override rule.
        # Only applies to long texts (>80 chars). Real attacks always have at least one marker.
        # Fix 6 (continued): Reuse _has_injection_apostrophe computed above so
        # that possessive apostrophes don't count as structural injection markers.
        _has_structural_markers = bool(
            _has_injection_apostrophe or '"' in text_clean
            or re.search(r'(;|--|#|/\*)', text_clean)
        )
        if (len(text_clean) > 80
                and not _has_structural_markers
                and not breakdown['injection_patterns']
                and not breakdown['sql_functions']
                and score >= 5.0):
            score = min(score, 4.9)
            evidence.append("Long prose without SQL structural markers — score capped below semantic override")

        # ═══ STRUCTURAL VALIDITY CHECK ═══
        if score >= 2 and not structural_validity:
            # Check if there's enough SQL structure for a real attack
            has_sql_keyword = len(breakdown['high_risk_keywords']) > 0
            has_logic = len(breakdown['medium_risk_keywords']) > 0
            has_function = len(breakdown['sql_functions']) > 0
            has_pattern = len(breakdown['injection_patterns']) > 0

            if (has_sql_keyword and (has_logic or has_pattern)) or has_function:
                structural_validity = True

        return {
            'score': score,
            'attack_type': attack_type,
            'structural_validity': structural_validity,
            'evidence': evidence,
            'breakdown': breakdown,
            'has_sql_semantics': score >= 2,
        }

    # Legacy alias for backward compatibility
    @classmethod
    def calculate_semantic_score(cls, text: str) -> dict[str, Any]:
        """Legacy method - delegates to analyze()."""
        result = cls.analyze(text)
        return {
            'score': result['score'],
            'breakdown': result['breakdown'],
            'has_sql_semantics': result['has_sql_semantics'],
        }


# ═══════════════════════════════════════════════════════════════════
# LAYER 5: SEVERITY MODEL
# ═══════════════════════════════════════════════════════════════════

class SeverityClassifier:
    """
    Attack-type-aware severity classification.

    Maps attack type → severity based on potential damage.
    """

    # Attack type → base severity
    SEVERITY_MAP = {
        AttackType.OS_COMMAND: Severity.CRITICAL,
        AttackType.STACKED_QUERY: Severity.HIGH,     # May upgrade to CRITICAL
        AttackType.UNION_BASED: Severity.HIGH,
        AttackType.ERROR_BASED: Severity.HIGH,
        AttackType.OUT_OF_BAND: Severity.HIGH,
        AttackType.TIME_BASED: Severity.MEDIUM,
        AttackType.BOOLEAN_BASED: Severity.MEDIUM,
        AttackType.COMMENT_TRUNCATION: Severity.LOW,
        AttackType.NONE: Severity.LOW,
    }

    # Destructive keywords that upgrade stacked queries to CRITICAL
    DESTRUCTIVE_KEYWORDS = [
        'drop', 'delete', 'truncate', 'alter', 'shutdown',
        'xp_cmdshell', 'exec', 'load_file', 'into outfile', 'into dumpfile',
    ]

    @classmethod
    def classify(cls, attack_type: AttackType, normalized_input: str) -> Severity:
        """Classify severity based on attack type and input content."""
        base_severity = cls.SEVERITY_MAP.get(attack_type, Severity.LOW)

        # Upgrade stacked queries to CRITICAL if destructive
        if attack_type == AttackType.STACKED_QUERY:
            for kw in cls.DESTRUCTIVE_KEYWORDS:
                if kw in normalized_input:
                    return Severity.CRITICAL

        return base_severity

    @classmethod
    def severity_to_action(cls, severity: Severity) -> Action:
        """Map severity to recommended action.

        CRITICAL and HIGH attacks are always BLOCKED to prevent
        destructive operations (DROP TABLE, xp_cmdshell, DELETE, etc.)
        from reaching the database. ALERT is sent alongside BLOCK
        via the incident logger for SOC notification.
        """
        mapping = {
            Severity.CRITICAL: Action.BLOCK,
            Severity.HIGH: Action.BLOCK,
            Severity.MEDIUM: Action.BLOCK,
            Severity.LOW: Action.CHALLENGE,
            Severity.INFO: Action.LOG,
        }
        return mapping.get(severity, Action.LOG)


# ═══════════════════════════════════════════════════════════════════
# LAYER 6: EXPLAINABILITY
# ═══════════════════════════════════════════════════════════════════

class ExplainabilityModule:
    """
    Produces structured, auditable decision explanations.
    """

    MITRE_TECHNIQUE = "T1190"  # Exploit Public-Facing Application

    @classmethod
    def build_explanation(
        cls,
        decision: Decision,
        action: Action,
        severity: Severity,
        attack_type: AttackType,
        confidence: str,
        ensemble_score: float,
        P_rf: float,
        P_cnn: float,
        semantic_result: dict,
        normalization_meta: dict,
        lexical_result: dict,
        decision_rule: str,
        detection_time_ms: float,
        input_hash: str,
        source_ip: str | None = None,
        endpoint: str | None = None,
        field_name: str | None = None,
        http_method: str | None = None,
    ) -> dict[str, Any]:
        """Build full explainability output."""
        factors = []
        if ensemble_score >= 0.60:
            factors.append(f"Ensemble score {ensemble_score:.2f} exceeds high-confidence threshold 0.60")
        if semantic_result['score'] >= 2.0:
            factors.append(f"Semantic score {semantic_result['score']:.1f} exceeds minimum threshold 2.0")
        if semantic_result.get('structural_validity'):
            factors.append("SQL structural validity confirmed")
        if abs(P_cnn - P_rf) < 0.2 and P_cnn > 0.5:
            factors.append("Model agreement: RF and CNN signals converge")

        explanation = {
            'summary': cls._build_summary(decision, attack_type, confidence),
            'layer_results': {
                'normalization': normalization_meta,
                'lexical_prefilter': lexical_result,
                'ml_ensemble': {
                    'rf_score': round(P_rf, 4),
                    'cnn_score': round(P_cnn, 4),
                    'ensemble_score': round(ensemble_score, 4),
                    'model_agreement': abs(P_cnn - P_rf) < 0.2,
                },
                'semantic_validation': {
                    'semantic_score': semantic_result['score'],
                    'structural_validity': semantic_result.get('structural_validity', False),
                    'attack_type': attack_type.value,
                    'evidence': semantic_result.get('evidence', []),
                },
            },
            'decision_rule': decision_rule,
            'decision_factors': factors,
        }

        siem_fields = {
            'event_id': f"sqli-{datetime.now(UTC).strftime('%Y%m%d')}-{input_hash[:8]}",
            'timestamp': datetime.now(UTC).isoformat(),
            'event_category': 'intrusion_detection',
            'event_type': 'sql_injection',
            'event_severity': severity.value.lower(),
            'source_ip': source_ip or 'unknown',
            'destination_endpoint': endpoint or 'unknown',
            'http_method': http_method or 'unknown',
            'field_name': field_name,
            'input_hash': input_hash,
            'attack_type': attack_type.value.lower(),
            'mitre_technique': cls.MITRE_TECHNIQUE,
            'detection_time_ms': round(detection_time_ms, 2),
            'ensemble_score': round(ensemble_score, 4),
            'semantic_score': semantic_result['score'],
        }

        return {
            'explanation': explanation,
            'siem_fields': siem_fields,
        }

    @classmethod
    def _build_summary(cls, decision: Decision, attack_type: AttackType, confidence: str) -> str:
        """Build human-readable summary."""
        if decision == Decision.SAFE:
            return "Input is safe — no SQL injection patterns detected."
        elif decision == Decision.INVALID:
            return "Input is malformed/invalid — unusual characters but no SQL semantic structure."
        elif decision == Decision.SUSPICIOUS:
            return "Input has some SQL-like characteristics — further review recommended."
        else:
            type_desc = {
                AttackType.BOOLEAN_BASED: "Boolean-based",
                AttackType.UNION_BASED: "UNION-based data extraction",
                AttackType.STACKED_QUERY: "Stacked query",
                AttackType.TIME_BASED: "Time-based blind",
                AttackType.ERROR_BASED: "Error-based extraction",
                AttackType.COMMENT_TRUNCATION: "Comment truncation",
                AttackType.OUT_OF_BAND: "Out-of-band",
                AttackType.OS_COMMAND: "OS command execution",
            }.get(attack_type, "Unknown type")
            return f"{type_desc} SQL injection detected with {confidence} confidence."

    @classmethod
    def build_cef(cls, result: dict) -> str:
        """Build CEF (Common Event Format) string for SIEM."""
        siem = result.get('siem_fields', {})
        severity_map = {"info": 1, "low": 3, "medium": 6, "high": 8, "critical": 10}
        sev_num = severity_map.get(siem.get('event_severity', 'info'), 5)

        cef = (
            f"CEF:0|SQLIProtector|EnsembleDetector|3.0|"
            f"{result.get('attack_type', 'UNKNOWN')}|"
            f"SQL Injection Detection|{sev_num}|"
            f"src={siem.get('source_ip', 'unknown')} "
            f"dst={siem.get('destination_endpoint', 'unknown')} "
            f"act={result.get('action', 'UNKNOWN')} "
            f"cs1={siem.get('ensemble_score', 0)} cs1Label=EnsembleScore "
            f"cs2={siem.get('semantic_score', 0)} cs2Label=SemanticScore "
            f"cs3={siem.get('attack_type', 'none')} cs3Label=AttackType "
            f"cn1={siem.get('detection_time_ms', 0)} cn1Label=DetectionTimeMs"
        )
        return cef


# ═══════════════════════════════════════════════════════════════════
# MAIN ENSEMBLE DETECTOR (Layers 2 + 4 combined)
# ═══════════════════════════════════════════════════════════════════

class SQLInjectionEnsemble:
    """
    Production-grade SQL Injection Ensemble Detector.

    Combines:
        - Random Forest (classic ML, TF-IDF features)
        - Char-level CNN (PyTorch deep learning, primary model)
        - SQL Semantic Analyzer (rule-based structural validation)
        - Attack-type-aware severity classification
        - Full decision explainability

    Architecture invariant:
        ML score alone CANNOT produce INJECTION decision without semantic >= tau_semantic_min.
    """

    def __init__(self, config: EnsembleConfig | None = None):
        self.config = config or EnsembleConfig()
        self.semantic_analyzer = SQLSemanticAnalyzer()
        self.normalizer = InputNormalizer()
        self.lexical_filter = LexicalPreFilter()
        self.severity_classifier = SeverityClassifier()
        self.explainability = ExplainabilityModule()

        # Model state
        self.rf_model = None
        self.rf_vectorizer = None
        self.cnn_model = None
        self.char_tokenizer = None

        self.rf_loaded = False
        self.cnn_loaded = False

        self._load_models()
        log.info("ensemble_initialized",
                 rf=self.rf_loaded,
                 cnn=self.cnn_loaded)

    def _load_models(self):
        """Load all ML models with graceful fallback."""
        # Random Forest + TF-IDF
        try:
            self.rf_model = joblib.load(MODULE_DIR / 'rf_sql_model.pkl')
            self.rf_vectorizer = joblib.load(MODULE_DIR / 'tfidf_vectorizer.pkl')
            self.rf_loaded = True
            log.info("model_loaded", model="random_forest")
        except Exception as e:
            log.warning("model_load_failed", model="random_forest", error=str(e))

        # CNN (PyTorch) — primary deep learning model
        try:
            from models.char_cnn_model import CharCNN
            from models.char_tokenizer import CharTokenizer

            cnn_path = MODULE_DIR / 'models' / 'char_cnn_detector.pt'
            tokenizer_path = MODULE_DIR / 'models' / 'char_tokenizer.json'

            self.cnn_model = CharCNN.load_from_checkpoint(str(cnn_path))
            self.char_tokenizer = CharTokenizer.load(str(tokenizer_path))
            self.cnn_loaded = True
            log.info("model_loaded", model="cnn_pytorch")
        except Exception as e:
            log.warning("model_load_failed", model="cnn_pytorch", error=str(e))

    # ─── Preprocessing ───

    @staticmethod
    def preprocess(text: str) -> str:
        """Legacy preprocessing for ML model input."""
        text = str(text).lower()
        text = urllib.parse.unquote(text)
        text = re.sub(r'/\*.*?\*/', ' ', text)
        text = re.sub(r'--.*$', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    @staticmethod
    def extract_features(text: str) -> dict[str, int]:
        """Extract numeric features for RF model."""
        clean = SQLInjectionEnsemble.preprocess(text)
        return {
            'length': len(clean),
            'num_digits': sum(c.isdigit() for c in clean),
            'num_special': sum(not c.isalnum() and not c.isspace() for c in clean),
            'num_quotes': clean.count("'") + clean.count('"'),
            'num_keywords': len(re.findall(
                r'\b(select|union|or|and|drop|sleep|where|from|insert|update|delete|having|group)\b',
                clean
            ))
        }

    # ─── Model Predictions ───

    def _predict_rf(self, text: str) -> float:
        """Get Random Forest injection probability."""
        if not self.rf_loaded:
            return 0.0

        from scipy.sparse import hstack

        clean_text = self.preprocess(text)
        features = self.extract_features(text)

        tfidf = self.rf_vectorizer.transform([clean_text])
        extra = np.array([[
            features['length'],
            features['num_digits'],
            features['num_special'],
            features['num_quotes'],
            features['num_keywords']
        ]])

        X = hstack([tfidf, extra])
        return float(self.rf_model.predict_proba(X)[0][1])

    def _predict_cnn(self, text: str) -> float:
        """Get CNN injection probability using PyTorch char-level model."""
        if not self.cnn_loaded or self.char_tokenizer is None:
            return 0.0

        import torch

        clean_text = self.preprocess(text)
        encoded = self.char_tokenizer.encode_batch([clean_text])
        x = torch.LongTensor(encoded)

        with torch.no_grad():
            prob = self.cnn_model.predict(x)

        return float(prob[0][0])

    # ─── Ensemble Decision Engine (Layer 4) ───

    def _compute_ensemble_score(self, P_rf: float, P_cnn: float) -> float:
        """Compute weighted ensemble score with model agreement bonus."""
        cfg = self.config

        # 2-model weighted fusion (RF + CNN)
        S = cfg.w_rf * P_rf + cfg.w_cnn * P_cnn

        # Agreement bonus: both models agree on direction
        both_high = P_rf >= 0.5 and P_cnn >= 0.5
        both_low = P_rf < 0.5 and P_cnn < 0.5
        if both_high or both_low:
            S = min(S * (1 + cfg.agreement_bonus), 1.0)

        return S

    def _ensemble_decision(self, P_rf: float, P_cnn: float,
                           semantic: dict) -> dict[str, Any]:
        """
        Apply ensemble decision rules with semantic gating.

        ARCHITECTURAL INVARIANT:
            INJECTION requires (ML >= tau_high AND semantic >= tau_semantic_min)
                            OR  (semantic >= tau_semantic_override)
            ML alone → NEVER INJECTION.
        """
        cfg = self.config
        sem_score = semantic['score']
        has_semantics = semantic['has_sql_semantics']

        S = self._compute_ensemble_score(P_rf, P_cnn)

        # === RULE 0: INVALID INPUT DETECTION ===
        # High CNN + Low RF + No SQL semantics = Malformed/garbage
        if P_cnn >= 0.70 and P_rf < 0.50 and sem_score < cfg.tau_semantic_min:
            return {
                'decision': Decision.INVALID,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Malformed input: P_cnn={P_cnn:.2f} but P_rf={P_rf:.2f}, sem={sem_score:.1f} (no SQL semantics)',
                'action': Action.LOG,
                'rule': 'RULE_0_INVALID_DETECTION',
            }

        # === RULE 1: HIGH CONFIDENCE INJECTION ===
        # Both ML and semantic agree.
        # GUARD: When models strongly disagree (CNN high / RF low), the
        # ensemble score can still exceed tau_high due to CNN's higher
        # weight (0.65).  In long natural-language inputs, CNN may fire
        # on embedded SQL-like substrings ("SELECT ... FROM ...") while
        # RF correctly identifies the overall input as prose.  We demote
        # to SUSPICIOUS when:
        #   • models diverge (|P_cnn - P_rf| > tau_model_divergence)
        #   • RF is confident the input is safe (P_rf < tau_safe)
        #   • the input lacks strong injection patterns (no structural
        #     validity from the semantic analyzer)
        models_diverge = abs(P_cnn - P_rf) > cfg.tau_model_divergence
        rf_says_safe = P_rf < cfg.tau_safe

        if cfg.tau_high <= S and has_semantics:
            if models_diverge and rf_says_safe and not semantic.get('structural_validity', False):
                return {
                    'decision': Decision.SUSPICIOUS,
                    'confidence_level': 'LOW',
                    'score': S,
                    'reason': f'Model divergence guard: P_cnn={P_cnn:.2f} vs P_rf={P_rf:.2f} (RF says safe, no structural attack patterns)',
                    'action': Action.CHALLENGE,
                    'rule': 'RULE_1_DIVERGENCE_GUARD',
                }
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Ensemble score {S:.2f} >= {cfg.tau_high}, sem={sem_score:.1f} (SQL semantics confirmed)',
                'action': Action.BLOCK,
                'rule': 'RULE_1_HIGH_CONFIDENCE',
            }

        # === RULE 2: CNN OVERRIDE (obfuscation) ===
        # Same divergence guard: if RF is confident it's safe and there
        # are no structural attack patterns, demote to SUSPICIOUS.
        if P_cnn >= cfg.tau_cnn_override and sem_score >= 3:
            if rf_says_safe and not semantic.get('structural_validity', False):
                return {
                    'decision': Decision.SUSPICIOUS,
                    'confidence_level': 'LOW',
                    'score': S,
                    'reason': f'CNN override guarded: P_cnn={P_cnn:.2f} but P_rf={P_rf:.2f} (RF says safe, no structural patterns)',
                    'action': Action.CHALLENGE,
                    'rule': 'RULE_2_CNN_OVERRIDE_GUARDED',
                }
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'CNN override: P_cnn={P_cnn:.2f}, sem={sem_score:.1f} (obfuscated SQLi)',
                'action': Action.BLOCK,
                'rule': 'RULE_2_CNN_OVERRIDE',
            }

        # === RULE 3: RF STRONG SIGNAL ===
        if P_rf >= cfg.tau_rf_strong and has_semantics:
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'RF strong signal: P_rf={P_rf:.2f}, sem={sem_score:.1f}',
                'action': Action.BLOCK,
                'rule': 'RULE_3_RF_STRONG',
            }

        # === RULE 3.5: SEMANTIC OVERRIDE ===
        # Very high semantic score catches attacks that fool ML (e.g. comment-split
        # keywords like UN/**/ION SE/**/LECT, hex encoding, MySQL conditional comments).
        #
        # Two modes:
        #   a) sem >= override AND structural_validity → INJECTION regardless of ML.
        #      This catches heavily obfuscated payloads where confirmed SQL attack
        #      patterns (tautologies, UNION SELECT, stacked queries) are present
        #      but ML was never trained on the encoding variant.
        #   b) sem >= override AND S >= tau_safe → INJECTION (soft ML gate).
        #      This is the fallback for cases where structural patterns are ambiguous
        #      but ML at least doesn't confidently say safe.
        #
        # The ML gate in mode (b) prevents false positives on natural language with
        # many SQL keywords (e.g. "The union between France and Germany was strong").
        has_structural = semantic.get('structural_validity', False)
        if sem_score >= cfg.tau_semantic_override and (has_structural or S >= cfg.tau_safe):
            return {
                'decision': Decision.INJECTION,
                'confidence_level': 'MEDIUM' if not has_structural else 'HIGH',
                'score': S,
                'reason': f'Semantic override: sem={sem_score:.1f} >= {cfg.tau_semantic_override}, structural={has_structural}',
                'action': Action.BLOCK,
                'rule': 'RULE_3_5_SEMANTIC_OVERRIDE',
            }

        # === RULE 4: CONFLICT ZONE WITH SEMANTICS ===
        if cfg.tau_low <= S and has_semantics and (P_cnn >= 0.50 or P_rf >= cfg.tau_rf_strong):
            confidence = 'MEDIUM' if cfg.tau_high > S else 'HIGH'
            return {
                'decision': Decision.INJECTION,
                'confidence_level': confidence,
                'score': S,
                'reason': f'Conflict zone with SQL semantics (P_rf={P_rf:.2f}, P_cnn={P_cnn:.2f}, sem={sem_score:.1f})',
                'action': Action.BLOCK,
                'rule': 'RULE_4_CONFLICT_WITH_SEMANTICS',
            }

        # === RULE 5: HIGH CONFIDENCE SAFE ===
        if cfg.tau_safe > S:
            return {
                'decision': Decision.SAFE,
                'confidence_level': 'HIGH',
                'score': S,
                'reason': f'Ensemble score {S:.2f} < {cfg.tau_safe} (both models agree safe)',
                'action': Action.ALLOW,
                'rule': 'RULE_5_SAFE',
            }

        # === RULE 6: SUSPICIOUS ===
        if sem_score >= 1:
            return {
                'decision': Decision.SUSPICIOUS,
                'confidence_level': 'LOW',
                'score': S,
                'reason': f'Gray zone with weak SQL semantics: S={S:.2f}, sem={sem_score:.1f}',
                'action': Action.CHALLENGE,
                'rule': 'RULE_6_SUSPICIOUS',
            }

        # === RULE 7: DEFAULT INVALID ===
        return {
            'decision': Decision.INVALID,
            'confidence_level': 'MEDIUM',
            'score': S,
            'reason': f'No SQL semantics: S={S:.2f}, sem={sem_score:.1f}',
            'action': Action.LOG,
            'rule': 'RULE_7_DEFAULT_INVALID',
        }

    # ─── Main Detection API ───

    def detect(self, text: str, source_ip: str | None = None,
               endpoint: str | None = None, field_name: str | None = None,
               http_method: str | None = None) -> dict[str, Any]:
        """
        Detect SQL injection using the full 7-layer pipeline.

        Args:
            text: Input text to analyze
            source_ip: Client IP for SIEM fields
            endpoint: API endpoint for SIEM fields
            field_name: Form field name for SIEM fields
            http_method: HTTP method for SIEM fields

        Returns:
            Comprehensive detection result with decision, severity, attack_type,
            explanation, siem_fields, and all intermediate scores.
        """
        start_time = time.time()

        # Input length check
        if len(text) > self.config.max_input_length:
            text = text[:self.config.max_input_length]

        # Layer 0: Normalization
        normalized_text, norm_meta = self.normalizer.normalize(text, self.config.max_input_length)

        # Layer 1: Lexical pre-filter
        lexical = self.lexical_filter.scan(normalized_text)

        # Fast-path: clearly safe input (no SQL indicators at all)
        # Also skip fast-path if normalizer detected evasion techniques
        # (comment stripping, zero-width chars, etc.) — those are suspicious.
        evasion_transforms = {'comment_strip', 'mysql_conditional_expand',
                              'zero_width_strip', 'combining_mark_strip',
                              'math_styled_map', 'homoglyph_map', 'unicode_nfkc'}
        had_evasion = bool(evasion_transforms & set(norm_meta['transformations']))
        if (not lexical['is_sql_like'] and not had_evasion
                and not any(c in text for c in "'\"--;#")
                and '/*' not in text):
            elapsed = (time.time() - start_time) * 1000
            input_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

            return {
                'decision': Decision.SAFE.value,
                'action': Action.ALLOW.value,
                'confidence_level': 'HIGH',
                'score': 0.0,
                'P_rf': 0.0,
                'P_cnn': 0.0,
                'semantic_score': 0.0,
                'semantic_breakdown': {'high_risk_keywords': [], 'medium_risk_keywords': [],
                                       'sql_functions': [], 'comment_patterns': [],
                                       'injection_patterns': []},
                'attack_type': AttackType.NONE.value,
                'severity': Severity.INFO.value,
                'reason': 'Fast-path: no SQL indicators in input',
                'rule': 'FAST_PATH_SAFE',
                'features': self.extract_features(text),
                'models_loaded': {'rf': self.rf_loaded, 'cnn': self.cnn_loaded},
                'processing_time_ms': round(elapsed, 2),
                'input_hash': input_hash,
                'explanation': {
                    'summary': 'Input is safe — no SQL indicators detected by lexical pre-filter.',
                    'layer_results': {
                        'normalization': norm_meta,
                        'lexical_prefilter': lexical,
                    },
                    'decision_rule': 'FAST_PATH_SAFE',
                    'decision_factors': ['Lexical pre-filter found zero SQL indicators'],
                },
                'siem_fields': {},
            }

        # Layer 2: ML Ensemble predictions
        P_rf = self._predict_rf(text)
        P_cnn = self._predict_cnn(text) if self.cnn_loaded else P_rf

        # Layer 3: Semantic validation (uses normalized text to defeat encoding evasion)
        semantic = self.semantic_analyzer.analyze(normalized_text)

        # If the normalizer detected active evasion (zero-width chars, math-styled
        # Unicode, comment splitting, etc.), the "standalone SQL" downgrade that caps
        # sem to 1.0 is wrong — obfuscated SQL is an attack, not documentation.
        # Re-score without the downgrade by checking for evasion + capped score.
        if had_evasion and semantic['score'] <= 1.0 and len(semantic['breakdown']['high_risk_keywords']) > 0:
            # The presence of high-risk keywords + active evasion = attack
            uncapped_score = 0.0
            uncapped_score += len(semantic['breakdown']['high_risk_keywords']) * 3
            uncapped_score += min(len(semantic['breakdown']['medium_risk_keywords']), 3)
            uncapped_score += len(semantic['breakdown']['sql_functions']) * 4
            uncapped_score += len(semantic['breakdown']['comment_patterns']) * 2
            # Add bonus for evasion itself
            uncapped_score += 2  # evasion detection bonus
            semantic['score'] = uncapped_score
            semantic['has_sql_semantics'] = uncapped_score >= 2
            semantic['structural_validity'] = True
            semantic['evidence'].append(
                f"Evasion detected ({', '.join(t for t in norm_meta['transformations'] if t in evasion_transforms)}) "
                f"— standalone SQL downgrade reversed"
            )

        attack_type = semantic['attack_type']

        # Layer 4: Decision engine
        result = self._ensemble_decision(P_rf, P_cnn, semantic)

        decision = result['decision']
        action = result['action']

        # Layer 5: Severity classification
        if decision == Decision.INJECTION:
            severity = self.severity_classifier.classify(attack_type, normalized_text)
            # INJECTION is always at least BLOCK; severity never downgrades action
            action = Action.BLOCK
        elif decision == Decision.SUSPICIOUS:
            severity = Severity.LOW
        elif decision == Decision.INVALID:
            severity = Severity.INFO
        else:
            severity = Severity.INFO

        elapsed = (time.time() - start_time) * 1000
        input_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

        # Layer 6: Explainability
        explain_output = self.explainability.build_explanation(
            decision=decision,
            action=action,
            severity=severity,
            attack_type=attack_type,
            confidence=result['confidence_level'],
            ensemble_score=result['score'],
            P_rf=P_rf, P_cnn=P_cnn,
            semantic_result=semantic,
            normalization_meta=norm_meta,
            lexical_result=lexical,
            decision_rule=result.get('rule', ''),
            detection_time_ms=elapsed,
            input_hash=input_hash,
            source_ip=source_ip,
            endpoint=endpoint,
            field_name=field_name,
            http_method=http_method,
        )

        # Build final output
        final_result = {
            'decision': decision.value,
            'action': action.value,
            'confidence_level': result['confidence_level'],
            'score': result['score'],
            'P_rf': P_rf,
            'P_cnn': P_cnn,
            'semantic_score': semantic['score'],
            'semantic_breakdown': semantic['breakdown'],
            'attack_type': attack_type.value,
            'severity': severity.value,
            'reason': result['reason'],
            'rule': result.get('rule', ''),
            'features': self.extract_features(text),
            'models_loaded': {
                'rf': self.rf_loaded,
                'cnn': self.cnn_loaded,
            },
            'processing_time_ms': round(elapsed, 2),
            'input_hash': input_hash,
            'explanation': explain_output['explanation'],
            'siem_fields': explain_output['siem_fields'],
        }

        # Log detection
        log.info("detection_complete",
                 decision=decision.value,
                 action=action.value,
                 severity=severity.value,
                 score=round(result['score'], 3),
                 semantic=semantic['score'],
                 attack_type=attack_type.value,
                 time_ms=round(elapsed, 2))

        return final_result

    def detect_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """Detect SQL injection in multiple texts."""
        return [self.detect(text) for text in texts]

    def is_safe(self, text: str) -> bool:
        """Quick check if input is safe."""
        decision = self.detect(text)['decision']
        return decision in ['SAFE', 'INVALID']

    def should_block(self, text: str) -> bool:
        """Check if input should be blocked."""
        result = self.detect(text)
        return result['action'] in ('BLOCK', 'ALERT')

    def get_cef(self, result: dict) -> str:
        """Get CEF format string for a detection result."""
        return self.explainability.build_cef(result)


# ═══════════════════════════════════════════════════════════════════
# LEGACY API (backward compatibility)
# ═══════════════════════════════════════════════════════════════════

class SQLInjectionDetector:
    """Legacy detector using only Random Forest (backward compatible)."""

    def __init__(self, threshold: float = 0.5):
        self._ensemble = SQLInjectionEnsemble()
        self.threshold = threshold
        self.model_loaded = self._ensemble.rf_loaded

    def detect(self, text: str) -> dict[str, Any]:
        P_rf = self._ensemble._predict_rf(text)
        is_injection = P_rf >= self.threshold

        return {
            'is_injection': is_injection,
            'confidence': P_rf if is_injection else (1 - P_rf),
            'label': 'SQL_INJECTION' if is_injection else 'SAFE',
            'probability': P_rf,
            'features': self._ensemble.extract_features(text)
        }

    def is_safe(self, text: str) -> bool:
        return not self.detect(text)['is_injection']


# ═══════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

# Module-level singleton (prevents creating new detector per call)
_default_detector: SQLInjectionEnsemble | None = None


def _get_detector() -> SQLInjectionEnsemble:
    """Get or create the global detector singleton."""
    global _default_detector
    if _default_detector is None:
        _default_detector = SQLInjectionEnsemble()
    return _default_detector


def detect_sql_injection(text: str) -> dict[str, Any]:
    """Quick detection using ensemble singleton (recommended)."""
    return _get_detector().detect(text)


def create_middleware():
    """Create middleware function for web frameworks."""
    detector = _get_detector()

    def check_request(params: dict[str, str]) -> dict[str, Any]:
        """Check all parameters for SQL injection."""
        blocked = False
        results = []

        for key, value in params.items():
            if isinstance(value, str) and len(value) > 0:
                result = detector.detect(value)
                if result['action'] in ('BLOCK', 'ALERT'):
                    blocked = True
                results.append({
                    'parameter': key,
                    'decision': result['decision'],
                    'action': result['action'],
                    'score': result['score'],
                    'semantic_score': result['semantic_score'],
                    'attack_type': result['attack_type'],
                    'severity': result['severity'],
                })

        return {
            'blocked': blocked,
            'results': results,
        }

    return check_request


# ═══════════════════════════════════════════════════════════════════
# DEMO
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 110)
    print("SQL Injection Ensemble Detector v3.0 — Production Demo")
    print("=" * 110)

    detector = SQLInjectionEnsemble()
    print(f"\nModels: RF={detector.rf_loaded}, CNN={detector.cnn_loaded}")
    print(f"Config: w_rf={detector.config.w_rf}, w_cnn={detector.config.w_cnn}")

    test_cases = [
        # Injections
        "' OR '1'='1",
        "' UNION SELECT password FROM users--",
        "'; DROP TABLE users; --",
        "' AND SLEEP(5)--",
        "%27%20OR%20%271%27%3D%271",

        # Safe
        "John O'Brien",
        "hello@email.com",
        "Please select an option",

        # Invalid
        "'fqule' = Robert O'nill",
        "!@#$%^&*()_+",
        "'''''",
    ]

    header = f"{'Input':<45} {'Decision':<11} {'Action':<9} {'Severity':<9} {'Attack':<18} {'S':>5} {'RF':>5} {'CNN':>5} {'Sem':>4} {'ms':>6}"
    print(f"\n{header}")
    print("-" * 130)

    for test in test_cases:
        r = detector.detect(test)
        display = test[:43] + '..' if len(test) > 45 else test
        print(f"{display:<45} {r['decision']:<11} {r['action']:<9} {r['severity']:<9} "
              f"{r['attack_type']:<18} {r['score']:5.2f} {r['P_rf']:5.2f} {r['P_cnn']:5.2f} "
              f"{r['semantic_score']:4.1f} {r['processing_time_ms']:6.1f}")

    print("\n" + "=" * 110)
