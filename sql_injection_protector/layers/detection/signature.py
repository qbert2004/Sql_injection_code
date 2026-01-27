"""Signature-based SQL injection detection using regex patterns."""

import re
import time
from dataclasses import dataclass
from typing import Optional

from sql_injection_protector.core.result import DetectorScore, DetectorType, FeatureVector
from sql_injection_protector.layers.detection.base import Detector


@dataclass
class SignatureRule:
    """A signature detection rule."""

    id: str
    name: str
    pattern: re.Pattern
    severity: float  # 0.0 - 1.0
    category: str
    description: str
    enabled: bool = True

    def match(self, text: str) -> Optional[re.Match]:
        """Check if rule matches text."""
        if not self.enabled:
            return None
        return self.pattern.search(text)


class SignatureDetector(Detector):
    """
    Signature-based detector using compiled regex patterns.

    Detects known SQL injection patterns including:
    - UNION-based injection
    - Boolean-based injection
    - Time-based blind injection
    - Error-based injection
    - Stacked queries
    - Comment injection
    """

    def __init__(self, weight: float = 0.3, rules: Optional[list[SignatureRule]] = None):
        """
        Initialize signature detector.

        Args:
            weight: Weight for ensemble scoring
            rules: Custom rules (uses defaults if None)
        """
        super().__init__(
            detector_type=DetectorType.SIGNATURE,
            name="SignatureDetector",
            weight=weight,
        )
        self.rules = rules or self._default_rules()

    def _default_rules(self) -> list[SignatureRule]:
        """Get default signature rules."""
        return [
            # UNION-based injection
            SignatureRule(
                id="SQLI-001",
                name="union_select",
                pattern=re.compile(
                    r"\bunion\b[\s\S]*?\bselect\b",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="union",
                description="UNION SELECT injection",
            ),
            SignatureRule(
                id="SQLI-002",
                name="union_all_select",
                pattern=re.compile(
                    r"\bunion\s+all\s+select\b",
                    re.IGNORECASE,
                ),
                severity=0.98,
                category="union",
                description="UNION ALL SELECT injection",
            ),
            # Boolean-based injection
            SignatureRule(
                id="SQLI-010",
                name="or_true_numeric",
                pattern=re.compile(
                    r"\bor\b\s+\d+\s*=\s*\d+",
                    re.IGNORECASE,
                ),
                severity=0.85,
                category="boolean",
                description="OR number=number injection",
            ),
            SignatureRule(
                id="SQLI-011",
                name="or_true_string",
                pattern=re.compile(
                    r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
                    re.IGNORECASE,
                ),
                severity=0.80,
                category="boolean",
                description="OR string=string injection",
            ),
            SignatureRule(
                id="SQLI-012",
                name="and_true_numeric",
                pattern=re.compile(
                    r"\band\b\s+\d+\s*=\s*\d+",
                    re.IGNORECASE,
                ),
                severity=0.75,
                category="boolean",
                description="AND number=number injection",
            ),
            SignatureRule(
                id="SQLI-013",
                name="or_1_equals_1",
                pattern=re.compile(
                    r"\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="boolean",
                description="Classic OR 1=1 injection",
            ),
            SignatureRule(
                id="SQLI-014",
                name="always_true",
                pattern=re.compile(
                    r"['\"]?\s*\bor\b\s+['\"]?[^'\"]+['\"]?\s*=\s*['\"]?[^'\"]+['\"]?\s*--",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="boolean",
                description="Always true condition with comment",
            ),
            # Time-based blind injection
            SignatureRule(
                id="SQLI-020",
                name="sleep_function",
                pattern=re.compile(
                    r"\bsleep\s*\(\s*\d+\s*\)",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="time_based",
                description="MySQL SLEEP() function",
            ),
            SignatureRule(
                id="SQLI-021",
                name="benchmark_function",
                pattern=re.compile(
                    r"\bbenchmark\s*\(\s*\d+\s*,",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="time_based",
                description="MySQL BENCHMARK() function",
            ),
            SignatureRule(
                id="SQLI-022",
                name="waitfor_delay",
                pattern=re.compile(
                    r"\bwaitfor\s+delay\b",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="time_based",
                description="MSSQL WAITFOR DELAY",
            ),
            SignatureRule(
                id="SQLI-023",
                name="pg_sleep",
                pattern=re.compile(
                    r"\bpg_sleep\s*\(",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="time_based",
                description="PostgreSQL pg_sleep() function",
            ),
            # Error-based injection
            SignatureRule(
                id="SQLI-030",
                name="extractvalue",
                pattern=re.compile(
                    r"\bextractvalue\s*\(",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="error_based",
                description="MySQL EXTRACTVALUE() injection",
            ),
            SignatureRule(
                id="SQLI-031",
                name="updatexml",
                pattern=re.compile(
                    r"\bupdatexml\s*\(",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="error_based",
                description="MySQL UPDATEXML() injection",
            ),
            # Stacked queries
            SignatureRule(
                id="SQLI-040",
                name="stacked_select",
                pattern=re.compile(
                    r";\s*select\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="stacked",
                description="Stacked SELECT query",
            ),
            SignatureRule(
                id="SQLI-041",
                name="stacked_insert",
                pattern=re.compile(
                    r";\s*insert\b",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="stacked",
                description="Stacked INSERT query",
            ),
            SignatureRule(
                id="SQLI-042",
                name="stacked_update",
                pattern=re.compile(
                    r";\s*update\b",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="stacked",
                description="Stacked UPDATE query",
            ),
            SignatureRule(
                id="SQLI-043",
                name="stacked_delete",
                pattern=re.compile(
                    r";\s*delete\b",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="stacked",
                description="Stacked DELETE query",
            ),
            SignatureRule(
                id="SQLI-044",
                name="stacked_drop",
                pattern=re.compile(
                    r";\s*drop\b",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="stacked",
                description="Stacked DROP query",
            ),
            # Comment injection
            SignatureRule(
                id="SQLI-050",
                name="inline_comment",
                pattern=re.compile(
                    r"/\*.*?\*/",
                    re.DOTALL,
                ),
                severity=0.60,
                category="comment",
                description="Inline SQL comment",
            ),
            SignatureRule(
                id="SQLI-051",
                name="line_comment_dash",
                pattern=re.compile(
                    r"--\s*$|--\s+",
                ),
                severity=0.70,
                category="comment",
                description="SQL line comment (--)",
            ),
            SignatureRule(
                id="SQLI-052",
                name="line_comment_hash",
                pattern=re.compile(
                    r"#\s*$|#\s+",
                ),
                severity=0.65,
                category="comment",
                description="MySQL line comment (#)",
            ),
            # Information gathering
            SignatureRule(
                id="SQLI-060",
                name="information_schema",
                pattern=re.compile(
                    r"\binformation_schema\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="info_gathering",
                description="Information schema access",
            ),
            SignatureRule(
                id="SQLI-061",
                name="sys_tables",
                pattern=re.compile(
                    r"\b(sysobjects|syscolumns|sysusers)\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="info_gathering",
                description="MSSQL system table access",
            ),
            # Dangerous functions
            SignatureRule(
                id="SQLI-070",
                name="load_file",
                pattern=re.compile(
                    r"\bload_file\s*\(",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="dangerous",
                description="MySQL LOAD_FILE() function",
            ),
            SignatureRule(
                id="SQLI-071",
                name="into_outfile",
                pattern=re.compile(
                    r"\binto\s+outfile\b",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="dangerous",
                description="MySQL INTO OUTFILE",
            ),
            SignatureRule(
                id="SQLI-072",
                name="xp_cmdshell",
                pattern=re.compile(
                    r"\bxp_cmdshell\b",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="dangerous",
                description="MSSQL xp_cmdshell",
            ),
            # Quote manipulation
            SignatureRule(
                id="SQLI-080",
                name="quote_escape",
                pattern=re.compile(
                    r"['\"](\s*|\s+)or(\s*|\s+)['\"]",
                    re.IGNORECASE,
                ),
                severity=0.85,
                category="quote",
                description="Quote escape with OR",
            ),
            SignatureRule(
                id="SQLI-081",
                name="double_quote_escape",
                pattern=re.compile(
                    r"['\"]['\"]",
                ),
                severity=0.50,
                category="quote",
                description="Double quote (escape attempt)",
            ),
            # Hex encoding
            SignatureRule(
                id="SQLI-090",
                name="hex_string",
                pattern=re.compile(
                    r"0x[0-9A-Fa-f]{8,}",
                ),
                severity=0.70,
                category="encoding",
                description="Hex-encoded string",
            ),
            SignatureRule(
                id="SQLI-091",
                name="char_encoding",
                pattern=re.compile(
                    r"\bchar\s*\(\s*\d+(\s*,\s*\d+)*\s*\)",
                    re.IGNORECASE,
                ),
                severity=0.75,
                category="encoding",
                description="CHAR() encoding",
            ),
        ]

    async def detect(
        self,
        text: str,
        feature_vector: Optional[FeatureVector] = None,
    ) -> DetectorScore:
        """
        Check text against all signature rules.

        Args:
            text: Input text to analyze
            feature_vector: Optional feature vector (not used)

        Returns:
            DetectorScore with match results
        """
        start_time = time.perf_counter()

        matched_rules: list[SignatureRule] = []
        max_severity = 0.0

        for rule in self.rules:
            if rule.match(text):
                matched_rules.append(rule)
                max_severity = max(max_severity, rule.severity)

        is_malicious = len(matched_rules) > 0
        score = max_severity if matched_rules else 0.0

        # Boost score if multiple rules match
        if len(matched_rules) > 1:
            score = min(1.0, score + 0.1 * (len(matched_rules) - 1))

        processing_time = (time.perf_counter() - start_time) * 1000

        return self._create_score(
            score=score,
            is_malicious=is_malicious,
            confidence=score,
            details={
                "matched_count": len(matched_rules),
                "categories": list(set(r.category for r in matched_rules)),
            },
            matched_patterns=[r.name for r in matched_rules],
            processing_time_ms=processing_time,
        )

    def add_rule(self, rule: SignatureRule) -> None:
        """Add a custom rule."""
        self.rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = False
                return True
        return False

    def get_rule(self, rule_id: str) -> Optional[SignatureRule]:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def get_rules_by_category(self, category: str) -> list[SignatureRule]:
        """Get all rules in a category."""
        return [r for r in self.rules if r.category == category]

    def get_categories(self) -> list[str]:
        """Get all unique rule categories."""
        return list(set(r.category for r in self.rules))

    def test_rule(self, rule_id: str, test_cases: list[str]) -> dict:
        """
        Test a specific rule against test cases.

        Returns match results for each test case.
        """
        rule = self.get_rule(rule_id)
        if not rule:
            return {"error": f"Rule {rule_id} not found"}

        results = {}
        for test in test_cases:
            match = rule.match(test)
            results[test] = {
                "matched": bool(match),
                "match_text": match.group(0) if match else None,
            }

        return results
