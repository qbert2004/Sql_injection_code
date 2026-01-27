"""OWASP Core Rule Set (CRS) inspired SQL injection rules."""

import re
from typing import List

from sql_injection_protector.layers.detection.signature import SignatureRule


class OWASPSQLiPlugin:
    """
    Plugin providing OWASP CRS-inspired SQL injection detection rules.

    Based on OWASP ModSecurity Core Rule Set (CRS) rules for SQL injection.
    Rule IDs follow CRS convention: 942xxx for SQL injection.
    """

    @property
    def name(self) -> str:
        return "owasp-sqli"

    @property
    def version(self) -> str:
        return "4.0.0"

    def get_rules(self) -> List[SignatureRule]:
        """Get all OWASP CRS-inspired rules."""
        return (
            self._get_union_rules()
            + self._get_select_rules()
            + self._get_boolean_rules()
            + self._get_comment_rules()
            + self._get_function_rules()
            + self._get_operator_rules()
            + self._get_encoding_rules()
            + self._get_db_specific_rules()
        )

    def _get_union_rules(self) -> List[SignatureRule]:
        """UNION-based injection rules."""
        return [
            SignatureRule(
                id="942100",
                name="owasp_union_attack",
                pattern=re.compile(
                    r"(?i)\bunion\b.+\bselect\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                severity=0.95,
                category="owasp-union",
                description="OWASP CRS: SQL Injection Attack Detected via libinjection",
            ),
            SignatureRule(
                id="942101",
                name="owasp_union_all_select",
                pattern=re.compile(
                    r"(?i)\bunion\s+all\s+select\b",
                    re.IGNORECASE,
                ),
                severity=0.98,
                category="owasp-union",
                description="OWASP CRS: UNION ALL SELECT detected",
            ),
            SignatureRule(
                id="942102",
                name="owasp_union_select_null",
                pattern=re.compile(
                    r"(?i)\bunion\b.+\bselect\b.+\bnull\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                severity=0.95,
                category="owasp-union",
                description="OWASP CRS: UNION SELECT with NULL values",
            ),
        ]

    def _get_select_rules(self) -> List[SignatureRule]:
        """SELECT-based injection rules."""
        return [
            SignatureRule(
                id="942110",
                name="owasp_select_from",
                pattern=re.compile(
                    r"(?i)\bselect\b.+\bfrom\b.+\bwhere\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                severity=0.70,
                category="owasp-select",
                description="OWASP CRS: SQL SELECT FROM WHERE pattern",
            ),
            SignatureRule(
                id="942111",
                name="owasp_subselect",
                pattern=re.compile(
                    r"(?i)\(\s*select\b",
                    re.IGNORECASE,
                ),
                severity=0.80,
                category="owasp-select",
                description="OWASP CRS: SQL subselect detected",
            ),
            SignatureRule(
                id="942112",
                name="owasp_select_concat",
                pattern=re.compile(
                    r"(?i)\bselect\b.+\bconcat\s*\(",
                    re.IGNORECASE | re.DOTALL,
                ),
                severity=0.85,
                category="owasp-select",
                description="OWASP CRS: SELECT with CONCAT function",
            ),
        ]

    def _get_boolean_rules(self) -> List[SignatureRule]:
        """Boolean-based injection rules."""
        return [
            SignatureRule(
                id="942120",
                name="owasp_always_true_1",
                pattern=re.compile(
                    r"(?i)['\"]?\s*\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-boolean",
                description="OWASP CRS: SQL Always True Condition (OR number=number)",
            ),
            SignatureRule(
                id="942121",
                name="owasp_always_true_2",
                pattern=re.compile(
                    r"(?i)['\"]?\s*\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
                    re.IGNORECASE,
                ),
                severity=0.85,
                category="owasp-boolean",
                description="OWASP CRS: SQL Always True Condition (OR string=string)",
            ),
            SignatureRule(
                id="942122",
                name="owasp_boolean_and",
                pattern=re.compile(
                    r"(?i)['\"]?\s*\band\b\s+['\"]?\d+['\"]?\s*[<>=]+\s*['\"]?\d+['\"]?",
                    re.IGNORECASE,
                ),
                severity=0.75,
                category="owasp-boolean",
                description="OWASP CRS: SQL Boolean Condition (AND comparison)",
            ),
            SignatureRule(
                id="942123",
                name="owasp_classic_sqli",
                pattern=re.compile(
                    r"(?i)['\"]?\s*;\s*--",
                ),
                severity=0.90,
                category="owasp-boolean",
                description="OWASP CRS: Classic SQL Injection termination",
            ),
        ]

    def _get_comment_rules(self) -> List[SignatureRule]:
        """Comment injection rules."""
        return [
            SignatureRule(
                id="942130",
                name="owasp_comment_injection_1",
                pattern=re.compile(
                    r"(?i)/\*!?\d*\s*\*/",
                ),
                severity=0.75,
                category="owasp-comment",
                description="OWASP CRS: MySQL inline comment",
            ),
            SignatureRule(
                id="942131",
                name="owasp_comment_injection_2",
                pattern=re.compile(
                    r"(?i)--\s*$|--\s+\w",
                ),
                severity=0.70,
                category="owasp-comment",
                description="OWASP CRS: SQL line comment",
            ),
            SignatureRule(
                id="942132",
                name="owasp_comment_evasion",
                pattern=re.compile(
                    r"(?i)/\*.*?\*/",
                    re.DOTALL,
                ),
                severity=0.65,
                category="owasp-comment",
                description="OWASP CRS: SQL block comment (potential evasion)",
            ),
        ]

    def _get_function_rules(self) -> List[SignatureRule]:
        """Dangerous function detection rules."""
        return [
            SignatureRule(
                id="942140",
                name="owasp_dangerous_func_1",
                pattern=re.compile(
                    r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
                    re.IGNORECASE,
                ),
                severity=0.95,
                category="owasp-function",
                description="OWASP CRS: Time-based SQL injection function",
            ),
            SignatureRule(
                id="942141",
                name="owasp_dangerous_func_2",
                pattern=re.compile(
                    r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="owasp-function",
                description="OWASP CRS: File operation SQL function",
            ),
            SignatureRule(
                id="942142",
                name="owasp_dangerous_func_3",
                pattern=re.compile(
                    r"(?i)\b(extractvalue|updatexml|xmltype)\s*\(",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-function",
                description="OWASP CRS: Error-based SQL injection function",
            ),
            SignatureRule(
                id="942143",
                name="owasp_char_encoding",
                pattern=re.compile(
                    r"(?i)\bchar\s*\(\s*\d+(\s*,\s*\d+)*\s*\)",
                    re.IGNORECASE,
                ),
                severity=0.80,
                category="owasp-function",
                description="OWASP CRS: CHAR() encoding detected",
            ),
            SignatureRule(
                id="942144",
                name="owasp_convert_func",
                pattern=re.compile(
                    r"(?i)\b(cast|convert)\s*\(.+\bas\b",
                    re.IGNORECASE,
                ),
                severity=0.65,
                category="owasp-function",
                description="OWASP CRS: Type conversion function",
            ),
        ]

    def _get_operator_rules(self) -> List[SignatureRule]:
        """SQL operator patterns."""
        return [
            SignatureRule(
                id="942150",
                name="owasp_operator_chain",
                pattern=re.compile(
                    r"(?i)\b(and|or)\b.+\b(and|or)\b.+\b(and|or)\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                severity=0.70,
                category="owasp-operator",
                description="OWASP CRS: Multiple boolean operators",
            ),
            SignatureRule(
                id="942151",
                name="owasp_like_injection",
                pattern=re.compile(
                    r"(?i)\blike\s+['\"]%",
                    re.IGNORECASE,
                ),
                severity=0.50,
                category="owasp-operator",
                description="OWASP CRS: LIKE wildcard pattern",
            ),
            SignatureRule(
                id="942152",
                name="owasp_having_clause",
                pattern=re.compile(
                    r"(?i)\bhaving\s+\d+\s*=\s*\d+",
                    re.IGNORECASE,
                ),
                severity=0.85,
                category="owasp-operator",
                description="OWASP CRS: HAVING clause injection",
            ),
            SignatureRule(
                id="942153",
                name="owasp_order_by_injection",
                pattern=re.compile(
                    r"(?i)\border\s+by\s+\d+",
                    re.IGNORECASE,
                ),
                severity=0.60,
                category="owasp-operator",
                description="OWASP CRS: ORDER BY column number",
            ),
        ]

    def _get_encoding_rules(self) -> List[SignatureRule]:
        """Encoding-based evasion rules."""
        return [
            SignatureRule(
                id="942160",
                name="owasp_hex_encoding",
                pattern=re.compile(
                    r"(?i)0x[0-9a-f]{8,}",
                    re.IGNORECASE,
                ),
                severity=0.75,
                category="owasp-encoding",
                description="OWASP CRS: Hex-encoded string detected",
            ),
            SignatureRule(
                id="942161",
                name="owasp_unicode_encoding",
                pattern=re.compile(
                    r"(?i)\\u00[0-9a-f]{2}",
                    re.IGNORECASE,
                ),
                severity=0.70,
                category="owasp-encoding",
                description="OWASP CRS: Unicode escape sequence",
            ),
            SignatureRule(
                id="942162",
                name="owasp_url_encoding",
                pattern=re.compile(
                    r"%27|%22|%3b|%2d%2d|%23",
                    re.IGNORECASE,
                ),
                severity=0.60,
                category="owasp-encoding",
                description="OWASP CRS: URL-encoded SQL characters",
            ),
        ]

    def _get_db_specific_rules(self) -> List[SignatureRule]:
        """Database-specific injection rules."""
        return [
            # MySQL specific
            SignatureRule(
                id="942170",
                name="owasp_mysql_specific",
                pattern=re.compile(
                    r"(?i)\b(information_schema|mysql\.|performance_schema)\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-mysql",
                description="OWASP CRS: MySQL system table access",
            ),
            # MSSQL specific
            SignatureRule(
                id="942171",
                name="owasp_mssql_specific",
                pattern=re.compile(
                    r"(?i)\b(xp_cmdshell|sp_executesql|master\.\.sysdatabases)\b",
                    re.IGNORECASE,
                ),
                severity=1.0,
                category="owasp-mssql",
                description="OWASP CRS: MSSQL dangerous procedure",
            ),
            SignatureRule(
                id="942172",
                name="owasp_mssql_system",
                pattern=re.compile(
                    r"(?i)\b(sysobjects|syscolumns|sysusers|sysdatabases)\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-mssql",
                description="OWASP CRS: MSSQL system table access",
            ),
            # PostgreSQL specific
            SignatureRule(
                id="942173",
                name="owasp_pgsql_specific",
                pattern=re.compile(
                    r"(?i)\b(pg_catalog|pg_sleep|pg_user|pg_database)\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-pgsql",
                description="OWASP CRS: PostgreSQL system access",
            ),
            # Oracle specific
            SignatureRule(
                id="942174",
                name="owasp_oracle_specific",
                pattern=re.compile(
                    r"(?i)\b(all_tables|dba_users|v\$version|utl_http)\b",
                    re.IGNORECASE,
                ),
                severity=0.90,
                category="owasp-oracle",
                description="OWASP CRS: Oracle system access",
            ),
            # SQLite specific
            SignatureRule(
                id="942175",
                name="owasp_sqlite_specific",
                pattern=re.compile(
                    r"(?i)\b(sqlite_master|sqlite_version)\b",
                    re.IGNORECASE,
                ),
                severity=0.85,
                category="owasp-sqlite",
                description="OWASP CRS: SQLite system table access",
            ),
        ]


# Factory function
def create_owasp_plugin() -> OWASPSQLiPlugin:
    """Create an OWASP CRS plugin instance."""
    return OWASPSQLiPlugin()
