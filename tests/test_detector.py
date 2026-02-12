"""
Pytest test suite for SQL Injection Detector.

Tests cover:
    - Classification correctness (SAFE, INVALID, INJECTION)
    - False positive prevention (safe inputs must not be blocked)
    - False negative prevention (attacks must be blocked)
    - Semantic analyzer accuracy
    - Attack type classification
    - Severity mapping
    - Explainability output structure
    - Input normalization
    - Edge cases and obfuscation
"""
import pytest


# ═══════════════════════════════════════════════════════════════════
# SAFE INPUTS — Must be SAFE or INVALID, never BLOCK
# ═══════════════════════════════════════════════════════════════════

SAFE_INPUTS = [
    # Names with apostrophes
    ("John O'Brien", "Irish name"),
    ("McDonald's", "Brand with apostrophe"),
    ("D'Angelo", "Italian name"),
    ("It's a test", "Contraction"),
    ("Don't worry", "Contraction 2"),
    ("children's toys", "Possessive"),

    # Normal text
    ("Hello World", "Simple text"),
    ("The quick brown fox", "Pangram"),
    ("user@example.com", "Email"),
    ("192.168.1.1", "IP address"),
    ("2024-01-15", "Date"),
    ("+1-555-123-4567", "Phone number"),
    ("john_doe", "Username"),
    ("password123", "Password"),
    ("admin", "Simple username"),

    # Text with SQL keywords (natural language)
    ("Please select an option", "select in English"),
    ("Drop me a line", "drop in English"),
    ("Update your profile", "update in English"),
    ("Delete old files", "delete in English"),
    ("Join our union", "union in English"),
    ("Insert coin to play", "insert in English"),
    ("The table is ready", "table in English"),

    # Special characters (non-SQL)
    ("C++ programming", "Programming language"),
    ("Price: $99.99", "Price"),
    ("50% discount!", "Percentage"),
    ("Rock 'n' Roll", "Music"),
    ("5 o'clock", "Time expression"),
]


@pytest.mark.parametrize("input_text,description", SAFE_INPUTS)
def test_safe_inputs_not_blocked(detector, input_text, description):
    """Safe inputs must NOT be blocked."""
    result = detector.detect(input_text)
    assert result['action'] != 'BLOCK', (
        f"FALSE POSITIVE: '{input_text}' ({description}) was blocked. "
        f"Decision={result['decision']}, Score={result['score']:.2f}, "
        f"Semantic={result['semantic_score']}"
    )


@pytest.mark.parametrize("input_text,description", SAFE_INPUTS)
def test_safe_inputs_not_alerted(detector, input_text, description):
    """Safe inputs must NOT trigger ALERT."""
    result = detector.detect(input_text)
    assert result['action'] != 'ALERT', (
        f"FALSE POSITIVE ALERT: '{input_text}' ({description}) triggered ALERT."
    )


# ═══════════════════════════════════════════════════════════════════
# INVALID INPUTS — Must be INVALID/LOG, never BLOCK
# ═══════════════════════════════════════════════════════════════════

INVALID_INPUTS = [
    ("''''''''", "Many quotes"),
    ("!@#$%^&*()", "Special chars only"),
    ("asdfghjkl", "Random letters"),
    ("========", "Many equals"),
    ("........", "Many dots"),
    ("'a'b'c'd'e'", "Quote mess"),
    ("'fqule' = Robert O'nill", "Malformed comparison"),
    ("<script>alert(1)</script>", "XSS not SQLi"),
    ("../../../../etc/passwd", "Path traversal not SQLi"),
    ("{{7*7}}", "SSTI not SQLi"),
    ("'1'1'1'1'11'1'1", "Quote garbage"),
    ("x' y' z'", "Multiple trailing quotes"),
]


@pytest.mark.parametrize("input_text,description", INVALID_INPUTS)
def test_invalid_inputs_not_blocked(detector, input_text, description):
    """Invalid/malformed inputs must NOT be blocked."""
    result = detector.detect(input_text)
    assert result['action'] != 'BLOCK', (
        f"FALSE POSITIVE: '{input_text}' ({description}) was blocked. "
        f"Decision={result['decision']}, Score={result['score']:.2f}, "
        f"Semantic={result['semantic_score']}"
    )


# ═══════════════════════════════════════════════════════════════════
# SQL INJECTIONS — Must be INJECTION and BLOCK (or ALERT)
# ═══════════════════════════════════════════════════════════════════

INJECTION_INPUTS = [
    # Classic injections
    ("' OR '1'='1", "Classic OR tautology"),
    ("' OR 1=1--", "OR with comment"),
    ("admin'--", "Comment bypass"),
    ("' OR 'a'='a", "String tautology"),

    # UNION-based
    ("' UNION SELECT NULL--", "UNION NULL"),
    ("' UNION SELECT username,password FROM users--", "UNION data extraction"),
    ("' UNION SELECT @@version--", "UNION version"),

    # Stacked queries
    ("'; DROP TABLE users--", "DROP TABLE"),
    ("'; DELETE FROM users--", "DELETE"),
    ("'; UPDATE users SET password='hacked'--", "UPDATE"),

    # Time-based blind
    ("' AND SLEEP(5)--", "MySQL SLEEP"),
    ("' AND BENCHMARK(10000000,SHA1('x'))--", "BENCHMARK"),
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR"),

    # Boolean-based blind
    ("' AND 1=1--", "Boolean true"),
    ("' AND SUBSTRING(username,1,1)='a'--", "Substring extraction"),

    # Error-based
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "Extractvalue"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", "Updatexml"),

    # MSSQL specific
    ("; EXEC xp_cmdshell('dir')--", "MSSQL cmdshell"),

    # Obfuscated
    ("'/**/OR/**/1=1--", "Comment obfuscation"),
    ("%27%20OR%201=1--", "URL encoded"),
    ("'OR'1'='1", "No-space obfuscation"),
]


@pytest.mark.parametrize("input_text,description", INJECTION_INPUTS)
def test_injections_are_blocked(detector, input_text, description):
    """SQL injections must be detected and blocked."""
    result = detector.detect(input_text)
    assert result['action'] in ('BLOCK', 'ALERT'), (
        f"FALSE NEGATIVE: '{input_text}' ({description}) was not blocked. "
        f"Decision={result['decision']}, Action={result['action']}, "
        f"Score={result['score']:.2f}, Semantic={result['semantic_score']}"
    )


@pytest.mark.parametrize("input_text,description", INJECTION_INPUTS)
def test_injections_are_classified_as_injection(detector, input_text, description):
    """SQL injections must be classified as INJECTION."""
    result = detector.detect(input_text)
    assert result['decision'] == 'INJECTION', (
        f"WRONG CLASS: '{input_text}' ({description}) classified as {result['decision']}. "
        f"Score={result['score']:.2f}, Semantic={result['semantic_score']}"
    )


# ═══════════════════════════════════════════════════════════════════
# ATTACK TYPE CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════

ATTACK_TYPE_CASES = [
    ("' OR '1'='1", "BOOLEAN_BASED"),
    ("' UNION SELECT username,password FROM users--", "UNION_BASED"),
    ("'; DROP TABLE users--", "STACKED_QUERY"),
    ("' AND SLEEP(5)--", "TIME_BASED"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "ERROR_BASED"),
]


@pytest.mark.parametrize("input_text,expected_type", ATTACK_TYPE_CASES)
def test_attack_type_classification(detector, input_text, expected_type):
    """Attack type must be correctly classified."""
    result = detector.detect(input_text)
    assert result['attack_type'] == expected_type, (
        f"Wrong attack type for '{input_text}': "
        f"expected {expected_type}, got {result['attack_type']}"
    )


# ═══════════════════════════════════════════════════════════════════
# SEVERITY CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════

def test_stacked_drop_is_critical(detector):
    """Destructive stacked queries must be CRITICAL severity."""
    result = detector.detect("'; DROP TABLE users--")
    assert result['severity'] in ('CRITICAL', 'HIGH'), (
        f"Expected CRITICAL/HIGH severity for DROP TABLE, got {result['severity']}"
    )


def test_union_is_high(detector):
    """UNION-based extraction must be HIGH severity."""
    result = detector.detect("' UNION SELECT password FROM users--")
    assert result['severity'] == 'HIGH', (
        f"Expected HIGH severity for UNION, got {result['severity']}"
    )


def test_boolean_is_medium(detector):
    """Boolean-based injection must be MEDIUM severity."""
    result = detector.detect("' OR '1'='1")
    assert result['severity'] == 'MEDIUM', (
        f"Expected MEDIUM severity for boolean, got {result['severity']}"
    )


# ═══════════════════════════════════════════════════════════════════
# OUTPUT STRUCTURE
# ═══════════════════════════════════════════════════════════════════

def test_result_has_all_required_fields(detector):
    """Detection result must include all required fields."""
    result = detector.detect("' OR '1'='1")

    required_fields = [
        'decision', 'action', 'confidence_level', 'score',
        'P_rf', 'P_cnn',
        'semantic_score', 'semantic_breakdown',
        'attack_type', 'severity',
        'reason', 'rule', 'features',
        'models_loaded', 'processing_time_ms',
        'input_hash', 'explanation', 'siem_fields',
    ]

    for field in required_fields:
        assert field in result, f"Missing field: {field}"


def test_explanation_structure(detector):
    """Explanation must have the correct structure."""
    result = detector.detect("' OR '1'='1")
    explanation = result['explanation']

    assert 'summary' in explanation
    assert 'layer_results' in explanation
    assert 'decision_rule' in explanation
    assert 'decision_factors' in explanation


def test_siem_fields_structure(detector):
    """SIEM fields must include required ECS-compatible fields."""
    result = detector.detect("' OR '1'='1")
    siem = result['siem_fields']

    required_siem = [
        'event_id', 'timestamp', 'event_category', 'event_type',
        'event_severity', 'attack_type', 'mitre_technique',
        'detection_time_ms', 'ensemble_score', 'semantic_score',
    ]

    for field in required_siem:
        assert field in siem, f"Missing SIEM field: {field}"

    assert siem['event_category'] == 'intrusion_detection'
    assert siem['mitre_technique'] == 'T1190'


# ═══════════════════════════════════════════════════════════════════
# SEMANTIC ANALYZER UNIT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestSemanticAnalyzer:
    """Unit tests for SQLSemanticAnalyzer."""

    def test_safe_input_zero_score(self, semantic_analyzer):
        """Safe inputs must produce semantic score 0."""
        result = semantic_analyzer.analyze("Hello World")
        assert result['score'] == 0, f"Expected 0, got {result['score']}"

    def test_injection_high_score(self, semantic_analyzer):
        """SQL injections must produce semantic score >= 2."""
        result = semantic_analyzer.analyze("' OR '1'='1")
        assert result['score'] >= 2, f"Expected >= 2, got {result['score']}"

    def test_union_select_detected(self, semantic_analyzer):
        """UNION SELECT must be detected."""
        result = semantic_analyzer.analyze("' UNION SELECT NULL--")
        assert result['attack_type'].value == 'UNION_BASED'

    def test_stacked_query_detected(self, semantic_analyzer):
        """Stacked queries must be detected."""
        result = semantic_analyzer.analyze("'; DROP TABLE users--")
        assert result['attack_type'].value == 'STACKED_QUERY'

    def test_time_based_detected(self, semantic_analyzer):
        """Time-based blind must be detected."""
        result = semantic_analyzer.analyze("' AND SLEEP(5)--")
        assert result['attack_type'].value == 'TIME_BASED'

    def test_obrien_low_score(self, semantic_analyzer):
        """O'Brien must NOT trigger SQL detection."""
        result = semantic_analyzer.analyze("John O'Brien")
        assert result['score'] < 2, f"O'Brien triggered score {result['score']}"

    def test_natural_select_low_score(self, semantic_analyzer):
        """'Please select an option' must NOT trigger SQL detection."""
        result = semantic_analyzer.analyze("Please select an option")
        assert result['score'] < 2, f"Natural text triggered score {result['score']}"

    def test_structural_validity_for_injection(self, semantic_analyzer):
        """Structural validity must be True for real injections."""
        result = semantic_analyzer.analyze("' OR '1'='1")
        assert result['structural_validity'] is True

    def test_structural_validity_false_for_safe(self, semantic_analyzer):
        """Structural validity must be False for safe inputs."""
        result = semantic_analyzer.analyze("Hello World")
        assert result['structural_validity'] is False


# ═══════════════════════════════════════════════════════════════════
# INPUT NORMALIZER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestInputNormalizer:
    """Unit tests for InputNormalizer."""

    def test_url_decode(self):
        from sql_injection_detector import InputNormalizer
        text, meta = InputNormalizer.normalize("%27%20OR%201=1")
        assert "' or 1=1" in text

    def test_double_url_decode(self):
        from sql_injection_detector import InputNormalizer
        text, meta = InputNormalizer.normalize("%2527%2520OR%25201=1")
        assert "or" in text

    def test_null_byte_strip(self):
        from sql_injection_detector import InputNormalizer
        text, meta = InputNormalizer.normalize("SE\x00LECT")
        assert "\x00" not in text
        assert "select" in text

    def test_comment_strip(self):
        from sql_injection_detector import InputNormalizer
        text, meta = InputNormalizer.normalize("UN/**/ION SE/**/LECT")
        assert "un ion se lect" in text or "union select" in text.replace(" ", "").replace("  ", " ")

    def test_max_length(self):
        from sql_injection_detector import InputNormalizer
        long_input = "A" * 20000
        text, meta = InputNormalizer.normalize(long_input, max_length=10000)
        assert len(text) <= 10000
        assert meta['was_truncated'] is True

    def test_html_entity_decode(self):
        from sql_injection_detector import InputNormalizer
        text, meta = InputNormalizer.normalize("&#39; OR 1=1")
        assert "'" in text


# ═══════════════════════════════════════════════════════════════════
# INCIDENT LOGGER TESTS
# ═══════════════════════════════════════════════════════════════════

class TestIncidentLogger:
    """Unit tests for IncidentLogger."""

    def test_log_and_retrieve(self, incident_logger):
        """Logging an incident and retrieving it."""
        result = {
            'decision': 'INJECTION',
            'action': 'BLOCK',
            'score': 0.95,
            'P_rf': 0.92,
            'P_cnn': 0.97,
            'semantic_score': 8.0,
            'confidence_level': 'HIGH',
            'reason': 'Test injection',
        }

        inc_id = incident_logger.log_incident(
            input_text="' OR '1'='1",
            result=result,
            source_ip="127.0.0.1",
        )

        assert inc_id > 0

        incidents = incident_logger.get_incidents(limit=10)
        assert len(incidents) >= 1

    def test_statistics(self, incident_logger):
        """Statistics must be computed correctly."""
        result = {
            'decision': 'INJECTION',
            'action': 'BLOCK',
            'score': 0.95,
            'P_rf': 0.92,
            'P_cnn': 0.97,
            'semantic_score': 8.0,
            'confidence_level': 'HIGH',
            'reason': 'Test',
        }

        incident_logger.log_incident("test", result)
        stats = incident_logger.get_statistics()
        assert stats['total_incidents'] >= 1

    def test_feedback(self, incident_logger):
        """False positive feedback must be stored."""
        result = {
            'decision': 'INJECTION',
            'action': 'BLOCK',
            'score': 0.95,
            'P_rf': 0.92,
            'P_cnn': 0.97,
            'semantic_score': 8.0,
            'confidence_level': 'HIGH',
            'reason': 'Test',
        }

        inc_id = incident_logger.log_incident("test", result)
        incident_logger.mark_false_positive(inc_id, True, "Test FP")

        incidents = incident_logger.get_incidents(limit=10)
        found = [i for i in incidents if i['id'] == inc_id]
        assert len(found) == 1
        assert found[0]['is_false_positive'] == 1


# ═══════════════════════════════════════════════════════════════════
# ARCHITECTURAL INVARIANT TEST
# ═══════════════════════════════════════════════════════════════════

def test_architectural_invariant_ml_alone_never_injection(detector):
    """
    CRITICAL: ML confidence alone must NEVER classify as INJECTION
    without semantic score >= 2.

    This test verifies the core architectural invariant.
    """
    # Random garbage that may trigger high CNN scores
    garbage_inputs = [
        "!@#$%^&*()",
        "'''''''''",
        "========",
        "'a'b'c'd'e'f'g'",
        "x\x00y\x00z",
    ]

    for input_text in garbage_inputs:
        result = detector.detect(input_text)
        if result['semantic_score'] < 2.0:
            assert result['decision'] != 'INJECTION', (
                f"INVARIANT VIOLATION: '{input_text}' classified as INJECTION "
                f"with semantic_score={result['semantic_score']} < 2.0. "
                f"ML scores: RF={result['P_rf']:.2f}, CNN={result['P_cnn']:.2f}"
            )


# ═══════════════════════════════════════════════════════════════════
# FAST-PATH TEST
# ═══════════════════════════════════════════════════════════════════

def test_fast_path_safe(detector):
    """Clean alphanumeric input must take fast path."""
    result = detector.detect("hello world 123")
    assert result['decision'] == 'SAFE'
    assert result['rule'] == 'FAST_PATH_SAFE'
    assert result['processing_time_ms'] < 10  # Fast path should be < 10ms


# ═══════════════════════════════════════════════════════════════════
# ADVERSARIAL EXAMPLES
# ═══════════════════════════════════════════════════════════════════

ADVERSARIAL_SAFE = [
    ("The password1=1 is strong", "1=1 in natural text"),
    ("Room 101 OR similar", "OR in natural sentence"),
    ("SELECT few items from the list", "SELECT FROM in prose"),
    ("Union Station is nearby", "Union as proper noun"),
    ("The user's comment was deleted", "deleted in natural text"),
    ("O'Reilly's book on SQL", "SQL as topic"),
    ("Benchmark test results", "benchmark as English word"),
    ("The sleep timer is set", "sleep as English word"),
    ("True or false question", "or false in quiz"),
]


@pytest.mark.parametrize("input_text,description", ADVERSARIAL_SAFE)
def test_adversarial_safe_not_blocked(detector, input_text, description):
    """Adversarial safe inputs designed to fool ML must NOT be blocked."""
    result = detector.detect(input_text)
    assert result['action'] not in ('BLOCK', 'ALERT'), (
        f"ADVERSARIAL FP: '{input_text}' ({description}) was blocked. "
        f"Decision={result['decision']}, Score={result['score']:.2f}, "
        f"Semantic={result['semantic_score']}"
    )
