"""
Pytest configuration and fixtures for SQL Injection Protector tests.
"""

import os
import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# CORE FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def project_root():
    """Project root directory."""
    return PROJECT_ROOT


@pytest.fixture
def settings():
    """Default settings fixture."""
    from sql_injection_protector.core.config import Settings
    return Settings()


@pytest.fixture
def detection_settings():
    """Detection settings fixture."""
    from sql_injection_protector.core.config import DetectionSettings
    return DetectionSettings()


@pytest.fixture
def preprocessing_settings():
    """Preprocessing settings fixture."""
    from sql_injection_protector.core.config import PreprocessingSettings
    return PreprocessingSettings()


# ============================================================================
# PREPROCESSING FIXTURES
# ============================================================================

@pytest.fixture
def decoder():
    """Decoder instance."""
    from sql_injection_protector.layers.preprocessing.decoder import Decoder
    return Decoder()


@pytest.fixture
def normalizer():
    """Normalizer instance."""
    from sql_injection_protector.layers.preprocessing.normalizer import Normalizer
    return Normalizer()


@pytest.fixture
def tokenizer():
    """SQL Tokenizer instance."""
    from sql_injection_protector.layers.preprocessing.tokenizer import SQLTokenizer
    return SQLTokenizer()


@pytest.fixture
def preprocessing_pipeline():
    """Preprocessing pipeline instance."""
    from sql_injection_protector.layers.preprocessing.pipeline import PreprocessingPipeline
    return PreprocessingPipeline()


# ============================================================================
# DETECTION FIXTURES
# ============================================================================

@pytest.fixture
def signature_detector():
    """Signature detector instance."""
    from sql_injection_protector.layers.detection.signature import SignatureDetector
    return SignatureDetector()


@pytest.fixture
def heuristic_analyzer():
    """Heuristic analyzer instance."""
    from sql_injection_protector.layers.detection.heuristic import HeuristicAnalyzer
    return HeuristicAnalyzer()


@pytest.fixture
def static_feature_extractor():
    """Static feature extractor instance."""
    from sql_injection_protector.layers.features.static import StaticFeatureExtractor
    return StaticFeatureExtractor()


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================

@pytest.fixture
def sql_injection_payloads():
    """Common SQL injection payloads for testing."""
    return [
        # Classic boolean-based
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "admin' --",
        "admin' #",
        "admin'/*",
        "') OR ('1'='1--",

        # UNION-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' UNION SELECT * FROM users--",
        "' UNION SELECT username, password FROM users--",
        "' UNION ALL SELECT NULL,NULL,NULL--",

        # Time-based blind
        "' AND SLEEP(5)--",
        "1' AND (SELECT SLEEP(5))--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "1' AND pg_sleep(5)--",

        # Stacked queries
        "'; DROP TABLE users--",
        "1'; DELETE FROM users WHERE 1=1--",
        "'; CREATE TABLE hacked(id INT)--",
        "'; SHUTDOWN--",

        # Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "' AND UpdateXML(1,CONCAT(0x7e,@@version),1)--",

        # Information gathering
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' AND (SELECT COUNT(*) FROM sysobjects)>0--",

        # Dangerous functions
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' INTO OUTFILE '/tmp/shell.php'--",
        "'; EXEC xp_cmdshell('dir')--",

        # Obfuscated
        "%27%20OR%20%271%27%3D%271",
        "0x61646D696E' --",
        "' OR CHAR(49)=CHAR(49)--",
        "1' UN/**/ION SE/**/LECT * FROM users--",
    ]


@pytest.fixture
def legitimate_inputs():
    """Legitimate inputs that should NOT trigger detection."""
    return [
        # Normal text
        "Hello world",
        "Normal search query",
        "Product Name 123",

        # Emails
        "john.doe@example.com",
        "user+tag@domain.co.uk",
        "test_user123@example.org",

        # Names with apostrophes
        "John O'Brien",
        "Mary-Jane Watson",
        "O'Malley & Sons",
        "McDonald's",

        # URLs
        "https://example.com/page?param=value",
        "http://api.example.org:8080/v1/users",

        # Technical strings
        "version 1.2.3",
        "error: null pointer exception",
        "C:\\Users\\Documents\\file.txt",

        # Numbers and dates
        "Price: $99.99",
        "2024-01-15",
        "Phone: +1-555-0123",

        # Unicode
        "Привет мир",
        "你好世界",
        "مرحبا",
    ]


@pytest.fixture
def edge_case_inputs():
    """Edge case inputs for testing."""
    return [
        "",  # Empty string
        " ",  # Single space
        "\t\n\r",  # Whitespace only
        "a" * 10000,  # Very long string
        "'" * 100,  # Many quotes
        "--" * 50,  # Many comment markers
        "\x00" * 10,  # Null bytes
        "SELECT",  # Single keyword
    ]


# ============================================================================
# ASYNC FIXTURES
# ============================================================================

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# MARKERS
# ============================================================================

def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_redis: marks tests that require Redis"
    )
