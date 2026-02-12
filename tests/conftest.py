"""
Pytest configuration and shared fixtures.
"""
import sys
from pathlib import Path

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def detector():
    """Session-scoped ensemble detector (loads models once)."""
    from sql_injection_detector import SQLInjectionEnsemble
    return SQLInjectionEnsemble()


@pytest.fixture(scope="session")
def semantic_analyzer():
    """Session-scoped semantic analyzer."""
    from sql_injection_detector import SQLSemanticAnalyzer
    return SQLSemanticAnalyzer()


@pytest.fixture
def incident_logger(tmp_path):
    """Temp-directory incident logger (per-test isolation)."""
    from incident_logger import IncidentLogger
    db_path = str(tmp_path / "test_incidents.db")
    return IncidentLogger(db_path=db_path)
