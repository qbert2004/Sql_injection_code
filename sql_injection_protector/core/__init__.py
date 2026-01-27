"""Core module for SQL Injection Protector."""

from sql_injection_protector.core.exceptions import (
    SQLIProtectorError,
    ConfigurationError,
    DetectionError,
    ModelLoadError,
    RedisConnectionError,
    RateLimitExceeded,
    ValidationError,
)
from sql_injection_protector.core.result import (
    DetectionResult,
    Decision,
    Action,
    ThreatLevel,
    DetectorType,
)
from sql_injection_protector.core.config import Settings, load_config
from sql_injection_protector.core.agent import SQLInjectionAgent

__all__ = [
    "SQLIProtectorError",
    "ConfigurationError",
    "DetectionError",
    "ModelLoadError",
    "RedisConnectionError",
    "RateLimitExceeded",
    "ValidationError",
    "DetectionResult",
    "Decision",
    "Action",
    "ThreatLevel",
    "DetectorType",
    "Settings",
    "load_config",
    "SQLInjectionAgent",
]
