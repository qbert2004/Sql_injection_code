"""Custom exceptions for SQL Injection Protector."""

from typing import Any, Optional


class SQLIProtectorError(Exception):
    """Base exception for all SQL Injection Protector errors."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(SQLIProtectorError):
    """Raised when configuration is invalid or missing."""

    pass


class DetectionError(SQLIProtectorError):
    """Raised when detection process fails."""

    pass


class ModelLoadError(SQLIProtectorError):
    """Raised when ML model fails to load."""

    def __init__(
        self,
        message: str,
        model_path: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.model_path = model_path


class RedisConnectionError(SQLIProtectorError):
    """Raised when Redis connection fails."""

    def __init__(
        self,
        message: str,
        redis_url: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.redis_url = redis_url


class RateLimitExceeded(SQLIProtectorError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        client_id: Optional[str] = None,
        retry_after: Optional[int] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.client_id = client_id
        self.retry_after = retry_after


class ValidationError(SQLIProtectorError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.field = field
        self.value = value


class PreprocessingError(SQLIProtectorError):
    """Raised when preprocessing fails."""

    pass


class TokenizationError(PreprocessingError):
    """Raised when tokenization fails."""

    pass


class SanitizerError(SQLIProtectorError):
    """Raised when sanitization fails."""

    pass


class HoneypotError(SQLIProtectorError):
    """Raised when honeypot operation fails."""

    pass


class SIEMExportError(SQLIProtectorError):
    """Raised when SIEM export fails."""

    def __init__(
        self,
        message: str,
        siem_host: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.siem_host = siem_host


class RetrainingError(SQLIProtectorError):
    """Raised when model retraining fails."""

    pass
