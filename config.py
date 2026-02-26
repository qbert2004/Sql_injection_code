"""
Configuration Management for SQL Injection Protector
=====================================================
Externalized, validated configuration with environment variable support.

Usage:
    from config import get_config
    config = get_config()

    # Access settings
    print(config.ensemble.alpha)
    print(config.api.port)
    print(config.logging.level)
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass(frozen=True)
class EnsembleConfig:
    """ML ensemble decision thresholds."""
    # Model weights for 2-model ensemble (RF + CNN, must sum to 1.0)
    w_rf: float = 0.35
    w_cnn: float = 0.65

    # Decision thresholds
    tau_high: float = 0.60
    tau_low: float = 0.40
    tau_safe: float = 0.30

    # Single-model override thresholds
    tau_cnn_override: float = 0.75
    tau_rf_strong: float = 0.70

    # Semantic gating thresholds
    tau_semantic_min: float = 2.0
    tau_semantic_override: float = 6.0

    # Model divergence
    tau_model_divergence: float = 0.40

    # Ensemble agreement bonus
    agreement_bonus: float = 0.10


@dataclass(frozen=True)
class NormalizationConfig:
    """Input normalization settings."""
    max_input_length: int = 10000
    max_url_decode_depth: int = 3
    enable_homoglyph_normalization: bool = True
    enable_unicode_nfkc: bool = True
    enable_null_byte_strip: bool = True
    enable_html_entity_decode: bool = True


@dataclass(frozen=True)
class ModelPaths:
    """Model file paths relative to project root."""
    rf_model: str = "rf_sql_model.pkl"
    tfidf_vectorizer: str = "tfidf_vectorizer.pkl"
    cnn_model: str = "models/char_cnn_detector.pt"
    char_tokenizer: str = "models/char_tokenizer.json"


@dataclass(frozen=True)
class APIConfig:
    """API server configuration.

    SECURITY NOTE: In production, always set API_KEY env var and restrict
    CORS_ORIGINS to your actual frontend domains.
    Default cors_origins are restricted to localhost for development safety.
    """
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    log_all_requests: bool = False
    enable_cors: bool = True
    cors_origins: tuple = ("http://localhost:3000", "http://localhost:8501")
    rate_limit_per_minute: int = 100
    api_key: str | None = None


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"
    log_file: str | None = None
    enable_console: bool = True
    enable_structlog: bool = True


@dataclass(frozen=True)
class IncidentConfig:
    """Incident logging configuration."""
    db_path: str = "incidents.db"
    auto_cleanup_days: int = 90
    log_safe_requests: bool = False


@dataclass(frozen=True)
class BackendConfig:
    """
    State backend configuration — controls where IP profiles and SGD model
    are persisted across restarts and worker processes.

    backend_type values
    -------------------
    sqlite  (default) — single-node, zero-dependency, agent_state.db
    redis             — distributed, needs REDIS_URL or REDIS_HOST/PORT
    null              — stateless, no persistence (testing / ephemeral)

    Redis env vars (only used when backend_type=redis)
    --------------------------------------------------
    REDIS_URL        full URL, e.g. redis://redis:6379/0
    REDIS_HOST       localhost  (fallback if REDIS_URL not set)
    REDIS_PORT       6379
    REDIS_DB         0
    REDIS_PASSWORD   (optional)
    REDIS_TTL_DAYS   7  (IP profile expiry in days)
    """
    backend_type: str = "sqlite"          # sqlite | redis | null
    sqlite_path: str = "agent_state.db"  # only used when backend_type=sqlite
    redis_url: str | None = None          # overrides host/port when set
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    redis_ttl_days: int = 7


@dataclass(frozen=True)
class AppConfig:
    """Root application configuration."""
    app_env: str = "development"
    project_root: str = str(Path(__file__).parent)
    ensemble: EnsembleConfig = field(default_factory=EnsembleConfig)
    normalization: NormalizationConfig = field(default_factory=NormalizationConfig)
    model_paths: ModelPaths = field(default_factory=ModelPaths)
    api: APIConfig = field(default_factory=APIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    incidents: IncidentConfig = field(default_factory=IncidentConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)


def _env(key: str, default: str = "") -> str:
    """Get environment variable with fallback."""
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = False) -> bool:
    """Get boolean environment variable."""
    return _env(key, str(default)).lower() in ("true", "1", "yes")


def _env_int(key: str, default: int = 0) -> int:
    """Get integer environment variable."""
    try:
        return int(_env(key, str(default)))
    except (ValueError, TypeError):
        return default


def _env_float(key: str, default: float = 0.0) -> float:
    """Get float environment variable."""
    try:
        return float(_env(key, str(default)))
    except (ValueError, TypeError):
        return default


def get_config() -> AppConfig:
    """
    Build configuration from environment variables with defaults.

    Environment variable mapping:
        APP_ENV                 → app_env
        ENSEMBLE_W_RF           → ensemble.w_rf
        ENSEMBLE_W_CNN          → ensemble.w_cnn
        ENSEMBLE_TAU_HIGH       → ensemble.tau_high
        ENSEMBLE_TAU_SEMANTIC   → ensemble.tau_semantic_min
        MAX_INPUT_LENGTH        → normalization.max_input_length
        API_HOST                → api.host
        API_PORT                → api.port
        API_DEBUG               → api.debug
        API_KEY                 → api.api_key
        LOG_ALL_REQUESTS        → api.log_all_requests
        RATE_LIMIT              → api.rate_limit_per_minute
        LOG_LEVEL               → logging.level
        LOG_FORMAT              → logging.format
        LOG_FILE                → logging.log_file
        INCIDENTS_DB            → incidents.db_path
        CLEANUP_DAYS            → incidents.auto_cleanup_days
    """
    return AppConfig(
        app_env=_env("APP_ENV", "development"),
        ensemble=EnsembleConfig(
            w_rf=_env_float("ENSEMBLE_W_RF", 0.35),
            w_cnn=_env_float("ENSEMBLE_W_CNN", 0.65),
            tau_high=_env_float("ENSEMBLE_TAU_HIGH", 0.60),
            tau_low=_env_float("ENSEMBLE_TAU_LOW", 0.40),
            tau_safe=_env_float("ENSEMBLE_TAU_SAFE", 0.30),
            tau_semantic_min=_env_float("ENSEMBLE_TAU_SEMANTIC", 2.0),
            tau_semantic_override=_env_float("ENSEMBLE_TAU_SEMANTIC_OVERRIDE", 6.0),
        ),
        normalization=NormalizationConfig(
            max_input_length=_env_int("MAX_INPUT_LENGTH", 10000),
        ),
        model_paths=ModelPaths(),
        api=APIConfig(
            host=_env("API_HOST", "0.0.0.0"),
            port=_env_int("API_PORT", 5000),
            debug=_env_bool("API_DEBUG", False),
            log_all_requests=_env_bool("LOG_ALL_REQUESTS", False),
            rate_limit_per_minute=_env_int("RATE_LIMIT", 100),
            api_key=_env("API_KEY") or None,
            cors_origins=tuple(
                origin.strip()
                for origin in _env("CORS_ORIGINS", "http://localhost:3000,http://localhost:8501").split(",")
                if origin.strip()
            ),
        ),
        logging=LoggingConfig(
            level=_env("LOG_LEVEL", "INFO"),
            format=_env("LOG_FORMAT", "json"),
            log_file=_env("LOG_FILE") or None,
        ),
        incidents=IncidentConfig(
            db_path=_env("INCIDENTS_DB", "incidents.db"),
            auto_cleanup_days=_env_int("CLEANUP_DAYS", 90),
        ),
        backend=BackendConfig(
            backend_type=_env("SQLI_BACKEND", "sqlite"),
            sqlite_path=_env("AGENT_STATE_DB", "agent_state.db"),
            redis_url=_env("REDIS_URL") or None,
            redis_host=_env("REDIS_HOST", "localhost"),
            redis_port=_env_int("REDIS_PORT", 6379),
            redis_db=_env_int("REDIS_DB", 0),
            redis_password=_env("REDIS_PASSWORD") or None,
            redis_ttl_days=_env_int("REDIS_TTL_DAYS", 7),
        ),
    )


# Module-level singleton
_config: AppConfig | None = None


def config() -> AppConfig:
    """Get or create the global configuration singleton."""
    global _config
    if _config is None:
        _config = get_config()
    return _config
