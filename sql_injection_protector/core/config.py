"""Configuration management with Pydantic and YAML support."""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


class DetectionSettings(BaseModel):
    """Detection layer settings."""

    signature_weight: float = Field(default=0.3, ge=0.0, le=1.0)
    ml_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    heuristic_weight: float = Field(default=0.2, ge=0.0, le=1.0)
    model_type: str = Field(default="transformer")
    model_path: str = Field(default="models/v1/transformer")
    fallback_to_tfidf: bool = Field(default=True)
    tfidf_model_path: str = Field(default="models/v1/tfidf_fallback.pkl")
    max_input_length: int = Field(default=10000)
    batch_size: int = Field(default=32)

    @field_validator("model_type")
    @classmethod
    def validate_model_type(cls, v: str) -> str:
        valid_types = {"transformer", "tfidf", "ensemble"}
        if v not in valid_types:
            raise ValueError(f"model_type must be one of {valid_types}")
        return v


class DecisionSettings(BaseModel):
    """Decision engine settings."""

    block_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    challenge_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    alert_threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    sanitize_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    strict_mode: bool = Field(default=False)
    learning_mode: bool = Field(default=False)


class RateLimitSettings(BaseModel):
    """Rate limiting settings."""

    enabled: bool = Field(default=True)
    redis_url: str = Field(default="redis://localhost:6379/0")
    requests_per_minute: int = Field(default=100, ge=1)
    requests_per_hour: int = Field(default=1000, ge=1)
    ban_duration_seconds: int = Field(default=3600, ge=60)
    sliding_window: bool = Field(default=True)


class HoneypotSettings(BaseModel):
    """Honeypot settings."""

    enabled: bool = Field(default=True)
    endpoints: list[str] = Field(
        default_factory=lambda: ["/admin", "/wp-admin", "/.env", "/phpmyadmin"]
    )
    collect_payloads: bool = Field(default=True)
    fake_responses: bool = Field(default=True)


class LearningSettings(BaseModel):
    """Learning and feedback settings."""

    collect_payloads: bool = Field(default=True)
    auto_retrain: bool = Field(default=True)
    min_samples_for_retrain: int = Field(default=500, ge=100)
    retrain_interval_hours: int = Field(default=24, ge=1)
    canary_deploy_percentage: float = Field(default=0.1, ge=0.0, le=1.0)
    manual_review_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class ObservabilitySettings(BaseModel):
    """Observability and SIEM settings."""

    cef_enabled: bool = Field(default=True)
    syslog_host: Optional[str] = Field(default=None)
    syslog_port: int = Field(default=514)
    syslog_protocol: str = Field(default="udp")
    prometheus_enabled: bool = Field(default=True)
    prometheus_port: int = Field(default=9090)
    log_level: str = Field(default="INFO")
    audit_log_path: Optional[str] = Field(default=None)

    @field_validator("syslog_protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        valid = {"udp", "tcp"}
        if v.lower() not in valid:
            raise ValueError(f"syslog_protocol must be one of {valid}")
        return v.lower()


class PreprocessingSettings(BaseModel):
    """Preprocessing layer settings."""

    max_decode_iterations: int = Field(default=5, ge=1, le=10)
    normalize_unicode: bool = Field(default=True)
    decode_html_entities: bool = Field(default=True)
    remove_null_bytes: bool = Field(default=True)
    lowercase: bool = Field(default=True)


class Settings(BaseModel):
    """Main configuration settings."""

    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    decision: DecisionSettings = Field(default_factory=DecisionSettings)
    rate_limiting: RateLimitSettings = Field(default_factory=RateLimitSettings)
    honeypot: HoneypotSettings = Field(default_factory=HoneypotSettings)
    learning: LearningSettings = Field(default_factory=LearningSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    preprocessing: PreprocessingSettings = Field(default_factory=PreprocessingSettings)

    # Application settings
    app_name: str = Field(default="SQLInjectionProtector")
    environment: str = Field(default="production")
    debug: bool = Field(default=False)

    class Config:
        extra = "ignore"


def load_config(
    config_path: Optional[str] = None, env_prefix: str = "SQLI_"
) -> Settings:
    """
    Load configuration from YAML file and environment variables.

    Priority (highest to lowest):
    1. Environment variables (SQLI_*)
    2. Config file
    3. Default values

    Args:
        config_path: Path to YAML config file
        env_prefix: Prefix for environment variables

    Returns:
        Settings object with merged configuration
    """
    config_data: dict[str, Any] = {}

    # Load from YAML if path provided
    if config_path:
        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                yaml_config = yaml.safe_load(f)
                if yaml_config:
                    # Handle nested 'sql_injection_protector' key
                    if "sql_injection_protector" in yaml_config:
                        config_data = yaml_config["sql_injection_protector"]
                    else:
                        config_data = yaml_config

    # Load from default config location
    else:
        default_paths = [
            Path("config.yaml"),
            Path("config/config.yaml"),
            Path("sql_injection_protector/config/defaults.yaml"),
        ]
        for path in default_paths:
            if path.exists():
                with open(path) as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config:
                        if "sql_injection_protector" in yaml_config:
                            config_data = yaml_config["sql_injection_protector"]
                        else:
                            config_data = yaml_config
                break

    # Override with environment variables
    config_data = _apply_env_overrides(config_data, env_prefix)

    return Settings(**config_data)


def _apply_env_overrides(config: dict[str, Any], prefix: str) -> dict[str, Any]:
    """Apply environment variable overrides to config."""
    env_mappings = {
        f"{prefix}DETECTION_MODEL_TYPE": ("detection", "model_type"),
        f"{prefix}DETECTION_MODEL_PATH": ("detection", "model_path"),
        f"{prefix}DECISION_BLOCK_THRESHOLD": ("decision", "block_threshold"),
        f"{prefix}DECISION_STRICT_MODE": ("decision", "strict_mode"),
        f"{prefix}DECISION_LEARNING_MODE": ("decision", "learning_mode"),
        f"{prefix}RATE_LIMIT_ENABLED": ("rate_limiting", "enabled"),
        f"{prefix}RATE_LIMIT_REDIS_URL": ("rate_limiting", "redis_url"),
        f"{prefix}RATE_LIMIT_RPM": ("rate_limiting", "requests_per_minute"),
        f"{prefix}HONEYPOT_ENABLED": ("honeypot", "enabled"),
        f"{prefix}LEARNING_AUTO_RETRAIN": ("learning", "auto_retrain"),
        f"{prefix}OBSERVABILITY_SYSLOG_HOST": ("observability", "syslog_host"),
        f"{prefix}OBSERVABILITY_PROMETHEUS_PORT": ("observability", "prometheus_port"),
        f"{prefix}DEBUG": ("debug",),
        f"{prefix}ENVIRONMENT": ("environment",),
    }

    for env_var, path in env_mappings.items():
        value = os.environ.get(env_var)
        if value is not None:
            # Convert string values to appropriate types
            if value.lower() in ("true", "false"):
                value = value.lower() == "true"
            elif value.isdigit():
                value = int(value)
            elif _is_float(value):
                value = float(value)

            # Navigate to nested location and set value
            current = config
            for key in path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[path[-1]] = value

    return config


def _is_float(value: str) -> bool:
    """Check if string is a valid float."""
    try:
        float(value)
        return "." in value
    except ValueError:
        return False


def get_default_config_path() -> Path:
    """Get the default configuration file path."""
    return Path(__file__).parent.parent / "config" / "defaults.yaml"
