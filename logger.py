"""
Structured Logging for SQL Injection Protector
================================================
Production-grade logging using structlog with JSON output for SIEM integration.

Usage:
    from logger import get_logger
    log = get_logger(__name__)
    log.info("detection_complete", decision="INJECTION", score=0.87)
"""

import logging
import sys
from typing import Optional

import structlog


def setup_logging(level: str = "INFO", format: str = "json",
                  log_file: Optional[str] = None,
                  enable_console: bool = True) -> None:
    """
    Configure structured logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format ('json' or 'console')
        log_file: Optional file path for log output
        enable_console: Whether to output to console
    """
    # Configure standard library logging
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers = []
    if enable_console:
        handlers.append(logging.StreamHandler(sys.stdout))
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        format="%(message)s",
        level=numeric_level,
        handlers=handlers,
        force=True,
    )

    # Configure structlog
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set the formatter for all handlers
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    for handler in logging.root.handlers:
        handler.setFormatter(formatter)


def get_logger(name: str = "sqli_protector") -> structlog.stdlib.BoundLogger:
    """
    Get a named structured logger.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Bound structlog logger instance
    """
    return structlog.get_logger(name)


# Initialize with defaults on import
_initialized = False


def ensure_logging() -> None:
    """Ensure logging is initialized (idempotent)."""
    global _initialized
    if not _initialized:
        try:
            from config import config
            cfg = config()
            setup_logging(
                level=cfg.logging.level,
                format=cfg.logging.format,
                log_file=cfg.logging.log_file,
                enable_console=cfg.logging.enable_console,
            )
        except Exception:
            setup_logging()
        _initialized = True
