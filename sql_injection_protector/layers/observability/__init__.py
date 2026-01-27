"""Observability layer - Layer 8: SIEM & Metrics."""

from sql_injection_protector.layers.observability.cef import (
    CEFFormatter,
    CEFEvent,
)
from sql_injection_protector.layers.observability.syslog import (
    SyslogExporter,
    AsyncSyslogExporter,
    SyslogMessage,
    SyslogFacility,
    SyslogSeverity,
)
from sql_injection_protector.layers.observability.metrics import (
    MetricsCollector,
    get_metrics,
    record_request,
    record_detection,
    record_decision,
)
from sql_injection_protector.layers.observability.persistence import (
    AuditLogger,
    AuditEntry,
)

__all__ = [
    "CEFFormatter",
    "CEFEvent",
    "SyslogExporter",
    "AsyncSyslogExporter",
    "SyslogMessage",
    "SyslogFacility",
    "SyslogSeverity",
    "MetricsCollector",
    "get_metrics",
    "record_request",
    "record_detection",
    "record_decision",
    "AuditLogger",
    "AuditEntry",
]
