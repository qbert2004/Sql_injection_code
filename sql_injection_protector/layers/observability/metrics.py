"""Prometheus metrics for monitoring and alerting."""

import time
from typing import Any, Optional

from sql_injection_protector.core.result import Action, Decision, DetectionResult, ThreatLevel


class MetricsCollector:
    """
    Prometheus-compatible metrics collector.

    Collects:
    - Request counters by action and source
    - Detection confidence histograms
    - Processing time histograms
    - Rate limit counters
    - Model performance metrics
    """

    def __init__(self, prefix: str = "sqli"):
        """
        Initialize metrics collector.

        Args:
            prefix: Prefix for all metric names
        """
        self.prefix = prefix
        self._counters: dict[str, dict[str, int]] = {}
        self._histograms: dict[str, list[float]] = {}
        self._gauges: dict[str, float] = {}

        # Initialize default metrics
        self._init_default_metrics()

    def _init_default_metrics(self) -> None:
        """Initialize default metrics."""
        # Counters
        self._counters["requests_total"] = {}
        self._counters["detections_total"] = {}
        self._counters["actions_total"] = {}
        self._counters["rate_limited_total"] = {}
        self._counters["honeypot_hits_total"] = {}

        # Histograms
        self._histograms["detection_confidence"] = []
        self._histograms["processing_seconds"] = []
        self._histograms["payload_length"] = []

        # Gauges
        self._gauges["model_accuracy"] = 0.0
        self._gauges["active_sessions"] = 0
        self._gauges["blocked_ips"] = 0

    def _metric_name(self, name: str) -> str:
        """Get full metric name with prefix."""
        return f"{self.prefix}_{name}"

    def inc_counter(
        self,
        name: str,
        labels: Optional[dict[str, str]] = None,
        value: int = 1,
    ) -> None:
        """
        Increment a counter.

        Args:
            name: Counter name
            labels: Label key-value pairs
            value: Increment value
        """
        if name not in self._counters:
            self._counters[name] = {}

        label_key = self._labels_to_key(labels)

        if label_key not in self._counters[name]:
            self._counters[name][label_key] = 0

        self._counters[name][label_key] += value

    def observe_histogram(self, name: str, value: float) -> None:
        """
        Add observation to a histogram.

        Args:
            name: Histogram name
            value: Observed value
        """
        if name not in self._histograms:
            self._histograms[name] = []

        self._histograms[name].append(value)

        # Keep only last 10000 observations
        if len(self._histograms[name]) > 10000:
            self._histograms[name] = self._histograms[name][-10000:]

    def set_gauge(self, name: str, value: float) -> None:
        """
        Set a gauge value.

        Args:
            name: Gauge name
            value: Gauge value
        """
        self._gauges[name] = value

    def inc_gauge(self, name: str, value: float = 1.0) -> None:
        """Increment a gauge."""
        if name not in self._gauges:
            self._gauges[name] = 0.0
        self._gauges[name] += value

    def dec_gauge(self, name: str, value: float = 1.0) -> None:
        """Decrement a gauge."""
        if name not in self._gauges:
            self._gauges[name] = 0.0
        self._gauges[name] -= value

    def _labels_to_key(self, labels: Optional[dict[str, str]]) -> str:
        """Convert labels to a string key."""
        if not labels:
            return ""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))

    def record_request(self, source: str = "unknown") -> None:
        """Record a request."""
        self.inc_counter("requests_total", {"source": source})

    def record_detection(
        self,
        detection_result: DetectionResult,
    ) -> None:
        """
        Record detection result metrics.

        Args:
            detection_result: Detection result
        """
        # Counter by threat level
        self.inc_counter(
            "detections_total",
            {"threat_level": detection_result.threat_level.name},
        )

        # Counter by malicious/benign
        self.inc_counter(
            "detections_total",
            {"is_malicious": str(detection_result.is_malicious).lower()},
        )

        # Confidence histogram
        self.observe_histogram("detection_confidence", detection_result.final_score)

        # Processing time histogram
        self.observe_histogram(
            "processing_seconds",
            detection_result.processing_time_ms / 1000,
        )

        # Payload length
        if detection_result.raw_input:
            self.observe_histogram("payload_length", len(detection_result.raw_input))

    def record_action(self, action: Action, source: str = "unknown") -> None:
        """
        Record action taken.

        Args:
            action: Action taken
            source: Request source
        """
        self.inc_counter("actions_total", {"action": action.name, "source": source})

    def record_decision(self, decision: Decision, source: str = "unknown") -> None:
        """
        Record full decision metrics.

        Args:
            decision: Decision object
            source: Request source
        """
        self.record_detection(decision.detection_result)
        self.record_action(decision.action, source)

    def record_rate_limit(self, client_id: str) -> None:
        """Record rate limit event."""
        self.inc_counter("rate_limited_total", {"client": client_id[:8]})

    def record_honeypot_hit(self, endpoint: str) -> None:
        """Record honeypot hit."""
        self.inc_counter("honeypot_hits_total", {"endpoint": endpoint})

    def get_counter(
        self,
        name: str,
        labels: Optional[dict[str, str]] = None,
    ) -> int:
        """Get counter value."""
        if name not in self._counters:
            return 0

        label_key = self._labels_to_key(labels)
        return self._counters[name].get(label_key, 0)

    def get_histogram_stats(self, name: str) -> dict[str, float]:
        """
        Get histogram statistics.

        Returns:
            Dict with count, sum, avg, min, max, percentiles
        """
        if name not in self._histograms or not self._histograms[name]:
            return {"count": 0, "sum": 0, "avg": 0, "min": 0, "max": 0}

        values = sorted(self._histograms[name])
        count = len(values)
        total = sum(values)

        return {
            "count": count,
            "sum": total,
            "avg": total / count,
            "min": values[0],
            "max": values[-1],
            "p50": values[int(count * 0.5)],
            "p90": values[int(count * 0.9)],
            "p99": values[int(count * 0.99)] if count >= 100 else values[-1],
        }

    def get_gauge(self, name: str) -> float:
        """Get gauge value."""
        return self._gauges.get(name, 0.0)

    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus format.

        Returns:
            Prometheus-formatted metrics string
        """
        lines = []

        # Export counters
        for name, label_values in self._counters.items():
            metric_name = self._metric_name(name)
            lines.append(f"# HELP {metric_name} Counter for {name}")
            lines.append(f"# TYPE {metric_name} counter")

            if not label_values:
                lines.append(f"{metric_name} 0")
            else:
                for labels, value in label_values.items():
                    if labels:
                        lines.append(f"{metric_name}{{{labels}}} {value}")
                    else:
                        lines.append(f"{metric_name} {value}")

        # Export histograms (simplified)
        for name, values in self._histograms.items():
            metric_name = self._metric_name(name)
            stats = self.get_histogram_stats(name)

            lines.append(f"# HELP {metric_name} Histogram for {name}")
            lines.append(f"# TYPE {metric_name} summary")
            lines.append(f'{metric_name}_count {stats["count"]}')
            lines.append(f'{metric_name}_sum {stats["sum"]}')

            if stats["count"] > 0:
                lines.append(f'{metric_name}{{quantile="0.5"}} {stats.get("p50", 0)}')
                lines.append(f'{metric_name}{{quantile="0.9"}} {stats.get("p90", 0)}')
                lines.append(f'{metric_name}{{quantile="0.99"}} {stats.get("p99", 0)}')

        # Export gauges
        for name, value in self._gauges.items():
            metric_name = self._metric_name(name)
            lines.append(f"# HELP {metric_name} Gauge for {name}")
            lines.append(f"# TYPE {metric_name} gauge")
            lines.append(f"{metric_name} {value}")

        return "\n".join(lines)

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all metrics as dictionary."""
        return {
            "counters": self._counters,
            "histograms": {
                name: self.get_histogram_stats(name)
                for name in self._histograms
            },
            "gauges": self._gauges,
        }


# Global metrics instance
_global_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Get global metrics collector."""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = MetricsCollector()
    return _global_metrics


def record_request(**kwargs) -> None:
    """Convenience function to record request."""
    get_metrics().record_request(**kwargs)


def record_detection(detection_result: DetectionResult) -> None:
    """Convenience function to record detection."""
    get_metrics().record_detection(detection_result)


def record_decision(decision: Decision, **kwargs) -> None:
    """Convenience function to record decision."""
    get_metrics().record_decision(decision, **kwargs)
