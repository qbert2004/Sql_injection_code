"""
Prometheus Metrics for SQL Injection Protector
===============================================
Centralized metrics definitions for monitoring and alerting.

Metrics exposed:
    - sqli_requests_total              — Total API requests by endpoint, method, status
    - sqli_request_duration_seconds    — Request duration histogram
    - sqli_detections_total            — Detection results by decision, action, attack_type
    - sqli_inference_duration_seconds  — ML inference latency histogram
    - sqli_blocked_total               — Total blocked requests (convenience counter)
    - sqli_rate_limit_exceeded_total   — Rate limit violations
    - sqli_errors_total                — Errors by type
    - sqli_active_requests             — Currently in-flight requests (gauge)
    - sqli_model_loaded                — Model loading status (gauge, 0 or 1)

    AI Agent metrics:
    - sqli_agent_active_bans           — Currently active IP bans (gauge)
    - sqli_agent_tracked_ips           — IPs in agent memory (gauge)
    - sqli_agent_tracked_sessions      — Sessions in agent memory (gauge)
    - sqli_agent_escalations_total     — Decision escalations by reason type (counter)
    - sqli_agent_auto_bans_total       — Automatic IP bans triggered (counter)
    - sqli_agent_online_layer_fits     — Incremental SGD fits performed (counter)
    - sqli_agent_false_positives_total — False positives corrected via feedback (counter)
    - sqli_agent_persistence_saves     — Successful agent state DB saves (counter)

Usage:
    from metrics import metrics
    metrics.requests_total.labels(endpoint="/api/check", method="POST", status=200).inc()
    metrics.agent_active_bans.set(5)
"""

from prometheus_client import Counter, Gauge, Histogram, Info


class AppMetrics:
    """Application metrics container — all Prometheus metrics in one place."""

    def __init__(self, namespace: str = "sqli"):
        # ── Request metrics ──────────────────────────────────────────────
        self.requests_total = Counter(
            f"{namespace}_requests_total",
            "Total API requests",
            ["endpoint", "method", "status"],
        )

        self.request_duration = Histogram(
            f"{namespace}_request_duration_seconds",
            "Request duration in seconds",
            ["endpoint", "method"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

        self.active_requests = Gauge(
            f"{namespace}_active_requests",
            "Currently in-flight requests",
            ["endpoint"],
        )

        # ── Detection metrics ────────────────────────────────────────────
        self.detections_total = Counter(
            f"{namespace}_detections_total",
            "Detection results by decision and action",
            ["decision", "action", "attack_type"],
        )

        self.inference_duration = Histogram(
            f"{namespace}_inference_duration_seconds",
            "ML ensemble inference latency in seconds",
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

        self.blocked_total = Counter(
            f"{namespace}_blocked_total",
            "Total blocked requests (BLOCK or ALERT action)",
        )

        self.severity_total = Counter(
            f"{namespace}_severity_total",
            "Detections by severity level",
            ["severity"],
        )

        # ── Error metrics ────────────────────────────────────────────────
        self.errors_total = Counter(
            f"{namespace}_errors_total",
            "Total errors by type",
            ["error_type"],
        )

        self.rate_limit_exceeded = Counter(
            f"{namespace}_rate_limit_exceeded_total",
            "Rate limit violations",
        )

        self.inference_timeouts = Counter(
            f"{namespace}_inference_timeouts_total",
            "ML inference timeouts",
        )

        # ── System metrics ───────────────────────────────────────────────
        self.model_loaded = Gauge(
            f"{namespace}_model_loaded",
            "Model loading status (1=loaded, 0=not loaded)",
            ["model"],
        )

        self.app_info = Info(
            f"{namespace}_app",
            "Application version and configuration",
        )

        # ── AI Agent metrics ─────────────────────────────────────────────
        # Memory gauges — updated every cleanup cycle and on demand
        self.agent_active_bans = Gauge(
            f"{namespace}_agent_active_bans",
            "Number of currently active IP bans in agent memory",
        )

        self.agent_tracked_ips = Gauge(
            f"{namespace}_agent_tracked_ips",
            "Number of IP profiles currently tracked by the agent",
        )

        self.agent_tracked_sessions = Gauge(
            f"{namespace}_agent_tracked_sessions",
            "Number of sessions currently tracked by the agent",
        )

        self.agent_mean_reputation = Gauge(
            f"{namespace}_agent_mean_reputation_score",
            "Mean reputation score across all tracked IPs (0=clean, 1=attacker)",
        )

        # Agent event counters
        self.agent_escalations_total = Counter(
            f"{namespace}_agent_escalations_total",
            "Total decision escalations by rule type",
            ["rule"],   # rule_b_autoban, rule_c_suspicious, rule_e_scanning, signature, online_layer
        )

        self.agent_auto_bans_total = Counter(
            f"{namespace}_agent_auto_bans_total",
            "Total automatic IP bans triggered by the agent",
        )

        self.agent_online_layer_fits = Counter(
            f"{namespace}_agent_online_layer_fits_total",
            "Total incremental SGD fit operations performed",
        )

        self.agent_false_positives_total = Counter(
            f"{namespace}_agent_false_positives_total",
            "Total false positives corrected via analyst feedback",
        )

        self.agent_persistence_saves = Counter(
            f"{namespace}_agent_persistence_saves_total",
            "Successful agent state saves to SQLite (periodic + shutdown)",
        )

        self.agent_persistence_loads = Counter(
            f"{namespace}_agent_persistence_loads_total",
            "Successful agent state loads from SQLite (startup)",
        )


# Module-level singleton
metrics = AppMetrics()
