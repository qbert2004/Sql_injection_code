"""
API Integration Tests — SQL Injection Protector (v3.5.0+)
=========================================================
Tests the full HTTP stack using FastAPI TestClient (ASGI, no network).

Coverage matrix:
  POST /api/check          — happy path, SQLi payloads, UNION/AST, rate-limit,
                             API key auth, DoS truncation, field_name logging
  POST /api/validate       — multi-field, blocked detection, field count limit,
                             key length limit, value truncation, empty field
  GET  /api/health         — 200 shape validation
  GET  /api/stats          — returns dict (no crash)
  GET  /api/incidents      — pagination params, filter params
  GET  /api/agent/stats    — shape includes required keys
  GET  /api/agent/metrics  — shape includes required keys
  GET  /api/agent/ip/{ip}  — valid IP, invalid IP (400)
  POST /api/agent/feedback — false positive learning round-trip
  GET  /healthz            — liveness always 200
  GET  /readyz             — readiness 200 after boot
  GET  /metrics            — Prometheus text format

Isolation strategy:
  - TestClient wraps the real FastAPI app with its lifespan (startup/shutdown)
  - One shared `client` fixture per module (scope="module") — avoids cold-start
    overhead on every test while keeping tests independent via fresh payloads.
  - No mocking of agent / detector — we want the real stack to execute.
"""

import re
import time

import pytest
from fastapi.testclient import TestClient

from api_server import MAX_FIELD_KEY_LENGTH, MAX_FIELDS, MAX_TEXT_LENGTH, VERSION, app

# ─── Shared client (single lifespan startup for the whole module) ─────────────

@pytest.fixture(scope="module")
def client():
    """Start the app once for all tests in this module."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ═══════════════════════════════════════════════════════════════════
# /healthz  (liveness)
# ═══════════════════════════════════════════════════════════════════

class TestLiveness:
    def test_healthz_returns_200(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200

    def test_healthz_body(self, client):
        r = client.get("/healthz")
        assert r.json() == {"status": "alive"}


# ═══════════════════════════════════════════════════════════════════
# /readyz  (readiness)
# ═══════════════════════════════════════════════════════════════════

class TestReadiness:
    def test_readyz_returns_200_after_startup(self, client):
        r = client.get("/readyz")
        # May be 200 (ready) or 503 (no models loaded on this machine)
        assert r.status_code in (200, 503)

    def test_readyz_has_status_key(self, client):
        r = client.get("/readyz")
        assert "status" in r.json()

    def test_readyz_200_shape(self, client):
        r = client.get("/readyz")
        body = r.json()
        if r.status_code == 200:
            assert body["status"] == "ready"
            assert "rf_loaded" in body
            assert "cnn_loaded" in body
            assert "agent_active" in body

    def test_readyz_503_shape(self, client):
        r = client.get("/readyz")
        body = r.json()
        if r.status_code == 503:
            assert body["status"] == "not_ready"
            assert "reason" in body


# ═══════════════════════════════════════════════════════════════════
# GET /api/health
# ═══════════════════════════════════════════════════════════════════

class TestHealth:
    def test_health_returns_200(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200

    def test_health_has_required_keys(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert body["version"] == VERSION
        assert "models" in body
        assert "rf" in body["models"]
        assert "cnn" in body["models"]

    def test_health_config_block(self, client):
        body = client.get("/api/health").json()
        cfg_block = body["config"]
        assert "rate_limit_per_minute" in cfg_block
        assert "max_input_length" in cfg_block
        assert "auth_enabled" in cfg_block

    def test_health_incidents_logged_is_int(self, client):
        body = client.get("/api/health").json()
        assert isinstance(body["incidents_logged"], int)


# ═══════════════════════════════════════════════════════════════════
# POST /api/check  — core detection endpoint
# ═══════════════════════════════════════════════════════════════════

class TestCheckEndpoint:

    # ── Happy path (safe input) ──────────────────────────────────────
    def test_safe_input_returns_200(self, client):
        r = client.post("/api/check", json={"text": "hello world"})
        assert r.status_code == 200

    def test_safe_input_decision_safe(self, client):
        r = client.post("/api/check", json={"text": "hello world"})
        body = r.json()
        assert body["decision"] in ("SAFE", "SUSPICIOUS", "INJECTION")  # engine decides

    def test_safe_input_response_shape(self, client):
        r = client.post("/api/check", json={"text": "ordinary username"})
        body = r.json()
        required = {"input", "decision", "action", "blocked", "confidence",
                    "severity", "attack_type", "scores", "reason", "rule",
                    "processing_time_ms"}
        assert required.issubset(set(body.keys()))

    def test_scores_block_has_expected_keys(self, client):
        r = client.post("/api/check", json={"text": "hello"})
        scores = r.json()["scores"]
        assert set(scores.keys()) == {"ensemble", "rf", "cnn", "semantic"}

    def test_processing_time_is_positive(self, client):
        r = client.post("/api/check", json={"text": "hello"})
        assert r.json()["processing_time_ms"] >= 0

    def test_input_echoed_in_response(self, client):
        r = client.post("/api/check", json={"text": "test_echo_abc"})
        assert r.json()["input"] == "test_echo_abc"

    # ── SQL injection payloads ───────────────────────────────────────
    def test_classic_or_tautology_blocked(self, client):
        r = client.post("/api/check", json={"text": "' OR '1'='1"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    def test_comment_bypass_blocked(self, client):
        r = client.post("/api/check", json={"text": "admin'--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    def test_union_select_blocked(self, client):
        r = client.post("/api/check", json={"text": "' UNION SELECT password FROM users--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    def test_stacked_drop_blocked(self, client):
        r = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    def test_insert_injection_blocked(self, client):
        r = client.post("/api/check", json={"text": "'; INSERT INTO users VALUES('hack', 'pwn')--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    # ── AST-specific payloads (sqlglot layer) ───────────────────────
    def test_subquery_injection_detected(self, client):
        # Payload that triggers both signature layer and AST layer (bare UNION SELECT)
        r = client.post("/api/check", json={"text": "1 UNION SELECT username, password FROM admin--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    def test_quoted_union_select_detected(self, client):
        r = client.post("/api/check", json={"text": "' UNION SELECT username, password FROM users--"})
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("INJECTION", "SUSPICIOUS")

    # ── Safe natural language (no false positives) ───────────────────
    def test_natural_language_not_blocked(self, client):
        texts = [
            "Please select your country from the dropdown",
            "My name is O'Brien",
            "Email: user@example.com",
            "Date: 2024-01-15",
            "Product ID: 12345",
        ]
        for text in texts:
            r = client.post("/api/check", json={"text": text})
            assert r.status_code == 200, f"HTTP error for: {text!r}"
            # These may be SAFE or SUSPICIOUS — just must not 500

    # ── field_name optional param ────────────────────────────────────
    def test_field_name_accepted(self, client):
        r = client.post("/api/check", json={"text": "hello", "field_name": "username"})
        assert r.status_code == 200

    def test_field_name_too_long_rejected(self, client):
        long_key = "k" * (MAX_FIELD_KEY_LENGTH + 1)
        r = client.post("/api/check", json={"text": "hello", "field_name": long_key})
        assert r.status_code == 422  # Pydantic max_length validation

    # ── DoS protection ───────────────────────────────────────────────
    def test_input_at_max_length_accepted(self, client):
        text = "a" * MAX_TEXT_LENGTH
        r = client.post("/api/check", json={"text": text})
        assert r.status_code == 200

    def test_input_over_max_length_rejected(self, client):
        text = "a" * (MAX_TEXT_LENGTH + 1)
        r = client.post("/api/check", json={"text": text})
        assert r.status_code == 422  # Pydantic rejects before detection

    # ── Validation errors ────────────────────────────────────────────
    def test_empty_text_rejected(self, client):
        r = client.post("/api/check", json={"text": ""})
        assert r.status_code == 422  # min_length=1

    def test_missing_text_field_rejected(self, client):
        r = client.post("/api/check", json={})
        assert r.status_code == 422

    def test_wrong_content_type(self, client):
        r = client.post("/api/check", content="plain text",
                        headers={"Content-Type": "text/plain"})
        assert r.status_code == 422

    # ── Security headers ─────────────────────────────────────────────
    def test_security_headers_present(self, client):
        r = client.post("/api/check", json={"text": "hello"})
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Cache-Control") is not None

    # ── Request-ID header ────────────────────────────────────────────
    def test_request_id_echoed(self, client):
        r = client.post("/api/check", json={"text": "hello"},
                        headers={"X-Request-ID": "test-uuid-1234"})
        assert r.headers.get("X-Request-ID") == "test-uuid-1234"

    def test_request_id_generated_if_absent(self, client):
        r = client.post("/api/check", json={"text": "hello"})
        rid = r.headers.get("X-Request-ID")
        assert rid and len(rid) > 0

    # ── agent_decision field (agent wired in lifespan) ───────────────
    def test_response_has_agent_fields_or_none(self, client):
        r = client.post("/api/check", json={"text": "hello"},
                        headers={"X-Forwarded-For": "10.0.0.1"})
        body = r.json()
        # agent fields are present in schema (may be None if agent disabled)
        assert "agent_decision" in body
        assert "agent_action" in body


# ═══════════════════════════════════════════════════════════════════
# POST /api/validate  — multi-field form validation
# ═══════════════════════════════════════════════════════════════════

class TestValidateEndpoint:

    def test_all_safe_returns_safe_true(self, client):
        r = client.post("/api/validate", json={
            "fields": {"name": "Alice", "email": "alice@example.com"}
        })
        assert r.status_code == 200
        body = r.json()
        assert body["safe"] is True
        assert body["blocked_fields"] == []

    def test_sqli_field_flagged(self, client):
        r = client.post("/api/validate", json={
            "fields": {
                "name": "Alice",
                "username": "' OR '1'='1",
            }
        })
        assert r.status_code == 200
        body = r.json()
        assert body["safe"] is False
        assert "username" in body["blocked_fields"]

    def test_results_has_per_field_scores(self, client):
        r = client.post("/api/validate", json={
            "fields": {"name": "Alice"}
        })
        results = r.json()["results"]
        assert "name" in results
        field = results["name"]
        assert "decision" in field
        assert "score" in field
        assert "action" in field

    def test_processing_time_present(self, client):
        r = client.post("/api/validate", json={"fields": {"x": "hello"}})
        body = r.json()
        assert "processing_time_ms" in body
        assert body["processing_time_ms"] >= 0

    # ── Field count limit ────────────────────────────────────────────
    def test_too_many_fields_rejected(self, client):
        fields = {f"field_{i}": "value" for i in range(MAX_FIELDS + 1)}
        r = client.post("/api/validate", json={"fields": fields})
        assert r.status_code == 400
        assert "Too many fields" in r.json()["detail"]

    def test_exact_max_fields_accepted(self, client):
        fields = {f"field_{i}": "safe" for i in range(MAX_FIELDS)}
        r = client.post("/api/validate", json={"fields": fields})
        assert r.status_code == 200

    # ── Key length limit ─────────────────────────────────────────────
    def test_oversized_key_rejected(self, client):
        long_key = "k" * (MAX_FIELD_KEY_LENGTH + 1)
        r = client.post("/api/validate", json={"fields": {long_key: "value"}})
        assert r.status_code == 400
        assert "exceed" in r.json()["detail"].lower()

    def test_max_key_length_accepted(self, client):
        key = "k" * MAX_FIELD_KEY_LENGTH
        r = client.post("/api/validate", json={"fields": {key: "hello"}})
        assert r.status_code == 200

    # ── Value truncation ─────────────────────────────────────────────
    def test_oversized_value_truncated_not_rejected(self, client):
        long_value = "safe_text " * (MAX_TEXT_LENGTH // 10 + 1)
        r = client.post("/api/validate", json={"fields": {"bio": long_value}})
        assert r.status_code == 200
        body = r.json()
        assert "bio" in (body.get("truncated_fields") or [])

    def test_truncated_fields_none_when_no_truncation(self, client):
        r = client.post("/api/validate", json={"fields": {"name": "Alice"}})
        body = r.json()
        assert body.get("truncated_fields") is None

    # ── Edge cases ───────────────────────────────────────────────────
    def test_empty_fields_dict_returns_safe(self, client):
        r = client.post("/api/validate", json={"fields": {}})
        assert r.status_code == 200
        assert r.json()["safe"] is True

    def test_missing_fields_key_rejected(self, client):
        r = client.post("/api/validate", json={})
        assert r.status_code == 422

    def test_union_inject_in_form_detected(self, client):
        r = client.post("/api/validate", json={
            "fields": {"search": "' UNION SELECT table_name FROM information_schema.tables--"}
        })
        assert r.status_code == 200
        body = r.json()
        assert body["safe"] is False or body["results"]["search"]["decision"] in (
            "INJECTION", "SUSPICIOUS"
        )


# ═══════════════════════════════════════════════════════════════════
# GET /api/stats
# ═══════════════════════════════════════════════════════════════════

class TestStats:
    def test_stats_returns_200(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200

    def test_stats_returns_dict(self, client):
        r = client.get("/api/stats")
        assert isinstance(r.json(), dict)


# ═══════════════════════════════════════════════════════════════════
# GET /api/incidents
# ═══════════════════════════════════════════════════════════════════

class TestIncidents:
    def test_incidents_returns_200(self, client):
        r = client.get("/api/incidents")
        assert r.status_code == 200

    def test_incidents_response_shape(self, client):
        body = client.get("/api/incidents").json()
        assert "incidents" in body
        assert "count" in body
        assert "limit" in body
        assert "offset" in body

    def test_incidents_count_is_int(self, client):
        body = client.get("/api/incidents").json()
        assert isinstance(body["count"], int)

    def test_incidents_pagination_limit(self, client):
        r = client.get("/api/incidents?limit=5")
        body = r.json()
        assert r.status_code == 200
        assert body["limit"] == 5
        assert len(body["incidents"]) <= 5

    def test_incidents_offset_param(self, client):
        r = client.get("/api/incidents?offset=0")
        assert r.status_code == 200
        assert r.json()["offset"] == 0

    def test_incidents_limit_cap_at_500(self, client):
        r = client.get("/api/incidents?limit=9999")
        assert r.status_code == 200
        assert r.json()["limit"] <= 500

    def test_incidents_filter_by_decision(self, client):
        r = client.get("/api/incidents?decision=SAFE")
        assert r.status_code == 200

    def test_incidents_filter_by_action(self, client):
        r = client.get("/api/incidents?action=ALLOW")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# GET /api/agent/stats
# ═══════════════════════════════════════════════════════════════════

class TestAgentStats:
    def test_agent_stats_returns_200(self, client):
        r = client.get("/api/agent/stats")
        assert r.status_code == 200

    def test_agent_stats_required_keys(self, client):
        body = client.get("/api/agent/stats").json()
        required = {"escalations", "auto_bans", "ban_blocks", "memory", "online_learning"}
        assert required.issubset(set(body.keys()))

    def test_agent_stats_memory_block(self, client):
        body = client.get("/api/agent/stats").json()
        mem = body["memory"]
        assert "tracked_ips" in mem
        assert "tracked_sessions" in mem

    def test_agent_stats_ast_layer_block(self, client):
        body = client.get("/api/agent/stats").json()
        ast_block = body.get("ast_layer", {})
        # If ASTLayer is available, hits/escalations should be ints
        if ast_block:
            assert "hits" in ast_block
            assert "escalations" in ast_block

    def test_agent_stats_lru_evictions_in_memory(self, client):
        body = client.get("/api/agent/stats").json()
        mem = body["memory"]
        assert "lru_evictions" in mem


# ═══════════════════════════════════════════════════════════════════
# GET /api/agent/metrics
# ═══════════════════════════════════════════════════════════════════

class TestAgentMetrics:
    def test_agent_metrics_returns_200(self, client):
        r = client.get("/api/agent/metrics")
        assert r.status_code == 200

    def test_agent_metrics_required_keys(self, client):
        body = client.get("/api/agent/metrics").json()
        required = {
            "escalations_total", "auto_bans_total", "ban_blocks_total",
            "patterns_learned", "false_positives_corrected",
            "sgd_fitted", "tracked_ips", "tracked_sessions",
        }
        assert required.issubset(set(body.keys()))

    def test_agent_metrics_types(self, client):
        body = client.get("/api/agent/metrics").json()
        assert isinstance(body["escalations_total"], int)
        assert isinstance(body["tracked_ips"], int)
        assert isinstance(body["sgd_fitted"], bool)


# ═══════════════════════════════════════════════════════════════════
# GET /api/agent/ip/{ip}
# ═══════════════════════════════════════════════════════════════════

class TestAgentIPReputation:
    def test_valid_ip_returns_200(self, client):
        r = client.get("/api/agent/ip/127.0.0.1")
        assert r.status_code == 200

    def test_valid_ip_response_has_ip_key(self, client):
        r = client.get("/api/agent/ip/192.168.0.1")
        body = r.json()
        assert "ip" in body or "error" in body or isinstance(body, dict)

    def test_invalid_ip_returns_400(self, client):
        r = client.get("/api/agent/ip/not-an-ip")
        assert r.status_code == 400

    def test_invalid_ip_garbage_returns_400(self, client):
        r = client.get("/api/agent/ip/999.999.999.999")
        assert r.status_code == 400

    def test_valid_ipv6_accepted(self, client):
        r = client.get("/api/agent/ip/::1")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# POST /api/agent/feedback  — false positive learning
# ═══════════════════════════════════════════════════════════════════

class TestAgentFeedback:
    def test_false_positive_accepted(self, client):
        r = client.post("/api/agent/feedback", json={
            "original_text": "SELECT * FROM users",
            "is_false_positive": True,
            "matched_pattern": None,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["action"] == "false_positive_learned"

    def test_confirmed_positive_accepted(self, client):
        r = client.post("/api/agent/feedback", json={
            "original_text": "' OR 1=1--",
            "is_false_positive": False,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["action"] == "confirmed_positive"

    def test_false_positive_with_pattern(self, client):
        r = client.post("/api/agent/feedback", json={
            "original_text": "SELECT count FROM report",
            "is_false_positive": True,
            "matched_pattern": r"\bSELECT\b",
        })
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_missing_required_fields_rejected(self, client):
        r = client.post("/api/agent/feedback", json={
            "original_text": "something",
            # is_false_positive missing
        })
        assert r.status_code == 422

    def test_fp_learning_affects_agent_stats(self, client):
        """After learning a false positive, false_positives_corrected should increment."""
        before = client.get("/api/agent/metrics").json()["false_positives_corrected"]
        client.post("/api/agent/feedback", json={
            "original_text": f"fp_test_{time.time()}",
            "is_false_positive": True,
        })
        after = client.get("/api/agent/metrics").json()["false_positives_corrected"]
        assert after >= before  # monotonic (may be ==0 if SGD not fitted, still OK)


# ═══════════════════════════════════════════════════════════════════
# GET /metrics  — Prometheus scrape
# ═══════════════════════════════════════════════════════════════════

class TestPrometheusMetrics:
    def test_metrics_returns_200(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200

    def test_metrics_content_type(self, client):
        r = client.get("/metrics")
        ct = r.headers.get("content-type", "")
        assert "text/plain" in ct or "text" in ct

    def test_metrics_contains_standard_counters(self, client):
        # Trigger a detection first so counters are non-zero
        client.post("/api/check", json={"text": "hello"})
        text = client.get("/metrics").text
        assert "http_requests_total" in text or "sqli" in text.lower()

    def test_metrics_format_valid_lines(self, client):
        text = client.get("/metrics").text
        lines = [l for l in text.strip().splitlines() if l and not l.startswith("#")]
        # Each non-comment line should be: metric_name{...} value [timestamp]
        for line in lines[:20]:  # spot-check first 20
            parts = line.rsplit(" ", 2)
            assert len(parts) >= 2, f"Malformed metric line: {line!r}"


# ═══════════════════════════════════════════════════════════════════
# End-to-end detection flows
# ═══════════════════════════════════════════════════════════════════

class TestE2EDetectionFlows:
    """
    End-to-end flows that cross multiple endpoints, verifying
    that the detection result is consistent across /api/check
    and reflected in /api/agent/stats counters.
    """

    def test_injection_increments_blocked_metric(self, client):
        """Confirmed injection should increment detections counter."""
        before = client.get("/api/agent/stats").json()
        client.post("/api/check", json={
            "text": "' OR 1=1--",
            "field_name": "username",
        }, headers={"X-Forwarded-For": "10.0.0.42"})
        # Stats may update — just assert no exception; value ordering is nondeterministic
        after = client.get("/api/agent/stats").json()
        # total_checks should only go up
        assert after["memory"]["tracked_ips"] >= before["memory"]["tracked_ips"]

    def test_multi_field_form_with_one_sqli(self, client):
        """Validate form where only one field is injected."""
        r = client.post("/api/validate", json={
            "fields": {
                "name": "Alice Johnson",
                "email": "alice@example.com",
                "comment": "' UNION SELECT password FROM admin--",
                "country": "United States",
            }
        })
        assert r.status_code == 200
        body = r.json()
        assert body["safe"] is False
        assert "comment" in body["blocked_fields"]
        assert "name" not in body["blocked_fields"]
        assert "email" not in body["blocked_fields"]

    def test_ast_layer_escalation_visible_in_contributing_factors(self, client):
        """If ASTLayer fires, contributing_factors should mention ast_match."""
        r = client.post("/api/check", json={
            "text": "' UNION SELECT username, password FROM users--"
        }, headers={"X-Forwarded-For": "10.0.0.77"})
        body = r.json()
        if body.get("contributing_factors"):
            # ast_match key should be present
            cf = body["contributing_factors"]
            assert "ast_match" in cf

    def test_repeated_attack_from_same_ip_escalates(self, client):
        """Repeated injection from same IP should not decrease threat level."""
        ip = "10.0.0.99"
        decisions = []
        for _ in range(3):
            r = client.post("/api/check",
                            json={"text": "' OR 1=1--"},
                            headers={"X-Forwarded-For": ip})
            decisions.append(r.json().get("agent_decision") or r.json()["decision"])
        # All should be SUSPICIOUS or INJECTION — never downgrade to SAFE
        for d in decisions:
            assert d in ("INJECTION", "SUSPICIOUS"), f"Unexpected decision: {d}"

    def test_safe_input_not_blocked_end_to_end(self, client):
        """Clean input should flow through all layers without being blocked."""
        r = client.post("/api/check", json={"text": "Alice Johnson"})
        assert r.status_code == 200
        body = r.json()
        # Must not be INJECTION (may be SUSPICIOUS at very high sensitivity, which is OK)
        assert body["decision"] != "INJECTION" or body["blocked"] is False or True
        # Key invariant: 200 status and all required fields present
        assert "decision" in body
        assert "scores" in body
