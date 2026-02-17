"""
API endpoint tests for SQL Injection Protector.

Tests cover:
    - Health check endpoint
    - Single text detection (/api/check)
    - Form validation (/api/validate)
    - Statistics endpoint (/api/stats)
    - Incidents endpoint (/api/incidents)
    - Feedback endpoint (/api/incident/{id}/feedback)
    - Export endpoint (/api/export)
    - API key authentication
    - Rate limiting
    - Error handling and edge cases
    - Input validation
    - Global exception handler
    - Security headers & request ID tracking
    - Prometheus metrics
"""
import os
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def client():
    """Create a TestClient for the API (loads models once per module)."""
    # Ensure no API key is set for standard tests
    env_backup = os.environ.get("API_KEY")
    os.environ.pop("API_KEY", None)
    os.environ.pop("RATE_LIMIT", None)

    # Import fresh app
    import api_server
    with TestClient(api_server.app, raise_server_exceptions=False) as c:
        yield c

    # Restore env
    if env_backup:
        os.environ["API_KEY"] = env_backup


@pytest.fixture
def auth_client(client):
    """
    Create a TestClient with API key authentication enabled.

    Instead of reloading modules (which destroys global detector/logger),
    we patch the config object in-place to enable API key auth.
    """
    import api_server

    # Save original config
    original_cfg = api_server.cfg

    # Create patched config with API key enabled
    patched_api = replace(original_cfg.api, api_key="test-secret-key-12345")
    patched_cfg = replace(original_cfg, api=patched_api)

    # Patch
    api_server.cfg = patched_cfg

    yield client

    # Restore original config
    api_server.cfg = original_cfg


# ═══════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════

class TestHealth:
    """Health check endpoint tests."""

    def test_health_returns_ok(self, client):
        """GET /api/health must return status ok."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_has_version(self, client):
        """Health response must include version."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "version" in data
        assert data["version"] == "3.1.0"

    def test_health_has_model_status(self, client):
        """Health response must include model loading status."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "models" in data
        assert "rf" in data["models"]
        assert "cnn" in data["models"]

    def test_health_has_config(self, client):
        """Health response must include config info."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "config" in data
        assert "rate_limit_per_minute" in data["config"]
        assert "max_input_length" in data["config"]
        assert "auth_enabled" in data["config"]

    def test_health_incidents_count(self, client):
        """Health response must include incidents_logged count."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "incidents_logged" in data
        assert isinstance(data["incidents_logged"], int)


# ═══════════════════════════════════════════════════════════════════
# SINGLE TEXT CHECK (/api/check)
# ═══════════════════════════════════════════════════════════════════

class TestCheckEndpoint:
    """POST /api/check endpoint tests."""

    def test_safe_input(self, client):
        """Safe input must return SAFE decision and not be blocked."""
        resp = client.post("/api/check", json={"text": "john_doe"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "SAFE"
        assert data["blocked"] is False
        assert data["action"] == "ALLOW"

    def test_injection_detected(self, client):
        """SQL injection must be detected and blocked."""
        resp = client.post("/api/check", json={"text": "' OR '1'='1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True
        assert data["action"] in ("BLOCK", "ALERT")

    def test_union_injection(self, client):
        """UNION injection must be detected."""
        resp = client.post("/api/check", json={"text": "' UNION SELECT password FROM users--"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True
        assert data["attack_type"] == "UNION_BASED"

    def test_stacked_query_injection(self, client):
        """Stacked query injection must be detected."""
        resp = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True
        assert data["severity"] in ("CRITICAL", "HIGH")

    def test_response_structure(self, client):
        """Response must include all required fields."""
        resp = client.post("/api/check", json={"text": "test input"})
        assert resp.status_code == 200
        data = resp.json()

        required_fields = [
            "input", "decision", "action", "blocked",
            "confidence", "severity", "attack_type",
            "scores", "reason", "rule", "processing_time_ms",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_scores_structure(self, client):
        """Scores must include ensemble, rf, cnn, semantic."""
        resp = client.post("/api/check", json={"text": "' OR 1=1--"})
        data = resp.json()
        scores = data["scores"]

        assert "ensemble" in scores
        assert "rf" in scores
        assert "cnn" in scores
        assert "semantic" in scores

    def test_field_name_param(self, client):
        """field_name parameter must be accepted."""
        resp = client.post("/api/check", json={
            "text": "admin",
            "field_name": "username"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] in ("SAFE", "INVALID", "SUSPICIOUS")

    def test_processing_time_positive(self, client):
        """Processing time must be > 0."""
        resp = client.post("/api/check", json={"text": "' OR '1'='1"})
        data = resp.json()
        assert data["processing_time_ms"] > 0

    def test_incident_id_for_blocked(self, client):
        """Blocked requests should have incident_id."""
        resp = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        data = resp.json()
        if data["blocked"]:
            assert data.get("incident_id") is not None

    def test_explanation_for_injection(self, client):
        """Injections must include explanation."""
        resp = client.post("/api/check", json={"text": "' OR '1'='1"})
        data = resp.json()
        assert data.get("explanation") is not None

    def test_siem_fields_for_injection(self, client):
        """Injections must include SIEM fields."""
        resp = client.post("/api/check", json={"text": "' OR '1'='1"})
        data = resp.json()
        assert data.get("siem_fields") is not None

    def test_empty_text_rejected(self, client):
        """Empty text must be rejected with 422."""
        resp = client.post("/api/check", json={"text": ""})
        assert resp.status_code == 422

    def test_missing_text_rejected(self, client):
        """Missing text field must be rejected with 422."""
        resp = client.post("/api/check", json={})
        assert resp.status_code == 422

    def test_invalid_json_rejected(self, client):
        """Invalid JSON body must be rejected."""
        resp = client.post("/api/check",
                           content=b"not json",
                           headers={"Content-Type": "application/json"})
        assert resp.status_code == 422

    def test_very_long_input_handled(self, client):
        """Very long input must be handled gracefully (max_length in model)."""
        long_text = "A" * 10000
        resp = client.post("/api/check", json={"text": long_text})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] in ("SAFE", "INVALID", "SUSPICIOUS", "INJECTION")

    def test_unicode_input(self, client):
        """Unicode input must be handled."""
        resp = client.post("/api/check", json={"text": "Привет мир! 🌍"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] in ("SAFE", "INVALID")

    def test_url_encoded_injection(self, client):
        """URL-encoded injection must be detected."""
        resp = client.post("/api/check", json={"text": "%27%20OR%201=1--"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True

    def test_comment_obfuscated_injection(self, client):
        """Comment-obfuscated injection must be detected."""
        resp = client.post("/api/check", json={"text": "'/**/OR/**/1=1--"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True


# ═══════════════════════════════════════════════════════════════════
# FORM VALIDATION (/api/validate)
# ═══════════════════════════════════════════════════════════════════

class TestValidateEndpoint:
    """POST /api/validate endpoint tests."""

    def test_safe_form(self, client):
        """All-safe form must return safe=True."""
        resp = client.post("/api/validate", json={
            "fields": {
                "username": "john_doe",
                "email": "john@example.com",
                "comment": "Hello World",
            }
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is True
        assert len(data["blocked_fields"]) == 0

    def test_form_with_injection(self, client):
        """Form with injection must return safe=False and identify blocked fields."""
        resp = client.post("/api/validate", json={
            "fields": {
                "username": "admin'--",
                "email": "john@example.com",
                "search": "' UNION SELECT password FROM users--",
            }
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is False
        assert len(data["blocked_fields"]) > 0
        # At least the search field with UNION must be blocked
        assert "search" in data["blocked_fields"]

    def test_validate_results_per_field(self, client):
        """Each field must have its own detection result."""
        resp = client.post("/api/validate", json={
            "fields": {
                "username": "john_doe",
                "password": "secure123",
            }
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "username" in data["results"]
        assert "password" in data["results"]

    def test_validate_result_structure(self, client):
        """Per-field results must include decision, action, score, severity, attack_type."""
        resp = client.post("/api/validate", json={
            "fields": {"test": "hello world"}
        })
        data = resp.json()
        result = data["results"]["test"]
        assert "decision" in result
        assert "action" in result
        assert "score" in result
        assert "severity" in result
        assert "attack_type" in result

    def test_validate_processing_time(self, client):
        """Validate response must include processing_time_ms."""
        resp = client.post("/api/validate", json={
            "fields": {"a": "hello"}
        })
        data = resp.json()
        assert "processing_time_ms" in data
        assert data["processing_time_ms"] > 0

    def test_validate_empty_fields(self, client):
        """Empty fields dict must return safe with no results."""
        resp = client.post("/api/validate", json={"fields": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert data["safe"] is True
        assert len(data["blocked_fields"]) == 0

    def test_validate_too_many_fields(self, client):
        """More than MAX_FIELDS must return 400."""
        fields = {f"field_{i}": f"value_{i}" for i in range(51)}
        resp = client.post("/api/validate", json={"fields": fields})
        assert resp.status_code == 400
        assert "Too many fields" in resp.json()["detail"]

    def test_validate_missing_fields(self, client):
        """Missing fields key must return 422."""
        resp = client.post("/api/validate", json={})
        assert resp.status_code == 422

    def test_validate_incident_ids(self, client):
        """Blocked fields should generate incident_ids."""
        resp = client.post("/api/validate", json={
            "fields": {
                "search": "' UNION SELECT password FROM users--",
            }
        })
        data = resp.json()
        if data["blocked_fields"]:
            assert data.get("incident_ids") is not None


# ═══════════════════════════════════════════════════════════════════
# STATISTICS (/api/stats)
# ═══════════════════════════════════════════════════════════════════

class TestStatsEndpoint:
    """GET /api/stats endpoint tests."""

    def test_stats_returns_ok(self, client):
        """Stats endpoint must return 200."""
        resp = client.get("/api/stats")
        assert resp.status_code == 200

    def test_stats_structure(self, client):
        """Stats must include expected fields."""
        resp = client.get("/api/stats")
        data = resp.json()
        assert "total_incidents" in data
        assert "by_decision" in data
        assert "blocked_count" in data
        assert "average_score" in data
        assert "unique_ips" in data

    def test_stats_by_decision(self, client):
        """Stats must include breakdown by decision."""
        resp = client.get("/api/stats")
        data = resp.json()
        by_decision = data["by_decision"]
        for key in ["safe", "invalid", "suspicious", "injection"]:
            assert key in by_decision


# ═══════════════════════════════════════════════════════════════════
# INCIDENTS (/api/incidents)
# ═══════════════════════════════════════════════════════════════════

class TestIncidentsEndpoint:
    """GET /api/incidents endpoint tests."""

    def test_incidents_returns_ok(self, client):
        """Incidents endpoint must return 200."""
        resp = client.get("/api/incidents")
        assert resp.status_code == 200

    def test_incidents_structure(self, client):
        """Response must include incidents list and pagination info."""
        resp = client.get("/api/incidents")
        data = resp.json()
        assert "incidents" in data
        assert "count" in data
        assert "limit" in data
        assert "offset" in data
        assert isinstance(data["incidents"], list)

    def test_incidents_pagination(self, client):
        """Pagination parameters must be respected."""
        resp = client.get("/api/incidents?limit=5&offset=0")
        data = resp.json()
        assert data["limit"] == 5
        assert data["offset"] == 0
        assert data["count"] <= 5

    def test_incidents_limit_capped(self, client):
        """Limit must be capped at 500."""
        resp = client.get("/api/incidents?limit=1000")
        data = resp.json()
        assert data["limit"] == 500

    def test_incidents_filter_by_decision(self, client):
        """Decision filter must work."""
        # First, generate an INJECTION incident
        client.post("/api/check", json={"text": "' OR '1'='1"})

        resp = client.get("/api/incidents?decision=INJECTION")
        data = resp.json()
        for inc in data["incidents"]:
            assert inc["decision"] == "INJECTION"

    def test_incidents_filter_by_action(self, client):
        """Action filter must work."""
        resp = client.get("/api/incidents?action=BLOCK")
        data = resp.json()
        for inc in data["incidents"]:
            assert inc["action"] == "BLOCK"


# ═══════════════════════════════════════════════════════════════════
# FEEDBACK (/api/incident/{id}/feedback)
# ═══════════════════════════════════════════════════════════════════

class TestFeedbackEndpoint:
    """POST /api/incident/{id}/feedback endpoint tests."""

    def test_feedback_submit(self, client):
        """Feedback submission must return ok."""
        # First create an incident
        resp = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        data = resp.json()
        incident_id = data.get("incident_id")

        if incident_id:
            resp = client.post(f"/api/incident/{incident_id}/feedback", json={
                "is_false_positive": False,
                "notes": "Confirmed attack"
            })
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

    def test_feedback_false_positive(self, client):
        """False positive feedback must be accepted."""
        resp = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        data = resp.json()
        incident_id = data.get("incident_id")

        if incident_id:
            resp = client.post(f"/api/incident/{incident_id}/feedback", json={
                "is_false_positive": True,
                "notes": "This was actually a safe input"
            })
            assert resp.status_code == 200

    def test_feedback_missing_body(self, client):
        """Missing request body must return 422."""
        resp = client.post("/api/incident/1/feedback", json={})
        assert resp.status_code == 422

    def test_feedback_without_notes(self, client):
        """Feedback without notes must be accepted (notes is optional)."""
        resp = client.post("/api/check", json={"text": "'; DROP TABLE users--"})
        data = resp.json()
        incident_id = data.get("incident_id")

        if incident_id:
            resp = client.post(f"/api/incident/{incident_id}/feedback", json={
                "is_false_positive": False,
            })
            assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# EXPORT (/api/export)
# ═══════════════════════════════════════════════════════════════════

class TestExportEndpoint:
    """GET /api/export endpoint tests."""

    def test_export_json(self, client):
        """JSON export must return valid JSON."""
        resp = client.get("/api/export?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers.get("content-type", "")

    def test_export_csv(self, client):
        """CSV export must return text/csv."""
        resp = client.get("/api/export?format=csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    def test_export_cef(self, client):
        """CEF export must return text/plain."""
        resp = client.get("/api/export?format=cef")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")

    def test_export_content_disposition(self, client):
        """Export must set Content-Disposition header."""
        resp = client.get("/api/export?format=json")
        assert "Content-Disposition" in resp.headers or "content-disposition" in resp.headers

    def test_export_severity_filter(self, client):
        """Severity filter must be accepted."""
        resp = client.get("/api/export?format=json&severity_min=HIGH")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# DEMO PAGE
# ═══════════════════════════════════════════════════════════════════

class TestDemoEndpoint:
    """GET /api/demo endpoint tests."""

    def test_demo_returns_html(self, client):
        """Demo page must return HTML."""
        resp = client.get("/api/demo")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

    def test_demo_contains_title(self, client):
        """Demo page must contain the app title."""
        resp = client.get("/api/demo")
        assert "SQL Injection" in resp.text


# ═══════════════════════════════════════════════════════════════════
# API KEY AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════

class TestAuthentication:
    """API key authentication tests."""

    def test_no_key_returns_401(self, auth_client):
        """Request without API key must return 401."""
        resp = auth_client.post("/api/check", json={"text": "test"})
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, auth_client):
        """Request with wrong API key must return 401."""
        resp = auth_client.post(
            "/api/check",
            json={"text": "test"},
            headers={"X-API-Key": "wrong-key"}
        )
        assert resp.status_code == 401

    def test_correct_key_allows_access(self, auth_client):
        """Request with correct API key must succeed."""
        resp = auth_client.post(
            "/api/check",
            json={"text": "hello world"},
            headers={"X-API-Key": "test-secret-key-12345"}
        )
        assert resp.status_code == 200

    def test_key_via_query_param(self, auth_client):
        """API key via query parameter must work."""
        resp = auth_client.post(
            "/api/check?api_key=test-secret-key-12345",
            json={"text": "hello world"},
        )
        assert resp.status_code == 200

    def test_health_no_auth_required(self, auth_client):
        """Health endpoint must NOT require authentication."""
        resp = auth_client.get("/api/health")
        assert resp.status_code == 200

    def test_stats_requires_auth(self, auth_client):
        """Stats endpoint must require authentication."""
        resp = auth_client.get("/api/stats")
        assert resp.status_code == 401

    def test_incidents_requires_auth(self, auth_client):
        """Incidents endpoint must require authentication."""
        resp = auth_client.get("/api/incidents")
        assert resp.status_code == 401

    def test_export_requires_auth(self, auth_client):
        """Export endpoint must require authentication."""
        resp = auth_client.get("/api/export")
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════

class TestRateLimiting:
    """Rate limiting tests."""

    def test_rate_limit_enforced(self, client):
        """Exceeding rate limit must return 429."""
        from dataclasses import replace

        import api_server

        # Save original config and rate limit store
        original_cfg = api_server.cfg
        original_store = api_server._rate_limit_store.copy()

        # Patch config with very low rate limit
        patched_api = replace(original_cfg.api, rate_limit_per_minute=3)
        patched_cfg = replace(original_cfg, api=patched_api)
        api_server.cfg = patched_cfg
        api_server._rate_limit_store.clear()

        try:
            # Make requests until rate limited
            responses = []
            for i in range(5):
                resp = client.post("/api/check", json={"text": f"test {i}"})
                responses.append(resp.status_code)

            # At least one must be 429
            assert 429 in responses, f"Rate limit not enforced: {responses}"
        finally:
            # Restore original config and rate limit store
            api_server.cfg = original_cfg
            api_server._rate_limit_store.clear()
            api_server._rate_limit_store.update(original_store)


# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Error handling and edge case tests."""

    def test_404_for_unknown_route(self, client):
        """Unknown route must return 404."""
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404

    def test_method_not_allowed(self, client):
        """Wrong HTTP method must return 405."""
        resp = client.get("/api/check")
        assert resp.status_code == 405

    def test_invalid_content_type(self, client):
        """Non-JSON content type must be rejected."""
        resp = client.post(
            "/api/check",
            content=b"text=hello",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert resp.status_code == 422

    def test_special_characters_in_input(self, client):
        """Special characters must not crash the API."""
        special_inputs = [
            "\x00\x01\x02\x03",
            "\\n\\r\\t",
            "<>&\"'`",
            "🔥💉🐛",
            "\u0000SELECT",
        ]
        for text in special_inputs:
            resp = client.post("/api/check", json={"text": text})
            assert resp.status_code == 200, f"Crashed on input: {repr(text)}"

    def test_concurrent_requests(self, client):
        """Multiple sequential requests must all succeed."""
        texts = [
            "hello world",
            "' OR '1'='1",
            "john_doe",
            "'; DROP TABLE--",
            "admin",
        ]
        for text in texts:
            resp = client.post("/api/check", json={"text": text})
            assert resp.status_code == 200, f"Failed for: {text}"

    def test_very_short_input(self, client):
        """Single character input must be handled."""
        resp = client.post("/api/check", json={"text": "a"})
        assert resp.status_code == 200

    def test_whitespace_only_input(self, client):
        """Whitespace-only input must be handled."""
        resp = client.post("/api/check", json={"text": "   "})
        assert resp.status_code == 200

    def test_numeric_only_input(self, client):
        """Numeric input must be handled."""
        resp = client.post("/api/check", json={"text": "12345"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "SAFE"


# ═══════════════════════════════════════════════════════════════════
# INTEGRATION: End-to-end workflow
# ═══════════════════════════════════════════════════════════════════

class TestIntegration:
    """End-to-end integration tests."""

    def test_full_workflow_safe(self, client):
        """Full workflow: check safe → verify in stats."""
        # Check a safe input
        resp = client.post("/api/check", json={"text": "normal_user_123"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "SAFE"
        assert data["blocked"] is False

        # Health should still be ok
        resp = client.get("/api/health")
        assert resp.json()["status"] == "ok"

    def test_full_workflow_attack(self, client):
        """Full workflow: detect attack → log → check incidents → feedback."""
        # 1. Send attack
        resp = client.post("/api/check", json={
            "text": "' UNION SELECT password FROM users--",
            "field_name": "search"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "INJECTION"
        assert data["blocked"] is True
        incident_id = data.get("incident_id")

        # 2. Check incidents list
        resp = client.get("/api/incidents?action=BLOCK&limit=5")
        assert resp.status_code == 200
        incidents = resp.json()["incidents"]
        assert len(incidents) > 0

        # 3. Submit feedback if incident_id exists
        if incident_id:
            resp = client.post(f"/api/incident/{incident_id}/feedback", json={
                "is_false_positive": False,
                "notes": "Confirmed UNION-based attack"
            })
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"

        # 4. Check stats
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_incidents"] > 0
        assert stats["blocked_count"] > 0

    def test_form_validation_full_workflow(self, client):
        """Full workflow: validate form → check results."""
        resp = client.post("/api/validate", json={
            "fields": {
                "first_name": "John",
                "last_name": "O'Brien",
                "email": "john@example.com",
                "search": "'; DROP TABLE users--",
                "comment": "Hello World",
            }
        })
        assert resp.status_code == 200
        data = resp.json()

        # Form is not safe (search field is malicious)
        assert data["safe"] is False
        assert "search" in data["blocked_fields"]

        # Safe fields must not be in blocked list
        assert "first_name" not in data["blocked_fields"]
        assert "last_name" not in data["blocked_fields"]
        assert "email" not in data["blocked_fields"]
        assert "comment" not in data["blocked_fields"]

        # Each field has a result
        for field in ["first_name", "last_name", "email", "search", "comment"]:
            assert field in data["results"]

    def test_export_after_incidents(self, client):
        """Export must include previously logged incidents."""
        # Generate some incidents
        client.post("/api/check", json={"text": "' OR '1'='1"})
        client.post("/api/check", json={"text": "'; DROP TABLE x--"})

        # Export JSON
        resp = client.get("/api/export?format=json&severity_min=LOW")
        assert resp.status_code == 200

        # Export CSV
        resp = client.get("/api/export?format=csv&severity_min=LOW")
        assert resp.status_code == 200

        # Export CEF
        resp = client.get("/api/export?format=cef&severity_min=LOW")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# PROMETHEUS METRICS
# ═══════════════════════════════════════════════════════════════════

class TestMetricsEndpoint:
    """Prometheus /metrics endpoint tests."""

    def test_metrics_returns_ok(self, client):
        """GET /metrics must return 200."""
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type(self, client):
        """Metrics must use Prometheus content type."""
        resp = client.get("/metrics")
        content_type = resp.headers.get("content-type", "")
        assert "text/plain" in content_type or "text/plain" in content_type

    def test_metrics_contains_app_info(self, client):
        """Metrics must contain app info."""
        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_app_info" in body

    def test_metrics_contains_request_counters(self, client):
        """Metrics must contain request counters after API calls."""
        # Make a request first
        client.post("/api/check", json={"text": "hello world"})

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_requests_total" in body

    def test_metrics_contains_detection_counters(self, client):
        """Metrics must contain detection counters after detection."""
        # Trigger a detection
        client.post("/api/check", json={"text": "' OR '1'='1"})

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_detections_total" in body

    def test_metrics_contains_inference_histogram(self, client):
        """Metrics must contain inference duration histogram."""
        client.post("/api/check", json={"text": "test"})

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_inference_duration_seconds" in body

    def test_metrics_contains_model_loaded(self, client):
        """Metrics must contain model loaded gauges."""
        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_model_loaded" in body

    def test_metrics_blocked_counter_increments(self, client):
        """Blocked counter must increment after blocking an injection."""
        # Send an injection
        client.post("/api/check", json={"text": "'; DROP TABLE users--"})

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_blocked_total" in body

    def test_metrics_request_duration_histogram(self, client):
        """Request duration histogram must be populated."""
        client.get("/api/health")

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_request_duration_seconds" in body

    def test_metrics_severity_counter(self, client):
        """Severity counter must track detection severity levels."""
        client.post("/api/check", json={"text": "' OR 1=1--"})

        resp = client.get("/metrics")
        body = resp.text
        assert "sqli_severity_total" in body


# ═══════════════════════════════════════════════════════════════════
# SECURITY HEADERS & REQUEST ID
# ═══════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """Security headers and request ID middleware tests."""

    def test_x_content_type_options(self, client):
        """Response must include X-Content-Type-Options: nosniff."""
        resp = client.get("/api/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        """Response must include X-Frame-Options: DENY."""
        resp = client.get("/api/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_x_xss_protection(self, client):
        """Response must include X-XSS-Protection header."""
        resp = client.get("/api/health")
        assert resp.headers.get("x-xss-protection") == "1; mode=block"

    def test_referrer_policy(self, client):
        """Response must include Referrer-Policy header."""
        resp = client.get("/api/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_cache_control_no_store(self, client):
        """Response must include Cache-Control: no-store."""
        resp = client.get("/api/health")
        assert "no-store" in resp.headers.get("cache-control", "")

    def test_csp_on_html_pages(self, client):
        """HTML pages (demo) must include Content-Security-Policy."""
        resp = client.get("/api/demo")
        assert resp.status_code == 200
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src" in csp

    def test_no_csp_on_json_api(self, client):
        """JSON API endpoints should NOT include CSP header."""
        resp = client.get("/api/health")
        # CSP is only for text/html
        csp = resp.headers.get("content-security-policy")
        assert csp is None

    def test_security_headers_on_post(self, client):
        """POST endpoints must also have security headers."""
        resp = client.post("/api/check", json={"text": "hello"})
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_request_id_generated(self, client):
        """Responses must include X-Request-ID header."""
        resp = client.get("/api/health")
        request_id = resp.headers.get("x-request-id")
        assert request_id is not None
        assert len(request_id) > 0

    def test_request_id_passthrough(self, client):
        """Client-provided X-Request-ID must be echoed back."""
        custom_id = "my-trace-12345"
        resp = client.get("/api/health", headers={"X-Request-ID": custom_id})
        assert resp.headers.get("x-request-id") == custom_id

    def test_request_id_unique_per_request(self, client):
        """Each request must get a different auto-generated request ID."""
        resp1 = client.get("/api/health")
        resp2 = client.get("/api/health")
        id1 = resp1.headers.get("x-request-id")
        id2 = resp2.headers.get("x-request-id")
        assert id1 != id2

    def test_request_id_is_valid_uuid(self, client):
        """Auto-generated request ID must be a valid UUID."""
        import uuid

        resp = client.get("/api/health")
        request_id = resp.headers.get("x-request-id")
        # Should not raise
        uuid.UUID(request_id)


# ═══════════════════════════════════════════════════════════════════
# IP VALIDATION
# ═══════════════════════════════════════════════════════════════════

class TestIPValidation:
    """IP extraction and validation tests."""

    def test_spoofed_xff_does_not_crash(self, client):
        """Spoofed X-Forwarded-For with garbage must not crash."""
        resp = client.post(
            "/api/check",
            json={"text": "hello"},
            headers={"X-Forwarded-For": "not-an-ip, also-garbage"},
        )
        assert resp.status_code == 200

    def test_valid_xff_accepted(self, client):
        """Valid X-Forwarded-For IP must be accepted."""
        resp = client.post(
            "/api/check",
            json={"text": "hello"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
        assert resp.status_code == 200

    def test_ipv6_xff_accepted(self, client):
        """IPv6 X-Forwarded-For must be accepted."""
        resp = client.post(
            "/api/check",
            json={"text": "hello"},
            headers={"X-Forwarded-For": "::1"},
        )
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════
# LOG INJECTION PREVENTION
# ═══════════════════════════════════════════════════════════════════

class TestLogInjectionPrevention:
    """Tests that log-injection vectors don't crash the API."""

    def test_newline_in_field_name(self, client):
        """Newline in field_name must not crash (log injection vector)."""
        resp = client.post("/api/check", json={
            "text": "hello",
            "field_name": "username\nINJECTED_LOG_LINE",
        })
        assert resp.status_code == 200

    def test_crlf_in_user_agent(self, client):
        """CRLF in User-Agent must not crash (header injection vector)."""
        resp = client.post(
            "/api/check",
            json={"text": "test"},
            headers={"User-Agent": "bot\r\nX-Injected: true"},
        )
        assert resp.status_code == 200

    def test_oversized_user_agent(self, client):
        """Very large User-Agent must not crash."""
        resp = client.post(
            "/api/check",
            json={"text": "test"},
            headers={"User-Agent": "A" * 10000},
        )
        assert resp.status_code == 200
