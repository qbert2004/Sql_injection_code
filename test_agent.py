"""
pytest test suite for SQLiAgent (agent.py)
==========================================
Covers:
  - Rules A-F (all 6 escalation rules)
  - Thread safety (concurrent evaluate() calls)
  - SQLite persistence (flush → load → verify)
  - IP memory: bans, TTL expiry, reputation formula
  - Session memory: field scanning, attack sequence
  - Edge cases: source_ip=None, session_id=None, expired bans, max_ips

Run:
    py -3 -m pytest test_agent.py -v
    py -3 -m pytest test_agent.py -v --tb=short

Requirements:
    pip install pytest
    (sklearn optional — online learning tests skipped if unavailable)
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from agent import (
    AgentConfig,
    AgentStore,
    IPMemory,
    IPProfile,
    SessionContext,
    SessionMemory,
    DecisionExplainer,
    OnlineLearning,
    PredictiveDefense,
    SQLiAgent,
    _SKLEARN_AVAILABLE,
)
from sql_injection_detector import EnsembleConfig


# ─────────────────────────────────────────────────────────────
#  Helpers: mock detector
# ─────────────────────────────────────────────────────────────

def _mock_detector(decision="SAFE", action="ALLOW", score=0.5, attack_type="NONE"):
    """Return a minimal mock SQLInjectionEnsemble."""
    det = MagicMock()
    # Use a real EnsembleConfig so that dataclasses.asdict() works in _get_adapted_detector
    det.config = EnsembleConfig()
    det.rf_model = MagicMock()
    det.rf_vectorizer = MagicMock()
    det.cnn_model = None
    det.char_tokenizer = None
    det.rf_loaded = True
    det.cnn_loaded = False
    det.detect.return_value = {
        "decision": decision,
        "action": action,
        "score": score,
        "P_rf": score,
        "P_cnn": 0.0,
        "semantic_score": score,
        "confidence_level": "HIGH" if score > 5 else "LOW",
        "severity": "HIGH" if action == "BLOCK" else "INFO",
        "attack_type": attack_type,
        "reason": f"Mock: {decision}",
        "rule": "MOCK_RULE",
        "evidence": [],
        "breakdown": {},
        "explanation": {},
        "siem_fields": {},
    }
    return det


def _injection_detector():
    return _mock_detector(decision="INJECTION", action="BLOCK", score=8.0, attack_type="BOOLEAN_BASED")


def _suspicious_detector():
    return _mock_detector(decision="SUSPICIOUS", action="CHALLENGE", score=4.5)


def _safe_detector():
    return _mock_detector(decision="SAFE", action="ALLOW", score=0.5)


def _make_agent(detector=None, config=None):
    """Create a SQLiAgent with a mock detector and optional config."""
    if detector is None:
        detector = _safe_detector()
    if config is None:
        config = AgentConfig(
            ip_attack_threshold=3,
            ip_attack_window_seconds=300,
            ip_ban_duration_seconds=3600,
            suspicious_escalation_count=3,
            suspicious_window_seconds=120,
            enable_adaptive_thresholds=False,   # off by default in tests
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
    return SQLiAgent(detector, config=config)


# ─────────────────────────────────────────────────────────────
#  IPMemory tests
# ─────────────────────────────────────────────────────────────

class TestIPMemory:

    def test_get_profile_creates_new(self):
        mem = IPMemory()
        with mem._lock:
            p = mem.get_profile("1.2.3.4")
        assert p.ip == "1.2.3.4"
        assert p.attack_count == 0

    def test_get_profile_returns_same_object(self):
        mem = IPMemory()
        with mem._lock:
            p1 = mem.get_profile("1.2.3.4")
            p2 = mem.get_profile("1.2.3.4")
        assert p1 is p2

    def test_update_tracks_attack(self):
        mem = IPMemory()
        result = {"agent_decision": "INJECTION", "agent_action": "BLOCK", "attack_type": "BOOLEAN_BASED"}
        mem.update("1.2.3.4", result, endpoint="/login", field_name="username")
        with mem._lock:
            p = mem.get_profile("1.2.3.4")
        assert p.attack_count == 1
        assert "/login" in p.endpoints_targeted
        assert "username" in p.fields_targeted

    def test_update_tracks_suspicious(self):
        mem = IPMemory()
        result = {"agent_decision": "SUSPICIOUS", "agent_action": "CHALLENGE"}
        mem.update("1.2.3.4", result)
        with mem._lock:
            p = mem.get_profile("1.2.3.4")
        assert p.suspicious_count == 1

    def test_ban_and_is_banned(self):
        mem = IPMemory()
        assert not mem.is_banned("1.2.3.4")
        mem.ban("1.2.3.4", duration_seconds=3600)
        assert mem.is_banned("1.2.3.4")

    def test_ban_expiry(self):
        mem = IPMemory()
        mem.ban("1.2.3.4", duration_seconds=0)  # immediate expiry
        time.sleep(0.01)
        assert not mem.is_banned("1.2.3.4")

    def test_compute_reputation_clean(self):
        p = IPProfile(ip="1.2.3.4", total_requests=100, attack_count=0)
        mem = IPMemory()
        assert mem.compute_reputation(p) == 0.0

    def test_compute_reputation_attacker(self):
        p = IPProfile(ip="1.2.3.4", total_requests=10, attack_count=10)
        p.attack_types["BOOLEAN_BASED"] = 5
        p.attack_types["UNION_BASED"] = 3
        p.attack_types["TIME_BASED"] = 2
        mem = IPMemory()
        score = mem.compute_reputation(p)
        assert score > 0.8   # high attack ratio + 10 attacks + 3 types

    def test_cleanup_stale(self):
        mem = IPMemory(ttl=0.01)
        result = {"agent_decision": "SAFE", "agent_action": "ALLOW"}
        mem.update("1.2.3.4", result)
        time.sleep(0.05)
        removed = mem.cleanup_stale()
        assert removed == 1
        with mem._lock:
            assert "1.2.3.4" not in mem._profiles

    def test_cleanup_does_not_remove_banned(self):
        mem = IPMemory(ttl=0.01)
        result = {"agent_decision": "INJECTION", "agent_action": "BLOCK"}
        mem.update("1.2.3.4", result)
        mem.ban("1.2.3.4", duration_seconds=3600)
        time.sleep(0.05)
        removed = mem.cleanup_stale()
        assert removed == 0   # banned IPs are kept

    def test_count_active_bans(self):
        mem = IPMemory()
        assert mem.count_active_bans() == 0
        mem.ban("1.1.1.1", 3600)
        mem.ban("2.2.2.2", 3600)
        assert mem.count_active_bans() == 2

    def test_mean_reputation_empty(self):
        mem = IPMemory()
        assert mem.mean_reputation() == 0.0

    def test_thread_safety_concurrent_updates(self):
        """Multiple threads updating the same IP must not raise exceptions."""
        mem = IPMemory()
        errors = []

        def worker():
            try:
                for _ in range(50):
                    mem.update(
                        "1.2.3.4",
                        {"agent_decision": "INJECTION", "agent_action": "BLOCK", "attack_type": "NONE"},
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        with mem._lock:
            p = mem.get_profile("1.2.3.4")
        assert p.attack_count == 400  # 8 threads × 50 iterations


# ─────────────────────────────────────────────────────────────
#  SessionMemory tests
# ─────────────────────────────────────────────────────────────

class TestSessionMemory:

    def test_get_or_create(self):
        mem = SessionMemory()
        with mem._lock:
            ctx = mem.get_or_create("session-1")
        assert ctx.session_id == "session-1"

    def test_tracks_fields(self):
        mem = SessionMemory()
        result = {"agent_decision": "SAFE", "agent_action": "ALLOW", "attack_type": "NONE"}
        mem.update("sess-1", result, field_name="username")
        mem.update("sess-1", result, field_name="password")
        with mem._lock:
            ctx = mem.get_or_create("sess-1")
        assert "username" in ctx.fields_probed
        assert "password" in ctx.fields_probed
        assert len(ctx.fields_probed) == 2

    def test_escalation_level_increases_on_attack(self):
        mem = SessionMemory()
        result = {"agent_decision": "INJECTION", "agent_action": "BLOCK", "attack_type": "BOOLEAN_BASED"}
        mem.update("sess-1", result)
        mem.update("sess-1", result)
        with mem._lock:
            ctx = mem.get_or_create("sess-1")
        assert ctx.escalation_level == 2

    def test_cleanup_stale_session(self):
        mem = SessionMemory(ttl=0.01)
        with mem._lock:
            mem.get_or_create("sess-old")
        time.sleep(0.05)
        removed = mem.cleanup_stale()
        assert removed == 1

    def test_thread_safety_concurrent_updates(self):
        """Multiple threads updating the same session must not raise exceptions."""
        mem = SessionMemory()
        errors = []

        def worker(field):
            try:
                for _ in range(30):
                    mem.update("sess-1",
                               {"agent_decision": "SAFE", "agent_action": "ALLOW", "attack_type": "NONE"},
                               field_name=field)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"field_{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — Rule A: Ban fast-path
# ─────────────────────────────────────────────────────────────

class TestRuleA:

    def test_banned_ip_blocked_without_calling_detector(self):
        """Rule A: banned IP → BLOCK immediately, detector.detect() never called."""
        det = _injection_detector()
        agent = _make_agent(det)
        agent.ip_memory.ban("1.2.3.4", duration_seconds=3600)

        result = agent.evaluate("safe text", source_ip="1.2.3.4")

        assert result["agent_decision"] == "INJECTION"
        assert result["agent_action"] == "BLOCK"
        assert result["rule"] == "AGENT_RULE_A_BAN"
        # detector.detect() must NOT have been called (would call underlying detect method)
        det.detect.assert_not_called()

    def test_expired_ban_allows_through(self):
        """Expired ban is lifted — request goes through normally."""
        det = _safe_detector()
        agent = _make_agent(det)
        agent.ip_memory.ban("1.2.3.4", duration_seconds=0)   # immediate expiry
        time.sleep(0.01)

        result = agent.evaluate("safe text", source_ip="1.2.3.4")
        # Ban expired → should go through (safe detector → SAFE)
        assert result["agent_decision"] == "SAFE"
        det.detect.assert_called_once()

    def test_ban_includes_profile_in_response(self):
        """Ban response includes ip_profile and session_context."""
        agent = _make_agent()
        agent.ip_memory.ban("5.5.5.5", duration_seconds=3600)
        result = agent.evaluate("anything", source_ip="5.5.5.5")
        assert result["ip_profile"] is not None
        assert result["ip_profile"]["is_banned"] is True
        assert result["session_context"] is not None


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — Rule B: Auto-ban by attack frequency
# ─────────────────────────────────────────────────────────────

class TestRuleB:
    """
    Rule B: Auto-ban by attack frequency.

    NOTE: The agent records `recent_attacks` inside ip_memory.update(), which is called
    AFTER _escalate_decision(). So the ban triggers on the N+1-th request, when the
    sliding window already has N attacks from previous calls.
    threshold=3 → ban fires when recent_attacks has >=3 entries, i.e. on the 4th call.
    """

    def test_three_attacks_trigger_autoban(self):
        """Rule B: After 3 successful attack records, the 4th call triggers auto-ban."""
        cfg = AgentConfig(
            ip_attack_threshold=3,
            ip_attack_window_seconds=300,
            ip_ban_duration_seconds=3600,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_injection_detector(), config=cfg)
        ip = "10.0.0.1"

        # 4 attacks: first 3 record the timestamps, 4th sees >=3 in window and bans
        for _ in range(4):
            agent.evaluate("' OR 1=1--", source_ip=ip)

        assert agent.ip_memory.is_banned(ip)
        assert agent._stats["auto_bans"] >= 1

    def test_attacks_outside_window_dont_ban(self):
        """Attacks outside the time window should NOT trigger ban."""
        cfg = AgentConfig(
            ip_attack_threshold=3,
            ip_attack_window_seconds=1,   # 1 second window
            ip_ban_duration_seconds=3600,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_injection_detector(), config=cfg)
        ip = "10.0.0.2"

        # Manually plant 2 old attack timestamps (outside 1s window)
        with agent.ip_memory._lock:
            p = agent.ip_memory.get_profile(ip)
            old_ts = time.time() - 10
            p.recent_attacks.append(old_ts)
            p.recent_attacks.append(old_ts)
            p.attack_count = 2

        # One more attack — total 3, but only 1 within window after update
        agent.evaluate("' OR 1=1--", source_ip=ip)

        assert not agent.ip_memory.is_banned(ip), "Should NOT be banned — only 1 attack within window"

    def test_autoban_result_is_block(self):
        """The request that triggers the ban should return BLOCK."""
        cfg = AgentConfig(
            ip_attack_threshold=2,
            ip_attack_window_seconds=300,
            ip_ban_duration_seconds=3600,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_injection_detector(), config=cfg)
        ip = "10.0.0.3"

        # With threshold=2:
        # Call 1: 0 in window → no ban, update records 1st attack
        # Call 2: 1 in window → no ban, update records 2nd attack
        # Call 3: 2 in window >= threshold=2 → BAN triggered on this call
        agent.evaluate("attack", source_ip=ip)
        agent.evaluate("attack", source_ip=ip)
        result = agent.evaluate("attack", source_ip=ip)  # 3rd → triggers ban

        assert result["agent_decision"] == "INJECTION"
        assert result["agent_action"] == "BLOCK"
        assert result["escalated"] is True


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — Rule C: SUSPICIOUS escalation
# ─────────────────────────────────────────────────────────────

class TestRuleC:
    """
    Rule C: SUSPICIOUS escalation.

    NOTE: same as Rule B — recent_suspicious is updated AFTER _escalate_decision.
    threshold=3 → escalation fires when recent_suspicious has >=3 entries,
    i.e. on the 4th SUSPICIOUS call.
    """

    def test_three_suspicious_escalate_to_block(self):
        """Rule C: After 3 SUSPICIOUS records, 4th call escalates to BLOCK."""
        cfg = AgentConfig(
            suspicious_escalation_count=3,
            suspicious_window_seconds=300,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_suspicious_detector(), config=cfg)
        ip = "10.0.1.1"

        # 4 calls: first 3 record suspicious timestamps, 4th sees >=3 and escalates
        results = [agent.evaluate("fuzzy input", source_ip=ip) for _ in range(4)]

        assert any(r["agent_decision"] == "INJECTION" for r in results), \
            f"Expected escalation on 4th call. decisions={[r['agent_decision'] for r in results]}"

    def test_two_suspicious_dont_escalate(self):
        """3 SUSPICIOUS requests (2 threshold) should not escalate before 4th call."""
        cfg = AgentConfig(
            suspicious_escalation_count=3,
            suspicious_window_seconds=300,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_suspicious_detector(), config=cfg)
        ip = "10.0.1.2"

        # Only 2 calls → 2 suspicious records, threshold=3 → no escalation yet
        results = [agent.evaluate("fuzzy input", source_ip=ip) for _ in range(2)]

        assert all(r["agent_decision"] == "SUSPICIOUS" for r in results), \
            f"Should stay SUSPICIOUS. decisions={[r['agent_decision'] for r in results]}"


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — Rule D: Adaptive thresholds
# ─────────────────────────────────────────────────────────────

class TestRuleD:

    def test_adapted_detector_created_for_high_reputation(self):
        """Rule D: high reputation IP gets adapted detector with lower tau."""
        cfg = AgentConfig(
            enable_adaptive_thresholds=True,
            reputation_tau_multiplier=0.75,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        det = _safe_detector()
        agent = _make_agent(det, config=cfg)
        ip = "10.0.2.1"

        # Build up reputation manually
        with agent.ip_memory._lock:
            p = agent.ip_memory.get_profile(ip)
            p.attack_count = 8
            p.total_requests = 10
            p.reputation_score = 0.8   # > 0.5 → triggers adaptation

        agent.evaluate("test", source_ip=ip)

        # Adaptive triggers counter should have incremented
        assert agent._stats["adaptive_threshold_triggers"] >= 1

    def test_no_adaptation_for_clean_ip(self):
        """Clean IP (reputation=0) should NOT trigger threshold adaptation."""
        cfg = AgentConfig(
            enable_adaptive_thresholds=True,
            reputation_tau_multiplier=0.75,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        det = _safe_detector()
        agent = _make_agent(det, config=cfg)

        agent.evaluate("test", source_ip="99.0.0.1")

        assert agent._stats["adaptive_threshold_triggers"] == 0


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — Rule E: Field scanning
# ─────────────────────────────────────────────────────────────

class TestRuleE:
    """
    Rule E: Field scanning detection.

    NOTE: session_memory.update() is called AFTER _escalate_decision, so fields are
    registered after each call. The 3rd unique field becomes visible only in the
    session AFTER the 3rd request, meaning the 4th request sees 3 fields in window
    and triggers the escalation.
    """

    def test_three_fields_in_60s_escalates_safe_to_suspicious(self):
        """Rule E: After 3 unique fields recorded, 4th request escalates SAFE → SUSPICIOUS."""
        cfg = AgentConfig(
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_safe_detector(), config=cfg)
        ip = "10.0.3.1"
        sid = "sess-scan"

        # 3 different fields — each call records the field AFTER the decision
        agent.evaluate("test", source_ip=ip, session_id=sid, field_name="username")
        agent.evaluate("test", source_ip=ip, session_id=sid, field_name="password")
        agent.evaluate("test", source_ip=ip, session_id=sid, field_name="email")

        # 4th request — by now session has 3 fields within 60s → escalates
        r4 = agent.evaluate("test", source_ip=ip, session_id=sid, field_name="address")

        assert r4["agent_decision"] == "SUSPICIOUS", \
            f"Expected SUSPICIOUS (field scanning). Got {r4['agent_decision']}"
        assert r4["escalated"] is True

    def test_single_field_no_escalation(self):
        """Repeated same field → no field-scan escalation."""
        cfg = AgentConfig(
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_safe_detector(), config=cfg)
        ip = "10.0.3.2"
        sid = "sess-single"

        for _ in range(5):
            result = agent.evaluate("test", source_ip=ip, session_id=sid, field_name="username")

        assert result["agent_decision"] == "SAFE"


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — No-IP fallback
# ─────────────────────────────────────────────────────────────

class TestNoIPFallback:

    def test_none_ip_returns_pure_detector_result(self):
        """source_ip=None → no agent memory, base detector decision returned."""
        det = _injection_detector()
        agent = _make_agent(det)

        result = agent.evaluate("' OR 1=1--", source_ip=None)

        assert result["agent_decision"] == "INJECTION"
        assert result["ip_profile"] is None
        assert result["session_context"] is None
        assert result["agent_reason"] == "No IP context — pure detector mode"

    def test_unknown_ip_returns_pure_detector_result(self):
        """source_ip='unknown' → same fallback as None."""
        det = _safe_detector()
        agent = _make_agent(det)

        result = agent.evaluate("hello", source_ip="unknown")

        assert result["ip_profile"] is None
        assert result["escalated"] is False

    def test_no_ip_does_not_accumulate_memory(self):
        """Calls with source_ip=None must NOT create IP profiles."""
        agent = _make_agent(_injection_detector())
        for _ in range(10):
            agent.evaluate("attack", source_ip=None)

        assert len(agent.ip_memory._profiles) == 0


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — session_id=None auto-generates from IP
# ─────────────────────────────────────────────────────────────

class TestSessionIDNone:

    def test_none_session_id_uses_auto_key(self):
        """session_id=None → auto-{ip} key, memory is still tracked."""
        agent = _make_agent(_safe_detector())
        ip = "10.0.4.1"

        result = agent.evaluate("test", source_ip=ip, session_id=None)

        assert result["session_context"] is not None
        # auto key should exist
        with agent.session_memory._lock:
            assert f"auto-{ip}" in agent.session_memory._sessions

    def test_two_calls_same_auto_session(self):
        """Two calls with session_id=None same IP → same session accumulates."""
        agent = _make_agent(_safe_detector())
        ip = "10.0.4.2"

        agent.evaluate("test1", source_ip=ip, session_id=None, field_name="a")
        agent.evaluate("test2", source_ip=ip, session_id=None, field_name="b")

        with agent.session_memory._lock:
            ctx = agent.session_memory.get_or_create(f"auto-{ip}")
        assert len(ctx.fields_probed) == 2


# ─────────────────────────────────────────────────────────────
#  DecisionExplainer
# ─────────────────────────────────────────────────────────────

class TestDecisionExplainer:

    def _make_base_result(self, score=7.2, rule="RULE_1_HIGH_CONFIDENCE"):
        return {"score": score, "rule": rule}

    def test_explains_escalated(self):
        explainer = DecisionExplainer()
        base = self._make_base_result()
        ctx = {
            "escalated": True,
            "escalation_reason": "Auto-ban: 3 attacks in window",
            "adaptive_threshold_used": False,
            "reputation_score": 0.0,
            "predictive_probability": 0.0,
            "field_scanning_detected": False,
            "signature_hit": False,
        }
        reason_str, factors = explainer.explain(base, ctx)
        assert "Auto-ban: 3 attacks in window" in reason_str
        assert factors["escalation_reason"] == "Auto-ban: 3 attacks in window"

    def test_no_duplicate_ban_info(self):
        """Escalation reason should appear exactly once in the reason string."""
        explainer = DecisionExplainer()
        base = self._make_base_result()
        ctx = {
            "escalated": True,
            "escalation_reason": "Auto-ban: 3 attacks in window",
            "adaptive_threshold_used": False,
            "reputation_score": 0.0,
            "predictive_probability": 0.0,
            "field_scanning_detected": False,
            "signature_hit": False,
        }
        reason_str, _ = explainer.explain(base, ctx)
        assert reason_str.count("Auto-ban") == 1, f"Duplicate found in: {reason_str!r}"

    def test_contributing_factors_structure(self):
        """contributing_factors must contain all required keys."""
        explainer = DecisionExplainer()
        base = self._make_base_result(score=2.0, rule="RULE_4_SAFE")
        ctx = {
            "escalated": False,
            "escalation_reason": "",
            "adaptive_threshold_used": True,
            "reputation_score": 0.78,
            "predictive_probability": 0.85,
            "field_scanning_detected": True,
            "signature_hit": True,
            "signature_pattern": r"union\s+(all\s+)?select\s+",
        }
        reason_str, factors = explainer.explain(base, ctx)

        required_keys = [
            "detector_score", "detector_rule", "escalation_reason",
            "adaptive_threshold", "predictive_defense", "field_scanning", "signature_match"
        ]
        for k in required_keys:
            assert k in factors, f"Missing key in contributing_factors: {k}"

        assert factors["adaptive_threshold"]["used"] is True
        assert factors["adaptive_threshold"]["reputation"] == pytest.approx(0.78, abs=0.001)
        assert factors["predictive_defense"]["used"] is True
        assert factors["predictive_defense"]["probability"] == pytest.approx(0.85, abs=0.001)
        assert factors["field_scanning"] is True
        assert factors["signature_match"] is not None

    def test_no_escalation_has_none_reason(self):
        explainer = DecisionExplainer()
        base = self._make_base_result(score=0.5, rule="FAST_PATH_SAFE")
        ctx = {
            "escalated": False,
            "escalation_reason": "",
            "adaptive_threshold_used": False,
            "reputation_score": 0.0,
            "predictive_probability": 0.0,
            "field_scanning_detected": False,
            "signature_hit": False,
        }
        _, factors = explainer.explain(base, ctx)
        assert factors["escalation_reason"] is None


# ─────────────────────────────────────────────────────────────
#  AgentStore — SQLite persistence
# ─────────────────────────────────────────────────────────────

class TestAgentStore:
    """
    SQLite persistence tests.

    Windows note: SQLite holds file locks until the connection is explicitly closed.
    We use a temp directory and skip cleanup errors to avoid PermissionError on unlink.
    Tests use pytest's tmp_path fixture for automatic cleanup.
    """

    @pytest.fixture
    def db_path(self, tmp_path):
        """Provide a unique DB path in pytest's tmp_path (auto-cleaned)."""
        return str(tmp_path / "agent_test.db")

    def test_schema_created_on_init(self, db_path):
        store = AgentStore(db_path=db_path)
        import sqlite3
        conn = sqlite3.connect(db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        table_names = {r[0] for r in tables}
        assert "ip_profiles" in table_names
        assert "agent_meta" in table_names

    def test_flush_and_load(self, db_path):
        """Flush agent state to DB, load into new agent → profiles restored."""
        store = AgentStore(db_path=db_path)

        det = _injection_detector()
        agent = _make_agent(det)
        agent.store = store

        ip = "1.2.3.4"
        # 4 calls: 3 record attacks, 4th triggers autoban (threshold=3)
        for _ in range(4):
            agent.evaluate("attack", source_ip=ip)

        saved = store.flush(agent, min_attacks=1)
        assert saved >= 1

        det2 = _safe_detector()
        agent2 = _make_agent(det2)
        loaded = store.load_into(agent2)
        assert loaded >= 1

        with agent2.ip_memory._lock:
            p = agent2.ip_memory.get_profile(ip)
        assert p.attack_count >= 1

    def test_ban_survives_restart(self, db_path):
        """Active ban persisted to DB must be restored after 'restart'."""
        store = AgentStore(db_path=db_path)

        agent = _make_agent(_injection_detector())
        agent.store = store

        ip = "9.9.9.9"
        agent.ip_memory.ban(ip, duration_seconds=3600)

        store.flush(agent, min_attacks=0)

        # 'Restart': new store + new agent, load from DB
        store2 = AgentStore(db_path=db_path)
        agent2 = _make_agent(_safe_detector())
        store2.load_into(agent2)

        assert agent2.ip_memory.is_banned(ip), \
            "Ban should survive across simulated restart"

    def test_expired_ban_not_restored(self, db_path):
        """Expired bans should NOT be restored (loaded as not-banned)."""
        store = AgentStore(db_path=db_path)

        agent = _make_agent(_injection_detector())
        agent.store = store

        ip = "8.8.8.8"
        with agent.ip_memory._lock:
            p = agent.ip_memory.get_profile(ip)
            p.is_banned = True
            p.ban_until = time.time() - 1  # already expired
            p.attack_count = 2

        store.flush(agent, min_attacks=1)

        store2 = AgentStore(db_path=db_path)
        agent2 = _make_agent(_safe_detector())
        store2.load_into(agent2)

        assert not agent2.ip_memory.is_banned(ip), \
            "Expired ban should NOT be restored"

    def test_clean_ips_not_persisted_by_default(self, db_path):
        """IPs with 0 attacks should NOT be persisted (min_attacks=1 default)."""
        store = AgentStore(db_path=db_path)
        agent = _make_agent(_safe_detector())
        agent.store = store

        with agent.ip_memory._lock:
            p = agent.ip_memory.get_profile("clean-ip")
            p.total_requests = 100

        saved = store.flush(agent, min_attacks=1)
        assert saved == 0

    def test_flush_is_idempotent(self, db_path):
        """Flushing twice should not create duplicate rows."""
        store = AgentStore(db_path=db_path)
        det = _injection_detector()
        agent = _make_agent(det)
        agent.store = store

        agent.evaluate("attack", source_ip="1.1.1.1")

        store.flush(agent, min_attacks=1)
        store.flush(agent, min_attacks=1)

        import sqlite3
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM ip_profiles").fetchone()[0]
        conn.close()
        assert count == 1


# ─────────────────────────────────────────────────────────────
#  PredictiveDefense
# ─────────────────────────────────────────────────────────────

class TestPredictiveDefense:

    def _profile_with_rep(self, rep: float) -> IPProfile:
        p = IPProfile(ip="1.2.3.4")
        p.reputation_score = rep
        return p

    def _empty_session(self) -> SessionContext:
        return SessionContext(session_id="test")

    def test_clean_ip_low_probability(self):
        cfg = AgentConfig()
        pred = PredictiveDefense(cfg)
        p = self._profile_with_rep(0.0)
        s = self._empty_session()
        prob = pred.predict_attack_probability(p, s)
        assert prob < 0.1

    def test_high_reputation_raises_probability(self):
        cfg = AgentConfig()
        pred = PredictiveDefense(cfg)
        p = self._profile_with_rep(1.0)
        s = self._empty_session()
        prob = pred.predict_attack_probability(p, s)
        assert prob >= 0.3   # at least reputation component (0.3 * 1.0)

    def test_field_scanning_raises_probability(self):
        cfg = AgentConfig()
        pred = PredictiveDefense(cfg)
        p = self._profile_with_rep(0.0)
        s = self._empty_session()
        now = time.time()
        s.fields_probed = ["a", "b", "c"]
        s.field_probe_times = [now - 10, now - 5, now]   # all within 60s
        prob = pred.predict_attack_probability(p, s)
        assert prob >= 0.3

    def test_multiplier_returns_1_when_disabled(self):
        cfg = AgentConfig(enable_predictive_defense=False)
        pred = PredictiveDefense(cfg)
        assert pred.get_tau_multiplier(0.99) == 1.0

    def test_multiplier_below_threshold(self):
        cfg = AgentConfig(enable_predictive_defense=True, predictive_threshold=0.7, predictive_tau_boost=0.80)
        pred = PredictiveDefense(cfg)
        assert pred.get_tau_multiplier(0.5) == 1.0

    def test_multiplier_above_threshold(self):
        cfg = AgentConfig(enable_predictive_defense=True, predictive_threshold=0.7, predictive_tau_boost=0.80)
        pred = PredictiveDefense(cfg)
        assert pred.get_tau_multiplier(0.9) == pytest.approx(0.80)


# ─────────────────────────────────────────────────────────────
#  OnlineLearning (sklearn required)
# ─────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _SKLEARN_AVAILABLE, reason="sklearn not installed")
class TestOnlineLearning:

    def test_seed_signatures_present(self):
        cfg = AgentConfig(enable_online_learning=True)
        ol = OnlineLearning(cfg)
        assert len(ol.signature_db) >= 10

    def test_signature_check_matches_sqli(self):
        cfg = AgentConfig(enable_online_learning=True)
        ol = OnlineLearning(cfg)
        matched, _ = ol.check_signatures("' OR 1=1")
        assert matched

    def test_signature_check_no_match_safe(self):
        cfg = AgentConfig(enable_online_learning=True)
        ol = OnlineLearning(cfg)
        matched, _ = ol.check_signatures("hello world this is safe")
        assert not matched

    def test_false_positive_suppresses_pattern(self):
        cfg = AgentConfig(enable_online_learning=True)
        ol = OnlineLearning(cfg)
        # Get first signature key
        first_sig = ol.signature_db[0][0]
        initial_weight = ol.pattern_weights[first_sig]

        ol.learn_from_false_positive("some text", matched_pattern=first_sig)

        assert ol.pattern_weights[first_sig] < initial_weight

    def test_thread_safety_concurrent_learns(self):
        cfg = AgentConfig(enable_online_learning=True, incremental_fit_batch_size=20)
        ol = OnlineLearning(cfg)
        profile = IPProfile(ip="1.1.1.1", attack_count=5)
        errors = []

        def worker():
            try:
                for _ in range(10):
                    ol.learn_from_blocked_attack("' OR 1=1--", profile)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"


# ─────────────────────────────────────────────────────────────
#  SQLiAgent — get_stats / get_ip_report
# ─────────────────────────────────────────────────────────────

class TestAgentPublicAPI:

    def test_get_stats_structure(self):
        agent = _make_agent()
        stats = agent.get_stats()
        assert "total_evaluated" in stats
        assert "auto_bans" in stats
        assert "memory" in stats
        assert "active_bans" in stats["memory"]
        assert "tracked_ips" in stats["memory"]
        assert "persistence" in stats

    def test_get_ip_report_unknown_ip(self):
        """get_ip_report creates a new profile if IP is unknown — should not raise."""
        agent = _make_agent()
        report = agent.get_ip_report("255.255.255.255")
        assert report["ip"] == "255.255.255.255"
        assert report["attack_count"] == 0

    def test_total_evaluated_counter(self):
        agent = _make_agent(_safe_detector())
        assert agent._stats["total_evaluated"] == 0

        agent.evaluate("test", source_ip="1.2.3.4")
        agent.evaluate("test", source_ip="1.2.3.4")

        assert agent._stats["total_evaluated"] == 2

    def test_learn_false_positive_api(self):
        """learn_false_positive() is a no-op when sklearn is unavailable, no crash."""
        agent = _make_agent()
        # Should not raise regardless of sklearn availability
        agent.learn_false_positive("some text", matched_pattern="test-pattern")

    def test_evaluate_returns_contributing_factors(self):
        """evaluate() must always return contributing_factors dict."""
        agent = _make_agent(_safe_detector())
        result = agent.evaluate("hello", source_ip="1.2.3.4")
        assert "contributing_factors" in result
        assert isinstance(result["contributing_factors"], dict)
        assert "detector_score" in result["contributing_factors"]

    def test_no_ip_evaluate_returns_contributing_factors(self):
        """No-IP fallback must also include contributing_factors."""
        agent = _make_agent(_safe_detector())
        result = agent.evaluate("hello", source_ip=None)
        assert "contributing_factors" in result
        assert result["contributing_factors"]["adaptive_threshold"]["used"] is False


# ─────────────────────────────────────────────────────────────
#  Concurrent evaluate() stress test
# ─────────────────────────────────────────────────────────────

class TestConcurrentEvaluate:

    def test_concurrent_different_ips(self):
        """
        Stress test: 8 threads × 20 calls each, different IPs.
        No exceptions should occur.
        """
        det = _injection_detector()
        cfg = AgentConfig(
            ip_attack_threshold=50,   # high threshold — avoid banning during test
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = SQLiAgent(det, config=cfg)
        errors = []

        def worker(thread_id: int):
            try:
                ip = f"10.{thread_id}.0.1"
                for _ in range(20):
                    result = agent.evaluate("' OR 1=1--", source_ip=ip)
                    assert "agent_decision" in result
            except Exception as e:
                errors.append((thread_id, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent errors: {errors}"
        assert len(agent.ip_memory._profiles) == 8  # one profile per thread

    def test_concurrent_same_ip_no_corruption(self):
        """
        Stress test: 8 threads hitting same IP concurrently.
        attack_count must be exactly 8 × 20 = 160 at the end.
        """
        det = _injection_detector()
        cfg = AgentConfig(
            ip_attack_threshold=1000,   # prevent auto-ban during test
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = SQLiAgent(det, config=cfg)
        errors = []

        def worker():
            try:
                for _ in range(20):
                    agent.evaluate("' OR 1=1--", source_ip="1.2.3.4")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrent errors: {errors}"

        with agent.ip_memory._lock:
            p = agent.ip_memory.get_profile("1.2.3.4")
        # Each call increments total_requests; each INJECTION result increments attack_count
        assert p.total_requests == 160
        assert p.attack_count == 160


# ─────────────────────────────────────────────────────────────
#  Edge case: max_tracked_ips (anti-DoS)
# ─────────────────────────────────────────────────────────────

class TestMaxTrackedIPs:

    def test_does_not_crash_above_max_ips(self):
        """
        With max_ips=5 and 10 unique IPs, agent must not crash.
        (Overflow protection relies on cleanup_stale; agent does not enforce it per-request.)
        """
        cfg = AgentConfig(
            max_tracked_ips=5,
            enable_adaptive_thresholds=False,
            enable_predictive_defense=False,
            enable_online_learning=False,
        )
        agent = _make_agent(_safe_detector(), config=cfg)

        for i in range(10):
            try:
                agent.evaluate("test", source_ip=f"192.168.1.{i}")
            except Exception as e:
                pytest.fail(f"Agent crashed with max_ips overflow: {e}")


if __name__ == "__main__":
    # Run with: py -3 test_agent.py
    import pytest as _pytest
    raise SystemExit(_pytest.main([__file__, "-v", "--tb=short"]))
