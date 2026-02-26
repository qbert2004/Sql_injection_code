"""
Tests for StateBackend abstraction — state_backend.py
======================================================
Covers:
  A. Protocol conformance — SQLiteBackend, NullBackend, RedisBackend (mock)
  B. SQLiteBackend functional — round-trip persist/restore
  C. NullBackend — no-op behaviour
  D. Factory (make_backend) — correct backend chosen per env var
  E. Backward-compat — AgentStore alias still works
  F. RedisBackend unit — tested via fakeredis (skipped if not installed)
  G. config.BackendConfig — parsed from env vars
"""

import importlib
import os
import sqlite3
import tempfile
import time
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from state_backend import (
    NullBackend,
    SQLiteBackend,
    StateBackend,
    make_backend,
)


# ═══════════════════════════════════════════════════════════════
#  Minimal Agent/IPProfile stubs (no real ML needed for backend tests)
# ═══════════════════════════════════════════════════════════════

@dataclass
class _FakeIPProfile:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)
    total_requests: int = 0
    attack_count: int = 0
    suspicious_count: int = 0
    attack_types: Counter = field(default_factory=Counter)
    endpoints_targeted: set = field(default_factory=set)
    fields_targeted: set = field(default_factory=set)
    is_banned: bool = False
    ban_until: float | None = None
    reputation_score: float = 0.0


class _FakeIPMemory:
    def __init__(self):
        self._profiles: dict[str, _FakeIPProfile] = {}
        self._lock = threading.RLock()

    def get_profile(self, ip: str) -> _FakeIPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = _FakeIPProfile(ip=ip)
        return self._profiles[ip]


@dataclass
class _FakeOnlineLearner:
    _enabled: bool = False
    _is_fitted: bool = False
    _clf: Any = None
    _vectorizer: Any = None
    _lock: threading.Lock = field(default_factory=threading.Lock)


class _FakeAgent:
    def __init__(self):
        self.ip_memory     = _FakeIPMemory()
        self.online_learner = _FakeOnlineLearner(
            _enabled=False, _is_fitted=False
        )
        self.config = MagicMock()
        self.config.sgd_model_path = "test_agent_sgd.joblib"


def _make_agent_with_profile(ip: str, **kwargs) -> _FakeAgent:
    agent = _FakeAgent()
    p = agent.ip_memory.get_profile(ip)
    for k, v in kwargs.items():
        setattr(p, k, v)
    return agent


# ═══════════════════════════════════════════════════════════════
#  A. Protocol conformance
# ═══════════════════════════════════════════════════════════════

class TestProtocolConformance:
    """Both concrete backends must satisfy the StateBackend Protocol."""

    def test_null_backend_is_state_backend(self):
        assert isinstance(NullBackend(), StateBackend)

    def test_sqlite_backend_is_state_backend(self, tmp_path):
        db = str(tmp_path / "test.db")
        assert isinstance(SQLiteBackend(db), StateBackend)

    def test_sqlite_has_all_protocol_methods(self, tmp_path):
        db = str(tmp_path / "test.db")
        b  = SQLiteBackend(db)
        for method in ("load_profiles", "flush_profiles", "load_sgd", "save_sgd", "ping", "close"):
            assert callable(getattr(b, method)), f"Missing method: {method}"

    def test_null_has_all_protocol_methods(self):
        b = NullBackend()
        for method in ("load_profiles", "flush_profiles", "load_sgd", "save_sgd", "ping", "close"):
            assert callable(getattr(b, method)), f"Missing method: {method}"


# ═══════════════════════════════════════════════════════════════
#  B. SQLiteBackend functional
# ═══════════════════════════════════════════════════════════════

class TestSQLiteBackend:

    def test_ping_returns_true(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / "test.db"))
        assert b.ping() is True

    def test_creates_schema_on_init(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        SQLiteBackend(db_path)
        conn = sqlite3.connect(db_path)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        assert "ip_profiles" in tables
        assert "agent_meta" in tables

    def test_flush_and_load_round_trip(self, tmp_path):
        """Persist a profile then restore it in a fresh agent."""
        db_path = str(tmp_path / "test.db")
        backend = SQLiteBackend(db_path)
        agent_a = _make_agent_with_profile(
            "1.2.3.4",
            attack_count=5,
            suspicious_count=2,
            reputation_score=0.8,
            attack_types=Counter({"UNION_BASED": 3, "BOOLEAN_BASED": 2}),
            endpoints_targeted={"/api/login", "/api/users"},
            fields_targeted={"username", "password"},
            is_banned=False,
        )
        n_saved = backend.flush_profiles(agent_a)
        assert n_saved == 1

        # Restore into a fresh agent
        agent_b = _FakeAgent()
        n_loaded = backend.load_profiles(agent_b)
        assert n_loaded == 1

        p = agent_b.ip_memory.get_profile("1.2.3.4")
        assert p.attack_count == 5
        assert p.suspicious_count == 2
        assert abs(p.reputation_score - 0.8) < 1e-9
        assert p.attack_types["UNION_BASED"] == 3
        assert "/api/login" in p.endpoints_targeted
        assert "username" in p.fields_targeted

    def test_min_attacks_filter(self, tmp_path):
        """Profiles with attack_count=0 are not persisted."""
        db_path = str(tmp_path / "test.db")
        backend = SQLiteBackend(db_path)
        agent   = _make_agent_with_profile("10.0.0.1", attack_count=0, is_banned=False)
        n = backend.flush_profiles(agent, min_attacks=1)
        assert n == 0

        # load should also return 0
        fresh = _FakeAgent()
        assert backend.load_profiles(fresh) == 0

    def test_banned_ip_persisted_even_with_zero_attacks(self, tmp_path):
        """Banned IPs are always persisted regardless of attack_count."""
        db_path = str(tmp_path / "test.db")
        backend = SQLiteBackend(db_path)
        future  = time.time() + 3600
        agent   = _make_agent_with_profile("9.9.9.9", attack_count=0, is_banned=True, ban_until=future)
        n = backend.flush_profiles(agent)
        assert n == 1

        fresh = _FakeAgent()
        backend.load_profiles(fresh)
        p = fresh.ip_memory.get_profile("9.9.9.9")
        assert p.is_banned is True

    def test_expired_ban_cleared_on_load(self, tmp_path):
        """Bans that have expired are not restored."""
        db_path = str(tmp_path / "test.db")
        backend = SQLiteBackend(db_path)
        past    = time.time() - 1  # already expired
        agent   = _make_agent_with_profile("5.5.5.5", attack_count=1,
                                           is_banned=True, ban_until=past)
        backend.flush_profiles(agent)

        fresh = _FakeAgent()
        backend.load_profiles(fresh)
        p = fresh.ip_memory.get_profile("5.5.5.5")
        assert p.is_banned is False
        assert p.ban_until is None

    def test_upsert_updates_existing_profile(self, tmp_path):
        """Second flush updates the row, not duplicates it."""
        db_path = str(tmp_path / "test.db")
        backend = SQLiteBackend(db_path)
        agent   = _make_agent_with_profile("2.2.2.2", attack_count=1)
        backend.flush_profiles(agent)

        agent.ip_memory.get_profile("2.2.2.2").attack_count = 10
        backend.flush_profiles(agent)

        fresh = _FakeAgent()
        backend.load_profiles(fresh)
        assert fresh.ip_memory.get_profile("2.2.2.2").attack_count == 10

        # Only one row
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM ip_profiles WHERE ip='2.2.2.2'").fetchone()[0]
        conn.close()
        assert count == 1

    def test_close_is_no_op(self, tmp_path):
        b = SQLiteBackend(str(tmp_path / "test.db"))
        b.close()  # Should not raise

    def test_concurrent_flush_serialized(self, tmp_path):
        """Concurrent flush calls must not corrupt data (uses _flush_lock)."""
        db_path = str(tmp_path / "conc.db")
        backend = SQLiteBackend(db_path)
        agents  = [_make_agent_with_profile(f"10.0.0.{i}", attack_count=i + 1)
                   for i in range(5)]

        errors = []
        def _flush(a):
            try:
                backend.flush_profiles(a)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_flush, args=(a,)) for a in agents]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors, f"Concurrent flush raised: {errors}"

    # ── Backward-compat aliases ───────────────────────────────

    def test_load_into_alias_works(self, tmp_path):
        db_path = str(tmp_path / "compat.db")
        backend = SQLiteBackend(db_path)
        agent_a = _make_agent_with_profile("7.7.7.7", attack_count=3)
        backend.flush(agent_a, save_sgd=False)

        agent_b = _FakeAgent()
        n = backend.load_into(agent_b, load_sgd=False)
        assert n == 1
        assert agent_b.ip_memory.get_profile("7.7.7.7").attack_count == 3


# ═══════════════════════════════════════════════════════════════
#  C. NullBackend
# ═══════════════════════════════════════════════════════════════

class TestNullBackend:

    def test_load_always_zero(self):
        assert NullBackend().load_profiles(_FakeAgent()) == 0

    def test_flush_always_zero(self):
        agent = _make_agent_with_profile("1.1.1.1", attack_count=10)
        assert NullBackend().flush_profiles(agent) == 0

    def test_ping_always_true(self):
        assert NullBackend().ping() is True

    def test_close_no_raise(self):
        NullBackend().close()

    def test_load_sgd_false(self):
        assert NullBackend().load_sgd(_FakeAgent()) is False

    def test_save_sgd_false(self):
        assert NullBackend().save_sgd(_FakeAgent()) is False

    def test_compat_aliases_work(self):
        b = NullBackend()
        agent = _make_agent_with_profile("x.x.x.x", attack_count=5)
        assert b.load_into(agent) == 0
        assert b.flush(agent) == 0


# ═══════════════════════════════════════════════════════════════
#  D. make_backend factory
# ═══════════════════════════════════════════════════════════════

class TestMakeBackend:

    def test_default_is_sqlite(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SQLI_BACKEND", raising=False)
        b = make_backend(sqlite_path=str(tmp_path / "x.db"))
        assert isinstance(b, SQLiteBackend)

    def test_explicit_sqlite(self, tmp_path):
        b = make_backend(backend_type="sqlite", sqlite_path=str(tmp_path / "x.db"))
        assert isinstance(b, SQLiteBackend)

    def test_explicit_null(self):
        b = make_backend(backend_type="null")
        assert isinstance(b, NullBackend)

    def test_env_var_null(self, monkeypatch):
        monkeypatch.setenv("SQLI_BACKEND", "null")
        b = make_backend()
        assert isinstance(b, NullBackend)

    def test_redis_fallback_when_not_installed(self, monkeypatch, tmp_path):
        """If redis-py not available, make_backend falls back to SQLite."""
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        # Simulate redis-py not installed
        with patch("state_backend.RedisBackend.from_env", side_effect=ImportError("no redis")):
            b = make_backend(sqlite_path=str(tmp_path / "fallback.db"))
        assert isinstance(b, SQLiteBackend)

    def test_redis_fallback_on_connection_error(self, monkeypatch, tmp_path):
        """If Redis is unreachable, make_backend falls back to SQLite."""
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        with patch("state_backend.RedisBackend.from_env", side_effect=Exception("Connection refused")):
            b = make_backend(sqlite_path=str(tmp_path / "fallback.db"))
        assert isinstance(b, SQLiteBackend)


# ═══════════════════════════════════════════════════════════════
#  E. Backward-compat: AgentStore alias
# ═══════════════════════════════════════════════════════════════

class TestAgentStoreAlias:

    def test_import_from_agent(self):
        """from agent import AgentStore must still work."""
        from agent import AgentStore
        assert AgentStore is not None

    def test_agent_store_is_sqlite_backend(self, tmp_path):
        from agent import AgentStore
        store = AgentStore(str(tmp_path / "compat.db"))
        assert isinstance(store, SQLiteBackend)

    def test_agent_store_load_into_flush(self, tmp_path):
        """Old API: store.load_into(agent) / store.flush(agent) still works."""
        from agent import AgentStore
        store   = AgentStore(str(tmp_path / "compat.db"))
        agent_a = _make_agent_with_profile("3.3.3.3", attack_count=2)
        store.flush(agent_a, save_sgd=False)

        agent_b = _FakeAgent()
        n = store.load_into(agent_b, load_sgd=False)
        assert n == 1
        assert agent_b.ip_memory.get_profile("3.3.3.3").attack_count == 2

    def test_import_from_state_backend(self):
        from state_backend import AgentStore, SQLiteBackend
        assert AgentStore is SQLiteBackend


# ═══════════════════════════════════════════════════════════════
#  F. RedisBackend unit (fakeredis — skipped if not installed)
# ═══════════════════════════════════════════════════════════════

try:
    import fakeredis
    _FAKEREDIS = True
except ImportError:
    _FAKEREDIS = False


@pytest.mark.skipif(not _FAKEREDIS, reason="fakeredis not installed (pip install fakeredis)")
class TestRedisBackend:
    """
    Tests RedisBackend using fakeredis — no real Redis required.
    """

    def _make_backend(self):
        from state_backend import RedisBackend
        client = fakeredis.FakeRedis(decode_responses=True)
        return RedisBackend(client, ttl_seconds=3600)

    def test_ping(self):
        b = self._make_backend()
        assert b.ping() is True

    def test_flush_and_load_round_trip(self):
        from state_backend import RedisBackend
        b = self._make_backend()
        agent_a = _make_agent_with_profile(
            "4.4.4.4",
            attack_count=3,
            reputation_score=0.6,
            attack_types=Counter({"UNION_BASED": 2}),
            endpoints_targeted={"/login"},
            is_banned=False,
        )
        n = b.flush_profiles(agent_a)
        assert n == 1

        agent_b = _FakeAgent()
        n2 = b.load_profiles(agent_b)
        assert n2 == 1

        p = agent_b.ip_memory.get_profile("4.4.4.4")
        assert p.attack_count == 3
        assert abs(p.reputation_score - 0.6) < 1e-6
        assert "/login" in p.endpoints_targeted

    def test_clean_ip_not_written(self):
        b = self._make_backend()
        agent = _make_agent_with_profile("6.6.6.6", attack_count=0, is_banned=False)
        n = b.flush_profiles(agent, min_attacks=1)
        assert n == 0

        fresh = _FakeAgent()
        assert b.load_profiles(fresh) == 0

    def test_multiple_ips(self):
        b = self._make_backend()
        for i in range(5):
            agent = _make_agent_with_profile(f"10.0.1.{i}", attack_count=i + 1)
            b.flush_profiles(agent)

        fresh = _FakeAgent()
        n = b.load_profiles(fresh)
        assert n == 5

    def test_ping_after_close(self):
        b = self._make_backend()
        b.close()
        # After close ping should return False (connection closed)
        # fakeredis may not raise, so just assert it does not crash
        result = b.ping()
        assert isinstance(result, bool)

    def test_conforms_to_protocol(self):
        b = self._make_backend()
        assert isinstance(b, StateBackend)


# ═══════════════════════════════════════════════════════════════
#  G. config.BackendConfig
# ═══════════════════════════════════════════════════════════════

class TestBackendConfig:

    def test_default_backend_is_sqlite(self, monkeypatch):
        monkeypatch.delenv("SQLI_BACKEND", raising=False)
        from config import get_config
        cfg = get_config()
        assert cfg.backend.backend_type == "sqlite"

    def test_redis_backend_from_env(self, monkeypatch):
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        monkeypatch.setenv("REDIS_URL", "redis://redis:6379/0")
        from config import get_config
        cfg = get_config()
        assert cfg.backend.backend_type == "redis"
        assert cfg.backend.redis_url == "redis://redis:6379/0"

    def test_null_backend_from_env(self, monkeypatch):
        monkeypatch.setenv("SQLI_BACKEND", "null")
        from config import get_config
        cfg = get_config()
        assert cfg.backend.backend_type == "null"

    def test_redis_ttl_from_env(self, monkeypatch):
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        monkeypatch.setenv("REDIS_TTL_DAYS", "14")
        from config import get_config
        cfg = get_config()
        assert cfg.backend.redis_ttl_days == 14

    def test_sqlite_path_from_env(self, monkeypatch):
        monkeypatch.setenv("AGENT_STATE_DB", "/tmp/custom.db")
        from config import get_config
        cfg = get_config()
        assert cfg.backend.sqlite_path == "/tmp/custom.db"
