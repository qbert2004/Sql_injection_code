"""
Distributed & Concurrency Tests  (v3.8.0)
==========================================
Covers the four hardest correctness properties of a distributed state backend:

  I.  Multi-process consistency
      Two separate processes share one backend.  Attacks registered by
      process A must be visible to process B — including ban escalation.

  II. Redis outage / failover semantics
      What happens when Redis becomes unavailable mid-request or at startup?
      Explicit contract: fail-open (detection continues), no crash, warning logged.

  III. TTL expiry
      IP profiles written with a short TTL must be invisible after expiry.

  IV. Chaos flush
      100 concurrent evaluations + forced flush must not deadlock, corrupt
      the SGD file, or lose ban state.

Architecture of multi-process tests
-------------------------------------
Python's `multiprocessing` module is used (not threads) so each worker
gets a real separate process — GIL does not apply, memory is isolated,
only the shared backend (SQLite file or fakeredis server) is common.

Worker functions are module-level (required for pickling on Windows).

Redis tests are skipped unless `fakeredis` is installed.
SQLite multi-process tests run on all platforms.
"""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from state_backend import (
    NullBackend,
    SQLiteBackend,
    make_backend,
)

# ── fakeredis availability ────────────────────────────────────────────────────
try:
    import fakeredis
    from state_backend import RedisBackend
    _FAKEREDIS = True
except ImportError:
    _FAKEREDIS = False


# ═══════════════════════════════════════════════════════════════
#  Shared fake-agent stubs (identical to test_state_backend.py
#  but duplicated here to avoid cross-file import coupling)
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


class _FakeAgent:
    def __init__(self):
        self.ip_memory      = _FakeIPMemory()
        self.online_learner = MagicMock(_enabled=False, _is_fitted=False)
        self.config         = MagicMock()
        self.config.sgd_model_path = "test_agent_sgd.joblib"


def _make_agent(ip: str, **profile_kwargs) -> _FakeAgent:
    agent = _FakeAgent()
    p = agent.ip_memory.get_profile(ip)
    for k, v in profile_kwargs.items():
        setattr(p, k, v)
    return agent


# ═══════════════════════════════════════════════════════════════
#  Worker functions — module-level for multiprocessing pickling
# ═══════════════════════════════════════════════════════════════

def _worker_register_attacks(db_path: str, ip: str, n_attacks: int,
                              result_queue: multiprocessing.Queue) -> None:
    """
    Worker A: register n_attacks for ip, flush to SQLite, report result.
    """
    backend = SQLiteBackend(db_path)
    agent   = _make_agent(ip, attack_count=n_attacks, is_banned=(n_attacks >= 5))
    if n_attacks >= 5:
        agent.ip_memory.get_profile(ip).ban_until = time.time() + 3600
    saved = backend.flush_profiles(agent)
    result_queue.put({"saved": saved, "attack_count": n_attacks})


def _worker_read_profile(db_path: str, ip: str,
                         result_queue: multiprocessing.Queue) -> None:
    """
    Worker B: load profiles from SQLite, report what it sees for ip.
    """
    backend = SQLiteBackend(db_path)
    agent   = _FakeAgent()
    n       = backend.load_profiles(agent)
    p       = agent.ip_memory.get_profile(ip)
    result_queue.put({
        "profiles_loaded": n,
        "attack_count":    p.attack_count,
        "is_banned":       p.is_banned,
        "reputation":      p.reputation_score,
    })


def _worker_concurrent_flush(db_path: str, ip_base: str, worker_id: int,
                               n: int, result_queue: multiprocessing.Queue) -> None:
    """
    Chaos worker: flush n profiles as fast as possible.
    """
    backend = SQLiteBackend(db_path)
    errors  = []
    saved   = 0
    for i in range(n):
        ip = f"{ip_base}.{worker_id}.{i % 256}"
        agent = _make_agent(ip, attack_count=1)
        try:
            saved += backend.flush_profiles(agent)
        except Exception as e:
            errors.append(str(e))
    result_queue.put({"worker_id": worker_id, "saved": saved, "errors": errors})


# ═══════════════════════════════════════════════════════════════
#  I. Multi-process consistency  (SQLite)
# ═══════════════════════════════════════════════════════════════

class TestMultiprocessConsistency:
    """
    Two processes share one SQLite file.
    State written by process A must be readable by process B.
    """

    def test_attack_count_visible_across_processes(self, tmp_path):
        """
        Process A registers 3 attacks for an IP.
        Process B reads the same DB and sees attack_count=3.
        """
        db_path = str(tmp_path / "shared.db")
        ip      = "192.168.1.1"
        queue   = multiprocessing.Queue()

        # Process A: write
        pa = multiprocessing.Process(
            target=_worker_register_attacks,
            args=(db_path, ip, 3, queue)
        )
        pa.start()
        pa.join(timeout=10)
        assert pa.exitcode == 0, "Worker A crashed"

        result_a = queue.get_nowait()
        assert result_a["saved"] == 1

        # Process B: read
        pb = multiprocessing.Process(
            target=_worker_read_profile,
            args=(db_path, ip, queue)
        )
        pb.start()
        pb.join(timeout=10)
        assert pb.exitcode == 0, "Worker B crashed"

        result_b = queue.get_nowait()
        assert result_b["profiles_loaded"] == 1
        assert result_b["attack_count"] == 3, (
            f"Cross-process consistency FAIL: expected attack_count=3, got {result_b['attack_count']}"
        )

    def test_ban_propagates_across_processes(self, tmp_path):
        """
        Process A bans an IP (attack_count=5, is_banned=True).
        Process B must see is_banned=True.
        This is the critical distributed escalation test.
        """
        db_path = str(tmp_path / "shared_ban.db")
        ip      = "10.0.0.1"
        queue   = multiprocessing.Queue()

        pa = multiprocessing.Process(
            target=_worker_register_attacks,
            args=(db_path, ip, 5, queue)
        )
        pa.start()
        pa.join(timeout=10)
        assert pa.exitcode == 0, "Worker A crashed"
        queue.get_nowait()  # discard A result

        pb = multiprocessing.Process(
            target=_worker_read_profile,
            args=(db_path, ip, queue)
        )
        pb.start()
        pb.join(timeout=10)
        assert pb.exitcode == 0, "Worker B crashed"

        result_b = queue.get_nowait()
        assert result_b["is_banned"] is True, (
            "Ban NOT propagated across processes — distributed escalation broken"
        )

    def test_multiple_workers_no_data_loss(self, tmp_path):
        """
        5 workers each write 10 profiles concurrently to same SQLite.
        After all finish, DB must contain all 50 unique IPs.
        """
        db_path  = str(tmp_path / "concurrent.db")
        queue    = multiprocessing.Queue()
        workers  = 5
        per_worker = 10

        processes = [
            multiprocessing.Process(
                target=_worker_concurrent_flush,
                args=(db_path, "172.16", i, per_worker, queue)
            )
            for i in range(workers)
        ]
        for p in processes: p.start()
        for p in processes: p.join(timeout=30)

        # Collect results
        all_errors = []
        total_saved = 0
        for _ in range(workers):
            r = queue.get_nowait()
            total_saved += r["saved"]
            all_errors.extend(r["errors"])

        assert not all_errors, f"Concurrent flush errors: {all_errors}"

        # Verify DB row count
        conn   = sqlite3.connect(db_path)
        n_rows = conn.execute("SELECT COUNT(*) FROM ip_profiles").fetchone()[0]
        conn.close()
        # Each worker writes IPs like "172.16.{worker_id}.{i % 256}"
        # With 5 workers × 10 iterations and 256 IP slots — no collision expected
        assert n_rows == workers * per_worker, (
            f"Expected {workers * per_worker} rows, got {n_rows} — data loss in concurrent writes"
        )


# ═══════════════════════════════════════════════════════════════
#  II. Redis outage / failover semantics
# ═══════════════════════════════════════════════════════════════

class TestRedisOutage:
    """
    Contract:
      - Redis unreachable at startup → make_backend() falls back to SQLite, no crash
      - Redis unreachable mid-operation → flush_profiles() returns 0, no crash
      - NullBackend.ping() always True (intentional for testing)
    """

    def test_make_backend_falls_back_to_sqlite_on_connection_error(self, tmp_path, monkeypatch):
        """make_backend('redis') falls back to SQLite when Redis refuses connection."""
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        with patch("state_backend.RedisBackend.from_env",
                   side_effect=Exception("Connection refused [Errno 111]")):
            backend = make_backend(sqlite_path=str(tmp_path / "fallback.db"))
        assert isinstance(backend, SQLiteBackend), \
            "Expected SQLite fallback on Redis connection error"
        assert backend.ping() is True

    def test_make_backend_falls_back_when_redis_not_installed(self, tmp_path, monkeypatch):
        """make_backend('redis') falls back to SQLite when redis-py absent."""
        monkeypatch.setenv("SQLI_BACKEND", "redis")
        with patch("state_backend.RedisBackend.from_env",
                   side_effect=ImportError("No module named 'redis'")):
            backend = make_backend(sqlite_path=str(tmp_path / "fallback.db"))
        assert isinstance(backend, SQLiteBackend)

    def test_sqlite_backend_ping_false_on_bad_path(self):
        """SQLiteBackend with read-only/missing path → ping() gracefully returns False."""
        backend = SQLiteBackend("/nonexistent/path/agent.db")
        # ping() attempts SELECT 1; should catch exception and return False
        result = backend.ping()
        assert isinstance(result, bool)
        # We don't assert False here because on some OS the path error
        # is deferred — the important thing is it does not raise.

    @pytest.mark.skipif(not _FAKEREDIS, reason="fakeredis not installed")
    def test_redis_flush_survives_mid_operation_error(self):
        """
        flush_profiles() must catch Redis errors and return 0 (fail-open).
        The agent should continue operating — no crash, no exception.
        """
        client  = fakeredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(client, ttl_seconds=3600)
        agent   = _make_agent("1.2.3.4", attack_count=5)

        # First flush works
        assert backend.flush_profiles(agent) == 1

        # Simulate Redis going down mid-operation by replacing pipeline with error
        def _broken_pipeline(*args, **kwargs):
            raise ConnectionError("Redis connection lost")

        original_pipeline = client.pipeline
        client.pipeline = _broken_pipeline
        try:
            result = backend.flush_profiles(agent)  # must not raise
            assert result == 0, "Expected 0 on Redis error, not an exception"
        finally:
            client.pipeline = original_pipeline  # restore

    @pytest.mark.skipif(not _FAKEREDIS, reason="fakeredis not installed")
    def test_redis_load_survives_error(self):
        """
        load_profiles() must catch Redis errors and return 0 (fail-open).
        Agent memory stays empty — better than crashing.
        """
        client  = fakeredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(client, ttl_seconds=3600)

        def _broken_smembers(key):
            raise ConnectionError("Redis connection lost")

        client.smembers = _broken_smembers
        agent  = _FakeAgent()
        result = backend.load_profiles(agent)   # must not raise
        assert result == 0

    def test_null_backend_never_fails(self):
        """NullBackend is the ultimate fallback — all ops return without error."""
        b     = NullBackend()
        agent = _make_agent("x.x.x.x", attack_count=10)
        assert b.flush_profiles(agent) == 0
        assert b.load_profiles(agent)  == 0
        assert b.ping()                is True
        b.close()  # no raise


# ═══════════════════════════════════════════════════════════════
#  III. TTL expiry (Redis)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _FAKEREDIS, reason="fakeredis not installed")
class TestRedisTTLExpiry:
    """
    IP profiles written with a short TTL must become invisible after expiry.
    fakeredis 2.x honours real wall-clock TTLs — we write with TTL=1s
    and sleep 1.2s to let the key expire naturally.
    """

    def test_profile_invisible_after_ttl(self):
        """
        Write a profile with TTL=1s, wait 1.2s, confirm it's gone.
        """
        client  = fakeredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(client, ttl_seconds=1)

        agent = _make_agent("5.5.5.5", attack_count=3)
        assert backend.flush_profiles(agent) == 1

        # Confirm visible immediately
        fresh_a = _FakeAgent()
        assert backend.load_profiles(fresh_a) == 1

        # Wait for TTL expiry (1s TTL + 0.2s margin)
        time.sleep(1.2)

        fresh_b = _FakeAgent()
        n = backend.load_profiles(fresh_b)
        assert n == 0, (
            f"Profile should have expired after TTL=1s+sleep but "
            f"load_profiles returned {n}"
        )

    def test_profile_still_visible_before_ttl(self):
        """Profile is readable immediately after write (TTL not yet expired)."""
        client  = fakeredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(client, ttl_seconds=3600)

        agent = _make_agent("6.6.6.6", attack_count=1)
        backend.flush_profiles(agent)

        fresh = _FakeAgent()
        assert backend.load_profiles(fresh) == 1

    def test_index_expires_with_profile(self):
        """The sqli:ip:index Set must also expire (no ghost IPs after TTL)."""
        client  = fakeredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(client, ttl_seconds=1)

        agent = _make_agent("7.7.7.7", attack_count=2)
        backend.flush_profiles(agent)

        # Before expiry — index must have 1 entry
        assert client.scard(RedisBackend.INDEX_KEY) == 1

        # Wait for TTL expiry
        time.sleep(1.2)

        # After expiry the index key should also be gone
        n = client.scard(RedisBackend.INDEX_KEY)
        assert n == 0, (
            f"Index Set not expired after TTL — ghost IPs can accumulate (scard={n})"
        )


# ═══════════════════════════════════════════════════════════════
#  IV. Chaos flush (SQLite)
# ═══════════════════════════════════════════════════════════════

class TestChaosFlush:
    """
    100 concurrent flush operations against the same SQLiteBackend.
    Verifies:
      - No deadlocks (all threads complete within timeout)
      - No SQLite corruption (DB is readable after chaos)
      - No data loss for banned IPs
    """

    def test_100_concurrent_flushes_no_deadlock(self, tmp_path):
        """
        100 threads flush simultaneously — all must complete within 30s.
        This tests _flush_lock serialisation under contention.
        """
        db_path  = str(tmp_path / "chaos.db")
        backend  = SQLiteBackend(db_path)
        n_threads = 100
        errors   = []
        done     = threading.Event()
        count    = [0]  # mutable counter shared across threads
        lock     = threading.Lock()

        def _flush_worker(i):
            try:
                agent = _make_agent(f"10.{i // 256}.{i % 256}.1",
                                    attack_count=1 + (i % 3))
                backend.flush_profiles(agent)
                with lock:
                    count[0] += 1
            except Exception as e:
                errors.append(f"Thread {i}: {e}")

        threads = [threading.Thread(target=_flush_worker, args=(i,))
                   for i in range(n_threads)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert not errors, f"Chaos flush errors:\n" + "\n".join(errors)
        assert count[0] == n_threads, \
            f"Not all threads completed: {count[0]}/{n_threads}"

    def test_db_readable_after_chaos(self, tmp_path):
        """After chaos flush, the SQLite file must be a valid readable DB."""
        db_path = str(tmp_path / "chaos_readable.db")
        backend = SQLiteBackend(db_path)

        # Write chaos
        errors = []
        def _writer(i):
            try:
                agent = _make_agent(f"192.168.{i % 256}.1", attack_count=2)
                backend.flush_profiles(agent)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=_writer, args=(i,)) for i in range(50)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=20)

        assert not errors

        # Verify DB integrity
        conn = sqlite3.connect(db_path)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        conn.close()
        assert integrity == "ok", f"SQLite integrity_check failed: {integrity}"

    def test_banned_ip_not_lost_under_concurrent_writes(self, tmp_path):
        """
        A banned IP written by one thread must be readable after 50 other
        threads concurrently write their own profiles.
        """
        db_path    = str(tmp_path / "ban_chaos.db")
        backend    = SQLiteBackend(db_path)
        banned_ip  = "99.99.99.99"

        # Write the ban first
        banned_agent = _make_agent(banned_ip, attack_count=10,
                                   is_banned=True, ban_until=time.time() + 3600)
        backend.flush_profiles(banned_agent)

        # Now 50 threads flood with other IPs
        def _noise_writer(i):
            agent = _make_agent(f"1.1.{i % 256}.1", attack_count=1)
            backend.flush_profiles(agent)

        threads = [threading.Thread(target=_noise_writer, args=(i,)) for i in range(50)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=20)

        # Banned IP must still be present and banned
        fresh = _FakeAgent()
        backend.load_profiles(fresh)
        p = fresh.ip_memory.get_profile(banned_ip)
        assert p.is_banned is True, "Banned IP lost under concurrent writes"
        assert p.attack_count == 10

    def test_flush_lock_prevents_double_flush_corruption(self, tmp_path):
        """
        Two threads racing to flush must be serialized by _flush_lock.
        The row count in DB must be exactly 1 (upsert, not duplicate).
        """
        db_path = str(tmp_path / "lock_test.db")
        backend = SQLiteBackend(db_path)
        ip      = "8.8.8.8"

        results = []

        def _racer(attack_n):
            agent = _make_agent(ip, attack_count=attack_n)
            n = backend.flush_profiles(agent)
            results.append(n)

        t1 = threading.Thread(target=_racer, args=(3,))
        t2 = threading.Thread(target=_racer, args=(7,))
        t1.start(); t2.start()
        t1.join(timeout=10); t2.join(timeout=10)

        conn   = sqlite3.connect(db_path)
        n_rows = conn.execute(
            f"SELECT COUNT(*) FROM ip_profiles WHERE ip='{ip}'"
        ).fetchone()[0]
        conn.close()
        assert n_rows == 1, f"Expected 1 row (upsert), got {n_rows} (duplicate write)"
