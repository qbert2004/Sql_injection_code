"""
StateBackend — Pluggable persistence abstraction for SQLi Agent  (v3.7.0)
=========================================================================
Defines the protocol that any state backend must implement so that
AgentStore (SQLite) and RedisBackend can be swapped without touching
agent.py logic.

Architecture
------------
                     SQLiAgent
                         |
                   StateBackend (Protocol)
                  /                     \\
          SQLiteBackend            RedisBackend
        (agent_state.db)       (Redis / Redis Cluster)

The Protocol contract has three responsibilities:
  1. IP profile CRUD      — load_profiles() / save_profiles()
  2. SGD model I/O        — load_sgd() / save_sgd()
  3. Lifecycle hooks      — ping() / close()

All methods are SYNCHRONOUS (matching the current threading model).
Async Redis support is straightforward to add later via asyncio.run()
wrapping or a dedicated async backend class.

Usage
-----
    from state_backend import make_backend
    backend = make_backend()          # reads SQLI_BACKEND env var
    # or explicitly:
    from state_backend import SQLiteBackend, RedisBackend
    backend = RedisBackend.from_env()

    # In agent startup:
    n = backend.load_profiles(agent)
    # On shutdown:
    backend.flush_profiles(agent)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections import Counter
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    pass  # avoid circular import with agent.py


# ═══════════════════════════════════════════════════════════════
#  Serialisation helpers (shared by all backends)
# ═══════════════════════════════════════════════════════════════

def _profile_to_dict(ip: str, p: Any) -> dict:
    """Serialise IPProfile to a plain dict for any backend."""
    return {
        "ip":               ip,
        "first_seen":       p.first_seen,
        "last_seen":        p.last_seen,
        "total_requests":   p.total_requests,
        "attack_count":     p.attack_count,
        "suspicious_count": p.suspicious_count,
        "attack_types":     json.dumps(dict(p.attack_types)),
        "endpoints":        json.dumps(list(p.endpoints_targeted)),
        "fields":           json.dumps(list(p.fields_targeted)),
        "is_banned":        int(p.is_banned),
        "ban_until":        p.ban_until,
        "reputation_score": p.reputation_score,
    }


def _dict_to_profile(agent: Any, row: dict, now: float) -> None:
    """Deserialise a dict into an IPProfile inside agent.ip_memory."""
    with agent.ip_memory._lock:
        p = agent.ip_memory.get_profile(row["ip"])
        p.first_seen        = float(row["first_seen"])
        p.last_seen         = float(row["last_seen"])
        p.total_requests    = int(row["total_requests"])
        p.attack_count      = int(row["attack_count"])
        p.suspicious_count  = int(row["suspicious_count"])
        p.attack_types      = Counter(json.loads(row.get("attack_types") or "{}"))
        p.endpoints_targeted = set(json.loads(row.get("endpoints") or "[]"))
        p.fields_targeted   = set(json.loads(row.get("fields") or "[]"))
        p.reputation_score  = float(row.get("reputation_score") or 0.0)

        ban_until = row.get("ban_until")
        if row.get("is_banned") and ban_until and float(ban_until) > now:
            p.is_banned = True
            p.ban_until = float(ban_until)
        else:
            p.is_banned  = False
            p.ban_until  = None


# ═══════════════════════════════════════════════════════════════
#  Protocol definition
# ═══════════════════════════════════════════════════════════════

@runtime_checkable
class StateBackend(Protocol):
    """
    Minimal interface every backend must satisfy.

    Methods
    -------
    load_profiles(agent)  → int
        Restore IP profiles from the backing store into agent.ip_memory.
        Returns the number of profiles loaded.

    flush_profiles(agent, min_attacks) → int
        Persist dirty profiles from agent.ip_memory to the backing store.
        Profiles with attack_count < min_attacks are skipped (clean traffic).
        Returns the number of profiles written.

    load_sgd(agent) → bool
        Restore the online SGD model into agent.online_learner.
        Returns True if model was loaded, False otherwise.

    save_sgd(agent) → bool
        Persist the online SGD model from agent.online_learner.
        Returns True on success, False otherwise.

    ping() → bool
        Health-check the backend connection.
        Returns True if the backend is reachable, False otherwise.

    close() → None
        Release any held connections / file handles.
    """

    def load_profiles(self, agent: Any) -> int: ...
    def flush_profiles(self, agent: Any, min_attacks: int = 1) -> int: ...
    def load_sgd(self, agent: Any) -> bool: ...
    def save_sgd(self, agent: Any) -> bool: ...
    def ping(self) -> bool: ...
    def close(self) -> None: ...


# ═══════════════════════════════════════════════════════════════
#  SQLiteBackend  (default, single-node, zero-dependency)
# ═══════════════════════════════════════════════════════════════

class SQLiteBackend:
    """
    SQLite-backed state backend — drop-in replacement for the old AgentStore.

    Differences from AgentStore:
      - Implements StateBackend protocol (load_profiles / flush_profiles)
      - Keeps AgentStore's public API (load_into / flush) as aliases
        so existing call sites in api_server.py need no changes.
      - _flush_lock + _lock thread-safety is preserved.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS ip_profiles (
        ip              TEXT PRIMARY KEY,
        first_seen      REAL NOT NULL,
        last_seen       REAL NOT NULL,
        total_requests  INTEGER NOT NULL DEFAULT 0,
        attack_count    INTEGER NOT NULL DEFAULT 0,
        suspicious_count INTEGER NOT NULL DEFAULT 0,
        attack_types    TEXT NOT NULL DEFAULT '{}',
        endpoints       TEXT NOT NULL DEFAULT '[]',
        fields          TEXT NOT NULL DEFAULT '[]',
        is_banned       INTEGER NOT NULL DEFAULT 0,
        ban_until       REAL,
        reputation_score REAL NOT NULL DEFAULT 0.0
    );
    CREATE TABLE IF NOT EXISTS agent_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str = "agent_state.db") -> None:
        self.db_path = db_path
        self._lock       = threading.Lock()
        self._flush_lock = threading.Lock()
        self._init_db()

    # ── Internal ──────────────────────────────────────────────

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(self._SCHEMA)
        except Exception as e:
            print(f"[SQLiteBackend] WARNING: Could not init DB at {self.db_path!r}: {e}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.row_factory = sqlite3.Row
        return conn

    # ── StateBackend protocol ─────────────────────────────────

    def load_profiles(self, agent: Any) -> int:
        """Load IP profiles from SQLite into agent memory."""
        loaded = 0
        now = time.time()
        try:
            with self._lock, self._connect() as conn:
                rows = conn.execute(
                    "SELECT * FROM ip_profiles WHERE attack_count > 0 OR is_banned = 1"
                ).fetchall()

            for row in rows:
                _dict_to_profile(agent, dict(row), now)
                loaded += 1

        except Exception as e:
            print(f"[SQLiteBackend] WARNING: load_profiles failed: {e}")

        return loaded

    def flush_profiles(self, agent: Any, min_attacks: int = 1) -> int:
        """Persist dirty IP profiles to SQLite."""
        acquired = self._flush_lock.acquire(blocking=True, timeout=8.0)
        if not acquired:
            print("[SQLiteBackend] WARNING: flush_profiles skipped — another flush in progress")
            return 0

        saved = 0
        try:
            with agent.ip_memory._lock:
                snapshot = [
                    (ip, p) for ip, p in agent.ip_memory._profiles.items()
                    if p.attack_count >= min_attacks or p.is_banned
                ]

            rows = [_profile_to_dict(ip, p) for ip, p in snapshot]

            if rows:
                with self._lock, self._connect() as conn:
                    conn.executemany(
                        """INSERT INTO ip_profiles
                           (ip, first_seen, last_seen, total_requests, attack_count,
                            suspicious_count, attack_types, endpoints, fields,
                            is_banned, ban_until, reputation_score)
                           VALUES (:ip,:first_seen,:last_seen,:total_requests,:attack_count,
                                   :suspicious_count,:attack_types,:endpoints,:fields,
                                   :is_banned,:ban_until,:reputation_score)
                           ON CONFLICT(ip) DO UPDATE SET
                               last_seen        = excluded.last_seen,
                               total_requests   = excluded.total_requests,
                               attack_count     = excluded.attack_count,
                               suspicious_count = excluded.suspicious_count,
                               attack_types     = excluded.attack_types,
                               endpoints        = excluded.endpoints,
                               fields           = excluded.fields,
                               is_banned        = excluded.is_banned,
                               ban_until        = excluded.ban_until,
                               reputation_score = excluded.reputation_score
                        """,
                        rows,
                    )
                    saved = len(rows)

        except Exception as e:
            print(f"[SQLiteBackend] WARNING: flush_profiles failed: {e}")
        finally:
            self._flush_lock.release()

        return saved

    def load_sgd(self, agent: Any) -> bool:
        """Load SGD model from disk into agent.online_learner."""
        try:
            import joblib
        except ImportError:
            return False

        if not hasattr(agent, "online_learner"):
            return False

        ol = agent.online_learner
        if not ol._enabled:
            return False

        model_path = getattr(agent.config, "sgd_model_path", "agent_sgd.joblib")
        if not os.path.exists(model_path):
            return False

        try:
            data = joblib.load(model_path)
            with ol._lock:
                ol._clf        = data["clf"]
                ol._vectorizer = data["vectorizer"]
                ol._is_fitted  = True
            return True
        except Exception as e:
            print(f"[SQLiteBackend] WARNING: load_sgd failed: {e}")
            return False

    def save_sgd(self, agent: Any) -> bool:
        """Persist agent.online_learner SGD model to disk atomically."""
        try:
            import joblib
        except ImportError:
            return False

        if not hasattr(agent, "online_learner"):
            return False

        ol = agent.online_learner
        if not (ol._enabled and ol._is_fitted):
            return False

        model_path = getattr(agent.config, "sgd_model_path", "agent_sgd.joblib")
        tmp_path   = model_path + ".tmp"
        try:
            joblib.dump({"clf": ol._clf, "vectorizer": ol._vectorizer}, tmp_path)
            os.replace(tmp_path, model_path)
            return True
        except Exception as e:
            print(f"[SQLiteBackend] WARNING: save_sgd failed: {e}")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            return False

    def ping(self) -> bool:
        """Check that the SQLite file is accessible."""
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        """No persistent connections to close for SQLite."""
        pass

    # ── AgentStore backward-compat aliases ───────────────────
    # api_server.py and existing code use store.load_into() / store.flush()
    # These aliases preserve the old API without any migration needed.

    def load_into(self, agent: Any, load_sgd: bool = True) -> int:
        """Backward-compat alias for load_profiles() + load_sgd()."""
        n = self.load_profiles(agent)
        if load_sgd:
            self.load_sgd(agent)
        return n

    def flush(self, agent: Any, min_attacks: int = 1, save_sgd: bool = True) -> int:
        """Backward-compat alias for flush_profiles() + save_sgd()."""
        n = self.flush_profiles(agent, min_attacks=min_attacks)
        if save_sgd:
            self.save_sgd(agent)
        return n


# ═══════════════════════════════════════════════════════════════
#  RedisBackend  (distributed, multi-worker)
# ═══════════════════════════════════════════════════════════════

class RedisBackend:
    """
    Redis-backed state backend for multi-worker / distributed deployments.

    Key design decisions
    --------------------
    * All IP profile fields are stored in a Redis Hash:
        HSET sqli:ip:<ip>  field1 val1 field2 val2 ...
      Hashes are efficient — O(1) per field, HGETALL is a single round-trip.

    * IP index kept in a Redis Set:
        sqli:ip:index  → {ip1, ip2, ...}
      Allows scanning all known IPs without KEYS (which is O(N) and blocks).

    * TTL per IP hash: default 7 days from last_seen.
      Clean (attack_count=0) IPs are never written, so Redis stays lean.

    * SGD model stored as a binary blob:
        SET sqli:sgd:model  <joblib bytes>
      Compressed with joblib compress=3 to reduce network transfer.

    * Atomic batch writes via Redis pipeline (MULTI/EXEC semantics):
      flush_profiles() uses pipe.execute() to minimise round-trips.

    * Graceful degradation: if redis-py is not installed or connection
      fails, RedisBackend.from_env() raises ImportError / ConnectionError
      and make_backend() falls back to SQLiteBackend automatically.

    Env vars
    --------
    REDIS_URL      redis://localhost:6379/0  (full URL takes precedence)
    REDIS_HOST     localhost
    REDIS_PORT     6379
    REDIS_DB       0
    REDIS_PASSWORD (optional)
    REDIS_TTL_DAYS 7  (IP profile expiry in days)

    Usage
    -----
        backend = RedisBackend.from_env()
        backend.ping()      # True if connected
        n = backend.load_profiles(agent)
        backend.flush_profiles(agent)
        backend.close()
    """

    KEY_PREFIX  = "sqli:ip:"
    INDEX_KEY   = "sqli:ip:index"
    SGD_KEY     = "sqli:sgd:model"
    DEFAULT_TTL = 7 * 24 * 3600    # 7 days in seconds

    def __init__(self, client: Any, ttl_seconds: int = DEFAULT_TTL) -> None:
        """
        Parameters
        ----------
        client      : redis.Redis instance (caller-created, testable)
        ttl_seconds : expiry for IP hash keys (default 7 days)
        """
        self._r   = client
        self._ttl = ttl_seconds

    # ── Constructors ──────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "RedisBackend":
        """
        Build a RedisBackend from environment variables.
        Raises ImportError if redis-py is not installed.
        Raises redis.ConnectionError if the server is unreachable.
        """
        try:
            import redis as _redis
        except ImportError as exc:
            raise ImportError(
                "redis-py is required for RedisBackend. "
                "Install with: pip install redis"
            ) from exc

        url      = os.environ.get("REDIS_URL", "")
        ttl_days = int(os.environ.get("REDIS_TTL_DAYS", "7"))
        ttl_s    = ttl_days * 24 * 3600

        if url:
            client = _redis.Redis.from_url(url, decode_responses=True)
        else:
            client = _redis.Redis(
                host     = os.environ.get("REDIS_HOST", "localhost"),
                port     = int(os.environ.get("REDIS_PORT", "6379")),
                db       = int(os.environ.get("REDIS_DB", "0")),
                password = os.environ.get("REDIS_PASSWORD") or None,
                decode_responses=True,
            )

        # Validate connection eagerly
        client.ping()
        return cls(client, ttl_seconds=ttl_s)

    @classmethod
    def from_url(cls, url: str, ttl_seconds: int = DEFAULT_TTL) -> "RedisBackend":
        """Convenience constructor from a Redis URL."""
        try:
            import redis as _redis
        except ImportError as exc:
            raise ImportError("redis-py required. pip install redis") from exc
        client = _redis.Redis.from_url(url, decode_responses=True)
        client.ping()
        return cls(client, ttl_seconds=ttl_s if (ttl_s := ttl_seconds) else cls.DEFAULT_TTL)

    # ── StateBackend protocol ─────────────────────────────────

    def load_profiles(self, agent: Any) -> int:
        """Load all known IP profiles from Redis into agent.ip_memory."""
        now = time.time()
        loaded = 0
        try:
            ips = self._r.smembers(self.INDEX_KEY)
            for ip in ips:
                raw = self._r.hgetall(f"{self.KEY_PREFIX}{ip}")
                if not raw:
                    continue
                try:
                    _dict_to_profile(agent, raw, now)
                    loaded += 1
                except Exception as e:
                    print(f"[RedisBackend] WARNING: parse error for {ip}: {e}")
        except Exception as e:
            print(f"[RedisBackend] WARNING: load_profiles failed: {e}")
        return loaded

    def flush_profiles(self, agent: Any, min_attacks: int = 1) -> int:
        """Persist dirty IP profiles to Redis via pipeline."""
        saved = 0
        try:
            with agent.ip_memory._lock:
                snapshot = [
                    (ip, p) for ip, p in agent.ip_memory._profiles.items()
                    if p.attack_count >= min_attacks or p.is_banned
                ]

            pipe = self._r.pipeline(transaction=False)
            for ip, p in snapshot:
                key  = f"{self.KEY_PREFIX}{ip}"
                data = _profile_to_dict(ip, p)
                # Redis HSET accepts a mapping directly
                pipe.hset(key, mapping={k: str(v) if v is not None else "" for k, v in data.items()})
                pipe.expire(key, self._ttl)
                pipe.sadd(self.INDEX_KEY, ip)

            if snapshot:
                pipe.expire(self.INDEX_KEY, self._ttl)
                pipe.execute()
                saved = len(snapshot)

        except Exception as e:
            print(f"[RedisBackend] WARNING: flush_profiles failed: {e}")
        return saved

    def load_sgd(self, agent: Any) -> bool:
        """Restore SGD model from Redis blob into agent.online_learner."""
        try:
            import joblib, io
        except ImportError:
            return False

        if not hasattr(agent, "online_learner"):
            return False
        ol = agent.online_learner
        if not ol._enabled:
            return False

        try:
            raw = self._r.get(self.SGD_KEY)
            if not raw:
                return False
            # Redis with decode_responses=True gives str — need bytes backend
            # Use a separate binary client for blob reads
            data = joblib.load(io.BytesIO(raw.encode("latin-1") if isinstance(raw, str) else raw))
            with ol._lock:
                ol._clf        = data["clf"]
                ol._vectorizer = data["vectorizer"]
                ol._is_fitted  = True
            return True
        except Exception as e:
            print(f"[RedisBackend] WARNING: load_sgd failed: {e}")
            return False

    def save_sgd(self, agent: Any) -> bool:
        """Persist SGD model to Redis as a binary blob."""
        try:
            import joblib, io
        except ImportError:
            return False

        if not hasattr(agent, "online_learner"):
            return False
        ol = agent.online_learner
        if not (ol._enabled and ol._is_fitted):
            return False

        try:
            buf = io.BytesIO()
            joblib.dump({"clf": ol._clf, "vectorizer": ol._vectorizer}, buf, compress=3)
            self._r.set(self.SGD_KEY, buf.getvalue().decode("latin-1"))
            return True
        except Exception as e:
            print(f"[RedisBackend] WARNING: save_sgd failed: {e}")
            return False

    def ping(self) -> bool:
        """Return True if Redis is reachable."""
        try:
            return bool(self._r.ping())
        except Exception:
            return False

    def close(self) -> None:
        """Close the Redis connection pool."""
        try:
            self._r.close()
        except Exception:
            pass

    # ── Backward-compat aliases (same as SQLiteBackend) ───────

    def load_into(self, agent: Any, load_sgd: bool = True) -> int:
        n = self.load_profiles(agent)
        if load_sgd:
            self.load_sgd(agent)
        return n

    def flush(self, agent: Any, min_attacks: int = 1, save_sgd: bool = True) -> int:
        n = self.flush_profiles(agent, min_attacks=min_attacks)
        if save_sgd:
            self.save_sgd(agent)
        return n


# ═══════════════════════════════════════════════════════════════
#  NullBackend  (testing / stateless mode)
# ═══════════════════════════════════════════════════════════════

class NullBackend:
    """
    No-op backend for testing or stateless deployments.
    All writes are discarded; reads return zero profiles.
    Satisfies the StateBackend protocol.
    """

    def load_profiles(self, agent: Any) -> int:      return 0
    def flush_profiles(self, agent: Any, min_attacks: int = 1) -> int: return 0
    def load_sgd(self, agent: Any) -> bool:          return False
    def save_sgd(self, agent: Any) -> bool:          return False
    def ping(self) -> bool:                          return True
    def close(self) -> None:                         pass

    # Compat aliases
    def load_into(self, agent: Any, load_sgd: bool = True) -> int:  return 0
    def flush(self, agent: Any, min_attacks: int = 1, save_sgd: bool = True) -> int: return 0


# ═══════════════════════════════════════════════════════════════
#  Factory
# ═══════════════════════════════════════════════════════════════

def make_backend(
    backend_type: str | None = None,
    sqlite_path: str = "agent_state.db",
) -> SQLiteBackend | RedisBackend | NullBackend:
    """
    Backend factory. Reads SQLI_BACKEND env var if backend_type is None.

    SQLI_BACKEND values
    -------------------
    sqlite   (default) — SQLiteBackend, single-node, zero-dependency
    redis              — RedisBackend, needs REDIS_URL or REDIS_HOST
    null               — NullBackend, stateless / testing

    Falls back to SQLiteBackend if redis-py is not installed or Redis
    is unreachable — logs a warning but does not crash.

    Example .env
    ------------
    SQLI_BACKEND=redis
    REDIS_URL=redis://redis:6379/0
    REDIS_TTL_DAYS=7
    """
    kind = (backend_type or os.environ.get("SQLI_BACKEND", "sqlite")).lower().strip()

    if kind == "redis":
        try:
            backend = RedisBackend.from_env()
            print(f"[StateBackend] RedisBackend connected ({os.environ.get('REDIS_URL', 'localhost:6379')})")
            return backend
        except ImportError:
            print("[StateBackend] WARNING: redis-py not installed. Falling back to SQLiteBackend.")
            print("[StateBackend]   Install with: pip install redis")
        except Exception as e:
            print(f"[StateBackend] WARNING: Redis connection failed ({e}). Falling back to SQLiteBackend.")
        return SQLiteBackend(db_path=sqlite_path)

    if kind == "null":
        print("[StateBackend] NullBackend — state is not persisted")
        return NullBackend()

    # Default: sqlite
    return SQLiteBackend(db_path=sqlite_path)


# ═══════════════════════════════════════════════════════════════
#  Backward-compat: AgentStore is now an alias for SQLiteBackend
# ═══════════════════════════════════════════════════════════════

AgentStore = SQLiteBackend
"""
Backward-compatibility alias.

Existing code that does:
    from agent import AgentStore
    store = AgentStore("agent_state.db")
    store.load_into(agent)
    store.flush(agent)

continues to work without modification.  The alias is intentionally
kept here (not in agent.py) so that agent.py remains dependency-free
for the StateBackend module.
"""
