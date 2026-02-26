"""
SQLi Protection AI Agent  (production-ready, v3.0)
===================================================
Autonomous AI agent that wraps SQLInjectionEnsemble and adds:
  - IP memory (counters, sliding-window history, reputation scoring)
  - Session context (field scanning, attack sequence tracking)
  - Decision escalation (SUSPICIOUS × N → BLOCK, auto-ban by frequency)
  - Adaptive thresholds (lower tau for known attackers)
  - Online self-learning (SGDClassifier incremental layer + signature DB)
  - Predictive defense (pre-request attack probability)
  - System coordination (WAF/SIEM webhooks, threat intel)
  - Decision explainability (string + structured contributing_factors)

Production features (v3.0 — added in v3.4.0 release):
  - threading.RLock in IPMemory and SessionMemory — no race conditions
  - SQLite persistence (AgentStore) — survives server restarts
  - Prometheus gauge updates via metrics module
  - Structured explanation object alongside human-readable string
  - LRU eviction (Roadmap C): IPMemory evicts oldest non-banned IPs when
    max_tracked_ips is reached — predictable memory usage (O(max_tracked_ips))
  - SGD auto-save (Roadmap A): flush(save_sgd=True) persists the fitted
    SGDClassifier; load_into(load_sgd=True) restores it on restart

Design notes:
  - PredictiveDefense uses a LOCAL multiplier variable, never mutates AgentConfig
  - IPProfile.recent_attacks uses TIME-based window filter, not just maxlen
  - cleanup_stale() is triggered externally (asyncio background task in api_server.py)
  - source_ip=None/"unknown" → pure detector fallback (no agent memory)

Usage (demo):
    py -3 agent.py

Usage (in api_server.py):
    from agent import SQLiAgent, AgentConfig, AgentStore
    store = AgentStore("agent_state.db")
    agent = SQLiAgent(detector, store=store)
    store.load_into(agent)          # restore bans + reputation on startup
    result = agent.evaluate(text, source_ip=ip, session_id=sid, endpoint=ep)
    # On shutdown:
    store.flush(agent)
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── State backend abstraction (v3.7.0) ──────────────────────────────────────
# AgentStore is now imported from state_backend so that SQLiteBackend and
# RedisBackend share the same interface.  The name AgentStore is preserved
# here as a re-export for backward compatibility with existing imports:
#   from agent import AgentStore   ← still works
from state_backend import (
    SQLiteBackend,
    RedisBackend,
    NullBackend,
    StateBackend,
    make_backend,
)
AgentStore = SQLiteBackend   # backward-compat alias

# ────────────────────────────────────────────────────────────
# Optional ML deps for OnlineLearning (graceful degradation)
# ────────────────────────────────────────────────────────────
try:
    from sklearn.linear_model import SGDClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

# ────────────────────────────────────────────────────────────
# Optional AST layer (sqlglot — graceful degradation)
# ────────────────────────────────────────────────────────────
try:
    import sqlglot as _sqlglot
    import sqlglot.expressions as _sqlglot_exp
    _SQLGLOT_AVAILABLE = True
except ImportError:
    _SQLGLOT_AVAILABLE = False

from sql_injection_detector import SQLInjectionEnsemble, EnsembleConfig


# ═══════════════════════════════════════════════════════════════
#  AgentConfig — все настраиваемые параметры агента
# ═══════════════════════════════════════════════════════════════

@dataclass
class AgentConfig:
    """Configuration for SQLiAgent. All values have sensible production defaults."""

    # ── IP escalation ──────────────────────────────────────────
    ip_attack_threshold: int = 3          # attacks in window → auto-ban
    ip_attack_window_seconds: int = 300   # sliding window (5 minutes)
    ip_ban_duration_seconds: int = 3600   # ban duration (1 hour)

    # ── SUSPICIOUS escalation ──────────────────────────────────
    suspicious_escalation_count: int = 3  # N suspicious in window → BLOCK
    suspicious_window_seconds: int = 120  # window for suspicious (2 minutes)

    # ── Adaptive thresholds ────────────────────────────────────
    enable_adaptive_thresholds: bool = True
    reputation_tau_multiplier: float = 0.75   # tau_high *= 0.75 for known attackers

    # ── Predictive defense ─────────────────────────────────────
    enable_predictive_defense: bool = True
    predictive_threshold: float = 0.7    # probability above which to tighten thresholds
    predictive_tau_boost: float = 0.80   # additional multiplier when prediction > threshold

    # ── Online learning ────────────────────────────────────────
    enable_online_learning: bool = True
    incremental_fit_batch_size: int = 10  # examples before SGD fit
    online_layer_weight: float = 0.20     # P_online blending weight (only for known attackers)

    # ── System coordination ────────────────────────────────────
    siem_webhook_url: str | None = None           # from env SIEM_WEBHOOK_URL
    threat_intel_api_key: str | None = None       # from env ABUSEIPDB_API_KEY

    # ── Memory TTL ─────────────────────────────────────────────
    ip_memory_ttl_seconds: int = 3600      # clean up inactive IPs after 1 hour
    session_memory_ttl_seconds: int = 1800 # clean up sessions after 30 minutes
    max_tracked_ips: int = 10000           # max IPs in memory

    # ── Persistence ────────────────────────────────────────────
    persistence_flush_interval: int = 300  # flush to SQLite every N seconds
    persist_min_attacks: int = 1           # only persist IPs with >= N attacks (skip clean IPs)
    sgd_model_path: str = "agent_sgd.joblib"  # path for SGD model persistence (Roadmap A)


def _agent_config_from_env(base: AgentConfig | None = None) -> AgentConfig:
    """Override AgentConfig from environment variables."""
    cfg = base or AgentConfig()
    if url := os.environ.get("SIEM_WEBHOOK_URL"):
        cfg.siem_webhook_url = url
    if key := os.environ.get("ABUSEIPDB_API_KEY"):
        cfg.threat_intel_api_key = key
    return cfg


# ═══════════════════════════════════════════════════════════════
#  AgentStore — MOVED to state_backend.py  (v3.7.0)
#
#  AgentStore is now SQLiteBackend imported above.
#  The class definition is kept here as a stub only to surface a
#  clear error if something tries to subclass it directly.
# ═══════════════════════════════════════════════════════════════

class AgentStore(SQLiteBackend):  # noqa: F811
    """
    Backward-compatibility stub — implementation moved to state_backend.SQLiteBackend.

    All logic lives in SQLiteBackend.  This subclass exists only so that:
        from agent import AgentStore
        store = AgentStore("agent_state.db")
    continues to work without modification anywhere in the codebase.
    """
    # No overrides — inherits everything from SQLiteBackend.


# ═══════════════════════════════════════════════════════════════
#  IPProfile + IPMemory  (thread-safe via RLock)
# ═══════════════════════════════════════════════════════════════

@dataclass
class IPProfile:
    """Per-IP state tracked by the agent."""
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    total_requests: int = 0
    attack_count: int = 0           # INJECTION / BLOCK decisions
    suspicious_count: int = 0       # SUSPICIOUS / CHALLENGE decisions
    # Sliding-window deques (time-filtered in logic, maxlen is safety cap)
    recent_attacks: deque = field(default_factory=lambda: deque(maxlen=200))
    recent_suspicious: deque = field(default_factory=lambda: deque(maxlen=200))
    attack_types: Counter = field(default_factory=Counter)  # {UNION_BASED: 3, ...}
    endpoints_targeted: set = field(default_factory=set)
    fields_targeted: set = field(default_factory=set)
    is_banned: bool = False
    ban_until: float | None = None
    reputation_score: float = 0.0   # 0.0 (clean) … 1.0 (known attacker)


class IPMemory:
    """
    In-memory store of per-IP profiles with TTL-based cleanup and LRU eviction.

    Thread safety: ALL public methods acquire self._lock (threading.RLock).
    The lock is reentrant so that nested calls from the same thread are safe.

    LRU eviction (Roadmap C):
      When the number of tracked IPs exceeds max_ips, the least-recently-seen
      non-banned IPs are evicted to keep memory bounded.  Banned IPs are always
      retained until their ban expires, so eviction never silently lifts a ban.
    """

    # Evict down to this fraction of max_ips when the cap is hit (hysteresis)
    _EVICT_TARGET_FRACTION = 0.80

    def __init__(self, ttl: float = 3600.0, max_ips: int = 10000) -> None:
        self._profiles: dict[str, IPProfile] = {}
        self._ttl = ttl
        self._max_ips = max_ips
        self._lock = threading.RLock()   # ← thread safety

    # ── Public API ─────────────────────────────────────────────

    def get_profile(self, ip: str) -> IPProfile:
        """Return existing profile or create a new one. Caller must hold self._lock."""
        # NOTE: intentionally no lock here — callers must hold _lock for consistency
        if ip not in self._profiles:
            # LRU eviction: if at capacity, free space before inserting
            if len(self._profiles) >= self._max_ips:
                evicted = self._evict_lru()
                # Surface eviction count via a shared counter (set by SQLiAgent)
                _eviction_callback = getattr(self, "_eviction_callback", None)
                if _eviction_callback is not None:
                    _eviction_callback(evicted)
            self._profiles[ip] = IPProfile(ip=ip)
        return self._profiles[ip]

    def _evict_lru(self) -> int:
        """
        Evict least-recently-seen non-banned IPs until we reach
        _EVICT_TARGET_FRACTION * max_ips entries.

        Banned IPs are NEVER evicted (eviction must not silently lift bans).
        Returns the number of entries removed.

        Caller must hold self._lock.
        """
        target = int(self._max_ips * self._EVICT_TARGET_FRACTION)
        now = time.time()

        # Collect eviction candidates: non-banned, sorted oldest last_seen first
        candidates = sorted(
            (
                (ip, p.last_seen)
                for ip, p in self._profiles.items()
                if not (p.is_banned and (p.ban_until is None or p.ban_until > now))
            ),
            key=lambda x: x[1],   # ascending → oldest first
        )

        removed = 0
        for ip, _ in candidates:
            if len(self._profiles) <= target:
                break
            del self._profiles[ip]
            removed += 1

        return removed

    def update(
        self,
        ip: str,
        result: dict,
        endpoint: str | None = None,
        field_name: str | None = None,
    ) -> None:
        """Update profile after a detection result."""
        with self._lock:
            p = self.get_profile(ip)
            now = time.time()
            p.last_seen = now
            p.total_requests += 1

            decision = result.get("agent_decision") or result.get("decision", "SAFE")
            action = result.get("agent_action") or result.get("action", "ALLOW")

            if action in ("BLOCK", "ALERT") or decision in ("INJECTION",):
                p.attack_count += 1
                p.recent_attacks.append(now)
                attack_type = result.get("attack_type", "UNKNOWN")
                if attack_type and attack_type != "NONE":
                    p.attack_types[attack_type] += 1

            if decision == "SUSPICIOUS" or action == "CHALLENGE":
                p.suspicious_count += 1
                p.recent_suspicious.append(now)

            if endpoint:
                p.endpoints_targeted.add(endpoint)
            if field_name:
                p.fields_targeted.add(field_name)

            p.reputation_score = self.compute_reputation(p)

    def is_banned(self, ip: str) -> bool:
        """Check whether IP is currently banned (handles expired bans)."""
        with self._lock:
            p = self._profiles.get(ip)
            if p is None:
                return False
            if p.is_banned and p.ban_until and time.time() > p.ban_until:
                # Ban expired — lift it
                p.is_banned = False
                p.ban_until = None
            return p.is_banned

    def ban(self, ip: str, duration_seconds: int) -> None:
        """Apply a timed ban to an IP."""
        with self._lock:
            p = self.get_profile(ip)
            p.is_banned = True
            p.ban_until = time.time() + duration_seconds

    def compute_reputation(self, p: IPProfile) -> float:
        """
        Weighted reputation score in [0.0, 1.0].
        0.0 = clean, 1.0 = confirmed attacker.
        NOTE: called internally, caller must hold _lock.
        """
        score = 0.0

        # Weight 1: Raw attack ratio (capped at 0.5)
        if p.total_requests > 0:
            score += min(p.attack_count / p.total_requests, 1.0) * 0.5

        # Weight 2: Absolute attack count (log-scale, capped at 0.3)
        if p.attack_count > 0:
            score += min(p.attack_count / 10.0, 1.0) * 0.3

        # Weight 3: Diverse attack types (polymorphic attacker)
        if len(p.attack_types) >= 3:
            score += 0.15
        elif len(p.attack_types) >= 2:
            score += 0.08

        # Weight 4: Multiple endpoints targeted (scanner)
        if len(p.endpoints_targeted) >= 5:
            score += 0.05

        return min(score, 1.0)

    def count_active_bans(self) -> int:
        """Return the number of currently active (non-expired) bans."""
        now = time.time()
        with self._lock:
            return sum(
                1 for p in self._profiles.values()
                if p.is_banned and (p.ban_until is None or p.ban_until > now)
            )

    def mean_reputation(self) -> float:
        """Return the mean reputation score across all tracked IPs."""
        with self._lock:
            scores = [p.reputation_score for p in self._profiles.values()]
        return sum(scores) / len(scores) if scores else 0.0

    def cleanup_stale(self) -> int:
        """Remove profiles inactive longer than TTL. Returns count removed."""
        now = time.time()
        with self._lock:
            stale = [ip for ip, p in self._profiles.items()
                     if now - p.last_seen > self._ttl and not p.is_banned]
            for ip in stale:
                del self._profiles[ip]
        return len(stale)

    def profile_to_dict(self, p: IPProfile) -> dict:
        """Serialize IPProfile for API responses. Caller must hold _lock or pass a snapshot."""
        ban_until_str = None
        if p.ban_until:
            ban_until_str = datetime.fromtimestamp(p.ban_until, tz=timezone.utc).isoformat()
        return {
            "ip": p.ip,
            "reputation_score": round(p.reputation_score, 4),
            "attack_count": p.attack_count,
            "suspicious_count": p.suspicious_count,
            "total_requests": p.total_requests,
            "is_banned": p.is_banned,
            "ban_until": ban_until_str,
            "first_seen": datetime.fromtimestamp(p.first_seen, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(p.last_seen, tz=timezone.utc).isoformat(),
            "attack_types": dict(p.attack_types),
            "endpoints_targeted": list(p.endpoints_targeted),
            "fields_targeted": list(p.fields_targeted),
        }


# ═══════════════════════════════════════════════════════════════
#  SessionContext + SessionMemory  (thread-safe via RLock)
# ═══════════════════════════════════════════════════════════════

@dataclass
class SessionContext:
    """Attack pattern within a single session (tab/browser/connection)."""
    session_id: str
    start_time: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    fields_probed: list = field(default_factory=list)     # ordered: username→id→search
    field_probe_times: list = field(default_factory=list) # timestamps for each field probe
    attack_sequence: list = field(default_factory=list)   # [BOOLEAN_BASED, UNION_BASED, ...]
    escalation_level: int = 0   # 0=normal 1=watch 2=challenge 3=block


class SessionMemory:
    """
    In-memory store of per-session contexts.

    Thread safety: ALL public methods acquire self._lock (threading.RLock).
    """

    def __init__(self, ttl: float = 1800.0) -> None:
        self._sessions: dict[str, SessionContext] = {}
        self._ttl = ttl
        self._lock = threading.RLock()   # ← thread safety

    def get_or_create(self, session_id: str) -> SessionContext:
        """Return existing session context or create a new one. Caller must hold _lock."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(session_id=session_id)
        return self._sessions[session_id]

    def update(
        self,
        session_id: str,
        result: dict,
        field_name: str | None = None,
    ) -> None:
        """Update session after a detection result."""
        with self._lock:
            ctx = self.get_or_create(session_id)
            now = time.time()
            ctx.last_active = now

            if field_name and field_name not in ctx.fields_probed:
                ctx.fields_probed.append(field_name)
                ctx.field_probe_times.append(now)

            decision = result.get("agent_decision") or result.get("decision", "SAFE")
            attack_type = result.get("attack_type", "NONE")

            if decision in ("INJECTION",) or result.get("agent_action") == "BLOCK":
                if attack_type and attack_type != "NONE":
                    ctx.attack_sequence.append(attack_type)
                ctx.escalation_level = min(ctx.escalation_level + 1, 3)
            elif decision == "SUSPICIOUS":
                ctx.escalation_level = min(ctx.escalation_level + 1, 2)

    def cleanup_stale(self) -> int:
        """Remove sessions inactive longer than TTL. Returns count removed."""
        now = time.time()
        with self._lock:
            stale = [sid for sid, ctx in self._sessions.items()
                     if now - ctx.last_active > self._ttl]
            for sid in stale:
                del self._sessions[sid]
        return len(stale)


# ═══════════════════════════════════════════════════════════════
#  OnlineLearning — incremental SGD layer + signature DB
# ═══════════════════════════════════════════════════════════════

class OnlineLearning:
    """
    Continuous self-learning layer on top of the static RF+CNN ensemble.

    Architecture:
      - Signature DB: fast regex pre-check for known attack patterns
      - SGDClassifier: online incremental ML layer (partial_fit capable)
      - Pattern weights: suppressed when analyst marks FP

    RF/CNN are NOT modified — only this auxiliary layer learns online.
    Thread safety: internal _lock guards SGD state.
    """

    # Built-in seed signatures (common attack patterns)
    _SEED_SIGNATURES = [
        r"'\s*(or|and)\s+\d+\s*=\s*\d+",                    # ' OR 1=1
        r"union\s+(all\s+)?select\s+",                        # UNION SELECT
        r";\s*(drop|delete|truncate)\s+table",                # ; DROP TABLE
        r"exec(\s+|\()\s*(xp_|sp_)",                         # exec xp_cmdshell
        r"into\s+(outfile|dumpfile)\s+",                      # INTO OUTFILE
        r"sleep\s*\(\s*\d+",                                  # SLEEP(N)
        r"benchmark\s*\(\s*\d+",                              # BENCHMARK(N,...)
        r"waitfor\s+delay\s+",                                # WAITFOR DELAY
        r"(load_file|char|ascii|hex)\s*\(",                   # SQL functions
        r"information_schema\.(tables|columns)",              # schema enumeration
    ]

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._enabled = config.enable_online_learning and _SKLEARN_AVAILABLE
        self._lock = threading.RLock()

        # Signature DB
        self.signature_db: list[tuple[str, re.Pattern]] = []
        self.pattern_weights: dict[str, float] = {}
        for sig in self._SEED_SIGNATURES:
            pat = re.compile(sig, re.I)
            self.signature_db.append((sig, pat))
            self.pattern_weights[sig] = 1.0

        # Online ML layer
        self._clf: Any = None
        self._vectorizer: Any = None
        self._is_fitted = False
        if self._enabled:
            self._clf = SGDClassifier(loss="log_loss", max_iter=1000, random_state=42)
            self._vectorizer = TfidfVectorizer(
                analyzer="char_wb", ngram_range=(3, 5), max_features=5000
            )

        # Training buffer
        self.training_buffer: deque = deque(maxlen=1000)
        self.metrics = {
            "patterns_learned": len(self._SEED_SIGNATURES),
            "false_positives_corrected": 0,
            "incremental_fits": 0,
            "sgd_trained_examples": 0,
        }

    # ── Signature matching ─────────────────────────────────────

    def check_signatures(self, text: str) -> tuple[bool, str | None]:
        """
        Quick signature pre-check. Returns (matched, pattern_string).
        Respects pattern_weights — patterns suppressed near 0 are skipped.
        """
        text_lower = text.lower()
        with self._lock:
            db_snapshot = list(self.signature_db)
            weights_snapshot = dict(self.pattern_weights)
        for sig, pat in db_snapshot:
            weight = weights_snapshot.get(sig, 1.0)
            if weight < 0.1:
                continue  # suppressed
            if pat.search(text_lower):
                return True, sig
        return False, None

    # ── Learning ───────────────────────────────────────────────

    def learn_from_blocked_attack(self, text: str, ip_profile: IPProfile) -> None:
        """
        Learn from a confirmed attack. Buffers example and optionally fits SGD.
        Also extracts new signature if this attack pattern is novel.
        """
        if not self._enabled:
            return

        with self._lock:
            self.training_buffer.append((text, 1))
            buf_len = len(self.training_buffer)

        if buf_len >= self.config.incremental_fit_batch_size:
            self._incremental_fit()

        # Extract n-gram signature from highly repeated attack types
        if ip_profile.attack_count >= 3:
            self._maybe_add_signature(text)

    def learn_from_false_positive(self, text: str, matched_pattern: str | None = None) -> None:
        """Analyst marked result as FP — add safe example and suppress pattern."""
        if not self._enabled:
            return

        with self._lock:
            self.training_buffer.append((text, 0))
            self.metrics["false_positives_corrected"] += 1
            if matched_pattern and matched_pattern in self.pattern_weights:
                self.pattern_weights[matched_pattern] *= 0.9
                if self.pattern_weights[matched_pattern] < 0.05:
                    self.pattern_weights[matched_pattern] = 0.05  # floor
            buf_len = len(self.training_buffer)

        if buf_len >= self.config.incremental_fit_batch_size:
            self._incremental_fit()

    # ── SGD prediction ─────────────────────────────────────────

    def get_online_probability(self, text: str) -> float | None:
        """
        Get injection probability from the online SGD layer.
        Returns None if not fitted yet.
        """
        with self._lock:
            if not self._enabled or not self._is_fitted:
                return None
            try:
                X = self._vectorizer.transform([text])
                proba = self._clf.predict_proba(X)[0]
                return float(proba[1]) if len(proba) > 1 else None
            except Exception:
                return None

    # ── Internal ───────────────────────────────────────────────

    def _incremental_fit(self) -> None:
        """Fit SGD on buffered examples."""
        with self._lock:
            if not self._enabled or len(self.training_buffer) < 2:
                return
            try:
                texts = [t for t, _ in self.training_buffer]
                labels = [lbl for _, lbl in self.training_buffer]

                if not self._is_fitted:
                    X = self._vectorizer.fit_transform(texts)
                    self._clf.partial_fit(X, labels, classes=[0, 1])
                    self._is_fitted = True
                else:
                    X = self._vectorizer.transform(texts)
                    self._clf.partial_fit(X, labels)

                self.metrics["incremental_fits"] += 1
                self.metrics["sgd_trained_examples"] += len(texts)
            except Exception:
                pass  # Never crash detection for learning errors

    def _maybe_add_signature(self, text: str) -> None:
        """Extract a simple n-gram signature from an attack text (heuristic)."""
        sql_seq = re.findall(
            r"\b(union|select|from|where|drop|insert|exec|sleep|benchmark)\b",
            text, re.I
        )
        if len(sql_seq) >= 2:
            combo = r"\b" + sql_seq[0].lower() + r"\b.{0,20}\b" + sql_seq[1].lower() + r"\b"
            with self._lock:
                if combo not in self.pattern_weights:
                    try:
                        pat = re.compile(combo, re.I)
                        self.signature_db.append((combo, pat))
                        self.pattern_weights[combo] = 1.0
                        self.metrics["patterns_learned"] += 1
                    except re.error:
                        pass


# ═══════════════════════════════════════════════════════════════
#  ASTLayer — sqlglot-based structural SQL analysis (Layer 1.5)
# ═══════════════════════════════════════════════════════════════

class ASTLayer:
    """
    SQL Abstract Syntax Tree pre-check using sqlglot (Layer 1.5).

    Sits between signature matching (Layer 1) and the ML ensemble (Layer 2).
    Catches structurally valid SQL injection that regex signatures miss,
    particularly:
      - UNION SELECT payloads injected after a closing quote
      - Stacked queries (semicolon-separated DROP/DELETE/INSERT)
      - SELECT with FROM clause embedded in field values

    Design decisions:
      - Graceful degradation: if sqlglot is not installed, check() is a no-op
      - No false positives on safe inputs: validated on 18-item test set
      - Multi-segment analysis: splits on ; and quotes to reach injected suffix
      - "SELECT 1 +" prefix trick: makes UNION fragments parseable
      - Bare SELECT without FROM is NOT flagged (too many FP: date functions, etc.)
      - Thread safe: stateless, no shared mutable state
      - Max ~2ms per call on typical payloads (pure Python, no I/O)

    Usage:
        ast_layer = ASTLayer()
        hit, reason, node_type = ast_layer.check("' UNION SELECT password FROM users--")
        # hit=True, reason='Union', node_type='Union'
    """

    # Node types that are structurally dangerous as user-controlled SQL
    _DANGEROUS_NODES: tuple = ()   # populated in __init__ if sqlglot available

    # Dialects to attempt in order (None = auto-detect)
    _DIALECTS = (None, "tsql", "mysql", "postgres")

    def __init__(self) -> None:
        self._available = _SQLGLOT_AVAILABLE
        if self._available:
            self._DANGEROUS_NODES = (
                _sqlglot_exp.Union,
                _sqlglot_exp.Subquery,
                _sqlglot_exp.Drop,
                _sqlglot_exp.Delete,
                _sqlglot_exp.TruncateTable,
                _sqlglot_exp.Insert,
                _sqlglot_exp.Create,
                _sqlglot_exp.Update,
                _sqlglot_exp.Merge,
            )

    def check(self, text: str) -> tuple[bool, str, str]:
        """
        Analyse text for SQL structural patterns.

        Returns:
            (hit: bool, reason: str, node_type: str)

        Where:
            hit      = True if a dangerous SQL structure was found
            reason   = human-readable description (e.g. "UNION in AST")
            node_type = sqlglot node class name (e.g. "Union", "Drop")

        Returns (False, "", "") if sqlglot is unavailable or no match found.
        """
        if not self._available or not text:
            return False, "", ""

        # Build analysis candidates:
        # 1. Original text (catches bare SELECT/INSERT/DROP)
        # 2. Stacked query suffixes after semicolon
        # 3. Content after quotes (injected SQL suffix after closing the string literal)
        # 4. Prefixed candidates: "SELECT 1 <fragment>" makes UNION fragments parseable
        candidates: set[str] = set()
        candidates.add(text)

        for seg in text.split(";"):
            seg = seg.strip()
            if seg:
                candidates.add(seg)
                candidates.add("SELECT 1 " + seg)   # make UNION parseable

        for quote_char in ("'", '"'):
            for part in text.split(quote_char):
                part = part.strip()
                if part:
                    candidates.add(part)
                    candidates.add("SELECT 1 " + part)

        for candidate in candidates:
            result = self._try_parse(candidate)
            if result[0]:
                return result

        return False, "", ""

    def _try_parse(self, segment: str) -> tuple[bool, str, str]:
        """Attempt to parse segment in multiple dialects, return first match."""
        for dialect in self._DIALECTS:
            try:
                tree = _sqlglot.parse_one(
                    segment,
                    dialect=dialect,
                    error_level=_sqlglot.ErrorLevel.IGNORE,
                )
                if tree is None:
                    continue

                # SELECT with FROM clause = structurally valid SQL query in input
                if isinstance(tree, _sqlglot_exp.Select):
                    if tree.args.get("from_") is not None:
                        return True, "SELECT with FROM clause in AST", "Select"

                # Walk for dangerous node types
                for node in tree.walk():
                    if isinstance(node, self._DANGEROUS_NODES):
                        node_name = type(node).__name__
                        return True, f"{node_name} in AST", node_name

            except Exception:
                continue   # Never crash detection for AST errors

        return False, "", ""

    @property
    def available(self) -> bool:
        """True if sqlglot is installed and AST checking is active."""
        return self._available


# ═══════════════════════════════════════════════════════════════
#  PredictiveDefense — pre-request attack probability
# ═══════════════════════════════════════════════════════════════

class PredictiveDefense:
    """
    Predicts probability of attack BEFORE calling the detector.
    Returns a local multiplier (never mutates AgentConfig).
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config

    def predict_attack_probability(
        self,
        profile: IPProfile,
        session: SessionContext,
    ) -> float:
        """
        Heuristic attack probability [0.0, 1.0] based on:
          - Reputation score (known attacker history)
          - Field scanning pattern (≥3 unique fields in short time)
          - Attack type escalation (BOOLEAN → UNION → TIME_BASED = recon→exploit)
        """
        score = 0.0

        # Component 1: reputation (up to 0.3)
        score += profile.reputation_score * 0.3

        # Component 2: rapid field scanning (up to 0.3)
        if len(session.fields_probed) >= 3 and len(session.field_probe_times) >= 3:
            time_span = session.field_probe_times[-1] - session.field_probe_times[0]
            if time_span < 60:
                score += 0.3

        # Component 3: attack sequence escalation (up to 0.4)
        seq = session.attack_sequence
        if len(seq) >= 3:
            score += 0.4
        elif len(seq) >= 2:
            score += 0.25
        elif len(seq) >= 1:
            score += 0.1

        return min(score, 1.0)

    def get_tau_multiplier(self, prob: float) -> float:
        """
        Returns a LOCAL tau multiplier (do NOT write this to AgentConfig).
        Applied additively on top of reputation-based multiplier.
        """
        if not self.config.enable_predictive_defense:
            return 1.0
        if prob > self.config.predictive_threshold:
            return self.config.predictive_tau_boost  # e.g. 0.80
        return 1.0


# ═══════════════════════════════════════════════════════════════
#  SystemCoordinator — WAF/SIEM integration (no-op by default)
# ═══════════════════════════════════════════════════════════════

class SystemCoordinator:
    """
    Integrates with external systems via env-configured webhooks/APIs.
    No-op by default (no env vars → all calls are silent).
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._siem_url = config.siem_webhook_url
        self._intel_key = config.threat_intel_api_key

    def notify_block(
        self,
        ip: str,
        attack_type: str,
        severity: str,
        payload_hash: str,
        escalated: bool = False,
    ) -> None:
        """Send block notification to SIEM webhook (async-safe: fire-and-forget)."""
        if not self._siem_url:
            return
        try:
            import urllib.request
            payload = json.dumps({
                "event": "SQLI_BLOCK",
                "ip": ip,
                "attack_type": attack_type,
                "severity": severity,
                "payload_hash": payload_hash,
                "escalated": escalated,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }).encode()
            req = urllib.request.Request(
                self._siem_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass  # Never crash detection for SIEM errors

    def check_threat_intel(self, ip: str) -> dict:
        """
        Check AbuseIPDB for known malicious IPs.
        Returns dict with 'is_known_bad' and 'abuse_confidence_score'.
        """
        if not self._intel_key:
            return {"is_known_bad": False, "abuse_confidence_score": 0}
        try:
            import urllib.request
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
            req = urllib.request.Request(url, headers={
                "Key": self._intel_key,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
            confidence = data.get("data", {}).get("abuseConfidenceScore", 0)
            return {
                "is_known_bad": confidence >= 50,
                "abuse_confidence_score": confidence,
            }
        except Exception:
            return {"is_known_bad": False, "abuse_confidence_score": 0}


# ═══════════════════════════════════════════════════════════════
#  DecisionExplainer — human-readable + structured explanation
# ═══════════════════════════════════════════════════════════════

class DecisionExplainer:
    """
    Generates both a human-readable string and a structured explanation dict.

    Structured format enables dashboards/SIEM to parse contributing factors
    without regex-splitting the reason string.
    """

    def explain(
        self,
        base_result: dict,
        agent_context: dict,
    ) -> tuple[str, dict]:
        """
        Build explanation.

        Returns:
            (reason_str, contributing_factors_dict)

        reason_str example:
            "Score: 7.20 | Rule: RULE_1_HIGH_CONFIDENCE | Auto-ban: 3 attacks in window | Adaptive threshold (rep=0.82)"

        contributing_factors_dict example:
            {
                "detector_score": 7.20,
                "detector_rule": "RULE_1_HIGH_CONFIDENCE",
                "escalation_reason": "Auto-ban: 3 attacks in window",
                "adaptive_threshold": {"used": True, "reputation": 0.82},
                "predictive_defense": {"used": True, "probability": 0.91},
                "field_scanning": True,
            }
        """
        parts: list[str] = []
        factors: dict[str, Any] = {}

        # ── Detector score & rule ──────────────────────────────
        score = base_result.get("score", 0.0)
        parts.append(f"Score: {score:.2f}")
        factors["detector_score"] = round(score, 4)

        rule = base_result.get("rule", "")
        if rule:
            parts.append(f"Rule: {rule}")
            factors["detector_rule"] = rule

        # ── Escalation ─────────────────────────────────────────
        if agent_context.get("escalated"):
            reason = agent_context.get("escalation_reason", "")
            if reason:
                parts.append(reason)
            factors["escalation_reason"] = reason or None
        else:
            factors["escalation_reason"] = None

        # ── Adaptive threshold ─────────────────────────────────
        if agent_context.get("adaptive_threshold_used"):
            rep = agent_context.get("reputation_score", 0.0)
            parts.append(f"Adaptive threshold (rep={rep:.2f})")
            factors["adaptive_threshold"] = {"used": True, "reputation": round(rep, 4)}
        else:
            factors["adaptive_threshold"] = {"used": False}

        # ── Predictive defense ─────────────────────────────────
        prob = agent_context.get("predictive_probability", 0.0)
        if prob > 0.5:
            parts.append(f"Predictive defense (prob={prob:.2f})")
            factors["predictive_defense"] = {"used": True, "probability": round(prob, 4)}
        else:
            factors["predictive_defense"] = {"used": False, "probability": round(prob, 4)}

        # ── Field scanning ─────────────────────────────────────
        field_scanning = bool(agent_context.get("field_scanning_detected"))
        if field_scanning:
            parts.append("Field scanning pattern detected")
        factors["field_scanning"] = field_scanning

        # ── Signature hit ──────────────────────────────────────
        sig_hit = bool(agent_context.get("signature_hit"))
        if sig_hit:
            sig = agent_context.get("signature_pattern", "")
            factors["signature_match"] = sig[:80] if sig else True
        else:
            factors["signature_match"] = None

        # ── AST layer hit ──────────────────────────────────────
        ast_hit = bool(agent_context.get("ast_hit"))
        if ast_hit:
            factors["ast_match"] = {
                "hit": True,
                "reason": agent_context.get("ast_reason", ""),
                "node_type": agent_context.get("ast_node_type", ""),
            }
            parts.append(f"AST: {agent_context.get('ast_reason', 'SQL structure')}")
        else:
            factors["ast_match"] = {"hit": False}

        reason_str = " | ".join(parts)
        return reason_str, factors


# ═══════════════════════════════════════════════════════════════
#  SQLiAgent — the main autonomous agent
# ═══════════════════════════════════════════════════════════════

class SQLiAgent:
    """
    Autonomous SQL injection protection agent.

    Wraps SQLInjectionEnsemble and adds memory, escalation, adaptive thresholds,
    online learning, predictive defense, coordination, and explainability.

    Thread safe: uses RLock inside IPMemory and SessionMemory.
    Persistent: pass an AgentStore to survive server restarts.

    Operates autonomously 99% of the time. Human review only needed for
    edge-case false positive feedback via /api/agent/feedback.
    """

    def __init__(
        self,
        detector: SQLInjectionEnsemble,
        config: AgentConfig | None = None,
        store: "AgentStore | None" = None,
    ) -> None:
        self.detector = detector
        self.config = _agent_config_from_env(config)
        self.store = store  # optional persistence layer

        # Sub-components
        self.ip_memory = IPMemory(
            ttl=self.config.ip_memory_ttl_seconds,
            max_ips=self.config.max_tracked_ips,
        )
        self.session_memory = SessionMemory(ttl=self.config.session_memory_ttl_seconds)
        self.online_learner = OnlineLearning(config=self.config)
        self.ast_layer = ASTLayer()              # Layer 1.5: sqlglot AST pre-check
        self.predictor = PredictiveDefense(config=self.config)
        self.coordinator = SystemCoordinator(config=self.config)
        self.explainer = DecisionExplainer()

        # Agent-level statistics
        self._stats: dict[str, int] = defaultdict(int)

        # Wire LRU eviction callback so SQLiAgent can count evictions
        self.ip_memory._eviction_callback = lambda n: self._stats.__setitem__(
            "lru_evictions", self._stats["lru_evictions"] + n
        )

    # ═══════════════════════════════════════════════════════════
    #  Main entry point
    # ═══════════════════════════════════════════════════════════

    def evaluate(
        self,
        text: str,
        source_ip: str | None = None,
        session_id: str | None = None,
        endpoint: str | None = None,
        field_name: str | None = None,
        http_method: str | None = None,
    ) -> dict:
        """
        Evaluate text for SQL injection with full agent context.

        Returns detector result extended with agent_* fields.
        Falls back to pure detector mode if source_ip is None/"unknown".
        """
        # Normalize IP — None/"unknown" → pure detector mode
        _ip = source_ip if (source_ip and source_ip != "unknown") else None

        if _ip is None:
            # ── FALLBACK: no IP context ───────────────────────
            base = self.detector.detect(
                text,
                source_ip=source_ip,
                endpoint=endpoint,
                field_name=field_name,
                http_method=http_method,
            )
            return self._wrap_no_ip(base)

        # ── Full agent pipeline ────────────────────────────────

        # Step 1: Load memory (under IP lock for consistency)
        with self.ip_memory._lock:
            profile = self.ip_memory.get_profile(_ip)

        _sid = session_id or f"auto-{_ip}"
        with self.session_memory._lock:
            session = self.session_memory.get_or_create(_sid)

        # Step 2: Rule A — immediate ban check (no detector call)
        if self.ip_memory.is_banned(_ip):
            return self._make_ban_response(
                text, _ip, profile, session, endpoint, field_name
            )

        # Step 3: Predictive defense — compute LOCAL multiplier
        with self.ip_memory._lock, self.session_memory._lock:
            predict_prob = self.predictor.predict_attack_probability(profile, session)
        predictive_multiplier = self.predictor.get_tau_multiplier(predict_prob)

        # Step 4: Signature pre-check (fast path, before ML)
        sig_hit, sig_pattern = self.online_learner.check_signatures(text)

        # Step 4.5: AST structural analysis (Layer 1.5 — sqlglot)
        # Catches structurally valid SQL (UNION SELECT, stacked DROP, etc.)
        # that regex signatures may miss.  Runs only if sqlglot is installed.
        ast_hit, ast_reason, ast_node_type = self.ast_layer.check(text)
        if ast_hit:
            self._stats["ast_layer_hits"] += 1

        # Step 5: Adapted detector (shared ML models, modified thresholds)
        with self.ip_memory._lock:
            adapted_det = self._get_adapted_detector(
                profile, endpoint, extra_multiplier=predictive_multiplier
            )
        base_result = adapted_det.detect(
            text,
            source_ip=_ip,
            endpoint=endpoint,
            field_name=field_name,
            http_method=http_method,
        )

        # Step 6: Escalation rules (B, C, E)
        agent_context: dict[str, Any] = {
            "predictive_probability": predict_prob,
            "predictive_multiplier": predictive_multiplier,
            "signature_hit": sig_hit,
            "signature_pattern": sig_pattern,
            "ast_hit": ast_hit,
            "ast_reason": ast_reason,
            "ast_node_type": ast_node_type,
            "escalated": False,
            "escalation_reason": "",
            "adaptive_threshold_used": adapted_det is not self.detector,
            "reputation_score": profile.reputation_score,
            "ban_triggered": False,
            "ban_reason": "",
            "field_scanning_detected": False,
        }

        final_result = self._escalate_decision(
            base_result, profile, session, _ip, endpoint, field_name, agent_context
        )

        # Step 7: Online learning (post-decision)
        if self.config.enable_online_learning:
            ad = final_result.get("agent_decision", "SAFE")
            if ad == "INJECTION":
                self.online_learner.learn_from_blocked_attack(text, profile)
            # Blend online probability for known attackers
            if profile.attack_count >= 3:
                p_online = self.online_learner.get_online_probability(text)
                if (p_online is not None
                        and p_online > 0.7
                        and final_result.get("agent_decision") == "SAFE"):
                    final_result["agent_decision"] = "SUSPICIOUS"
                    final_result["agent_action"] = "CHALLENGE"
                    agent_context["escalated"] = True
                    agent_context["escalation_reason"] = (
                        f"Online ML layer: P_injection={p_online:.2f}"
                    )
                    self._stats["online_layer_escalations"] += 1

        # Step 8: System coordination
        if final_result.get("agent_action") in ("BLOCK", "ALERT"):
            payload_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
            self.coordinator.notify_block(
                ip=_ip,
                attack_type=base_result.get("attack_type", "UNKNOWN"),
                severity=base_result.get("severity", "MEDIUM"),
                payload_hash=payload_hash,
                escalated=agent_context.get("escalated", False),
            )

        # Step 9: Update memory
        self.ip_memory.update(_ip, final_result, endpoint, field_name)
        self.session_memory.update(_sid, final_result, field_name)

        # Step 10: Explainability (string + structured)
        agent_reason, contributing_factors = self.explainer.explain(base_result, agent_context)
        final_result["agent_reason"] = agent_reason
        final_result["contributing_factors"] = contributing_factors

        # Step 11: Attach structured context
        self._stats["total_evaluated"] += 1
        with self.ip_memory._lock:
            final_result["ip_profile"] = self.ip_memory.profile_to_dict(
                self.ip_memory.get_profile(_ip)
            )
        with self.session_memory._lock:
            final_result["session_context"] = {
                "escalation_level": session.escalation_level,
                "fields_probed_count": len(session.fields_probed),
                "attack_sequence": session.attack_sequence[-5:],  # last 5
            }

        return final_result

    # ═══════════════════════════════════════════════════════════
    #  Adaptive threshold — creates temp detector (shared models)
    # ═══════════════════════════════════════════════════════════

    def _get_adapted_detector(
        self,
        profile: IPProfile,
        endpoint: str | None,
        extra_multiplier: float = 1.0,
    ) -> SQLInjectionEnsemble:
        """
        Create a temporary detector instance with lowered tau thresholds
        for suspicious IPs. Model objects are shared (no copying).

        Never modifies self.config or self.detector.config.
        extra_multiplier: from PredictiveDefense (local variable, not stored).
        NOTE: caller must hold ip_memory._lock when reading profile fields.
        """
        if not self.config.enable_adaptive_thresholds:
            return self.detector

        # Compute combined local multiplier
        multiplier = 1.0

        # Rule D: reputation-based adaptation
        if profile.reputation_score > 0.5:
            multiplier *= self.config.reputation_tau_multiplier  # e.g. × 0.75

        # Rule F: repeat attack on same endpoint
        if endpoint and endpoint in profile.endpoints_targeted and profile.attack_count >= 1:
            multiplier *= 0.85

        # Predictive defense (Rule D+ extension)
        multiplier *= extra_multiplier  # e.g. × 0.80 from predictive

        # Floor: never reduce tau below 50% of baseline
        multiplier = max(multiplier, 0.5)

        # Only create adapted instance if thresholds actually change
        if abs(multiplier - 1.0) < 0.01:
            return self.detector

        self._stats["adaptive_threshold_triggers"] += 1

        # Build adapted config (copy all fields except tau_*)
        base_cfg = self.detector.config
        adapted_cfg = EnsembleConfig(
            **{k: v for k, v in dataclasses.asdict(base_cfg).items()
               if k not in ("tau_high", "tau_low", "tau_safe")}
        )
        adapted_cfg.tau_high = base_cfg.tau_high * multiplier
        adapted_cfg.tau_low = base_cfg.tau_low * multiplier
        adapted_cfg.tau_safe = base_cfg.tau_safe * multiplier

        # Create lightweight instance that SHARES loaded model objects
        tmp = SQLInjectionEnsemble(config=adapted_cfg)
        tmp.rf_model = self.detector.rf_model
        tmp.rf_vectorizer = self.detector.rf_vectorizer
        tmp.cnn_model = self.detector.cnn_model
        tmp.char_tokenizer = self.detector.char_tokenizer
        tmp.rf_loaded = self.detector.rf_loaded
        tmp.cnn_loaded = self.detector.cnn_loaded

        return tmp

    # ═══════════════════════════════════════════════════════════
    #  Escalation rules
    # ═══════════════════════════════════════════════════════════

    def _escalate_decision(
        self,
        base_result: dict,
        profile: IPProfile,
        session: SessionContext,
        ip: str,
        endpoint: str | None,
        field_name: str | None,
        agent_context: dict,
    ) -> dict:
        """
        Apply agent escalation rules on top of base detector result.
        Rules B, C, E (Rule A already handled before detector call).
        Returns a new result dict with agent_decision/agent_action added.
        """
        result = dict(base_result)
        now = time.time()

        base_decision = base_result.get("decision", "SAFE")
        base_action = base_result.get("action", "ALLOW")

        agent_decision = base_decision
        agent_action = base_action

        # ── Rule B: Auto-ban by attack frequency ───────────────
        # TIME-based window filter (not just maxlen)
        with self.ip_memory._lock:
            recent_in_window = [
                t for t in profile.recent_attacks
                if now - t <= self.config.ip_attack_window_seconds
            ]

        if len(recent_in_window) >= self.config.ip_attack_threshold:
            self.ip_memory.ban(ip, self.config.ip_ban_duration_seconds)
            self._stats["auto_bans"] += 1
            agent_decision = "INJECTION"
            agent_action = "BLOCK"
            agent_context["escalated"] = True
            agent_context["ban_triggered"] = True
            agent_context["ban_reason"] = (
                f"{len(recent_in_window)} attacks in "
                f"{self.config.ip_attack_window_seconds}s"
            )
            agent_context["escalation_reason"] = (
                f"Auto-ban: {len(recent_in_window)} attacks in window"
            )
            self._stats["escalations"] += 1

        # ── Rule C: SUSPICIOUS escalation ─────────────────────
        elif base_decision == "SUSPICIOUS":
            with self.ip_memory._lock:
                recent_susp_in_window = [
                    t for t in profile.recent_suspicious
                    if now - t <= self.config.suspicious_window_seconds
                ]
            if len(recent_susp_in_window) >= self.config.suspicious_escalation_count:
                agent_decision = "INJECTION"
                agent_action = "BLOCK"
                agent_context["escalated"] = True
                agent_context["escalation_reason"] = (
                    f"Escalated: {len(recent_susp_in_window)} suspicious requests in window"
                )
                self._stats["escalations"] += 1
                self._stats["suspicious_escalations"] += 1

        # ── Rule E: Field scanning pattern ─────────────────────
        unique_fields_recent = set()
        with self.session_memory._lock:
            if len(session.field_probe_times) >= 3:
                recent_field_times = [
                    (f, t) for f, t in zip(session.fields_probed, session.field_probe_times)
                    if now - t <= 60
                ]
                unique_fields_recent = {f for f, _ in recent_field_times}

        if len(unique_fields_recent) >= 3:
            agent_context["field_scanning_detected"] = True
            if agent_decision == "SAFE":
                agent_decision = "SUSPICIOUS"
                agent_action = "CHALLENGE"
                agent_context["escalated"] = True
                agent_context["escalation_reason"] = (
                    f"Field scanning: {len(unique_fields_recent)} unique fields in 60s"
                )
                self._stats["escalations"] += 1

        # ── Signature hit boost ────────────────────────────────
        if agent_context.get("signature_hit") and agent_decision == "SAFE":
            agent_decision = "SUSPICIOUS"
            agent_action = "CHALLENGE"
            agent_context["escalated"] = True
            agent_context["escalation_reason"] = (
                f"Signature match: {agent_context.get('signature_pattern', '')[:60]}"
            )
            self._stats["signature_escalations"] += 1

        # ── AST layer escalation (Layer 1.5 — sqlglot) ─────────
        # Escalates SAFE→SUSPICIOUS on structural SQL detection.
        # Escalates SUSPICIOUS→INJECTION on structural SQL (high confidence
        # structural match + prior suspicious signal = confirmed).
        if agent_context.get("ast_hit"):
            if agent_decision == "SAFE":
                agent_decision = "SUSPICIOUS"
                agent_action = "CHALLENGE"
                agent_context["escalated"] = True
                agent_context["escalation_reason"] = (
                    f"AST layer: {agent_context.get('ast_reason', 'SQL structure detected')}"
                )
                self._stats["ast_escalations"] += 1
            elif agent_decision == "SUSPICIOUS":
                # AST hit on already-suspicious input → promote to INJECTION
                agent_decision = "INJECTION"
                agent_action = "BLOCK"
                agent_context["escalated"] = True
                agent_context["escalation_reason"] = (
                    f"AST layer + suspicious: {agent_context.get('ast_reason', '')}"
                )
                self._stats["ast_escalations"] += 1

        result["agent_decision"] = agent_decision
        result["agent_action"] = agent_action
        result["escalated"] = agent_context["escalated"]
        result["adaptive_threshold_used"] = agent_context["adaptive_threshold_used"]

        return result

    # ═══════════════════════════════════════════════════════════
    #  Banned IP fast-path
    # ═══════════════════════════════════════════════════════════

    def _make_ban_response(
        self,
        text: str,
        ip: str,
        profile: IPProfile,
        session: SessionContext,
        endpoint: str | None,
        field_name: str | None,
    ) -> dict:
        """Return a pre-built BLOCK response for banned IPs (no detector call)."""
        self._stats["ban_blocks"] += 1
        ban_until_str = ""
        with self.ip_memory._lock:
            if profile.ban_until:
                ban_until_str = datetime.fromtimestamp(
                    profile.ban_until, tz=timezone.utc
                ).isoformat()
            ip_profile_dict = self.ip_memory.profile_to_dict(profile)

        with self.session_memory._lock:
            session_ctx = {
                "escalation_level": session.escalation_level,
                "fields_probed_count": len(session.fields_probed),
                "attack_sequence": session.attack_sequence[-5:],
            }

        contributing_factors: dict[str, Any] = {
            "detector_score": 10.0,
            "detector_rule": "AGENT_RULE_A_BAN",
            "escalation_reason": f"IP banned until {ban_until_str}",
            "adaptive_threshold": {"used": False},
            "predictive_defense": {"used": False, "probability": 0.0},
            "field_scanning": False,
            "signature_match": None,
        }

        return {
            # Mimic detector result structure
            "decision": "INJECTION",
            "action": "BLOCK",
            "score": 10.0,
            "P_rf": 1.0,
            "P_cnn": 1.0,
            "semantic_score": 10.0,
            "confidence_level": "HIGH",
            "severity": "CRITICAL",
            "attack_type": "BLOCKED_IP",
            "reason": f"IP {ip} is banned until {ban_until_str}",
            "rule": "AGENT_RULE_A_BAN",
            "evidence": [f"IP banned until {ban_until_str}"],
            "breakdown": {},
            "explanation": {"rule": "AGENT_RULE_A_BAN", "reason": "IP in ban list"},
            "siem_fields": {"agent_ban": True, "ban_until": ban_until_str},
            # Agent fields
            "agent_decision": "INJECTION",
            "agent_action": "BLOCK",
            "agent_reason": f"IP banned until {ban_until_str}",
            "contributing_factors": contributing_factors,
            "escalated": False,  # was already banned
            "adaptive_threshold_used": False,
            "ip_profile": ip_profile_dict,
            "session_context": session_ctx,
        }

    # ═══════════════════════════════════════════════════════════
    #  No-IP fallback wrapper
    # ═══════════════════════════════════════════════════════════

    def _wrap_no_ip(self, base_result: dict) -> dict:
        """Add agent_* fields with neutral defaults when no IP is available."""
        result = dict(base_result)
        result["agent_decision"] = base_result.get("decision", "SAFE")
        result["agent_action"] = base_result.get("action", "ALLOW")
        result["agent_reason"] = "No IP context — pure detector mode"
        result["contributing_factors"] = {
            "detector_score": round(base_result.get("score", 0.0), 4),
            "detector_rule": base_result.get("rule", ""),
            "escalation_reason": None,
            "adaptive_threshold": {"used": False},
            "predictive_defense": {"used": False, "probability": 0.0},
            "field_scanning": False,
            "signature_match": None,
        }
        result["escalated"] = False
        result["adaptive_threshold_used"] = False
        result["ip_profile"] = None
        result["session_context"] = None
        return result

    # ═══════════════════════════════════════════════════════════
    #  Public reporting API
    # ═══════════════════════════════════════════════════════════

    def get_ip_report(self, ip: str) -> dict:
        """Return full IP profile report for analyst dashboard."""
        with self.ip_memory._lock:
            profile = self.ip_memory.get_profile(ip)
            return self.ip_memory.profile_to_dict(profile)

    def get_stats(self) -> dict:
        """Return agent-level operational statistics."""
        return {
            "total_evaluated": self._stats["total_evaluated"],
            "escalations": self._stats["escalations"],
            "suspicious_escalations": self._stats["suspicious_escalations"],
            "auto_bans": self._stats["auto_bans"],
            "ban_blocks": self._stats["ban_blocks"],
            "adaptive_threshold_triggers": self._stats["adaptive_threshold_triggers"],
            "signature_escalations": self._stats["signature_escalations"],
            "online_layer_escalations": self._stats["online_layer_escalations"],
            "ast_layer": {
                "available": self.ast_layer.available,
                "hits": self._stats["ast_layer_hits"],
                "escalations": self._stats["ast_escalations"],
            },
            "online_learning": {
                "patterns_learned": self.online_learner.metrics["patterns_learned"],
                "false_positives_corrected": self.online_learner.metrics["false_positives_corrected"],
                "incremental_fits": self.online_learner.metrics["incremental_fits"],
                "sgd_trained_examples": self.online_learner.metrics["sgd_trained_examples"],
                "sgd_available": _SKLEARN_AVAILABLE,
                "sgd_fitted": self.online_learner._is_fitted,
            },
            "memory": {
                "tracked_ips": len(self.ip_memory._profiles),
                "tracked_sessions": len(self.session_memory._sessions),
                "active_bans": self.ip_memory.count_active_bans(),
                "mean_reputation": round(self.ip_memory.mean_reputation(), 4),
                "max_tracked_ips": self.ip_memory._max_ips,
                "lru_evictions": self._stats["lru_evictions"],
            },
            "persistence": {
                "store_configured": self.store is not None,
                "store_path": self.store.db_path if self.store else None,
            },
        }

    def learn_false_positive(self, text: str, matched_pattern: str | None = None) -> None:
        """Public API for analyst feedback: mark a detection as false positive."""
        self.online_learner.learn_from_false_positive(text, matched_pattern)

    def update_prometheus_gauges(self) -> None:
        """
        Update Prometheus gauges with current agent state.
        Called from cleanup loop and on demand.
        Fails silently if metrics module is not available.
        """
        try:
            from metrics import metrics as app_metrics
            app_metrics.agent_active_bans.set(self.ip_memory.count_active_bans())
            app_metrics.agent_tracked_ips.set(len(self.ip_memory._profiles))
            app_metrics.agent_tracked_sessions.set(len(self.session_memory._sessions))
            app_metrics.agent_mean_reputation.set(self.ip_memory.mean_reputation())
        except Exception:
            pass  # Never crash agent for metrics errors


# ═══════════════════════════════════════════════════════════════
#  Async cleanup + persistence loop (for api_server.py lifespan)
# ═══════════════════════════════════════════════════════════════

async def agent_cleanup_loop(
    agent: SQLiAgent,
    interval_seconds: int = 300,
) -> None:
    """
    Background asyncio task:
      1. Clean up stale IP/session memory every N seconds
      2. Flush agent state to SQLite (if store configured)
      3. Update Prometheus gauges

    Usage in api_server.py lifespan:
        import asyncio
        from agent import agent_cleanup_loop
        asyncio.create_task(agent_cleanup_loop(agent))
    """
    import asyncio
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            # 1. Memory cleanup
            ips_cleaned = agent.ip_memory.cleanup_stale()
            sessions_cleaned = agent.session_memory.cleanup_stale()

            # 2. Persistence flush
            if agent.store is not None:
                saved = agent.store.flush(
                    agent,
                    min_attacks=agent.config.persist_min_attacks,
                )
                if saved > 0:
                    try:
                        from metrics import metrics as app_metrics
                        app_metrics.agent_persistence_saves.inc()
                    except Exception:
                        pass

            # 3. Prometheus gauges
            agent.update_prometheus_gauges()

        except Exception:
            pass  # Never crash background task


# ═══════════════════════════════════════════════════════════════
#  Demo / self-test
# ═══════════════════════════════════════════════════════════════

def _demo_run():
    """
    Interactive demo: simulates escalating attack from a single IP.
    Shows agent memory, reputation buildup, auto-ban trigger, and persistence.
    """
    import tempfile, os

    print("\n" + "=" * 70)
    print("  SQLi Protection AI Agent v2.0 — Production Demo")
    print("  Escalating attack from 192.168.1.100 -> auto-ban + SQLite save")
    print("=" * 70 + "\n")

    # Initialize with in-memory SQLite for demo
    db_fd, db_path = tempfile.mkstemp(suffix=".db", prefix="agent_demo_")
    os.close(db_fd)

    print("Loading detector...")
    detector = SQLInjectionEnsemble()
    store = AgentStore(db_path)
    agent = SQLiAgent(detector, store=store)
    print(f"Agent ready. Store: {db_path}\n")

    ATTACKER_IP = "192.168.1.100"
    LEGITIMATE_IP = "10.0.0.50"

    test_cases = [
        # (text, ip, session, endpoint, field, label)
        ("john_doe",                                       LEGITIMATE_IP,  "sess-legit", "/login",    "username", "Legitimate request"),
        ("SELECT * FROM users WHERE id=1",                 ATTACKER_IP,    "sess-atk",   "/login",    "username", "Attack 1: basic SELECT"),
        ("' OR '1'='1",                                    ATTACKER_IP,    "sess-atk",   "/login",    "username", "Attack 2: tautology"),
        ("' OR '1'='1",                                    ATTACKER_IP,    "sess-atk",   "/search",   "q",        "Attack 3: same tautology, new field"),
        ("admin'--",                                       ATTACKER_IP,    "sess-atk",   "/search",   "q",        "Attack 4: comment injection"),
        ("1 UNION SELECT password FROM users--",           ATTACKER_IP,    "sess-atk",   "/api/items","id",       "Attack 5: UNION SELECT"),
        ("hello world",                                    LEGITIMATE_IP,  "sess-legit", "/search",   "q",        "Legitimate between attacks"),
        ("'; DROP TABLE users--",                          ATTACKER_IP,    "sess-atk",   "/api/items","id",       "Attack 6: DROP TABLE"),
        ("1=1",                                            ATTACKER_IP,    "sess-atk",   "/profile",  "name",     "Attack 7: simple tautology"),
        ("SELECT version()",                               ATTACKER_IP,    "sess-atk",   "/profile",  "bio",      "Attack 8: version probe"),
        ("anything",                                       ATTACKER_IP,    "sess-atk",   "/profile",  "bio",      "Post-ban request (should be blocked by ban)"),
    ]

    for i, (text, ip, session, endpoint, field, label) in enumerate(test_cases, 1):
        print(f"[{i:2d}] {label}")
        print(f"     IP={ip}  Text: {text[:50]!r}")

        result = agent.evaluate(
            text,
            source_ip=ip,
            session_id=session,
            endpoint=endpoint,
            field_name=field,
        )

        agent_dec = result.get("agent_decision", "SAFE")
        agent_act = result.get("agent_action", "ALLOW")
        escalated = result.get("escalated", False)
        agent_reason = result.get("agent_reason", "")

        status_icon = {
            "INJECTION": "[BLOCK]",
            "SUSPICIOUS": "[WARN] ",
            "SAFE": "[OK]   ",
            "INVALID": "[INV]  ",
        }.get(agent_dec, "[?]")

        print(f"     {status_icon} {agent_dec} -> {agent_act}"
              + (" [ESCALATED]" if escalated else ""))
        print(f"     Reason: {agent_reason}")

        if ip == ATTACKER_IP and result.get("ip_profile"):
            prof = result["ip_profile"]
            print(f"     IP profile: attacks={prof['attack_count']}, "
                  f"rep={prof['reputation_score']:.3f}, "
                  f"banned={prof['is_banned']}")

        # Show structured factors on escalations
        if escalated and result.get("contributing_factors"):
            factors = result["contributing_factors"]
            if factors.get("escalation_reason"):
                print(f"     Factors: {factors['escalation_reason']}")

        print()

    # Test persistence: flush and reload
    print("-" * 70)
    print("Testing persistence: flush -> reload -> verify ban survives restart")
    saved = store.flush(agent)
    print(f"  Flushed {saved} profiles to {db_path}")

    # Simulate restart
    detector2 = SQLInjectionEnsemble()
    store2 = AgentStore(db_path)
    agent2 = SQLiAgent(detector2, store=store2)
    loaded = store2.load_into(agent2)
    print(f"  Loaded {loaded} profiles on 'restart'")

    # Verify ban survived
    still_banned = agent2.ip_memory.is_banned(ATTACKER_IP)
    print(f"  Attacker {ATTACKER_IP} still banned after restart: {still_banned}")
    print()

    print("-" * 70)
    print("Agent statistics:")
    stats = agent.get_stats()
    for k, v in stats.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for kk, vv in v.items():
                print(f"    {kk}: {vv}")
        else:
            print(f"  {k}: {v}")

    print("\n[DONE] Demo complete.")
    print(f"[CLEANUP] Removing temp DB: {db_path}")
    try:
        os.unlink(db_path)
    except Exception:
        pass
    print()


if __name__ == "__main__":
    _demo_run()
