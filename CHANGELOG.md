# CHANGELOG — SQL Injection Protector

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.9.0] — 2026-02-25

### Added
- **`soak_test.py`** — long-running stability test (memory + latency drift profiling)
  - Multiprocessing architecture: one writer process + main monitor loop
  - Metrics: RSS growth, p50/p95/p99 latency, 10-second sampling windows for drift
  - PASS/FAIL checks: no crash, RSS growth ≤ 150 MB, p99 drift ≤ 100 ms,
    error rate ≤ 0.1%, throughput ≥ 70% of target RPS
  - Args: `--duration` (default 300s), `--rps` (default 5.0), `--output` (JSON report)
  - Supports 5-minute CI mode and 24-hour full soak mode
- **`load_test.py`** — high-throughput load test via real multiprocessing
  - N parallel worker processes (no GIL contention) each running full detector + agent
  - Per-worker + aggregate latency: p50/p95/p99/max across all workers merged via heapq
  - ASCII histogram of merged latency distribution (10 buckets)
  - Per-worker breakdown table: requests, errors, RPS, p50, p99, RSS growth
  - Ramp-up mode: `--ramp-seconds` staggers worker start to simulate gradual traffic
  - PASS/FAIL checks: no crash, SLA p99 ≤ threshold, error rate OK, ≥ 1000 RPS aggregate
  - Args: `--workers` (default 4), `--requests` (default 1000), `--sla-p99-ms` (default 100),
    `--ramp-seconds` (default 0)
  - JSON report output; each worker uses isolated SQLite DB (no lock contention)
- **`SECURITY_WHITEPAPER.md`** — formal security documentation
  - System architecture diagram (5-layer pipeline + data flow)
  - Threat model: assets, threat actors, trust boundaries, attack surface
  - Per-layer security analysis (normalisation, signature, AST, ML ensemble, behavioral)
  - Behavioral defense: IP reputation mechanics, online learning poisoning risk
  - State backend security: SQLite permissions, Redis AUTH/TLS requirements,
    deserialization risk for joblib SGD blob
  - API security: endpoint inventory, input validation gaps, header trust
  - Test coverage summary: 598 tests across 7 test files
  - Residual risks: 7 documented gaps with exploitability ratings and mitigations
  - Deployment hardening checklist (24 items across infrastructure, Redis, SQLite,
    model files, API, monitoring)
  - Compliance notes: OWASP A03:2021, NIST SP 800-53 SI-10, data minimisation

### Test Results
```
598 passed, 1 skipped, 0 failed  (unchanged — no code changes in this release)
```
load_test.py: 4 workers x 50 req validated (0 errors, all workers returned)
soak_test.py: architecture verified (imports clean, worker process functional)

---

## [3.8.0] — 2026-02-24

### Added
- **`state_backend.py`** — pluggable persistence abstraction layer
  - `StateBackend` Protocol (`@runtime_checkable`) with 6 methods:
    `load_profiles`, `flush_profiles`, `load_sgd`, `save_sgd`, `ping`, `close`
  - `SQLiteBackend` — full implementation (refactored out of `AgentStore`)
  - `RedisBackend` — distributed backend for multi-worker deployments
    - IP profiles stored as Redis Hashes (`sqli:ip:<ip>`)
    - IP index in Redis Set (`sqli:ip:index`)
    - SGD model as binary blob (`sqli:sgd:model`, joblib compressed)
    - Configurable TTL (default 7 days), pipeline batch writes
    - Constructors: `from_env()`, `from_url()`
  - `NullBackend` — no-op for testing and stateless ephemeral deployments
  - `make_backend()` factory — reads `SQLI_BACKEND` env var, graceful
    fallback to SQLite if Redis unavailable or redis-py not installed
  - `AgentStore = SQLiteBackend` backward-compat alias in `state_backend.py`
- **`config.py`** — new `BackendConfig` dataclass
  - Fields: `backend_type`, `sqlite_path`, `redis_url`, `redis_host`,
    `redis_port`, `redis_db`, `redis_password`, `redis_ttl_days`
  - Full env var mapping: `SQLI_BACKEND`, `AGENT_STATE_DB`, `REDIS_URL`,
    `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `REDIS_PASSWORD`, `REDIS_TTL_DAYS`
  - `AppConfig.backend: BackendConfig` added to root config
- **`tests/test_state_backend.py`** — 42 tests across 7 groups
  - Protocol conformance, SQLite round-trip, NullBackend, factory fallback,
    AgentStore alias, RedisBackend (fakeredis), BackendConfig env parsing
- **`benchmark.py`** — performance benchmark script
  - Sequential and concurrent latency (p50/p95/p99/max)
  - Injection-only vs safe-only latency breakdown
  - RPS throughput measurement, SLA check (p99 < 100ms)
  - Args: `--samples`, `--warmup`, `--concurrency`
- **`model_metadata.json`** — ML reproducibility contract
  - `sklearn_version`, `tfidf_max_features`, `handcrafted_feature_count: 5`,
    `handcrafted_features` list, `rf_expected_features: 50005`,
    `rf_max_depth`, `feature_pipeline` description,
    `training_dataset_hash_sha256_prefix`, `reproduce_cmd`

### Changed
- **`agent.py`** — `AgentStore` class body removed, replaced with stub
  subclassing `SQLiteBackend`; backward-compatible import alias preserved:
  `from agent import AgentStore` still works without modification
- **`requirements.txt`** — `scikit-learn>=1.5.0` pinned to `scikit-learn==1.8.0`
  (models trained on 1.8.0; prevents silent inference drift on upgrades)
- **`api_server.py`** — `VERSION` bumped from `3.6.0` to `3.7.0`

### Fixed
- **sklearn `InconsistentVersionWarning`** — `rf_sql_model.pkl` and
  `tfidf_vectorizer.pkl` resaved on sklearn 1.8.0; warnings eliminated (448→0)
- **`tests/test_api.py`** — `test_health_has_version` hardcoded `"3.1.0"`
  updated to `"3.7.0"` to match actual server VERSION constant

### Test Results
```
598 passed, 1 skipped, 0 failed
```

---

## [3.7.0] — 2026-02-24

### Added
- **`test_fuzz.py`** — Fuzz & Property-based verification harness (199 tests)
  - **Section A**: Safety properties via Hypothesis (200 examples each):
    `never_crashes`, `required_keys`, `score_in_unit_interval`,
    `decision_in_enum`, `action_in_enum`, `alphanumeric_never_injection`,
    `email_never_injection`, `integer_never_injection`, `idempotency`
  - **Section B**: Adversarial corpus:
    - Case obfuscation (32 combinations: 4 templates × 8 seeds)
    - Comment insertion (`/**/` splitting)
    - Whitespace variants (tab, LF, CRLF, VT, FF, NBSP)
    - UNION with 1–10 column counts
    - Time-based blind payloads (MySQL, MSSQL, PostgreSQL)
    - String concatenation / CHR() / CHAR() obfuscation
    - Second-order injection patterns
  - **Section C**: False positive safety — 50+ benign corpus items
    (names with apostrophes, SQL keywords in prose, emails, addresses,
    URLs, hashed passwords, Unicode names)
  - **Section D**: Structural invariants — no crash on extreme inputs,
    monotonic scoring, AST hit visibility, numeric scores, RF/CNN in `[0,1]`
  - **Section E**: Mutation regression — 6 payloads × 8 single-char
    mutations (insert\_space, double\_char, swap\_case, add\_comment)
- `_fresh_ip()` helper — unique IP per Hypothesis example; eliminates
  cross-test IP-ban state contamination
- `VALID_ACTIONS` enum updated to include `"LOG"` (action for `INVALID` decision)

### Fixed
- **`VALID_ACTIONS` missing `"LOG"`** — `INVALID` decision maps to action
  `LOG`; enum was incomplete causing fuzz test failures on garbled inputs
- **IP ban cross-test contamination** — module-scoped agent now uses fresh
  IPs per evaluation; stateful side-effects eliminated

### Known Gaps (documented, not bugs)
- `S/**/E/**/L/**/E/**/C/**/T` char-level comment splitting — regex layer
  cannot recover fragmented tokens; AST cannot parse invalid SQL.
  Documented in corpus comments as design boundary.
- Pure hex payloads (`0x2720554e...`) without SQL structural context —
  hex-decode normalisation not implemented to avoid FP on binary data

### Test Results
```
381 tests collected and passing (pre-merge count)
448 passed, 1 skipped after full suite integration
```

---

## [3.6.0] — 2026-02-23

### Added
- **`AgentStore`** — SQLite persistence layer for IP profiles and SGD model
  - Schema: `ip_profiles` table (12 columns), `agent_meta` table
  - WAL mode + `synchronous=NORMAL` for concurrent read safety
  - `_flush_lock` — serialises concurrent flush() calls; prevents SGD
    file corruption from concurrent `joblib.dump()` calls
  - `load_into(agent, load_sgd=True)` — restores profiles + SGD on startup
  - `flush(agent, min_attacks=1, save_sgd=True)` — atomic SGD save via
    temp-file + `os.replace()` (atomic on POSIX; best-effort on Windows)
  - `save_sgd_model()` / `load_sgd_model()` — disk persistence for the
    online SGDClassifier layer
- Prometheus gauge updates on every `evaluate()` call (`agent_mean_reputation`)
- `cleanup_stale()` called from asyncio background task in `api_server.py`
- `LRU eviction` in `IPMemory` — evicts oldest non-banned IPs at
  `max_tracked_ips` capacity to bound memory usage
- **Kubernetes** deployment manifests (referenced in ARCHITECTURE doc)

### Changed
- `IPMemory` and `SessionMemory` use `threading.RLock` (was `Lock`)
  to prevent deadlock on re-entrant calls from same thread
- `PredictiveDefense` uses a local `multiplier` variable; never mutates
  `AgentConfig` (immutable config guarantee preserved)

### Fixed
- Race condition in `IPMemory.get_profile()` under concurrent load
- SGD file corruption on concurrent shutdown + periodic flush

---

## [3.5.0] — 2026-02-22

### Added
- **AST detection layer** via `sqlglot` — structural SQL parsing
  - Detects `UNION SELECT`, `DROP TABLE`, `INSERT INTO`, stacked queries
  - `ast_match` key in `contributing_factors` when AST fires
  - Graceful degradation if `sqlglot` not installed
- **Semantic scoring** — keyword-weighted signal (0–20 scale)
  - Weights per keyword class: UNION/SELECT=3, DROP/EXEC=4, SLEEP/WAITFOR=5
  - Used as gate: if `sem < tau_semantic_min` → override CNN
- **Model divergence guard** — when `|P_cnn - P_rf| > tau_model_divergence`
  and RF says safe → downgrade to SUSPICIOUS (prevents CNN FP amplification)
- **`contributing_factors`** structured dict alongside human-readable `reason`
- **`tests/test_detector.py`** — 163 parametrised tests
  - Known injection corpus (40+ payloads across 8 attack types)
  - False positive safety corpus (30+ benign inputs)
  - API contract tests (`/api/detect`, `/api/validate`, `/api/health`)

### Changed
- `EnsembleConfig` weights: `w_rf=0.35`, `w_cnn=0.65` (was 0.50/0.50)
- Decision logic refactored into `_ensemble_decision()` with 6 ordered rules
- `INVALID` decision added for garbled/non-SQL inputs; action=`LOG`

---

## [3.4.0] — 2026-02-21

### Added
- **`AgentConfig`** dataclass — all agent thresholds externalised
  (`ip_attack_threshold`, `ip_ban_duration_seconds`, `suspicious_escalation_count`,
  `reputation_tau_multiplier`, `persistence_flush_interval`, etc.)
- **`IPProfile`** — per-IP state with sliding-window deques for recent attacks
  (`maxlen=200`), `reputation_score`, `ban_until` timestamp
- **`IPMemory`** — thread-safe IP profile store with LRU eviction cap
- **`SessionMemory`** — per-session field scan and attack sequence tracking
- **`OnlineLearning`** — incremental `SGDClassifier` layer; self-trains on
  confirmed injections; prediction used as 3rd ensemble signal when fitted
- **`PredictiveDefense`** — pre-request attack probability from IP history
- **Behavioral escalation** rules:
  - Rule A: IP banned → BLOCK immediately (score=10)
  - Rule B: Attack frequency in window → auto-ban
  - Rule C: Suspicious escalation (N suspicious → BLOCK)
  - Rule D: Reputation-based threshold adaptation
- **`api_server.py`** — FastAPI server with lifespan context manager
  - `/api/detect`, `/api/validate` (batch), `/api/health`, `/metrics`
  - Background task: periodic flush + stale IP cleanup every 5 min
  - Emergency flush on shutdown via `atexit` + lifespan teardown
- **`incident_logger.py`** — SQLite-backed incident log with auto-cleanup

---

## [3.3.0] — 2026-02-20

### Added
- **CNN layer** — Character-level CNN (`CharCNN`) PyTorch model
  - `models/char_cnn_detector.pt` trained on synthetic + extended dataset
  - `training/train_cnn.py` — training script with early stopping
  - `training/cnn_training_log.json` — per-epoch metrics
- **BiLSTM layer** — `CharBiLSTM` alternative model
  - `training/train_bilstm.py` — gradient clipping, ReduceLROnPlateau
  - `training/bilstm_training_log.json`
- **`CharTokenizer`** — character-level tokenizer with `save()`/`load()`
  (`models/char_tokenizer.json`)

---

## [3.2.0] — 2026-02-19

### Added
- **`sql_injection_detector.py`** — `SQLInjectionEnsemble` core class
  - RF + CNN 2-model ensemble with configurable weights
  - Input normalisation pipeline: URL decode (depth-3), NFKC unicode,
    homoglyph substitution, null-byte strip, HTML entity decode
  - Comment stripping (`/* */`, `--`) before RF inference
  - `EnsembleConfig` — frozen dataclass for all ensemble thresholds
- **`config.py`** — externalised configuration with env var support
  - `AppConfig` root with `EnsembleConfig`, `APIConfig`, `LoggingConfig`,
    `NormalizationConfig`, `ModelPaths`, `IncidentConfig`
  - `get_config()` builder + `config()` singleton
- **`logger.py`** — structured JSON logging via structlog
- **`metrics.py`** — Prometheus metrics definitions
- **`SQL_Dataset_Extended.csv`** — augmented training dataset

---

## [3.1.0] — 2026-02-18

### Added
- **Random Forest layer** — `rf_sql_model.pkl` + `tfidf_vectorizer.pkl`
  - TF-IDF: char n-gram (2–5), `char_wb` analyser, `max_features=50000`,
    `sublinear_tf=True`
  - RF: 200 estimators, `max_depth=30`, `class_weight=balanced`
  - 5 hand-crafted numeric features: `length`, `num_digits`, `num_special`,
    `num_quotes`, `num_keywords` — hstacked with TF-IDF (50005 total)
  - `training/train_rf.py` — full training + evaluation pipeline
  - `training/rf_training_log.json` — metrics snapshot
- **Signature layer** — regex-based fast pre-filter
  - 40+ patterns across 8 attack categories
  - `BOOLEAN_BASED`, `UNION_BASED`, `TIME_BASED`, `STACKED_QUERY`,
    `COMMENT_TRUNCATION`, `OS_COMMAND`, `ERROR_BASED`, `BLIND`
- **`global_test.py`** — integration smoke test

---

## [3.0.0] — 2026-02-17

### Added
- Initial project structure
- `SQL_Dataset_Extended.csv` — 50k+ labelled SQL/safe samples
- `VDCNN_Model.ipynb` — VDCNN research notebook
- `training/generate_dataset.py` — synthetic dataset generator
- Basic detection prototype

---

*Maintained by the project team. Each version entry records what changed,
what was fixed, and what the test suite results were at release time.*
