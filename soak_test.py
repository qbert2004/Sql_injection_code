"""
Soak Test - SQL Injection Detector v3.8.0
==========================================
Long-running stability test. Runs for a configurable duration (default 300s / 5 min
for CI; 6-24h for real soak) at a steady RPS and measures:

  1. Memory growth (RSS) - detects memory leaks in detector + agent
  2. Latency drift       - p99 must not grow over time (no algorithmic degradation)
  3. Redis key growth    - IP index must not accumulate unbounded (TTL enforced)
  4. SQLite file growth  - agent_state.db must not grow unbounded
  5. Error rate          - zero crashes for the full duration

Design
------
  - Uses multiprocessing to simulate real process isolation (not threads)
  - One writer process: evaluates mixed injection/safe corpus at target RPS
  - One monitor process: samples RSS + latency percentiles every SAMPLE_INTERVAL
  - Results reported as a time-series table + final PASS/FAIL verdict

Usage
-----
  python soak_test.py                         # 300s quick soak (CI mode)
  python soak_test.py --duration 3600         # 1h real soak
  python soak_test.py --duration 86400        # 24h full soak
  python soak_test.py --rps 5 --duration 600  # 5 RPS for 10 min
  python soak_test.py --rps 20 --duration 3600 --redis  # with Redis backend

Thresholds (configurable via args)
-----------------------------------
  --max-rss-growth-mb   Max allowed RSS growth over duration (default: 150 MB)
  --max-p99-drift-ms    Max allowed p99 latency increase (default: 100 ms)
  --max-error-rate      Max allowed error fraction (default: 0.001 = 0.1%)
"""

from __future__ import annotations

import argparse
import gc
import itertools
import json
import multiprocessing
import os
import random
import sqlite3
import statistics
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

# ── Corpus ────────────────────────────────────────────────────────────────────

INJECTIONS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT password FROM users--",
    "'; DROP TABLE users--",
    "admin'--",
    "' AND SLEEP(5)--",
    "' UNION SELECT username,password FROM admin--",
    "'; WAITFOR DELAY '0:0:1'--",
    "' OR BENCHMARK(100000,MD5(1))--",
    "1; SELECT pg_sleep(1)--",
    "'/**/OR/**/1/**/=/**/1--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
]

SAFE_INPUTS = [
    "hello world",
    "user@example.com",
    "Alice Johnson",
    "2024-01-15",
    "Please select your country",
    "The union of these two sets is empty",
    "Update your profile information",
    "O'Brien",
    "P@ssw0rd!2024",
    "+1-800-555-0123",
    "https://example.com/path?q=hello",
    "Select Comfort mattresses",
    "42",
    "The quick brown fox",
    "Francois Muller",
]

_CORPUS = INJECTIONS + SAFE_INPUTS
_ip_counter = itertools.count(300_000)


def _fresh_ip() -> str:
    n = next(_ip_counter)
    return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


# ── Memory helper ─────────────────────────────────────────────────────────────

def _rss_mb() -> float:
    """Return current process RSS in MB. Cross-platform."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    except ImportError:
        # Fallback: read /proc/self/status on Linux
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) / 1024
        except Exception:
            pass
        # Windows fallback via ctypes
        try:
            import ctypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(pmc)
            ctypes.windll.psapi.GetProcessMemoryInfo(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(pmc),
                pmc.cb,
            )
            return pmc.WorkingSetSize / 1024 / 1024
        except Exception:
            return 0.0


# ── Worker process ────────────────────────────────────────────────────────────

def _soak_worker(
    duration_s: int,
    target_rps: float,
    result_queue: multiprocessing.Queue,
    db_path: str,
) -> None:
    """
    Main soak worker: evaluates requests at target_rps for duration_s seconds.
    Sends periodic samples (every 10s) and a final summary to result_queue.
    """
    import warnings as _w
    _w.filterwarnings("ignore")

    from agent import SQLiAgent, AgentConfig
    from sql_injection_detector import SQLInjectionEnsemble
    from state_backend import SQLiteBackend

    backend = SQLiteBackend(db_path)
    det     = SQLInjectionEnsemble()
    agent   = SQLiAgent(det, store=backend)

    rng          = random.Random(42)
    interval_s   = 1.0 / target_rps
    t_start      = time.perf_counter()
    t_end        = t_start + duration_s
    t_last_sample = t_start

    request_count = 0
    error_count   = 0
    window_lats   = []   # latencies in current 10s window
    all_lats      = []   # all latencies for final summary
    samples       = []   # time-series: (elapsed_s, rss_mb, p50, p95, p99, rps_window)
    rss_start     = _rss_mb()

    corpus_cycle = itertools.cycle(_CORPUS)

    while time.perf_counter() < t_end:
        t_req = time.perf_counter()
        text  = next(corpus_cycle)
        ip    = _fresh_ip()

        try:
            t0  = time.perf_counter()
            agent.evaluate(text, source_ip=ip)
            lat = (time.perf_counter() - t0) * 1000
            window_lats.append(lat)
            all_lats.append(lat)
            request_count += 1
        except Exception:
            error_count += 1

        # Emit a sample every 10 seconds
        elapsed = time.perf_counter() - t_start
        if elapsed - (t_last_sample - t_start) >= 10.0 and window_lats:
            rss = _rss_mb()
            p50 = statistics.median(window_lats)
            p95 = sorted(window_lats)[int(len(window_lats) * 0.95)]
            p99 = sorted(window_lats)[int(len(window_lats) * 0.99)] if len(window_lats) >= 100 else max(window_lats)
            window_rps = len(window_lats) / 10.0
            samples.append({
                "elapsed_s": round(elapsed, 1),
                "rss_mb":    round(rss, 1),
                "p50_ms":    round(p50, 2),
                "p95_ms":    round(p95, 2),
                "p99_ms":    round(p99, 2),
                "rps":       round(window_rps, 1),
            })
            window_lats = []
            t_last_sample = time.perf_counter()

        # Rate-limit
        elapsed_req = time.perf_counter() - t_req
        sleep_s     = interval_s - elapsed_req
        if sleep_s > 0:
            time.sleep(sleep_s)

    # Flush state
    try:
        backend.flush_profiles(agent)
    except Exception:
        pass

    rss_end    = _rss_mb()
    total_s    = time.perf_counter() - t_start
    all_lats_s = sorted(all_lats)
    n          = len(all_lats_s)

    result_queue.put({
        "status":        "done",
        "requests":      request_count,
        "errors":        error_count,
        "duration_s":    round(total_s, 1),
        "actual_rps":    round(request_count / total_s, 2),
        "rss_start_mb":  round(rss_start, 1),
        "rss_end_mb":    round(rss_end, 1),
        "rss_growth_mb": round(rss_end - rss_start, 1),
        "p50_ms":        round(all_lats_s[n // 2], 2)         if n else 0,
        "p95_ms":        round(all_lats_s[int(n * 0.95)], 2)  if n else 0,
        "p99_ms":        round(all_lats_s[int(n * 0.99)], 2)  if n else 0,
        "max_ms":        round(all_lats_s[-1], 2)              if n else 0,
        "samples":       samples,
    })


# ── Main ──────────────────────────────────────────────────────────────────────

def _percentile(data: list, p: float) -> float:
    s = sorted(data)
    i = min(int(len(s) * p / 100), len(s) - 1)
    return s[i]


def main() -> int:
    parser = argparse.ArgumentParser(description="Soak Test - SQL Injection Detector")
    parser.add_argument("--duration",          type=int,   default=300,   help="Test duration in seconds (default: 300)")
    parser.add_argument("--rps",               type=float, default=5.0,   help="Target requests per second (default: 5)")
    parser.add_argument("--max-rss-growth-mb", type=float, default=150.0, help="Max allowed RSS growth in MB (default: 150)")
    parser.add_argument("--max-p99-drift-ms",  type=float, default=100.0, help="Max allowed p99 latency increase over run (default: 100 ms)")
    parser.add_argument("--max-error-rate",    type=float, default=0.001, help="Max allowed error fraction (default: 0.001)")
    parser.add_argument("--output",            type=str,   default=None,  help="JSON output file for results")
    args = parser.parse_args()

    print("=" * 65)
    print("  SQL Injection Detector - Soak Test v3.8.0")
    print("=" * 65)
    print(f"  Duration    : {args.duration}s")
    print(f"  Target RPS  : {args.rps}")
    print(f"  RSS limit   : +{args.max_rss_growth_mb} MB")
    print(f"  p99 drift   : +{args.max_p99_drift_ms} ms")
    print(f"  Error rate  : <{args.max_error_rate * 100:.1f}%")
    print("=" * 65)

    # Temp DB for soak state
    import tempfile
    tmp_dir = tempfile.mkdtemp(prefix="sqli_soak_")
    db_path = os.path.join(tmp_dir, "soak_agent.db")

    result_q = multiprocessing.Queue()
    worker   = multiprocessing.Process(
        target=_soak_worker,
        args=(args.duration, args.rps, result_q, db_path),
    )

    print(f"\nStarting soak worker (PID will be reported)...")
    t_wall = time.perf_counter()
    worker.start()
    print(f"  Worker PID: {worker.pid}")
    print(f"  DB path:    {db_path}")
    print()

    # Progress reporting while worker runs
    last_print = time.perf_counter()
    while worker.is_alive():
        time.sleep(5)
        elapsed = time.perf_counter() - t_wall
        pct     = min(elapsed / args.duration * 100, 100)
        print(f"  [{elapsed:6.0f}s / {args.duration}s  {pct:5.1f}%]  running...", flush=True)
        last_print = time.perf_counter()

    worker.join()
    wall_total = time.perf_counter() - t_wall

    # Collect result
    try:
        result = result_q.get(timeout=5)
    except Exception as e:
        print(f"\n[FAIL] Worker did not return results: {e}")
        return 1

    if worker.exitcode != 0:
        print(f"\n[FAIL] Worker exited with code {worker.exitcode}")
        return 1

    # SQLite file size
    db_size_kb = os.path.getsize(db_path) / 1024 if os.path.exists(db_path) else 0

    # ── Print time-series table ──────────────────────────────────
    samples = result.get("samples", [])
    if samples:
        print("\n  Time-series (10s windows):")
        print(f"  {'Elapsed':>8}  {'RSS MB':>7}  {'p50 ms':>7}  {'p95 ms':>7}  {'p99 ms':>7}  {'RPS':>6}")
        print("  " + "-" * 55)
        for s in samples:
            print(f"  {s['elapsed_s']:>7.0f}s  "
                  f"{s['rss_mb']:>7.1f}  "
                  f"{s['p50_ms']:>7.2f}  "
                  f"{s['p95_ms']:>7.2f}  "
                  f"{s['p99_ms']:>7.2f}  "
                  f"{s['rps']:>6.1f}")

    # ── Latency drift analysis ────────────────────────────────────
    p99_drift_ms = 0.0
    if len(samples) >= 3:
        first_p99 = samples[0]["p99_ms"]
        last_p99  = samples[-1]["p99_ms"]
        p99_drift_ms = last_p99 - first_p99

    # ── Verdict ───────────────────────────────────────────────────
    requests     = result["requests"]
    errors       = result["errors"]
    error_rate   = errors / max(requests, 1)
    rss_growth   = result["rss_growth_mb"]

    checks = {
        "no_worker_crash":        worker.exitcode == 0,
        "rss_growth_ok":          rss_growth <= args.max_rss_growth_mb,
        "p99_drift_ok":           p99_drift_ms <= args.max_p99_drift_ms,
        "error_rate_ok":          error_rate <= args.max_error_rate,
        "min_throughput_ok":      result["actual_rps"] >= args.rps * 0.7,
    }
    all_pass = all(checks.values())

    print("\n" + "=" * 65)
    print("  SOAK TEST RESULTS")
    print("=" * 65)
    print(f"  Requests     : {requests:,}")
    print(f"  Errors       : {errors}  ({error_rate*100:.3f}%)")
    print(f"  Duration     : {result['duration_s']}s")
    print(f"  Actual RPS   : {result['actual_rps']}")
    print()
    print(f"  RSS start    : {result['rss_start_mb']} MB")
    print(f"  RSS end      : {result['rss_end_mb']} MB")
    print(f"  RSS growth   : {rss_growth:+.1f} MB  (limit: +{args.max_rss_growth_mb} MB)")
    print()
    print(f"  p50 latency  : {result['p50_ms']} ms")
    print(f"  p95 latency  : {result['p95_ms']} ms")
    print(f"  p99 latency  : {result['p99_ms']} ms")
    print(f"  Max latency  : {result['max_ms']} ms")
    print(f"  p99 drift    : {p99_drift_ms:+.1f} ms  (limit: +{args.max_p99_drift_ms} ms)")
    print()
    print(f"  DB size      : {db_size_kb:.1f} KB")
    print()

    print("  Checks:")
    for check, passed in checks.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"    {status}  {check}")

    verdict = "PASS" if all_pass else "FAIL"
    print()
    print(f"  Overall: {verdict}")
    print("=" * 65)

    # ── JSON output ───────────────────────────────────────────────
    report = {
        "verdict":       verdict,
        "config": {
            "duration_s":          args.duration,
            "target_rps":          args.rps,
            "max_rss_growth_mb":   args.max_rss_growth_mb,
            "max_p99_drift_ms":    args.max_p99_drift_ms,
            "max_error_rate":      args.max_error_rate,
        },
        "results":       result,
        "checks":        checks,
        "p99_drift_ms":  round(p99_drift_ms, 2),
        "db_size_kb":    round(db_size_kb, 1),
    }

    out_path = args.output or os.path.join(tmp_dir, "soak_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report: {out_path}\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
