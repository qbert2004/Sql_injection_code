"""
Load Test - SQL Injection Detector v3.8.0
==========================================
High-throughput load test using real process isolation (multiprocessing).
Targets 1000+ RPS across N workers and measures:

  - p50 / p95 / p99 / max latency (milliseconds, merged across all workers)
  - Aggregate throughput (RPS)
  - Per-worker throughput breakdown
  - CPU usage (process + system)
  - Memory (RSS) growth under load
  - Error rate
  - SLA verdict: p99 < 100 ms

Architecture
------------
  Main process
    +-- Worker-0  (Process)  evaluates corpus slice at full speed
    +-- Worker-1  (Process)  evaluates corpus slice at full speed
    +-- ...
    +-- Worker-N  (Process)  evaluates corpus slice at full speed
    |
    +-- result_queue  (multiprocessing.Queue)
         <-- each worker pushes its latency list + stats on completion

Why multiprocessing?
  ThreadPoolExecutor is GIL-bound for CPU-intensive ML inference.
  Process isolation gives true parallelism: each worker owns its own
  SQLInjectionEnsemble + SQLiAgent, no shared state, no GIL contention.

Usage
-----
  python load_test.py                            # 4 workers x 250 req = 1000 total
  python load_test.py --workers 8 --requests 2000
  python load_test.py --workers 4 --requests 1000 --sla-p99-ms 150
  python load_test.py --workers 8 --requests 4000 --ramp-seconds 5

Thresholds (configurable via args)
-----------------------------------
  --sla-p99-ms      SLA ceiling for p99 latency (default: 100 ms)
  --max-error-rate  Max allowed error fraction   (default: 0.001 = 0.1%)
"""

from __future__ import annotations

import argparse
import itertools
import json
import multiprocessing
import os
import sys
import time
import warnings

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
    "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "'; EXEC xp_cmdshell('whoami')--",
    "' OR 'x'='x",
    "1 OR 1=1",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' GROUP BY COLUMNINDEX HAVING 1=1--",
    "'; INSERT INTO users VALUES ('hacked','pass')--",
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
    "123 Main Street, Springfield",
    "Product ID: 78234",
    "I would like to select the blue option",
    "My name is O'Reilly",
    "Search query: python tutorial",
]

_CORPUS = INJECTIONS + SAFE_INPUTS  # 40 items, balanced 50/50


def _build_worker_corpus(worker_id: int, n_requests: int) -> list[str]:
    """Deterministic corpus slice for this worker."""
    import random
    rng = random.Random(worker_id * 31337)
    pool = list(itertools.islice(itertools.cycle(_CORPUS), n_requests))
    rng.shuffle(pool)
    return pool


# ── Worker process ─────────────────────────────────────────────────────────────

def _load_worker(
    worker_id: int,
    n_requests: int,
    result_queue: multiprocessing.Queue,
    db_dir: str,
    ramp_seconds: float = 0.0,
) -> None:
    """
    Each worker runs in its own process. It:
      1. Imports and initialises the detector + agent (fresh per process)
      2. Optionally waits for ramp_seconds before firing (stagger start)
      3. Evaluates n_requests as fast as possible (no rate limiting)
      4. Pushes result dict onto result_queue

    Using a per-worker SQLite DB avoids lock contention between workers.
    """
    import warnings as _w
    _w.filterwarnings("ignore")

    # Stagger start to simulate ramp-up
    if ramp_seconds > 0:
        import random
        delay = random.Random(worker_id).uniform(0, ramp_seconds)
        time.sleep(delay)

    # Per-worker SQLite database
    db_path = os.path.join(db_dir, f"load_worker_{worker_id}.db")

    from agent import SQLiAgent, AgentConfig
    from sql_injection_detector import SQLInjectionEnsemble
    from state_backend import SQLiteBackend

    backend = SQLiteBackend(db_path)
    detector = SQLInjectionEnsemble()
    agent = SQLiAgent(detector, store=backend)

    corpus = _build_worker_corpus(worker_id, n_requests)

    # IP generator: each worker uses a unique IP range so ban states don't overlap
    ip_base = 100_000 + worker_id * 10_000
    ip_counter = itertools.count(ip_base)

    def _fresh_ip() -> str:
        n = next(ip_counter)
        return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    latencies: list[float] = []
    error_count = 0

    # RSS before
    rss_start = _rss_mb()

    t_start = time.perf_counter()
    for text in corpus:
        try:
            t0 = time.perf_counter()
            agent.evaluate(text, source_ip=_fresh_ip())
            latencies.append((time.perf_counter() - t0) * 1000)
        except Exception:
            error_count += 1

    elapsed = time.perf_counter() - t_start
    rss_end = _rss_mb()

    # Sort for fast percentile extraction on main side
    latencies.sort()

    result_queue.put({
        "worker_id":     worker_id,
        "requests":      len(latencies),
        "errors":        error_count,
        "elapsed_s":     round(elapsed, 3),
        "rps":           round(len(latencies) / elapsed, 1) if elapsed > 0 else 0,
        "rss_start_mb":  round(rss_start, 1),
        "rss_end_mb":    round(rss_end, 1),
        "rss_growth_mb": round(rss_end - rss_start, 1),
        "latencies_ms":  latencies,  # sorted list
    })


# ── Memory helper ──────────────────────────────────────────────────────────────

def _rss_mb() -> float:
    """Current process RSS in MB. Cross-platform."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    except ImportError:
        pass
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    try:
        import ctypes
        class _PMC(ctypes.Structure):
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
        pmc = _PMC()
        pmc.cb = ctypes.sizeof(pmc)
        ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(pmc),
            pmc.cb,
        )
        return pmc.WorkingSetSize / 1024 / 1024
    except Exception:
        return 0.0


# ── CPU helper ─────────────────────────────────────────────────────────────────

def _cpu_percent() -> float | None:
    """Process CPU % (requires psutil; returns None if unavailable)."""
    try:
        import psutil
        return psutil.Process(os.getpid()).cpu_percent(interval=0.1)
    except Exception:
        return None


# ── Percentile helper ──────────────────────────────────────────────────────────

def _percentile(sorted_data: list[float], p: float) -> float:
    """Fast percentile from pre-sorted list."""
    if not sorted_data:
        return 0.0
    idx = min(int(len(sorted_data) * p / 100), len(sorted_data) - 1)
    return sorted_data[idx]


def _merge_sorted(*sorted_lists: list[float]) -> list[float]:
    """Merge N sorted lists into one sorted list (merge sort)."""
    import heapq
    merged = list(heapq.merge(*sorted_lists))
    return merged


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Load Test - SQL Injection Detector")
    parser.add_argument("--workers",       type=int,   default=4,     help="Number of parallel worker processes (default: 4)")
    parser.add_argument("--requests",      type=int,   default=1000,  help="Total requests across all workers (default: 1000)")
    parser.add_argument("--sla-p99-ms",   type=float, default=100.0, help="SLA ceiling for p99 latency in ms (default: 100)")
    parser.add_argument("--max-error-rate",type=float, default=0.001, help="Max allowed error fraction (default: 0.001)")
    parser.add_argument("--ramp-seconds",  type=float, default=0.0,   help="Stagger worker start over N seconds (default: 0 = simultaneous)")
    parser.add_argument("--output",        type=str,   default=None,  help="JSON output file path for results")
    args = parser.parse_args()

    n_workers  = args.workers
    n_requests = args.requests
    per_worker = max(1, n_requests // n_workers)
    # Last worker picks up remainder
    per_worker_list = [per_worker] * n_workers
    per_worker_list[-1] += n_requests - per_worker * n_workers

    print("=" * 68)
    print("  SQL Injection Detector - Load Test v3.8.0")
    print("=" * 68)
    print(f"  Workers       : {n_workers}")
    print(f"  Total requests: {n_requests:,}  ({per_worker} per worker, last={per_worker_list[-1]})")
    print(f"  Ramp-up       : {args.ramp_seconds}s")
    print(f"  SLA p99       : <{args.sla_p99_ms} ms")
    print(f"  Max error rate: <{args.max_error_rate * 100:.1f}%")
    print("=" * 68)

    import tempfile
    tmp_dir = tempfile.mkdtemp(prefix="sqli_load_")
    print(f"\n  Temp dir: {tmp_dir}")

    result_queue = multiprocessing.Queue()
    processes: list[multiprocessing.Process] = []

    for wid in range(n_workers):
        p = multiprocessing.Process(
            target=_load_worker,
            args=(wid, per_worker_list[wid], result_queue, tmp_dir, args.ramp_seconds),
        )
        processes.append(p)

    # Record main-process RSS before workers start
    rss_before_launch = _rss_mb()

    print(f"\n  Launching {n_workers} worker process(es)...")
    t_wall_start = time.perf_counter()
    for p in processes:
        p.start()
    pids = [p.pid for p in processes]
    print(f"  Worker PIDs: {pids}")

    # Wait for all workers
    for p in processes:
        p.join()

    t_wall_end = time.perf_counter()
    wall_elapsed = t_wall_end - t_wall_start

    # Check for crashed workers
    crashed = [p for p in processes if p.exitcode != 0]
    if crashed:
        print(f"\n  [FAIL] {len(crashed)} worker(s) crashed: exitcodes {[p.exitcode for p in crashed]}")

    # Collect results
    worker_results: list[dict] = []
    while not result_queue.empty():
        worker_results.append(result_queue.get_nowait())
    worker_results.sort(key=lambda r: r["worker_id"])

    if len(worker_results) < n_workers:
        print(f"\n  [FAIL] Only {len(worker_results)}/{n_workers} workers returned results.")
        return 1

    # ── Aggregate ──────────────────────────────────────────────────────────────

    all_latencies   = _merge_sorted(*[r["latencies_ms"] for r in worker_results])
    total_requests  = sum(r["requests"] for r in worker_results)
    total_errors    = sum(r["errors"]   for r in worker_results)
    error_rate      = total_errors / max(total_requests, 1)
    total_rss_growth = sum(r["rss_growth_mb"] for r in worker_results)
    agg_rps         = total_requests / wall_elapsed if wall_elapsed > 0 else 0

    n = len(all_latencies)
    p50  = _percentile(all_latencies, 50)
    p95  = _percentile(all_latencies, 95)
    p99  = _percentile(all_latencies, 99)
    pmax = all_latencies[-1] if all_latencies else 0.0
    pmin = all_latencies[0]  if all_latencies else 0.0

    import statistics as _stats
    mean_lat = _stats.mean(all_latencies) if all_latencies else 0.0

    # ── Per-worker table ───────────────────────────────────────────────────────

    print("\n  Per-worker breakdown:")
    print(f"  {'Worker':>6}  {'Requests':>8}  {'Errors':>6}  {'RPS':>7}  {'p50 ms':>7}  {'p99 ms':>7}  {'RSS +MB':>7}")
    print("  " + "-" * 64)
    for r in worker_results:
        wlats = r["latencies_ms"]
        wp50  = _percentile(wlats, 50) if wlats else 0
        wp99  = _percentile(wlats, 99) if wlats else 0
        print(f"  {r['worker_id']:>6}  "
              f"{r['requests']:>8,}  "
              f"{r['errors']:>6}  "
              f"{r['rps']:>7.1f}  "
              f"{wp50:>7.2f}  "
              f"{wp99:>7.2f}  "
              f"{r['rss_growth_mb']:>+7.1f}")

    # ── Aggregate latency summary ──────────────────────────────────────────────

    print(f"\n  Aggregate latency ({n:,} samples from {n_workers} workers):")
    print(f"  {'Mean':>8} : {mean_lat:7.2f} ms")
    print(f"  {'Min':>8} : {pmin:7.2f} ms")
    print(f"  {'p50':>8} : {p50:7.2f} ms")
    print(f"  {'p95':>8} : {p95:7.2f} ms")
    print(f"  {'p99':>8} : {p99:7.2f} ms")
    print(f"  {'Max':>8} : {pmax:7.2f} ms")

    # ── Throughput ─────────────────────────────────────────────────────────────

    print(f"\n  Throughput:")
    print(f"  {'Total req':>14} : {total_requests:,}")
    print(f"  {'Wall time':>14} : {wall_elapsed:.2f}s")
    print(f"  {'Aggregate RPS':>14} : {agg_rps:.1f} req/s")
    print(f"  {'Sum worker RPS':>14} : {sum(r['rps'] for r in worker_results):.1f} req/s")
    print(f"  {'RSS growth total':>14} : +{total_rss_growth:.1f} MB")
    print(f"  {'Errors':>14} : {total_errors} ({error_rate * 100:.3f}%)")

    # ── Latency histogram (ASCII, 10 buckets) ──────────────────────────────────

    if all_latencies and n >= 10:
        print("\n  Latency histogram (ms):")
        buckets = 10
        lo, hi = pmin, pmax
        bw = (hi - lo) / buckets if hi > lo else 1.0
        counts = [0] * buckets
        for lat in all_latencies:
            b = min(int((lat - lo) / bw), buckets - 1)
            counts[b] += 1
        max_count = max(counts) or 1
        bar_width = 30
        for i, c in enumerate(counts):
            lo_b = lo + i * bw
            hi_b = lo_b + bw
            bar = "#" * int(c / max_count * bar_width)
            print(f"  [{lo_b:6.1f}-{hi_b:6.1f}] {bar:<{bar_width}}  {c:5,}")

    # ── SLA / checks ──────────────────────────────────────────────────────────

    checks = {
        "no_worker_crash":     len(crashed) == 0,
        "sla_p99_ok":          p99 <= args.sla_p99_ms,
        "error_rate_ok":       error_rate <= args.max_error_rate,
        "min_1000_rps":        agg_rps >= 1000,
        "all_workers_returned": len(worker_results) == n_workers,
    }
    all_pass = all(checks.values())

    print("\n" + "=" * 68)
    print("  LOAD TEST RESULTS")
    print("=" * 68)
    for check, passed in checks.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status}  {check}")

    verdict = "PASS" if all_pass else "FAIL"
    print()
    print(f"  Overall: {verdict}")
    print("=" * 68)

    # ── JSON report ────────────────────────────────────────────────────────────

    report = {
        "verdict": verdict,
        "config": {
            "workers":         n_workers,
            "total_requests":  n_requests,
            "sla_p99_ms":      args.sla_p99_ms,
            "max_error_rate":  args.max_error_rate,
            "ramp_seconds":    args.ramp_seconds,
        },
        "aggregate": {
            "total_requests":   total_requests,
            "total_errors":     total_errors,
            "error_rate":       round(error_rate, 6),
            "wall_elapsed_s":   round(wall_elapsed, 3),
            "aggregate_rps":    round(agg_rps, 1),
            "mean_ms":          round(mean_lat, 2),
            "p50_ms":           round(p50, 2),
            "p95_ms":           round(p95, 2),
            "p99_ms":           round(p99, 2),
            "max_ms":           round(pmax, 2),
            "rss_growth_total_mb": round(total_rss_growth, 1),
        },
        "workers": [
            {
                "worker_id":    r["worker_id"],
                "requests":     r["requests"],
                "errors":       r["errors"],
                "rps":          r["rps"],
                "elapsed_s":    r["elapsed_s"],
                "rss_growth_mb": r["rss_growth_mb"],
                "p50_ms":       round(_percentile(r["latencies_ms"], 50), 2),
                "p95_ms":       round(_percentile(r["latencies_ms"], 95), 2),
                "p99_ms":       round(_percentile(r["latencies_ms"], 99), 2),
            }
            for r in worker_results
        ],
        "checks": checks,
    }

    out_path = args.output or os.path.join(tmp_dir, "load_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report: {out_path}\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
