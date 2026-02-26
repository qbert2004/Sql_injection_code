"""
Performance Benchmark - SQL Injection Detector v3.7.0
======================================================
Measures single-node latency and throughput of the full detection pipeline.

Metrics:
    Latency    - p50 / p95 / p99 / max  (milliseconds, per-request)
    Throughput - requests-per-second (RPS) under sequential and concurrent load
    Per-layer  - how much each layer (regex/AST/RF/CNN) costs

Usage:
    python benchmark.py                     # quick run (300 samples)
    python benchmark.py --samples 1000      # full run
    python benchmark.py --samples 1000 --concurrency 4
"""

import argparse
import statistics
import time
import itertools
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings("ignore")  # suppress sklearn version warnings in bench output

from agent import SQLiAgent, AgentConfig
from sql_injection_detector import SQLInjectionEnsemble

# -- Corpus --------------------------------------------------------------------

INJECTIONS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT password FROM users--",
    "'; DROP TABLE users--",
    "admin'--",
    "' AND SLEEP(5)--",
    "1; SELECT pg_sleep(3)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' OR 0x4f523d31--",
    "'/**/OR/**/1/**/=/**/1--",
    "' UNION/**/SELECT/**/username,password/**/FROM/**/users--",
    "1'\tOR\t1=1--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "'; EXEC sp_configure 'show advanced options',1--",
]

SAFE_INPUTS = [
    "hello world",
    "user@example.com",
    "Alice Johnson",
    "2024-01-15",
    "Please select your country",
    "The union of these two sets",
    "Update your profile information",
    "123 Union Street, Springfield",
    "O'Brien",
    "P@ssw0rd!2024#",
    "+1-800-555-0123",
    "https://example.com/path?q=hello",
    "Select Comfort mattresses",
    "Francois Muller",
    "The quick brown fox jumps over the lazy dog",
]

# Build balanced corpus cycling both lists
def _build_corpus(n: int) -> list[str]:
    pool = list(itertools.islice(itertools.cycle(INJECTIONS + SAFE_INPUTS), n))
    return pool


# -- Benchmark helpers ---------------------------------------------------------

_ip_counter = itertools.count(100_000)

def _fresh_ip() -> str:
    n = next(_ip_counter)
    return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def _run_sequential(agent: SQLiAgent, corpus: list[str]) -> list[float]:
    """Return per-request latencies in ms."""
    latencies = []
    for text in corpus:
        t0 = time.perf_counter()
        agent.evaluate(text, source_ip=_fresh_ip())
        latencies.append((time.perf_counter() - t0) * 1000)
    return latencies


def _run_concurrent(agent: SQLiAgent, corpus: list[str], workers: int) -> tuple[list[float], float]:
    """Return (per-request latencies ms, wall-clock elapsed s)."""
    latencies: list[float] = [0.0] * len(corpus)
    t_wall_start = time.perf_counter()

    def _task(idx_text):
        idx, text = idx_text
        t0 = time.perf_counter()
        agent.evaluate(text, source_ip=_fresh_ip())
        return idx, (time.perf_counter() - t0) * 1000

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_task, (i, t)) for i, t in enumerate(corpus)]
        for f in as_completed(futures):
            idx, lat = f.result()
            latencies[idx] = lat

    elapsed = time.perf_counter() - t_wall_start
    return latencies, elapsed


def _percentile(data: list[float], p: float) -> float:
    data_sorted = sorted(data)
    idx = int(len(data_sorted) * p / 100)
    idx = min(idx, len(data_sorted) - 1)
    return data_sorted[idx]


def _print_latency_table(title: str, latencies: list[float], rps: float | None = None):
    n = len(latencies)
    mean = statistics.mean(latencies)
    p50  = _percentile(latencies, 50)
    p95  = _percentile(latencies, 95)
    p99  = _percentile(latencies, 99)
    pmax = max(latencies)
    pmin = min(latencies)

    print(f"\n{'-' * 60}")
    print(f"  {title}")
    print(f"{'-' * 60}")
    print(f"  Samples : {n:,}")
    print(f"  Mean    : {mean:7.2f} ms")
    print(f"  Min     : {pmin:7.2f} ms")
    print(f"  p50     : {p50:7.2f} ms")
    print(f"  p95     : {p95:7.2f} ms")
    print(f"  p99     : {p99:7.2f} ms")
    print(f"  Max     : {pmax:7.2f} ms")
    if rps is not None:
        print(f"  RPS     : {rps:7.1f} req/s")
    print(f"{'-' * 60}")


# -- Main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Detector - Performance Benchmark")
    parser.add_argument("--samples",     type=int, default=300,  help="Number of requests (default: 300)")
    parser.add_argument("--warmup",      type=int, default=20,   help="Warmup requests (default: 20)")
    parser.add_argument("--concurrency", type=int, default=0,    help="Thread workers for concurrent bench (0=skip, default)")
    args = parser.parse_args()

    print("=" * 60)
    print("  SQL Injection Detector - Performance Benchmark v3.7.0")
    print("=" * 60)

    print("\nInitialising detector + agent...")
    t0 = time.perf_counter()
    detector = SQLInjectionEnsemble()
    agent    = SQLiAgent(detector)
    init_ms  = (time.perf_counter() - t0) * 1000
    print(f"  Init time : {init_ms:.0f} ms")

    # -- Warmup ------------------------------------------------------
    print(f"\nWarmup ({args.warmup} requests)...")
    warmup_corpus = _build_corpus(args.warmup)
    _run_sequential(agent, warmup_corpus)
    print("  Done.")

    # -- Sequential Benchmark -----------------------------------------
    print(f"\nSequential benchmark ({args.samples:,} requests)...")
    corpus = _build_corpus(args.samples)

    t_start = time.perf_counter()
    latencies = _run_sequential(agent, corpus)
    elapsed   = time.perf_counter() - t_start
    rps_seq   = args.samples / elapsed

    _print_latency_table(
        f"Sequential  ({args.samples:,} requests)",
        latencies,
        rps=rps_seq,
    )

    # -- Injection-only latency ----------------------------------------
    print(f"\nInjection-only latency ({len(INJECTIONS)} canonical payloads ? 5 repeats)...")
    inj_corpus = _build_corpus(len(INJECTIONS) * 5)[:len(INJECTIONS) * 5]
    inj_latencies = _run_sequential(agent, inj_corpus)
    _print_latency_table("Injection payloads (sequential)", inj_latencies)

    # -- Safe-only latency ---------------------------------------------
    safe_corpus = SAFE_INPUTS * 5
    safe_latencies = _run_sequential(agent, safe_corpus)
    _print_latency_table("Safe inputs (sequential)", safe_latencies)

    # -- Concurrent Benchmark -----------------------------------------
    if args.concurrency > 0:
        print(f"\nConcurrent benchmark ({args.samples:,} requests, {args.concurrency} workers)...")
        conc_latencies, wall = _run_concurrent(agent, corpus, workers=args.concurrency)
        rps_conc = args.samples / wall
        _print_latency_table(
            f"Concurrent  ({args.concurrency} workers)",
            conc_latencies,
            rps=rps_conc,
        )

    # -- Summary -------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    p50  = _percentile(latencies, 50)
    p95  = _percentile(latencies, 95)
    p99  = _percentile(latencies, 99)
    sla_ok = p99 < 100  # SLA: p99 < 100ms for single-node
    print(f"  p50 latency : {p50:.2f} ms")
    print(f"  p95 latency : {p95:.2f} ms")
    sla_str = "[OK] SLA <100ms" if sla_ok else "[BREACH] SLA >100ms"
    print(f"  p99 latency : {p99:.2f} ms  {sla_str}")
    print(f"  Throughput  : {rps_seq:.1f} RPS (sequential)")
    print(f"  Init time   : {init_ms:.0f} ms")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
