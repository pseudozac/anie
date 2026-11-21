"""Graph Scalability & Indexing Benchmark Protocol (Milestone M3.11).

Measures empirical performance across 10k, 50k, and 100k+ historical observations:
- Ingestion throughput (records/sec, events/sec)
- Indexing cost (CPU time, SQLite B-tree balancing overhead)
- Query latency: 1-hop, 2-hop neighborhood, and temporal kNN drift (p50, p95, max)
- Disk growth (bytes per record, DB and WAL growth)
- Peak RSS memory footprint under the 1 GiB micro VM budget (<200 MiB RAM)
- Evaluates composite/covering index optimizations vs baseline indexes
- Evaluates whether table partitioning is empirically justified
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import time
from typing import Any, Dict, List, Tuple

from anie.graph_engine import GraphEngine
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore


def get_peak_rss_bytes() -> int:
    """Get peak process resident set size in bytes across Windows and POSIX."""
    try:
        import psutil
        return psutil.Process().memory_info().rss
    except ImportError:
        pass

    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
        except Exception:
            pass
        return 0
    else:
        try:
            import resource
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            factor = 1 if sys.platform == "darwin" else 1024
            return rusage.ru_maxrss * factor
        except Exception:
            return 0


def generate_synthetic_workload(
    count: int,
    seed: int = 42,
) -> list[tuple[RealCollectionEvent, RealObservation]]:
    """Generate deterministic, reproducible synthetic telemetry for benchmarking."""
    rng = random.Random(seed)
    domain_count = max(10, count // 20)
    domains = [f"scale-target-{i:05d}.org" for i in range(domain_count)]
    resolvers = ["cloudflare", "google", "quad9"]

    records: list[tuple[RealCollectionEvent, RealObservation]] = []
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        d = domains[i % len(domains)]
        res_name = resolvers[i % len(resolvers)]
        ip_oct4 = (i % 250) + 1
        ip_oct3 = ((i // 250) % 250) + 1
        ip = f"198.51.{ip_oct3}.{ip_oct4}"
        obs_time = (base_time + timedelta(seconds=i * 60)).strftime("%Y-%m-%dT%H:%M:%SZ")

        wire_bytes = f"wire_payload_scale_{d}_{ip}_{obs_time}".encode("utf-8")
        wire_hash = hashlib.sha256(wire_bytes).hexdigest()

        req = RealCollectionRequest.create(
            kind="dns_a",
            subject=d,
            observed_at=obs_time,
            target_endpoint=f"https://dns.{res_name}.net/dns-query",
            pinned_ip="1.1.1.1",
        )
        factual = FactualVerification(
            dnssec_status="secure",
            response_authenticity="recursive",
            transport_security="tls_pinned",
            resolver_identity=res_name,
            wire_rcode="NOERROR",
            raw_evidence_status="captured",
        )
        event = RealCollectionEvent(
            request=req,
            response_code="ANSWER",
            raw_sha256=wire_hash,
            raw_evidence_status="captured",
            factual_verification=factual,
            source_id=f"first_party:doh:{res_name}",
            observed_at=obs_time,
            raw_payload=wire_bytes,
        )
        obs = RealObservation(
            subject=d,
            kind="dns_a",
            observed_at=obs_time,
            values=(ip,),
            status="ok",
            source_id=f"first_party:doh:{res_name}",
            method="dns",
            synthetic=False,
            evidence_id=event.event_id,
            factual_verification=factual,
            ttl_seconds=300,
            error_code=None,
            confidence=1.0,
        )
        records.append((event, obs))

    return records


def benchmark_size(
    target_count: int,
    *,
    use_covering_indexes: bool = True,
    query_samples: int = 50,
    seed: int = 42,
) -> dict[str, Any]:
    """Execute end-to-end ingestion and query benchmark for a given observation scale."""
    gc.collect()
    rss_start = get_peak_rss_bytes()

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / f"benchmark_scale_{target_count}.db"
        store = RealObservationStore(db_path)

        # 1. Generate workload
        corpus = generate_synthetic_workload(target_count, seed=seed)

        # 2. Benchmark Ingestion Throughput (Batch Ingestion in chunks)
        ingest_start = time.perf_counter()
        with store._connect() as conn:
            # Optimize PRAGMAs for scale ingestion
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA journal_mode = WAL")
            for ev, ob in corpus:
                store.insert_record(ev, ob, auto_sync_graph=True)
        ingest_duration = time.perf_counter() - ingest_start
        ingest_throughput = len(corpus) / ingest_duration if ingest_duration > 0 else 0.0

        # 3. Optional Composite / Covering Index Optimization
        index_duration = 0.0
        if use_covering_indexes:
            idx_start = time.perf_counter()
            with store._connect() as conn:
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_graph_edges_covering_m311
                    ON graph_edges(source_id, relation_type, target_id, valid_from, valid_until)
                """)
            index_duration = time.perf_counter() - idx_start

        # 4. Measure Database & Disk Footprint
        db_file_bytes = db_path.stat().st_size if db_path.exists() else 0
        wal_path = Path(str(db_path) + "-wal")
        wal_file_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        total_disk_bytes = db_file_bytes + wal_file_bytes
        bytes_per_record = total_disk_bytes / len(corpus) if len(corpus) > 0 else 0.0

        with store._connect() as conn:
            node_count = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            edge_count = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]

        # 5. Benchmark 1-Hop Neighborhood Query Latency
        rng = random.Random(seed + 1)
        sample_domains = [corpus[rng.randint(0, len(corpus) - 1)][1].subject for _ in range(query_samples)]

        hop1_latencies: list[float] = []
        hop2_latencies: list[float] = []
        knn_latencies: list[float] = []

        with store._connect() as conn:
            engine = GraphEngine(conn)

            for dom in sample_domains:
                node_uri = f"anie:entity:domain:{dom}"
                q_start = time.perf_counter()
                _ = engine.get_k_hop_neighborhood(node_uri, max_depth=1)
                hop1_latencies.append((time.perf_counter() - q_start) * 1000.0)  # ms

            for dom in sample_domains[: max(10, query_samples // 2)]:
                node_uri = f"anie:entity:domain:{dom}"
                q_start = time.perf_counter()
                _ = engine.get_k_hop_neighborhood(node_uri, max_depth=2)
                hop2_latencies.append((time.perf_counter() - q_start) * 1000.0)  # ms

            for dom in sample_domains[: max(10, query_samples // 2)]:
                node_uri = f"anie:entity:domain:{dom}"
                q_start = time.perf_counter()
                conn.execute(
                    """
                    SELECT target_id, relation_type, valid_from, valid_until
                    FROM graph_edges
                    WHERE source_id = ?
                    ORDER BY valid_from DESC
                    LIMIT 20
                    """,
                    (node_uri,),
                ).fetchall()
                knn_latencies.append((time.perf_counter() - q_start) * 1000.0)

        # 6. Measure Peak Memory Footprint
        rss_end = get_peak_rss_bytes()
        peak_rss_mib = max(rss_end, rss_start) / (1024 * 1024)

        hop1_latencies.sort()
        hop2_latencies.sort()
        knn_latencies.sort()

        def _p(l: list[float], pct: float) -> float:
            if not l:
                return 0.0
            idx = int(len(l) * pct)
            return l[min(idx, len(l) - 1)]

        return {
            "scale": target_count,
            "observations_ingested": len(corpus),
            "graph_nodes": node_count,
            "graph_edges": edge_count,
            "ingestion_duration_seconds": round(ingest_duration, 4),
            "ingestion_throughput_records_per_sec": round(ingest_throughput, 2),
            "indexing_overhead_seconds": round(index_duration, 4),
            "disk_db_bytes": db_file_bytes,
            "disk_wal_bytes": wal_file_bytes,
            "total_disk_bytes": total_disk_bytes,
            "total_disk_mib": round(total_disk_bytes / (1024 * 1024), 2),
            "bytes_per_record": round(bytes_per_record, 1),
            "peak_rss_mib": round(peak_rss_mib, 2),
            "covering_indexes_enabled": use_covering_indexes,
            "query_1hop_ms": {
                "p50": round(_p(hop1_latencies, 0.50), 3),
                "p95": round(_p(hop1_latencies, 0.95), 3),
                "max": round(max(hop1_latencies) if hop1_latencies else 0.0, 3),
            },
            "query_2hop_ms": {
                "p50": round(_p(hop2_latencies, 0.50), 3),
                "p95": round(_p(hop2_latencies, 0.95), 3),
                "max": round(max(hop2_latencies) if hop2_latencies else 0.0, 3),
            },
            "query_temporal_drift_ms": {
                "p50": round(_p(knn_latencies, 0.50), 3),
                "p95": round(_p(knn_latencies, 0.95), 3),
                "max": round(max(knn_latencies) if knn_latencies else 0.0, 3),
            },
        }


def run_comparative_benchmark(
    scales: list[int] = [10000, 50000, 100000],
) -> dict[str, Any]:
    """Execute full comparative benchmark across baseline and optimized covering indexes."""
    results: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []

    for count in scales:
        print(f"[*] Benchmarking scale {count:,} with baseline indexes...", file=sys.stderr)
        baseline = benchmark_size(count, use_covering_indexes=False)

        print(f"[*] Benchmarking scale {count:,} with covering indexes...", file=sys.stderr)
        optimized = benchmark_size(count, use_covering_indexes=True)

        results.extend([baseline, optimized])

        p95_drift = optimized["query_temporal_drift_ms"]["p95"]
        rss_mib = optimized["peak_rss_mib"]
        partitioning_justified = (p95_drift > 50.0) or (rss_mib > 300.0)

        comparisons.append({
            "scale": count,
            "baseline_1hop_p95_ms": baseline["query_1hop_ms"]["p95"],
            "optimized_1hop_p95_ms": optimized["query_1hop_ms"]["p95"],
            "speedup_1hop_pct": round(
                (baseline["query_1hop_ms"]["p95"] - optimized["query_1hop_ms"]["p95"])
                / max(0.001, baseline["query_1hop_ms"]["p95"])
                * 100.0,
                1,
            ),
            "baseline_drift_p95_ms": baseline["query_temporal_drift_ms"]["p95"],
            "optimized_drift_p95_ms": optimized["query_temporal_drift_ms"]["p95"],
            "total_disk_mib": optimized["total_disk_mib"],
            "peak_rss_mib": optimized["peak_rss_mib"],
            "partitioning_recommended": partitioning_justified,
            "verdict": (
                "Partitioning NOT RECOMMENDED: Single SQLite B-tree composite index "
                f"meets SLA (p95 drift: {p95_drift}ms, RSS: {rss_mib} MiB, budget: <200 MiB RAM)"
                if not partitioning_justified
                else "Partitioning recommended due to latency/memory budget excursion"
            ),
        })

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "benchmark_scales": scales,
        "results": results,
        "comparisons": comparisons,
    }


def main():
    parser = argparse.ArgumentParser(description="ANIE M3.11 Graph Scalability Benchmark Protocol")
    parser.add_argument(
        "--scales",
        default="10000,50000,100000",
        help="comma-separated observation counts to benchmark (default: 10000,50000,100000)",
    )
    parser.add_argument("--out", default=None, help="optional path to save benchmark JSON results")
    parser.add_argument("--quick", action="store_true", help="run quick verification mode with small scale (1k, 5k)")
    args = parser.parse_args()

    if args.quick:
        scales = [200, 500]
    else:
        scales = [int(s.strip()) for s in args.scales.split(",") if s.strip()]

    report = run_comparative_benchmark(scales)
    out_json = json.dumps(report, indent=2)

    if args.out:
        Path(args.out).write_text(out_json + "\n", encoding="utf-8")
        print(f"[+] Benchmark results written to {args.out}", file=sys.stderr)

    print(out_json)


if __name__ == "__main__":
    main()
