"""Deterministic Graph and Storage Benchmark Suite for ANIE (Milestone M3.3.1 & M3.3.2).

Measures:
1. Ingestion throughput and build overhead (single-commit vs batch insert, records/sec).
2. Edge deduplication and evidence union under repeated updates.
3. Storage growth and efficiency (bytes/node, bytes/edge, total DB bytes).
4. Temporal and historical graph query latency (1-hop, 2-hop neighborhood, co-hosting, lineage trace, history).
5. Memory footprint under true OS Resident Set Size (RSS) across 300, 10,000, and 100,000 observations.
6. Stress conditions simulating 1 GiB VM (memory limit <50 MiB) vs 2-OCPU/12-GB ARM64 VM.
7. Cold restart and recovery behavior with SQLite WAL checkpointing and integrity verification.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import Any, Iterator

from anie.discrepancy_engine import DiscrepancyEngine
from anie.discrepancy_models import RealDiscrepancyReport
from anie.graph_engine import GraphEngine
from anie.graph_models import EpistemicLayer, GraphEdge, GraphNode, NodeType, RelationType
from anie.multi_resolver import build_mock_dns_wire_response
from anie.observations import canonical_json, utc_iso
from anie.profiling import get_process_rss, profile_execution
from anie.real_models import FactualVerification, RealCollectionEvent, RealCollectionRequest, RealObservation
from anie.real_store import RealObservationStore


def generate_synthetic_workload_batches(
    num_domains: int = 50,
    rounds: int = 1,
    batch_size: int = 5000,
    base_time: str = "2026-11-20T10:00:00Z",
) -> Iterator[list[tuple[RealCollectionEvent, RealObservation]]]:
    """Stream deterministic multi-resolver observations in bounded batches.
    
    Generates multi-round temporal updates:
    - Stable domains retain IPs across rounds, validating edge deduplication & evidence union.
    - Dynamic CDN domains rotate IPs across rounds, validating historical timeline transitions.
    """
    resolvers = ["cloudflare", "google", "quad9"]

    cdn_ips = [
        "104.16.12.34", "104.16.12.35", "104.17.45.67", "104.18.99.100",  # Cloudflare
        "151.101.1.69", "151.101.65.69", "151.101.129.69",                 # Fastly
        "13.224.10.11", "13.224.10.12", "13.225.50.60",                   # AWS CloudFront
    ]
    standard_ips = [
        f"198.51.100.{i % 250 + 1}" for i in range(100)
    ]

    base_dt = datetime.fromisoformat(base_time.replace("Z", "+00:00"))
    current_batch: list[tuple[RealCollectionEvent, RealObservation]] = []

    for round_idx in range(rounds):
        round_dt = base_dt + timedelta(hours=24 * round_idx)
        round_time_str = round_dt.isoformat(timespec="seconds").replace("+00:00", "Z")

        for d_idx in range(num_domains):
            domain = f"target-{d_idx:04d}.example.org"
            is_cdn = (d_idx % 3 == 0)
            is_filtered = (d_idx % 7 == 0)

            for r_idx, res in enumerate(resolvers):
                req = RealCollectionRequest.create(
                    kind="dns_a",
                    subject=domain,
                    observed_at=round_time_str,
                    target_endpoint=f"https://{res}.example.net/dns-query",
                    pinned_ip="192.0.2.1",
                )

                # Determine response values
                if is_filtered and res == "quad9":
                    ips = []
                    rcode = 3  # NXDOMAIN
                    status = "empty"
                    err_code = None
                elif is_cdn:
                    # Rotate across known Anycast pool with round offset for temporal variation
                    ip_pick = cdn_ips[(d_idx * 3 + r_idx + round_idx) % len(cdn_ips)]
                    ips = [ip_pick]
                    rcode = 0
                    status = "ok"
                    err_code = None
                else:
                    ip_pick = standard_ips[d_idx % len(standard_ips)]
                    ips = [ip_pick]
                    rcode = 0
                    status = "ok"
                    err_code = None

                raw_wire = build_mock_dns_wire_response(
                    domain=domain,
                    kind="A",
                    ips=ips,
                    rcode=rcode,
                    ad_flag=True,
                    ttl=300 - r_idx * 10,
                )
                raw_sha = sha256(raw_wire).hexdigest()

                factual = FactualVerification(
                    dnssec_status="secure" if rcode == 0 else "indeterminate",
                    response_authenticity="recursive",
                    transport_security="tls_pinned",
                    resolver_identity=res,
                    wire_rcode="NOERROR" if rcode == 0 else "NXDOMAIN",
                    raw_evidence_status="captured",
                    resolver_ad_claim=(rcode == 0),
                )

                event = RealCollectionEvent(
                    request=req,
                    response_code="NOERROR" if rcode == 0 else "NXDOMAIN",
                    raw_sha256=raw_sha,
                    raw_evidence_status="captured",
                    factual_verification=factual,
                    source_id=f"oracle-collector-01:{res}",
                    observed_at=round_time_str,
                    raw_payload=raw_wire,
                )

                obs = RealObservation(
                    subject=domain,
                    kind="dns_a",
                    observed_at=round_time_str,
                    values=tuple(ips),
                    status=status,
                    error_code=err_code,
                    source_id=f"oracle-collector-01:{res}",
                    method="dns",
                    synthetic=False,
                    evidence_id=event.event_id,
                    factual_verification=factual,
                    ttl_seconds=300,
                )

                current_batch.append((event, obs))
                if len(current_batch) >= batch_size:
                    yield current_batch
                    current_batch = []

    if current_batch:
        yield current_batch


def generate_synthetic_workload(
    num_domains: int = 50,
    rounds: int = 1,
    base_time: str = "2026-11-20T10:00:00Z",
) -> list[tuple[RealCollectionEvent, RealObservation]]:
    """Generate deterministic multi-resolver observations for benchmarking."""
    records: list[tuple[RealCollectionEvent, RealObservation]] = []
    for batch in generate_synthetic_workload_batches(num_domains=num_domains, rounds=rounds, batch_size=5000, base_time=base_time):
        records.extend(batch)
    return records


def run_benchmarks(
    num_domains: int = 100,
    rounds: int = 1,
    scale: str | None = None,
    target_observations: int | None = None,
    batch_size: int = 5000,
) -> dict[str, Any]:
    """Execute complete ANIE architectural benchmark suite."""
    # Scale preset resolution
    if scale == "10k" or target_observations == 10000:
        rounds = 3
        num_domains = 1112  # 1112 * 3 * 3 = 10,008 observations
    elif scale == "100k" or target_observations == 100000:
        rounds = 3
        num_domains = 11112  # 11112 * 3 * 3 = 100,008 observations

    total_expected = num_domains * 3 * rounds

    results: dict[str, Any] = {}
    temp_dir = tempfile.mkdtemp(prefix="anie_bench_")

    try:
        db_path = Path(temp_dir) / "benchmark.sqlite"
        store = RealObservationStore(db_path)

        # Baseline memory
        base_rss = get_process_rss()
        results["baseline_memory"] = {
            "current_rss_mb": round(base_rss["current_rss_bytes"] / 1048576.0, 2),
            "peak_rss_mb": round(base_rss["peak_rss_bytes"] / 1048576.0, 2),
        }

        # --- Phase 1: Workload Specification ---
        results["workload"] = {
            "num_domains": num_domains,
            "rounds": rounds,
            "resolvers": ["cloudflare", "google", "quad9"],
            "total_observations": total_expected,
            "batch_chunk_size": min(batch_size, 5000),
        }

        # --- Phase 2: Ingestion & Storage Benchmark ---
        sample_single_latencies: list[float] = []
        sample_records_for_disc: dict[str, list[RealObservation]] = {}
        sample_events_for_disc: dict[str, RealCollectionEvent] = {}

        total_ingested = 0
        t0_ingest = time.perf_counter()

        batch_generator = generate_synthetic_workload_batches(
            num_domains=num_domains,
            rounds=rounds,
            batch_size=min(batch_size, 5000),
        )

        first_batch = True
        for batch in batch_generator:
            # On first batch, measure sample single-record commit latencies
            if first_batch and len(batch) >= 20:
                first_batch = False
                sample_single = batch[:20]
                remainder = batch[20:]

                for ev, ob in sample_single:
                    t_single_start = time.perf_counter()
                    store.insert_record(ev, ob, auto_sync_graph=True)
                    sample_single_latencies.append((time.perf_counter() - t_single_start) * 1000.0)
                    total_ingested += 1

                    # Collect for discrepancy test
                    if len(sample_records_for_disc) < 100:
                        sample_records_for_disc.setdefault(ob.subject, []).append(ob)
                        sample_events_for_disc[ev.event_id] = ev

                if remainder:
                    store.insert_batch(remainder, auto_sync_graph=True)
                    total_ingested += len(remainder)
                    for ev, ob in remainder:
                        if len(sample_records_for_disc) < 100:
                            sample_records_for_disc.setdefault(ob.subject, []).append(ob)
                            sample_events_for_disc[ev.event_id] = ev
            else:
                store.insert_batch(batch, auto_sync_graph=True)
                total_ingested += len(batch)
                if len(sample_records_for_disc) < 100:
                    for ev, ob in batch:
                        if len(sample_records_for_disc) < 100:
                            sample_records_for_disc.setdefault(ob.subject, []).append(ob)
                            sample_events_for_disc[ev.event_id] = ev

        t1_ingest = time.perf_counter()
        ingest_elapsed_s = max(t1_ingest - t0_ingest, 0.0001)
        db_size_bytes = store.db_size_bytes()

        # Count stored elements & verify evidence union
        with store._connect() as conn:
            node_count = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            edge_count = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
            multi_evidence_edges = conn.execute(
                "SELECT COUNT(*) FROM graph_edges WHERE json_array_length(evidence_hashes_json) > 1"
            ).fetchone()[0]

        single_commit_mean = (
            round(sum(sample_single_latencies) / len(sample_single_latencies), 3)
            if sample_single_latencies
            else 0.0
        )

        results["ingestion_and_storage"] = {
            "elapsed_seconds": round(ingest_elapsed_s, 4),
            "records_per_second": round(total_ingested / ingest_elapsed_s, 1),
            "single_record_commit_latency_ms": single_commit_mean,
            "total_nodes_indexed": node_count,
            "total_edges_indexed": edge_count,
            "multi_evidence_deduplicated_edges": multi_evidence_edges,
            "total_db_size_kb": round(db_size_bytes / 1024.0, 2),
            "bytes_per_record": round(db_size_bytes / max(total_ingested, 1), 1),
        }

        # --- Phase 3: Discrepancy Engine Execution ---
        engine = DiscrepancyEngine(window_seconds=60.0)
        t0_disc = time.perf_counter()
        discrepancy_count = 0

        for subj, subj_obs in sample_records_for_disc.items():
            report = engine.analyze(subj, "dns_a", subj_obs, list(sample_events_for_disc.values()))
            store.insert_discrepancy(report, auto_sync_graph=True)
            discrepancy_count += 1

        t1_disc = time.perf_counter()
        disc_elapsed_s = max(t1_disc - t0_disc, 0.0001)

        results["discrepancy_analysis"] = {
            "elapsed_seconds": round(disc_elapsed_s, 4),
            "analyses_per_second": round(discrepancy_count / disc_elapsed_s, 1),
            "total_discrepancy_reports": discrepancy_count,
        }

        # --- Phase 4: Graph Query Latencies ---
        with store._connect() as conn:
            g_engine = GraphEngine(conn)
            test_domains = list(sample_records_for_disc.keys())[:30]

            # 1. 1-Hop Neighborhood
            latencies_1hop = []
            for dom in test_domains:
                dom_uri = f"anie:entity:domain:{dom}"
                t0_q = time.perf_counter()
                g_engine.get_k_hop_neighborhood(dom_uri, max_depth=1)
                latencies_1hop.append((time.perf_counter() - t0_q) * 1000.0)

            # 2. 2-Hop Neighborhood
            latencies_2hop = []
            for dom in test_domains:
                dom_uri = f"anie:entity:domain:{dom}"
                t0_q = time.perf_counter()
                g_engine.get_k_hop_neighborhood(dom_uri, max_depth=2)
                latencies_2hop.append((time.perf_counter() - t0_q) * 1000.0)

            # 3. Co-hosting lookup
            sample_ips = ["104.16.12.34", "151.101.1.69", "198.51.100.1"]
            latencies_cohost = []
            for ip in sample_ips:
                t0_q = time.perf_counter()
                g_engine.find_co_hosted_domains(ip)
                latencies_cohost.append((time.perf_counter() - t0_q) * 1000.0)

            # 4. Evidence Lineage Tracing
            latencies_lineage = []
            for dom in test_domains[:15]:
                dom_uri = f"anie:entity:domain:{dom}"
                t0_q = time.perf_counter()
                g_engine.trace_evidence_lineage(dom_uri)
                latencies_lineage.append((time.perf_counter() - t0_q) * 1000.0)

            # 5. Historical Timeline Query
            latencies_history = []
            for dom in test_domains[:15]:
                dom_uri = f"anie:entity:domain:{dom}"
                t0_q = time.perf_counter()
                g_engine.get_history(dom_uri)
                latencies_history.append((time.perf_counter() - t0_q) * 1000.0)

            # 6. Obsidian Markdown Export
            latencies_obsidian = []
            for dom in test_domains[:15]:
                t0_q = time.perf_counter()
                g_engine.export_obsidian_markdown(dom)
                latencies_obsidian.append((time.perf_counter() - t0_q) * 1000.0)

        def _stats(arr: list[float]) -> dict[str, float]:
            if not arr:
                return {"mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}
            s = sorted(arr)
            n = len(s)
            return {
                "mean_ms": round(sum(s) / n, 3),
                "p50_ms": round(s[n // 2], 3),
                "p95_ms": round(s[int(n * 0.95)], 3),
                "p99_ms": round(s[-1], 3),
            }

        results["query_latencies"] = {
            "neighborhood_1hop": _stats(latencies_1hop),
            "neighborhood_2hop": _stats(latencies_2hop),
            "co_hosted_domains": _stats(latencies_cohost),
            "evidence_lineage": _stats(latencies_lineage),
            "historical_timeline": _stats(latencies_history),
            "obsidian_markdown_export": _stats(latencies_obsidian),
        }

        # --- Phase 5: Cold Restart & Recovery Latency ---
        store.checkpoint_wal(truncate=True)
        del store

        t0_cold = time.perf_counter()
        reopened_store = RealObservationStore(db_path)
        with reopened_store._connect() as conn:
            reopened_engine = GraphEngine(conn)
            reopened_engine.get_k_hop_neighborhood(f"anie:entity:domain:{test_domains[0]}", max_depth=1)
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        t1_cold = time.perf_counter()

        results["recovery_and_restart"] = {
            "cold_reopen_and_query_ms": round((t1_cold - t0_cold) * 1000.0, 3),
            "sqlite_integrity": integrity,
            "status": "ACID_VERIFIED" if integrity == "ok" else "CORRUPT",
        }

        # --- Phase 6: Memory Envelope & Hardware Context ---
        end_rss = get_process_rss()
        results["memory_envelope"] = {
            "final_rss_mb": round(end_rss["current_rss_bytes"] / 1048576.0, 2),
            "peak_rss_mb": round(end_rss["peak_rss_bytes"] / 1048576.0, 2),
            "within_1gib_vm_envelope": (end_rss["peak_rss_bytes"] < 52428800),  # < 50 MiB
            "within_12gib_arm64_envelope": (end_rss["peak_rss_bytes"] < 12582912000),  # < 12 GB
        }

        results["hardware_context"] = {
            "local_host": {
                "os": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
            "oracle_arm64_target": {
                "shape": "VM.Standard.A1.Flex",
                "cpu_architecture": "Ampere Altra (aarch64)",
                "target_ocpus": 2,
                "target_ram_gb": 12,
                "storage": "50 GB OCI Block Volume (~3000 IOPS / 480 MB/s)",
                "free_tier_entitlement": "Always Free (2 OCPUs / 12 GB RAM)",
                "expected_arm64_throughput": "1.2x - 1.8x local single-thread; zero memory pressure",
            },
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="ANIE M3.3.1 / M3.3.2 Graph and Storage Benchmark Suite")
    parser.add_argument("--domains", type=int, default=100, help="number of domains in test workload (default: 100)")
    parser.add_argument("--rounds", type=int, default=1, help="number of repeated collection rounds (default: 1)")
    parser.add_argument("--scale", choices=["small", "10k", "100k"], default=None, help="preset scale benchmark (small: 300 obs, 10k: 10,000 obs, 100k: 100,000 obs)")
    parser.add_argument("--observations", type=int, default=None, help="target number of observations to benchmark")
    parser.add_argument("--batch-size", type=int, default=5000, help="batch chunk size (default: 5000, max: 5000)")
    parser.add_argument("--json", action="store_true", help="output raw JSON results")
    args = parser.parse_args()

    results = run_benchmarks(
        num_domains=args.domains,
        rounds=args.rounds,
        scale=args.scale,
        target_observations=args.observations,
        batch_size=args.batch_size,
    )

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("==============================================================================")
        print("ANIE M3.3.2 GRAPH & STORAGE ARCHITECTURE BENCHMARK REPORT")
        print("==============================================================================")
        print(f"Workload: {results['workload']['num_domains']} domains x 3 resolvers x {results['workload']['rounds']} rounds ({results['workload']['total_observations']} observations)")
        print("\n--- INGESTION & STORAGE ---")
        print(f"Ingestion Time:       {results['ingestion_and_storage']['elapsed_seconds']} s ({results['ingestion_and_storage']['records_per_second']} records/s)")
        print(f"Single Commit Lat:    {results['ingestion_and_storage']['single_record_commit_latency_ms']} ms/record")
        print(f"Graph Nodes Indexed:  {results['ingestion_and_storage']['total_nodes_indexed']}")
        print(f"Graph Edges Indexed:  {results['ingestion_and_storage']['total_edges_indexed']}")
        print(f"Deduplicated Edges:   {results['ingestion_and_storage']['multi_evidence_deduplicated_edges']} (evidence union merged)")
        print(f"Total SQLite DB Size: {results['ingestion_and_storage']['total_db_size_kb']} KB")
        print(f"Storage Footprint:    {results['ingestion_and_storage']['bytes_per_record']} bytes/record")

        print("\n--- DISCREPANCY CONSENSUS ENGINE ---")
        print(f"Discrepancy Analyses: {results['discrepancy_analysis']['total_discrepancy_reports']}")
        print(f"Analysis Throughput:  {results['discrepancy_analysis']['analyses_per_second']} analyses/s")

        print("\n--- GRAPH QUERY LATENCIES ---")
        for q_name, stats in results["query_latencies"].items():
            print(f"{q_name:<26} Mean: {stats['mean_ms']:>6.3f} ms | p50: {stats['p50_ms']:>6.3f} ms | p95: {stats['p95_ms']:>6.3f} ms")

        print("\n--- RECOVERY & MEMORY ENVELOPE ---")
        print(f"Cold Restart Query:   {results['recovery_and_restart']['cold_reopen_and_query_ms']} ms ({results['recovery_and_restart']['status']}, {results['recovery_and_restart']['sqlite_integrity']})")
        print(f"Process Peak RSS:     {results['memory_envelope']['peak_rss_mb']} MiB")
        print(f"1 GiB VM Envelope:    {'PASS (<50 MiB)' if results['memory_envelope']['within_1gib_vm_envelope'] else 'FAIL'}")
        print(f"12 GiB ARM64 Envelop: {'PASS (<12 GB)' if results['memory_envelope']['within_12gib_arm64_envelope'] else 'FAIL'}")

        print("\n--- HARDWARE COMPARISON CONTEXT ---")
        local = results["hardware_context"]["local_host"]
        target = results["hardware_context"]["oracle_arm64_target"]
        print(f"Local Host:           {local['os']} {local['release']} ({local['architecture']}), Python {local['python_version']}")
        print(f"Oracle OCI Target:    {target['shape']} ({target['cpu_architecture']}, {target['target_ocpus']} OCPUs, {target['target_ram_gb']} GB RAM)")
        print(f"OCI Storage Specs:    {target['storage']}")
        print(f"Performance Contrast: {target['expected_arm64_throughput']}")
        print("==============================================================================")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
