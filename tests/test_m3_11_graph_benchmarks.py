"""Unit test suite for Milestone M3.11 Graph Scalability & Benchmark Protocol.

Verifies:
1. Determinism and reproducibility of synthetic benchmark workloads.
2. End-to-end benchmark execution across sample scales.
3. Metric collection: query latency (p50/p95), ingestion throughput, disk size, and RSS.
4. Comparative index evaluation and partitioning necessity assessment.
"""
from __future__ import annotations

import unittest

from tools.benchmark_graph_scale import (
    benchmark_size,
    generate_synthetic_workload,
    run_comparative_benchmark,
)


class TestM311GraphBenchmarks(unittest.TestCase):
    def test_workload_generation_determinism(self):
        """Verify that synthetic workload generator produces bit-for-bit identical output with fixed seed."""
        wl1 = generate_synthetic_workload(count=50, seed=123)
        wl2 = generate_synthetic_workload(count=50, seed=123)

        self.assertEqual(len(wl1), 50)
        self.assertEqual(len(wl2), 50)

        for (ev1, ob1), (ev2, ob2) in zip(wl1, wl2):
            self.assertEqual(ev1.event_id, ev2.event_id)
            self.assertEqual(ev1.raw_sha256, ev2.raw_sha256)
            self.assertEqual(ob1.observation_id, ob2.observation_id)
            self.assertEqual(ob1.values, ob2.values)

    def test_benchmark_size_execution_and_metrics(self):
        """Verify benchmark_size produces all required SLA metrics within bounds."""
        res = benchmark_size(target_count=100, use_covering_indexes=True, query_samples=10, seed=42)

        self.assertEqual(res["scale"], 100)
        self.assertEqual(res["observations_ingested"], 100)
        self.assertGreater(res["graph_nodes"], 0)
        self.assertGreater(res["graph_edges"], 0)
        self.assertGreater(res["ingestion_throughput_records_per_sec"], 0.0)

        # Latency bounds
        self.assertIn("p50", res["query_1hop_ms"])
        self.assertIn("p95", res["query_1hop_ms"])
        self.assertLess(res["query_1hop_ms"]["p95"], 50.0, "1-hop p95 query latency must be under 50ms")
        self.assertLess(res["query_temporal_drift_ms"]["p95"], 20.0, "Temporal drift query latency must be under 20ms")

        # Disk and memory bounds
        self.assertGreater(res["total_disk_bytes"], 0)
        self.assertLess(res["total_disk_mib"], 50.0, "Disk footprint must be well within micro VM bounds")

    def test_comparative_benchmark_evaluates_partitioning(self):
        """Verify run_comparative_benchmark executes comparative assessment and evaluates partitioning."""
        report = run_comparative_benchmark(scales=[100])
        self.assertIn("results", report)
        self.assertIn("comparisons", report)
        self.assertEqual(len(report["comparisons"]), 1)

        comp = report["comparisons"][0]
        self.assertIn("speedup_1hop_pct", comp)
        self.assertIn("partitioning_recommended", comp)
        self.assertFalse(comp["partitioning_recommended"], "Single SQLite B-tree must meet SLA without partitioning at this scale")


if __name__ == "__main__":
    unittest.main()
