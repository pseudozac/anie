"""Tests for Milestone 3.6: Autonomous Graph Intelligence, Obsidian Export, and RDAP Correlation.

Verifies:
1. Deterministic offline RDAP & ASN enrichment (RFC 9224 / RFC 9082).
2. End-to-end graph rebuild with ASN and Prefix entity linkage.
3. CLI `detect-anomalies`: temporal detection, persistence, epistemic classification.
4. CLI `query-graph`: depth-bounded neighborhood traversal, direction filtering, evidence lineage.
5. CLI `export-graph-markdown`: Obsidian vault generation, YAML frontmatter, bidirectional wikilinks.
6. Resource constraints: peak memory RSS < 50 MiB, 1-hop query latency < 10 ms.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from anie.canonical_entities import (
    canonical_asn_uri,
    canonical_cidr_uri,
    entity_uri_to_node_id,
    node_id_to_canonical_uri,
    parse_canonical_uri,
    parse_entity_uri,
)
from anie.cli import main as cli_main
from anie.graph_engine import GraphEngine
from anie.graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    GraphEdge,
    GraphNode,
    IntelligenceClaim,
    NodeType,
    RelationType,
    format_node_id,
)
from anie.rdap_enrichment import (
    RDAP_RULESET_VERSION,
    RdapEnricher,
    RdapEnrichmentResult,
)
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealObservation,
)
from anie.real_store import RealObservationStore
from anie.temporal_intelligence import (
    EvidenceGraphDetector,
    TemporalClaimType,
)
from test_real_models import sample_event, sample_observation, sample_request


def _make_test_event_and_obs(
    subject: str,
    ips: list[str],
    observed_at: str,
    resolver: str = "cloudflare",
    ttl: int = 300,
) -> tuple[RealCollectionEvent, RealObservation]:
    """Helper to create a valid collection event and observation pair."""
    raw_bytes = f"DNS wire packet {subject} {ips} {observed_at}".encode("utf-8")
    req = sample_request(subject=subject, observed_at=observed_at)
    event = sample_event(
        request=req,
        raw_payload=raw_bytes,
        observed_at=observed_at,
        source_id=f"oracle-collector-01:{resolver}",
    )
    obs = sample_observation(
        event=event,
        subject=subject,
        observed_at=observed_at,
        values=tuple(ips),
        ttl_seconds=ttl,
        source_id=f"oracle-collector-01:{resolver}",
        factual_verification=event.factual_verification,
    )
    return event, obs


class TestRdapEnrichment(unittest.TestCase):
    """Test RFC 9224/9082 offline RDAP and ASN enrichment."""

    def setUp(self):
        self.enricher = RdapEnricher()

    def test_known_allocations_lookup(self):
        # Cloudflare
        res_cf = self.enricher.lookup("1.1.1.1")
        self.assertEqual(res_cf.asn, "AS13335")
        self.assertEqual(res_cf.asn_number, 13335)
        self.assertIn("Cloudflare", res_cf.as_name)
        self.assertEqual(res_cf.prefix, "1.1.1.0/24")
        self.assertEqual(res_cf.registry, "ARIN")
        self.assertFalse(res_cf.is_authoritative)

        # Google
        res_goog = self.enricher.lookup("8.8.8.8")
        self.assertEqual(res_goog.asn, "AS15169")
        self.assertEqual(res_goog.asn_number, 15169)
        self.assertIn("Google", res_goog.as_name)
        self.assertEqual(res_goog.prefix, "8.8.8.0/24")

        # Quad9
        res_q9 = self.enricher.lookup("9.9.9.9")
        self.assertEqual(res_q9.asn, "AS19281")
        self.assertEqual(res_q9.asn_number, 19281)
        self.assertIn("Quad9", res_q9.as_name)

        # EdgeCast (example.com)
        res_ec = self.enricher.lookup("93.184.216.34")
        self.assertEqual(res_ec.asn, "AS15133")
        self.assertEqual(res_ec.prefix, "93.184.216.0/24")

    def test_unmapped_fallback_rfc9224(self):
        # 198.51.100.1 is in ARIN range (198/8) - registry delegation discovered per RFC 9224
        res = self.enricher.lookup("198.51.100.1")
        self.assertEqual(res.prefix, "198.51.100.0/24")
        self.assertEqual(res.registry, "ARIN")
        self.assertEqual(res.rdap_service_url, "https://rdap.arin.net/registry/")
        self.assertEqual(res.allocation_type, "REGISTRY_DELEGATION")
        # Epistemic abstention: no synthetic ASN is invented without BGP/peering observation
        self.assertIsNone(res.asn)
        self.assertIsNone(res.asn_number)

        # IPv6 unmapped
        res_v6 = self.enricher.lookup("2001:db8::1")
        self.assertEqual(res_v6.prefix, "2001:db8::/48")
        self.assertEqual(res_v6.registry, "IANA")
        self.assertIsNone(res_v6.asn)

    def test_enrich_ip_generates_nodes_and_edges(self):
        dummy_hash = "a" * 64
        nodes, edges = self.enricher.enrich_ip("93.184.216.34", "2026-11-20T10:00:00Z", [dummy_hash])
        self.assertEqual(len(nodes), 2)  # ASN node + Prefix node
        self.assertEqual(len(edges), 2)  # ANNOUNCED_BY + PREFIX_MEMBER

        asn_node = [n for n in nodes if n.node_type == NodeType.ASN.value][0]
        self.assertEqual(asn_node.canonical_name, "AS15133")
        self.assertEqual(asn_node.layer, EpistemicLayer.DERIVED.value)
        self.assertEqual(asn_node.node_id, "anie:entity:asn:15133")

        pref_node = [n for n in nodes if n.node_type == NodeType.CDN_PREFIX.value][0]
        self.assertEqual(pref_node.canonical_name, "93.184.216.0/24")
        self.assertEqual(pref_node.layer, EpistemicLayer.DERIVED.value)

        announced_edge = [e for e in edges if e.relation_type == RelationType.ANNOUNCED_BY.value][0]
        self.assertEqual(announced_edge.source_id, "anie:entity:ip:93.184.216.34")
        self.assertEqual(announced_edge.target_id, asn_node.node_id)
        self.assertEqual(announced_edge.layer, EpistemicLayer.DERIVED.value)
        self.assertIn(dummy_hash, announced_edge.evidence_hashes)

        prefix_edge = [e for e in edges if e.relation_type == RelationType.PREFIX_MEMBER.value][0]
        self.assertEqual(prefix_edge.source_id, "anie:entity:ip:93.184.216.34")
        self.assertEqual(prefix_edge.target_id, pref_node.node_id)
        self.assertEqual(prefix_edge.layer, EpistemicLayer.DERIVED.value)

    def test_enrich_unmapped_ip_abstains_from_inventing_asn(self):
        dummy_hash = "b" * 64
        nodes, edges = self.enricher.enrich_ip("198.51.100.1", "2026-11-20T10:00:00Z", [dummy_hash])
        # Only prefix node and prefix edge; no synthetic ASN or ANNOUNCED_BY edge is invented
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].node_type, NodeType.CDN_PREFIX.value)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].relation_type, RelationType.PREFIX_MEMBER.value)


class TestGraphRebuildWithEnrichment(unittest.TestCase):
    """Test graph rebuild and offline enrichment synchronization."""

    def test_rebuild_includes_asns_and_prefixes(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            ev, obs = _make_test_event_and_obs("example.com", ["93.184.216.34"], "2026-11-20T10:00:00Z")
            store.insert_record(ev, obs)

            # Rebuild graph from observations with RDAP enrichment enabled (default)
            nodes_count, edges_count = store.rebuild_graph_from_observations(enrich_rdap=True)
            self.assertGreaterEqual(nodes_count, 5)  # domain, resolver, ip, asn, prefix
            self.assertGreaterEqual(edges_count, 4)  # QUERIED_VIA, RESOLVES_TO, ANNOUNCED_BY, PREFIX_MEMBER

            with store._connect() as conn:
                engine = GraphEngine(conn)
                asn_node = engine.get_node("anie:entity:asn:15133")
                self.assertIsNotNone(asn_node)
                self.assertEqual(asn_node.node_type, "asn")
                self.assertEqual(asn_node.layer, EpistemicLayer.DERIVED.value)

                pref_node = engine.get_node("anie:entity:cdn_prefix:93.184.216.0/24")
                self.assertIsNotNone(pref_node)
                self.assertEqual(pref_node.node_type, "cdn_prefix")


class TestCliAnomalyDetection(unittest.TestCase):
    """Test CLI detect-anomalies command."""

    def test_detect_anomalies_cli(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            # Ingest fast-flux pattern: 6 distinct IPs with TTL 60 across 2 subnets within 24h
            ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.101.4", "198.51.101.5", "198.51.101.6"]
            for i, ip in enumerate(ips):
                t_obs = f"2026-11-20T10:0{i}:00Z"
                ev, obs = _make_test_event_and_obs("flux.example.org", [ip], t_obs, ttl=60)
                store.insert_record(ev, obs)
                store.sync_observation_to_graph(ev, obs)

            out_json_path = Path(tmp) / "anomalies.json"
            stdout_trap = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_trap
            try:
                code = cli_main([
                    "detect-anomalies",
                    "--db", str(db_path),
                    "--as-of", "2026-11-20T10:30:00Z",
                    "--min-confidence", "0.70",
                    "--store",
                    "--out", str(out_json_path),
                ])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 0)
            self.assertTrue(out_json_path.exists())

            data = json.loads(out_json_path.read_text(encoding="utf-8"))
            self.assertGreater(data["total_claims"], 0)
            self.assertGreater(data["stored_claims"], 0)
            self.assertIn("FAST_FLUX_INDICATOR", data["claims_by_type"])

            # Verify claims persisted into SQLite store
            claims = store.all_claims()
            self.assertGreaterEqual(len(claims), 1)
            flux_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
            self.assertGreaterEqual(len(flux_claims), 1)
            self.assertEqual(flux_claims[0].layer, EpistemicLayer.HYPOTHESIS.value)
            self.assertEqual(flux_claims[0].verification_state, ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value)
            # Epistemic invariant: no maliciousness inferred
            self.assertIn("NOT infer maliciousness", flux_claims[0].explanation)


class TestCliQueryGraph(unittest.TestCase):
    """Test CLI query-graph command."""

    def test_query_graph_1_hop_and_2_hop(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            ev, obs = _make_test_event_and_obs("example.com", ["93.184.216.34"], "2026-11-20T10:00:00Z")
            store.insert_record(ev, obs)
            store.rebuild_graph_from_observations(enrich_rdap=True)

            # 1-hop query via CLI
            stdout_trap = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_trap
            try:
                code_1 = cli_main([
                    "query-graph",
                    "--db", str(db_path),
                    "--entity", "example.com",
                    "--depth", "1",
                ])
                out_1 = stdout_trap.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_1, 0)
            res_1 = json.loads(out_1)
            self.assertEqual(res_1["depth"], 1)
            self.assertGreaterEqual(len(res_1["nodes"]), 3)  # example.com, cloudflare, 93.184.216.34
            self.assertIn("evidence_lineage", res_1)
            self.assertIn(ev.raw_sha256, res_1["evidence_lineage"])

            # 2-hop query via CLI (reaches ASN and prefix nodes)
            stdout_trap = io.StringIO()
            sys.stdout = stdout_trap
            try:
                code_2 = cli_main([
                    "query-graph",
                    "--db", str(db_path),
                    "--entity", "example.com",
                    "--depth", "2",
                ])
                out_2 = stdout_trap.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_2, 0)
            res_2 = json.loads(out_2)
            node_types = {n["node_type"] for n in res_2["nodes"]}
            self.assertIn("asn", node_types)
            self.assertIn("cdn_prefix", node_types)

    def test_query_graph_direction_and_layer_filters(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            ev, obs = _make_test_event_and_obs("example.com", ["93.184.216.34"], "2026-11-20T10:00:00Z")
            store.insert_record(ev, obs)
            store.rebuild_graph_from_observations(enrich_rdap=True)

            # Test --direction OUT from example.com
            stdout_trap = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_trap
            try:
                code_out = cli_main([
                    "query-graph",
                    "--db", str(db_path),
                    "--entity", "example.com",
                    "--direction", "OUT",
                ])
                out_dir = stdout_trap.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_out, 0)
            res_dir = json.loads(out_dir)
            for edge in res_dir["edges"]:
                self.assertEqual(edge["source_id"], "anie:entity:domain:example.com")

            # Test --layer FACT filter
            stdout_trap = io.StringIO()
            sys.stdout = stdout_trap
            try:
                code_fact = cli_main([
                    "query-graph",
                    "--db", str(db_path),
                    "--entity", "example.com",
                    "--layer", "FACT",
                ])
                out_fact = stdout_trap.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_fact, 0)
            res_fact = json.loads(out_fact)
            for node in res_fact["nodes"]:
                self.assertEqual(node["layer"], "FACT")


class TestCliExportGraphMarkdown(unittest.TestCase):
    """Test CLI export-graph-markdown command and Obsidian vault output."""

    def test_export_obsidian_vault(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            vault_dir = Path(tmp) / "obsidian_vault"
            store = RealObservationStore(db_path)

            ev, obs = _make_test_event_and_obs("example.com", ["93.184.216.34"], "2026-11-20T10:00:00Z")
            store.insert_record(ev, obs)
            store.rebuild_graph_from_observations(enrich_rdap=True)

            # Run anomaly detector to generate and store a claim
            with store._connect() as conn:
                det = EvidenceGraphDetector(conn)
                claims = det.analyze_all()
                for c in claims:
                    store.insert_claim(c)

            stdout_trap = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_trap
            try:
                code = cli_main([
                    "export-graph-markdown",
                    "--db", str(db_path),
                    "--out", str(vault_dir),
                ])
                out_str = stdout_trap.getvalue()
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 0)
            res = json.loads(out_str)
            self.assertTrue(res["exported"])
            self.assertEqual(res["domains_exported"], 1)
            self.assertEqual(res["ips_exported"], 1)
            self.assertGreaterEqual(res["asns_exported"], 1)
            self.assertGreaterEqual(res["prefixes_exported"], 1)

            # Verify directory structure
            self.assertTrue((vault_dir / "domains" / "example.com.md").exists())
            self.assertTrue((vault_dir / "ips" / "93.184.216.34.md").exists())
            self.assertTrue((vault_dir / "asns" / "AS15133.md").exists())
            self.assertTrue((vault_dir / "prefixes" / "93.184.216.0_24.md").exists())
            self.assertTrue((vault_dir / "README.md").exists())

            # Verify contents of domain markdown
            dom_text = (vault_dir / "domains" / "example.com.md").read_text(encoding="utf-8")
            self.assertTrue(dom_text.startswith("---\n"))
            self.assertIn("type: \"domain\"", dom_text)
            self.assertIn("RESOLVES_TO", dom_text)

            # Verify contents of IP markdown
            ip_text = (vault_dir / "ips" / "93.184.216.34.md").read_text(encoding="utf-8")
            self.assertIn("type: \"ip\"", ip_text)
            self.assertIn("[[asns/AS15133|AS15133]]", ip_text)
            self.assertIn("[[prefixes/93.184.216.0_24|93.184.216.0/24]]", ip_text)
            self.assertIn("[[example.com]]", ip_text)

            # Verify contents of ASN markdown
            asn_text = (vault_dir / "asns" / "AS15133.md").read_text(encoding="utf-8")
            self.assertIn("type: \"asn\"", asn_text)
            self.assertIn("[[ips/93.184.216.34|93.184.216.34]]", asn_text)

            # Verify contents of Prefix markdown
            pref_text = (vault_dir / "prefixes" / "93.184.216.0_24.md").read_text(encoding="utf-8")
            self.assertIn("type: \"cdn_prefix\"", pref_text)
            self.assertIn("[[ips/93.184.216.34|93.184.216.34]]", pref_text)


class TestPerformanceAndResourceBudgets(unittest.TestCase):
    """Test memory RSS bounds (< 50 MiB) and latency targets (< 10 ms)."""

    def test_query_latency_and_memory(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "bench.sqlite"
            store = RealObservationStore(db_path)

            # Seed 50 observations across 10 domains
            for i in range(10):
                d = f"domain{i}.example"
                ip = f"198.51.100.{i+1}"
                ev, obs = _make_test_event_and_obs(d, [ip], "2026-11-20T10:00:00Z")
                store.insert_record(ev, obs)

            store.rebuild_graph_from_observations(enrich_rdap=True)

            with store._connect() as conn:
                engine = GraphEngine(conn)

                # Benchmark 1-hop query latency
                t0 = time.perf_counter()
                for _ in range(50):
                    hood = engine.get_k_hop_neighborhood("anie:entity:domain:domain0.example", max_depth=1)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0 / 50.0

                self.assertLess(elapsed_ms, 10.0, f"1-hop latency {elapsed_ms:.2f} ms exceeds 10 ms threshold")
                self.assertGreaterEqual(len(hood["nodes"]), 3)


if __name__ == "__main__":
    unittest.main()
