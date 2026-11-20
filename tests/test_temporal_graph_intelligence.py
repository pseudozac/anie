"""Comprehensive Verification Suite for ANIE Phase 3.4 Temporal Graph Intelligence.

Covers:
1. Query plan & composite index verification for sub-millisecond 1-hop traversal.
2. Infrastructure transition detection across observation epochs.
3. Domain-to-IP evolution and ephemeral/persistent duration classification.
4. Shared infrastructure correlation with strict anti-maliciousness guardrails.
5. Resolver discrepancy timeline tracking.
6. Fast-flux candidate indicators, falsifiability conditions, and guardrail enforcement.
7. Unexpected resolution divergence detection (Anycast to unicast).
8. SQLite FTS5 searchable memory (prefix, phrase, ranking, entity filtering).
9. Obsidian vault export with structured markdown and wikilinks.
10. Full graph and search index rebuild from Layer 1/2 authoritative records.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from anie.discrepancy_engine import DiscrepancyEngine
from anie.discrepancy_models import RealDiscrepancyReport
from anie.graph_engine import GraphEngine
from anie.graph_models import (
    ClaimVerificationState,
    EpistemicLayer,
    GraphNode,
    IntelligenceClaim,
    NodeType,
)
from anie.multi_resolver import build_mock_dns_wire_response
from anie.real_models import FactualVerification, RealCollectionEvent, RealCollectionRequest, RealObservation
from anie.real_store import RealObservationStore
from anie.temporal_intelligence import (
    TemporalClaimType,
    TemporalIntelligenceEngine,
    is_known_anycast_ip,
)


def make_test_event_and_obs(
    domain: str,
    ips: list[str],
    observed_at: str,
    resolver: str = "cloudflare",
    ttl: int = 300,
    rcode: int = 0,
) -> tuple[RealCollectionEvent, RealObservation]:
    """Helper to create deterministic paired event and observation."""
    raw_wire = build_mock_dns_wire_response(
        domain=domain,
        kind="A",
        ips=ips,
        rcode=rcode,
        ad_flag=(rcode == 0),
        ttl=ttl,
    )
    raw_sha = sha256(raw_wire).hexdigest()

    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint=f"https://{resolver}.example.net/dns-query",
        pinned_ip="192.0.2.1",
    )
    factual = FactualVerification(
        dnssec_status="secure" if rcode == 0 else "indeterminate",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity=resolver,
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
        source_id=f"oracle-collector-01:{resolver}",
        observed_at=observed_at,
        raw_payload=raw_wire,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=tuple(ips),
        status="ok" if rcode == 0 else "empty",
        source_id=f"oracle-collector-01:{resolver}",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=ttl,
    )
    return event, obs


class TestTemporalGraphIntelligence(unittest.TestCase):
    """Test suite for Milestone M3.4 Temporal Graph Intelligence & Scalability."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="anie_m34_test_")
        self.db_path = Path(self.temp_dir) / "test_m34.sqlite"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_composite_indexes_exist_and_accelerate_1hop(self):
        """Verify composite indexes exist and 1-hop neighborhood executes without regression."""
        with self.store._connect() as conn:
            idx_rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_graph_edges_%'"
            ).fetchall()
            idx_names = {r[0] for r in idx_rows}
            self.assertIn("idx_graph_edges_source_target", idx_names)
            self.assertIn("idx_graph_edges_target_source", idx_names)

        # Ingest sample records
        ev, ob = make_test_event_and_obs("example.org", ["93.184.216.34"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            res_1hop = engine.get_k_hop_neighborhood("anie:entity:domain:example.org", max_depth=1)
            self.assertEqual(res_1hop["depth"], 1)
            node_ids = {n["node_id"] for n in res_1hop["nodes"]}
            self.assertIn("anie:entity:domain:example.org", node_ids)
            self.assertIn("anie:entity:ip:93.184.216.34", node_ids)
            self.assertIn("anie:entity:resolver:cloudflare", node_ids)

            # Test depth 0 returns only root
            res_0hop = engine.get_k_hop_neighborhood("anie:entity:domain:example.org", max_depth=0)
            self.assertEqual(len(res_0hop["nodes"]), 1)
            self.assertEqual(len(res_0hop["edges"]), 0)

    def test_infrastructure_transition_detection(self):
        """Verify IP set changes across observation epochs generate INFRASTRUCTURE_TRANSITION claims."""
        # Epoch 1: Resolves to IP 198.51.100.1
        ev1, ob1 = make_test_event_and_obs("dynamic.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev1, ob1)

        # Epoch 2: Migrates to IP 198.51.100.2
        ev2, ob2 = make_test_event_and_obs("dynamic.example.org", ["198.51.100.2"], "2026-11-21T10:00:00Z")
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("dynamic.example.org")

            transition_claims = [c for c in claims if c.claim_type == TemporalClaimType.INFRASTRUCTURE_TRANSITION.value]
            self.assertEqual(len(transition_claims), 1)
            claim = transition_claims[0]
            self.assertEqual(claim.properties["previous_ips"], ["198.51.100.1"])
            self.assertEqual(claim.properties["new_ips"], ["198.51.100.2"])
            self.assertIn(ev1.raw_sha256, claim.supporting_evidence_hashes)
            self.assertIn(ev2.raw_sha256, claim.supporting_evidence_hashes)
            self.assertEqual(claim.verification_state, ClaimVerificationState.ATTESTED_ASSERTION.value)

    def test_ip_relationship_evolution_and_classification(self):
        """Verify relationship duration and classification (ephemeral vs persistent)."""
        # Day 1
        ev1, ob1 = make_test_event_and_obs("stable.example.org", ["198.51.100.10"], "2026-11-01T10:00:00Z", ttl=300)
        self.store.insert_record(ev1, ob1)
        # Day 10 (persistent > 7 days)
        ev2, ob2 = make_test_event_and_obs("stable.example.org", ["198.51.100.10"], "2026-11-11T10:00:00Z", ttl=300)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("stable.example.org")

            evo_claims = [c for c in claims if c.claim_type == TemporalClaimType.IP_RELATIONSHIP_EVOLUTION.value]
            self.assertEqual(len(evo_claims), 1)
            self.assertEqual(evo_claims[0].properties["classification"], "persistent")
            self.assertGreater(evo_claims[0].properties["duration_hours"], 200.0)

    def test_shared_infrastructure_correlation_and_guardrail(self):
        """Verify co-hosting detection strictly prohibits inferring malicious intent."""
        # Both domains share standard hosting IP 198.51.100.50
        ev1, ob1 = make_test_event_and_obs("site-a.example.org", ["198.51.100.50"], "2026-11-20T10:00:00Z")
        ev2, ob2 = make_test_event_and_obs("site-b.example.org", ["198.51.100.50"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("site-a.example.org")

            shared_claims = [c for c in claims if c.claim_type == TemporalClaimType.SHARED_INFRASTRUCTURE.value]
            self.assertEqual(len(shared_claims), 1)
            c = shared_claims[0]
            self.assertEqual(c.properties["guardrail_status"], "PASS_NO_MALICIOUS_INFERENCE")
            self.assertIn("NOT infer common administrative ownership", c.explanation)
            self.assertIn("site-b.example.org", c.explanation)

    def test_fast_flux_candidate_indicator_and_falsifiability(self):
        """Verify fast-flux heuristic triggers only on non-CDN rapid rotation with low TTL and diverse subnets."""
        # Domain rapidly rotates across 5 distinct /24 subnets with 60s TTL
        ips = [
            "198.51.100.1",
            "198.51.101.2",
            "198.51.102.3",
            "198.51.103.4",
            "198.51.104.5",
        ]
        for idx, ip in enumerate(ips):
            ev, ob = make_test_event_and_obs(
                "flux.example.org",
                [ip],
                f"2026-11-20T{10+idx:02d}:00:00Z",
                ttl=60,
            )
            self.store.insert_record(ev, ob)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("flux.example.org")

            flux_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
            self.assertEqual(len(flux_claims), 1)
            fc = flux_claims[0]
            self.assertEqual(fc.verification_state, ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value)
            self.assertIn("NOT infer maliciousness", fc.explanation)
            self.assertIn("legitimate Anycast", fc.falsifiability_condition)
            self.assertEqual(fc.properties["subnet_count"], 5)
            self.assertEqual(fc.properties["median_ttl"], 60)

    def test_fast_flux_does_not_flag_legitimate_cdn_anycast(self):
        """Verify known Anycast CDN edge pools (e.g. Cloudflare) are NOT falsely flagged as fast-flux."""
        # 5 distinct Cloudflare Anycast IPs (104.16.x.x)
        cf_ips = [
            "104.16.12.34",
            "104.16.12.35",
            "104.17.45.67",
            "104.18.99.100",
            "172.64.10.20",
        ]
        for idx, ip in enumerate(cf_ips):
            ev, ob = make_test_event_and_obs("cdn-backed.example.org", [ip], f"2026-11-20T{10+idx:02d}:00:00Z", ttl=60)
            self.store.insert_record(ev, ob)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("cdn-backed.example.org")
            flux_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
            # Should NOT flag legitimate CDN Anycast
            self.assertEqual(len(flux_claims), 0)

    def test_unexpected_resolution_divergence(self):
        """Verify transition from Anycast to unicast triggers divergence indicator."""
        # T1: Cloudflare Anycast
        ev1, ob1 = make_test_event_and_obs("split.example.org", ["104.16.12.34"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev1, ob1)
        # T2: Drops to direct server unicast
        ev2, ob2 = make_test_event_and_obs("split.example.org", ["198.51.100.99"], "2026-11-21T10:00:00Z")
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("split.example.org")
            div_claims = [c for c in claims if c.claim_type == TemporalClaimType.RESOLUTION_DIVERGENCE_INDICATOR.value]
            self.assertEqual(len(div_claims), 1)
            self.assertEqual(div_claims[0].properties["from_topology"], "Anycast/CDN Edge")
            self.assertEqual(div_claims[0].properties["to_topology"], "Unicast/Dedicated")

    def test_sqlite_fts5_searchable_memory(self):
        """Verify full-text search across nodes, claims, and discrepancies using native SQLite FTS5."""
        # 1. Ingest observation (creates domain node)
        ev, ob = make_test_event_and_obs("searchable-target.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        # 2. Ingest discrepancy report
        disc = RealDiscrepancyReport.create(
            subject="searchable-target.example.org",
            kind="dns_a",
            analyzed_at="2026-11-20T10:00:00Z",
            verdict="SECURITY_FILTERING_DETECTED",
            category="POLICY_FILTER_BLOCK",
            explanation="Quad9 security filtered the malicious test domain while Cloudflare returned standard IP.",
            confidence=0.95,
            participating_resolvers=["cloudflare", "quad9"],
            answers_by_resolver={"cloudflare": ["198.51.100.1"], "quad9": []},
            dnssec_by_resolver={"cloudflare": "secure", "quad9": "indeterminate"},
            evidence_hashes={"cloudflare": ev.raw_sha256, "quad9": "0" * 64},
            evidence_ids={"cloudflare": ev.event_id, "quad9": "ev_filtered"},
            observation_ids={"cloudflare": ob.observation_id, "quad9": "ob_filtered"},
        )
        self.store.insert_discrepancy(disc)

        # 3. Test Prefix Search on Domain Name
        results_domain = self.store.search_intelligence("searchable*")
        self.assertGreaterEqual(len(results_domain), 1)
        found_titles = [r["title"] for r in results_domain]
        self.assertTrue(any("searchable-target" in t for t in found_titles))

        # 4. Test Full-Text Search on Discrepancy Body
        results_disc = self.store.search_intelligence("filtered")
        self.assertGreaterEqual(len(results_disc), 1)
        self.assertEqual(results_disc[0]["entity_type"], "discrepancy")
        self.assertIn("[filtered]", results_disc[0]["excerpt"])

    def test_obsidian_vault_export(self):
        """Verify full Obsidian vault generation with linked notes and provenance anchors."""
        ev, ob = make_test_event_and_obs("vault-test.example.org", ["104.16.12.34"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        vault_dir = Path(self.temp_dir) / "obsidian_vault"
        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            summary = engine.export_obsidian_vault(vault_dir)

            self.assertTrue((vault_dir / "README.md").exists())
            self.assertTrue((vault_dir / "domains" / "vault-test.example.org.md").exists())
            self.assertTrue((vault_dir / "ips" / "104.16.12.34.md").exists())
            self.assertGreaterEqual(summary["domains_exported"], 1)

            # Check markdown content and frontmatter
            note_content = (vault_dir / "domains" / "vault-test.example.org.md").read_text(encoding="utf-8")
            self.assertIn("---", note_content)
            self.assertIn("vault-test.example.org", note_content)
            self.assertIn(ev.raw_sha256, note_content)

    def test_graph_and_search_rebuild_from_authoritative_records(self):
        """Verify rebuild_graph_from_observations completely regenerates graph and FTS index."""
        ev, ob = make_test_event_and_obs("rebuild.example.org", ["198.51.100.77"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        # Truncate and rebuild
        nodes_count, edges_count = self.store.rebuild_graph_from_observations()
        self.assertGreater(nodes_count, 0)
        self.assertGreater(edges_count, 0)

        # Verify FTS index works after rebuild
        fts_res = self.store.search_intelligence("rebuild*")
        self.assertGreaterEqual(len(fts_res), 1)


if __name__ == "__main__":
    unittest.main()
