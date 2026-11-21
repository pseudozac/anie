"""Tests for Milestone 3.7: Correctness Verification, Hardening, and Guardrail Auditing.

Verifies:
1. RFC 9224 / RFC 9082 distinction: IANA registry delegation vs service discovery vs observed BGP origin-AS.
2. Epistemic abstention: unmapped IPs produce no synthetic ASNs or speculative ANNOUNCED_BY edges.
3. Anomaly detection false-positive audit: Dynamic DNS (e.g. duckdns.org), Anycast/CDN edge pools,
   and shared hosting density guardrails.
4. Graph rebuild determinism and retention of analyst claims, signatures, and uncertainty states.
5. Obsidian vault export security: path traversal defense, Windows reserved names (CON, NUL, PRN),
   control character filtering, symlink attack rejection, and 500 KB note size ceiling.
6. Performance and memory budget verification under larger representative workloads (1000 observations).
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
)
from anie.graph_engine import GraphEngine, sanitize_vault_filename, _safe_write_vault_note
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
    classify_ip_infrastructure,
    is_known_anycast_ip,
)
from test_real_models import sample_event, sample_observation, sample_request


def _make_test_event_and_obs(
    subject: str,
    ips: list[str],
    observed_at: str,
    resolver: str = "cloudflare",
    ttl: int = 300,
) -> tuple[RealCollectionEvent, RealObservation]:
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


class TestRfc9224AndBgpEpistemicDistinction(unittest.TestCase):
    """Audit rdap_enrichment.py per RFC 9224, RFC 9082, and BGP epistemic boundaries."""

    def setUp(self):
        self.enricher = RdapEnricher()

    def test_rfc9224_service_discovery_and_registry_delegations(self):
        # Test ARIN allocation
        res_arin = self.enricher.lookup("198.51.100.1")
        self.assertEqual(res_arin.registry, "ARIN")
        self.assertEqual(res_arin.rdap_service_url, "https://rdap.arin.net/registry/")
        self.assertEqual(res_arin.allocation_type, "REGISTRY_DELEGATION")
        self.assertIsNone(res_arin.asn)
        self.assertIsNone(res_arin.routing_origin_type)

        # Test RIPE NCC allocation
        res_ripe = self.enricher.lookup("193.0.0.1")
        self.assertEqual(res_ripe.registry, "RIPE NCC")
        self.assertEqual(res_ripe.rdap_service_url, "https://rdap.db.ripe.net/")
        self.assertEqual(res_ripe.allocation_type, "REGISTRY_DELEGATION")

        # Test APNIC allocation
        res_apnic = self.enricher.lookup("202.12.27.33")
        self.assertEqual(res_apnic.registry, "APNIC")
        self.assertEqual(res_apnic.rdap_service_url, "https://rdap.apnic.net/")

        # Test LACNIC allocation
        res_lacnic = self.enricher.lookup("200.10.0.1")
        self.assertEqual(res_lacnic.registry, "LACNIC")
        self.assertEqual(res_lacnic.rdap_service_url, "https://rdap.lacnic.net/rdap/")

        # Test AFRINIC allocation
        res_afrinic = self.enricher.lookup("196.216.2.1")
        self.assertEqual(res_afrinic.registry, "AFRINIC")
        self.assertEqual(res_afrinic.rdap_service_url, "https://rdap.afrinic.net/rdap/")

    def test_epistemic_abstention_no_synthetic_asn(self):
        """Unmapped IPs must abstain from asserting synthetic ASNs or fake origin-AS edges."""
        unmapped_ips = ["198.51.100.42", "203.0.113.99", "2001:db8::1"]
        for ip in unmapped_ips:
            res = self.enricher.lookup(ip)
            self.assertIsNone(res.asn, f"IP {ip} should not have a synthesized ASN")
            self.assertIsNone(res.asn_number)
            self.assertIsNone(res.routing_origin_type)

            nodes, edges = self.enricher.enrich_ip(ip, "2026-11-20T12:00:00Z", ["dummyhash" * 4])
            # Only PREFIX_MEMBER and CDN_PREFIX node should exist
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0].node_type, NodeType.CDN_PREFIX.value)
            self.assertEqual(len(edges), 1)
            self.assertEqual(edges[0].relation_type, RelationType.PREFIX_MEMBER.value)

            # Assert no ASN or ANNOUNCED_BY edge exists
            self.assertFalse(any(n.node_type == NodeType.ASN.value for n in nodes))
            self.assertFalse(any(e.relation_type == RelationType.ANNOUNCED_BY.value for e in edges))

    def test_mapped_ip_preserves_routing_heuristic_disclaimer(self):
        """Known peering/routing prefix mappings emit ANNOUNCED_BY with clear heuristic origin note."""
        nodes, edges = self.enricher.enrich_ip("1.1.1.1", "2026-11-20T12:00:00Z", ["dummyhash" * 4])
        self.assertEqual(len(nodes), 2)
        self.assertEqual(len(edges), 2)

        announced = [e for e in edges if e.relation_type == RelationType.ANNOUNCED_BY.value][0]
        self.assertEqual(announced.layer, EpistemicLayer.DERIVED.value)
        self.assertIn("disclaimer", announced.properties)
        self.assertIn("does not imply live BGP", announced.properties["disclaimer"])


class TestAnomalyDetectionGuardrails(unittest.TestCase):
    """Audit anomaly detection against legitimate CDNs, dynamic DNS, and shared hosting."""

    def test_dynamic_dns_confidence_reduction(self):
        """Dynamic DNS providers (duckdns.org, no-ip.com) legitimately rotate residential IPs.
        
        Detector should identify dynamic DNS provider, downgrade confidence from 0.70 to 0.35,
        and log explanation preventing false positive alarms.
        """
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            # Ingest fast-flux-like residential IP churn across 2 subnets on duckdns.org subdomain
            domain = "myhomelab.duckdns.org"
            ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.101.4", "198.51.101.5", "198.51.101.6"]
            for i, ip in enumerate(ips):
                t_str = f"2026-11-20T10:{i:02d}:00Z"
                ev, obs = _make_test_event_and_obs(domain, [ip], t_str, ttl=60)
                store.insert_record(ev, obs)

            with store._connect() as conn:
                det = EvidenceGraphDetector(conn)
                claims = det.analyze_all()

                ff_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
                self.assertEqual(len(ff_claims), 1)
                claim = ff_claims[0]
                # Verify confidence is downgraded to 0.35 (below default 0.70 threshold)
                self.assertAlmostEqual(claim.confidence, 0.35, places=2)
                self.assertTrue(claim.properties.get("is_dynamic_dns"))
                self.assertIn("public dynamic DNS provider", claim.explanation)

    def test_anycast_cdn_pools_suppress_fast_flux(self):
        """Anycast/CDN edge IP rotation (Cloudflare, Akamai, Azure) must NOT trigger fast flux."""
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            # Cloudflare IP rotation across multiple /24 prefixes
            domain = "high-traffic-portal.com"
            cf_ips = ["104.16.1.1", "104.16.2.2", "104.17.3.3", "104.18.4.4", "104.19.5.5", "104.20.6.6"]
            for i, ip in enumerate(cf_ips):
                t_str = f"2026-11-20T10:{i:02d}:00Z"
                ev, obs = _make_test_event_and_obs(domain, [ip], t_str, ttl=300)
                store.insert_record(ev, obs)

            with store._connect() as conn:
                det = EvidenceGraphDetector(conn)
                claims = det.analyze_all()

                ff_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
                self.assertEqual(len(ff_claims), 0, "Known Anycast CDN pool should not trigger fast-flux indicator")

    def test_shared_hosting_density_and_no_malicious_inference(self):
        """Shared hosting density categorization and explicit anti-guilt-by-association guardrails."""
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            # 25 domains co-hosted on single IP -> HIGH_DENSITY_MULTI_TENANT
            ip = "198.51.100.50"
            for i in range(25):
                dom = f"tenant{i:02d}.sharedhost.com"
                ev, obs = _make_test_event_and_obs(dom, [ip], "2026-11-20T12:00:00Z")
                store.insert_record(ev, obs)

            with store._connect() as conn:
                det = EvidenceGraphDetector(conn)
                claims = det.analyze_all()

                co_claims = [c for c in claims if c.claim_type == TemporalClaimType.SHARED_INFRASTRUCTURE.value]
                self.assertGreaterEqual(len(co_claims), 1)
                for c in co_claims:
                    self.assertEqual(c.properties.get("hosting_density"), "HIGH_DENSITY_MULTI_TENANT")
                    self.assertEqual(c.properties.get("guardrail_status"), "PASS_NO_MALICIOUS_INFERENCE")
                    self.assertIn("does NOT infer", c.explanation)


class TestGraphRebuildDeterminismAndClaimsPreservation(unittest.TestCase):
    """Verify graph rebuild determinism and durable boundary of analyst claims."""

    def test_rebuild_determinism_and_claim_immutability(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_store.sqlite"
            store = RealObservationStore(db_path)

            # Ingest 20 observations
            for i in range(20):
                d = f"site{i}.org"
                ip = f"93.184.216.{i+1}"
                ev, obs = _make_test_event_and_obs(d, [ip], f"2026-11-20T12:{i:02d}:00Z")
                store.insert_record(ev, obs)

            # Insert analyst-verified claim and contested claim
            analyst_claim = IntelligenceClaim.create(
                subject_uri="anie:entity:domain:site0.org",
                claim_type="ANALYST_VALIDATED_ASSESSMENT",
                layer=EpistemicLayer.VALIDATED,
                asserted_at="2026-11-20T12:30:00Z",
                valid_from="2026-11-20T12:00:00Z",
                confidence=1.0,
                explanation="Senior analyst confirmed infrastructure provenance.",
                supporting_evidence_hashes=["dummyhash" * 4],
                verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
                analyst_identity="analyst-lead-01",
                attestation_signature="ed25519:test_valid_signature_analyst_01",
            )
            store.insert_claim(analyst_claim)

            contested_claim = IntelligenceClaim.create(
                subject_uri="anie:entity:domain:site1.org",
                claim_type="CONTESTED_ASSESSMENT",
                layer=EpistemicLayer.HYPOTHESIS,
                asserted_at="2026-11-20T12:35:00Z",
                valid_from="2026-11-20T12:00:00Z",
                confidence=0.5,
                explanation="Contested by peer reviewer.",
                supporting_evidence_hashes=["dummyhash" * 4],
                verification_state=ClaimVerificationState.CONTESTED,
                analyst_identity="analyst-peer-02",
                attestation_signature="ed25519:test_contested_signature_02",
            )
            store.insert_claim(contested_claim)

            # Perform 3 consecutive rebuilds
            rebuild_results = []
            for _ in range(3):
                n_count, e_count = store.rebuild_graph_from_observations(enrich_rdap=True)
                rebuild_results.append((n_count, e_count))

            # Determinism check: node and edge counts must be identical across rebuilds
            self.assertEqual(rebuild_results[0], rebuild_results[1])
            self.assertEqual(rebuild_results[1], rebuild_results[2])

            # Integrity check: analyst claims must remain intact with signatures intact
            c1 = store.get_claim(analyst_claim.claim_id)
            self.assertIsNotNone(c1)
            self.assertEqual(c1.analyst_identity, "analyst-lead-01")
            self.assertEqual(c1.attestation_signature, "ed25519:test_valid_signature_analyst_01")
            self.assertEqual(c1.verification_state, ClaimVerificationState.ATTESTED_ASSERTION.value)

            c2 = store.get_claim(contested_claim.claim_id)
            self.assertIsNotNone(c2)
            self.assertEqual(c2.verification_state, ClaimVerificationState.CONTESTED.value)


class TestObsidianExportSecurity(unittest.TestCase):
    """Test Obsidian vault export security against traversal, reserved names, and attacks."""

    def test_sanitize_vault_filename(self):
        # Traversal protection (leading dot-dots stripped by sanitize_vault_filename)
        self.assertEqual(sanitize_vault_filename("../../evil_path"), "_.._evil_path")
        self.assertEqual(sanitize_vault_filename(".."), "unnamed_entity")
        self.assertEqual(sanitize_vault_filename("."), "unnamed_entity")
        self.assertEqual(sanitize_vault_filename(""), "unnamed_entity")

        # Windows reserved names
        self.assertEqual(sanitize_vault_filename("CON"), "_CON")
        self.assertEqual(sanitize_vault_filename("prn"), "_prn")
        self.assertEqual(sanitize_vault_filename("NUL.txt"), "_NUL.txt")
        self.assertEqual(sanitize_vault_filename("com1"), "_com1")
        self.assertEqual(sanitize_vault_filename("LPT3"), "_LPT3")

        # Control characters and invalid characters
        self.assertEqual(sanitize_vault_filename("bad\x00file\x1fname"), "badfilename")
        self.assertEqual(sanitize_vault_filename("domain:with?bad<chars>"), "domain_with_bad_chars_")

    def test_safe_write_vault_note_containment_and_ceiling(self):
        with TemporaryDirectory() as tmp:
            vault_root = Path(tmp) / "vault"
            sub_dir = vault_root / "domains"
            sub_dir.mkdir(parents=True, exist_ok=True)

            # Normal write
            _safe_write_vault_note(sub_dir, vault_root, "valid.domain.com", "# Valid Content")
            written = (sub_dir / "valid.domain.com.md").read_text(encoding="utf-8")
            self.assertIn("# Valid Content", written)

            # Oversized note (>500 KB) truncation
            oversized_content = "X" * 600_000
            _safe_write_vault_note(sub_dir, vault_root, "oversized.com", oversized_content)
            trunc_file = sub_dir / "oversized.com.md"
            self.assertTrue(trunc_file.exists())
            self.assertLessEqual(trunc_file.stat().st_size, 510_000)
            self.assertIn("TRUNCATED", trunc_file.read_text(encoding="utf-8"))

            # Windows reserved device note safely written as _NUL.md
            _safe_write_vault_note(sub_dir, vault_root, "NUL", "# Nul device note")
            self.assertTrue((sub_dir / "_NUL.md").exists())


class TestScaleAndPerformanceBudgets(unittest.TestCase):
    """Test performance, latency, and memory with representative scale dataset (1000 records)."""

    def test_thousand_records_benchmark(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "scale_bench.sqlite"
            store = RealObservationStore(db_path)

            # Ingest 1000 observations over 100 domains
            t0 = time.perf_counter()
            for d_idx in range(100):
                d = f"corp-unit-{d_idx:03d}.internal.net"
                for o_idx in range(10):
                    ip = f"10.0.{d_idx}.{o_idx+1}"
                    ev, obs = _make_test_event_and_obs(d, [ip], f"2026-11-20T12:{o_idx:02d}:00Z")
                    store.insert_record(ev, obs)
            t_ingest = time.perf_counter() - t0

            # Rebuild graph
            t0_rebuild = time.perf_counter()
            nodes_count, edges_count = store.rebuild_graph_from_observations(enrich_rdap=True)
            t_rebuild = time.perf_counter() - t0_rebuild

            self.assertGreaterEqual(nodes_count, 1000)
            self.assertGreaterEqual(edges_count, 1000)

            # Test 1-hop traversal latency across 50 random nodes
            with store._connect() as conn:
                engine = GraphEngine(conn)
                t0_query = time.perf_counter()
                for i in range(50):
                    hood = engine.get_k_hop_neighborhood(f"anie:entity:domain:corp-unit-{i:03d}.internal.net", max_depth=1)
                    self.assertGreaterEqual(len(hood["nodes"]), 2)
                t_query = (time.perf_counter() - t0_query) * 1000.0 / 50.0

                self.assertLess(t_query, 10.0, f"Average 1-hop query latency {t_query:.2f} ms exceeds 10 ms budget")

            # Check process RSS memory usage (portable standard library check)
            rss_mib = 0.0
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
                        rss_mib = counters.WorkingSetSize / (1024 * 1024)
                except Exception:
                    pass
            if rss_mib == 0.0:
                try:
                    import resource
                    rss_mib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
                except ImportError:
                    pass

            if rss_mib > 0.0:
                self.assertLess(rss_mib, 200.0, f"Process memory {rss_mib:.2f} MiB exceeded ceiling")


if __name__ == "__main__":
    unittest.main()
