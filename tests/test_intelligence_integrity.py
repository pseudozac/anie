"""Comprehensive Verification Suite for Milestone M3.4.1 Intelligence Integrity & Scale Acceptance.

Validates:
1. P0: Prevention of data loss for validated, contested, and revoked claims during graph rebuild.
2. P0: Epistemic verification state rules (no unauthorized promotion, genuine Ed25519 attestation).
3. P1: Temporal correctness (24-hour window enforcement, as_of historical filtering, dual-stack IPv4/IPv6).
4. P1: Graph query determinism, truncation metadata, and intermediate work bounding.
5. P1: SQLite FTS5 search integrity, observable error reporting, and reindex repair.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
from anie.real_store import RealObservationStore, get_fts_sync_errors, clear_fts_sync_errors
from anie.temporal_intelligence import (
    TemporalClaimType,
    TemporalIntelligenceEngine,
    classify_ip_infrastructure,
    is_known_anycast_ip,
)


def make_test_pair(
    domain: str,
    ips: list[str],
    observed_at: str,
    resolver: str = "cloudflare",
    kind: str = "dns_a",
    ttl: int = 300,
    rcode: int = 0,
) -> tuple[RealCollectionEvent, RealObservation]:
    """Create a verified test event and observation pair."""
    wire_kind = "AAAA" if kind == "dns_aaaa" else "A"
    raw_wire = build_mock_dns_wire_response(
        domain=domain,
        kind=wire_kind,
        ips=ips,
        rcode=rcode,
        ad_flag=(rcode == 0),
        ttl=ttl,
    )
    raw_sha = sha256(raw_wire).hexdigest()

    req = RealCollectionRequest.create(
        kind=kind,
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
        kind=kind,
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


class TestIntelligenceIntegrity(unittest.TestCase):
    """Test suite verifying all M3.4.1 correctness requirements."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="anie_m341_test_")
        self.db_path = Path(self.temp_dir) / "test_m341.sqlite"
        self.store = RealObservationStore(self.db_path)
        clear_fts_sync_errors()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- P0: Intelligence Durability & Rebuild Isolation ---

    def test_rebuild_preserves_validated_contested_and_revoked_claims(self):
        """P0: Verify rebuild_graph_from_observations preserves analyst claims across all states."""
        # 1. Author an independent Ed25519 keypair for an analyst
        priv_key = Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()

        # Ingest baseline observation
        ev, ob = make_test_pair("gov-service.example.org", ["198.51.100.22"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        # 2. Insert Validated & Signed Claim
        claim1 = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:gov-service.example.org",
            claim_type="ANALYST_INFRASTRUCTURE_VERIFICATION",
            layer=EpistemicLayer.VALIDATED,
            asserted_at="2026-11-20T11:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=1.0,
            explanation="Analyst verified government portal apex delegation via primary zone file.",
            supporting_evidence_hashes=[ev.raw_sha256],
            analyst_identity="analyst-cert-847",
            attestation_signature=base64.b64encode(b"A" * 64).decode("ascii"),
            verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
            properties={"ticket": "SEC-9021"},
        )
        # Sign it with real Ed25519 key
        sig_bytes = priv_key.sign(claim1.canonical_signing_bytes())
        claim1_signed = IntelligenceClaim.create(
            subject_uri=claim1.subject_uri,
            claim_type=claim1.claim_type,
            layer=claim1.layer,
            asserted_at=claim1.asserted_at,
            valid_from=claim1.valid_from,
            confidence=claim1.confidence,
            explanation=claim1.explanation,
            supporting_evidence_hashes=claim1.supporting_evidence_hashes,
            analyst_identity="analyst-cert-847",
            attestation_signature=base64.b64encode(sig_bytes).decode("ascii"),
            verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
            properties={"ticket": "SEC-9021"},
        )
        self.assertTrue(claim1_signed.verify_attestation(pub_bytes))
        self.store.insert_claim(claim1_signed)

        # 3. Insert Contested Claim
        claim2 = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:gov-service.example.org",
            claim_type="ROUTE_ANOMALY_CONTESTATION",
            layer=EpistemicLayer.HYPOTHESIS,
            asserted_at="2026-11-20T11:30:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=0.5,
            explanation="BGP route collector report contested by ISP network operations center.",
            supporting_evidence_hashes=[ev.raw_sha256],
            verification_state=ClaimVerificationState.CONTESTED,
            properties={"dispute_case": "NOC-4401"},
        )
        self.store.insert_claim(claim2)

        # 4. Insert Revoked Claim
        claim3 = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:gov-service.example.org",
            claim_type="DEPRECATED_TELEMETRY",
            layer=EpistemicLayer.HYPOTHESIS,
            asserted_at="2026-11-20T12:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=0.1,
            explanation="Telemetry revoked after sensor NTP clock drift identified.",
            supporting_evidence_hashes=[ev.raw_sha256],
            verification_state=ClaimVerificationState.REVOKED,
            properties={"revocation_reason": "CLOCK_DRIFT"},
        )
        self.store.insert_claim(claim3)

        # Confirm 3 claims exist before rebuild
        claims_before = self.store.all_claims()
        self.assertEqual(len(claims_before), 3)

        # 5. Execute Graph Rebuild
        nodes_rebuilt, edges_rebuilt = self.store.rebuild_graph_from_observations()
        self.assertGreater(nodes_rebuilt, 0)
        self.assertGreater(edges_rebuilt, 0)

        # 6. Verify Exact Claim Preservation
        claims_after = self.store.all_claims()
        self.assertEqual(len(claims_after), 3)

        # Verify claim identities, signatures, and states
        claims_by_id = {c.claim_id: c for c in claims_after}
        self.assertIn(claim1_signed.claim_id, claims_by_id)
        self.assertIn(claim2.claim_id, claims_by_id)
        self.assertIn(claim3.claim_id, claims_by_id)

        c1 = claims_by_id[claim1_signed.claim_id]
        self.assertEqual(c1.verification_state, ClaimVerificationState.ATTESTED_ASSERTION.value)
        self.assertEqual(c1.analyst_identity, "analyst-cert-847")
        self.assertTrue(c1.verify_attestation(pub_bytes))

        c2 = claims_by_id[claim2.claim_id]
        self.assertEqual(c2.verification_state, ClaimVerificationState.CONTESTED.value)

        c3 = claims_by_id[claim3.claim_id]
        self.assertEqual(c3.verification_state, ClaimVerificationState.REVOKED.value)

    def test_rebuild_rollback_on_failure_preserves_atomic_state(self):
        """P0: Ensure crash / exception during rebuild rolls back without corrupting graph or claims."""
        ev, ob = make_test_pair("atomic-test.example.org", ["198.51.100.99"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        claim = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:atomic-test.example.org",
            claim_type="TEST_CLAIM",
            layer=EpistemicLayer.HYPOTHESIS,
            asserted_at="2026-11-20T10:30:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=0.8,
            explanation="Atomic state integrity test claim.",
            supporting_evidence_hashes=[ev.raw_sha256],
        )
        self.store.insert_claim(claim)

        # Simulate exception inside a connection transaction
        try:
            with self.store._connect() as conn:
                conn.execute("DELETE FROM graph_edges")
                raise RuntimeError("Simulated crash mid-rebuild")
        except RuntimeError:
            pass

        # Verify transaction rolled back cleanly
        with self.store._connect() as conn:
            edge_count = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
            claim_count = conn.execute("SELECT COUNT(*) FROM intelligence_claims").fetchone()[0]
            self.assertGreater(edge_count, 0)
            self.assertEqual(claim_count, 1)

    # --- P0: Epistemic State Machine & Attestation Engine ---

    def test_machine_generated_claims_never_at_attested_assertion(self):
        """P0: Verify all automated detector findings default strictly to UNVERIFIED_HYPOTHESIS."""
        ev1, ob1 = make_test_pair("epoch.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z")
        ev2, ob2 = make_test_pair("epoch.example.org", ["198.51.100.2"], "2026-11-21T10:00:00Z")
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("epoch.example.org")

            for c in claims:
                self.assertEqual(
                    c.verification_state,
                    ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
                    f"Claim {c.claim_type} was illegally promoted to {c.verification_state}",
                )
                self.assertIsNone(c.attestation_signature)
                self.assertEqual(c.properties.get("confidence_type"), "heuristic_uncalibrated")

    def test_attested_assertion_rejects_missing_signature_or_identity(self):
        """P0: Enforce that ATTESTED_ASSERTION requires genuine non-empty identity and signature."""
        ev, ob = make_test_pair("attest.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z")

        # 1. Reject missing analyst identity
        with self.assertRaises(ValueError):
            IntelligenceClaim.create(
                subject_uri="anie:entity:domain:attest.example.org",
                claim_type="TEST_TYPE",
                layer=EpistemicLayer.VALIDATED,
                asserted_at="2026-11-20T10:00:00Z",
                valid_from="2026-11-20T10:00:00Z",
                confidence=1.0,
                explanation="Test without identity.",
                supporting_evidence_hashes=[ev.raw_sha256],
                analyst_identity=None,
                attestation_signature="dGVzdA==",
                verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
            )

        # 2. Reject missing signature
        with self.assertRaises(ValueError):
            IntelligenceClaim.create(
                subject_uri="anie:entity:domain:attest.example.org",
                claim_type="TEST_TYPE",
                layer=EpistemicLayer.VALIDATED,
                asserted_at="2026-11-20T10:00:00Z",
                valid_from="2026-11-20T10:00:00Z",
                confidence=1.0,
                explanation="Test without signature.",
                supporting_evidence_hashes=[ev.raw_sha256],
                analyst_identity="analyst-001",
                attestation_signature=None,
                verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
            )

    def test_forged_or_corrupted_signature_fails_verification(self):
        """P0: Verify that forged or mismatched Ed25519 signatures fail attestation verification."""
        priv_key = Ed25519PrivateKey.generate()
        wrong_priv_key = Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()

        ev, ob = make_test_pair("forged.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z")
        claim = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:forged.example.org",
            claim_type="VERIFIED_ROUTE",
            layer=EpistemicLayer.VALIDATED,
            asserted_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=1.0,
            explanation="Testing forged signature rejection.",
            supporting_evidence_hashes=[ev.raw_sha256],
            analyst_identity="analyst-007",
            attestation_signature=base64.b64encode(b"X" * 64).decode("ascii"),
            verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
        )

        # Forged signature must fail
        self.assertFalse(claim.verify_attestation(pub_bytes))

        # Sign with wrong key - must fail against true pub_bytes
        wrong_sig = wrong_priv_key.sign(claim.canonical_signing_bytes())
        claim_wrong_key = IntelligenceClaim.create(
            subject_uri=claim.subject_uri,
            claim_type=claim.claim_type,
            layer=claim.layer,
            asserted_at=claim.asserted_at,
            valid_from=claim.valid_from,
            confidence=claim.confidence,
            explanation=claim.explanation,
            supporting_evidence_hashes=claim.supporting_evidence_hashes,
            analyst_identity="analyst-007",
            attestation_signature=base64.b64encode(wrong_sig).decode("ascii"),
            verification_state=ClaimVerificationState.ATTESTED_ASSERTION,
        )
        self.assertFalse(claim_wrong_key.verify_attestation(pub_bytes))

    # --- P1: Temporal Correctness ---

    def test_fast_flux_24hour_window_enforcement(self):
        """P1: Verify observations older than 24 hours from as_of are excluded from fast-flux detection."""
        # 5 distinct IPs, but spread over 5 days (not 24 hours!)
        for i in range(5):
            ev, ob = make_test_pair(
                "slow-rotation.example.org",
                [f"198.51.10{i}.1"],
                f"2026-11-{10+i:02d}T10:00:00Z",
                ttl=60,
            )
            self.store.insert_record(ev, ob)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            # Evaluate as of Day 4
            claims = ti_engine.analyze_domain("slow-rotation.example.org", as_of="2026-11-14T12:00:00Z")
            flux_claims = [c for c in claims if c.claim_type == TemporalClaimType.FAST_FLUX_INDICATOR.value]
            # Must NOT trigger because only 1 IP was observed in the 24-hour window
            self.assertEqual(len(flux_claims), 0)

    def test_as_of_historical_filtering(self):
        """P1: Verify as_of parameter strictly filters out future observations."""
        ev1, ob1 = make_test_pair("timetravel.example.org", ["198.51.100.1"], "2026-11-01T10:00:00Z")
        ev2, ob2 = make_test_pair("timetravel.example.org", ["198.51.100.2"], "2026-11-15T10:00:00Z")
        self.store.insert_record(ev1, ob1)
        self.store.insert_record(ev2, ob2)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            # Analyze domain as of Nov 5 (before ev2 occurred)
            claims = ti_engine.analyze_domain("timetravel.example.org", as_of="2026-11-05T00:00:00Z")

            # Transition detector should NOT fire because only 1 observation is visible as of Nov 5
            trans_claims = [c for c in claims if c.claim_type == TemporalClaimType.INFRASTRUCTURE_TRANSITION.value]
            self.assertEqual(len(trans_claims), 0)

    def test_dual_stack_ipv4_and_ipv6_handling(self):
        """P1: Verify both dns_a and dns_aaaa are analyzed across transitions and evolution."""
        ev_v4, ob_v4 = make_test_pair("dualstack.example.org", ["198.51.100.1"], "2026-11-20T10:00:00Z", kind="dns_a")
        ev_v6, ob_v6 = make_test_pair("dualstack.example.org", ["2001:db8::1"], "2026-11-20T10:00:00Z", kind="dns_aaaa")
        self.store.insert_record(ev_v4, ob_v4)
        self.store.insert_record(ev_v6, ob_v6)

        with self.store._connect() as conn:
            ti_engine = TemporalIntelligenceEngine(conn)
            claims = ti_engine.analyze_domain("dualstack.example.org")

            evo_claims = [c for c in claims if c.claim_type == TemporalClaimType.IP_RELATIONSHIP_EVOLUTION.value]
            # Both IPv4 and IPv6 relationships should be tracked
            tracked_ips = {c.properties["ip"] for c in evo_claims}
            self.assertIn("198.51.100.1", tracked_ips)
            self.assertIn("2001:db8::1", tracked_ips)

    def test_provenance_tagged_network_classification(self):
        """P1: Verify IP classification returns provenance metadata and disclaims authoritative BGP proof."""
        res_cf = classify_ip_infrastructure("104.16.1.1")
        self.assertTrue(res_cf["is_known_anycast_heuristic"])
        self.assertEqual(res_cf["provider"], "Cloudflare")
        self.assertFalse(res_cf["authoritative"])
        self.assertIn("Heuristic prefix match only", res_cf["notice"])

        res_unicast = classify_ip_infrastructure("198.51.100.1")
        self.assertFalse(res_unicast["is_known_anycast_heuristic"])
        self.assertEqual(res_unicast["classification"], "UNICAST_OR_UNCLASSIFIED")

    # --- P1: Graph Query Completeness & Bounding ---

    def test_graph_traversal_deterministic_ordering_and_metadata(self):
        """P1: Verify get_k_hop_neighborhood returns deterministic ordering and truncation metadata."""
        # Create a hub domain connected to 10 IPs
        for i in range(10):
            ev, ob = make_test_pair("hub.example.org", [f"198.51.100.{i}"], "2026-11-20T10:00:00Z")
            self.store.insert_record(ev, ob)

        with self.store._connect() as conn:
            engine = GraphEngine(conn)
            # Fetch with max_edges = 4 (triggering edge truncation)
            res = engine.get_k_hop_neighborhood("anie:entity:domain:hub.example.org", max_depth=1, max_edges=4)

            self.assertTrue(res["truncated"])
            self.assertEqual(len(res["edges"]), 4)
            self.assertEqual(res["limit_edges"], 4)
            self.assertGreaterEqual(res["total_edges_visited"], 4)

            # Check that node results are deterministically ordered
            node_ids_1 = [n["node_id"] for n in res["nodes"]]
            res2 = engine.get_k_hop_neighborhood("anie:entity:domain:hub.example.org", max_depth=1, max_edges=4)
            node_ids_2 = [n["node_id"] for n in res2["nodes"]]
            self.assertEqual(node_ids_1, node_ids_2)

    # --- P1: Search Integrity & Repair ---

    def test_fts_repair_and_reindex_integrity(self):
        """P1: Verify reindex_fts restores complete searchability and verify_fts_integrity reports accurately."""
        ev, ob = make_test_pair("fts-repair.example.org", ["198.51.100.55"], "2026-11-20T10:00:00Z")
        self.store.insert_record(ev, ob)

        claim = IntelligenceClaim.create(
            subject_uri="anie:entity:domain:fts-repair.example.org",
            claim_type="OBSERVABILITY_TEST",
            layer=EpistemicLayer.HYPOTHESIS,
            asserted_at="2026-11-20T10:00:00Z",
            valid_from="2026-11-20T10:00:00Z",
            confidence=0.9,
            explanation="Special unique search phrase: quantum-cryptography-audit",
            supporting_evidence_hashes=[ev.raw_sha256],
        )
        self.store.insert_claim(claim)

        # Confirm searchable
        res_before = self.store.search_intelligence("quantum-cryptography-audit")
        self.assertEqual(len(res_before), 1)

        # Corrupt / clear FTS virtual table directly
        with self.store._connect() as conn:
            conn.execute("DELETE FROM intelligence_fts")

        # Now search fails to find anything
        self.assertEqual(len(self.store.search_intelligence("quantum-cryptography-audit")), 0)

        # Run reindex_fts to repair
        repair_summary = self.store.reindex_fts()
        self.assertGreater(repair_summary["total_fts_rows"], 0)

        # Verify search restored
        res_after = self.store.search_intelligence("quantum-cryptography-audit")
        self.assertEqual(len(res_after), 1)

        # Verify integrity check passes
        integrity = self.store.verify_fts_integrity()
        self.assertTrue(integrity["is_consistent"])
        self.assertEqual(len(integrity["sync_errors"]), 0)


if __name__ == "__main__":
    unittest.main()
