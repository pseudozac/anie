"""Unit and integration tests for Milestone M3.9: AEGIS Consumer Contract V2 and Backward Compatibility."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.canonical_entities import canonical_domain_uri
from anie.consumer_contract import (
    CONSUMER_CONTRACT_VERSION_V1,
    CONSUMER_CONTRACT_VERSION_V2,
    CROSS_VECTOR_FINDING_SCHEMA,
    FINDINGS_FEED_SCHEMA_V2,
    IOC_FEED_SCHEMA,
    AnieIntelligenceClient,
)
from anie.cross_vector_correlation import (
    AbstentionState,
    CrossVectorFinding,
    FindingState,
    FindingType,
    TemporalCorrelationNarrative,
    VectorObservationSummary,
)
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore


def _seed_sample_data(store: RealObservationStore) -> tuple[str, str, str]:
    now_iso = "2026-11-21T10:00:00Z"
    domain = "contract-v2-test.com"
    ip = "104.16.100.1"

    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=now_iso,
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    raw_payload = b"raw_wire_contract_test"
    raw_hash = hashlib.sha256(raw_payload).hexdigest()

    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity="cloudflare",
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
    )
    event = RealCollectionEvent(
        request=req,
        response_code="ANSWER",
        raw_sha256=raw_hash,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id="first_party:doh:cloudflare",
        observed_at=now_iso,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=now_iso,
        values=(ip,),
        status="ok",
        source_id="first_party:doh:cloudflare",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
    )
    store.insert_record(event, obs)

    # Insert cross-vector finding
    subject_uri = canonical_domain_uri(domain)
    finding = CrossVectorFinding(
        subject_uri=subject_uri,
        finding_type=FindingType.CDN_PROVIDER_MIGRATION.value,
        epistemic_layer="HYPOTHESIS",
        asserted_at=now_iso,
        valid_from=now_iso,
        valid_until=None,
        state=FindingState.ACTIVE.value,
        temporal_correlation_vs_causation=TemporalCorrelationNarrative(
            coincident_change_detected=True,
            causation_inferred=False,
            analysis="Test correlation analysis without causal assumption.",
        ),
        abstention_state=AbstentionState(
            abstained=False,
            reason=None,
            participating_vectors=["dns", "tls"],
        ),
        vectors={
            "dns": VectorObservationSummary(
                vector="dns",
                observed_at=now_iso,
                evidence_id=event.event_id,
                evidence_hash=raw_hash,
                values=[ip],
            )
        },
        competing_hypotheses=[],
    )
    store.insert_cross_vector_finding(finding)

    return domain, finding.finding_id, raw_hash


class TestM39ConsumerContractV2(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_client_v2.db"
        self.store = RealObservationStore(self.db_path)
        self.domain, self.finding_id, self.raw_hash = _seed_sample_data(self.store)
        self.client = AnieIntelligenceClient(self.store)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_query_cross_vector_findings(self):
        """Verify querying cross-vector findings with V2 contract schema and pagination."""
        res = self.client.query_cross_vector_findings(limit=10)
        self.assertEqual(res.contract_version, CONSUMER_CONTRACT_VERSION_V2)
        self.assertEqual(len(res.items), 1)

        f = res.items[0]
        self.assertEqual(f["finding_id"], self.finding_id)
        self.assertEqual(f["schema"], CROSS_VECTOR_FINDING_SCHEMA)
        self.assertEqual(f["finding_type"], FindingType.CDN_PROVIDER_MIGRATION.value)
        self.assertFalse(f["temporal_correlation_vs_causation"]["causation_inferred"])

    def test_get_cross_vector_finding_by_id(self):
        """Verify direct lookup of finding by identifier."""
        finding = self.client.get_cross_vector_finding(self.finding_id)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["finding_id"], self.finding_id)
        self.assertEqual(finding["subject_uri"], canonical_domain_uri(self.domain))

        # Non-existent finding returns None
        self.assertIsNone(self.client.get_cross_vector_finding("fnd_nonexistent_12345"))

    def test_export_normalized_findings_feed(self):
        """Verify export of standardized findings feed."""
        feed = self.client.export_normalized_findings_feed(limit=5)
        self.assertEqual(feed.schema, FINDINGS_FEED_SCHEMA_V2)
        self.assertEqual(feed.contract_version, CONSUMER_CONTRACT_VERSION_V2)
        self.assertEqual(feed.total_findings, 1)
        self.assertEqual(len(feed.findings), 1)
        self.assertIn("First-party empirical cross-vector intelligence", feed.notice)

    def test_authoritative_evidence_verification_client(self):
        """Verify evidence authoritativeness through client API."""
        # Genuine hash
        res_real = self.client.verify_evidence_authoritativeness(self.raw_hash)
        self.assertTrue(res_real["is_authoritative"])
        self.assertEqual(res_real["status"], "AUTHORITATIVE_VERIFIED")

        # Fake hash
        fake_hash = hashlib.sha256(b"fake_client_hash").hexdigest()
        res_fake = self.client.verify_evidence_authoritativeness(fake_hash)
        self.assertFalse(res_fake["is_authoritative"])
        self.assertEqual(res_fake["status"], "UNVERIFIED_EVIDENCE_REFERENCE")

    def test_backward_compatibility_v1_methods(self):
        """Verify that all existing V1 consumer methods continue to function seamlessly."""
        # 1. query_entities
        entities_res = self.client.query_entities(limit=5)
        self.assertEqual(entities_res.contract_version, CONSUMER_CONTRACT_VERSION_V1)
        self.assertGreaterEqual(len(entities_res.items), 1)

        # 2. query_relationships
        rel_res = self.client.query_relationships(limit=5)
        self.assertEqual(rel_res.contract_version, CONSUMER_CONTRACT_VERSION_V1)

        # 3. get_entity_provenance
        subj_uri = canonical_domain_uri(self.domain)
        bundle = self.client.get_entity_provenance(subj_uri)
        self.assertEqual(bundle.schema, "anie.entity-provenance-bundle.v1")
        self.assertGreaterEqual(len(bundle.supporting_observations), 1)
        self.assertGreaterEqual(len(bundle.forensic_events), 1)

        # 4. export_canonical_ioc_feed
        ioc_feed = self.client.export_canonical_ioc_feed(limit=5)
        self.assertEqual(ioc_feed.feed_schema, IOC_FEED_SCHEMA)


if __name__ == "__main__":
    unittest.main()
