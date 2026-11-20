"""Tests for Phase 3.5 V4 Release Bundles with Claims Partition."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.graph_models import ClaimVerificationState, IntelligenceClaim
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    REAL_MANIFEST_SCHEMA_V3,
    REAL_MANIFEST_SCHEMA_V4,
    AegisReleaseBundle,
    AegisReleaseConsumer,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.real_store import RealObservationStore


def _generate_test_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub_raw, "test-op-key-1"


def _sample_records():
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject="sample.org",
        observed_at="2026-11-20T10:00:00Z",
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
    raw_payload = b'{"domain": "sample.org", "answers": ["93.184.216.34"]}'
    import hashlib
    raw_hash = hashlib.sha256(raw_payload).hexdigest()

    factual = FactualVerification(
        dnssec_status="indeterminate",
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
        observed_at="2026-11-20T10:00:00Z",
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject="sample.org",
        kind="dns_a",
        observed_at="2026-11-20T10:00:00Z",
        values=("93.184.216.34",),
        status="ok",
        source_id="first_party:doh:cloudflare",
        method="dns",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    claim = IntelligenceClaim(
        subject_uri="anie:entity:domain:sample.org",
        claim_type="INFRASTRUCTURE_TRANSITION",
        layer="HYPOTHESIS",
        asserted_at="2026-11-20T10:00:00Z",
        valid_from="2026-11-20T10:00:00Z",
        valid_until=None,
        confidence=0.85,
        ruleset_version="anie.temporal-intelligence.v1",
        explanation="Sample claim for release v4 testing",
        supporting_evidence_hashes=(event.raw_sha256,),
        supporting_node_ids=("anie:entity:domain:sample.org",),
        verification_state=ClaimVerificationState.UNVERIFIED_HYPOTHESIS.value,
    )
    return obs, event, claim


class TestV4ClaimsRelease(unittest.TestCase):
    def setUp(self):
        self.priv_key, self.pub_raw, self.key_id = _generate_test_key()
        self.trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            allow_rollback=False,
        )

    def test_export_and_verify_v4_manifest(self):
        obs, evt, claim = _sample_records()

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release_v4"
            manifest = publish_real(
                ([obs], [evt], [], [claim]),
                out_dir,
                as_of="2026-11-20T12:00:00Z",
                release_sequence=1,
                published_at="2026-11-20T12:01:00Z",
                source_commit="abcdef0123456789abcdef0123456789abcdef01",
            )

            self.assertEqual(manifest["schema"], REAL_MANIFEST_SCHEMA_V4)
            self.assertEqual(manifest["total_observations"], 1)
            self.assertEqual(manifest["total_events"], 1)
            self.assertEqual(manifest["total_claims"], 1)

            file_names = {f["file"] for f in manifest["files"]}
            self.assertIn("real_observations.jsonl.gz", file_names)
            self.assertIn("real_events.jsonl.gz", file_names)
            self.assertIn("real_claims.jsonl.gz", file_names)

            # Verification of unsigned candidate release
            res = verify_real_release(out_dir, integrity_only=True)
            self.assertTrue(res["structural_valid"])
            self.assertTrue(res["evidence_integrity_valid"])
            self.assertEqual(res["total_claims"], 1)

    def test_consumer_ingestion_v4(self):
        obs, evt, claim = _sample_records()

        with TemporaryDirectory() as tmp:
            pub_dir = Path(tmp) / "pub"
            consumer_db = Path(tmp) / "consumer.db"
            tracker_db = Path(tmp) / "tracker.db"

            manifest = publish_real(
                ([obs], [evt], [], [claim]),
                pub_dir,
                as_of="2026-11-20T12:00:00Z",
                release_sequence=1,
                published_at="2026-11-20T12:01:00Z",
            )

            # Sign manifest with operator key
            sign_manifest_detached(
                pub_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-20T12:01:00Z",
                expires_at="2026-12-20T12:01:00Z",
            )

            c_store = RealObservationStore(consumer_db)
            tracker = ReleaseSequenceTracker(tracker_db)
            consumer = AegisReleaseConsumer(
                trust=self.trust,
                sequence_tracker=tracker,
                store=c_store,
                allow_uninitialized_state=True,
            )

            bundle = consumer.verify_and_load_bundle(pub_dir)
            self.assertIsInstance(bundle, AegisReleaseBundle)
            self.assertEqual(len(bundle.observations), 1)
            self.assertEqual(len(bundle.events), 1)
            self.assertEqual(len(bundle.claims), 1)

            # Verify consumer store has claim persisted
            saved_claims = c_store.claims_for_subject("anie:entity:domain:sample.org")
            self.assertEqual(len(saved_claims), 1)
            self.assertEqual(saved_claims[0].claim_type, "INFRASTRUCTURE_TRANSITION")

    def test_backward_compatibility_v2_release(self):
        obs, evt, _ = _sample_records()

        with TemporaryDirectory() as tmp:
            pub_dir = Path(tmp) / "pub_v2"
            consumer_db = Path(tmp) / "consumer.db"
            tracker_db = Path(tmp) / "tracker.db"

            # Publish without claims (triggers schema v2)
            manifest = publish_real(
                ([obs], [evt]),
                pub_dir,
                as_of="2026-11-20T12:00:00Z",
                release_sequence=1,
                published_at="2026-11-20T12:01:00Z",
            )
            self.assertNotEqual(manifest["schema"], REAL_MANIFEST_SCHEMA_V4)

            sign_manifest_detached(
                pub_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-20T12:01:00Z",
                expires_at="2026-12-20T12:01:00Z",
            )

            c_store = RealObservationStore(consumer_db)
            tracker = ReleaseSequenceTracker(tracker_db)
            consumer = AegisReleaseConsumer(
                trust=self.trust,
                sequence_tracker=tracker,
                store=c_store,
                allow_uninitialized_state=True,
            )
            bundle = consumer.verify_and_load_bundle(pub_dir)
            self.assertIsInstance(bundle, AegisReleaseBundle)
            self.assertEqual(len(bundle.observations), 1)
            self.assertEqual(len(bundle.events), 1)
            self.assertEqual(len(bundle.claims), 0)


if __name__ == "__main__":
    unittest.main()
