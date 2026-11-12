"""Explicit 8-stage trust boundary verification test suite for ANIE Phase 2.1 Task 7.

Validates the full trust matrix:
1. Valid Unsigned Candidate Release (integrity_only=True)
2. Tampered Observation Payload (integrity check fails)
3. Tampered Raw Evidence Bytes (raw_sha256 mismatch fails)
4. Missing Evidence Reference (referential integrity fails)
5. Invalid Detached Attestation Signature (cryptographic failure)
6. Wrong Public Key (signature verification failure)
7. Replayed or Downgraded Release Sequence (anti-rollback failure)
8. Valid Authenticated Release with Detached Ed25519 Attestation
"""
from __future__ import annotations

import gzip
import json
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    ATTESTATION_NAME,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.real_store import RealObservationStore


def _gen_keypair():
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_raw


def make_test_pair(subject: str = "example.com", kind: str = "dns_a", observed_at: str = "2026-11-12T10:00:00Z"):
    req = RealCollectionRequest.create(
        kind=kind,
        subject=subject,
        observed_at=observed_at,
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="104.16.248.249",
    )
    payload = b"\x00\x00\x81\x80test_dns_wire_bytes"
    payload_sha = sha256(payload).hexdigest()
    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="recursive",
        transport_security="tls_pinned",
        resolver_identity="cloudflare_doh",
        wire_rcode="NOERROR",
        raw_evidence_status="captured",
    )
    ev = RealCollectionEvent(
        request=req,
        response_code="ANSWER",
        raw_sha256=payload_sha,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id="first_party:doh:cloudflare",
        observed_at=observed_at,
        raw_payload=payload,
    )
    obs = RealObservation(
        subject=subject,
        kind=kind,
        observed_at=observed_at,
        values=("93.184.216.34",),
        status="ok",
        source_id="first_party:doh:cloudflare",
        method="dns",
        synthetic=False,
        evidence_id=ev.event_id,
        factual_verification=factual,
        ttl_seconds=300,
    )
    return ev, obs


class TestPublicationTrustBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_p = Path(self.tmp.name)
        ev, obs = make_test_pair()
        self.data = ([obs], [ev])
        self.pub_dir = self.tmp_p / "publication"
        self.manifest = publish_real(
            self.data,
            self.pub_dir,
            as_of="2026-11-12T10:00:00Z",
            release_sequence=1,
            publisher_identity="anie-first-party",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
            published_at="2026-11-12T10:01:00Z",
        )

    def tearDown(self):
        self.tmp.cleanup()

    # Stage 1: Valid Unsigned Candidate
    def test_stage1_valid_unsigned_candidate(self):
        res = verify_real_release(self.pub_dir, integrity_only=True)
        self.assertEqual(res["status"], "CANDIDATE_INTEGRITY_VERIFIED")
        self.assertFalse(res["authenticated"])
        self.assertTrue(res["integrity_only"])
        self.assertTrue(res["structural_valid"])
        self.assertTrue(res["evidence_integrity_valid"])
        self.assertFalse(res["safe_to_autonomously_act"])

    # Stage 2: Tampered Observation Payload
    def test_stage2_tampered_observation_payload(self):
        obs_file = self.pub_dir / "real_observations.jsonl.gz"
        with gzip.open(obs_file, "rt") as f:
            lines = f.readlines()
        data = json.loads(lines[0])
        data["values"] = ["999.999.999.999"]
        with gzip.open(obs_file, "wt") as f:
            f.write(json.dumps(data) + "\n")

        with self.assertRaises(Exception):
            verify_real_release(self.pub_dir, integrity_only=True)

    # Stage 3: Tampered Raw Evidence Bytes
    def test_stage3_tampered_raw_evidence_bytes(self):
        ev_file = self.pub_dir / "real_events.jsonl.gz"
        with gzip.open(ev_file, "rt") as f:
            lines = f.readlines()
        data = json.loads(lines[0])
        data["raw_payload_b64"] = "QUJD"
        with gzip.open(ev_file, "wt") as f:
            f.write(json.dumps(data) + "\n")

        with self.assertRaises(Exception):
            verify_real_release(self.pub_dir, integrity_only=True)

    # Stage 4: Missing Evidence Reference
    def test_stage4_missing_evidence_reference(self):
        ev_file = self.pub_dir / "real_events.jsonl.gz"
        with gzip.open(ev_file, "wt") as f:
            f.write("")

        with self.assertRaises(Exception):
            verify_real_release(self.pub_dir, integrity_only=True)

    # Stage 5: Invalid Detached Attestation Signature
    def test_stage5_invalid_detached_attestation(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
            publisher_identity="anie-first-party",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        att_file = self.pub_dir / ATTESTATION_NAME
        att = json.loads(att_file.read_text(encoding="utf-8"))
        # Corrupt signature bytes
        sig = att["signature_base64"]
        corrupted = ("AAAA" if sig[:4] != "AAAA" else "BBBB") + sig[4:]
        att["signature_base64"] = corrupted
        att_file.write_text(json.dumps(att), encoding="utf-8")

        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            expected_source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        with self.assertRaises(ValueError) as ctx:
            verify_real_release(self.pub_dir, trust=trust, now="2026-11-12T12:00:00Z")
        self.assertIn("signature verification failed", str(ctx.exception))

    # Stage 6: Wrong Public Key
    def test_stage6_wrong_public_key(self):
        priv_a, pub_a = _gen_keypair()
        priv_b, pub_b = _gen_keypair()

        sign_manifest_detached(
            self.pub_dir,
            priv_a,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
            publisher_identity="anie-first-party",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        trust_b = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_b,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            expected_source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        with self.assertRaises(ValueError) as ctx:
            verify_real_release(self.pub_dir, trust=trust_b, now="2026-11-12T12:00:00Z")
        self.assertIn("key fingerprint mismatch", str(ctx.exception))

    # Stage 7: Replayed or Older Release Sequence (Anti-Rollback)
    def test_stage7_replayed_release_sequence(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
            publisher_identity="anie-first-party",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            expected_source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        state_file = self.tmp_p / "sequence_state.json"
        tracker = ReleaseSequenceTracker(state_file, auto_init=True)

        res1 = verify_real_release(
            self.pub_dir,
            trust=trust,
            sequence_tracker=tracker,
            now="2026-11-12T12:00:00Z",
        )
        self.assertTrue(res1["authenticated"])
        self.assertTrue(res1["anti_rollback_verified"])

        # Replay attempt with same sequence 1 must fail closed
        with self.assertRaises(ValueError) as ctx:
            verify_real_release(
                self.pub_dir,
                trust=trust,
                sequence_tracker=tracker,
                now="2026-11-12T12:00:00Z",
            )
        self.assertIn("rollback", str(ctx.exception).lower())

    # Stage 8: Valid Authenticated Release
    def test_stage8_valid_authenticated_release(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
            publisher_identity="anie-first-party",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            expected_publisher="anie-first-party",
            expected_source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        res = verify_real_release(
            self.pub_dir,
            trust=trust,
            now="2026-11-12T12:00:00Z",
        )
        self.assertEqual(res["status"], "AUTHENTICATED")
        self.assertTrue(res["authenticated"])
        self.assertTrue(res["publisher_authenticated"])
        self.assertFalse(res["safe_to_autonomously_act"])


if __name__ == "__main__":
    unittest.main()
