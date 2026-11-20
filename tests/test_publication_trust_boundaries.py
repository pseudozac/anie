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
    AegisReleaseConsumer,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    TRACKER_SCHEMA_V1,
    TRACKER_SCHEMA_V2,
    _iter_bounded_gzip_records,
    generate_keypair,
    inspect_candidate,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.preflight_hardening import check_no_signing_keys, run_security_preflight
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

    # Stage 9: Hash Chain Continuity
    def test_stage9_hash_chain_continuity_succeeds(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
        )
        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            require_hash_chain=True,
        )
        state_file = self.tmp_p / "tracker_chain.json"
        tracker = ReleaseSequenceTracker(state_file, auto_init=True)

        res1 = verify_real_release(
            self.pub_dir,
            trust=trust,
            sequence_tracker=tracker,
            now="2026-11-12T12:00:00Z",
        )
        self.assertTrue(res1["authenticated"])
        self.assertTrue(res1["hash_chain_verified"])
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 1)
        self.assertEqual(tracker.get_last_accepted_digest("anie-first-party"), res1["manifest_sha256"])

        # Create release 2 pointing to release 1's manifest digest
        pub_dir_2 = self.tmp_p / "pub2"
        publish_real(
            self.data,
            pub_dir_2,
            "2026-11-12T12:00:00Z",
            release_sequence=2,
            prev_manifest_sha256=res1["manifest_sha256"],
            published_at="2026-11-12T12:10:00Z",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        sign_manifest_detached(
            pub_dir_2,
            priv_key,
            key_id="op-test-1",
            release_sequence=2,
            issued_at="2026-11-12T12:15:00Z",
            expires_at="2026-11-20T06:00:00Z",
            prev_manifest_sha256=res1["manifest_sha256"],
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )

        res2 = verify_real_release(
            pub_dir_2,
            trust=trust,
            sequence_tracker=tracker,
            now="2026-11-12T12:20:00Z",
        )
        self.assertTrue(res2["authenticated"])
        self.assertTrue(res2["anti_rollback_verified"])
        self.assertTrue(res2["hash_chain_verified"])
        self.assertEqual(res2["prev_manifest_sha256"], res1["manifest_sha256"])
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 2)
        self.assertEqual(tracker.get_last_accepted_digest("anie-first-party"), res2["manifest_sha256"])

    # Stage 10: Broken Hash Chain Fails Closed
    def test_stage10_broken_hash_chain_fails_closed(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
        )
        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
        )
        state_file = self.tmp_p / "tracker_broken_chain.json"
        tracker = ReleaseSequenceTracker(state_file, auto_init=True)
        res1 = verify_real_release(self.pub_dir, trust=trust, sequence_tracker=tracker, now="2026-11-12T12:00:00Z")

        # Create release 2 with a forged / tampered prev_manifest_sha256
        forged_digest = "e" * 64
        pub_dir_broken = self.tmp_p / "pub_broken"
        publish_real(
            self.data,
            pub_dir_broken,
            "2026-11-12T12:00:00Z",
            release_sequence=2,
            prev_manifest_sha256=forged_digest,
            published_at="2026-11-12T12:10:00Z",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        sign_manifest_detached(
            pub_dir_broken,
            priv_key,
            key_id="op-test-1",
            release_sequence=2,
            issued_at="2026-11-12T12:15:00Z",
            expires_at="2026-11-20T06:00:00Z",
            prev_manifest_sha256=forged_digest,
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )

        with self.assertRaises(ValueError) as ctx:
            verify_real_release(
                pub_dir_broken,
                trust=trust,
                sequence_tracker=tracker,
                now="2026-11-12T12:20:00Z",
            )
        self.assertIn("hash chain broken", str(ctx.exception).lower())
        # Confirm tracker sequence did NOT advance
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 1)
        self.assertEqual(tracker.get_last_accepted_digest("anie-first-party"), res1["manifest_sha256"])

        # Test require_hash_chain policy violation when release 2 omits prev_manifest_sha256
        pub_dir_no_chain = self.tmp_p / "pub_no_chain"
        publish_real(
            self.data,
            pub_dir_no_chain,
            "2026-11-12T12:00:00Z",
            release_sequence=2,
            prev_manifest_sha256=None,
            published_at="2026-11-12T12:10:00Z",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        sign_manifest_detached(
            pub_dir_no_chain,
            priv_key,
            key_id="op-test-1",
            release_sequence=2,
            issued_at="2026-11-12T12:15:00Z",
            expires_at="2026-11-20T06:00:00Z",
            source_commit="a64ddad12c2603ed0ef968542b26d1a14af836e2",
        )
        trust_strict = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
            require_hash_chain=True,
        )
        with self.assertRaises(ValueError) as ctx:
            verify_real_release(
                pub_dir_no_chain,
                trust=trust_strict,
                sequence_tracker=tracker,
                now="2026-11-12T12:20:00Z",
            )
        self.assertIn("hash chain required", str(ctx.exception).lower())

    # Stage 11: CLI Keygen and Strict Permissions
    def test_stage11_cli_keygen_and_permissions(self):
        keys_dir = self.tmp_p / "keys"
        res = generate_keypair(keys_dir, "prod-operator-2026")

        self.assertEqual(res["key_id"], "prod-operator-2026")
        priv_p = Path(res["private_key_path"])
        pub_p = Path(res["public_key_path"])
        meta_p = Path(res["metadata_path"])

        self.assertTrue(priv_p.is_file())
        self.assertTrue(pub_p.is_file())
        self.assertTrue(meta_p.is_file())

        # Check POSIX 0600 file permissions on private key
        import os
        if os.name != "nt":
            mode = priv_p.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, f"private key file permissions must be 0600: got {oct(mode)}")

        # Check metadata
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        self.assertEqual(meta["schema"], "anie.operator-key-metadata.v1")
        self.assertEqual(meta["key_id"], "prod-operator-2026")
        self.assertEqual(meta["algorithm"], "Ed25519")
        self.assertEqual(meta["key_fingerprint"], res["key_fingerprint"])

        # Fail without force if files exist
        with self.assertRaises(FileExistsError):
            generate_keypair(keys_dir, "prod-operator-2026", force=False)

        # Force overwrite succeeds
        res_forced = generate_keypair(keys_dir, "prod-operator-2026", force=True)
        self.assertEqual(res_forced["key_id"], "prod-operator-2026")

    # Stage 12: Candidate Pre-Signing Inspection
    def test_stage12_inspect_candidate_summary(self):
        summary = inspect_candidate(self.pub_dir)
        self.assertEqual(summary["status"], "CANDIDATE_INTEGRITY_VERIFIED")
        self.assertEqual(summary["release_sequence"], 1)
        self.assertEqual(summary["total_observations"], 1)
        self.assertEqual(summary["total_events"], 1)
        self.assertEqual(summary["domains"], ["example.com"])
        self.assertEqual(summary["query_kinds"], ["dns_a"])
        self.assertIn("observation_window", summary)
        self.assertEqual(summary["observation_window"]["first_seen"], "2026-11-12T10:00:00Z")

    # Stage 13: AEGIS Consumer Transactional Ingestion
    def test_stage13_aegis_consumer_transactional_acceptance(self):
        priv_key, pub_raw = _gen_keypair()
        sign_manifest_detached(
            self.pub_dir,
            priv_key,
            key_id="op-test-1",
            release_sequence=1,
            issued_at="2026-11-12T10:05:00Z",
            expires_at="2026-11-20T06:00:00Z",
        )
        trust = RealReleaseTrust.from_single_key(
            key_id="op-test-1",
            public_key_raw=pub_raw,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-01T00:00:00Z",
        )
        tracker_file = self.tmp_p / "aegis_tracker.json"
        tracker = ReleaseSequenceTracker(tracker_file, auto_init=True)
        consumer = AegisReleaseConsumer(trust=trust, sequence_tracker=tracker)

        res, observations, events = consumer.verify_and_load(self.pub_dir, now="2026-11-12T12:00:00Z")
        self.assertTrue(res["authenticated"])
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(events), 1)
        self.assertIsInstance(observations[0], RealObservation)
        self.assertIsInstance(events[0], RealCollectionEvent)
        self.assertEqual(observations[0].subject, "example.com")
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 1)

        # Attempt to load tampered candidate via consumer fails closed without updating sequence
        tampered_dir = self.tmp_p / "consumer_tampered"
        import shutil
        shutil.copytree(self.pub_dir, tampered_dir)
        (tampered_dir / ATTESTATION_NAME).write_text("{}", encoding="utf-8")

        with self.assertRaises(ValueError):
            consumer.verify_and_load(tampered_dir, now="2026-11-12T12:00:00Z")
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 1)

    # Stage 14: Collector Private Key Isolation
    def test_stage14_collector_private_key_isolation(self):
        collector_dir = self.tmp_p / "collector_storage"
        collector_dir.mkdir(parents=True, exist_ok=True)

        # Clean directory passes preflight key isolation check
        ok, msg = check_no_signing_keys([collector_dir])
        self.assertTrue(ok)
        self.assertIn("No private signing keys detected", msg)

        # Plant private key file: must fail closed
        key_file = collector_dir / "rogue.priv"
        key_file.write_text("bogus-private-key", encoding="utf-8")
        ok, msg = check_no_signing_keys([collector_dir])
        self.assertFalse(ok)
        self.assertIn("Private signing key file detected", msg)
        key_file.unlink()

        # Plant file containing private key header: must fail closed
        pem_file = collector_dir / "stray.pem"
        pem_file.write_text("-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg...\n-----END PRIVATE KEY-----", encoding="utf-8")
        ok, msg = check_no_signing_keys([collector_dir])
        self.assertFalse(ok)
        self.assertIn("Private key PEM header detected", msg)

        # Run security preflight report: must fail closed
        report = run_security_preflight(signing_key_paths=[collector_dir])
        self.assertFalse(report.passed)
        self.assertFalse(report.signing_keys_absent)
        self.assertIn("SECURITY FAILURE", report.failure_reason)

    # Stage 15: Sequence Tracker V1 to V2 Migration
    def test_stage15_tracker_v1_to_v2_migration(self):
        v1_path = self.tmp_p / "tracker_v1.json"
        v1_data = {
            "schema": TRACKER_SCHEMA_V1,
            "initialized_at": "2026-11-12T00:00:00Z",
            "updated_at": "2026-11-12T00:00:00Z",
            "sequences": {
                "anie-first-party": 4,
            },
        }
        v1_path.write_text(json.dumps(v1_data), encoding="utf-8")

        tracker = ReleaseSequenceTracker(v1_path)
        # Verify seamless reading of v1 state
        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 4)
        self.assertIsNone(tracker.get_last_accepted_digest("anie-first-party"))

        # Update advances to v2 schema seamlessly
        new_digest = "b" * 64
        tracker.update_accepted("anie-first-party", 5, manifest_sha256=new_digest)

        self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 5)
        self.assertEqual(tracker.get_last_accepted_digest("anie-first-party"), new_digest)

        # Verify persisted state file has TRACKER_SCHEMA_V2
        saved = json.loads(v1_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["schema"], TRACKER_SCHEMA_V2)
        self.assertEqual(saved["sequences"]["anie-first-party"], 5)
        self.assertEqual(saved["publishers"]["anie-first-party"]["last_sequence"], 5)
        self.assertEqual(saved["publishers"]["anie-first-party"]["last_manifest_sha256"], new_digest)

    # Stage 16: Decompression Bomb & Streaming Bounds Protection
    def test_stage16_decompression_bomb_protection(self):
        import io
        # 1. Line exceeds max_record_bytes
        long_line = b"A" * 600000 + b"\n"
        stream = io.BytesIO(long_line)
        with self.assertRaises(ValueError) as ctx:
            list(_iter_bounded_gzip_records(stream, max_record_bytes=500000))
        self.assertIn("exceeds byte limit", str(ctx.exception).lower())

        # 2. Total decompressed bytes exceed ceiling
        chunks = b"A" * 500 + b"\n"
        stream = io.BytesIO(chunks * 10)
        with self.assertRaises(ValueError) as ctx:
            list(_iter_bounded_gzip_records(stream, max_total_bytes=2000))
        self.assertIn("exceeded decompression limit", str(ctx.exception).lower())

        # 3. Record count exceeds ceiling
        stream = io.BytesIO(b"line\n" * 10)
        with self.assertRaises(ValueError) as ctx:
            list(_iter_bounded_gzip_records(stream, max_records=5))
        self.assertIn("exceeded maximum record limit", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
