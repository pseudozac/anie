"""Adversarial and integrity tests for Phase 2 PR 4: Authenticated First-Party Publication.

Verifies:
- Deterministic canonical serialization and byte-for-byte reproducibility.
- Manifest determinism with fixed publication timestamp.
- Air-gapped detached Ed25519 signing and verification.
- Complete metadata binding enforcement across manifest, payload, attestation, and trust policy.
- Separate integrity vs authentication result contracts.
- Manifest and archive tampering detection.
- Raw DNS evidence hash verification.
- Referential integrity between observations and events.
- Strict model reconstruction validation (ordering, duplicate IDs, content-addressed IDs).
- Anti-contamination guards against synthetic records.
- Decompression bomb and size limit defenses.
- Fail-closed persistent sequence tracking and anti-rollback protection.
- Concurrency-safe atomic state tracker sequence advancement.
- Key rotation and key revocation compatibility.
- Genuine offline detached signing CLI workflow.
- Strict key file loading without truncation fallbacks.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from anie.cli import main as cli_main
from anie.demo import demo_observations
from anie.observations import canonical_json
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    ATTESTATION_NAME,
    DATASET_TYPE_REAL,
    MAX_PARTITION_DECOMPRESSED_BYTES,
    REAL_MANIFEST_SCHEMA,
    RealReleaseTrust,
    ReleaseSequenceTracker,
    TrackerStateError,
    TrackerStateLostError,
    TrustedKey,
    export_canonical_dataset,
    key_fingerprint,
    load_private_key_file,
    load_public_key_file,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.real_store import RealObservationStore
from test_real_models import sample_event, sample_observation, sample_request

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
if os.environ.get("GITHUB_ACTIONS") == "true" and not HAVE_CRYPTO:
    raise RuntimeError("cryptography is required in GitHub CI and must not be skipped")


def make_test_pair(subject: str = "example.com", kind: str = "dns_a", observed_at: str = "2026-11-12T10:00:00Z"):
    req = sample_request(subject=subject, kind=kind, observed_at=observed_at)
    payload = b"\x00\x00\x81\x80test_dns_wire_bytes"
    ev = sample_event(request=req, raw_payload=payload, observed_at=observed_at)
    val = ("93.184.216.34",) if kind == "dns_a" else ("2606:2800:220:1:248:1893:25c8:1946",)
    obs = sample_observation(subject=subject, kind=kind, observed_at=observed_at, values=val, event=ev)
    return ev, obs


class TestDeterministicPublication(unittest.TestCase):
    def test_byte_for_byte_reproducibility(self):
        """Two independent publications of identical data produce identical archives and manifest hashes."""
        ev1, obs1 = make_test_pair("example.com", "dns_a", "2026-11-12T08:00:00Z")
        ev2, obs2 = make_test_pair("iana.org", "dns_aaaa", "2026-11-12T08:05:00Z")
        data = ([obs1, obs2], [ev1, ev2])

        with TemporaryDirectory() as tmp:
            dir_a = Path(tmp) / "pub_a"
            dir_b = Path(tmp) / "pub_b"

            # Use fixed published_at to achieve 100% manifest determinism
            man_a = publish_real(data, dir_a, as_of="2026-11-12T10:00:00Z", release_sequence=1, published_at="2026-11-12T10:01:00Z")
            man_b = publish_real(data, dir_b, as_of="2026-11-12T10:00:00Z", release_sequence=1, published_at="2026-11-12T10:01:00Z")

            # Assert identical partition SHA-256 hashes
            for fa, fb in zip(man_a["files"], man_b["files"]):
                self.assertEqual(fa["sha256"], fb["sha256"])
                self.assertEqual(fa["bytes"], fb["bytes"])
                self.assertEqual(fa["records"], fb["records"])

                file_bytes_a = (dir_a / fa["file"]).read_bytes()
                file_bytes_b = (dir_b / fb["file"]).read_bytes()
                self.assertEqual(file_bytes_a, file_bytes_b)

            # Assert identical manifest contents and SHA-256
            manifest_a_bytes = (dir_a / "manifest.json").read_bytes()
            manifest_b_bytes = (dir_b / "manifest.json").read_bytes()
            self.assertEqual(manifest_a_bytes, manifest_b_bytes)
            self.assertEqual(sha256(manifest_a_bytes).hexdigest(), sha256(manifest_b_bytes).hexdigest())

    def test_export_canonical_dataset_ordering_and_referential_integrity(self):
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "real.sqlite"
            store = RealObservationStore(store_db)

            # Insert out of order
            ev2, obs2 = make_test_pair("iana.org", "dns_aaaa", "2026-11-12T08:10:00Z")
            ev1, obs1 = make_test_pair("example.com", "dns_a", "2026-11-12T08:00:00Z")

            store.insert_record(ev2, obs2)
            store.insert_record(ev1, obs1)

            obs_list, ev_list = export_canonical_dataset(store, as_of="2026-11-12T10:00:00Z")
            # Must be ordered by observed_at ASC
            self.assertEqual(obs_list[0].subject, "example.com")
            self.assertEqual(obs_list[1].subject, "iana.org")
            self.assertEqual(ev_list[0].event_id, ev1.event_id)
            self.assertEqual(ev_list[1].event_id, ev2.event_id)

    def test_single_snapshot_export_prevents_silent_truncation(self):
        """Export must reject datasets exceeding limit rather than silently truncating."""
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "real.sqlite"
            store = RealObservationStore(store_db)

            ev1, obs1 = make_test_pair("example.com", "dns_a", "2026-11-12T08:00:00Z")
            ev2, obs2 = make_test_pair("iana.org", "dns_aaaa", "2026-11-12T08:05:00Z")

            store.insert_record(ev1, obs1)
            store.insert_record(ev2, obs2)

            # Request export with limit=1 when 2 records exist
            with self.assertRaisesRegex(ValueError, "dataset exceeds maximum partition limit"):
                export_canonical_dataset(store, as_of="2026-11-12T10:00:00Z", limit=1)

    def test_cannot_overwrite_existing_release_directory(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")
            with self.assertRaises(FileExistsError):
                publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

    def test_atomic_staging_cleanup_on_error(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            # Simulate verify failure before atomic rename
            with patch("anie.real_publish.verify_real_release", side_effect=RuntimeError("simulated verify crash")):
                with self.assertRaises(RuntimeError):
                    publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Final directory was never created
            self.assertFalse(out_dir.exists())
            # Staging directory was cleaned up
            staging_dirs = list(Path(tmp).glob(".staging_*"))
            self.assertEqual(len(staging_dirs), 0)


class TestAntiContamination(unittest.TestCase):
    def test_reject_synthetic_observation_in_publish_real(self):
        ev, _ = make_test_pair()
        synth_obs = demo_observations()[0]  # Synthetic fixture
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            with self.assertRaises(PermissionError):
                publish_real(([synth_obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")  # type: ignore

    def test_reject_synthetic_event_in_publish_real(self):
        ev, obs = make_test_pair()
        object.__setattr__(ev, "source_id", "synthetic:doh")
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            with self.assertRaises(PermissionError):
                publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

    def test_reject_synthetic_records_in_export_canonical(self):
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "real.sqlite"
            store = RealObservationStore(store_db)
            ev, obs = make_test_pair()
            store.insert_record(ev, obs)

            # Manually inject a synthetic row directly into sqlite
            with store._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO real_observations (
                        observation_id, evidence_id, subject_type, subject, kind,
                        observed_at, status, source_id, method, synthetic, confidence, payload
                    ) VALUES (
                        'obs_bad_synthetic', ?, 'domain', 'bad.com', 'dns_a',
                        '2026-11-12T09:00:00Z', 'ok', 'synthetic:test', 'dns', 0, NULL,
                        '{"schema":"anie.real-observation.v1","subject":"bad.com","kind":"dns_a","observed_at":"2026-11-12T09:00:00Z","values":["1.1.1.1"],"status":"ok","source_id":"synthetic:test","method":"dns","synthetic":false,"ttl_seconds":300}'
                    )
                    """,
                    (ev.event_id,),
                )

            with self.assertRaises(PermissionError):
                export_canonical_dataset(store, as_of="2026-11-12T10:00:00Z")


class TestIntegrityAndEvidenceVerification(unittest.TestCase):
    def test_unsigned_candidate_verification_contract(self):
        """Unsigned candidate release verification distinguishes candidate integrity from authentication."""
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # 1. Unsigned verification requires integrity_only=True
            with self.assertRaisesRegex(ValueError, "authenticated release verification requires a RealReleaseTrust"):
                verify_real_release(out_dir, trust=None, integrity_only=False)

            # 2. Candidate inspection with integrity_only=True succeeds and reports unauthenticated
            res = verify_real_release(out_dir, integrity_only=True)
            self.assertEqual(res["status"], "CANDIDATE_INTEGRITY_VERIFIED")
            self.assertFalse(res["authenticated"])
            self.assertTrue(res["integrity_only"])
            self.assertTrue(res["structural_valid"])
            self.assertTrue(res["evidence_integrity_valid"])
            self.assertFalse(res["publisher_authenticated"])
            self.assertFalse(res["anti_rollback_verified"])
            self.assertEqual(res["dataset_type"], DATASET_TYPE_REAL)
            self.assertEqual(res["total_observations"], 1)
            self.assertEqual(res["total_events"], 1)
            self.assertIsNone(res["key_id"])

    def test_manifest_tampering_detected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")
            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["total_observations"] = 999  # Tampered count
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "total_observations|record count mismatch|integrity mismatch"):
                verify_real_release(out_dir, integrity_only=True)

    def test_partition_file_tampering_detected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")
            obs_file = out_dir / "real_observations.jsonl.gz"
            # Append corrupt byte
            with obs_file.open("ab") as f:
                f.write(b"\x00")

            with self.assertRaisesRegex(ValueError, "SHA-256 integrity mismatch|size mismatch"):
                verify_real_release(out_dir, integrity_only=True)

    def test_corrupted_raw_dns_evidence_detected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Unpack real_events.jsonl.gz, modify raw_payload_b64, repack
            ev_file = out_dir / "real_events.jsonl.gz"
            with gzip.open(ev_file, "rb") as gz:
                lines = gz.read().splitlines()
            ev_data = json.loads(lines[0].decode("utf-8"))
            ev_data["raw_payload_b64"] = base64.b64encode(b"TAMPERED_DNS_WIRE_BYTES").decode("ascii")

            tampered_payload = (canonical_json(ev_data) + "\n").encode("utf-8")
            with ev_file.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
                    gz.write(tampered_payload)

            # Update manifest sha256 to isolate the raw evidence test from partition hash check
            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["files"][1]["sha256"] = sha256(ev_file.read_bytes()).hexdigest()
            man_data["files"][1]["bytes"] = ev_file.stat().st_size
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "raw_sha256 mismatch|raw evidence verification failed"):
                verify_real_release(out_dir, integrity_only=True)

    def test_missing_referenced_collection_event_detected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Repack real_events.jsonl.gz with an empty event list
            ev_file = out_dir / "real_events.jsonl.gz"
            with ev_file.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
                    gz.write(b"")

            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["files"][1]["sha256"] = sha256(ev_file.read_bytes()).hexdigest()
            man_data["files"][1]["bytes"] = ev_file.stat().st_size
            man_data["files"][1]["records"] = 0
            man_data["total_events"] = 0
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "broken referential integrity"):
                verify_real_release(out_dir, integrity_only=True)

    def test_duplicate_observation_id_rejected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Duplicate the observation record in real_observations.jsonl.gz
            obs_file = out_dir / "real_observations.jsonl.gz"
            rec_line = canonical_json(obs.to_dict()) + "\n"
            double_payload = (rec_line + rec_line).encode("utf-8")
            with obs_file.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
                    gz.write(double_payload)

            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["files"][0]["sha256"] = sha256(obs_file.read_bytes()).hexdigest()
            man_data["files"][0]["bytes"] = obs_file.stat().st_size
            man_data["files"][0]["records"] = 2
            man_data["total_observations"] = 2
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate observation_id"):
                verify_real_release(out_dir, integrity_only=True)

    def test_out_of_order_records_rejected(self):
        """Partitions not in strict deterministic order must fail closed."""
        ev1, obs1 = make_test_pair("example.com", "dns_a", "2026-11-12T08:00:00Z")
        ev2, obs2 = make_test_pair("iana.org", "dns_aaaa", "2026-11-12T08:05:00Z")

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs1, obs2], [ev1, ev2]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Invert order of observations in archive
            obs_file = out_dir / "real_observations.jsonl.gz"
            inverted_payload = (canonical_json(obs2.to_dict()) + "\n" + canonical_json(obs1.to_dict()) + "\n").encode("utf-8")
            with obs_file.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
                    gz.write(inverted_payload)

            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["files"][0]["sha256"] = sha256(obs_file.read_bytes()).hexdigest()
            man_data["files"][0]["bytes"] = obs_file.stat().st_size
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "out of deterministic order"):
                verify_real_release(out_dir, integrity_only=True)


class TestDetachedEd25519SigningAndVerification(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        self.key_id = "test-operator-key-01"
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_bytes = self.priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            expected_publisher="anie-first-party",
        )

    def test_detached_signing_and_verification_happy_path(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1)

            att = sign_manifest_detached(
                out_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )
            self.assertEqual(att["key_id"], self.key_id)
            self.assertEqual(att["key_fingerprint"], key_fingerprint(self.pub_bytes))

            res = verify_real_release(
                out_dir,
                trust=self.trust,
                now="2026-11-12T11:00:00Z",
            )
            self.assertEqual(res["status"], "AUTHENTICATED")
            self.assertTrue(res["authenticated"])
            self.assertTrue(res["structural_valid"])
            self.assertTrue(res["evidence_integrity_valid"])
            self.assertTrue(res["publisher_authenticated"])
            self.assertEqual(res["key_id"], self.key_id)
            self.assertEqual(res["key_fingerprint"], key_fingerprint(self.pub_bytes))

    def test_metadata_binding_enforced_in_signing(self):
        """Signing must fail closed when requested metadata conflicts with manifest."""
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1, publisher_identity="anie-first-party")

            # 1. Publisher mismatch
            with self.assertRaisesRegex(ValueError, "publisher mismatch"):
                sign_manifest_detached(
                    out_dir,
                    self.priv_key,
                    key_id=self.key_id,
                    release_sequence=1,
                    publisher_identity="unauthorized-channel",
                    issued_at="2026-11-12T10:05:00Z",
                    expires_at="2026-12-12T10:05:00Z",
                )

            # 2. Sequence mismatch
            with self.assertRaisesRegex(ValueError, "release sequence mismatch"):
                sign_manifest_detached(
                    out_dir,
                    self.priv_key,
                    key_id=self.key_id,
                    release_sequence=2,  # Manifest says 1
                    issued_at="2026-11-12T10:05:00Z",
                    expires_at="2026-12-12T10:05:00Z",
                )

            # 3. Commit mismatch
            with self.assertRaisesRegex(ValueError, "source_commit mismatch"):
                sign_manifest_detached(
                    out_dir,
                    self.priv_key,
                    key_id=self.key_id,
                    release_sequence=1,
                    source_commit="1" * 40,  # Manifest has 0*40
                    issued_at="2026-11-12T10:05:00Z",
                    expires_at="2026-12-12T10:05:00Z",
                )

    def test_metadata_binding_enforced_in_verification(self):
        """Verification must reject inconsistent metadata even if cryptographic signature is valid."""
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                out_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )

            att_file = out_dir / ATTESTATION_NAME
            att = json.loads(att_file.read_text(encoding="utf-8"))

            # Tamper outer key_id
            tampered_att = dict(att)
            tampered_att["key_id"] = "different-key-id"
            att_file.write_text(canonical_json(tampered_att) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "outer attestation key_id '.*' does not match"):
                verify_real_release(out_dir, trust=self.trust, now="2026-11-12T11:00:00Z")

    def test_forged_signature_rejected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                out_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )

            # Corrupt signature bytes
            att_path = out_dir / ATTESTATION_NAME
            att = json.loads(att_path.read_text(encoding="utf-8"))
            raw_sig = bytearray(base64.b64decode(att["signature_base64"]))
            raw_sig[0] ^= 0xFF
            att["signature_base64"] = base64.b64encode(raw_sig).decode("ascii")
            att_path.write_text(canonical_json(att) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "signature verification failed"):
                verify_real_release(out_dir, trust=self.trust, now="2026-11-12T11:00:00Z")

    def test_wrong_untrusted_public_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                out_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )

            # Operator pinned a different key
            other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            other_trust = RealReleaseTrust.from_single_key(
                key_id=self.key_id,
                public_key_raw=other_key,
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
            )
            with self.assertRaisesRegex(ValueError, "key fingerprint mismatch"):
                verify_real_release(out_dir, trust=other_trust, now="2026-11-12T11:00:00Z")

    def test_revoked_key_id_and_revoked_fingerprint_rejected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                out_dir,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=1,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )

            # 1. Test revoked key_id
            revoked_id_trust = RealReleaseTrust.from_single_key(
                key_id=self.key_id,
                public_key_raw=self.pub_bytes,
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                revoked_key_ids=frozenset({self.key_id}),
            )
            with self.assertRaisesRegex(ValueError, "revoked by operator trust policy"):
                verify_real_release(out_dir, trust=revoked_id_trust, now="2026-11-12T11:00:00Z")

            # 2. Test revoked fingerprint
            revoked_fp_trust = RealReleaseTrust.from_single_key(
                key_id=self.key_id,
                public_key_raw=self.pub_bytes,
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                revoked_fingerprints=frozenset({key_fingerprint(self.pub_bytes)}),
            )
            with self.assertRaisesRegex(ValueError, "key fingerprint '.*' has been revoked"):
                verify_real_release(out_dir, trust=revoked_fp_trust, now="2026-11-12T11:00:00Z")

    def test_key_rotation_compatibility(self):
        """Verifies multi-key trust configuration handles rotation seamlessly."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        # Key 1: Active Q1-Q2
        k1_priv = self.priv_key
        k1_pub = self.pub_bytes
        # Key 2: Active Q3-Q4
        k2_priv = Ed25519PrivateKey.generate()
        k2_pub = k2_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        trust = RealReleaseTrust(
            trusted_keys={
                "operator-k1": TrustedKey(
                    key_id="operator-k1",
                    public_key_raw=k1_pub,
                    valid_from="2026-01-01T00:00:00Z",
                    valid_until="2026-07-01T00:00:00Z",
                ),
                "operator-k2": TrustedKey(
                    key_id="operator-k2",
                    public_key_raw=k2_pub,
                    valid_from="2026-06-01T00:00:00Z",
                    valid_until="2027-01-01T00:00:00Z",
                ),
            }
        )

        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            # Release 1 signed by Key 1 in March
            dir1 = Path(tmp) / "rel_1"
            publish_real(([obs], [ev]), dir1, as_of="2026-03-01T10:00:00Z", release_sequence=1)
            sign_manifest_detached(
                dir1,
                k1_priv,
                key_id="operator-k1",
                release_sequence=1,
                issued_at="2026-03-01T10:05:00Z",
                expires_at="2026-04-01T10:05:00Z",
            )
            res1 = verify_real_release(dir1, trust=trust, now="2026-03-15T12:00:00Z")
            self.assertTrue(res1["authenticated"])
            self.assertEqual(res1["key_id"], "operator-k1")

            # Release 2 signed by Key 2 in August
            dir2 = Path(tmp) / "rel_2"
            publish_real(([obs], [ev]), dir2, as_of="2026-08-01T10:00:00Z", release_sequence=2)
            sign_manifest_detached(
                dir2,
                k2_priv,
                key_id="operator-k2",
                release_sequence=2,
                issued_at="2026-08-01T10:05:00Z",
                expires_at="2026-09-01T10:05:00Z",
            )
            res2 = verify_real_release(dir2, trust=trust, now="2026-08-15T12:00:00Z")
            self.assertTrue(res2["authenticated"])
            self.assertEqual(res2["key_id"], "operator-k2")


class TestReplayAndRollbackProtection(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        self.key_id = "rollback-test-key"
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_bytes = self.priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.trust = RealReleaseTrust.from_single_key(
            key_id=self.key_id,
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
        )

    def test_persistent_sequence_rollback_rejection(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "verifier_state.json"
            tracker = ReleaseSequenceTracker(state_file, auto_init=True)

            # Step 1: Verify Sequence 5
            dir5 = Path(tmp) / "rel_5"
            publish_real(([obs], [ev]), dir5, as_of="2026-11-12T10:00:00Z", release_sequence=5)
            sign_manifest_detached(
                dir5,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=5,
                issued_at="2026-11-12T10:05:00Z",
                expires_at="2026-12-12T10:05:00Z",
            )
            res5 = verify_real_release(dir5, trust=self.trust, now="2026-11-12T11:00:00Z", sequence_tracker=tracker)
            self.assertTrue(res5["authenticated"])
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 5)

            # Step 2: Attempting Sequence 4 (Downgrade/Replay attack)
            dir4 = Path(tmp) / "rel_4"
            publish_real(([obs], [ev]), dir4, as_of="2026-11-12T09:00:00Z", release_sequence=4)
            sign_manifest_detached(
                dir4,
                self.priv_key,
                key_id=self.key_id,
                release_sequence=4,
                issued_at="2026-11-12T09:05:00Z",
                expires_at="2026-12-12T09:05:00Z",
            )

            # Must be rejected fail-closed
            with self.assertRaisesRegex(ValueError, "replayed or downgraded"):
                verify_real_release(dir4, trust=self.trust, now="2026-11-12T11:00:00Z", sequence_tracker=tracker)

            # Step 3: Historical audit with allow_rollback=True succeeds without modifying high-water mark
            res_hist = verify_real_release(
                dir4,
                trust=self.trust,
                now="2026-11-12T11:00:00Z",
                sequence_tracker=tracker,
                allow_rollback=True,
            )
            self.assertTrue(res_hist["authenticated"])
            # High-water mark remains at 5
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 5)

    def test_tracker_corruption_fails_closed(self):
        """Malformed or unreadable state file must raise TrackerStateError and never reset to zero."""
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            tracker = ReleaseSequenceTracker(state_file)
            tracker.initialize()
            tracker.update_accepted_sequence("anie-first-party", 10)

            # Corrupt the state file
            state_file.write_text("{malformed json corrupt state")

            # Must fail closed with TrackerStateError, never return 0 or reset
            with self.assertRaises(TrackerStateError):
                tracker.get_last_accepted_sequence("anie-first-party")

            with self.assertRaises(TrackerStateError):
                tracker.update_accepted_sequence("anie-first-party", 11)

    def test_tracker_missing_state_after_init(self):
        """Deleting state file after initialization must be detected as TrackerStateLostError."""
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            tracker = ReleaseSequenceTracker(state_file)
            tracker.initialize()
            self.assertTrue(tracker.is_initialized())
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 0)

            # Unexpected deletion
            state_file.unlink()
            self.assertFalse(tracker.is_initialized())

            with self.assertRaises(TrackerStateLostError):
                tracker.get_last_accepted_sequence("anie-first-party")

    def test_tracker_concurrent_updates_prevent_downgrade(self):
        """Concurrent verifiers cannot cause a lower sequence to overwrite a higher accepted sequence."""
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "concurrent_state.json"
            tracker = ReleaseSequenceTracker(state_file, auto_init=True)

            def worker(seq: int):
                try:
                    tracker.update_accepted_sequence("anie-first-party", seq)
                    return True
                except ValueError:
                    # Expected if racing behind a higher sequence
                    return False

            with ThreadPoolExecutor(max_workers=8) as ex:
                # Dispatch random order sequences
                futures = [ex.submit(worker, s) for s in [5, 12, 8, 20, 15, 22, 10, 25]]
                results = [f.result() for f in futures]

            final_seq = tracker.get_last_accepted_sequence("anie-first-party")
            # Highest sequence submitted was 25
            self.assertEqual(final_seq, 25)

    def test_tracker_write_failure_clean_rollback(self):
        """Write or replace failure leaves original state file uncorrupted."""
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "atomic_state.json"
            tracker = ReleaseSequenceTracker(state_file, auto_init=True)
            tracker.update_accepted_sequence("anie-first-party", 10)

            # Simulate failure during replace
            with patch.object(Path, "replace", side_effect=OSError("simulated disk full")):
                with self.assertRaises(OSError):
                    tracker.update_accepted_sequence("anie-first-party", 20)

            # Original state remains intact at 10
            self.assertEqual(tracker.get_last_accepted_sequence("anie-first-party"), 10)


class TestResourceLimitsAndSafety(unittest.TestCase):
    def test_decompression_bomb_protection(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Test that decompressing a partition exceeding the configured limit is rejected fail-closed
            with patch("anie.real_publish.MAX_PARTITION_DECOMPRESSED_BYTES", 200):
                with self.assertRaisesRegex(ValueError, "exceeded decompression limit"):
                    verify_real_release(out_dir, integrity_only=True)

    def test_single_record_byte_limit_rejected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            obs_file = out_dir / "real_observations.jsonl.gz"
            huge_line = b"X" * 600000 + b"\n"  # Exceeds 500,000 byte limit
            with obs_file.open("wb") as raw:
                with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
                    gz.write(huge_line)

            man_file = out_dir / "manifest.json"
            man_data = json.loads(man_file.read_text(encoding="utf-8"))
            man_data["files"][0]["sha256"] = sha256(obs_file.read_bytes()).hexdigest()
            man_data["files"][0]["bytes"] = obs_file.stat().st_size
            man_file.write_text(canonical_json(man_data) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "exceeds byte limit"):
                verify_real_release(out_dir, integrity_only=True)

    def test_truncated_archive_rejected(self):
        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "release"
            publish_real(([obs], [ev]), out_dir, as_of="2026-11-12T10:00:00Z")

            # Truncate real_observations.jsonl.gz
            obs_file = out_dir / "real_observations.jsonl.gz"
            raw_bytes = obs_file.read_bytes()
            obs_file.write_bytes(raw_bytes[: len(raw_bytes) // 2])

            with self.assertRaises(ValueError):
                verify_real_release(out_dir, integrity_only=True)


class TestKeyLoadingAndOfflineWorkflow(unittest.TestCase):
    def test_strict_key_loading_pem_and_raw(self):
        """Strict loaders accept valid PEM and 32 raw bytes; reject truncated/corrupted keys."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv = Ed25519PrivateKey.generate()
        pem_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        with TemporaryDirectory() as tmp:
            pem_path = Path(tmp) / "priv.pem"
            pem_path.write_bytes(pem_bytes)

            raw_path = Path(tmp) / "pub.raw"
            raw_path.write_bytes(pub_raw)

            # Valid loads
            loaded_priv = load_private_key_file(pem_path)
            self.assertIsInstance(loaded_priv, Ed25519PrivateKey)

            loaded_pub = load_public_key_file(raw_path)
            self.assertEqual(loaded_pub, pub_raw)

            # Truncated raw key must fail closed without fallback
            bad_raw = Path(tmp) / "bad.raw"
            bad_raw.write_bytes(b"\x00" * 16)  # 16 bytes instead of 32
            with self.assertRaisesRegex(ValueError, "unsupported private key format|permissive truncation"):
                load_private_key_file(bad_raw)

            with self.assertRaisesRegex(ValueError, "unsupported public key format|permissive truncation"):
                load_public_key_file(bad_raw)


class TestCliRealPublication(unittest.TestCase):
    def test_cli_detached_offline_signing_workflow(self):
        """Full genuine offline signing and verification CLI workflow."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv_key = Ed25519PrivateKey.generate()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        ev, obs = make_test_pair()
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "real.sqlite"
            store = RealObservationStore(db_path)
            store.insert_record(ev, obs)

            key_file = Path(tmp) / "operator.key"
            key_file.write_bytes(priv_pem)
            pub_file = Path(tmp) / "operator.pub"
            pub_file.write_bytes(pub_raw)
            state_file = Path(tmp) / "verifier_state.json"

            out_dir = Path(tmp) / "release_cli"

            # 1. Collector VM exports unsigned candidate release
            exit_pub = cli_main([
                "publish-real",
                "--db", str(db_path),
                "--out", str(out_dir),
                "--as-of", "2026-11-12T10:00:00Z",
                "--sequence", "1",
            ])
            self.assertEqual(exit_pub, 0)
            self.assertTrue((out_dir / "manifest.json").exists())
            self.assertFalse((out_dir / ATTESTATION_NAME).exists())

            # 2. Inspect unsigned candidate using --integrity-only
            exit_cand = cli_main([
                "verify-real",
                "--dir", str(out_dir),
                "--integrity-only",
            ])
            self.assertEqual(exit_cand, 0)

            # 3. Unsigned verification without --integrity-only and without --key-file fails
            exit_fail = cli_main([
                "verify-real",
                "--dir", str(out_dir),
            ])
            self.assertEqual(exit_fail, 2)

            # 4. Operator machine executes detached offline signing
            exit_sign = cli_main([
                "sign-real",
                "--dir", str(out_dir),
                "--key-file", str(key_file),
                "--key-id", "operator-2026-key",
                "--sequence", "1",
                "--publisher", "anie-first-party",
            ])
            self.assertEqual(exit_sign, 0)
            self.assertTrue((out_dir / ATTESTATION_NAME).exists())

            # 5. Independent consumer verifies signed release with state tracker
            exit_ver = cli_main([
                "verify-real",
                "--dir", str(out_dir),
                "--key-file", str(pub_file),
                "--key-id", "operator-2026-key",
                "--state-file", str(state_file),
                "--init-state",
            ])
            self.assertEqual(exit_ver, 0)

            # 6. Re-verifying same release sequence fails due to anti-replay
            exit_replay = cli_main([
                "verify-real",
                "--dir", str(out_dir),
                "--key-file", str(pub_file),
                "--key-id", "operator-2026-key",
                "--state-file", str(state_file),
            ])
            self.assertEqual(exit_replay, 2)  # ValueError caught by CLI

            # 7. Auditing with --allow-rollback succeeds
            exit_audit = cli_main([
                "verify-real",
                "--dir", str(out_dir),
                "--key-file", str(pub_file),
                "--key-id", "operator-2026-key",
                "--state-file", str(state_file),
                "--allow-rollback",
            ])
            self.assertEqual(exit_audit, 0)


if __name__ == "__main__":
    unittest.main()
