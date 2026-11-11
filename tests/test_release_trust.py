"""Offline consumer trust and rollback tests, no network or signing credentials."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.demo import demo_observations
from anie.publish import publish_synthetic
from anie.release_trust import (
    ConsumerTrustPolicy, verify_pinned_synthetic_release,
    validate_release_provenance,
)

AS_OF = "2026-11-11T10:00:00Z"
NOW = "2026-11-11T11:00:00Z"


class TestReleaseTrust(unittest.TestCase):
    def _fixture(self, tmp):
        path = Path(tmp) / "release"
        publish_synthetic(demo_observations(), path, AS_OF)
        digest = sha256((path / "manifest.json").read_bytes()).hexdigest()
        return path, digest

    def test_correct_external_pin_and_offline_verification(self):
        with TemporaryDirectory() as tmp:
            path, digest = self._fixture(tmp)
            result = verify_pinned_synthetic_release(path, ConsumerTrustPolicy(digest), now=NOW)
            self.assertTrue(result["verified"])
            self.assertEqual(result["age_seconds"], 3600)
            self.assertFalse(result["publisher_signature_verified"])
            self.assertFalse(result["safe_to_autonomously_act"])

    def test_wrong_pin_is_rejected_before_reading_data(self):
        with TemporaryDirectory() as tmp:
            path, digest = self._fixture(tmp)
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                verify_pinned_synthetic_release(path, ConsumerTrustPolicy("0" * 64), now=NOW)

    def test_stale_and_future_dated_release(self):
        with TemporaryDirectory() as tmp:
            path, digest = self._fixture(tmp)
            with self.assertRaisesRegex(ValueError, "stale"):
                verify_pinned_synthetic_release(path, ConsumerTrustPolicy(digest, max_age_seconds=60), now=NOW)
            with self.assertRaisesRegex(ValueError, "future"):
                verify_pinned_synthetic_release(path, ConsumerTrustPolicy(digest), now="2026-11-10T10:00:00Z")

    def test_malformed_policy_rejected(self):
        for digest in ["", "Z" * 64, "abc", None]:
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                ConsumerTrustPolicy(digest)
        with self.assertRaises(ValueError):
            ConsumerTrustPolicy("0" * 64, max_age_seconds=True)
        with self.assertRaises(ValueError):
            ConsumerTrustPolicy("0" * 64, expected_schema="anie.intelligence.v2")

    def test_corrupt_data_fails_even_when_manifest_pin_matches(self):
        with TemporaryDirectory() as tmp:
            path, digest = self._fixture(tmp)
            target = path / "observations.jsonl.gz"
            data = bytearray(target.read_bytes())
            data[20] ^= 1
            target.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                verify_pinned_synthetic_release(path, ConsumerTrustPolicy(digest), now=NOW)

    def test_rehashed_unsupported_schema_denied_even_with_updated_pin(self):
        with TemporaryDirectory() as tmp:
            path, _ = self._fixture(tmp)
            file = path / "manifest.json"
            obj = json.loads(file.read_text())
            obj["intelligence_schema"] = "anie.intelligence.v999"
            file.write_text(json.dumps(obj))
            digest = sha256(file.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "unsupported intelligence schema"):
                verify_pinned_synthetic_release(path, ConsumerTrustPolicy(digest), now=NOW)

    def test_provenance_contract_is_not_signature(self):
        commit = "a" * 40
        digest = "b" * 64
        envelope = {
            "schema": "anie.release-provenance.v1",
            "source_commit": commit,
            "manifest_sha256": digest,
            "builder": "local-offline",
            "dataset_type": "synthetic_demo_only",
            "signature_state": "unsigned_design_only",
        }
        result = validate_release_provenance(envelope, expected_commit=commit, manifest_sha256=digest)
        self.assertFalse(result["publisher_signature_verified"])
        for key, value in [("source_commit", "c" * 40), ("manifest_sha256", "d" * 64),
                           ("dataset_type", "real"), ("signature_state", "signed"),
                           ("builder", "untrusted-cloud")]:
            with self.subTest(key=key):
                bad = {**envelope, key: value}
                with self.assertRaises(ValueError):
                    validate_release_provenance(bad, expected_commit=commit, manifest_sha256=digest)
