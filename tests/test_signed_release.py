"""Adversarial offline Ed25519 release verification; keys are ephemeral in memory."""
from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.demo import demo_observations
from anie.publish import publish_synthetic
from anie.observations import canonical_json
from anie.signed_release import (
    ATTESTATION_NAME, SignedReleaseTrust, key_fingerprint,
    sign_synthetic_release, verify_signed_synthetic_release,
)

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None
AS_OF = "2026-11-11T10:00:00Z"
ISSUED = "2026-11-11T11:00:00Z"
EXPIRES = "2026-11-12T11:00:00Z"
NOW = "2026-11-11T12:00:00Z"
COMMIT = "a" * 40


@unittest.skipUnless(HAVE_CRYPTO, "optional cryptography[signing] extra not installed")
class TestSignedSyntheticRelease(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        self.private_key = Ed25519PrivateKey.generate()
        self.public_raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.root = SignedReleaseTrust(self.public_raw, expected_source_commit=COMMIT)

    def _fixture(self, tmp):
        directory = Path(tmp) / "release"
        publish_synthetic(demo_observations(), directory, AS_OF)
        return directory

    def _sign(self, directory, **params):
        args = dict(source_commit=COMMIT, release_sequence=1, issued_at=ISSUED, expires_at=EXPIRES)
        args.update(params)
        return sign_synthetic_release(directory, self.private_key, **args)

    def _check(self, directory, *, trust=None, now=NOW):
        return verify_signed_synthetic_release(directory, trust or self.root, now=now)

    def _rewrite(self, directory, mutator):
        path = directory / ATTESTATION_NAME
        data = json.loads(path.read_text(encoding="utf-8"))
        mutator(data)
        path.write_text(canonical_json(data) + "\n", encoding="utf-8")

    def test_genuine_signature_and_full_evidence_replay(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            att = self._sign(directory)
            result = self._check(directory)
            self.assertTrue(result["verified"])
            self.assertTrue(result["publisher_signature_verified"])
            self.assertFalse(result["publisher_real_world_identity_verified"])
            self.assertFalse(result["safe_to_autonomously_act"])
            self.assertEqual(result["release_sequence"], 1)
            self.assertEqual(result["source_commit"], COMMIT)
            self.assertEqual(att["key_fingerprint"], key_fingerprint(self.public_raw))

    def test_missing_signature_rejected(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            with self.assertRaisesRegex(ValueError, "missing or unsafe"):
                self._check(directory)

    def test_wrong_public_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                self._check(directory, trust=replace(self.root, public_key_raw=other))

    def test_modified_signature_or_payload_rejected(self):
        for field in ["signature", "payload"]:
            with self.subTest(field=field), TemporaryDirectory() as tmp:
                directory = self._fixture(tmp)
                self._sign(directory)
                if field == "signature":
                    def change(data):
                        raw = bytearray(base64.b64decode(data["signature_base64"]))
                        raw[0] ^= 1
                        data["signature_base64"] = base64.b64encode(raw).decode("ascii")
                else:
                    def change(data):
                        data["payload"]["source_commit"] = "b" * 40
                self._rewrite(directory, change)
                with self.assertRaisesRegex(ValueError, "signature verification failed"):
                    self._check(directory)

    def test_unsupported_fields_and_schema_denied(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            self._rewrite(directory, lambda data: data.update({"extra": "untrusted"}))
            with self.assertRaisesRegex(ValueError, "fields"):
                self._check(directory)
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            self._rewrite(directory, lambda data: data.update({"schema": "anie.rsa-sha1.v1"}))
            with self.assertRaisesRegex(ValueError, "schema"):
                self._check(directory)

    def test_wrong_expected_source_commit(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "wrong source commit"):
                self._check(directory, trust=replace(self.root, expected_source_commit="b" * 40))

    def test_replay_and_downgrade(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "replayed or downgraded"):
                self._check(directory, trust=replace(self.root, last_accepted_sequence=1))
            with self.assertRaisesRegex(ValueError, "replayed or downgraded"):
                self._check(directory, trust=replace(self.root, last_accepted_sequence=5))

    def test_revoked_key_denied(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            revocation = frozenset({key_fingerprint(self.public_raw)})
            with self.assertRaisesRegex(ValueError, "revoked"):
                self._check(directory, trust=replace(self.root, revoked_fingerprints=revocation))

    def test_expired_or_not_yet_valid_trust_key(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "key expired"):
                self._check(directory, trust=replace(self.root, key_valid_until="2026-11-11T11:30:00Z"))
            with self.assertRaisesRegex(ValueError, "key expired"):
                self._check(directory, trust=replace(self.root, key_valid_from="2026-11-11T13:00:00Z"))

    def test_expired_or_future_signature(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "not currently valid"):
                self._check(directory, now="2026-11-12T12:00:00Z")
            with self.assertRaisesRegex(ValueError, "not currently valid"):
                self._check(directory, now="2026-11-11T10:30:00Z")

    def test_stale_dataset_even_with_valid_signature(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "stale"):
                self._check(directory, trust=replace(self.root, max_age_seconds=60))

    def test_signed_data_mutation_is_rejected(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            data_path = directory / "intelligence.jsonl.gz"
            data = bytearray(data_path.read_bytes())
            data[-10] ^= 1
            data_path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                self._check(directory)

    def test_replaced_manifest_is_rejected(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            path = directory / "manifest.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["notice"] = "attacker-controlled notice"
            path.write_text(canonical_json(data) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "signed manifest digest mismatch"):
                self._check(directory)

    def test_unsigned_or_malformed_release_cannot_be_signed(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            with self.assertRaisesRegex(ValueError, "cannot sign before"):
                self._sign(directory, issued_at="2026-11-10T09:00:00Z")
            with self.assertRaisesRegex(ValueError, "invalid release sequence"):
                self._sign(directory, release_sequence=True)
            self._sign(directory)
            with self.assertRaises(FileExistsError):
                self._sign(directory)

    def test_unrecognized_builder_and_repo_rejected(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            with self.assertRaisesRegex(ValueError, "publisher identity"):
                replace(self.root, expected_repository="attacker/repo")
            with self.assertRaisesRegex(ValueError, "publisher identity"):
                replace(self.root, expected_builder="untrusted-build")

    def test_invalid_signature_cannot_be_laundered_with_new_hash(self):
        with TemporaryDirectory() as tmp:
            directory = self._fixture(tmp)
            self._sign(directory)
            # Rewriting both old-style manifest and attestation does not
            # let an attacker forge Ed25519 authentication.
            def change(data):
                data["payload"]["manifest_sha256"] = "b" * 64
            self._rewrite(directory, change)
            with self.assertRaisesRegex(ValueError, "signature verification failed"):
                self._check(directory)
