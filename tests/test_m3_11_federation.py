"""Unit test suite for Milestone M3.11 Multi-Collector Federation Trust Architecture.

Verifies:
1. Valid collector receipt signing and Ed25519 verification.
2. Rejection of tampered signatures and bitflipped payload attributes.
3. Trust store enrollment, expiration, and key revocation enforcement.
4. Monotonic sequence tracking, replay rejection, and equivocation conflict detection.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import unittest

from anie.federation import (
    CollectorReceipt,
    CollectorSequenceTracker,
    CollectorTrustStore,
    _crypto,
    sign_collector_receipt,
    verify_collector_receipt,
)


class TestM311Federation(unittest.TestCase):
    def setUp(self):
        InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey, _ = _crypto()
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        self.collector_id = "collector:us-east-1a"
        self.key_id = "collector-2026-key1"

        self.trust_store = CollectorTrustStore()
        self.trust_store.enroll_key(
            collector_identity=self.collector_id,
            key_id=self.key_id,
            public_key=self.pub_key,
            valid_from="2026-11-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
        )
        self.seq_tracker = CollectorSequenceTracker()

    def test_collector_receipt_signing_and_verification_happy_path(self):
        """Verify that an authentic signed collector receipt verifies cleanly."""
        dataset_digest = hashlib.sha256(b"simulated_batch_telemetry_bytes").hexdigest()
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=dataset_digest,
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
            source_context={"region": "us-east-1", "method": "dns"},
        )

        self.assertEqual(receipt.collector_identity, self.collector_id)
        self.assertEqual(receipt.sequence_number, 1)

        result = verify_collector_receipt(receipt, self.trust_store, sequence_tracker=self.seq_tracker)
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["collector_identity"], self.collector_id)
        self.assertEqual(result["dataset_digest"], dataset_digest)

    def test_receipt_tampered_signature_rejected(self):
        """Verify that a tampered signature fails closed with INVALID_SIGNATURE."""
        dataset_digest = hashlib.sha256(b"telemetry").hexdigest()
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=dataset_digest,
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
        )

        sig_raw = bytearray(base64.b64decode(receipt.signature_base64))
        sig_raw[5] ^= 0xFF  # Flip bit in signature
        tampered_sig_b64 = base64.b64encode(sig_raw).decode("ascii")

        tampered_receipt = CollectorReceipt(
            schema=receipt.schema,
            collector_identity=receipt.collector_identity,
            key_id=receipt.key_id,
            key_fingerprint=receipt.key_fingerprint,
            dataset_digest=receipt.dataset_digest,
            collection_interval=receipt.collection_interval,
            sequence_number=receipt.sequence_number,
            source_context=receipt.source_context,
            signature_base64=tampered_sig_b64,
        )

        res = verify_collector_receipt(tampered_receipt, self.trust_store)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "INVALID_SIGNATURE")

    def test_receipt_tampered_payload_rejected(self):
        """Verify that altering any payload field invalidates the signature."""
        dataset_digest = hashlib.sha256(b"telemetry").hexdigest()
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=dataset_digest,
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
        )

        # Alter dataset digest
        tampered_receipt = CollectorReceipt(
            schema=receipt.schema,
            collector_identity=receipt.collector_identity,
            key_id=receipt.key_id,
            key_fingerprint=receipt.key_fingerprint,
            dataset_digest="f" * 64,
            collection_interval=receipt.collection_interval,
            sequence_number=receipt.sequence_number,
            source_context=receipt.source_context,
            signature_base64=receipt.signature_base64,
        )

        res = verify_collector_receipt(tampered_receipt, self.trust_store)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "INVALID_SIGNATURE")

    def test_unenrolled_collector_fails(self):
        """Verify that an unenrolled collector identity fails closed."""
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity="collector:unregistered",
            key_id="some-key",
            dataset_digest=hashlib.sha256(b"data").hexdigest(),
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
        )

        res = verify_collector_receipt(receipt, self.trust_store)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "UNENROLLED_COLLECTOR")

    def test_expired_key_fails(self):
        """Verify that an expired key fails verification."""
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=hashlib.sha256(b"data").hexdigest(),
            started_at="2027-01-05T10:00:00Z",
            completed_at="2027-01-05T10:05:00Z",
            sequence_number=1,
        )

        # Evaluated past key's valid_until (2026-12-31)
        res = verify_collector_receipt(receipt, self.trust_store, now="2027-01-05T12:00:00Z")
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "EXPIRED_KEY")

    def test_revoked_key_fails(self):
        """Verify that revoking a collector key immediately fails verification."""
        receipt = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=hashlib.sha256(b"data").hexdigest(),
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
        )

        # Revoke the key
        self.trust_store.revoke_key(self.key_id, reason="compromise_simulation")

        res = verify_collector_receipt(receipt, self.trust_store)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "REVOKED_KEY")

    def test_sequence_replay_and_equivocation_protection(self):
        """Verify monotonic anti-replay protection and equivocation conflict detection."""
        digest1 = hashlib.sha256(b"batch1").hexdigest()
        digest2 = hashlib.sha256(b"batch2").hexdigest()
        digest_equivocation = hashlib.sha256(b"batch_equivocation").hexdigest()

        # Sequence 1
        rcpt1 = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=digest1,
            started_at="2026-11-21T10:00:00Z",
            completed_at="2026-11-21T10:05:00Z",
            sequence_number=1,
        )
        res1 = verify_collector_receipt(rcpt1, self.trust_store, sequence_tracker=self.seq_tracker)
        self.assertTrue(res1["verified"])

        # Sequence 2
        rcpt2 = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=digest2,
            started_at="2026-11-21T10:10:00Z",
            completed_at="2026-11-21T10:15:00Z",
            sequence_number=2,
        )
        res2 = verify_collector_receipt(rcpt2, self.trust_store, sequence_tracker=self.seq_tracker)
        self.assertTrue(res2["verified"])

        # Replay: Re-submitting sequence 1 must fail
        res_replay = verify_collector_receipt(rcpt1, self.trust_store, sequence_tracker=self.seq_tracker)
        self.assertFalse(res_replay["verified"])
        self.assertEqual(res_replay["status"], "REPLAY_OR_EQUIVOCATION")
        self.assertIn("REPLAY_DETECTED", res_replay["reason"])

        # Equivocation: Re-issuing sequence 2 with conflicting digest must fail closed
        rcpt_equiv = sign_collector_receipt(
            self.priv_key,
            collector_identity=self.collector_id,
            key_id=self.key_id,
            dataset_digest=digest_equivocation,
            started_at="2026-11-21T10:10:00Z",
            completed_at="2026-11-21T10:15:00Z",
            sequence_number=2,
        )
        res_equiv = verify_collector_receipt(rcpt_equiv, self.trust_store, sequence_tracker=self.seq_tracker)
        self.assertFalse(res_equiv["verified"])
        self.assertEqual(res_equiv["status"], "REPLAY_OR_EQUIVOCATION")
        self.assertIn("COLLECTOR_EQUIVOCATION_CONFLICT", res_equiv["reason"])


if __name__ == "__main__":
    unittest.main()
