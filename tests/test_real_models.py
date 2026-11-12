"""Tests for Phase 2 real-world intelligence observation and provenance models."""
from __future__ import annotations

import base64
from hashlib import sha256
import unittest

from anie.real_models import (
    REAL_EVENT_SCHEMA,
    REAL_OBSERVATION_SCHEMA,
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)

SAMPLE_SHA = sha256(b"sample_wire_packet").hexdigest()
EVENT_ID = f"event_{SAMPLE_SHA}"


def sample_factual(**kwargs) -> FactualVerification:
    defaults = {
        "dnssec_status": "secure",
        "response_authenticity": "recursive",
        "transport_security": "tls_pinned",
        "resolver_identity": "cloudflare_doh",
        "wire_rcode": "NOERROR",
        "raw_evidence_status": "captured",
    }
    defaults.update(kwargs)
    return FactualVerification(**defaults)


def sample_request(**kwargs) -> RealCollectionRequest:
    defaults = {
        "kind": "dns_a",
        "subject": "example.com",
        "observed_at": "2026-11-12T10:00:00Z",
        "target_endpoint": "https://cloudflare-dns.com/dns-query",
        "pinned_ip": "104.16.132.229",
    }
    defaults.update(kwargs)
    return RealCollectionRequest.create(**defaults)


def sample_event(**kwargs) -> RealCollectionEvent:
    payload = kwargs.pop("raw_payload", b"sample_wire_packet")
    digest = sha256(payload).hexdigest() if payload else SAMPLE_SHA
    defaults = {
        "request": sample_request(),
        "response_code": "ANSWER",
        "raw_sha256": digest,
        "raw_evidence_status": "captured",
        "factual_verification": sample_factual(),
        "source_id": "first_party:doh:cloudflare",
        "observed_at": "2026-11-12T10:00:00Z",
        "raw_payload": payload,
    }
    defaults.update(kwargs)
    return RealCollectionEvent(**defaults)


def sample_observation(**kwargs) -> RealObservation:
    event = kwargs.pop("event", None) or sample_event()
    defaults = {
        "subject": "example.com",
        "kind": "dns_a",
        "observed_at": "2026-11-12T10:00:00Z",
        "values": ("93.184.216.34",),
        "status": "ok",
        "source_id": "first_party:doh:cloudflare",
        "method": "dns",
        "synthetic": False,
        "evidence_id": event.event_id,
        "factual_verification": sample_factual(),
        "ttl_seconds": 300,
        "error_code": None,
        "confidence": None,
    }
    defaults.update(kwargs)
    return RealObservation(**defaults)


class TestRealModels(unittest.TestCase):
    def test_real_observation_creation_and_canonical_id(self):
        obs = sample_observation()
        self.assertFalse(obs.synthetic)
        self.assertEqual(obs.method, "dns")
        self.assertTrue(obs.observation_id.startswith("obs_"))
        self.assertEqual(len(obs.observation_id), 68)  # "obs_" + 64 hex

        # Serialization roundtrip
        d = obs.to_dict()
        self.assertEqual(d["schema"], REAL_OBSERVATION_SCHEMA)
        self.assertFalse(d["synthetic"])
        roundtrip = RealObservation.from_dict(d)
        self.assertEqual(obs, roundtrip)
        self.assertEqual(obs.observation_id, roundtrip.observation_id)

    def test_synthetic_flag_must_be_strictly_false(self):
        with self.assertRaisesRegex(ValueError, "synthetic=False"):
            sample_observation(synthetic=True)
        with self.assertRaisesRegex(ValueError, "synthetic=False"):
            sample_observation(synthetic=None)

    def test_method_cannot_be_synthetic(self):
        with self.assertRaisesRegex(ValueError, "method must be in"):
            sample_observation(method="synthetic")

    def test_synthetic_source_id_rejected(self):
        with self.assertRaisesRegex(ValueError, "cannot have synthetic source_id"):
            sample_observation(source_id="synthetic:demo")

    def test_evidence_id_format_enforced(self):
        with self.assertRaisesRegex(ValueError, "evidence_id must match"):
            sample_observation(evidence_id="invalid_id")

    def test_confidence_nullable_and_bounded(self):
        # Nullable by default
        obs = sample_observation(confidence=None)
        self.assertIsNone(obs.confidence)

        # Valid bounded float
        obs_conf = sample_observation(confidence=0.85)
        self.assertEqual(obs_conf.confidence, 0.85)

        # Boundary values 0.0 and 1.0
        self.assertEqual(sample_observation(confidence=0.0).confidence, 0.0)
        self.assertEqual(sample_observation(confidence=1.0).confidence, 1.0)

        # Out of bounds rejected
        with self.assertRaisesRegex(ValueError, "confidence must be between"):
            sample_observation(confidence=1.05)
        with self.assertRaisesRegex(ValueError, "confidence must be between"):
            sample_observation(confidence=-0.1)
        with self.assertRaisesRegex(ValueError, "confidence must be a float or None"):
            sample_observation(confidence=True)  # bool is subclass of int in Python

    def test_factual_verification_attributes(self):
        fact = sample_factual(
            dnssec_status="secure",
            response_authenticity="authoritative",
            transport_security="tls_pinned",
            resolver_identity="cloudflare_doh",
            wire_rcode="NOERROR",
            raw_evidence_status="captured",
        )
        self.assertEqual(fact.dnssec_status, "secure")
        self.assertEqual(fact.response_authenticity, "authoritative")

        with self.assertRaisesRegex(ValueError, "invalid dnssec_status"):
            sample_factual(dnssec_status="unknown_status")
        with self.assertRaisesRegex(ValueError, "invalid response_authenticity"):
            sample_factual(response_authenticity="guessed")
        with self.assertRaisesRegex(ValueError, "invalid transport_security"):
            sample_factual(transport_security="insecure_plain")
        with self.assertRaisesRegex(ValueError, "invalid raw_evidence_status"):
            sample_factual(raw_evidence_status="corrupted")

    def test_real_collection_event_raw_evidence_integrity(self):
        payload = b"\x00\x01\x02\x03dns_payload"
        event = sample_event(raw_payload=payload)
        self.assertEqual(event.raw_sha256, sha256(payload).hexdigest())
        self.assertEqual(event.raw_evidence_status, "captured")
        self.assertTrue(event.event_id.startswith("event_"))

        # Serialization roundtrip
        d = event.to_dict()
        self.assertEqual(d["schema"], REAL_EVENT_SCHEMA)
        self.assertEqual(base64.b64decode(d["raw_payload_b64"]), payload)
        roundtrip = RealCollectionEvent.from_dict(d)
        self.assertEqual(event, roundtrip)
        self.assertEqual(event.event_id, roundtrip.event_id)

    def test_raw_payload_hash_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "raw_sha256 mismatch"):
            sample_event(raw_payload=b"abc", raw_sha256=sha256(b"def").hexdigest())

    def test_raw_payload_bounded_storage(self):
        oversized = b"A" * 65536  # Exceeds 65535 byte boundary
        with self.assertRaisesRegex(ValueError, "exceeds maximum size"):
            sample_event(raw_payload=oversized)

    def test_raw_evidence_unavailable_status(self):
        event = sample_event(
            raw_payload=None,
            raw_sha256=sha256(b"").hexdigest(),
            raw_evidence_status="unavailable",
            factual_verification=sample_factual(raw_evidence_status="unavailable"),
        )
        self.assertIsNone(event.raw_payload)
        self.assertEqual(event.raw_evidence_status, "unavailable")
        d = event.to_dict()
        self.assertNotIn("raw_payload_b64", d)
        roundtrip = RealCollectionEvent.from_dict(d)
        self.assertEqual(event, roundtrip)

    def test_event_rejects_synthetic_source(self):
        with self.assertRaisesRegex(ValueError, "cannot originate from synthetic source"):
            sample_event(source_id="synthetic:fixture")


if __name__ == "__main__":
    unittest.main()
