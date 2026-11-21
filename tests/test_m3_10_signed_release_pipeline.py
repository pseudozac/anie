"""Integration tests for Milestone M3.10 Phase B: Signed Release Pipeline & Adversarial Verification."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.cross_vector_correlation import (
    CrossVectorCorrelator,
    VectorObservationSummary,
)
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_publish import (
    RealReleaseTrust,
    ReleaseSequenceTracker,
    generate_keypair,
    load_public_key_file,
    publish_real,
    sign_manifest_detached,
    verify_real_release,
)
from anie.real_store import RealObservationStore


def _make_telemetry_records(
    domain: str,
    ip: str = "104.21.48.12",
    observed_at: str = "2026-11-21T10:00:00Z",
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = f"raw_dns_wire_{domain}_{ip}_{observed_at}".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="dns_a",
        subject=domain,
        observed_at=observed_at,
        target_endpoint="https://cloudflare-dns.com/dns-query",
        pinned_ip="1.1.1.1",
    )
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
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=domain,
        kind="dns_a",
        observed_at=observed_at,
        values=(ip,),
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
    return event, obs


def _make_http_telemetry_records(
    domain: str,
    server: str = "cloudflare",
    observed_at: str = "2026-11-21T10:01:00Z",
) -> tuple[RealCollectionEvent, RealObservation]:
    raw_payload = f"HTTP/1.1 200 OK\r\nServer: {server}\r\n\r\n".encode("utf-8")
    raw_hash = hashlib.sha256(raw_payload).hexdigest()
    req = RealCollectionRequest.create(
        kind="http_metadata",
        subject=domain,
        observed_at=observed_at,
        target_endpoint=f"https://{domain}/",
        pinned_ip="104.21.48.12",
    )
    factual = FactualVerification(
        dnssec_status="secure",
        response_authenticity="authoritative",
        transport_security="tls_pinned",
        resolver_identity="first_party_http",
        wire_rcode="200",
        raw_evidence_status="captured",
    )
    event = RealCollectionEvent(
        request=req,
        response_code="200",
        raw_sha256=raw_hash,
        raw_evidence_status="captured",
        factual_verification=factual,
        source_id="first_party:http:direct",
        observed_at=observed_at,
        raw_payload=raw_payload,
    )
    obs = RealObservation(
        subject=domain,
        kind="http_metadata",
        observed_at=observed_at,
        values=(server,),
        status="ok",
        source_id="first_party:http:direct",
        method="http",
        synthetic=False,
        evidence_id=event.event_id,
        factual_verification=factual,
        ttl_seconds=300,
        error_code=None,
        confidence=None,
    )
    return event, obs


class TestM310SignedReleasePipeline(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.base_path = Path(self.tmp_dir.name)
        self.db_path = self.base_path / "telemetry.db"
        self.keys_path = self.base_path / "keys"
        self.release_path = self.base_path / "release_v1"
        self.tracker_path = self.base_path / "sequence_tracker.json"

        self.store = RealObservationStore(self.db_path)
        self.key_meta = generate_keypair(self.keys_path, key_id="operator-2026-key")
        self.pub_bytes = load_public_key_file(self.key_meta["public_key_path"])

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_end_to_end_publish_sign_and_verify_with_findings(self):
        """Verify end-to-end pipeline: ingest -> cross-vector correlate -> publish -> sign -> verify."""
        domain = "cloudflare-cdn.com"
        ev_dns, obs_dns = _make_telemetry_records(domain, "104.21.48.12", "2026-11-21T10:00:00Z")
        ev_http, obs_http = _make_http_telemetry_records(domain, "cloudflare", "2026-11-21T10:01:00Z")
        self.store.insert_record(ev_dns, obs_dns)
        self.store.insert_record(ev_http, obs_http)

        # Generate a cross-vector finding
        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain=domain,
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev_dns.event_id,
                    evidence_hash=ev_dns.raw_sha256,
                    values=["104.21.48.12"],
                ),
                "http": VectorObservationSummary(
                    vector="http",
                    observed_at="2026-11-21T10:01:00Z",
                    evidence_id=ev_http.event_id,
                    evidence_hash=ev_http.raw_sha256,
                    values=["cloudflare"],
                    metadata={"server": "cloudflare"},
                ),
            },
        )
        self.assertEqual(len(findings), 1)
        for f in findings:
            self.store.insert_cross_vector_finding(f)

        # 1. Publish candidate release containing findings
        pub_result = publish_real(
            self.store,
            output_dir=self.release_path,
            as_of="2026-11-21T12:00:00Z",
            release_sequence=1,
            include_findings=True,
        )
        self.assertEqual(pub_result["total_findings"], 1)
        self.assertTrue((self.release_path / "real_findings.jsonl.gz").is_file())

        # 2. Candidate inspection before signing (integrity_only=True)
        cand_res = verify_real_release(self.release_path, integrity_only=True)
        self.assertTrue(cand_res["evidence_integrity_valid"])
        self.assertFalse(cand_res["authenticated"])
        self.assertEqual(cand_res["total_findings"], 1)

        # 3. Sign manifest detached with Ed25519
        att = sign_manifest_detached(
            self.release_path,
            private_key_path=self.key_meta["private_key_path"],
            key_id="operator-2026-key",
            issued_at="2026-11-21T12:05:00Z",
            source_commit="0000000000000000000000000000000000000000",
        )
        self.assertIn("signature_base64", att)
        self.assertTrue((self.release_path / "signature.ed25519.json").is_file())

        # 4. Independent offline verification with trust policy
        trust = RealReleaseTrust.from_single_key(
            key_id="operator-2026-key",
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2030-01-01T00:00:00Z",
            expected_publisher="anie-first-party",
        )
        tracker = ReleaseSequenceTracker(self.tracker_path, auto_init=True)

        verify_res = verify_real_release(
            self.release_path,
            trust=trust,
            sequence_tracker=tracker,
            allow_uninitialized_state=True,
            now="2026-11-21T12:06:00Z",
        )
        self.assertTrue(verify_res["authenticated"])
        self.assertEqual(verify_res["status"], "AUTHENTICATED")
        self.assertEqual(verify_res["total_findings"], 1)
        self.assertTrue(verify_res["anti_rollback_verified"])

    def test_adversarial_tampered_findings_partition_rejected(self):
        """Verify that tampering with bytes in real_findings.jsonl.gz fails closed."""
        ev_dns, obs_dns = _make_telemetry_records("tamper-test.com", "104.21.48.12")
        self.store.insert_record(ev_dns, obs_dns)

        correlator = CrossVectorCorrelator(self.store)
        findings = correlator.correlate_records(
            domain="tamper-test.com",
            vectors={
                "dns": VectorObservationSummary(
                    vector="dns",
                    observed_at="2026-11-21T10:00:00Z",
                    evidence_id=ev_dns.event_id,
                    evidence_hash=ev_dns.raw_sha256,
                    values=["104.21.48.12"],
                ),
            },
        )
        self.store.insert_cross_vector_finding(findings[0])

        publish_real(
            self.store,
            output_dir=self.release_path,
            as_of="2026-11-21T12:00:00Z",
            release_sequence=1,
            include_findings=True,
        )

        # Adversarial bitflip in real_findings.jsonl.gz
        findings_file = self.release_path / "real_findings.jsonl.gz"
        raw_data = bytearray(findings_file.read_bytes())
        raw_data[20] ^= 0xFF
        findings_file.write_bytes(bytes(raw_data))

        with self.assertRaises(ValueError) as ctx:
            verify_real_release(self.release_path, integrity_only=True)
        self.assertTrue("size mismatch" in str(ctx.exception) or "SHA-256 integrity mismatch" in str(ctx.exception))

    def test_adversarial_corrupted_signature_rejected(self):
        """Verify that altering even a single character of the signature fails closed."""
        ev_dns, obs_dns = _make_telemetry_records("sig-test.com", "104.21.48.12")
        self.store.insert_record(ev_dns, obs_dns)

        publish_real(
            self.store,
            output_dir=self.release_path,
            as_of="2026-11-21T12:00:00Z",
            release_sequence=1,
        )
        sign_manifest_detached(
            self.release_path,
            private_key_path=self.key_meta["private_key_path"],
            key_id="operator-2026-key",
            issued_at="2026-11-21T12:05:00Z",
            source_commit="0000000000000000000000000000000000000000",
        )

        # Corrupt signature in JSON
        sig_file = self.release_path / "signature.ed25519.json"
        sig_data = json.loads(sig_file.read_text(encoding="utf-8"))
        raw_sig = list(sig_data["signature_base64"])
        raw_sig[5] = "A" if raw_sig[5] != "A" else "B"
        sig_data["signature_base64"] = "".join(raw_sig)
        sig_file.write_text(json.dumps(sig_data), encoding="utf-8")

        trust = RealReleaseTrust.from_single_key(
            key_id="operator-2026-key",
            public_key_raw=self.pub_bytes,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2030-01-01T00:00:00Z",
        )
        with self.assertRaises(Exception) as ctx:
            verify_real_release(self.release_path, trust=trust, now="2026-11-21T12:06:00Z")
        self.assertIn("signature verification failed", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
