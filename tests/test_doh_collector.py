"""Tests for Phase 2 DoH collection engine, wire responses, and PR 1 store integration."""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import socket
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock

from anie.collection_policy import ScopeDenied
from anie.dns_wire import make_dns_query
from anie.doh_collector import DohCollector
from anie.doh_governor import DohRateGovernor
from anie.publish import publish_synthetic
from anie.real_models import RealCollectionEvent, RealObservation
from anie.real_store import RealObservationStore

IPV4_SAMPLE = b"\x5d\xb8\xd8\x22"  # 93.184.216.34
IPV6_SAMPLE = bytes.fromhex("26062800022000010248189325c81946")


def make_raw_dns_response(
    domain: str = "example.com",
    kind: str = "dns_a",
    *,
    flags: int = 0x8180,  # QR=1, RD=1, RA=1
    rcode: int = 0,
    answers: bytes | None = None,
    authority: bytes = b"",
    answer_count: int | None = None,
) -> bytes:
    """Synthesize a complete RFC 1035 / RFC 8484 DNS wire response packet."""
    question = make_dns_query(domain, kind)[12:]
    answer_bytes = answers
    if answer_bytes is None and rcode == 0:
        data = IPV4_SAMPLE if kind == "dns_a" else IPV6_SAMPLE
        typ = 1 if kind == "dns_a" else 28
        # Name pointer to question at offset 12: 0xC00C
        answer_bytes = b"\xc0\x0c" + struct.pack("!HHIH", typ, 1, 300, len(data)) + data

    an_count = (1 if answer_bytes else 0) if answer_count is None else answer_count
    combined_flags = (flags & ~0x0F) | rcode
    header = struct.pack("!HHHHHH", 0, combined_flags, 1, an_count, 1 if authority else 0, 0)
    return header + question + (answer_bytes or b"") + authority


def make_soa_record() -> bytes:
    """Synthesize a negative SOA record."""
    rdata = b"\xc0\x0c\xc0\x0c" + struct.pack("!IIIII", 1, 2, 3, 4, 60)
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(rdata)) + rdata


class MockHttpResponse:
    def __init__(
        self,
        status: int = 200,
        payload: bytes = b"",
        headers: dict[str, str] | None = None,
    ):
        self.status = status
        self.payload = payload
        self.headers = headers or {"Content-Type": "application/dns-message"}
        self._stream = BytesIO(payload)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def read(self, amt: int | None = None) -> bytes:
        return self._stream.read(amt)


class MockHttpsConnection:
    def __init__(self, response: MockHttpResponse | Exception):
        self.response = response
        self.closed = False
        self.requests: list[dict] = []

    def request(self, method: str, path: str, headers: dict | None = None):
        self.requests.append({"method": method, "path": path, "headers": headers or {}})
        if isinstance(self.response, Exception):
            raise self.response

    def getresponse(self) -> MockHttpResponse:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        self.closed = True


class TestDohCollector(unittest.TestCase):
    def setUp(self):
        self.mock_addrinfo = lambda host, port, type=socket.SOCK_STREAM: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443))
        ]

    def test_collect_answer_response_ok(self):
        # Wire packet with AD flag set (0x81A0: QR, RD, RA, AD)
        wire_data = make_raw_dns_response("example.com", "dns_a", flags=0x81A0)
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")

        # Verify Observation model
        self.assertEqual(obs.subject, "example.com")
        self.assertEqual(obs.kind, "dns_a")
        self.assertEqual(obs.status, "ok")
        self.assertEqual(obs.values, ("93.184.216.34",))
        self.assertEqual(obs.method, "dns")
        self.assertFalse(obs.synthetic)
        self.assertIsNone(obs.confidence)  # Nullable confidence
        self.assertEqual(obs.evidence_id, event.event_id)

        # Verify Factual Verification
        self.assertEqual(obs.factual_verification.dnssec_status, "secure")
        self.assertEqual(obs.factual_verification.response_authenticity, "recursive")
        self.assertEqual(obs.factual_verification.transport_security, "tls_pinned")
        self.assertEqual(obs.factual_verification.resolver_identity, "cloudflare_doh")

        # Verify Event model
        self.assertEqual(event.response_code, "ANSWER")
        self.assertEqual(event.raw_evidence_status, "captured")
        self.assertEqual(event.raw_payload, wire_data)
        self.assertTrue(event.verify_raw_evidence())

    def test_collect_nxdomain_response(self):
        wire_data = make_raw_dns_response(
            "iana.org", "dns_a", rcode=3, answers=b"", authority=make_soa_record()
        )
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("iana.org", "dns_a")
        self.assertEqual(obs.status, "empty")
        self.assertEqual(obs.values, ())
        self.assertEqual(event.response_code, "NXDOMAIN")
        self.assertEqual(obs.factual_verification.wire_rcode, "NXDOMAIN")

    def test_collect_nodata_response(self):
        wire_data = make_raw_dns_response(
            "iana.org", "dns_aaaa", rcode=0, answers=b"", authority=make_soa_record()
        )
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("iana.org", "dns_aaaa")
        self.assertEqual(obs.status, "empty")
        self.assertEqual(obs.values, ())
        self.assertEqual(event.response_code, "NODATA")

    def test_collect_servfail_error_and_dnssec_indeterminate(self):
        # SERVFAIL response (rcode=2)
        wire_data = make_raw_dns_response(
            "example.com", "dns_a", rcode=2, answers=b""
        )
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")
        self.assertEqual(obs.status, "error")
        self.assertEqual(obs.error_code, "unavailable")
        self.assertEqual(event.response_code, "SERVFAIL")

        # Crucial mandatory invariant: SERVFAIL must NOT be inferred as DNSSEC bogus
        self.assertEqual(obs.factual_verification.dnssec_status, "indeterminate")
        self.assertNotEqual(obs.factual_verification.dnssec_status, "bogus")

    def test_collect_refused_error(self):
        wire_data = make_raw_dns_response(
            "example.com", "dns_a", rcode=5, answers=b""
        )
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")
        self.assertEqual(obs.status, "error")
        self.assertEqual(obs.error_code, "unavailable")
        self.assertEqual(event.response_code, "REFUSED")

    def test_unallowlisted_target_denied_before_network(self):
        mock_conn = MagicMock()
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaises(ScopeDenied):
            collector.collect("evil.com", "dns_a")
        mock_conn.assert_not_called()

    def test_unallowlisted_kind_denied_before_network(self):
        mock_conn = MagicMock()
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaises(ScopeDenied):
            collector.collect("example.com", "dns_mx")
        mock_conn.assert_not_called()

    def test_http_redirect_prohibited(self):
        mock_conn = MockHttpsConnection(
            MockHttpResponse(status=302, payload=b"", headers={"Location": "https://attacker.org"})
        )
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaisesRegex(ScopeDenied, "redirect prohibited"):
            collector.collect("example.com", "dns_a")

    def test_http_error_status_fails_closed(self):
        mock_conn = MockHttpsConnection(MockHttpResponse(status=500, payload=b"Internal Server Error"))
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaisesRegex(ValueError, "status denied: 500"):
            collector.collect("example.com", "dns_a")

    def test_unexpected_content_type_rejected(self):
        mock_conn = MockHttpsConnection(
            MockHttpResponse(status=200, payload=b"{}", headers={"Content-Type": "application/dns-json"})
        )
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaisesRegex(ValueError, "unexpected DoH media type"):
            collector.collect("example.com", "dns_a")

    def test_oversized_response_rejected(self):
        mock_conn = MockHttpsConnection(
            MockHttpResponse(status=200, payload=b"X" * 65536)
        )
        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        with self.assertRaisesRegex(ValueError, "oversized DoH"):
            collector.collect("example.com", "dns_a")

    def test_retry_on_socket_timeout_recovers(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        # Attempt 1 times out; Attempt 2 succeeds
        conn1 = MockHttpsConnection(socket.timeout("connection timed out"))
        conn2 = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        conns = [conn1, conn2]

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: conns.pop(0),
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")
        self.assertEqual(obs.status, "ok")
        self.assertEqual(len(conns), 0)  # Both connections attempted

    def test_retry_budget_exhaustion_fails(self):
        # Two consecutive timeouts exhaust the retry budget (1 retry allowed)
        conn1 = MockHttpsConnection(socket.timeout("timeout 1"))
        conn2 = MockHttpsConnection(socket.timeout("timeout 2"))
        conns = [conn1, conn2]

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: conns.pop(0),
            addrinfo_fn=self.mock_addrinfo,
        )

        with self.assertRaisesRegex(TimeoutError, "timed out after 1 retry"):
            collector.collect("example.com", "dns_a")

    def test_integration_with_real_store(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")

        with TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "state_real.sqlite"
            store = RealObservationStore(store_path)

            # Insert collected records into real store
            self.assertTrue(store.insert_record(event, obs))
            self.assertEqual(len(store.all_observations()), 1)
            self.assertEqual(store.check_referential_integrity(), [])

            # Export records and verify cryptographic raw evidence hash
            records = store.export_records()
            self.assertEqual(len(records), 1)
            exported_event, exported_obs = records[0]
            self.assertEqual(exported_event.raw_payload, wire_data)
            self.assertTrue(exported_event.verify_raw_evidence())

            # Anti-contamination: collected real observation must NOT be publishable via publish_synthetic
            with self.assertRaises(PermissionError):
                publish_synthetic([obs], Path(tmp) / "pub", "2026-11-12T10:00:00Z")  # type: ignore


if __name__ == "__main__":
    unittest.main()
