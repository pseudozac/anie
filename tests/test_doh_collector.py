"""Adversarial and security tests for Phase 2 DoH collection engine."""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
from io import BytesIO
from pathlib import Path
import socket
import struct
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest

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
    flags: int = 0x8180,
    rcode: int = 0,
    answers: bytes | None = None,
    authority: bytes = b"",
    answer_count: int | None = None,
) -> bytes:
    question = make_dns_query(domain, kind)[12:]
    answer_bytes = answers
    if answer_bytes is None and rcode == 0:
        data = IPV4_SAMPLE if kind == "dns_a" else IPV6_SAMPLE
        typ = 1 if kind == "dns_a" else 28
        answer_bytes = b"\xc0\x0c" + struct.pack("!HHIH", typ, 1, 300, len(data)) + data

    an_count = (1 if answer_bytes else 0) if answer_count is None else answer_count
    combined_flags = (flags & ~0x0F) | rcode
    header = struct.pack("!HHHHHH", 0, combined_flags, 1, an_count, 1 if authority else 0, 0)
    return header + question + (answer_bytes or b"") + authority


def make_soa_record() -> bytes:
    rdata = b"\xc0\x0c\xc0\x0c" + struct.pack("!IIIII", 1, 2, 3, 4, 60)
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(rdata)) + rdata


class MockHttpResponse:
    def __init__(
        self,
        status: int = 200,
        payload: bytes = b"",
        headers: dict[str, str] | None = None,
        read_delay: float = 0.0,
        chunk_size: int | None = None,
    ):
        self.status = status
        self.payload = payload
        self.headers = headers or {"Content-Type": "application/dns-message"}
        self._stream = BytesIO(payload)
        self.read_delay = read_delay
        self.chunk_size = chunk_size

    def getheader(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def read(self, amt: int | None = None) -> bytes:
        if self.read_delay > 0:
            time.sleep(self.read_delay)
        max_read = amt or 4096
        if self.chunk_size is not None:
            max_read = min(max_read, self.chunk_size)
        return self._stream.read(max_read)


class MockSocket:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def settimeout(self, t: float):
        self.timeout = t


class MockHttpsConnection:
    def __init__(
        self,
        response: MockHttpResponse | Exception,
        connect_delay: float = 0.0,
        header_delay: float = 0.0,
        deadline: float | None = None,
    ):
        self.response = response
        self.connect_delay = connect_delay
        self.header_delay = header_delay
        self.deadline = deadline
        self.closed = False
        self.requests: list[dict] = []
        self.sock = MockSocket()

    def connect(self):
        if self.connect_delay > 0:
            time.sleep(self.connect_delay)

    def request(self, method: str, path: str, headers: dict | None = None):
        if self.connect_delay > 0:
            time.sleep(self.connect_delay)
        self.requests.append({"method": method, "path": path, "headers": headers or {}})
        if isinstance(self.response, Exception):
            raise self.response

    def getresponse(self) -> MockHttpResponse:
        if self.header_delay > 0:
            time.sleep(self.header_delay)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        self.closed = True


class TestDohCollectorAdversarial(unittest.TestCase):
    def setUp(self):
        self.mock_addrinfo = lambda host, port, type=socket.SOCK_STREAM: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443))
        ]
        self.rate_gov = DohRateGovernor.create_test_governor()

    def test_ad_flag_recorded_as_claim_without_independent_secure_verdict(self):
        # Resolver sets AD flag (flags = 0x81A0: QR, RD, RA, AD)
        wire_data = make_raw_dns_response("example.com", "dns_a", flags=0x81A0)
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")

        # Crucial requirement: AD flag is preserved as a resolver claim,
        # but does NOT set dnssec_status="secure"; it remains "indeterminate"
        self.assertTrue(obs.factual_verification.resolver_ad_claim)
        self.assertEqual(obs.factual_verification.dnssec_status, "indeterminate")
        self.assertNotEqual(obs.factual_verification.dnssec_status, "secure")

    def test_servfail_error_does_not_infer_bogus(self):
        wire_data = make_raw_dns_response("example.com", "dns_a", rcode=2, answers=b"")
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))

        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        event, obs = collector.collect("example.com", "dns_a")
        self.assertEqual(obs.status, "error")
        self.assertEqual(obs.error_code, "unavailable")
        self.assertEqual(obs.factual_verification.dnssec_status, "indeterminate")
        self.assertFalse(obs.factual_verification.resolver_ad_claim)

    def test_endpoint_resolution_delay_exhausts_deadline(self):
        # Resolver operation that never returns (sleeps 60s in isolated subprocess)
        hanging_cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.15,  # Strict short deadline
            subproc_cmd=hanging_cmd,
        )

        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")
        elapsed = time.monotonic() - t0
        # Main execution path must return promptly within ~0.2-0.5s, NOT block for 60s
        self.assertLess(elapsed, 0.8)

    def test_slow_http_headers_exhaust_deadline(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        # Connection simulates header read delay exceeding total timeout
        slow_conn = MockHttpsConnection(
            MockHttpResponse(status=200, payload=wire_data),
            header_delay=0.35,
        )
        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.12,
            connection_factory=lambda ip, host, timeout, **kw: slow_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.6)

    def test_slow_response_body_chunks_cannot_reset_deadline(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        # 10-byte chunks with 0.05s delay per chunk across ~44-byte response
        # Total reading time would be ~0.25s.
        # With timeout_seconds=0.10s, deadline must be exceeded after ~2 chunks.
        slow_resp = MockHttpResponse(status=200, payload=wire_data, read_delay=0.05, chunk_size=10)
        mock_conn = MockHttpsConnection(slow_resp)

        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.10,
            connection_factory=lambda ip, host, timeout, **kw: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")
        elapsed = time.monotonic() - t0
        # Must fail when cumulative read time exhausts deadline, not reset per chunk
        self.assertLess(elapsed, 0.4)

    def test_synthetic_and_real_pipeline_isolation(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout, **kw: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )
        event, real_obs = collector.collect("example.com", "dns_a")

        # 1. Real observation must explicitly have synthetic=False
        self.assertFalse(real_obs.synthetic)

        # 2. Synthetic publisher must strictly reject real observations
        with self.assertRaises((PermissionError, ValueError, ScopeDenied, AttributeError)):
            publish_synthetic([real_obs], Path("tmp_pub"), as_of="2026-11-12T00:00:00Z")

        # 3. RealObservation constructor must reject synthetic=True records
        bad_dict = real_obs.to_dict()
        bad_dict["synthetic"] = True
        with self.assertRaises(ValueError):
            RealObservation.from_dict(bad_dict)

    def test_slow_trickle_headers_cannot_extend_deadline_loopback(self):
        # Local loopback TCP server on ephemeral port (isolated fixture, no public network/DNS)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def slow_trickle_server():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.recv(1024)
                    # Trickle response headers 1 byte at a time with 0.04s sleep per byte
                    # Over 55 bytes, full transmission would take ~2.2 seconds
                    header_bytes = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n"
                    for b in header_bytes:
                        conn.sendall(bytes([b]))
                        time.sleep(0.04)
            except Exception:
                pass

        server_thread = threading.Thread(target=slow_trickle_server, daemon=True)
        server_thread.start()

        try:
            # Client has a short 0.15s deadline; server attempts to trickle for >2.0s
            collector = DohCollector(
                rate_governor=self.rate_gov,
                timeout_seconds=0.15,
                connection_factory=lambda ip, host, timeout, deadline=None: http.client.HTTPConnection("127.0.0.1", port=port, timeout=timeout),
                addrinfo_fn=lambda h, p, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443))],
            )

            t0 = time.monotonic()
            with self.assertRaises((TimeoutError, socket.timeout)):
                collector.collect("example.com", "dns_a")
            elapsed = time.monotonic() - t0

            # Execution must abort promptly within ~0.15s - 0.45s, not wait 2.2s for slow-trickle
            self.assertLess(elapsed, 0.6)
        finally:
            server.close()
            server_thread.join(timeout=1.0)

    def test_tls_connection_stall_exhausts_deadline(self):
        # Connection factory stalls during connect
        stalled_conn = MockHttpsConnection(
            MockHttpResponse(status=200, payload=b""),
            connect_delay=0.4,
        )
        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.1,
            connection_factory=lambda ip, host, timeout: stalled_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")

    def test_slow_http_body_read_exhausts_deadline(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        slow_resp = MockHttpResponse(status=200, payload=wire_data, read_delay=0.3)
        mock_conn = MockHttpsConnection(slow_resp)

        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.1,  # Short deadline
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")

    def test_overall_deadline_not_reset_on_retry(self):
        # Attempt 1 times out; Attempt 2 would succeed but remaining deadline has expired
        wire_data = make_raw_dns_response("example.com", "dns_a")
        conn1 = MockHttpsConnection(socket.timeout("timeout 1"), connect_delay=0.15)
        conn2 = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        conns = [conn1, conn2]

        collector = DohCollector(
            rate_governor=self.rate_gov,
            timeout_seconds=0.2,  # Budget allows only attempt 1
            connection_factory=lambda ip, host, timeout: conns.pop(0),
            addrinfo_fn=self.mock_addrinfo,
        )

        # Monotonic deadline is not reset on retry, so attempt 2 is rejected
        with self.assertRaises(TimeoutError):
            collector.collect("example.com", "dns_a")

    def test_malformed_cname_chain_fails_closed(self):
        # A response containing a CNAME record must fail closed
        qname = make_dns_query("example.com", "dns_a")[12:]
        # Answer with type 5 (CNAME) pointing to sub.example.com
        cname_rdata = b"\x03sub\xc0\x0c"
        cname_record = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 300, len(cname_rdata)) + cname_rdata
        wire_data = struct.pack("!HHHHHH", 0, 0x8180, 1, 1, 0, 0) + qname + cname_record

        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        with self.assertRaisesRegex(ValueError, "CNAME/DNAME chain not yet supported"):
            collector.collect("example.com", "dns_a")

    def test_malformed_compression_loop_fails_closed(self):
        # Packet with a compression pointer pointing to itself (offset 12 -> 0xC00C)
        wire_data = struct.pack("!HHHHHH", 0, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        with self.assertRaisesRegex(ValueError, "compression loop"):
            collector.collect("example.com", "dns_a")

    def test_batch_enforces_pilot_domain_limit(self):
        wire_data = make_raw_dns_response("example.com", "dns_a")
        mock_conn = MockHttpsConnection(MockHttpResponse(status=200, payload=wire_data))
        collector = DohCollector(
            rate_governor=self.rate_gov,
            connection_factory=lambda ip, host, timeout: mock_conn,
            addrinfo_fn=self.mock_addrinfo,
        )

        # Batch of 3 domains fails pilot constraint
        with self.assertRaisesRegex(ScopeDenied, "maximum authorized domains"):
            collector.collect_batch([
                ("example.com", "dns_a"),
                ("iana.org", "dns_a"),
                ("third.org", "dns_a"),
            ])


if __name__ == "__main__":
    unittest.main()
