"""No-network tests for RFC 8484 DNS parsing and the opt-in public pilot."""
from __future__ import annotations

from dataclasses import replace
import struct
import unittest
from unittest.mock import patch

from anie.collection_policy import ScopeDenied
from anie.dns_wire import make_dns_query, parse_dns_wire
from anie.live_dns_pilot import (
    PILOT_ACK, PILOT_DOMAIN, PILOT_HOST, MAX_RESPONSE_BYTES,
    request_plan, run_live_dns_pilot, _pinned_ip, _fetch_doh,
)

IPV4 = b"\x5d\xb8\xd8\x22"  # 93.184.216.34, sample bytes (not a live claim)
IPV6 = bytes.fromhex("26062800022000010248189325c81946")


def response(kind="dns_a", *, flags=0x8180, rcode=None, answers=None, authority=b"", count=None):
    question = make_dns_query("example.com", kind)[12:]
    answer_bytes = answers
    if answers is None:
        data = IPV4 if kind == "dns_a" else IPV6
        typ = 1 if kind == "dns_a" else 28
        answer_bytes = b"\xc0\x0c" + struct.pack("!HHIH", typ, 1, 120, len(data)) + data
    answer_count = (1 if answer_bytes else 0) if count is None else count
    if rcode is not None:
        flags = (flags & ~0x0F) | rcode
    header = struct.pack("!HHHHHH", 0, flags, 1, answer_count, 1 if authority else 0, 0)
    return header + question + answer_bytes + authority


def soa():
    # Owner = compressed example.com; mname and rname point to example.com.
    rdata = b"\xc0\x0c\xc0\x0c" + struct.pack("!IIIII", 1, 2, 3, 4, 60)
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(rdata)) + rdata


class TestDNSWire(unittest.TestCase):
    def test_builds_doh_query_without_network(self):
        payload = make_dns_query("EXAMPLE.COM.", "dns_a")
        self.assertEqual(payload[:12], struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0))
        self.assertIn(b"\x07example\x03com\x00\x00\x01\x00\x01", payload)
        with self.assertRaises(ValueError):
            make_dns_query("example.com", "dns_ptr")

    def test_a_record_and_real_origin_observation(self):
        parsed = parse_dns_wire(response(), domain="example.com", kind="dns_a")
        self.assertEqual(parsed.outcome, "ANSWER")
        self.assertEqual(parsed.values, ("93.184.216.34",))
        self.assertEqual(parsed.ttl_seconds, 120)
        record = parsed.as_observation(
            source_id="cloudflare_doh:pilot", observed_at="2026-11-12T00:00:00Z"
        )
        self.assertFalse(record.synthetic)
        self.assertEqual(record.method, "dns")

    def test_aaaa(self):
        p = parse_dns_wire(response("dns_aaaa"), domain="example.com", kind="dns_aaaa")
        self.assertEqual(p.status, "ok")
        self.assertEqual(p.values, ("2606:2800:220:1:248:1893:25c8:1946",))

    def test_negative_answers_require_soa_for_nodata(self):
        p = parse_dns_wire(response(answers=b"", authority=soa(), rcode=3),
                           domain="example.com", kind="dns_a")
        self.assertEqual((p.status, p.outcome, p.ttl_seconds), ("empty", "NXDOMAIN", 60))
        p = parse_dns_wire(response(answers=b"", authority=soa()),
                           domain="example.com", kind="dns_a")
        self.assertEqual((p.status, p.outcome, p.ttl_seconds), ("empty", "NODATA", 60))
        with self.assertRaisesRegex(ValueError, "NOERROR without"):
            parse_dns_wire(response(answers=b""), domain="example.com", kind="dns_a")

    def test_nxdomain_without_soa_not_cached(self):
        p = parse_dns_wire(response(answers=b"", rcode=3), domain="example.com", kind="dns_a")
        self.assertEqual(p.outcome, "NXDOMAIN")
        self.assertIsNone(p.ttl_seconds)

    def test_servfail_is_error_not_absence(self):
        parsed = parse_dns_wire(response(answers=b"", rcode=2), domain="example.com", kind="dns_a")
        self.assertEqual(parsed.status, "error")
        self.assertEqual(parsed.error_code, "unavailable")
        self.assertEqual(parsed.values, ())

    def test_cname_chain_never_becomes_negative(self):
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 40, 2) + b"\xc0\x0c"
        with self.assertRaisesRegex(ValueError, "CNAME"):
            parse_dns_wire(response(answers=cname), domain="example.com", kind="dns_a")

    def test_malformed_dns_messages_fail_closed(self):
        correct = response()
        variants = [
            correct[:10], correct + b"x",
            b"\x00\x01" + correct[2:],
            correct[:2] + b"\x01\x80" + correct[4:],  # not a response (QR=0)
            correct[:2] + b"\x83\x80" + correct[4:],  # truncated flag
            correct[:4] + struct.pack("!H", 2) + correct[6:],  # qdcount=2
            correct[:-1],
        ]
        for wire in variants:
            with self.subTest(data=wire[:12].hex()), self.assertRaises(ValueError):
                parse_dns_wire(wire, domain="example.com", kind="dns_a")

    def test_compression_pointer_loop_fails(self):
        wire = bytearray(response())
        idx = len(make_dns_query("example.com", "dns_a"))
        # Owner points to itself, not the canonical qname.
        wire[idx] = 0xC0 | ((idx >> 8) & 0x3F)
        wire[idx + 1] = idx & 0xFF
        with self.assertRaisesRegex(ValueError, "compression loop"):
            parse_dns_wire(bytes(wire), domain="example.com", kind="dns_a")


class _FakeResponse:
    def __init__(self, status=200, content=bytes(), content_type="application/dns-message", length=None):
        self.status = status
        self.content = content
        self.content_type = content_type
        self.length = length

    def getheader(self, name, default=None):
        if name == "Content-Type":
            return self.content_type
        if name == "Content-Length":
            return self.length
        return default

    def read(self, maximum):
        return self.content[:maximum]


class _FakeConnection:
    def __init__(self, ip, resp=None):
        self.resp = resp or _FakeResponse(content=response())
        self.calls = []
        self.closed = False

    def request(self, method, path, headers=None):
        self.calls.append((method, path, headers))

    def getresponse(self):
        return self.resp

    def close(self):
        self.closed = True


class TestPilot(unittest.TestCase):
    def test_default_does_not_contact_network(self):
        with patch("anie.live_dns_pilot._fetch_doh", side_effect=AssertionError("network must not run")):
            with self.assertRaises(ScopeDenied):
                run_live_dns_pilot(acknowledge_scope="")
            with self.assertRaises(ScopeDenied):
                run_live_dns_pilot(acknowledge_scope="yes")

    def test_exact_two_preflight_queries(self):
        p = request_plan()
        self.assertEqual(len(p), 2)
        self.assertEqual({r.kind for r in p}, {"dns_a", "dns_aaaa"})
        self.assertTrue(all(r.url.startswith("https://cloudflare-dns.com/dns-query?dns=") for r in p))
        self.assertTrue(all(r.domain == PILOT_DOMAIN for r in p))

    def test_explicit_approved_scope_with_mocked_transport(self):
        calls = []
        def fake(request):
            calls.append(request)
            return response(request.kind)
        with patch("anie.live_dns_pilot._fetch_doh", side_effect=fake):
            results = run_live_dns_pilot(acknowledge_scope=PILOT_ACK)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(not row["synthetic"] and not row["stored"] and not row["published"] for row in results))
        self.assertEqual(results[0]["source"], "cloudflare_doh:pilot")

    def test_resolver_rebinding_or_private_address_denied(self):
        with patch("anie.live_dns_pilot.socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("1.1.1.1", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]):
            with self.assertRaises(ScopeDenied):
                _pinned_ip()
        with patch("anie.live_dns_pilot.socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("1.1.1.1", 443)),
        ]):
            self.assertEqual(_pinned_ip(), "1.1.1.1")

    def test_no_redirect_or_unapproved_media(self):
        for bad_response in [
            _FakeResponse(status=302),
            _FakeResponse(status=429),
            _FakeResponse(content_type="text/html"),
            _FakeResponse(length=str(MAX_RESPONSE_BYTES + 1)),
            _FakeResponse(content=b"a" * (MAX_RESPONSE_BYTES + 1)),
        ]:
            conn = _FakeConnection("1.1.1.1", resp=bad_response)
            with self.subTest(code=bad_response.status):
                with patch("anie.live_dns_pilot._pinned_ip", return_value="1.1.1.1"), patch(
                    "anie.live_dns_pilot._PinnedHttpsConnection", return_value=conn
                ):
                    with self.assertRaises(ValueError):
                        _fetch_doh(request_plan()[0])
                self.assertTrue(conn.closed)

    def test_fixed_source_cannot_expand_targets(self):
        invalid = replace(request_plan()[0], domain="other.example.com")
        with self.assertRaises(ScopeDenied):
            _fetch_doh(invalid)
