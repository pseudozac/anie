"""ANIE v0.2 collector policy and fixture parsing acceptance suite (offline only)."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from anie.collection_policy import (
    CollectionBudget, CollectionPolicy, ScopeDenied, ensure_global_ip,
    validate_https_redirect, validate_resolved_addresses,
)
from anie.collection_pipeline import (
    FixtureTransport, OfflineCollector, parse_autnum_fixture,
)
from anie.collection_ledger import CollectionLedger
from anie.demo import demo_observations
from anie.observations import Observation

STAMP = "2026-11-11T09:00:00Z"
DOMAIN = "sample.example.test"
DOC_IP = "203.0.113.17"


def dns(answers=None, *, rcode="NOERROR", kind="A", question=DOMAIN, **changes):
    obj = {
        "protocol": "dns", "qtype": kind, "question": question,
        "rcode": rcode, "answers": [{"type": kind, "value": item, "ttl": 90} for item in (answers if answers is not None else ["192.0.2.8"])],
        "complete": True, "truncated": False,
    }
    obj.update(changes)
    return obj


def policy(*, targets=(DOMAIN, DOC_IP), kinds=("dns_a", "dns_aaaa", "dns_ptr", "rdap_network"), **limits):
    return CollectionPolicy(targets=frozenset(targets), kinds=frozenset(kinds), **limits)


def get(kind, target, raw, *, pol=None):
    return OfflineCollector(pol or policy(), FixtureTransport({(kind, target): raw})).collect(kind, target, STAMP)


class TestCollectionPolicy(unittest.TestCase):
    def test_default_denies_all(self):
        with self.assertRaises(ScopeDenied):
            CollectionPolicy().authorize("dns_a", DOMAIN)

    def test_explicit_exact_scope(self):
        p = policy()
        self.assertEqual(p.authorize("dns_a", DOMAIN.upper()), DOMAIN)
        with self.assertRaises(ScopeDenied):
            p.authorize("dns_a", "other.example.test")
        with self.assertRaises(ScopeDenied):
            p.authorize("rdap_network", DOMAIN)
        with self.assertRaises(ScopeDenied):
            p.authorize("dns_ptr", "127.0.0.1")

    def test_reject_uncanonical_and_invalid_limits(self):
        with self.assertRaises(ValueError):
            policy(targets=(DOMAIN.upper(),))
        with self.assertRaises(ValueError):
            policy(max_requests=True)
        with self.assertRaises(ValueError):
            policy(max_response_bytes=100)
        with self.assertRaises(ValueError):
            policy(max_response_bytes=999999, max_total_response_bytes=512)

    def test_deny_non_global_network_destinations(self):
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.10", "198.51.100.1", "203.0.113.1", "2001:db8::1", "fe80::1", "::1", "224.0.0.1", "255.255.255.255", "2606:4700::1111%eth0"]:
            with self.subTest(address=address), self.assertRaises((ScopeDenied, ValueError)):
                ensure_global_ip(address)
        self.assertEqual(ensure_global_ip("1.1.1.1"), "1.1.1.1")

    def test_allowlisted_global_resolution_and_rebinding(self):
        p = policy(targets=("www.example.org",), kinds=("dns_a",), max_redirects=1)
        self.assertEqual(validate_resolved_addresses(p, "www.example.org", ("1.1.1.1", "8.8.8.8")), ("1.1.1.1", "8.8.8.8"))
        with self.assertRaises(ScopeDenied):
            validate_resolved_addresses(p, "www.example.org", ("1.1.1.1", "127.0.0.1"))
        with self.assertRaises(ScopeDenied):
            validate_resolved_addresses(p, "not-allowed.example.org", ("1.1.1.1",))
        with self.assertRaises(ScopeDenied):
            p.assert_public_target("127.0.0.1")

    def test_redirect_checks_are_explicit_and_budgeted(self):
        p = policy(targets=("www.example.org",), kinds=("dns_a",), max_redirects=1)
        self.assertEqual(validate_https_redirect(p, "https://www.example.org/path", ("1.1.1.1",), 1), "https://www.example.org/path")
        for url in [
            "http://www.example.org/path", "https://user:pass@www.example.org/",
            "https://www.example.org:8443/path", "https://127.0.0.1/",
            "https://unapproved.example.org/", "https://www.example.org/#frag",
        ]:
            with self.subTest(url=url), self.assertRaises(ScopeDenied):
                validate_https_redirect(p, url, ("1.1.1.1",), 1)
        with self.assertRaises(ScopeDenied):
            validate_https_redirect(p, "https://www.example.org/", ("1.1.1.1",), 2)
        with self.assertRaises(ScopeDenied):
            validate_https_redirect(policy(targets=("www.example.org",), kinds=("dns_a",)), "https://www.example.org/", ("1.1.1.1",), 1)

    def test_request_and_byte_budgets(self):
        p = policy(max_requests=2, max_requests_per_target=1, max_response_bytes=512, max_total_response_bytes=512)
        b = CollectionBudget(p)
        b.reserve("dns_a", DOMAIN)
        with self.assertRaises(ScopeDenied):
            b.reserve("dns_a", DOMAIN)
        b.account_bytes(400)
        with self.assertRaises(ScopeDenied):
            b.account_bytes(200)
        with self.assertRaises(ScopeDenied):
            b.account_bytes(600)

    def test_no_nonfixture_transport(self):
        class FakeLiveTransport:
            def exchange(self, request):
                raise AssertionError("must not execute")
        with self.assertRaises(TypeError):
            OfflineCollector(policy(), FakeLiveTransport())


class TestDNSParsing(unittest.TestCase):
    def test_complete_answer_and_evidence(self):
        event = get("dns_a", DOMAIN, dns(["192.0.2.8", "192.0.2.7"]))
        self.assertEqual(event.response_code, "ANSWER")
        self.assertEqual(event.observation.status, "ok")
        self.assertEqual(event.observation.values, ("192.0.2.7", "192.0.2.8"))
        self.assertEqual(event.observation.ttl_seconds, 90)
        self.assertTrue(event.event_id.startswith("event_"))
        self.assertNotEqual(event.event_id, event.observation.observation_id)

    def test_nxdomain_distinct_from_nodata(self):
        nxdomain = get("dns_a", DOMAIN, dns([], rcode="NXDOMAIN", negative_ttl=40))
        nodata = get("dns_a", DOMAIN, dns([], negative_proof="NODATA", negative_ttl=60))
        self.assertEqual((nxdomain.observation.status, nodata.observation.status), ("empty", "empty"))
        self.assertEqual((nxdomain.response_code, nodata.response_code), ("NXDOMAIN", "NODATA"))
        self.assertNotEqual(nxdomain.event_id, nodata.event_id)

    def test_errors_never_become_negative(self):
        scenarios = {
            "SERVFAIL": dns([], rcode="SERVFAIL"),
            "REFUSED": dns([], rcode="REFUSED"),
            "TIMEOUT": {"transport_error": "timeout"},
            "RATE_LIMITED": {"transport_error": "rate_limited"},
        }
        for code, fixture in scenarios.items():
            with self.subTest(outcome=code):
                event = get("dns_a", DOMAIN, fixture)
                self.assertEqual(event.response_code, code)
                self.assertEqual(event.observation.status, "error")
                self.assertEqual(event.observation.values, ())

    def test_noerror_without_negative_proof_is_not_nodata(self):
        event = get("dns_a", DOMAIN, dns([]))
        self.assertEqual(event.response_code, "INVALID_RESPONSE")
        self.assertEqual(event.observation.error_code, "invalid_response")

    def test_truncated_question_mismatch_and_wrong_rrtype(self):
        wrong_record = dns(["192.0.2.3"])
        wrong_record["answers"] = [{"type": "TXT", "value": "unexpected", "ttl": 30}]
        bad = [
            dns(["192.0.2.3"], truncated=True),
            dns(["192.0.2.3"], question="other.example.test"),
            dns(["192.0.2.3"], kind="AAAA"),
            dns(["192.0.2.3"], complete=False),
            wrong_record,
        ]
        for fixture in bad:
            with self.subTest(fixture=fixture):
                self.assertEqual(get("dns_a", DOMAIN, fixture).response_code, "INVALID_RESPONSE")

    def test_aaaa_and_ptr_without_real_resolution(self):
        aaaa = get("dns_aaaa", DOMAIN, dns(["2001:db8::12"], kind="AAAA"))
        self.assertEqual(aaaa.observation.values, ("2001:db8::12",))
        ptr = get("dns_ptr", DOC_IP, dns(["reverse.example.test"], kind="PTR", question=DOC_IP))
        self.assertEqual(ptr.observation.values, ("reverse.example.test",))

    def test_oversized_fixture_denied_before_parse(self):
        p = policy(max_response_bytes=256)
        with self.assertRaises(ScopeDenied):
            get("dns_a", DOMAIN, dns(["192.0.2.3"], extra="A" * 500), pol=p)


class TestRDAPParsing(unittest.TestCase):
    def test_network_with_verified_cidr(self):
        raw = {"protocol": "rdap", "http_status": 200, "body": {
            "objectClassName": "ip network", "ipVersion": "v4",
            "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
            "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        }}
        event = get("rdap_network", DOC_IP, raw)
        self.assertEqual(event.response_code, "HTTP_200")
        self.assertEqual(event.observation.values, ("203.0.113.0/24",))

    def test_rdap_range_without_extension(self):
        raw = {"protocol": "rdap", "http_status": 200, "body": {
            "objectClassName": "ip network",
            "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
        }}
        event = get("rdap_network", DOC_IP, raw)
        self.assertEqual(event.observation.values, ("203.0.113.0/24",))

    def test_inconsistent_or_malformed_rdap_is_error(self):
        bodies = [
            {"objectClassName": "domain", "cidr0_cidrs": []},
            {"objectClassName": "ip network", "startAddress": "192.0.2.1", "endAddress": "192.0.2.100"},
            {"objectClassName": "ip network", "ipVersion": "v6", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]},
            {"objectClassName": "ip network", "cidr0_cidrs": [{"v4prefix": "203.0.113.1", "length": 24}]},
            {"objectClassName": "ip network", "startAddress": "203.0.113.0", "endAddress": "203.0.113.50", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]},
        ]
        for body in bodies:
            with self.subTest(body=body):
                event = get("rdap_network", DOC_IP, {"protocol": "rdap", "http_status": 200, "body": body})
                self.assertEqual(event.response_code, "INVALID_RESPONSE")
                self.assertEqual(event.observation.status, "error")

    def test_http_error_not_benign(self):
        for status, outcome in [(404, "HTTP_404"), (429, "HTTP_429"), (500, "HTTP_5XX")]:
            with self.subTest(status=status):
                e = get("rdap_network", DOC_IP, {"protocol": "rdap", "http_status": status})
                self.assertEqual(e.response_code, outcome)
                self.assertEqual(e.observation.status, "error")

    def test_autnum_is_not_ip_attribution(self):
        response = {"protocol": "rdap", "http_status": 200, "body": {
            "objectClassName": "autnum", "startAutnum": 64500, "endAutnum": 64510,
        }}
        record = parse_autnum_fixture("AS64505", response)
        self.assertEqual(record["asn"], "AS64505")
        self.assertEqual(record["ip_association"], "not_established")
        with self.assertRaises(ValueError):
            parse_autnum_fixture("AS64515", response)

    def test_rdap_asn_not_automatically_linked_to_ip(self):
        p = policy(kinds=("rdap_asn",), targets=(DOC_IP,))
        with self.assertRaises(ScopeDenied):
            OfflineCollector(p, FixtureTransport({("rdap_asn", DOC_IP): {}})).collect("rdap_asn", DOC_IP, STAMP)


class TestLedgerAndCompatibility(unittest.TestCase):
    def test_append_idempotence_and_status_replay(self):
        nx = get("dns_a", DOMAIN, dns([], rcode="NXDOMAIN"))
        nd = get("dns_a", DOMAIN, dns([], negative_proof="NODATA"))
        with TemporaryDirectory() as tmp:
            ledger = CollectionLedger(Path(tmp) / "collection.sqlite")
            self.assertTrue(ledger.add(nx))
            self.assertFalse(ledger.add(nx))
            self.assertTrue(ledger.add(nd))
            result = ledger.by_subject(DOMAIN)
            self.assertEqual(len(result), 2)
            self.assertEqual({event.response_code for event in result}, {"NODATA", "NXDOMAIN"})

    def test_ledger_detects_tampering(self):
        event = get("dns_a", DOMAIN, dns(["192.0.2.1"]))
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "collection.sqlite"
            ledger = CollectionLedger(path)
            ledger.add(event)
            db = sqlite3.connect(path)
            try:
                with db:
                    db.execute("UPDATE collection_events SET event_id='event_tampered'")
            finally:
                db.close()
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                ledger.by_subject(DOMAIN)

    def test_prior_observation_contract_unchanged(self):
        baseline = demo_observations()[0]
        roundtrip = Observation.from_dict(baseline.to_dict())
        self.assertEqual(baseline.observation_id, roundtrip.observation_id)
        self.assertEqual(set(roundtrip.to_dict()), {
            "subject", "kind", "observed_at", "values", "status",
            "source_id", "method", "synthetic", "ttl_seconds", "error_code",
        })
