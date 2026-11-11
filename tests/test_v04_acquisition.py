"""ANIE v0.4 offline bootstrap and cache scheduling regression tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.rdap_bootstrap import OfflineRdapBootstrap
from anie.offline_scheduler import OfflineCollectionScheduler, OfflineCacheConfig
from anie.collection_pipeline import FixtureTransport, OfflineCollector
from anie.collection_policy import CollectionPolicy, ScopeDenied
from anie.collection_ledger import CollectionLedger

D = "telemetry.example.test"
IP = "203.0.113.17"
START = "2026-11-11T10:00:00Z"


def ts(offset):
    base = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset)).isoformat(timespec="seconds").replace("+00:00", "Z")


def dns(values=None, *, rcode="NOERROR", negttl=None, nodata=False, ttl=30):
    answers = [{"type": "A", "value": value, "ttl": ttl} for value in (values if values is not None else ["192.0.2.10"])]
    data = {
        "protocol": "dns", "qtype": "A", "question": D,
        "rcode": rcode, "answers": answers, "complete": True, "truncated": False,
    }
    if negttl is not None:
        data["negative_ttl"] = negttl
    if nodata:
        data["negative_proof"] = "NODATA"
    return data


def build_fixture(raw, *, kind="dns_a", subject=D, ledger=None, config=None, policy=None):
    policy = policy or CollectionPolicy(
        targets=frozenset({subject}), kinds=frozenset({kind}),
        max_requests=100, max_requests_per_target=100,
    )
    transport = FixtureTransport({(kind, subject): raw})
    return OfflineCollectionScheduler(
        OfflineCollector(policy, transport), ledger=ledger, config=config
    )


class TestOfflineBootstrap(unittest.TestCase):
    def registry(self, routes=None):
        return {
            "version": "1.0", "publication": "2026-11-01T00:00:00Z",
            "services": routes or [
                [["203.0.0.0/16"], ["https://registry.example.org/rdap/"]],
                [["203.0.113.0/24"], ["https://more-specific.example.org/rdap/"]],
            ],
        }

    def test_ipv4_longest_prefix_and_source(self):
        routes = OfflineRdapBootstrap(self.registry(), family=4)
        chosen = routes.select(IP)
        self.assertEqual(chosen.matched_prefix, "203.0.113.0/24")
        self.assertEqual(chosen.base_urls, ("https://more-specific.example.org/rdap/",))
        self.assertEqual(chosen.origin, "synthetic:rdap-bootstrap")
        self.assertEqual(routes.route_count, 2)

    def test_unmatched_fails_closed_without_fallback(self):
        routes = OfflineRdapBootstrap(self.registry(), family=4)
        self.assertIsNone(routes.select("192.0.2.1"))
        with self.assertRaises(ValueError):
            routes.select("2001:db8::1")

    def test_ipv6_longest_prefix(self):
        obj = self.registry([
            [["2001:db8::/32"], ["https://rdap.example.org/"]],
            [["2001:db8:4::/48"], ["https://rdap-specific.example.org/"]],
        ])
        chosen = OfflineRdapBootstrap(obj, family=6).select("2001:db8:4::1")
        self.assertEqual(chosen.matched_prefix, "2001:db8:4::/48")

    def test_incomplete_or_unsupported_schema_rejected(self):
        for obj in [None, [], {}, {"version": "9", "publication": START, "services": []},
                    {"version": "1.0", "publication": "nonsense", "services": []}]:
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                OfflineRdapBootstrap(obj, family=4)

    def test_duplicate_prefix_rejected(self):
        obj = self.registry([
            [["203.0.113.0/24"], ["https://one.example.org/"]],
            [["203.0.113.0/24"], ["https://two.example.org/"]],
        ])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            OfflineRdapBootstrap(obj, family=4)

    def test_noncanonical_network_rejected(self):
        obj = self.registry([[["203.0.113.5/24"], ["https://rdap.example.org/"]]])
        with self.assertRaisesRegex(ValueError, "CIDR"):
            OfflineRdapBootstrap(obj, family=4)

    def test_block_untrusted_url_forms(self):
        invalid = [
            "http://registry.example.org/", "https://127.0.0.1/", "https://127.1/",
            "https://127.000.000.001/", "https://metadata.local/",
            "https://registry.example.test/",
            "https://user:password@registry.example.org/",
            "https://registry.example.org:8443/",
            "https://registry.example.org/#fragment",
            "https://registry.example.org/?key=secret",
            "https://registry.example.org\\@other.example.org/",
            "https://registry.example.org%2f.attacker.com/",
            "https://registry.example.org/a b",
        ]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ValueError):
                OfflineRdapBootstrap(self.registry([[["203.0.113.0/24"], [url]]]), family=4)

    def test_reject_family_mix_and_scoped_ipv6(self):
        obj = self.registry([[["2001:db8::/32"], ["https://rdap.example.org/"]]])
        with self.assertRaises(ValueError):
            OfflineRdapBootstrap(obj, family=4)
        routes = OfflineRdapBootstrap(obj, family=6)
        with self.assertRaises(ValueError):
            routes.select("fe80::1%eth0")

    def test_refuse_oversize_and_invalid_services(self):
        obj = self.registry()
        obj["description"] = "x" * 520_000
        with self.assertRaisesRegex(ValueError, "byte budget"):
            OfflineRdapBootstrap(obj, family=4)
        obj = self.registry([[["203.0.113.0/24"], []]])
        with self.assertRaises(ValueError):
            OfflineRdapBootstrap(obj, family=4)


class TestOfflineCache(unittest.TestCase):
    def test_cache_hit_preserves_first_observation_timestamp_and_id(self):
        s = build_fixture(dns())
        first = s.query("dns_a", D, now=ts(0))
        second = s.query("dns_a", D, now=ts(15))
        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(second.event.event_id, first.event.event_id)
        self.assertEqual(second.event.observation.observed_at, ts(0))
        self.assertEqual(s.metrics()["fixture_exchanges"], 1)
        self.assertEqual(s.metrics()["cache_hits"], 1)

    def test_ttl_expiration_causes_new_observation(self):
        s = build_fixture(dns(ttl=30))
        s.query("dns_a", D, now=ts(0))
        q = s.query("dns_a", D, now=ts(30))
        self.assertFalse(q.from_cache)
        self.assertEqual(q.event.request.observed_at, ts(30))
        self.assertEqual(s.metrics()["fixture_exchanges"], 2)

    def test_nxdomain_negative_cache_and_nodata_are_not_errors(self):
        for raw, code in [(dns([], rcode="NXDOMAIN", negttl=20), "NXDOMAIN"),
                          (dns([], nodata=True, negttl=20), "NODATA")]:
            with self.subTest(code=code):
                s = build_fixture(raw)
                first = s.query("dns_a", D, now=ts(0))
                second = s.query("dns_a", D, now=ts(10))
                self.assertEqual(first.event.response_code, code)
                self.assertEqual(first.event.observation.status, "empty")
                self.assertTrue(second.from_cache)
                self.assertEqual(second.cache_lifetime_seconds, 20)

    def test_negative_without_provided_ttl_not_cached(self):
        s = build_fixture(dns([], rcode="NXDOMAIN"))
        self.assertEqual(s.query("dns_a", D, now=ts(0)).cache_lifetime_seconds, 0)
        self.assertFalse(s.query("dns_a", D, now=ts(1)).from_cache)

    def test_timeout_cooldown_not_benign(self):
        s = build_fixture({"transport_error": "timeout"})
        first = s.query("dns_a", D, now=ts(0))
        again = s.query("dns_a", D, now=ts(2))
        self.assertTrue(again.from_cache)
        self.assertEqual(again.event.observation.status, "error")
        self.assertEqual(first.event.response_code, "TIMEOUT")
        self.assertFalse(s.query("dns_a", D, now=ts(5)).from_cache)

    def test_rate_limit_longer_cooldown(self):
        s = build_fixture({"transport_error": "rate_limited"})
        a = s.query("dns_a", D, now=ts(0))
        self.assertEqual(a.cache_lifetime_seconds, 60)
        self.assertTrue(s.query("dns_a", D, now=ts(59)).from_cache)
        self.assertFalse(s.query("dns_a", D, now=ts(60)).from_cache)

    def test_rdap_local_refresh_not_attributed_to_source(self):
        raw = {"protocol": "rdap", "http_status": 200, "body": {
            "objectClassName": "ip network",
            "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
        }}
        config = OfflineCacheConfig(rdap_refresh_seconds=90)
        s = build_fixture(raw, kind="rdap_network", subject=IP, config=config)
        first = s.query("rdap_network", IP, now=ts(0))
        self.assertEqual(first.cache_lifetime_seconds, 90)
        self.assertTrue(s.query("rdap_network", IP, now=ts(89)).from_cache)
        self.assertFalse(s.query("rdap_network", IP, now=ts(90)).from_cache)

    def test_rate_window_blocks_fresh_queries_only(self):
        config = OfflineCacheConfig(max_requests_per_window=1, window_seconds=60)
        s = build_fixture(dns(ttl=5), config=config)
        s.query("dns_a", D, now=ts(0))
        self.assertTrue(s.query("dns_a", D, now=ts(2)).from_cache)
        with self.assertRaisesRegex(ScopeDenied, "rate window"):
            s.query("dns_a", D, now=ts(5))
        self.assertFalse(s.query("dns_a", D, now=ts(60)).from_cache)

    def test_byte_and_total_budget_still_applies(self):
        p = CollectionPolicy(targets=frozenset({D}), kinds=frozenset({"dns_a"}),
                             max_requests=1, max_requests_per_target=1)
        s = build_fixture(dns(ttl=5), policy=p)
        s.query("dns_a", D, now=ts(0))
        with self.assertRaisesRegex(ScopeDenied, "budget"):
            s.query("dns_a", D, now=ts(5))

    def test_allowlist_rechecked_even_when_cache_is_hot(self):
        s = build_fixture(dns())
        s.query("dns_a", D, now=ts(0))
        with self.assertRaises(ScopeDenied):
            s.query("dns_a", "not-allowlisted.example.test", now=ts(1))

    def test_time_cannot_go_backwards(self):
        s = build_fixture(dns())
        s.query("dns_a", D, now=ts(30))
        with self.assertRaisesRegex(ValueError, "backwards"):
            s.query("dns_a", D, now=ts(29))

    def test_cache_capacity_and_conservative_eviction(self):
        config = OfflineCacheConfig(max_entries=1)
        p = CollectionPolicy(targets=frozenset({D, "other.example.test"}), kinds=frozenset({"dns_a"}),
                             max_requests=10, max_requests_per_target=10)
        fixtures = {
            ("dns_a", D): dns(ttl=60),
            ("dns_a", "other.example.test"): {**dns(ttl=60), "question": "other.example.test"},
        }
        s = OfflineCollectionScheduler(OfflineCollector(p, FixtureTransport(fixtures)), config=config)
        s.query("dns_a", D, now=ts(0))
        s.query("dns_a", "other.example.test", now=ts(1))
        self.assertEqual(s.cache_entries, 1)
        self.assertFalse(s.query("dns_a", D, now=ts(2)).from_cache)

    def test_ledger_persists_only_real_fixture_exchanges(self):
        with TemporaryDirectory() as root:
            db = CollectionLedger(Path(root) / "events.sqlite")
            s = build_fixture(dns(ttl=15), ledger=db)
            s.query("dns_a", D, now=ts(0))
            s.query("dns_a", D, now=ts(10))
            s.query("dns_a", D, now=ts(15))
            self.assertEqual(len(db.by_subject(D)), 2)
            # New process doesn't claim to have the old process's cache state.
            restarted = build_fixture(dns(ttl=15), ledger=db)
            self.assertFalse(restarted.query("dns_a", D, now=ts(20)).from_cache)
            self.assertEqual(len(db.by_subject(D)), 3)

    def test_reject_invalid_config(self):
        for params in [
            {"error_cooldown_seconds": 0}, {"error_cooldown_seconds": 301},
            {"max_entries": True}, {"window_seconds": -1},
            {"max_requests_per_window": 0},
        ]:
            with self.subTest(params=params), self.assertRaises(ValueError):
                OfflineCacheConfig(**params)
