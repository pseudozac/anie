"""Tests for Phase 2 DoH policy governor, allowlists, rate budgets, and anti-rebinding."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest

from anie.collection_policy import ScopeDenied
from anie.doh_governor import (
    ALLOWED_QUERY_KINDS,
    ALLOWED_RESOLVER_ENDPOINTS,
    ALLOWED_TARGET_DOMAINS,
    DohRateGovernor,
    resolve_and_pin_endpoint,
    validate_resolver_endpoint,
    validate_target,
)


class TestDohGovernor(unittest.TestCase):
    def test_allowlist_permits_authorized_targets(self):
        self.assertEqual(validate_target("example.com", "dns_a"), ("example.com", "dns_a"))
        self.assertEqual(validate_target("EXAMPLE.COM.", "dns_aaaa"), ("example.com", "dns_aaaa"))
        self.assertEqual(validate_target("iana.org", "dns_a"), ("iana.org", "dns_a"))
        self.assertEqual(validate_target("IANA.ORG", "dns_aaaa"), ("iana.org", "dns_aaaa"))

    def test_allowlist_denies_unauthorized_targets(self):
        with self.assertRaises(ScopeDenied):
            validate_target("google.com", "dns_a")
        with self.assertRaises(ScopeDenied):
            validate_target("sub.example.com", "dns_a")
        with self.assertRaises(ScopeDenied):
            validate_target("attacker.org", "dns_a")
        with self.assertRaises(ScopeDenied):
            validate_target("192.0.2.1", "dns_a")

    def test_allowlist_denies_unauthorized_kinds(self):
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "dns_ptr")
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "dns_txt")
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "dns_mx")
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "rdap_asn")

    def test_resolver_endpoint_validation(self):
        host, path = validate_resolver_endpoint("https://cloudflare-dns.com/dns-query")
        self.assertEqual(host, "cloudflare-dns.com")
        self.assertEqual(path, "/dns-query")

        # Insecure or unauthorized resolvers denied
        with self.assertRaises(ScopeDenied):
            validate_resolver_endpoint("http://cloudflare-dns.com/dns-query")
        with self.assertRaises(ScopeDenied):
            validate_resolver_endpoint("https://8.8.8.8/dns-query")
        with self.assertRaises(ScopeDenied):
            validate_resolver_endpoint("https://cloudflare-dns.com:8443/dns-query")
        with self.assertRaises(ScopeDenied):
            validate_resolver_endpoint("https://user:pass@cloudflare-dns.com/dns-query")

    def test_anti_rebinding_accepts_all_global_ips(self):
        def mock_getaddrinfo(host, port, type=socket.SOCK_STREAM):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.133.229", 443)),
            ]

        pinned_ip = resolve_and_pin_endpoint("cloudflare-dns.com", getaddrinfo_fn=mock_getaddrinfo)
        self.assertEqual(pinned_ip, "104.16.132.229")

    def test_anti_rebinding_rejects_private_and_loopback_ips(self):
        def mock_private(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        with self.assertRaisesRegex(ScopeDenied, "non-global address"):
            resolve_and_pin_endpoint("cloudflare-dns.com", getaddrinfo_fn=mock_private)

    def test_anti_rebinding_rejects_mixed_global_and_private_answers(self):
        # A DNS rebinding attack returning a public IP alongside a local IP must fail closed
        def mock_mixed(host, port, type=socket.SOCK_STREAM):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.16.132.229", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443)),
            ]

        with self.assertRaisesRegex(ScopeDenied, "non-global address"):
            resolve_and_pin_endpoint("cloudflare-dns.com", getaddrinfo_fn=mock_mixed)

    def test_anti_rebinding_rejects_documentation_ranges(self):
        def mock_doc(host, port, type=socket.SOCK_STREAM):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]

        with self.assertRaisesRegex(ScopeDenied, "non-global address"):
            resolve_and_pin_endpoint("cloudflare-dns.com", getaddrinfo_fn=mock_doc)

    def test_rate_governor_target_cooldown(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate.sqlite"
            gov = DohRateGovernor(db_path, target_cooldown_seconds=2.0)
            t0 = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

            # First reservation succeeds
            gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t0)

            # Second reservation 1 second later fails cooldown
            t1 = t0 + timedelta(seconds=1)
            with self.assertRaisesRegex(ScopeDenied, "cooldown"):
                gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t1)

            # Reservation for different domain succeeds immediately
            gov.check_and_reserve("iana.org", "cloudflare_doh", now_dt=t1)

            # Reservation after cooldown succeeds
            t2 = t0 + timedelta(seconds=3)
            gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t2)

    def test_rate_governor_hourly_target_budget(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate.sqlite"
            gov = DohRateGovernor(
                db_path,
                max_target_per_hour=3,
                target_cooldown_seconds=1.0,
            )
            base_t = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

            for i in range(3):
                t = base_t + timedelta(seconds=i * 5)
                gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t)

            # 4th reservation within the hour fails
            t_fail = base_t + timedelta(seconds=20)
            with self.assertRaisesRegex(ScopeDenied, "hourly budget"):
                gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t_fail)

            # Slices after 1 hour succeed again
            t_next_hour = base_t + timedelta(hours=1, seconds=10)
            gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t_next_hour)

    def test_rate_governor_resolver_and_daily_budget(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate.sqlite"
            gov = DohRateGovernor(
                db_path,
                max_target_per_hour=100,
                target_cooldown_seconds=0.0,
                max_resolver_per_hour=5,
                max_daily_total=8,
            )
            base_t = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

            for i in range(5):
                t = base_t + timedelta(seconds=i * 2)
                gov.check_and_reserve(f"target{i}.example.com", "cloudflare_doh", now_dt=t)

            # 6th query to same resolver in this hour fails
            t_fail = base_t + timedelta(seconds=12)
            with self.assertRaisesRegex(ScopeDenied, "resolver.*hourly budget"):
                gov.check_and_reserve("target6.example.com", "cloudflare_doh", now_dt=t_fail)


if __name__ == "__main__":
    unittest.main()
