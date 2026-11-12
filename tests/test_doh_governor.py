"""Adversarial and security tests for Phase 2 DoH policy governor and persistent quotas."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import sqlite3
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from anie.collection_policy import ScopeDenied
from anie.doh_governor import (
    ALLOWED_QUERY_KINDS,
    ALLOWED_RESOLVER_ENDPOINTS,
    ALLOWED_TARGET_DOMAINS,
    DohRateGovernor,
    resolve_and_pin_endpoint,
    validate_batch_domains,
    validate_resolver_endpoint,
    validate_target,
)


class TestDohGovernorAdversarial(unittest.TestCase):
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

    def test_allowlist_denies_unauthorized_kinds(self):
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "dns_ptr")
        with self.assertRaises(ScopeDenied):
            validate_target("example.com", "dns_txt")

    def test_batch_domain_limit_enforced(self):
        # 1 or 2 domains allowed
        self.assertEqual(validate_batch_domains(["example.com", "iana.org"]), ["example.com", "iana.org"])
        self.assertEqual(validate_batch_domains(["example.com", "example.com"]), ["example.com"])

        # 3 domains exceed pilot batch limit
        with self.assertRaisesRegex(ScopeDenied, "maximum authorized domains"):
            validate_batch_domains(["example.com", "iana.org", "other.org"])

    def test_invalid_and_nonpositive_config_rejected(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "rate.sqlite"
            with self.assertRaises(ValueError):
                DohRateGovernor(p, max_target_per_hour=0)
            with self.assertRaises(ValueError):
                DohRateGovernor(p, max_target_per_hour=-1)
            with self.assertRaises(ValueError):
                DohRateGovernor(p, target_cooldown_seconds=0)
            with self.assertRaises(ValueError):
                DohRateGovernor(p, target_cooldown_seconds=-5.0)
            with self.assertRaises(ValueError):
                DohRateGovernor(p, max_resolver_per_hour=-10)
            with self.assertRaises(ValueError):
                DohRateGovernor(p, max_daily_total=0)

    def test_in_memory_disallowed_without_explicit_test_flag(self):
        with self.assertRaisesRegex(ValueError, "durable quota database required"):
            DohRateGovernor(None)
        with self.assertRaisesRegex(ValueError, "durable quota database required"):
            DohRateGovernor(":memory:")

    def test_persistent_quotas_after_process_restart(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "persistent_rate.sqlite"
            t0 = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

            # Process 1 creates governor, reserves 1 slot for example.com
            gov1 = DohRateGovernor(
                db_path,
                max_target_per_hour=1,
                target_cooldown_seconds=1800.0,
            )
            gov1.check_and_reserve("example.com", "cloudflare_doh", now_dt=t0)
            # Process 1 exits

            # Process 2 starts fresh with new governor instance pointing to same file
            gov2 = DohRateGovernor(
                db_path,
                max_target_per_hour=1,
                target_cooldown_seconds=1800.0,
            )
            # Must remember previous reservation and fail closed on quota exhaustion
            with self.assertRaisesRegex(ScopeDenied, "cooldown"):
                gov2.check_and_reserve("example.com", "cloudflare_doh", now_dt=t0 + timedelta(seconds=10))

    def test_concurrent_reservations_atomic_race_protection(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "race_rate.sqlite"
            # Exactly 1 slot available
            gov = DohRateGovernor(
                db_path,
                max_target_per_hour=1,
                target_cooldown_seconds=1800.0,
            )
            t0 = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)

            results = []
            errors = []

            def attempt_reserve(proc_id: int):
                proc_gov = DohRateGovernor(
                    db_path,
                    max_target_per_hour=1,
                    target_cooldown_seconds=1800.0,
                )
                try:
                    res = proc_gov.check_and_reserve("example.com", "cloudflare_doh", now_dt=t0)
                    results.append(proc_id)
                except ScopeDenied as exc:
                    errors.append((proc_id, str(exc)))

            # Two competing processes run at the exact same time
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                f1 = executor.submit(attempt_reserve, 1)
                f2 = executor.submit(attempt_reserve, 2)
                f1.result()
                f2.result()

            # Exactly one process succeeded, exactly one was rejected
            self.assertEqual(len(results), 1)
            self.assertEqual(len(errors), 1)

    def test_sqlite_lock_contention_fails_closed(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "locked_rate.sqlite"
            # Fast fail-closed under lock contention via short busy_timeout_ms
            gov = DohRateGovernor(db_path, target_cooldown_seconds=1800.0, busy_timeout_ms=50)

            # Manually hold an EXCLUSIVE lock from another connection
            locking_conn = sqlite3.connect(db_path)
            locking_conn.execute("BEGIN EXCLUSIVE")

            try:
                # Governor attempts to reserve with timeout; must fail closed with ScopeDenied
                with self.assertRaises(ScopeDenied):
                    gov.check_and_reserve("example.com", "cloudflare_doh")
            finally:
                locking_conn.execute("ROLLBACK")
                locking_conn.close()

    def test_quota_database_failure_fails_closed(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "rate.sqlite"
            # 1. Initialization failure fails closed
            with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("disk I/O error")):
                with self.assertRaises(ScopeDenied):
                    DohRateGovernor(db_path)

            # 2. Reservation-time failure fails closed
            gov = DohRateGovernor(db_path)
            with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("disk I/O error")):
                with self.assertRaises(ScopeDenied):
                    gov.check_and_reserve("example.com", "cloudflare_doh")

    def test_dns_resolution_delay_exhausts_deadline(self):
        # A resolver operation that sleeps 60s in an isolated child process
        hanging_cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
        t0 = time.monotonic()
        with self.assertRaises(TimeoutError):
            resolve_and_pin_endpoint(
                "cloudflare-dns.com",
                timeout=0.15,
                subproc_cmd=hanging_cmd,
            )
        elapsed = time.monotonic() - t0
        # Main execution path must return promptly within ~0.2-0.5s, NOT block for 60s
        self.assertLess(elapsed, 0.8)

    def test_repeated_dns_timeouts_do_not_leak_resources(self):
        hanging_cmd = [sys.executable, "-c", "import time; time.sleep(60)"]
        initial_threads = threading.active_count()
        for _ in range(5):
            with self.assertRaises(TimeoutError):
                resolve_and_pin_endpoint(
                    "cloudflare-dns.com",
                    timeout=0.08,
                    subproc_cmd=hanging_cmd,
                )
        # Verify zero background threads leaked
        self.assertEqual(threading.active_count(), initial_threads)

    def test_sqlite_lock_contention_bounded_deadline(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "locked_rate.sqlite"
            # Configured default busy timeout is 5000ms
            gov = DohRateGovernor(db_path, target_cooldown_seconds=1800.0, busy_timeout_ms=5000)

            locking_conn = sqlite3.connect(db_path)
            locking_conn.execute("BEGIN EXCLUSIVE")

            t0 = time.monotonic()
            try:
                # With deadline timeout=0.12s, lock acquisition must fail closed within ~0.3s, not wait 5.0s
                with self.assertRaises((ScopeDenied, TimeoutError)):
                    gov.check_and_reserve("example.com", "cloudflare_doh", timeout=0.12)
                elapsed = time.monotonic() - t0
                self.assertLess(elapsed, 0.6)
            finally:
                locking_conn.execute("ROLLBACK")
                locking_conn.close()


if __name__ == "__main__":
    unittest.main()
