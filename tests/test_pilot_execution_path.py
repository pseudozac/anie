"""Rigorous offline validation test suite for ANIE 72-Hour Fixed Window Pilot Execution Path.

Covers all operational and safety conditions required by Phase 2.1:
1. First scheduled batch planning and execution (Day 1: A/AAAA)
2. Second-day query alternation (Day 2: AAAA/A)
3. Third scheduled batch (Day 3: A/AAAA)
4. Fourth calendar date rejection (authorization expired, NOT extended to fourth date)
5. Duplicate invocation on the same UTC calendar day rejected (max 1 batch attempt per day)
6. Crash after a reservation but before completion (stale reservation marked FAILED)
7. Restart with an existing reservation on same calendar day rejected (fail closed)
8. Failed batch on Day 1 does NOT extend authorization to fourth date
9. Missed Day 2 remains missed; Day 3 executes Day 3 alternation cleanly without catch-up
10. Expired pilot authorization creates completion sentinel; service condition blocks collection
11. Invocation before authorization window start date is rejected
12. Pilot summary accurately distinguishes completed batches, failed attempts, and missed days
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.collection_policy import ScopeDenied
from anie.orchestrator import BatchConfig, BatchOrchestrator
from anie.pilot_governor import PilotGovernor


class TestPilotExecutionPath(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.quota_db = self.tmp_path / "doh_quota.sqlite"
        self.store_db = self.tmp_path / "real_intelligence.sqlite"
        self.sentinel_file = self.tmp_path / "pilot_completed.sentinel"
        self.start_date = "2026-11-13"

    def tearDown(self):
        self.tmp.cleanup()

    def _make_orchestrator(self, start_date: str = "2026-11-13") -> BatchOrchestrator:
        cfg = BatchConfig(
            mode="dry_run",
            quota_db_path=self.quota_db,
            store_db_path=self.store_db,
            pilot_mode=True,
            pilot_sentinel_path=self.sentinel_file,
            pilot_start_date=start_date,
        )
        return BatchOrchestrator(cfg)

    # Condition 1: First scheduled batch (Day 1: example.com dns_a, iana.org dns_aaaa)
    def test_01_first_scheduled_batch(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        run_id, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d1)

        self.assertEqual(day_num, 1)
        self.assertEqual(queries, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])

        # Complete batch successfully
        gov.record_pilot_outcome(run_id, "SUCCESS", batch_id="batch_day1", now_dt=d1)
        self.assertEqual(gov.get_completed_runs_count(), 1)
        self.assertFalse(self.sentinel_file.exists())

    # Condition 2: Second-day query alternation (Day 2: example.com dns_aaaa, iana.org dns_a)
    def test_02_second_day_query_alternation(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        gov.record_pilot_outcome(r1, "SUCCESS", batch_id="batch_day1", now_dt=d1)

        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        run_id, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d2)

        self.assertEqual(day_num, 2)
        self.assertEqual(queries, [("example.com", "dns_aaaa"), ("iana.org", "dns_a")])
        gov.record_pilot_outcome(run_id, "SUCCESS", batch_id="batch_day2", now_dt=d2)
        self.assertEqual(gov.get_completed_runs_count(), 2)

    # Condition 3: Third scheduled batch (Day 3: example.com dns_a, iana.org dns_aaaa)
    def test_03_third_scheduled_batch(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        for day, date_str in [(1, "2026-11-13"), (2, "2026-11-14")]:
            dt = datetime.fromisoformat(f"{date_str}T06:00:00+00:00")
            r, _, _ = gov.check_and_plan_pilot_batch(now_dt=dt)
            gov.record_pilot_outcome(r, "SUCCESS", batch_id=f"batch_day{day}", now_dt=dt)

        d3 = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
        run_id, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d3)
        self.assertEqual(day_num, 3)
        self.assertEqual(queries, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])

        gov.record_pilot_outcome(run_id, "SUCCESS", batch_id="batch_day3", now_dt=d3)
        self.assertEqual(gov.get_completed_runs_count(), 3)
        self.assertTrue(gov.is_pilot_completed(d3))
        self.assertTrue(self.sentinel_file.exists())

    # Condition 4: Fourth calendar date rejection (authorization window expired)
    def test_04_fourth_date_rejection_window_expired(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        for day, date_str in [(1, "2026-11-13"), (2, "2026-11-14"), (3, "2026-11-15")]:
            dt = datetime.fromisoformat(f"{date_str}T06:00:00+00:00")
            r, _, _ = gov.check_and_plan_pilot_batch(now_dt=dt)
            gov.record_pilot_outcome(r, "SUCCESS", batch_id=f"batch_day{day}", now_dt=dt)

        d4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d4)
        self.assertIn("expired", str(ctx.exception).lower())

    # Condition 5: Duplicate invocation on the same UTC day
    def test_05_duplicate_invocation_same_utc_day(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1_morning = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1_morning)
        gov.record_pilot_outcome(r1, "SUCCESS", batch_id="batch_day1", now_dt=d1_morning)

        # Duplicate attempt 4 hours later on the same date
        d1_afternoon = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d1_afternoon)
        self.assertIn("already executed or attempted", str(ctx.exception))

    # Condition 6: Crash after a reservation but before completion
    def test_06_crash_after_reservation_before_completion(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, day_num, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Process crashes: record_pilot_outcome is NOT called

        # Next day: governor reconciles stale reservation to FAILED
        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        r2, day_num2, queries = gov.check_and_plan_pilot_batch(now_dt=d2)

        # Day 2 executes Day 2 queries (AAAA/A)
        self.assertEqual(day_num2, 2)
        self.assertEqual(queries, [("example.com", "dns_aaaa"), ("iana.org", "dns_a")])
        summary = gov.get_pilot_summary(d2)
        self.assertEqual(summary["failed_attempts"], 1)

    # Condition 7: Restart with an existing reservation on same calendar day rejected
    def test_07_restart_with_existing_reservation_same_day(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Crash occurs on Day 1. Immediate restart attempt 5 minutes later on same day:
        d1_restart = datetime(2026, 11, 13, 6, 5, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d1_restart)
        self.assertIn("interrupted", str(ctx.exception).lower())
        self.assertIn("prohibited", str(ctx.exception).lower())

    # Condition 8: Failed batch on Day 1 does NOT extend authorization to fourth date
    def test_08_failed_batch_does_not_extend_authorization(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Day 1 fails
        gov.record_pilot_outcome(r1, "FAILED", batch_id="batch_d1", error_reason="connection timeout", now_dt=d1)

        # Day 2 succeeds
        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        r2, day_num2, _ = gov.check_and_plan_pilot_batch(now_dt=d2)
        self.assertEqual(day_num2, 2)
        gov.record_pilot_outcome(r2, "SUCCESS", batch_id="batch_d2", now_dt=d2)

        # Day 3 succeeds
        d3 = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
        r3, day_num3, _ = gov.check_and_plan_pilot_batch(now_dt=d3)
        self.assertEqual(day_num3, 3)
        gov.record_pilot_outcome(r3, "SUCCESS", batch_id="batch_d3", now_dt=d3)

        # Day 4: Must fail closed! Even though only 2 batches succeeded, Day 4 is outside the 3-day window
        d4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d4)
        self.assertIn("expired", str(ctx.exception).lower())

    # Condition 9: Missed Day 2 remains missed; Day 3 executes Day 3 alternation cleanly
    def test_09_missed_day_remains_missed(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        gov.record_pilot_outcome(r1, "SUCCESS", batch_id="batch_day1", now_dt=d1)

        # Day 2 (2026-11-14) is completely MISSED (node offline)
        # Power restored on Day 3 (2026-11-15)
        d3 = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
        r3, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d3)

        # Day 3 executes Day 3 queries (A/AAAA) directly
        self.assertEqual(day_num, 3)
        self.assertEqual(queries, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])
        gov.record_pilot_outcome(r3, "SUCCESS", batch_id="batch_day3", now_dt=d3)

        # Verify summary distinguishes completed and missed
        summary = gov.get_pilot_summary(d3)
        self.assertEqual(summary["completed_batches"], 2)
        self.assertEqual(summary["missed_days"], 1)

        # Day 4 must be expired
        d4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied):
            gov.check_and_plan_pilot_batch(now_dt=d4)

    # Condition 10: Expired pilot authorization and sentinel halting
    def test_10_expired_pilot_authorization_and_sentinel(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        for day, date_str in [(1, "2026-11-13"), (2, "2026-11-14"), (3, "2026-11-15")]:
            dt = datetime.fromisoformat(f"{date_str}T06:00:00+00:00")
            r, _, _ = gov.check_and_plan_pilot_batch(now_dt=dt)
            gov.record_pilot_outcome(r, "SUCCESS", batch_id=f"batch_day{day}", now_dt=dt)

        self.assertTrue(self.sentinel_file.exists())
        sentinel_data = json.loads(self.sentinel_file.read_text(encoding="utf-8"))
        self.assertEqual(sentinel_data["status"], "72_HOUR_PILOT_COMPLETED")
        self.assertEqual(sentinel_data["completed_batches"], 3)
        self.assertEqual(sentinel_data["failed_attempts"], 0)
        self.assertEqual(sentinel_data["missed_days"], 0)

        # Orchestrator fails closed on Day 4
        orch = self._make_orchestrator(start_date=self.start_date)
        report = orch.execute_batch()
        self.assertIn(report.outcome, ("FAILED", "SKIPPED"))
        self.assertIn("sentinel", report.reason)

    # Condition 11: Invocation before window start date is rejected
    def test_11_invocation_before_window_start_rejected(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date="2026-11-14")
        d_early = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d_early)
        self.assertIn("not yet begun", str(ctx.exception).lower())

    # Condition 12: Pilot summary accurately distinguishes completed, failed, and missed
    def test_12_pilot_summary_reporting(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file, pilot_start_date=self.start_date)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        gov.record_pilot_outcome(r1, "SUCCESS", batch_id="b1", now_dt=d1)

        # Day 2 fails
        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        r2, _, _ = gov.check_and_plan_pilot_batch(now_dt=d2)
        gov.record_pilot_outcome(r2, "FAILED", batch_id="b2", error_reason="mock error", now_dt=d2)

        summary = gov.get_pilot_summary(d2)
        self.assertEqual(summary["completed_batches"], 1)
        self.assertEqual(summary["failed_attempts"], 1)
        self.assertEqual(summary["missed_days"], 0)
        self.assertEqual(len(summary["runs"]), 2)


if __name__ == "__main__":
    unittest.main()
