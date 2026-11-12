"""Rigorous offline validation test suite for ANIE 72-Hour Pilot Execution Path.

Covers all 10 operational conditions required by Phase 2.1 Task 3:
1. First scheduled batch planning and execution (Day 1: A/AAAA)
2. Second-day query alternation (Day 2: AAAA/A)
3. Third scheduled batch (Day 3: A/AAAA)
4. Fourth invocation rejection (authorization ceiling exhausted)
5. Duplicate invocation on the same UTC calendar day (anti-duplication)
6. Crash after a reservation but before completion (stale reservation reconciliation)
7. Restart with an existing reservation on same calendar day (fail-closed, no duplicate queries)
8. Failure and partial collection handling (safe alternation retry on next day)
9. Missed scheduled execution (clean sequential progression without multi-batch catch-up)
10. Expired pilot authorization and observable completion sentinel verification
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

    def tearDown(self):
        self.tmp.cleanup()

    def _make_orchestrator(self, now_dt: datetime | None = None) -> BatchOrchestrator:
        cfg = BatchConfig(
            mode="dry_run",
            quota_db_path=self.quota_db,
            store_db_path=self.store_db,
            pilot_mode=True,
            pilot_sentinel_path=self.sentinel_file,
        )
        orch = BatchOrchestrator(cfg)
        return orch

    # Condition 1: First scheduled batch (Day 1: example.com dns_a, iana.org dns_aaaa)
    def test_01_first_scheduled_batch(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
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
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
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
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
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
        self.assertTrue(gov.is_pilot_completed())
        self.assertTrue(self.sentinel_file.exists())

    # Condition 4: Fourth invocation rejection
    def test_04_fourth_invocation_rejection(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        for day, date_str in [(1, "2026-11-13"), (2, "2026-11-14"), (3, "2026-11-15")]:
            dt = datetime.fromisoformat(f"{date_str}T06:00:00+00:00")
            r, _, _ = gov.check_and_plan_pilot_batch(now_dt=dt)
            gov.record_pilot_outcome(r, "SUCCESS", batch_id=f"batch_day{day}", now_dt=dt)

        d4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d4)
        self.assertIn("completed", str(ctx.exception).lower())

    # Condition 5: Duplicate invocation on the same UTC day
    def test_05_duplicate_invocation_same_utc_day(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
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
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, day_num, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Process crashes here: record_pilot_outcome is NOT called!

        # Next day, governor automatically reconciles the stale PLANNED record to FAILED
        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        r2, day_num2, _ = gov.check_and_plan_pilot_batch(now_dt=d2)

        # Crashed run did NOT increment completed_count, so Day 1 alternation is safely re-attempted
        self.assertEqual(day_num2, 1)
        summary = gov.get_pilot_summary()
        self.assertEqual(summary["runs"][0]["status"], "FAILED")
        self.assertIn("crashed or terminated", summary["runs"][0]["error_reason"])

    # Condition 7: Restart with an existing reservation on same calendar day
    def test_07_restart_with_existing_reservation_same_day(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Crash occurs on Day 1. Immediate restart attempt 5 minutes later on same day:
        d1_restart = datetime(2026, 11, 13, 6, 5, 0, tzinfo=timezone.utc)
        with self.assertRaises(ScopeDenied) as ctx:
            gov.check_and_plan_pilot_batch(now_dt=d1_restart)
        self.assertIn("interrupted", str(ctx.exception).lower())
        self.assertIn("prohibited", str(ctx.exception).lower())

    # Condition 8: Failure and partial collection handling
    def test_08_failure_and_partial_collection_handling(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        # Record partial failure outcome
        gov.record_pilot_outcome(r1, "PARTIAL", batch_id="batch_partial", error_reason="query timeout on iana.org", now_dt=d1)

        # Completed count is still 0
        self.assertEqual(gov.get_completed_runs_count(), 0)

        # Same day retry is blocked
        with self.assertRaises(ScopeDenied):
            gov.check_and_plan_pilot_batch(now_dt=datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc))

        # Next day safely re-attempts day 1
        d2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
        r2, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d2)
        self.assertEqual(day_num, 1)

    # Condition 9: Missed scheduled execution
    def test_09_missed_scheduled_execution(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        d1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
        r1, _, _ = gov.check_and_plan_pilot_batch(now_dt=d1)
        gov.record_pilot_outcome(r1, "SUCCESS", batch_id="batch_day1", now_dt=d1)

        # Host is powered off on 2026-11-14 (Day 2 missed entirely)
        # Power restored on 2026-11-15 (Day 3)
        d3 = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
        r2, day_num, queries = gov.check_and_plan_pilot_batch(now_dt=d3)

        # Executes Run 2 alternation cleanly; no double-batch burst!
        self.assertEqual(day_num, 2)
        self.assertEqual(queries, [("example.com", "dns_aaaa"), ("iana.org", "dns_a")])

    # Condition 10: Expired pilot authorization and sentinel halting
    def test_10_expired_pilot_authorization_and_sentinel(self):
        gov = PilotGovernor(self.quota_db, sentinel_path=self.sentinel_file)
        for day, date_str in [(1, "2026-11-13"), (2, "2026-11-14"), (3, "2026-11-15")]:
            dt = datetime.fromisoformat(f"{date_str}T06:00:00+00:00")
            r, _, _ = gov.check_and_plan_pilot_batch(now_dt=dt)
            gov.record_pilot_outcome(r, "SUCCESS", batch_id=f"batch_day{day}", now_dt=dt)

        self.assertTrue(self.sentinel_file.exists())
        sentinel_data = json.loads(self.sentinel_file.read_text(encoding="utf-8"))
        self.assertEqual(sentinel_data["status"], "72_HOUR_PILOT_COMPLETED")
        self.assertEqual(sentinel_data["total_runs_completed"], 3)
        self.assertEqual(len(sentinel_data["runs"]), 3)

        # Test CLI orchestrator integration with sentinel present
        orch = self._make_orchestrator()
        report = orch.execute_batch()
        self.assertIn(report.outcome, ("FAILED", "SKIPPED"))
        self.assertIn("sentinel", report.reason)


if __name__ == "__main__":
    unittest.main()
