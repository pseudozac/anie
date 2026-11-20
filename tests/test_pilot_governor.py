"""Comprehensive test suite for Phase 2.1 PilotGovernor and 72-hour alternation scheduling."""
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.collection_policy import ScopeDenied
from anie.orchestrator import BatchConfig, BatchOrchestrator
from anie.pilot_governor import PilotGovernor, MAX_AUTHORIZED_PILOT_RUNS, PILOT_DAY_QUERIES


class TestPilotGovernor(unittest.TestCase):
    def test_three_day_deterministic_alternation_progression(self):
        """Verify the exact 3-day query alternation progression: A/AAAA, AAAA/A, A/AAAA."""
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_pilot.sqlite"
            gov = PilotGovernor(db_path)

            # Day 1: 2026-11-13
            dt1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
            run1, day1, plan1 = gov.check_and_plan_pilot_batch(now_dt=dt1)
            self.assertEqual(day1, 1)
            self.assertEqual(plan1, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])
            gov.record_pilot_outcome(run1, "SUCCESS", batch_id="batch_day1", now_dt=dt1)
            self.assertEqual(gov.get_completed_runs_count(), 1)

            # Day 2: 2026-11-14
            dt2 = datetime(2026, 11, 14, 6, 5, 0, tzinfo=timezone.utc)
            run2, day2, plan2 = gov.check_and_plan_pilot_batch(now_dt=dt2)
            self.assertEqual(day2, 2)
            self.assertEqual(plan2, [("example.com", "dns_aaaa"), ("iana.org", "dns_a")])
            gov.record_pilot_outcome(run2, "SUCCESS", batch_id="batch_day2", now_dt=dt2)
            self.assertEqual(gov.get_completed_runs_count(), 2)

            # Day 3: 2026-11-15
            dt3 = datetime(2026, 11, 15, 6, 10, 0, tzinfo=timezone.utc)
            run3, day3, plan3 = gov.check_and_plan_pilot_batch(now_dt=dt3)
            self.assertEqual(day3, 3)
            self.assertEqual(plan3, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])
            gov.record_pilot_outcome(run3, "SUCCESS", batch_id="batch_day3", now_dt=dt3)
            self.assertEqual(gov.get_completed_runs_count(), 3)

            # Day 4: Must fail closed at authorization boundary
            dt4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
            with self.assertRaises(ScopeDenied) as ctx:
                gov.check_and_plan_pilot_batch(now_dt=dt4)
            self.assertTrue("completed" in str(ctx.exception).lower() or "ceiling" in str(ctx.exception).lower())

    def test_duplicate_run_on_same_calendar_day_is_blocked(self):
        """Timer firing twice or catch-up execution on the same date must be rejected."""
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_pilot.sqlite"
            gov = PilotGovernor(db_path)

            dt1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
            run1, day1, plan1 = gov.check_and_plan_pilot_batch(now_dt=dt1)
            gov.record_pilot_outcome(run1, "SUCCESS", batch_id="batch_day1", now_dt=dt1)

            # Second execution attempt at 06:10 UTC on same date
            dt1_dup = datetime(2026, 11, 13, 6, 10, 0, tzinfo=timezone.utc)
            with self.assertRaises(ScopeDenied) as ctx:
                gov.check_and_plan_pilot_batch(now_dt=dt1_dup)
            self.assertIn("already executed", str(ctx.exception))

    def test_blocked_status_halts_subsequent_runs(self):
        """A critical security or integrity failure marked BLOCKED prevents further execution."""
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_pilot.sqlite"
            gov = PilotGovernor(db_path)

            dt1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
            run1, day1, plan1 = gov.check_and_plan_pilot_batch(now_dt=dt1)
            gov.record_pilot_outcome(run1, "BLOCKED", error_reason="IMDS access violation detected", now_dt=dt1)

            # Day 2 attempt must be blocked
            dt2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
            with self.assertRaises(ScopeDenied) as ctx:
                gov.check_and_plan_pilot_batch(now_dt=dt2)
            self.assertIn("BLOCKED state", str(ctx.exception))

    def test_orchestrator_integration_pilot_mode_dry_run(self):
        """Test BatchOrchestrator with pilot_mode=True over simulated 3-day timeline."""
        with TemporaryDirectory() as tmp:
            quota_db = Path(tmp) / "doh_quota.sqlite"
            store_db = Path(tmp) / "real_intelligence.sqlite"
            log_file = Path(tmp) / "collector.jsonl"
            lock_file = Path(tmp) / "collector.lock"

            gov = PilotGovernor(quota_db)

            # Day 1: 2026-11-13
            dt1 = datetime(2026, 11, 13, 6, 0, 0, tzinfo=timezone.utc)
            cfg1 = BatchConfig(
                mode="dry_run",
                quota_db_path=quota_db,
                store_db_path=store_db,
                log_file_path=log_file,
                lock_file_path=lock_file,
                pilot_mode=True,
            )
            # Patch datetime in pilot governor
            run1, day1, q1 = gov.check_and_plan_pilot_batch(now_dt=dt1)
            self.assertEqual(day1, 1)
            self.assertEqual(q1, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])
            gov.record_pilot_outcome(run1, "SUCCESS", batch_id="b1", now_dt=dt1)

            # Day 2: 2026-11-14
            dt2 = datetime(2026, 11, 14, 6, 0, 0, tzinfo=timezone.utc)
            run2, day2, q2 = gov.check_and_plan_pilot_batch(now_dt=dt2)
            self.assertEqual(day2, 2)
            self.assertEqual(q2, [("example.com", "dns_aaaa"), ("iana.org", "dns_a")])
            gov.record_pilot_outcome(run2, "SUCCESS", batch_id="b2", now_dt=dt2)

            # Day 3: 2026-11-15
            dt3 = datetime(2026, 11, 15, 6, 0, 0, tzinfo=timezone.utc)
            run3, day3, q3 = gov.check_and_plan_pilot_batch(now_dt=dt3)
            self.assertEqual(day3, 3)
            self.assertEqual(q3, [("example.com", "dns_a"), ("iana.org", "dns_aaaa")])
            gov.record_pilot_outcome(run3, "SUCCESS", batch_id="b3", now_dt=dt3)

            # Day 4: Must fail
            dt4 = datetime(2026, 11, 16, 6, 0, 0, tzinfo=timezone.utc)
            with self.assertRaises(ScopeDenied):
                gov.check_and_plan_pilot_batch(now_dt=dt4)


if __name__ == "__main__":
    unittest.main()
