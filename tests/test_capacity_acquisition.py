"""Tests for Oracle Ampere A1 Capacity Acquisition and Bounded Retry Engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from anie.capacity_retry import (
    CapacityAcquisitionConfig,
    CapacityAcquisitionManager,
    CrossPlatformLock,
    OUTCOME_API_ERROR,
    OUTCOME_OUT_OF_CAPACITY,
    OUTCOME_SUCCESS,
    OUTCOME_THROTTLED,
    STATE_ACQUIRED,
    STATE_EXPIRED,
    STATE_PENDING,
    STATE_RETRYING,
    STATE_THROTTLED,
)


class TestCapacityAcquisition(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.state_dir = Path(self.tmp_dir.name) / "capacity_test"
        self.base_time = datetime(2026, 11, 21, 6, 0, 0, tzinfo=timezone.utc)
        self.config = CapacityAcquisitionConfig(
            min_interval_seconds=3600,
            max_duration_seconds=7 * 86400,
            initial_backoff_seconds=3600,
            max_backoff_seconds=28800,
            backoff_multiplier=2.0,
        )
        self.mgr = CapacityAcquisitionManager(
            self.state_dir,
            config=self.config,
            now=self.base_time,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_initial_state_is_pending_and_eligible(self):
        summary = self.mgr.get_summary(self.base_time)
        self.assertEqual(summary["status"], STATE_PENDING)
        self.assertTrue(summary["schedule"]["is_currently_eligible"])
        self.assertEqual(summary["metrics"]["total_attempts"], 0)

    def test_minimum_60_minute_interval(self):
        # Initial attempt at T
        eligible, _ = self.mgr.check_eligibility(self.base_time)
        self.assertTrue(eligible)

        # Record out-of-capacity attempt
        self.mgr.record_attempt(
            OUTCOME_OUT_OF_CAPACITY,
            error_message="Out of host capacity.",
            now=self.base_time,
        )

        # At T + 30 minutes (1800s): must be INELIGIBLE (strictly <= 60 min rate-limited)
        t_30m = self.base_time + timedelta(minutes=30)
        eligible_30m, reason_30m = self.mgr.check_eligibility(t_30m)
        self.assertFalse(eligible_30m)
        self.assertIn("rate-governor cooldown active", reason_30m)

        # At T + 59 minutes: still ineligible
        t_59m = self.base_time + timedelta(minutes=59)
        eligible_59m, _ = self.mgr.check_eligibility(t_59m)
        self.assertFalse(eligible_59m)

        # At T + 60 minutes: ELIGIBLE
        t_60m = self.base_time + timedelta(minutes=60)
        eligible_60m, _ = self.mgr.check_eligibility(t_60m)
        self.assertTrue(eligible_60m)

    def test_exponential_backoff_on_throttling_or_api_error(self):
        curr_time = self.base_time

        # Attempt 1: Throttled -> 1 hour backoff (3600s)
        self.mgr.record_attempt(OUTCOME_THROTTLED, error_message="Too many requests", now=curr_time)
        self.assertEqual(self.mgr.state.status, STATE_THROTTLED)
        expected_next = (curr_time + timedelta(seconds=3600)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(self.mgr.state.next_eligible_at, expected_next)

        # Advance to T + 1h
        curr_time += timedelta(seconds=3600)
        eligible, _ = self.mgr.check_eligibility(curr_time)
        self.assertTrue(eligible)

        # Attempt 2: Throttled again -> 2 hours backoff (7200s)
        self.mgr.record_attempt(OUTCOME_THROTTLED, error_message="Too many requests", now=curr_time)
        expected_next_2 = (curr_time + timedelta(seconds=7200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(self.mgr.state.next_eligible_at, expected_next_2)

        # Advance to T + 3h
        curr_time += timedelta(seconds=7200)

        # Attempt 3: API Error -> 4 hours backoff (14400s)
        self.mgr.record_attempt(OUTCOME_API_ERROR, error_message="InternalServerError", now=curr_time)
        expected_next_3 = (curr_time + timedelta(seconds=14400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(self.mgr.state.next_eligible_at, expected_next_3)

        # Advance to T + 7h
        curr_time += timedelta(seconds=14400)

        # Attempt 4: Max backoff cap enforced (28800s / 8h)
        self.mgr.record_attempt(OUTCOME_THROTTLED, error_message="Too many requests", now=curr_time)
        expected_next_4 = (curr_time + timedelta(seconds=28800)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual(self.mgr.state.next_eligible_at, expected_next_4)

    def test_hard_7_day_expiration(self):
        # Advance time to 7 days + 1 second
        t_expired = self.base_time + timedelta(days=7, seconds=1)

        eligible, reason = self.mgr.check_eligibility(t_expired)
        self.assertFalse(eligible)
        self.assertIn("expired", reason.lower())
        self.assertEqual(self.mgr.state.status, STATE_EXPIRED)

    def test_idempotency_prevents_duplicate_instances(self):
        existing_instances = [
            {
                "name": "anie-collector-01",
                "state": "RUNNING",
                "ocid": "ocid1.instance.oc1.ap-hyderabad-1.xxx",
            },
            {
                "name": "anie-arm-01",
                "state": "PROVISIONING",
                "ocid": "ocid1.instance.oc1.ap-hyderabad-1.newarm",
                "public_ip": "129.225.200.5",
                "private_ip": "10.42.1.150",
            },
        ]

        found = self.mgr.verify_idempotency(existing_instances)
        self.assertTrue(found)
        self.assertEqual(self.mgr.state.status, STATE_ACQUIRED)
        self.assertEqual(self.mgr.state.acquired_instance_ocid, "ocid1.instance.oc1.ap-hyderabad-1.newarm")
        self.assertEqual(self.mgr.state.acquired_public_ip, "129.225.200.5")

        # Further attempts must be immediately rejected
        eligible, reason = self.mgr.check_eligibility(self.base_time)
        self.assertFalse(eligible)
        self.assertIn("already successfully acquired", reason)

    def test_immediate_termination_on_success(self):
        instance_info = {
            "ocid": "ocid1.instance.oc1.ap-hyderabad-1.successarm",
            "public_ip": "129.225.200.10",
            "private_ip": "10.42.1.151",
        }
        self.mgr.record_attempt(
            OUTCOME_SUCCESS,
            instance_details=instance_info,
            now=self.base_time,
        )

        self.assertEqual(self.mgr.state.status, STATE_ACQUIRED)
        self.assertEqual(self.mgr.state.acquired_instance_ocid, "ocid1.instance.oc1.ap-hyderabad-1.successarm")
        self.assertIsNone(self.mgr.state.next_eligible_at)

        eligible, _ = self.mgr.check_eligibility(self.base_time + timedelta(hours=2))
        self.assertFalse(eligible)

    def test_cross_platform_mutual_exclusion_lock(self):
        lock_file = self.state_dir / "test_mutex.lock"
        lock1 = CrossPlatformLock(lock_file)
        lock2 = CrossPlatformLock(lock_file)

        # First process acquires lock
        self.assertTrue(lock1.acquire())

        # Second process attempting concurrent lock must FAIL (zero parallel runs)
        self.assertFalse(lock2.acquire())

        # Release lock 1
        lock1.release()

        # Second process can now acquire lock
        self.assertTrue(lock2.acquire())
        lock2.release()


if __name__ == "__main__":
    unittest.main()
