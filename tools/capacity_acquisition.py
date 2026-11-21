#!/usr/bin/env python3
"""CLI utility for managing OCI Ampere A1 capacity acquisition retries."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from anie.capacity_retry import (
    CapacityAcquisitionConfig,
    CapacityAcquisitionManager,
    OUTCOME_API_ERROR,
    OUTCOME_OUT_OF_CAPACITY,
    OUTCOME_SUCCESS,
    OUTCOME_THROTTLED,
    STATE_ACQUIRED,
)

DEFAULT_STATE_DIR = Path(".anie-capacity")


def main() -> int:
    parser = argparse.ArgumentParser(description="OCI Ampere A1 Capacity Acquisition Runner")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Directory to store state and lock")
    parser.add_argument("--status", action="store_true", help="Print current status JSON summary")
    parser.add_argument("--can-attempt", action="store_true", help="Check eligibility; exit 0 if eligible, 1 otherwise")
    parser.add_argument(
        "--record-attempt",
        choices=[OUTCOME_OUT_OF_CAPACITY, OUTCOME_SUCCESS, OUTCOME_THROTTLED, OUTCOME_API_ERROR],
        help="Record the result of a provisioning attempt",
    )
    parser.add_argument("--error-message", help="Error message if attempt failed")
    parser.add_argument("--ocid", help="Instance OCID if successfully acquired")
    parser.add_argument("--public-ip", help="Public IP if successfully acquired")
    parser.add_argument("--private-ip", help="Private IP if successfully acquired")
    parser.add_argument("--simulate-schedule", type=int, metavar="DAYS", help="Simulate retry schedule over N days")

    args = parser.parse_args()
    mgr = CapacityAcquisitionManager(args.state_dir)

    if args.status:
        summary = mgr.get_summary()
        print(json.dumps(summary, indent=2))
        return 0

    if args.can_attempt:
        eligible, reason = mgr.check_eligibility()
        print(f"Eligible: {eligible} ({reason})")
        return 0 if eligible else 1

    if args.record_attempt:
        details = {}
        if args.ocid:
            details["ocid"] = args.ocid
        if args.public_ip:
            details["public_ip"] = args.public_ip
        if args.private_ip:
            details["private_ip"] = args.private_ip

        state = mgr.record_attempt(
            outcome=args.record_attempt,
            error_message=args.error_message,
            instance_details=details if details else None,
        )
        print(f"Recorded {args.record_attempt}. Current status: {state.status}, next eligible: {state.next_eligible_at}")
        return 0

    if args.simulate_schedule:
        days = args.simulate_schedule
        print(f"Simulating {days}-day bounded retry progression (minimum 60-minute intervals)...")
        from datetime import timedelta
        sim_start = datetime(2026, 11, 21, 6, 0, 0, tzinfo=timezone.utc)
        curr = sim_start
        end_time = sim_start + timedelta(days=days)
        attempts = 0
        while curr < end_time:
            eligible, _ = mgr.check_eligibility(curr)
            if not eligible:
                break
            attempts += 1
            mgr.record_attempt(OUTCOME_OUT_OF_CAPACITY, error_message="Out of host capacity.", now=curr)
            curr += timedelta(hours=1)
        print(f"Total simulated 60-min attempts before expiration: {attempts} (Max: {days * 24})")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
