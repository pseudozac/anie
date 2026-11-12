#!/usr/bin/env python3
"""Offline Schedule Cadence and Policy Quota Simulator for ANIE.

Simulates 24-hour and 30-day collection schedules against DohRateGovernor quotas,
verifying cooldown constraints, resolver rate windows, daily quotas, and A/AAAA alternation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from anie.doh_governor import (
    DEFAULT_MAX_TARGET_PER_HOUR,
    DEFAULT_MAX_RESOLVER_PER_HOUR,
    DEFAULT_MAX_DAILY_TOTAL,
    DEFAULT_TARGET_COOLDOWN_SECONDS,
)


class ScheduleSimulation:
    def __init__(
        self,
        cadence: str = "daily",  # "daily" or "four_hour"
        domains: list[str] | None = None,
        resolver: str = "cloudflare-dns.com",
        cooldown_sec: float = DEFAULT_TARGET_COOLDOWN_SECONDS,
        max_target_hr: int = DEFAULT_MAX_TARGET_PER_HOUR,
        max_resolver_hr: int = DEFAULT_MAX_RESOLVER_PER_HOUR,
        max_daily: int = DEFAULT_MAX_DAILY_TOTAL,
    ):
        self.cadence = cadence
        self.domains = domains or ["example.com", "iana.org"]
        self.resolver = resolver
        self.cooldown_sec = cooldown_sec
        self.max_target_hr = max_target_hr
        self.max_resolver_hr = max_resolver_hr
        self.max_daily = max_daily

    def generate_batch_timestamps(self, start_dt: datetime, duration_days: int) -> list[datetime]:
        """Generate scheduled batch execution timestamps."""
        end_dt = start_dt + timedelta(days=duration_days)
        cur = start_dt
        timestamps = []

        if self.cadence == "daily":
            # 06:00:00 UTC each day
            cur = cur.replace(hour=6, minute=0, second=0, microsecond=0)
            if cur < start_dt:
                cur += timedelta(days=1)
            while cur < end_dt:
                timestamps.append(cur)
                cur += timedelta(days=1)
        elif self.cadence == "four_hour":
            # 00, 04, 08, 12, 16, 20:00:00 UTC
            hours = [0, 4, 8, 12, 16, 20]
            cur = cur.replace(minute=0, second=0, microsecond=0)
            while cur < end_dt:
                if cur.hour in hours and cur >= start_dt:
                    timestamps.append(cur)
                cur += timedelta(hours=1)
        else:
            raise ValueError(f"unknown cadence: {self.cadence}")

        return timestamps

    def run_simulation(self, duration_days: int = 30) -> dict[str, Any]:
        """Run discrete-time offline simulation of queries and rate quotas."""
        start_dt = datetime(2026, 11, 15, 0, 0, 0, tzinfo=timezone.utc)
        timestamps = self.generate_batch_timestamps(start_dt, duration_days)

        query_history: list[dict[str, Any]] = []
        last_domain_query_time: dict[str, datetime] = {}
        last_domain_query_kind: dict[str, str] = {}

        min_cooldown_observed = float("inf")
        max_resolver_1h_observed = 0
        max_daily_observed = 0
        quota_violations = []

        batches_data = []

        for b_idx, b_time in enumerate(timestamps, 1):
            batch_queries = []
            for d in self.domains:
                # Alternation logic: alternate from last persisted observation
                last_k = last_domain_query_kind.get(d)
                next_k = "dns_aaaa" if last_k == "dns_a" else "dns_a"

                # Check cooldown
                if d in last_domain_query_time:
                    elapsed = (b_time - last_domain_query_time[d]).total_seconds()
                    min_cooldown_observed = min(min_cooldown_observed, elapsed)
                    if elapsed < self.cooldown_sec:
                        quota_violations.append(
                            f"Batch #{b_idx} at {b_time.isoformat()}: Cooldown violation for {d}: "
                            f"{elapsed:.1f}s < {self.cooldown_sec:.1f}s"
                        )

                # Check 1-hour window for resolver
                window_1h_start = b_time - timedelta(hours=1)
                recent_resolver_queries = [
                    q for q in query_history
                    if q["time"] > window_1h_start and q["time"] <= b_time and q["resolver"] == self.resolver
                ]
                if len(recent_resolver_queries) + 1 > self.max_resolver_hr:
                    quota_violations.append(
                        f"Batch #{b_idx} at {b_time.isoformat()}: Hourly resolver limit exceeded: "
                        f"{len(recent_resolver_queries) + 1} > {self.max_resolver_hr}"
                    )

                # Check 24-hour daily window
                window_24h_start = b_time - timedelta(hours=24)
                recent_daily_queries = [
                    q for q in query_history
                    if q["time"] > window_24h_start and q["time"] <= b_time
                ]
                if len(recent_daily_queries) + 1 > self.max_daily:
                    quota_violations.append(
                        f"Batch #{b_idx} at {b_time.isoformat()}: Daily total limit exceeded: "
                        f"{len(recent_daily_queries) + 1} > {self.max_daily}"
                    )

                # Record query execution
                q_entry = {
                    "time": b_time,
                    "domain": d,
                    "kind": next_k,
                    "resolver": self.resolver,
                }
                query_history.append(q_entry)
                last_domain_query_time[d] = b_time
                last_domain_query_kind[d] = next_k
                batch_queries.append((d, next_k))

            # Record max rolling windows
            cur_1h = len([q for q in query_history if q["time"] > b_time - timedelta(hours=1)])
            cur_24h = len([q for q in query_history if q["time"] > b_time - timedelta(hours=24)])
            max_resolver_1h_observed = max(max_resolver_1h_observed, cur_1h)
            max_daily_observed = max(max_daily_observed, cur_24h)

            batches_data.append({
                "batch_num": b_idx,
                "timestamp": b_time.isoformat(),
                "queries": batch_queries,
                "rolling_1h_queries": cur_1h,
                "rolling_24h_queries": cur_24h,
            })

        # Calculate alternation balance
        a_count = sum(1 for q in query_history if q["kind"] == "dns_a")
        aaaa_count = sum(1 for q in query_history if q["kind"] == "dns_aaaa")

        total_records = len(query_history)
        est_db_kb = 32.0 + (total_records * 1.5)  # ~1.5 KB per record pair in SQLite
        est_bundle_kb = total_records * 0.15      # ~0.15 KB per record in compressed gzip

        return {
            "cadence": self.cadence,
            "duration_days": duration_days,
            "total_batches": len(timestamps),
            "total_queries": total_records,
            "queries_per_day": round(total_records / duration_days, 1),
            "min_cooldown_observed_hours": round(min_cooldown_observed / 3600.0, 2) if min_cooldown_observed != float("inf") else None,
            "cooldown_margin_ratio": round(min_cooldown_observed / self.cooldown_sec, 1) if min_cooldown_observed != float("inf") else None,
            "max_resolver_1h_queries": max_resolver_1h_observed,
            "max_resolver_1h_limit": self.max_resolver_hr,
            "resolver_hourly_headroom": self.max_resolver_hr - max_resolver_1h_observed,
            "max_daily_queries_observed": max_daily_observed,
            "daily_quota_limit": self.max_daily,
            "daily_quota_headroom": self.max_daily - max_daily_observed,
            "dns_a_count": a_count,
            "dns_aaaa_count": aaaa_count,
            "alternation_parity": "exact" if a_count == aaaa_count else "balanced_diff_1",
            "quota_violations_count": len(quota_violations),
            "quota_violations": quota_violations[:5],
            "est_db_size_kb": round(est_db_kb, 1),
            "est_release_bundle_kb": round(est_bundle_kb, 1),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="ANIE Schedule Cadence Simulator")
    parser.add_argument("--days", type=int, default=30, help="Simulation duration in days (default: 30)")
    parser.add_argument("--json", type=Path, help="Path to write JSON comparison output")
    args = parser.parse_args()

    sim_daily_24h = ScheduleSimulation("daily").run_simulation(1)
    sim_daily_30d = ScheduleSimulation("daily").run_simulation(args.days)

    sim_4h_24h = ScheduleSimulation("four_hour").run_simulation(1)
    sim_4h_30d = ScheduleSimulation("four_hour").run_simulation(args.days)

    print("=" * 78)
    print("ANIE PILOT SCHEDULE RECONCILIATION & POLICY QUOTA SIMULATION")
    print("=" * 78)

    print("\n--- 24-HOUR SIMULATION WINDOW ---")
    print(f"{'Metric':<32} | {'Daily Schedule (06:00 UTC)':<22} | {'4-Hour Schedule':<20}")
    print("-" * 78)
    print(f"{'Total Batches Executed':<32} | {sim_daily_24h['total_batches']:<22} | {sim_4h_24h['total_batches']:<20}")
    print(f"{'Total DNS Queries':<32} | {sim_daily_24h['total_queries']:<22} | {sim_4h_24h['total_queries']:<20}")
    q_per_dom_d = sim_daily_24h['total_queries'] // 2
    q_per_dom_4 = sim_4h_24h['total_queries'] // 2
    print(f"{'Queries / Domain / Day':<32} | {q_per_dom_d:<22} | {q_per_dom_4:<20}")
    print(f"{'Per-Domain Cooldown Interval':<32} | {'24 hours (48x margin)':<22} | {'4 hours (8x margin)':<20}")
    res_1h_d = f"{sim_daily_24h['max_resolver_1h_queries']} / {sim_daily_24h['max_resolver_1h_limit']}"
    res_1h_4 = f"{sim_4h_24h['max_resolver_1h_queries']} / {sim_4h_24h['max_resolver_1h_limit']}"
    print(f"{'Resolver 1-Hour Peak Queries':<32} | {res_1h_d:<22} | {res_1h_4:<20}")
    q_util_d = f"{sim_daily_24h['max_daily_queries_observed']} / {sim_daily_24h['daily_quota_limit']} (12.5%)"
    q_util_4 = f"{sim_4h_24h['max_daily_queries_observed']} / {sim_4h_24h['daily_quota_limit']} (75.0%)"
    print(f"{'Daily Quota Utilization':<32} | {q_util_d:<22} | {q_util_4:<20}")
    q_slack_d = f"+{sim_daily_24h['daily_quota_headroom']} queries"
    q_slack_4 = f"+{sim_4h_24h['daily_quota_headroom']} queries"
    print(f"{'Daily Quota Headroom (slack)':<32} | {q_slack_d:<22} | {q_slack_4:<20}")
    alt_ratio_d = f"{sim_daily_24h['dns_a_count']}A : {sim_daily_24h['dns_aaaa_count']}AAAA"
    alt_ratio_4 = f"{sim_4h_24h['dns_a_count']}A : {sim_4h_24h['dns_aaaa_count']}AAAA"
    print(f"{'A / AAAA Query Ratio':<32} | {alt_ratio_d:<22} | {alt_ratio_4:<20}")
    print(f"{'Policy Quota Violations':<32} | {sim_daily_24h['quota_violations_count']:<22} | {sim_4h_24h['quota_violations_count']:<20}")

    print(f"\n--- {args.days}-DAY OPERATIONAL SIMULATION WINDOW ---")
    print(f"{'Metric':<32} | {'Daily Schedule (06:00 UTC)':<22} | {'4-Hour Schedule':<20}")
    print("-" * 78)
    print(f"{'Total Batches Executed':<32} | {sim_daily_30d['total_batches']:<22} | {sim_4h_30d['total_batches']:<20}")
    print(f"{'Total Real Observations':<32} | {sim_daily_30d['total_queries']:<22} | {sim_4h_30d['total_queries']:<20}")
    alt_balance_d = f"{sim_daily_30d['dns_a_count']}A : {sim_daily_30d['dns_aaaa_count']}AAAA"
    alt_balance_4 = f"{sim_4h_30d['dns_a_count']}A : {sim_4h_30d['dns_aaaa_count']}AAAA"
    print(f"{'A / AAAA Alternation Balance':<32} | {alt_balance_d:<22} | {alt_balance_4:<20}")
    print(f"{'Temporal Resolution (cycle)':<32} | {'48 hours / full cycle':<22} | {'8 hours / full cycle':<20}")
    db_sz_d = f"{sim_daily_30d['est_db_size_kb']} KB"
    db_sz_4 = f"{sim_4h_30d['est_db_size_kb']} KB"
    print(f"{'Estimated SQLite DB Size':<32} | {db_sz_d:<22} | {db_sz_4:<20}")
    bnd_sz_d = f"{sim_daily_30d['est_release_bundle_kb']} KB"
    bnd_sz_4 = f"{sim_4h_30d['est_release_bundle_kb']} KB"
    print(f"{'Estimated Release Bundle Size':<32} | {bnd_sz_d:<22} | {bnd_sz_4:<20}")
    print(f"{'Policy Quota Violations':<32} | {sim_daily_30d['quota_violations_count']:<22} | {sim_4h_30d['quota_violations_count']:<20}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        comparison = {
            "simulation_days": args.days,
            "daily_24h": sim_daily_24h,
            "daily_30d": sim_daily_30d,
            "four_hour_24h": sim_4h_24h,
            "four_hour_30d": sim_4h_30d,
        }
        args.json.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
        print(f"\nSimulation comparison saved to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
