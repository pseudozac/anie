"""Time-aware DNS analysis. Negative answers are distinct from timeouts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dataclasses import dataclass
from .observations import Observation, utc_iso

DNS_KINDS = {"dns_a", "dns_aaaa"}


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(utc_iso(ts).replace("Z", "+00:00"))


@dataclass(frozen=True)
class DomainFeatures:
    domain: str
    dns_changes_7d: int
    unique_ips_7d: int
    latest_ip_count: int
    errors_7d: int
    successful_snapshots_7d: int
    latest_at: str | None
    evidence_ids: tuple[str, ...]
    has_comparison: bool

    def vector(self) -> tuple[float, ...]:
        return (float(self.dns_changes_7d), float(self.unique_ips_7d), float(self.latest_ip_count), float(self.dns_changes_7d) / max(1.0, float(self.successful_snapshots_7d - 1)))


def domain_features(domain: str, observations: list[Observation], as_of: str, window_days: int = 7) -> DomainFeatures:
    now = _parse(as_of)
    cutoff = now - timedelta(days=window_days)
    relevant = [o for o in observations if o.subject == domain and o.kind in DNS_KINDS and _parse(o.observed_at) <= now]
    groups: dict[str, list[Observation]] = defaultdict(list)
    for ob in relevant:
        groups[ob.kind].append(ob)
    window_obs = [o for o in relevant if _parse(o.observed_at) >= cutoff]
    changes = 0
    unique_ips: set[str] = set()
    latest_ip_count = 0
    ids = set()
    compared = False
    last_success: str | None = None
    for kind, group in groups.items():
        # A conflict between different sources at the exact timestamp is not a temporal change.
        group.sort(key=lambda o: (o.observed_at, o.observation_id))
        successes = [o for o in group if o.status in {"ok", "empty"}]
        window_successes = [o for o in successes if _parse(o.observed_at) >= cutoff]
        for ob in window_successes:
            unique_ips.update(ob.values)
            ids.add(ob.observation_id)
        if successes:
            latest_ip_count += len(successes[-1].values)
            if last_success is None or successes[-1].observed_at > last_success:
                last_success = successes[-1].observed_at
        # Compare only successive complete responses from the same source; no inference from errors.
        by_source: dict[str, list[Observation]] = defaultdict(list)
        for ob in successes:
            by_source[ob.source_id].append(ob)
        for source_observations in by_source.values():
            # Conflicting complete answers from the same source at the same timestamp
            # are ambiguous, not a sequential change. Exclude that timepoint.
            timepoints: dict[str, list[Observation]] = defaultdict(list)
            for ob in source_observations:
                timepoints[ob.observed_at].append(ob)
            unambiguous = [point[0] for _, point in sorted(timepoints.items()) if len({o.values for o in point}) == 1]
            if len(unambiguous) >= 2:
                compared = True
            for prev, curr in zip(unambiguous, unambiguous[1:]):
                if _parse(prev.observed_at) >= cutoff and _parse(curr.observed_at) >= cutoff and prev.values != curr.values:
                    changes += 1
                    ids.add(prev.observation_id)
                    ids.add(curr.observation_id)
    for ob in window_obs:
        if ob.status == "error":
            ids.add(ob.observation_id)
    return DomainFeatures(
        domain=domain, dns_changes_7d=changes, unique_ips_7d=len(unique_ips),
        latest_ip_count=latest_ip_count,
        errors_7d=sum(o.status == "error" for o in window_obs),
        successful_snapshots_7d=sum(o.status in {"ok", "empty"} for o in window_obs),
        latest_at=last_success, evidence_ids=tuple(sorted(ids)), has_comparison=compared,
    )
