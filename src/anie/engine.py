"""Build evidence-linked domain and IP intelligence from local observations."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from . import SCHEMA
from .ml import MODEL_VERSION, RobustKNNNovelty
from .observations import Observation, utc_iso
from .temporal import domain_features


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_intelligence(observations: list[Observation], as_of: str) -> list[dict]:
    as_of = utc_iso(as_of)
    valid = [ob for ob in observations if ob.observed_at <= as_of]
    domains = sorted({ob.subject for ob in valid if ob.kind in {"dns_a", "dns_aaaa"}})
    features = {domain: domain_features(domain, valid, as_of) for domain in domains}
    comparable = {d: f.vector() for d, f in features.items() if f.has_comparison and f.successful_snapshots_7d >= 2}
    ml = RobustKNNNovelty().fit(comparable)
    results: list[dict] = []
    for domain in domains:
        f = features[domain]
        ai = ml.evaluate(domain, f.vector(), has_comparison=domain in comparable)
        stale = f.latest_at is None or (_time(as_of) - _time(f.latest_at)).total_seconds() > 86400
        changed = f.dns_changes_7d > 0
        if f.has_comparison:
            statement = "Observed DNS answer sets changed within the seven-day window" if changed else "No DNS answer-set change observed between comparable snapshots in the seven-day window"
        else:
            statement = "Not enough comparable DNS snapshots to assess change"
        results.append({
            "schema": SCHEMA,
            "indicator": {"type": "domain", "value": domain},
            "finding": {
                "type": "dns_infrastructure_change" if changed else "dns_observation_context",
                "statement": statement,
                "classification": "context", "maliciousness": "undetermined",
            },
            "assessment": {
                "status": "evidence_observed" if f.has_comparison else "insufficient_history",
                "freshness": "stale" if stale else "recent",
                "confidence": None,
                "ai": {"model_version": MODEL_VERSION, **ai},
            },
            "features": {
                "dns_changes_7d": f.dns_changes_7d, "unique_ips_7d": f.unique_ips_7d,
                "latest_ip_count": f.latest_ip_count, "collection_errors_7d": f.errors_7d,
                "complete_dns_snapshots_7d": f.successful_snapshots_7d,
            },
            "evidence_ids": list(f.evidence_ids),
            "last_observed_at": f.latest_at,
            "assessed_at": as_of,
            "recheck_required": stale or f.errors_7d > 0 or ai["status"].startswith("insufficient"),
            "synthetic": all(ob.synthetic for ob in valid if ob.subject == domain),
        })
    ips = sorted({ob.subject for ob in valid if ob.kind in {"rdap_network", "rdap_asn", "dns_ptr"}})
    for ip in ips:
        ip_obs = sorted((ob for ob in valid if ob.subject == ip), key=lambda o: (o.observed_at, o.observation_id))
        successes = [o for o in ip_obs if o.status in {"ok", "empty"}]
        latest = successes[-1] if successes else None
        results.append({
            "schema": SCHEMA, "indicator": {"type": "ip", "value": ip},
            "finding": {"type": "registration_and_reverse_dns_context", "statement": "Directly recorded IP metadata; no threat attribution", "classification": "context", "maliciousness": "undetermined"},
            "assessment": {"status": "evidence_observed" if latest else "insufficient_history", "freshness": "stale" if latest is None or (_time(as_of) - _time(latest.observed_at)).total_seconds() > 86400 else "recent", "confidence": None, "ai": {"model_version": MODEL_VERSION, "status": "not_applicable", "novelty_distance": None, "threshold": None, "baseline_size": 0}},
            "features": {"observation_count": len(ip_obs), "record_kinds": sorted({ob.kind for ob in ip_obs})},
            "evidence_ids": [ob.observation_id for ob in ip_obs],
            "last_observed_at": latest.observed_at if latest else None,
            "assessed_at": as_of, "recheck_required": latest is None,
            "synthetic": all(ob.synthetic for ob in ip_obs),
        })
    return sorted(results, key=lambda r: (r["indicator"]["type"], r["indicator"]["value"]))
