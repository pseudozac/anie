"""Time-separated, synthetic-only model benchmark for ANIE.

Research metric: detecting *intentionally unusual infrastructure change* in
invented DNS snapshots. This cannot validate threat detection or attribution.

The benchmark never modifies ANIE's production intelligence schema or model.
No network, filesystem, database, cloud, or API access occurs in this module.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from time import perf_counter
import ipaddress
import random
import tracemalloc

from .ml import MODEL_VERSION, RobustKNNNovelty
from .observations import Observation, canonical_json, utc_iso
from .temporal import domain_features

TRAIN_AS_OF = "2026-11-01T12:00:00Z"
EVAL_AS_OF = "2026-11-11T12:00:00Z"
BENCHMARK_VERSION = "anie.temporal-benchmark.v1"
DEFAULT_SEED = 20261111
# A full seven-day holdout feature window occurs strictly after training.
HOLDOUT_DAYS = 7

# Category labels describe INVENTED infrastructure behavior, not maliciousness.
CATEGORIES = (
    ("stable", 24, False),
    ("shared_hosting", 10, False),
    ("routine_migration", 8, False),
    ("owner_transfer_unobservable", 6, False),
    ("intermittent_errors", 8, False),
    ("rapid_rotation", 8, True),
    ("unusual_fanout", 8, True),
    ("stale", 6, False),
    ("sparse", 6, False),
    ("same_source_contradiction", 4, False),
    ("cross_source_disagreement", 4, False),
)


@dataclass(frozen=True)
class Scenario:
    domain: str
    category: str
    expected_novelty: bool
    hidden_note: str


def _date(day: str) -> str:
    return day + "T10:00:00Z"


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(utc_iso(value).replace("Z", "+00:00"))


def synthetic_temporal_corpus(seed: int = DEFAULT_SEED) -> tuple[list[Observation], list[Scenario]]:
    """Deterministic invented DNS snapshots; reserved IPs and .test names only."""
    if type(seed) is not int or seed < 0 or seed > 2**32 - 1:
        raise ValueError("seed must be a 32-bit unsigned integer")
    rng = random.Random(seed)
    observations: list[Observation] = []
    scenarios: list[Scenario] = []
    train_dates = [_date(day) for day in ("2026-10-29", "2026-10-31", "2026-11-01")]
    eval_dates = [_date(day) for day in ("2026-11-06", "2026-11-08", "2026-11-10", "2026-11-11")]

    def add(domain: str, at: str, values: list[str] | tuple[str, ...], *,
            source: str = "synthetic:benchmark", error: str | None = None) -> None:
        observations.append(Observation.from_dict({
            "subject": domain,
            "kind": "dns_a",
            "observed_at": at,
            "values": list(values) if error is None else [],
            "status": "error" if error else "ok",
            "source_id": source,
            "method": "synthetic",
            "synthetic": True,
            "ttl_seconds": 300 if error is None else None,
            "error_code": error,
        }))

    for category, count, unusual in CATEGORIES:
        for index in range(count):
            domain = f"{category.replace('_', '-')}-{index:02d}.example.test"
            base_num = rng.randrange(1, 200)
            base = f"192.0.2.{base_num}"
            alternate = f"198.51.100.{(base_num + 13) % 220 + 1}"
            third = f"203.0.113.{(base_num + 37) % 220 + 1}"
            fourth = f"198.51.100.{(base_num + 73) % 220 + 1}"
            shared = "192.0.2.220"
            note = (
                "simulated unobservable registration-owner change; not fed to model"
                if category == "owner_transfer_unobservable"
                else "no malware, compromise, or owner attribution ground truth"
            )
            scenarios.append(Scenario(domain, category, unusual, note))
            for i, at in enumerate(train_dates):
                if category == "shared_hosting":
                    vals = [base, shared]
                elif category == "routine_migration" and i >= 1:
                    vals = [alternate]
                else:
                    vals = [base]
                add(domain, at, vals)
            if category == "stale":
                continue
            if category == "sparse":
                add(domain, eval_dates[-1], [base])
                continue
            for i, at in enumerate(eval_dates):
                if category == "intermittent_errors" and i == 1:
                    add(domain, at, [], error="timeout")
                    continue
                if category == "shared_hosting":
                    vals = [base, shared]
                elif category in {"routine_migration", "owner_transfer_unobservable"}:
                    vals = [base if i < 2 else alternate]
                elif category == "rapid_rotation":
                    vals = [[base], [alternate], [third], [fourth]][i]
                elif category == "unusual_fanout":
                    # Six distinct addresses in one complete snapshot: unusual
                    # fanout without intra-window answer-set changes.
                    vals = [f"203.0.113.{(base_num + j * 17) % 220 + 1}" for j in range(6)]
                else:
                    vals = [base]
                add(domain, at, vals)
                if category == "same_source_contradiction" and i == 1:
                    add(domain, at, [alternate])
                if category == "cross_source_disagreement":
                    add(domain, at, [alternate], source="synthetic:independent")
    return observations, scenarios


def _fingerprint(observations: list[Observation]) -> str:
    payload = [{"id": ob.observation_id, **ob.to_dict()} for ob in sorted(observations, key=lambda o: o.observation_id)]
    return sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _quality(domain: str, heldout: list[Observation], as_of: str) -> tuple[str, list[str]]:
    """Reject ambiguous, sparse and stale evidence before evaluating ANY model."""
    records = [o for o in heldout if o.subject == domain and o.kind == "dns_a"]
    successes = [o for o in records if o.status in {"ok", "empty"}]
    flags = []
    if any(o.status == "error" for o in records):
        flags.append("collection_errors")
    if not successes:
        return "stale_or_no_evidence", flags
    if _utc(as_of) - max(_utc(o.observed_at) for o in successes) > timedelta(hours=48):
        return "stale_or_no_evidence", flags
    if len(successes) < 2:
        return "insufficient_comparable_evidence", flags
    grouped: dict[tuple[str, str, str], set[tuple[str, ...]]] = defaultdict(set)
    cross: dict[tuple[str, str], set[tuple[str, ...]]] = defaultdict(set)
    for o in successes:
        grouped[(o.kind, o.source_id, o.observed_at)].add(o.values)
        cross[(o.kind, o.observed_at)].add(o.values)
    if any(len(sets) > 1 for sets in grouped.values()):
        return "contradictory_same_source", flags + ["conflicting_same_source_snapshots"]
    if any(len(sets) > 1 for sets in cross.values()):
        return "conflicting_sources", flags + ["cross_source_disagreement"]
    features = domain_features(domain, records, as_of)
    if not features.has_comparison or features.successful_snapshots_7d < 2:
        return "insufficient_comparable_evidence", flags
    return "eligible", flags


def _count_metrics(predictions: list[tuple[bool, bool | None]]) -> dict:
    tp = fp = tn = fn = abstain_positive = abstain_negative = 0
    for truth, predicted in predictions:
        if predicted is None:
            if truth:
                abstain_positive += 1
            else:
                abstain_negative += 1
        elif predicted and truth:
            tp += 1
        elif predicted and not truth:
            fp += 1
        elif not predicted and truth:
            fn += 1
        else:
            tn += 1
    total = len(predictions)
    positives = tp + fn + abstain_positive
    evaluated = tp + fp + tn + fn
    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 6) if denominator else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "abstained_positive": abstain_positive,
        "abstained_negative": abstain_negative,
        "coverage": ratio(evaluated, total),
        "precision": ratio(tp, tp + fp),
        "recall_all_positive_cases": ratio(tp, positives),
        "recall_on_evaluated_cases": ratio(tp, tp + fn),
        "false_positive_rate_evaluated": ratio(fp, fp + tn),
        "false_positive_count": fp,
    }


def evaluate_temporal_benchmark(
    observations: list[Observation], scenarios: list[Scenario], *,
    train_as_of: str = TRAIN_AS_OF, eval_as_of: str = EVAL_AS_OF
) -> dict:
    """Train fit/threshold from earlier snapshots; test only later observations.

    This intentionally uses one fixed, predeclared temporal split, NOT a full
    rolling-origin cross-validation. Do not tune on these heldout labels.
    """
    train_as_of, eval_as_of = utc_iso(train_as_of), utc_iso(eval_as_of)
    train_end, evaluation_end = _utc(train_as_of), _utc(eval_as_of)
    if evaluation_end - train_end <= timedelta(days=HOLDOUT_DAYS):
        raise ValueError("train/eval gap must exceed the seven-day feature window")
    if not observations or not scenarios or len(scenarios) > 500 or len(observations) > 10000:
        raise ValueError("invalid or oversized benchmark corpus")
    if any(not o.synthetic or o.kind != "dns_a" for o in observations):
        raise ValueError("benchmark requires synthetic DNS-A observations only")
    subjects = [s.domain for s in scenarios]
    if len(subjects) != len(set(subjects)):
        raise ValueError("scenario subjects must be unique")
    if any(o.subject not in subjects or _utc(o.observed_at) > evaluation_end for o in observations):
        raise ValueError("observation outside registered subjects or eval horizon")
    train = [o for o in observations if _utc(o.observed_at) <= train_end]
    heldout = [o for o in observations if train_end < _utc(o.observed_at) <= evaluation_end]
    if not train or not heldout:
        raise ValueError("train and heldout observations must exist")
    if any(_utc(o.observed_at) >= evaluation_end - timedelta(days=HOLDOUT_DAYS) for o in train):
        raise ValueError("training observations overlap evaluation feature window")
    if any(_utc(o.observed_at) <= train_end for o in heldout):
        raise AssertionError("future observations entered the training fold")
    # Training labels are NEVER consulted while fitting the unsupervised model.
    train_vectors = {}
    for domain in sorted(subjects):
        f = domain_features(domain, train, train_as_of)
        if f.has_comparison and f.successful_snapshots_7d >= 2:
            train_vectors[domain] = f.vector()
    model = RobustKNNNovelty(min_peers=20, k=5).fit(train_vectors)
    predictions: dict[str, list[tuple[bool, bool | None]]] = {
        "ml_knn_novelty": [],
        "deterministic_large_change": [],
        "naive_any_dns_change": [],
    }
    diagnostics = []
    abstention_reasons = Counter()
    for scenario in sorted(scenarios, key=lambda s: s.domain):
        status, caveats = _quality(scenario.domain, heldout, eval_as_of)
        domain_obs = [o for o in heldout if o.subject == scenario.domain]
        feature = domain_features(scenario.domain, domain_obs, eval_as_of)
        if status != "eligible":
            abstention_reasons[status] += 1
            output = {key: None for key in predictions}
            ml_details = {"status": status, "novelty_distance": None, "threshold": None}
        else:
            ml_details = model.evaluate(scenario.domain, feature.vector(), has_comparison=True)
            output = {
                "ml_knn_novelty": None if ml_details["status"] not in {"outlier", "within_cohort"} else ml_details["status"] == "outlier",
                "deterministic_large_change": feature.dns_changes_7d >= 2 or feature.latest_ip_count >= 4,
                "naive_any_dns_change": feature.dns_changes_7d >= 1,
            }
        for name in predictions:
            predictions[name].append((scenario.expected_novelty, output[name]))
        diagnostics.append({
            "subject": scenario.domain,
            "scenario": scenario.category,
            "synthetic_expected_novelty": scenario.expected_novelty,
            "eligibility": status,
            "caveats": caveats,
            "features": {
                "dns_changes_7d": feature.dns_changes_7d,
                "unique_ips_7d": feature.unique_ips_7d,
                "latest_ip_count": feature.latest_ip_count,
                "collection_errors_7d": feature.errors_7d,
            },
            "predictions": output,
            "ml_diagnostics": ml_details,
            "evidence_ids": list(feature.evidence_ids),
            "observed_through": feature.latest_at,
            "threat_verdict": "not_assessed",
        })
    return {
        "schema": BENCHMARK_VERSION,
        "dataset_type": "synthetic_only",
        "seed": None,  # The caller's seed is added by benchmark_run(), not inferred.
        "train_as_of": train_as_of,
        "eval_as_of": eval_as_of,
        "holdout_window_days": HOLDOUT_DAYS,
        "train_observation_sha256": _fingerprint(train),
        "heldout_observation_sha256": _fingerprint(heldout),
        "observations": {"train": len(train), "heldout": len(heldout), "all": len(observations)},
        "training_entities": len(train_vectors),
        "scenario_counts": dict(sorted(Counter(s.category for s in scenarios).items())),
        "synthetic_positive_cases": sum(s.expected_novelty for s in scenarios),
        "synthetic_negative_cases": sum(not s.expected_novelty for s in scenarios),
        "abstention_reasons": dict(sorted(abstention_reasons.items())),
        "model_version": MODEL_VERSION,
        "methods": {name: _count_metrics(items) for name, items in predictions.items()},
        "guardrails": {
            "maliciousness_labels_used_for_training": 0,
            "malicious_verdicts_issued": 0,
            "external_collection_requests": 0,
            "owner_attribution_inferred": 0,
        },
        "per_case": diagnostics,
    }


def benchmark_run(seed: int = DEFAULT_SEED) -> dict:
    observations, scenarios = synthetic_temporal_corpus(seed)
    result = evaluate_temporal_benchmark(observations, scenarios)
    result["seed"] = seed
    return result


def benchmark_snapshot(report: dict) -> dict:
    """Deterministic record for Git-tracked regression checks; no timings."""
    reduced = {key: value for key, value in report.items() if key != "per_case"}
    reduced["per_case_predictions_sha256"] = sha256(canonical_json(report["per_case"]).encode("utf-8")).hexdigest()
    return reduced


def profiled_benchmark(seed: int = DEFAULT_SEED) -> tuple[dict, dict]:
    """Resource measurements are diagnostic only; never golden-snapshot inputs."""
    tracemalloc.start()
    began = perf_counter()
    try:
        report = benchmark_run(seed)
        elapsed_ms = round((perf_counter() - began) * 1000, 3)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return report, {"elapsed_ms": elapsed_ms, "peak_allocated_bytes": peak, "note": "local Python allocator only, not total RSS; hardware-dependent"}
