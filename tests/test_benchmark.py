"""Time-split benchmark, abstention and leakage regression tests."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from anie.benchmarks import (
    BENCHMARK_VERSION, DEFAULT_SEED, TRAIN_AS_OF, EVAL_AS_OF,
    benchmark_run, benchmark_snapshot, evaluate_temporal_benchmark,
    synthetic_temporal_corpus, profiled_benchmark,
)
from anie.observations import Observation


class TestTemporalBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = benchmark_run()
        cls.observations, cls.scenarios = synthetic_temporal_corpus()

    def test_deterministic_replay(self):
        self.assertEqual(benchmark_snapshot(self.report), benchmark_snapshot(benchmark_run()))
        obs2, cases2 = synthetic_temporal_corpus()
        self.assertEqual(
            [(o.observation_id, o.to_dict()) for o in self.observations],
            [(o.observation_id, o.to_dict()) for o in obs2],
        )
        self.assertEqual(self.scenarios, cases2)
        self.assertEqual(self.report["schema"], BENCHMARK_VERSION)
        self.assertEqual(self.report["dataset_type"], "synthetic_only")
        self.assertEqual(self.report["seed"], DEFAULT_SEED)

    def test_seed_changes_simulated_corpus(self):
        other = benchmark_run(DEFAULT_SEED + 1)
        self.assertNotEqual(
            self.report["train_observation_sha256"], other["train_observation_sha256"]
        )

    def test_training_uses_only_pre_cutoff_observations(self):
        old = self.report
        domain = next(s.domain for s in self.scenarios if s.category == "stable")
        future = Observation.from_dict({
            "subject": domain, "kind": "dns_a",
            "observed_at": "2026-11-11T11:00:00Z",
            "values": ["198.51.100.211"], "status": "ok",
            "source_id": "synthetic:benchmark",
            "method": "synthetic", "synthetic": True,
            "ttl_seconds": 300, "error_code": None,
        })
        new = evaluate_temporal_benchmark(self.observations + [future], self.scenarios)
        self.assertEqual(old["train_observation_sha256"], new["train_observation_sha256"])
        self.assertEqual(old["training_entities"], new["training_entities"])
        self.assertNotEqual(old["heldout_observation_sha256"], new["heldout_observation_sha256"])

    def test_labels_are_not_training_features(self):
        altered = [replace(s, expected_novelty=not s.expected_novelty) for s in self.scenarios]
        outcome = evaluate_temporal_benchmark(self.observations, altered)
        self.assertEqual(outcome["train_observation_sha256"], self.report["train_observation_sha256"])
        original_predictions = [x["predictions"] for x in self.report["per_case"]]
        altered_predictions = [x["predictions"] for x in outcome["per_case"]]
        self.assertEqual(original_predictions, altered_predictions)

    def test_bad_split_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "gap"):
            evaluate_temporal_benchmark(
                self.observations, self.scenarios,
                train_as_of=TRAIN_AS_OF, eval_as_of="2026-11-05T12:00:00Z",
            )
        with self.assertRaisesRegex(ValueError, "gap"):
            evaluate_temporal_benchmark(
                self.observations, self.scenarios,
                train_as_of=EVAL_AS_OF, eval_as_of=EVAL_AS_OF,
            )

    def test_future_snapshot_rejected(self):
        future = Observation.from_dict({
            "subject": self.scenarios[0].domain, "kind": "dns_a",
            "observed_at": "2026-11-12T10:00:00Z",
            "values": ["192.0.2.4"], "status": "ok",
            "source_id": "synthetic:benchmark",
            "method": "synthetic", "synthetic": True,
        })
        with self.assertRaisesRegex(ValueError, "horizon"):
            evaluate_temporal_benchmark(self.observations + [future], self.scenarios)

    def test_untrusted_real_data_rejected(self):
        source = self.observations[0].to_dict()
        source["method"] = "dns"
        source["synthetic"] = False
        with self.assertRaisesRegex(ValueError, "synthetic"):
            evaluate_temporal_benchmark([Observation.from_dict(source)] + self.observations[1:], self.scenarios)

    def test_stale_sparse_conflicts_abstain(self):
        suppressed = {"stale", "sparse", "same_source_contradiction", "cross_source_disagreement"}
        relevant = [x for x in self.report["per_case"] if x["scenario"] in suppressed]
        self.assertEqual(len(relevant), 20)
        for case in relevant:
            with self.subTest(scenario=case["scenario"], domain=case["subject"]):
                self.assertNotEqual(case["eligibility"], "eligible")
                self.assertTrue(all(v is None for v in case["predictions"].values()))
                self.assertEqual(case["threat_verdict"], "not_assessed")

    def test_collection_errors_not_negative_answers(self):
        cases = [x for x in self.report["per_case"] if x["scenario"] == "intermittent_errors"]
        self.assertEqual(len(cases), 8)
        for case in cases:
            self.assertEqual(case["features"]["dns_changes_7d"], 0)
            self.assertEqual(case["features"]["collection_errors_7d"], 1)
            self.assertIn("collection_errors", case["caveats"])
            self.assertEqual(case["eligibility"], "eligible")

    def test_fanout_change_naive_baseline_limitation(self):
        cases = [x for x in self.report["per_case"] if x["scenario"] == "unusual_fanout"]
        self.assertEqual(len(cases), 8)
        for case in cases:
            self.assertEqual(case["features"]["dns_changes_7d"], 0)
            self.assertEqual(case["predictions"]["naive_any_dns_change"], False)

    def test_no_maliciousness_or_owner_attribution(self):
        self.assertEqual(self.report["guardrails"]["malicious_verdicts_issued"], 0)
        self.assertEqual(self.report["guardrails"]["owner_attribution_inferred"], 0)
        for case in self.report["per_case"]:
            self.assertEqual(case["threat_verdict"], "not_assessed")
        owners = [c for c in self.report["per_case"] if c["scenario"] == "owner_transfer_unobservable"]
        self.assertEqual(len(owners), 6)

    def test_metrics_account_for_abstentions(self):
        report = self.report
        for scores in report["methods"].values():
            self.assertEqual(
                scores["tp"] + scores["fp"] + scores["tn"] + scores["fn"]
                + scores["abstained_positive"] + scores["abstained_negative"],
                len(report["per_case"]),
            )
            self.assertEqual(scores["tp"] + scores["fn"] + scores["abstained_positive"], report["synthetic_positive_cases"])
            self.assertIsNone(scores["precision"]) if scores["tp"] + scores["fp"] == 0 else self.assertGreaterEqual(scores["precision"], 0)

    def test_resource_profile_not_in_snapshot(self):
        report, profile = profiled_benchmark()
        snapshot = benchmark_snapshot(report)
        self.assertNotIn("elapsed_ms", str(snapshot))
        self.assertGreaterEqual(profile["elapsed_ms"], 0)
        self.assertGreaterEqual(profile["peak_allocated_bytes"], 0)
