"""Tests for intelligence quality evaluation framework and epistemic decoupling (Phase 3.5)."""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from anie.intelligence_evaluator import (
    IntelligenceEvaluationReport,
    IntelligenceEvaluator,
    ScenarioEvaluationResult,
)
from anie.real_store import RealObservationStore


class TestIntelligenceEvaluator(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_eval.db"
        self.store = RealObservationStore(self.db_path)
        self.evaluator = IntelligenceEvaluator(self.store)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_benchmark_scenarios_generation(self):
        scenarios = self.evaluator.generate_benchmark_scenarios()
        expected_scenarios = {
            "legitimate_cdn_rotation",
            "legitimate_round_robin",
            "resolver_filtering",
            "infrastructure_migration",
            "fast_flux_botnet",
            "unexpected_resolution_flip",
            "stable_baseline",
        }
        self.assertEqual(set(scenarios.keys()), expected_scenarios)

        for name, sc in scenarios.items():
            self.assertIn("domain", sc)
            self.assertIn("ground_truth", sc)
            self.assertIn("records", sc)
            self.assertTrue(len(sc["records"]) > 0)

    def test_full_evaluation_execution(self):
        report = self.evaluator.evaluate()

        self.assertIsInstance(report, IntelligenceEvaluationReport)
        self.assertEqual(report.total_scenarios, 7)
        self.assertEqual(report.true_positives, 3)
        self.assertEqual(report.false_positives, 0)
        self.assertEqual(report.true_negatives, 4)
        self.assertEqual(report.false_negatives, 0)
        self.assertEqual(report.unresolved_count, 0)

        # Performance metrics
        self.assertEqual(report.precision, 1.0)
        self.assertEqual(report.recall, 1.0)
        self.assertEqual(report.false_positive_rate, 0.0)
        self.assertEqual(report.accuracy, 1.0)
        self.assertEqual(report.evidence_completeness_rate, 1.0)

        # Explicit epistemic decoupling: accuracy vs confidence
        report_dict = report.to_dict()
        self.assertIn("disclaimer", report_dict)
        self.assertIn("Heuristic detector confidence scores remain uncalibrated", report_dict["disclaimer"])
        self.assertTrue(len(report.limitations) >= 5)

        # Ensure all scenarios produced complete evidence
        for res in report.scenario_results:
            self.assertTrue(res.is_correct)
            self.assertTrue(res.evidence_complete)


if __name__ == "__main__":
    unittest.main()
