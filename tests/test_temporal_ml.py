import unittest
from anie.demo import demo_observations
from anie.engine import build_intelligence
from anie.ml import RobustKNNNovelty
from anie.observations import Observation
from anie.temporal import domain_features

AS_OF = "2026-11-11T10:00:00Z"


class TestTemporalML(unittest.TestCase):
    def test_synthetic_outlier_is_detected_as_novel_not_malicious(self):
        records = build_intelligence(demo_observations(), AS_OF)
        self.assertEqual(len(records), 34)
        changed = next(r for r in records if r["indicator"]["value"] == "changing.example.test")
        self.assertEqual(changed["features"]["dns_changes_7d"], 2)
        self.assertEqual(changed["features"]["collection_errors_7d"], 1)
        self.assertEqual(changed["assessment"]["ai"]["status"], "outlier")
        self.assertEqual(changed["finding"]["maliciousness"], "undetermined")
        normal = next(r for r in records if r["indicator"]["value"] == "baseline-01.example.test")
        self.assertEqual(normal["assessment"]["ai"]["status"], "within_cohort")
        self.assertEqual(normal["features"]["dns_changes_7d"], 0)
        self.assertIsNone(normal["assessment"]["confidence"])

    def test_never_confuse_errors_with_empty_rrsets(self):
        stamps = ["2026-11-09T00:00:00Z", "2026-11-10T00:00:00Z", "2026-11-11T00:00:00Z"]
        items = []
        for at, status, values in zip(stamps, ["ok", "error", "ok"], [["192.0.2.2"], [], ["192.0.2.2"]]):
            items.append(Observation.from_dict(dict(subject="example.test", kind="dns_a", observed_at=at, values=values, status=status, source_id="synthetic:a", method="synthetic", synthetic=True, error_code="timeout" if status == "error" else None)))
        f = domain_features("example.test", items, AS_OF)
        self.assertEqual(f.dns_changes_7d, 0)
        self.assertEqual(f.errors_7d, 1)

    def test_no_cross_source_changes(self):
        items = [Observation.from_dict(dict(subject="example.test", kind="dns_a", observed_at="2026-11-10T00:00:00Z", values=["192.0.2.1"], status="ok", source_id="synthetic:a", method="synthetic", synthetic=True)), Observation.from_dict(dict(subject="example.test", kind="dns_a", observed_at="2026-11-11T00:00:00Z", values=["192.0.2.2"], status="ok", source_id="synthetic:b", method="synthetic", synthetic=True))]
        f = domain_features("example.test", items, AS_OF)
        self.assertFalse(f.has_comparison)
        self.assertEqual(f.dns_changes_7d, 0)

    def test_insufficient_cohort_abstains(self):
        model = RobustKNNNovelty(min_peers=20).fit({"a": (1., 2., 3., 0.)})
        result = model.evaluate("a", (1., 2., 3., 0.), has_comparison=True)
        self.assertEqual(result["status"], "insufficient_cohort")
        self.assertIsNone(result["novelty_distance"])

    def test_future_observations_ignored(self):
        items = demo_observations()
        findings = build_intelligence(items, "2026-11-09T09:00:00Z")
        changed = next(x for x in findings if x["indicator"]["value"] == "changing.example.test")
        self.assertEqual(changed["features"]["dns_changes_7d"], 0)
        self.assertEqual(changed["assessment"]["status"], "insufficient_history")
