"""End-to-end integration acceptance test for ANIE Phase 2."""
from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from phase2_acceptance_runner import run_acceptance_tests


class TestPhase2EndToEndAcceptance(unittest.TestCase):
    def test_complete_phase2_acceptance_workflow(self):
        """Execute complete 10-step Phase 2 integration acceptance suite fail-closed."""
        report = run_acceptance_tests(verbose=False)
        self.assertEqual(report["batch_execution"]["outcome"], "SUCCESS")
        self.assertEqual(report["batch_execution"]["queries_succeeded"], 2)
        self.assertEqual(report["sqlite_persistence"], "verified")
        self.assertEqual(report["evidence_integrity"], "verified")
        self.assertEqual(report["candidate_integrity"], "verified")
        self.assertEqual(report["consumer_verification"], "authenticated")
        self.assertEqual(report["anti_rollback"], "verified_monotonic_and_replay_rejected")
        self.assertEqual(report["adversarial_defenses"], "all_passed_fail_closed")
        self.assertEqual(report["process_restart_persistence"], "verified")


if __name__ == "__main__":
    unittest.main()
