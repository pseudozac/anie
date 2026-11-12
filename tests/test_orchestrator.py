"""Comprehensive unit tests for Phase 2 PR 3 (Bounded Batch Orchestration).

Tests policy envelope governance, canonical domain uniqueness, query alternation,
fail-closed execution modes, host metrics validation, preflight safeguards,
concurrency locking, monotonic batch deadline exhaustion, dry-run telemetry correctness,
CLI exit codes, and systemd unit configuration assertions.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import MagicMock, patch

from anie.cli import main as cli_main
from anie.collection_policy import ScopeDenied
from anie.orchestrator import (
    acquire_collector_lock,
    check_sqlite_integrity,
    emit_telemetry,
    get_available_disk_mb,
    get_available_memory_mb,
    run_preflight_checks,
    BatchConfig,
    BatchOrchestrator,
    BatchReport,
    MAX_BATCH_TIMEOUT_SECONDS,
    MAX_LOG_SIZE_BYTES,
    MAX_QUERIES_PER_BATCH,
    VALID_MODES,
)
from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore
from test_real_models import sample_event, sample_observation, sample_request


def make_dummy_event_and_obs(domain: str, kind: str) -> tuple[RealCollectionEvent, RealObservation]:
    req = sample_request(kind=kind, subject=domain)
    event = sample_event(request=req)
    val = ("93.184.216.34",) if kind == "dns_a" else ("2606:2800:220:1:248:1893:25c8:1946",)
    obs = sample_observation(subject=domain, kind=kind, values=val, event=event)
    return event, obs


class TestBatchPolicyEnvelope(unittest.TestCase):
    def test_default_envelope_valid(self):
        config = BatchConfig()
        orch = BatchOrchestrator(config)
        queries = orch.determine_batch_queries()
        self.assertEqual(queries, [("example.com", "dns_a"), ("iana.org", "dns_a")])

    def test_domain_count_exceeded_raises_scope_denied(self):
        config = BatchConfig(domains=["example.com", "iana.org", "extra.com"])
        orch = BatchOrchestrator(config)
        with self.assertRaises(ScopeDenied):
            orch.determine_batch_queries()

    def test_disallowed_domain_raises_scope_denied(self):
        config = BatchConfig(domains=["example.com", "google.com"])
        orch = BatchOrchestrator(config)
        with self.assertRaises(ScopeDenied):
            orch.determine_batch_queries()

    def test_duplicate_domain_in_single_batch_raises_scope_denied(self):
        # Enforces the 30-minute per-domain cooldown: cannot query same domain twice in one batch
        config = BatchConfig(
            explicit_queries=[("example.com", "dns_a"), ("example.com", "dns_aaaa")]
        )
        orch = BatchOrchestrator(config)
        with self.assertRaisesRegex(ScopeDenied, "cooldown"):
            orch.determine_batch_queries()

    def test_canonical_domain_uniqueness_enforced(self):
        # Case variation and trailing dots must resolve to duplicate detection
        config = BatchConfig(domains=["example.com", "EXAMPLE.COM."])
        orch = BatchOrchestrator(config)
        with self.assertRaisesRegex(ScopeDenied, "duplicate"):
            orch.determine_batch_queries()

    def test_batch_query_ceiling_exceeded_raises_scope_denied(self):
        config = BatchConfig(
            explicit_queries=[
                ("d1.com", "dns_a"),
                ("d2.com", "dns_a"),
                ("d3.com", "dns_a"),
                ("d4.com", "dns_a"),
                ("d5.com", "dns_a"),
            ]
        )
        orch = BatchOrchestrator(config)
        with self.assertRaises(ScopeDenied):
            orch.determine_batch_queries()


class TestQueryAlternation(unittest.TestCase):
    def test_alternation_with_empty_store_defaults_to_dns_a(self):
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "store.sqlite"
            config = BatchConfig(domains=["example.com"], store_db_path=store_db)
            orch = BatchOrchestrator(config)
            queries = orch.determine_batch_queries()
            self.assertEqual(queries, [("example.com", "dns_a")])

    def test_alternation_after_dns_a_yields_dns_aaaa(self):
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "store.sqlite"
            store = RealObservationStore(store_db)
            event, obs = make_dummy_event_and_obs("example.com", "dns_a")
            store.insert_record(event, obs)

            config = BatchConfig(domains=["example.com"], store_db_path=store_db)
            orch = BatchOrchestrator(config)
            queries = orch.determine_batch_queries()
            self.assertEqual(queries, [("example.com", "dns_aaaa")])

    def test_alternation_after_dns_aaaa_yields_dns_a(self):
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "store.sqlite"
            store = RealObservationStore(store_db)
            event, obs = make_dummy_event_and_obs("example.com", "dns_aaaa")
            store.insert_record(event, obs)

            config = BatchConfig(domains=["example.com"], store_db_path=store_db)
            orch = BatchOrchestrator(config)
            queries = orch.determine_batch_queries()
            self.assertEqual(queries, [("example.com", "dns_a")])

    def test_live_mode_store_read_error_fails_closed(self):
        # Database errors in live mode must not be silently swallowed
        with TemporaryDirectory() as tmp:
            store_db = Path(tmp) / "corrupt_store.sqlite"
            store_db.write_bytes(b"CORRUPT STORE FILE")
            config = BatchConfig(domains=["example.com"], mode="live", store_db_path=store_db)
            orch = BatchOrchestrator(config)
            with self.assertRaises(RuntimeError):
                orch.determine_batch_queries()


class TestFailClosedExecutionModes(unittest.TestCase):
    def test_batch_config_rejects_invalid_mode(self):
        for invalid_mode in ["", "invalid", "backdoor", "LIVE", None]:
            with self.assertRaises(ValueError):
                BatchConfig(mode=invalid_mode)  # type: ignore

    def test_execute_batch_rejects_unexpected_mode_directly(self):
        # Bypassing __post_init__ via object mutation must still fail closed in execute_batch
        config = BatchConfig(mode="dry_run")
        object.__setattr__(config, "mode", "unauthorized_mode")
        orch = BatchOrchestrator(config)
        report = orch.execute_batch()
        self.assertEqual(report.outcome, "FAILED")
        self.assertIn("invalid execution mode", report.reason)

    def test_programmatic_api_cannot_bypass_live_auth(self):
        with TemporaryDirectory() as tmp:
            config = BatchConfig(
                mode="live",
                quota_db_path=Path(tmp) / "quota.sqlite",
                store_db_path=Path(tmp) / "store.sqlite",
            )
            orch = BatchOrchestrator(config)
            with patch.dict(os.environ, {}, clear=True):
                report = orch.execute_batch()
                self.assertEqual(report.outcome, "FAILED")
                self.assertIn("live collection unauthorized", report.reason)

    def test_live_mode_with_env_authorization_succeeds(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            log_f = Path(tmp) / "collector.jsonl"
            config = BatchConfig(
                domains=["example.com"],
                mode="live",
                quota_db_path=q_db,
                store_db_path=s_db,
                log_file_path=log_f,
            )

            mock_collector = MagicMock()
            event, obs = make_dummy_event_and_obs("example.com", "dns_a")
            mock_collector.collect.return_value = (event, obs)

            orch = BatchOrchestrator(
                config,
                collector_factory=lambda **kw: mock_collector,
                mem_fn=lambda: 512,
                disk_fn=lambda p: 1000,
            )

            with patch.dict(os.environ, {"ANIE_LIVE_COLLECTION_AUTHORIZED": "1"}):
                report = orch.execute_batch()
                self.assertEqual(report.outcome, "SUCCESS")
                self.assertEqual(report.mode, "live")
                self.assertEqual(report.queries_succeeded, 1)
                self.assertIn(obs.observation_id, report.records_persisted["observation_ids"])
                # Verify persisted in store_db
                store = RealObservationStore(s_db)
                loaded = store.get_observation(obs.observation_id)
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded.subject, "example.com")

    def test_live_mode_partial_failure(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            config = BatchConfig(
                domains=["example.com", "iana.org"],
                mode="live",
                quota_db_path=q_db,
                store_db_path=s_db,
            )

            mock_collector = MagicMock()
            event, obs = make_dummy_event_and_obs("example.com", "dns_a")
            mock_collector.collect.side_effect = [(event, obs), RuntimeError("mock network timeout")]

            orch = BatchOrchestrator(
                config,
                collector_factory=lambda **kw: mock_collector,
                mem_fn=lambda: 512,
                disk_fn=lambda p: 1000,
            )

            with patch.dict(os.environ, {"ANIE_LIVE_COLLECTION_AUTHORIZED": "1"}):
                report = orch.execute_batch()
                self.assertEqual(report.outcome, "PARTIAL")
                self.assertEqual(report.queries_succeeded, 1)
                self.assertEqual(report.queries_failed, 1)


class TestFailClosedHostMetrics(unittest.TestCase):
    def test_unknown_memory_availability_fails_closed_in_preflight(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            rep = run_preflight_checks(
                quota_db_path=q_db,
                store_db_path=s_db,
                mem_fn=lambda: None,  # OS metrics unavailable
                disk_fn=lambda p: 1000,
            )
            self.assertFalse(rep.passed)
            self.assertTrue(rep.operational_error)
            self.assertIn("operational error: host memory availability cannot be determined", rep.failure_reason)

    def test_unknown_memory_causes_batch_to_fail(self):
        with TemporaryDirectory() as tmp:
            config = BatchConfig(
                quota_db_path=Path(tmp) / "quota.sqlite",
                store_db_path=Path(tmp) / "store.sqlite",
            )
            orch = BatchOrchestrator(
                config,
                mem_fn=lambda: None,
                disk_fn=lambda p: 1000,
            )
            report = orch.execute_batch()
            self.assertEqual(report.outcome, "FAILED")
            self.assertIn("host memory availability cannot be determined", report.reason)

    def test_threshold_validation_rejects_invalid_values(self):
        for bad_val in [0, -10, float("nan"), float("inf"), "100", None, True]:
            with self.assertRaises((ValueError, TypeError)):
                BatchConfig(min_mem_mb=bad_val)  # type: ignore
            with self.assertRaises((ValueError, TypeError)):
                BatchConfig(min_disk_mb=bad_val)  # type: ignore

    def test_timeout_validation_rejects_invalid_values(self):
        for bad_timeout in [0.0, -1.0, 26.0, 50.0, float("nan"), float("inf"), "20.0", None]:
            with self.assertRaises((ValueError, TypeError)):
                BatchConfig(timeout_seconds=bad_timeout)  # type: ignore

    def test_distinguish_resource_shortage_from_operational_error(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"

            # Genuine resource shortage -> SKIPPED
            rep_shortage = run_preflight_checks(
                quota_db_path=q_db,
                store_db_path=s_db,
                min_mem_mb=200,
                mem_fn=lambda: 150,  # Below threshold
                disk_fn=lambda p: 1000,
            )
            self.assertFalse(rep_shortage.passed)
            self.assertFalse(rep_shortage.operational_error)

            # Operational error -> FAILED
            rep_op_err = run_preflight_checks(
                quota_db_path=q_db,
                store_db_path=s_db,
                mem_fn=lambda: None,  # Metric failure
                disk_fn=lambda p: 1000,
            )
            self.assertFalse(rep_op_err.passed)
            self.assertTrue(rep_op_err.operational_error)


class TestMonotonicBatchDeadline(unittest.TestCase):
    def test_sequential_query_exhaustion_under_batch_deadline(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            config = BatchConfig(
                domains=["example.com", "iana.org"],
                mode="live",
                quota_db_path=q_db,
                store_db_path=s_db,
                timeout_seconds=0.1,  # Strict tight batch timeout
            )

            mock_collector = MagicMock()
            event, obs = make_dummy_event_and_obs("example.com", "dns_a")

            def slow_first_query(domain, kind, timeout_seconds=None):
                time.sleep(0.15)  # Exhausts the 0.1s batch deadline
                return event, obs

            mock_collector.collect.side_effect = slow_first_query

            orch = BatchOrchestrator(
                config,
                collector_factory=lambda **kw: mock_collector,
                mem_fn=lambda: 512,
                disk_fn=lambda p: 1000,
            )

            with patch.dict(os.environ, {"ANIE_LIVE_COLLECTION_AUTHORIZED": "1"}):
                report = orch.execute_batch()
                # First query succeeded after delay, but exhausted deadline for second query
                self.assertEqual(report.queries_succeeded, 1)
                self.assertEqual(report.queries_failed, 1)
                self.assertEqual(report.outcome, "PARTIAL")


class TestAdvisoryLocking(unittest.TestCase):
    def test_lock_acquisition_and_release(self):
        with TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "collector.lock"
            with acquire_collector_lock(lock_path) as f:
                self.assertIsNotNone(f)
            # Re-acquisition after release succeeds
            with acquire_collector_lock(lock_path) as f2:
                self.assertIsNotNone(f2)

    def test_concurrency_lock_contention(self):
        with TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "collector.lock"
            with acquire_collector_lock(lock_path):
                # Attempt concurrent acquisition on same lock
                with self.assertRaises(BlockingIOError):
                    with acquire_collector_lock(lock_path):
                        pass

    def test_orchestrator_skips_on_lock_contention(self):
        with TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "collector.lock"
            config = BatchConfig(
                quota_db_path=Path(tmp) / "quota.sqlite",
                store_db_path=Path(tmp) / "store.sqlite",
                lock_file_path=lock_path,
            )
            orch = BatchOrchestrator(
                config,
                mem_fn=lambda: 512,
                disk_fn=lambda p: 1000,
            )
            with acquire_collector_lock(lock_path):
                report = orch.execute_batch()
                self.assertEqual(report.outcome, "SKIPPED")
                self.assertIn("concurrency lock contention", report.reason)


class TestDryRunTelemetry(unittest.TestCase):
    def test_dry_run_reports_zero_execution_metrics(self):
        with TemporaryDirectory() as tmp:
            config = BatchConfig(
                domains=["example.com", "iana.org"],
                mode="dry_run",
                quota_db_path=Path(tmp) / "quota.sqlite",
                store_db_path=Path(tmp) / "store.sqlite",
                log_file_path=Path(tmp) / "collector.jsonl",
            )
            orch = BatchOrchestrator(
                config,
                mem_fn=lambda: 512,
                disk_fn=lambda p: 1000,
            )
            report = orch.execute_batch()
            self.assertEqual(report.outcome, "SUCCESS")
            self.assertEqual(report.mode, "dry_run")
            # Invariants: dry run does NOT report real query execution
            self.assertEqual(report.queries_planned, 2)
            self.assertEqual(report.queries_attempted, 0)
            self.assertEqual(report.queries_succeeded, 0)
            self.assertEqual(report.queries_failed, 0)
            self.assertEqual(report.queries_skipped, 0)
            self.assertEqual(report.records_persisted, {"observation_ids": [], "event_ids": []})
            self.assertTrue(config.log_file_path.exists())


class TestTelemetryAndRotation(unittest.TestCase):
    def test_telemetry_emission_and_rotation(self):
        with TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "collector.jsonl"
            # Emit first record with tiny max_bytes threshold to trigger rotation on next
            rec1 = {"batch_id": "test_1", "outcome": "SUCCESS", "padding": "x" * 200}
            self.assertTrue(emit_telemetry(rec1, log_path, max_bytes=100))
            self.assertTrue(log_path.exists())

            # Emit second record - should trigger rotation to .jsonl.1
            rec2 = {"batch_id": "test_2", "outcome": "SUCCESS"}
            self.assertTrue(emit_telemetry(rec2, log_path, max_bytes=100))

            backup_path = log_path.with_suffix(".jsonl.1")
            self.assertTrue(backup_path.exists())
            self.assertTrue(log_path.exists())

            # Read log lines
            line1 = backup_path.read_text(encoding="utf-8").strip()
            self.assertEqual(json.loads(line1)["batch_id"], "test_1")
            line2 = log_path.read_text(encoding="utf-8").strip()
            self.assertEqual(json.loads(line2)["batch_id"], "test_2")


class TestCliIntegration(unittest.TestCase):
    def test_cli_dry_run_default(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            log_f = Path(tmp) / "collector.jsonl"
            exit_code = cli_main([
                "collect-batch",
                "--domains", "example.com",
                "--quota-db", str(q_db),
                "--store-db", str(s_db),
                "--log-file", str(log_f),
                "--mode", "dry_run",
            ])
            self.assertEqual(exit_code, 0)
            self.assertTrue(log_f.exists())

    def test_cli_live_unauthorized_fails_with_code_1(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            with patch.dict(os.environ, {}, clear=True):
                exit_code = cli_main([
                    "collect-batch",
                    "--live",
                    "--quota-db", str(q_db),
                    "--store-db", str(s_db),
                ])
                self.assertEqual(exit_code, 1)

    def test_cli_partial_outcome_returns_exit_code_1(self):
        with TemporaryDirectory() as tmp:
            q_db = Path(tmp) / "quota.sqlite"
            s_db = Path(tmp) / "store.sqlite"
            # Mock BatchOrchestrator.execute_batch to return PARTIAL outcome
            partial_rep = BatchReport(
                batch_id="test_partial",
                started_at="2026-11-12T12:00:00Z",
                completed_at="2026-11-12T12:00:01Z",
                duration_seconds=1.0,
                mode="live",
                outcome="PARTIAL",
                queries_attempted=2,
                queries_succeeded=1,
                queries_failed=1,
            )
            with patch("anie.orchestrator.BatchOrchestrator.execute_batch", return_value=partial_rep):
                exit_code = cli_main([
                    "collect-batch",
                    "--quota-db", str(q_db),
                    "--store-db", str(s_db),
                ])
                self.assertEqual(exit_code, 1)


class TestSystemdConfiguration(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parent.parent
        self.service_path = repo_root / "systemd" / "anie-collector.service"
        self.timer_path = repo_root / "systemd" / "anie-collector.timer"
        self.readme_path = repo_root / "systemd" / "README.md"

    def test_service_unit_file_directives(self):
        self.assertTrue(self.service_path.exists(), f"missing {self.service_path}")
        content = self.service_path.read_text(encoding="utf-8")

        # Required oneshot timeout semantics
        self.assertIn("Type=oneshot", content)
        self.assertIn("TimeoutStartSec=30s", content)
        self.assertIn("TimeoutStopSec=15s", content)
        self.assertIn("KillMode=control-group", content)
        self.assertIn("Restart=no", content)

        # RuntimeMaxSec MUST NOT be present for Type=oneshot
        self.assertNotIn("RuntimeMaxSec=", content)

        # Resource limits for 1 GiB micro instance
        self.assertIn("MemoryMax=128M", content)
        self.assertIn("MemoryHigh=96M", content)
        self.assertIn("CPUQuota=20%", content)
        self.assertIn("Nice=19", content)

        # Hardening and isolation
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("ProtectHome=yes", content)
        self.assertIn("CapabilityBoundingSet=", content)
        self.assertIn("NoNewPrivileges=yes", content)
        self.assertIn("User=anie", content)
        self.assertIn("Group=anie", content)

    def test_timer_unit_file_directives(self):
        self.assertTrue(self.timer_path.exists(), f"missing {self.timer_path}")
        content = self.timer_path.read_text(encoding="utf-8")

        self.assertIn("Unit=anie-collector.service", content)
        self.assertIn("OnCalendar=*-*-* 06:00:00 UTC", content)
        self.assertIn("RandomizedDelaySec=300s", content)
        self.assertIn("Persistent=false", content)

    def test_systemd_readme_documents_timeout_and_dstate(self):
        self.assertTrue(self.readme_path.exists(), f"missing {self.readme_path}")
        content = self.readme_path.read_text(encoding="utf-8")

        # Documents why RuntimeMaxSec does not apply to Type=oneshot
        self.assertIn("RuntimeMaxSec", content)
        self.assertIn("TimeoutStartSec", content)

        # Documents kernel uninterruptible sleep (D-state) caveat
        self.assertIn("TASK_UNINTERRUPTIBLE", content)
        self.assertIn("D-state", content)

        # Documents cadence comparison (Daily vs 4-Hour)
        self.assertIn("4-Hour", content)
        self.assertIn("Daily", content)

        # Documents emergency rollback
        self.assertIn("Rollback", content)


if __name__ == "__main__":
    unittest.main()
