"""Tests for Phase 2 real-world SQLite store, referential integrity, and retention."""
from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from anie.real_models import (
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import CURRENT_SCHEMA_VERSION, RealObservationStore
from test_real_models import sample_event, sample_factual, sample_observation, sample_request


class TestRealObservationStore(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "state_real.sqlite"
        self.store = RealObservationStore(self.db_path)

    def tearDown(self):
        # Explicitly clean up directory
        self.tmp.cleanup()

    def test_schema_initialization_and_version(self):
        with sqlite3.connect(self.db_path) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(version, CURRENT_SCHEMA_VERSION)
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(journal.lower(), "wal")

            # Verify tables exist
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertIn("real_events", tables)
            self.assertIn("real_observations", tables)

    def test_referential_integrity_enforced_on_insert(self):
        event = sample_event()
        obs = sample_observation(event=event)

        # Successful atomic insertion
        self.assertTrue(self.store.insert_record(event, obs))
        self.assertEqual(len(self.store.all_observations()), 1)

        # Inserting observation with nonexistent evidence_id fails foreign key check
        unlinked_obs = sample_observation(
            evidence_id="event_0000000000000000000000000000000000000000000000000000000000000000"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._connect() as conn:
                conn.execute("""
                    INSERT INTO real_observations (
                        observation_id, evidence_id, subject_type, subject,
                        kind, observed_at, status, source_id, method,
                        synthetic, confidence, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    unlinked_obs.observation_id,
                    unlinked_obs.evidence_id,
                    "domain",
                    unlinked_obs.subject,
                    unlinked_obs.kind,
                    unlinked_obs.observed_at,
                    unlinked_obs.status,
                    unlinked_obs.source_id,
                    unlinked_obs.method,
                    0,
                    unlinked_obs.confidence,
                    "{}",
                ))

    def test_referential_integrity_mismatch_in_api(self):
        event1 = sample_event(raw_payload=b"packet_1")
        event2 = sample_event(raw_payload=b"packet_2")
        obs1 = sample_observation(event=event1)

        with self.assertRaisesRegex(ValueError, "referential mismatch"):
            self.store.insert_record(event2, obs1)

    def test_idempotent_ingestion(self):
        event = sample_event()
        obs = sample_observation(event=event)

        # First insert succeeds
        self.assertTrue(self.store.insert_record(event, obs))

        # Second insert with identical keys is ignored
        self.assertFalse(self.store.insert_record(event, obs))
        self.assertEqual(len(self.store.all_observations()), 1)

    def test_database_constraint_rejects_synthetic_observations(self):
        event = sample_event()
        obs = sample_observation(event=event)
        self.store.insert_record(event, obs)

        # Direct SQL attempt to set synthetic=1 must be rejected by CHECK(synthetic = 0)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._connect() as conn:
                conn.execute(
                    "UPDATE real_observations SET synthetic = 1 WHERE observation_id = ?",
                    (obs.observation_id,),
                )

    def test_batch_insertion(self):
        records = []
        for i in range(10):
            ev = sample_event(
                request=sample_request(subject=f"node{i}.example.com"),
                raw_payload=f"wire_data_{i}".encode(),
            )
            ob = sample_observation(
                subject=f"node{i}.example.com",
                event=ev,
                values=(f"192.0.2.{i}",),
            )
            records.append((ev, ob))

        ev_cnt, obs_cnt = self.store.insert_batch(records)
        self.assertEqual(ev_cnt, 10)
        self.assertEqual(obs_cnt, 10)
        self.assertEqual(len(self.store.all_observations()), 10)

        # Re-inserting batch is idempotent
        ev_cnt2, obs_cnt2 = self.store.insert_batch(records)
        self.assertEqual(obs_cnt2, 0)

    def test_event_delete_restricted_while_observation_exists(self):
        event = sample_event()
        obs = sample_observation(event=event)
        self.store.insert_record(event, obs)

        # Deleting event must fail due to ON DELETE RESTRICT
        with self.assertRaises(sqlite3.IntegrityError):
            with self.store._connect() as conn:
                conn.execute(
                    "DELETE FROM real_events WHERE event_id = ?",
                    (event.event_id,),
                )

    def test_retention_pruning_invariants(self):
        # Create old records (2026-01-01) and newer records (2026-11-01)
        old_ev = sample_event(
            request=sample_request(observed_at="2026-01-01T00:00:00Z"),
            observed_at="2026-01-01T00:00:00Z",
            raw_payload=b"old_packet",
        )
        old_obs = sample_observation(
            observed_at="2026-01-01T00:00:00Z",
            event=old_ev,
        )

        new_ev = sample_event(
            request=sample_request(observed_at="2026-11-01T00:00:00Z"),
            observed_at="2026-11-01T00:00:00Z",
            raw_payload=b"new_packet",
        )
        new_obs = sample_observation(
            observed_at="2026-11-01T00:00:00Z",
            event=new_ev,
        )

        self.store.insert_record(old_ev, old_obs)
        self.store.insert_record(new_ev, new_obs)
        self.assertEqual(len(self.store.all_observations()), 2)

        # 1. Pruning observations older than 2026-06-01 deletes 1 observation
        deleted_obs = self.store.prune_observations_older_than("2026-06-01T00:00:00Z")
        self.assertEqual(deleted_obs, 1)
        self.assertEqual(len(self.store.all_observations()), 1)

        # The old event still exists (preserving evidence until explicitly cleaned)
        self.assertIsNotNone(self.store.get_event(old_ev.event_id))

        # 2. Pruning unreferenced events now safely removes the old orphaned event
        deleted_events = self.store.prune_unreferenced_events()
        self.assertEqual(deleted_events, 1)
        self.assertIsNone(self.store.get_event(old_ev.event_id))

        # The new event and observation remain intact
        self.assertIsNotNone(self.store.get_event(new_ev.event_id))
        self.assertIsNotNone(self.store.get_observation(new_obs.observation_id))

        # Foreign key integrity check passes
        self.assertEqual(self.store.check_referential_integrity(), [])

    def test_two_phase_prune_retention(self):
        ev = sample_event(
            request=sample_request(observed_at="2026-01-01T00:00:00Z"),
            observed_at="2026-01-01T00:00:00Z",
            raw_payload=b"packet_phase",
        )
        obs = sample_observation(
            observed_at="2026-01-01T00:00:00Z",
            event=ev,
        )
        self.store.insert_record(ev, obs)

        # Execute two-phase retention
        obs_del, ev_del = self.store.prune_retention(
            observation_cutoff_iso="2026-06-01T00:00:00Z",
            event_cutoff_iso="2026-06-01T00:00:00Z",
        )
        self.assertEqual(obs_del, 1)
        self.assertEqual(ev_del, 1)
        self.assertEqual(self.store.check_referential_integrity(), [])

    def test_durability_and_checkpointing(self):
        event = sample_event()
        obs = sample_observation(event=event)
        self.store.insert_record(event, obs)

        # Checkpoint WAL
        busy, log, checkpointed = self.store.checkpoint_wal(truncate=True)
        self.assertEqual(busy, 0)
        self.assertTrue(self.store.db_size_bytes() > 0)

        # Reopen database in strict FULL sync mode
        store_full = RealObservationStore(self.db_path, synchronous="FULL")
        loaded = store_full.get_observation(obs.observation_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.observation_id, obs.observation_id)

    def test_schema_migration_framework(self):
        # Verify user_version migration hook
        with self.store._connect() as conn:
            self.store._migrate(conn, from_version=1, to_version=2)
            new_ver = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(new_ver, 2)


if __name__ == "__main__":
    unittest.main()
