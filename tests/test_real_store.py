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

    def test_event_id_collision_conflicting_payload_rejected(self):
        from unittest.mock import patch, PropertyMock
        event = sample_event()
        obs = sample_observation(event=event)
        self.assertTrue(self.store.insert_record(event, obs))

        # Attempt to insert a conflicting event through API with matching event_id but altered payload
        conflicting_event = sample_event(raw_payload=b"different_payload")
        target_eid = event.event_id
        with patch.object(RealCollectionEvent, "event_id", new_callable=PropertyMock) as mock_eid:
            mock_eid.side_effect = lambda: target_eid
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.insert_record(conflicting_event, obs)

    def test_observation_id_collision_conflicting_payload_rejected(self):
        from unittest.mock import patch, PropertyMock
        event = sample_event()
        obs = sample_observation(event=event)
        self.assertTrue(self.store.insert_record(event, obs))

        # Attempt to insert a conflicting observation through API with matching observation_id but altered confidence
        conflicting_obs = sample_observation(event=event, confidence=0.99)
        target_oid = obs.observation_id
        with patch.object(RealObservation, "observation_id", new_callable=PropertyMock) as mock_oid:
            mock_oid.side_effect = lambda: target_oid
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.insert_record(event, conflicting_obs)

    def test_batch_atomic_rollback_on_conflict(self):
        # Prepare 3 records; the 3rd one has a conflicting/invalid foreign key
        ev1 = sample_event(request=sample_request(subject="batch1.example.com"), raw_payload=b"wire1")
        ob1 = sample_observation(subject="batch1.example.com", event=ev1)

        ev2 = sample_event(request=sample_request(subject="batch2.example.com"), raw_payload=b"wire2")
        ob2 = sample_observation(subject="batch2.example.com", event=ev2)

        # ev3 is valid, but ob3 deliberately references a non-existent evidence_id
        ev3 = sample_event(request=sample_request(subject="batch3.example.com"), raw_payload=b"wire3")
        ob3 = sample_observation(
            subject="batch3.example.com",
            evidence_id="event_0000000000000000000000000000000000000000000000000000000000000000",
        )

        with self.assertRaises(ValueError):
            # Fails referential match check before commit, rolling back entire batch
            self.store.insert_batch([(ev1, ob1), (ev2, ob2), (ev3, ob3)])

        # Assert atomic rollback: NONE of the batch records were committed
        self.assertEqual(len(self.store.all_observations()), 0)
        self.assertIsNone(self.store.get_event(ev1.event_id))

    def test_batch_atomic_rollback_on_database_conflict(self):
        from unittest.mock import patch, PropertyMock
        ev1 = sample_event(request=sample_request(subject="batch1.example.com"), raw_payload=b"wire1")
        ob1 = sample_observation(subject="batch1.example.com", event=ev1)
        self.store.insert_record(ev1, ob1)

        ev2 = sample_event(request=sample_request(subject="batch2.example.com"), raw_payload=b"wire2")
        ob2 = sample_observation(subject="batch2.example.com", event=ev2)

        # Create a conflicting observation with identical ID but altered confidence
        ob1_conflicting = sample_observation(
            subject="batch1.example.com",
            event=ev1,
            confidence=0.5,
        )
        target_id = ob1.observation_id
        with patch.object(RealObservation, "observation_id", new_callable=PropertyMock) as mock_id:
            mock_id.side_effect = lambda: target_id
            with self.assertRaises(sqlite3.IntegrityError):
                self.store.insert_batch([(ev1, ob1_conflicting), (ev2, ob2)])

        # Verify ev2 was NOT committed due to rollback
        self.assertIsNone(self.store.get_event(ev2.event_id))
        self.assertIsNone(self.store.get_observation(ob2.observation_id))

    def test_raw_evidence_hash_verified_on_load_and_export(self):
        event = sample_event(raw_payload=b"verified_wire_packet")
        obs = sample_observation(event=event)
        self.store.insert_record(event, obs)

        # Normal load and export succeed
        loaded_ev = self.store.get_event(event.event_id)
        self.assertIsNotNone(loaded_ev)
        self.assertEqual(loaded_ev.raw_payload, b"verified_wire_packet")

        exported_events = self.store.export_events()
        self.assertEqual(len(exported_events), 1)
        self.assertEqual(exported_events[0].event_id, event.event_id)

        exported_records = self.store.export_records()
        self.assertEqual(len(exported_records), 1)
        self.assertEqual(exported_records[0][0].event_id, event.event_id)

        # Directly tamper with raw_payload BLOB in the database
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE real_events SET raw_payload = ? WHERE event_id = ?",
                (b"corrupted_bytes", event.event_id),
            )

        # Loading or exporting tampered event must fail closed with ValueError
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.store.get_event(event.event_id)

        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.store.get_event_for_observation(obs.observation_id)

        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.store.export_events()

        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.store.export_records()


if __name__ == "__main__":
    unittest.main()
