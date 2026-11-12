"""Real-world SQLite observation store and provenance ledger.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 1).

Durability and Crash Recovery Architecture:
------------------------------------------
This store operates SQLite in Write-Ahead Logging (WAL) mode:
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 10000;

Durability Guarantees:
1. Under `PRAGMA synchronous = NORMAL` (default for micro shape efficiency):
   - Application crashes (process termination, SIGKILL): Zero data loss.
   - OS crashes / power loss: Database structure is immune to corruption, but the
     most recent un-checkpointed transaction writes might roll back if OS cache
     was not flushed to disk.
   - Crash Recovery: On subsequent open, SQLite automatically inspects the WAL file,
     replays completed transactions, rolls back incomplete ones, and reconstructs
     a consistent database state.
2. Under `PRAGMA synchronous = FULL` (strict mode):
   - Guarantees physical sync (`fsync`) of WAL pages to non-volatile storage on every
     commit, eliminating transaction loss even under sudden host power loss, at the
     expense of higher disk I/O latency.
3. Systemd cgroups bounding (MemoryMax, CPUQuota, IO priority) manage process contention
   to prevent starvation of interactive host services, but cannot by themselves
   guarantee SSH responsiveness if kernel contention, disk saturation, or hypervisor
   I/O limits are reached.

Referential Integrity & Retention Invariants:
--------------------------------------------
- Every `real_observation` MUST reference an existing `real_event` (`ON DELETE RESTRICT`).
- Foreign key enforcement is mandatory (`PRAGMA foreign_keys = ON`).
- Evidence retention invariant: A provenance event cannot be pruned or deleted while
  any dependent observation references it. Pruning must delete expired observations first,
  and only then prune unreferenced events.
- Anti-Cross-Contamination:
  - Table constraint `CHECK(synthetic = 0)` prevents any synthetic observation row
    from ever being stored in `real_observations`.
  - Type-checking rejects synthetic `Observation` instances at the Python API boundary.
"""
from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any

from .observations import canonical_json, Observation
from .real_models import (
    REAL_EVENT_SCHEMA,
    REAL_OBSERVATION_SCHEMA,
    RealCollectionEvent,
    RealObservation,
)

CURRENT_SCHEMA_VERSION = 1


class RealObservationStore:
    """ACID-compliant SQLite store for genuine first-party observations and evidence."""

    def __init__(self, path: str | Path, synchronous: str = "NORMAL"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if synchronous not in {"NORMAL", "FULL", "EXTRA"}:
            raise ValueError(f"unsupported synchronous mode: {synchronous}")
        self.synchronous = synchronous
        self._init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute(f"PRAGMA synchronous = {self.synchronous}")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize tables and run migrations if necessary."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Check user_version for migrations
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._apply_schema_v1(conn)
                conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
            elif version < CURRENT_SCHEMA_VERSION:
                self._migrate(conn, version, CURRENT_SCHEMA_VERSION)

    def _apply_schema_v1(self, conn: sqlite3.Connection) -> None:
        """Initial schema creation."""
        # 1. Forensic Raw Event Ledger
        conn.execute("""
            CREATE TABLE IF NOT EXISTS real_events (
                event_id TEXT PRIMARY KEY,
                schema TEXT NOT NULL,
                subject TEXT NOT NULL,
                kind TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                response_code TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL,
                raw_evidence_status TEXT NOT NULL,
                raw_payload BLOB,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_real_events_subject_time 
            ON real_events(subject, observed_at, event_id)
        """)

        # 2. Normalized Real Observations (with referential integrity to events)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS real_observations (
                observation_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL REFERENCES real_events(event_id) ON DELETE RESTRICT,
                subject_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                kind TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                source_id TEXT NOT NULL,
                method TEXT NOT NULL,
                synthetic INTEGER NOT NULL CHECK(synthetic = 0),
                confidence REAL,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_real_obs_subject_time 
            ON real_observations(subject_type, subject, observed_at, observation_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_real_obs_evidence 
            ON real_observations(evidence_id)
        """)

    def _migrate(self, conn: sqlite3.Connection, from_version: int, to_version: int) -> None:
        """Incremental database schema migration framework."""
        # Future migrations:
        # if from_version < 2 and to_version >= 2:
        #     ...
        conn.execute(f"PRAGMA user_version = {to_version}")

    def insert_record(self, event: RealCollectionEvent, observation: RealObservation) -> bool:
        """Atomically insert a provenance event and its dependent observation.
        
        Idempotent: Uses INSERT OR IGNORE.
        Returns True if the observation was newly inserted, False if already present.
        """
        # Strict Cross-Pipeline Protection
        if isinstance(observation, Observation):
            raise TypeError("synthetic Observation cannot enter RealObservationStore")
        if not isinstance(observation, RealObservation):
            raise TypeError(f"expected RealObservation, got {type(observation)}")
        if not isinstance(event, RealCollectionEvent):
            raise TypeError(f"expected RealCollectionEvent, got {type(event)}")
        if observation.synthetic is not False:
            raise ValueError("real observation must have synthetic=False")
        if observation.evidence_id != event.event_id:
            raise ValueError(
                f"referential mismatch: observation.evidence_id ({observation.evidence_id}) "
                f"does not match event.event_id ({event.event_id})"
            )

        with self._connect() as conn:
            # 1. Insert Event
            conn.execute("""
                INSERT OR IGNORE INTO real_events (
                    event_id, schema, subject, kind, observed_at,
                    response_code, raw_sha256, raw_evidence_status,
                    raw_payload, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                REAL_EVENT_SCHEMA,
                event.request.subject,
                event.request.kind,
                event.observed_at,
                event.response_code,
                event.raw_sha256,
                event.raw_evidence_status,
                event.raw_payload,
                canonical_json(event.to_dict()),
            ))

            # 2. Insert Observation
            prev_changes = conn.total_changes
            conn.execute("""
                INSERT OR IGNORE INTO real_observations (
                    observation_id, evidence_id, subject_type, subject,
                    kind, observed_at, status, source_id, method,
                    synthetic, confidence, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                observation.observation_id,
                observation.evidence_id,
                "domain" if observation.kind in {"dns_a", "dns_aaaa"} else "ip",
                observation.subject,
                observation.kind,
                observation.observed_at,
                observation.status,
                observation.source_id,
                observation.method,
                0,  # synthetic = 0
                observation.confidence,
                canonical_json(observation.to_dict()),
            ))
            return (conn.total_changes - prev_changes) == 1

    def insert_batch(
        self,
        records: Iterable[tuple[RealCollectionEvent, RealObservation]],
    ) -> tuple[int, int]:
        """Atomically insert a batch of (event, observation) pairs.
        
        Batch size is bounded to 5,000 pairs per call.
        Returns (events_inserted, observations_inserted).
        """
        event_rows = []
        obs_rows = []
        seen_event_ids: set[str] = set()

        for event, obs in records:
            if isinstance(obs, Observation):
                raise TypeError("synthetic Observation cannot enter RealObservationStore")
            if not isinstance(obs, RealObservation) or not isinstance(event, RealCollectionEvent):
                raise TypeError("batch items must be tuples of (RealCollectionEvent, RealObservation)")
            if obs.synthetic is not False:
                raise ValueError("real observation must have synthetic=False")
            if obs.evidence_id != event.event_id:
                raise ValueError(f"referential mismatch for event {event.event_id} and observation {obs.observation_id}")

            if event.event_id not in seen_event_ids:
                seen_event_ids.add(event.event_id)
                event_rows.append((
                    event.event_id,
                    REAL_EVENT_SCHEMA,
                    event.request.subject,
                    event.request.kind,
                    event.observed_at,
                    event.response_code,
                    event.raw_sha256,
                    event.raw_evidence_status,
                    event.raw_payload,
                    canonical_json(event.to_dict()),
                ))

            obs_rows.append((
                obs.observation_id,
                obs.evidence_id,
                "domain" if obs.kind in {"dns_a", "dns_aaaa"} else "ip",
                obs.subject,
                obs.kind,
                obs.observed_at,
                obs.status,
                obs.source_id,
                obs.method,
                0,
                obs.confidence,
                canonical_json(obs.to_dict()),
            ))

            if len(obs_rows) > 5000:
                raise ValueError("batch size must not exceed 5000 items")

        if not obs_rows:
            return (0, 0)

        with self._connect() as conn:
            # Insert all events first
            conn.executemany("""
                INSERT OR IGNORE INTO real_events (
                    event_id, schema, subject, kind, observed_at,
                    response_code, raw_sha256, raw_evidence_status,
                    raw_payload, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, event_rows)

            # Insert all observations second
            prev_changes = conn.total_changes
            conn.executemany("""
                INSERT OR IGNORE INTO real_observations (
                    observation_id, evidence_id, subject_type, subject,
                    kind, observed_at, status, source_id, method,
                    synthetic, confidence, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, obs_rows)
            obs_inserted = conn.total_changes - prev_changes

            # Compute actual event inserts
            return (len(event_rows), obs_inserted)

    def get_observation(self, observation_id: str) -> RealObservation | None:
        """Fetch a real observation by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM real_observations WHERE observation_id = ?",
                (observation_id,),
            ).fetchone()
            if not row:
                return None
            return RealObservation.from_dict(json.loads(row[0]))

    def get_event(self, event_id: str) -> RealCollectionEvent | None:
        """Fetch a provenance collection event by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM real_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if not row:
                return None
            return RealCollectionEvent.from_dict(json.loads(row[0]))

    def get_event_for_observation(self, observation_id: str) -> RealCollectionEvent | None:
        """Fetch the linked provenance event for an observation."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT e.payload FROM real_events e
                JOIN real_observations o ON o.evidence_id = e.event_id
                WHERE o.observation_id = ?
            """, (observation_id,)).fetchone()
            if not row:
                return None
            return RealCollectionEvent.from_dict(json.loads(row[0]))

    def by_subject(self, subject: str, limit: int = 1000) -> list[RealObservation]:
        """Fetch real observations for a subject ordered by observation time."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT payload FROM real_observations
                WHERE subject = ?
                ORDER BY observed_at, observation_id
                LIMIT ?
            """, (subject, limit)).fetchall()
            return [RealObservation.from_dict(json.loads(r[0])) for r in rows]

    def all_observations(self, limit: int = 10000) -> list[RealObservation]:
        """Fetch all real observations up to limit."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT payload FROM real_observations
                ORDER BY observed_at, observation_id
                LIMIT ?
            """, (limit,)).fetchall()
            return [RealObservation.from_dict(json.loads(r[0])) for r in rows]

    # --- Retention & Referential Invariants ---

    def prune_observations_older_than(self, cutoff_iso: str) -> int:
        """Prune observations strictly older than cutoff timestamp.
        
        Preserves all linked events; events are NEVER pruned here.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM real_observations WHERE observed_at < ?",
                (cutoff_iso,),
            )
            return cur.rowcount

    def prune_unreferenced_events(self) -> int:
        """Prune provenance events that have NO dependent observations.
        
        Guarantees that an event is never deleted while an observation references it.
        """
        with self._connect() as conn:
            cur = conn.execute("""
                DELETE FROM real_events
                WHERE event_id NOT IN (SELECT evidence_id FROM real_observations)
            """)
            return cur.rowcount

    def prune_retention(
        self,
        observation_cutoff_iso: str,
        event_cutoff_iso: str,
    ) -> tuple[int, int]:
        """Execute two-phase ordered retention pruning.
        
        Phase 1: Prune expired observations older than observation_cutoff_iso.
        Phase 2: Prune events older than event_cutoff_iso that are unreferenced.
        
        Returns (observations_deleted, events_deleted).
        """
        with self._connect() as conn:
            # Phase 1: Prune observations
            cur_obs = conn.execute(
                "DELETE FROM real_observations WHERE observed_at < ?",
                (observation_cutoff_iso,),
            )
            obs_deleted = cur_obs.rowcount

            # Phase 2: Prune unreferenced events older than event_cutoff
            cur_events = conn.execute("""
                DELETE FROM real_events
                WHERE observed_at < ?
                  AND event_id NOT IN (SELECT evidence_id FROM real_observations)
            """, (event_cutoff_iso,))
            events_deleted = cur_events.rowcount

            return (obs_deleted, events_deleted)

    def check_referential_integrity(self) -> list[tuple[Any, ...]]:
        """Verify SQLite foreign key integrity.
        
        Returns empty list if 100% intact; non-empty list on violations.
        """
        with self._connect() as conn:
            return conn.execute("PRAGMA foreign_key_check").fetchall()

    def db_size_bytes(self) -> int:
        """Calculate active SQLite database file size in bytes."""
        with self._connect() as conn:
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            return page_count * page_size

    def checkpoint_wal(self, truncate: bool = True) -> tuple[int, int, int]:
        """Perform WAL checkpointing to bound disk usage."""
        mode = "TRUNCATE" if truncate else "PASSIVE"
        with self._connect() as conn:
            res = conn.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()
            return (res[0], res[1], res[2])
