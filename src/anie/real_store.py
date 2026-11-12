"""Real-world SQLite observation store and provenance ledger.

Part of ANIE Phase 2 First-Party Intelligence Architecture (PR 1).

Durability and Crash-Recovery Semantics:
---------------------------------------
This store operates SQLite in Write-Ahead Logging (WAL) mode:
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 10000;

Durability and Persistence Considerations:
1. Under `PRAGMA synchronous = NORMAL` (default for micro shape I/O balance):
   - Application crash (SIGKILL, process termination): Committed transactions
     reside in the WAL / OS page cache and are recovered automatically on next open.
   - OS crash / sudden power loss: Structural integrity of the database file
     is protected against corruption, but durability is NOT absolute: the most
     recently committed transactions in the WAL that have not yet been flushed by
     the operating system or storage controller to non-volatile media may be lost
     (reverted to a prior consistent state).
   - Recovery: Automatic upon the first subsequent database connection via SQLite's
     built-in WAL replay mechanism.
2. Under `PRAGMA synchronous = FULL` (strict durability mode):
   - Every transaction commit issues an `fsync()` system call on the WAL file before
     returning control.
   - Durability against sudden OS crash or power interruption is substantially higher,
     dependent on underlying filesystem barrier semantics and whether the storage
     controller honors flush commands without volatile write-cache deceit.
   - Trade-off: Higher disk I/O latency on resource-constrained micro shapes (such as
     Oracle Cloud VM.Standard.E2.1.Micro with remote network-attached block volumes).
3. Resource limits and host responsiveness:
   - Systemd cgroup constraints (e.g. MemoryMax, CPUQuota) and process scheduling
     (e.g. Nice=19, idle I/O priority) manage user-space CPU and memory competition
     to mitigate resource starvation.
   - However, resource limits do NOT guarantee host or SSH responsiveness. Kernel-level
     lock contention, swap thrashing, network buffer saturation, or hypervisor/iSCSI
     queue stalls can still cause SSH banner timeouts or dropped connections.

Referential Integrity & Retention Invariants:
--------------------------------------------
- Every `real_observation` MUST reference an existing `real_event` (`ON DELETE RESTRICT`).
- Foreign key enforcement is mandatory (`PRAGMA foreign_keys = ON`).
- Idempotency & Collision Protection:
  - Exact identical duplicate records are accepted idempotently.
  - Conflicting records sharing an existing identifier (`event_id` or `observation_id`)
    are strictly rejected with an IntegrityError; silent overwrites and silent ignores
    of differing data are prohibited.
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
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any

from .observations import canonical_json, Observation
from .real_models import (
    MAX_RAW_PAYLOAD_BYTES,
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
        conn.execute(f"PRAGMA user_version = {to_version}")

    def insert_record(self, event: RealCollectionEvent, observation: RealObservation) -> bool:
        """Atomically insert a provenance event and its dependent observation.
        
        Strict Idempotency:
        - If an identical record exists, it is accepted as an idempotent no-op (returns False).
        - If a conflicting record with matching identifier exists, IntegrityError is raised.
        
        Returns True if the observation was newly inserted, False if already present identically.
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
        if not event.verify_raw_evidence():
            raise ValueError(f"raw evidence verification failed for event {event.event_id}")

        event_canonical = canonical_json(event.to_dict())
        obs_canonical = canonical_json(observation.to_dict())

        with self._connect() as conn:
            # 1. Check or Insert Event
            existing_event = conn.execute(
                "SELECT payload FROM real_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing_event is not None:
                if existing_event[0] != event_canonical:
                    raise sqlite3.IntegrityError(
                        f"conflicting real_event with matching event_id {event.event_id}"
                    )
            else:
                conn.execute("""
                    INSERT INTO real_events (
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
                    event_canonical,
                ))

            # 2. Check or Insert Observation
            existing_obs = conn.execute(
                "SELECT payload FROM real_observations WHERE observation_id = ?",
                (observation.observation_id,),
            ).fetchone()
            if existing_obs is not None:
                if existing_obs[0] != obs_canonical:
                    raise sqlite3.IntegrityError(
                        f"conflicting real_observation with matching observation_id {observation.observation_id}"
                    )
                return False
            else:
                conn.execute("""
                    INSERT INTO real_observations (
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
                    obs_canonical,
                ))
                return True

    def insert_batch(
        self,
        records: Iterable[tuple[RealCollectionEvent, RealObservation]],
    ) -> tuple[int, int]:
        """Atomically insert a batch of (event, observation) pairs.
        
        Strict Collision Protection:
        - Re-inserting identical records is accepted idempotently.
        - Any conflicting identifier in batch or database causes immediate IntegrityError
          and rolls back the entire batch atomically.
        
        Batch size is bounded to 5,000 pairs per call.
        Returns (events_inserted, observations_inserted).
        """
        batch_events: dict[str, tuple[RealCollectionEvent, str]] = {}
        batch_observations: dict[str, tuple[RealObservation, str]] = {}
        pair_count = 0

        for event, obs in records:
            pair_count += 1
            if pair_count > 5000:
                raise ValueError("batch size must not exceed 5000 items")

            if isinstance(obs, Observation):
                raise TypeError("synthetic Observation cannot enter RealObservationStore")
            if not isinstance(obs, RealObservation) or not isinstance(event, RealCollectionEvent):
                raise TypeError("batch items must be tuples of (RealCollectionEvent, RealObservation)")
            if obs.synthetic is not False:
                raise ValueError("real observation must have synthetic=False")
            if obs.evidence_id != event.event_id:
                raise ValueError(
                    f"referential mismatch for event {event.event_id} and observation {obs.observation_id}"
                )
            if not event.verify_raw_evidence():
                raise ValueError(f"raw evidence verification failed for event {event.event_id}")

            ev_canonical = canonical_json(event.to_dict())
            obs_canonical = canonical_json(obs.to_dict())

            # Validate intra-batch collisions
            if event.event_id in batch_events:
                if batch_events[event.event_id][1] != ev_canonical:
                    raise sqlite3.IntegrityError(
                        f"conflicting real_event in batch with event_id {event.event_id}"
                    )
            else:
                batch_events[event.event_id] = (event, ev_canonical)

            if obs.observation_id in batch_observations:
                if batch_observations[obs.observation_id][1] != obs_canonical:
                    raise sqlite3.IntegrityError(
                        f"conflicting real_observation in batch with observation_id {obs.observation_id}"
                    )
            else:
                batch_observations[obs.observation_id] = (obs, obs_canonical)

        if not batch_observations:
            return (0, 0)

        with self._connect() as conn:
            # 1. Validate events against DB and collect new events
            new_events = []
            for event_id, (event, ev_canonical) in batch_events.items():
                existing = conn.execute(
                    "SELECT payload FROM real_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != ev_canonical:
                        raise sqlite3.IntegrityError(
                            f"conflicting real_event in database with event_id {event_id}"
                        )
                else:
                    new_events.append((
                        event.event_id,
                        REAL_EVENT_SCHEMA,
                        event.request.subject,
                        event.request.kind,
                        event.observed_at,
                        event.response_code,
                        event.raw_sha256,
                        event.raw_evidence_status,
                        event.raw_payload,
                        ev_canonical,
                    ))

            # 2. Validate observations against DB and collect new observations
            new_observations = []
            for obs_id, (obs, obs_canonical) in batch_observations.items():
                existing = conn.execute(
                    "SELECT payload FROM real_observations WHERE observation_id = ?",
                    (obs_id,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != obs_canonical:
                        raise sqlite3.IntegrityError(
                            f"conflicting real_observation in database with observation_id {obs_id}"
                        )
                else:
                    new_observations.append((
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
                        obs_canonical,
                    ))

            # 3. Insert new events and observations atomically
            if new_events:
                conn.executemany("""
                    INSERT INTO real_events (
                        event_id, schema, subject, kind, observed_at,
                        response_code, raw_sha256, raw_evidence_status,
                        raw_payload, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, new_events)

            if new_observations:
                conn.executemany("""
                    INSERT INTO real_observations (
                        observation_id, evidence_id, subject_type, subject,
                        kind, observed_at, status, source_id, method,
                        synthetic, confidence, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, new_observations)

            return (len(new_events), len(new_observations))

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
        """Fetch a provenance collection event by ID, verifying raw evidence hash."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload, raw_payload, raw_sha256, raw_evidence_status FROM real_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if not row:
                return None
            payload_json, raw_blob, raw_sha256, status = row
            self._verify_stored_raw_hash(event_id, raw_blob, raw_sha256, status)
            event = RealCollectionEvent.from_dict(json.loads(payload_json))
            if not event.verify_raw_evidence():
                raise ValueError(f"raw evidence verification failed for event {event_id}")
            return event

    def get_event_for_observation(self, observation_id: str) -> RealCollectionEvent | None:
        """Fetch the linked provenance event for an observation with hash verification."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT e.event_id, e.payload, e.raw_payload, e.raw_sha256, e.raw_evidence_status
                FROM real_events e
                JOIN real_observations o ON o.evidence_id = e.event_id
                WHERE o.observation_id = ?
            """, (observation_id,)).fetchone()
            if not row:
                return None
            event_id, payload_json, raw_blob, raw_sha256, status = row
            self._verify_stored_raw_hash(event_id, raw_blob, raw_sha256, status)
            event = RealCollectionEvent.from_dict(json.loads(payload_json))
            if not event.verify_raw_evidence():
                raise ValueError(f"raw evidence verification failed for event {event_id}")
            return event

    @staticmethod
    def _verify_stored_raw_hash(
        event_id: str,
        raw_blob: bytes | None,
        raw_sha256: str,
        raw_evidence_status: str,
    ) -> None:
        """Verify stored raw BLOB matches raw_sha256."""
        if raw_evidence_status == "captured":
            if raw_blob is None:
                raise ValueError(f"missing raw payload BLOB for captured event {event_id}")
            computed = sha256(raw_blob).hexdigest()
            if computed != raw_sha256:
                raise ValueError(
                    f"raw payload BLOB hash mismatch for event {event_id}: expected {raw_sha256}, got {computed}"
                )
        elif raw_blob is not None:
            computed = sha256(raw_blob).hexdigest()
            if computed != raw_sha256:
                raise ValueError(
                    f"raw payload BLOB hash mismatch for event {event_id}: expected {raw_sha256}, got {computed}"
                )

    def export_events(self, limit: int = 10000) -> list[RealCollectionEvent]:
        """Export collection events with cryptographic raw evidence verification."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_id, payload, raw_payload, raw_sha256, raw_evidence_status "
                "FROM real_events ORDER BY observed_at, event_id LIMIT ?",
                (limit,),
            ).fetchall()
            events = []
            for event_id, payload_json, raw_blob, raw_sha256, status in rows:
                self._verify_stored_raw_hash(event_id, raw_blob, raw_sha256, status)
                event = RealCollectionEvent.from_dict(json.loads(payload_json))
                if not event.verify_raw_evidence():
                    raise ValueError(f"raw evidence verification failed on export for event {event_id}")
                events.append(event)
            return events

    def export_records(self, limit: int = 10000) -> list[tuple[RealCollectionEvent, RealObservation]]:
        """Export paired (event, observation) records with full evidence hash verification."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT e.event_id, e.payload, e.raw_payload, e.raw_sha256, e.raw_evidence_status, o.payload
                FROM real_observations o
                JOIN real_events e ON o.evidence_id = e.event_id
                ORDER BY o.observed_at, o.observation_id
                LIMIT ?
            """, (limit,)).fetchall()
            records = []
            for event_id, ev_json, raw_blob, raw_sha256, status, obs_json in rows:
                self._verify_stored_raw_hash(event_id, raw_blob, raw_sha256, status)
                event = RealCollectionEvent.from_dict(json.loads(ev_json))
                if not event.verify_raw_evidence():
                    raise ValueError(f"raw evidence verification failed on export for event {event_id}")
                obs = RealObservation.from_dict(json.loads(obs_json))
                records.append((event, obs))
            return records

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
