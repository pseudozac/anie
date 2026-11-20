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
from datetime import datetime, timezone
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
from .discrepancy_models import RealDiscrepancyReport, DISCREPANCY_REPORT_SCHEMA
from .graph_models import GraphEdge, GraphNode, IntelligenceClaim

CURRENT_SCHEMA_VERSION = 3


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

    @property
    def schema_version(self) -> int:
        """Current schema version of the SQLite database."""
        with self._connect() as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])

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

        # 3. Multi-Resolver Discrepancy Intelligence Ledger
        conn.execute("""
            CREATE TABLE IF NOT EXISTS real_discrepancies (
                analysis_id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                kind TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                verdict TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                ruleset_version TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_real_discrepancies_subject_time 
            ON real_discrepancies(subject, kind, analyzed_at, analysis_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_real_discrepancies_verdict 
            ON real_discrepancies(verdict)
        """)

        # 4. Graph-Native Intelligence Tables (Milestone M3.3.1)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                canonical_name TEXT NOT NULL,
                layer TEXT NOT NULL,
                first_observed_at TEXT NOT NULL,
                last_observed_at TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_layer ON graph_nodes(layer)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS graph_edges (
                edge_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                target_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                relation_type TEXT NOT NULL,
                layer TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                confidence REAL NOT NULL,
                ruleset_version TEXT NOT NULL,
                evidence_hashes_json TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id, relation_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_id, relation_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_time ON graph_edges(observed_at)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS intelligence_claims (
                claim_id TEXT PRIMARY KEY,
                subject_uri TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                claim_type TEXT NOT NULL,
                layer TEXT NOT NULL,
                asserted_at TEXT NOT NULL,
                valid_from TEXT NOT NULL,
                valid_until TEXT,
                ruleset_version TEXT NOT NULL,
                confidence REAL NOT NULL,
                explanation TEXT NOT NULL,
                supporting_evidence_hashes_json TEXT NOT NULL,
                supporting_node_ids_json TEXT NOT NULL,
                analyst_identity TEXT,
                attestation_signature TEXT,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_subject ON intelligence_claims(subject_uri)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_time ON intelligence_claims(asserted_at)")

        # 5. Consumer Release Journal (Milestone M3.3.2)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS consumer_releases (
                publisher TEXT NOT NULL,
                release_sequence INTEGER NOT NULL,
                manifest_sha256 TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                total_observations INTEGER NOT NULL,
                total_events INTEGER NOT NULL,
                total_discrepancies INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('COMMITTED', 'INSPECTION')),
                PRIMARY KEY (publisher, release_sequence)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_consumer_releases_pub ON consumer_releases(publisher, release_sequence)")

    def _migrate(self, conn: sqlite3.Connection, from_version: int, to_version: int) -> None:
        """Incremental database schema migration framework."""
        if from_version < 2:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS real_discrepancies (
                    analysis_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_real_discrepancies_subject_time 
                ON real_discrepancies(subject, kind, analyzed_at, analysis_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_real_discrepancies_verdict 
                ON real_discrepancies(verdict)
            """)
        if from_version < 3:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    first_observed_at TEXT NOT NULL,
                    last_observed_at TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_nodes_layer ON graph_nodes(layer)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                    target_id TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                    relation_type TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_until TEXT,
                    confidence REAL NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    evidence_hashes_json TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id, relation_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_id, relation_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graph_edges_time ON graph_edges(observed_at)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS intelligence_claims (
                    claim_id TEXT PRIMARY KEY,
                    subject_uri TEXT NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
                    claim_type TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    asserted_at TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_until TEXT,
                    ruleset_version TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    explanation TEXT NOT NULL,
                    supporting_evidence_hashes_json TEXT NOT NULL,
                    supporting_node_ids_json TEXT NOT NULL,
                    analyst_identity TEXT,
                    attestation_signature TEXT,
                    payload TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_subject ON intelligence_claims(subject_uri)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_time ON intelligence_claims(asserted_at)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS consumer_releases (
                    publisher TEXT NOT NULL,
                    release_sequence INTEGER NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    total_observations INTEGER NOT NULL,
                    total_events INTEGER NOT NULL,
                    total_discrepancies INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('COMMITTED', 'INSPECTION')),
                    PRIMARY KEY (publisher, release_sequence)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumer_releases_pub ON consumer_releases(publisher, release_sequence)")
        conn.execute(f"PRAGMA user_version = {to_version}")

    def insert_record(
        self,
        event: RealCollectionEvent,
        observation: RealObservation,
        *,
        auto_sync_graph: bool = True,
    ) -> bool:
        """Atomically insert a provenance event and its dependent observation.
        
        Strict Idempotency:
        - If an identical record exists, it is accepted as an idempotent no-op (returns False).
        - If a conflicting record with matching identifier exists, IntegrityError is raised.
        - Automatically synchronizes graph nodes and edges in the SAME transaction (auto_sync_graph=True).
        
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
                if auto_sync_graph:
                    from .graph_engine import GraphEngine
                    engine = GraphEngine(conn)
                    nodes, edges = engine.extract_from_observation(event, observation)
                    for node in nodes:
                        engine.upsert_node(node)
                    for edge in edges:
                        engine.insert_edge(edge)
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

            if auto_sync_graph:
                from .graph_engine import GraphEngine
                engine = GraphEngine(conn)
                nodes, edges = engine.extract_from_observation(event, observation)
                for node in nodes:
                    engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)

            return True

    def insert_batch(
        self,
        records: Iterable[tuple[RealCollectionEvent, RealObservation]],
        *,
        auto_sync_graph: bool = True,
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

            # 4. Automatic Graph Synchronization (M3.3.2)
            if auto_sync_graph:
                from .graph_engine import GraphEngine
                engine = GraphEngine(conn)
                for obs_id, (obs, _) in batch_observations.items():
                    ev = batch_events[obs.evidence_id][0]
                    nodes, edges = engine.extract_from_observation(ev, obs)
                    for node in nodes:
                        engine.upsert_node(node)
                    for edge in edges:
                        engine.insert_edge(edge)

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

    def all_events(self, limit: int = 10000) -> list[RealCollectionEvent]:
        """Fetch all real collection events up to limit."""
        return self.export_events(limit=limit)

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

    # --- Multi-Resolver Discrepancy & Historical Intelligence ---

    def insert_discrepancy(self, report: RealDiscrepancyReport, *, auto_sync_graph: bool = True) -> bool:
        """Atomically insert a multi-resolver discrepancy analysis report.
        
        Strict Idempotency:
        - If an identical record exists, returns False.
        - If conflicting data with identical analysis_id exists, raises sqlite3.IntegrityError.
        - Automatically synchronizes graph nodes and edges in the SAME transaction (auto_sync_graph=True).
        """
        payload_json = canonical_json(report.to_dict())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM real_discrepancies WHERE analysis_id = ?",
                (report.analysis_id,),
            ).fetchone()
            if row is not None:
                if row[0] == payload_json:
                    if auto_sync_graph:
                        from .graph_engine import GraphEngine
                        engine = GraphEngine(conn)
                        node, edges = engine.extract_from_discrepancy(report)
                        engine.upsert_node(node)
                        for edge in edges:
                            engine.insert_edge(edge)
                    return False
                raise sqlite3.IntegrityError(
                    f"conflicting discrepancy record with identical analysis_id '{report.analysis_id}'"
                )

            conn.execute(
                """
                INSERT INTO real_discrepancies (
                    analysis_id, subject, kind, analyzed_at, verdict, category, confidence, ruleset_version, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.analysis_id,
                    report.subject,
                    report.kind,
                    report.analyzed_at,
                    report.verdict,
                    report.category,
                    report.confidence,
                    report.ruleset_version,
                    payload_json,
                ),
            )
            if auto_sync_graph:
                from .graph_engine import GraphEngine
                engine = GraphEngine(conn)
                node, edges = engine.extract_from_discrepancy(report)
                engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)
            return True

    def get_discrepancy(self, analysis_id: str) -> RealDiscrepancyReport | None:
        """Fetch a specific discrepancy report by analysis_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM real_discrepancies WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                return None
            return RealDiscrepancyReport.from_dict(json.loads(row[0]))

    def discrepancies_for_subject(self, subject: str, kind: str | None = None, limit: int = 1000) -> list[RealDiscrepancyReport]:
        """Fetch discrepancy reports for a subject ordered by analyzed_at DESC."""
        with self._connect() as conn:
            if kind:
                rows = conn.execute(
                    """
                    SELECT payload FROM real_discrepancies
                    WHERE subject = ? AND kind = ?
                    ORDER BY analyzed_at DESC, analysis_id DESC
                    LIMIT ?
                    """,
                    (subject, kind, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT payload FROM real_discrepancies
                    WHERE subject = ?
                    ORDER BY analyzed_at DESC, analysis_id DESC
                    LIMIT ?
                    """,
                    (subject, limit),
                ).fetchall()
            return [RealDiscrepancyReport.from_dict(json.loads(r[0])) for r in rows]

    def all_discrepancies(self, limit: int = 10000) -> list[RealDiscrepancyReport]:
        """Fetch all discrepancy reports ordered by analyzed_at ASC, analysis_id ASC."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload FROM real_discrepancies
                ORDER BY analyzed_at ASC, analysis_id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [RealDiscrepancyReport.from_dict(json.loads(r[0])) for r in rows]

    def get_historical_summary(
        self,
        subject: str,
        kind: str = "dns_a",
        *,
        record_type: str | None = None,
    ) -> dict[str, Any]:
        """Compute resource-efficient historical intelligence foundation for a domain.
        
        Evaluates repeated observations, first-seen / last-seen timestamps,
        timeline of observed IP sets, resolver agreement rate, and security filtering incidents.
        """
        query_kind = record_type or kind
        with self._connect() as conn:
            # 1. Observation bounds
            bounds = conn.execute(
                """
                SELECT MIN(observed_at), MAX(observed_at), COUNT(*)
                FROM real_observations
                WHERE subject = ? AND kind = ?
                """,
                (subject, query_kind),
            ).fetchone()

            first_seen = bounds[0] if bounds and bounds[2] > 0 else None
            last_seen = bounds[1] if bounds and bounds[2] > 0 else None
            total_obs = bounds[2] if bounds else 0

            # 2. Distinct observations timeline
            obs_rows = conn.execute(
                """
                SELECT observed_at, source_id, status, payload
                FROM real_observations
                WHERE subject = ? AND kind = ?
                ORDER BY observed_at ASC, observation_id ASC
                """,
                (subject, query_kind),
            ).fetchall()

            timeline = []
            distinct_value_sets = set()
            all_ips = set()
            for obs_time, source_id, status, payload_json in obs_rows:
                obs_data = json.loads(payload_json)
                vals = tuple(sorted(obs_data.get("values", [])))
                distinct_value_sets.add(vals)
                for v in vals:
                    all_ips.add(v)
                timeline.append({
                    "observed_at": obs_time,
                    "source_id": source_id,
                    "status": status,
                    "values": list(vals),
                    "resolver": obs_data.get("factual_verification", {}).get("resolver_identity", source_id),
                })

            # 3. Discrepancy reports history
            disc_rows = conn.execute(
                """
                SELECT analyzed_at, verdict, category, confidence, payload
                FROM real_discrepancies
                WHERE subject = ? AND kind = ?
                ORDER BY analyzed_at ASC, analysis_id ASC
                """,
                (subject, query_kind),
            ).fetchall()

            discrepancy_history = []
            agreement_count = 0
            filtering_incidents = 0
            for a_time, verdict, cat, conf, p_json in disc_rows:
                if verdict == "AGREEMENT":
                    agreement_count += 1
                elif verdict == "SECURITY_FILTERING_DETECTED":
                    filtering_incidents += 1
                discrepancy_history.append({
                    "analyzed_at": a_time,
                    "verdict": verdict,
                    "category": cat,
                    "confidence": conf,
                })

            total_disc = len(disc_rows)
            agreement_rate = (agreement_count / total_disc) if total_disc > 0 else None

            return {
                "subject": subject,
                "kind": query_kind,
                "record_type": query_kind,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "total_observations": total_obs,
                "total_discrepancy_reports": total_disc,
                "total_discrepancy_analyses": total_disc,
                "unique_ip_sets_observed": len(distinct_value_sets),
                "unique_ip_addresses": sorted(all_ips),
                "resolver_agreement_rate": agreement_rate,
                "agreement_rate": agreement_rate,
                "security_filtering_incidents": filtering_incidents,
                "timeline": timeline,
                "discrepancies": discrepancy_history,
            }

    # --- Graph-Native Intelligence Integration (M3.3.1) ---

    def sync_observation_to_graph(
        self,
        event: RealCollectionEvent,
        observation: RealObservation,
    ) -> tuple[int, int]:
        """Extract graph nodes and edges from observation/event and persist to graph tables.
        
        Returns (nodes_upserted_count, edges_inserted_count).
        """
        from .graph_engine import GraphEngine
        with self._connect() as conn:
            engine = GraphEngine(conn)
            nodes, edges = engine.extract_from_observation(event, observation)
            for node in nodes:
                engine.upsert_node(node)
            for edge in edges:
                engine.insert_edge(edge)
            return len(nodes), len(edges)

    def sync_discrepancy_to_graph(
        self,
        report: RealDiscrepancyReport,
    ) -> tuple[int, int]:
        """Extract graph node and edges from discrepancy report and persist to graph tables.
        
        Returns (nodes_upserted_count, edges_inserted_count).
        """
        from .graph_engine import GraphEngine
        with self._connect() as conn:
            engine = GraphEngine(conn)
            node, edges = engine.extract_from_discrepancy(report)
            engine.upsert_node(node)
            for edge in edges:
                engine.insert_edge(edge)
            return 1, len(edges)

    def insert_claim(self, claim: IntelligenceClaim) -> bool:
        """Insert an attributable intelligence claim into intelligence_claims table."""
        with self._connect() as conn:
            # Ensure subject node exists or is created
            node_row = conn.execute("SELECT node_id FROM graph_nodes WHERE node_id = ?", (claim.subject_uri,)).fetchone()
            if node_row is None:
                conn.execute(
                    """
                    INSERT INTO graph_nodes (
                        node_id, node_type, canonical_name, layer,
                        first_observed_at, last_observed_at, properties_json, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim.subject_uri,
                        "domain" if ":domain:" in claim.subject_uri else "claim",
                        claim.subject_uri.split(":")[-1],
                        claim.layer,
                        claim.asserted_at,
                        claim.asserted_at,
                        "{}",
                        "{}",
                    ),
                )

            cur = conn.execute(
                """
                INSERT OR IGNORE INTO intelligence_claims (
                    claim_id, subject_uri, claim_type, layer,
                    asserted_at, valid_from, valid_until, ruleset_version,
                    confidence, explanation, supporting_evidence_hashes_json,
                    supporting_node_ids_json, analyst_identity, attestation_signature,
                    payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claim.claim_id,
                    claim.subject_uri,
                    claim.claim_type,
                    claim.layer,
                    claim.asserted_at,
                    claim.valid_from,
                    claim.valid_until,
                    claim.ruleset_version,
                    claim.confidence,
                    claim.explanation,
                    json.dumps(list(claim.supporting_evidence_hashes)),
                    json.dumps(list(claim.supporting_node_ids)),
                    claim.analyst_identity,
                    claim.attestation_signature,
                    canonical_json(claim.to_dict()),
                ),
            )
            return cur.rowcount > 0

    def get_claim(self, claim_id: str) -> IntelligenceClaim | None:
        """Fetch intelligence claim by claim_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM intelligence_claims WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            return IntelligenceClaim.from_dict(json.loads(row[0])) if row else None

    def claims_for_subject(self, subject_uri: str) -> list[IntelligenceClaim]:
        """Fetch all claims for a given subject URI."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM intelligence_claims WHERE subject_uri = ? ORDER BY asserted_at ASC",
                (subject_uri,),
            ).fetchall()
            return [IntelligenceClaim.from_dict(json.loads(r[0])) for r in rows]

    def all_claims(self, limit: int = 1000) -> list[IntelligenceClaim]:
        """Fetch all intelligence claims up to limit."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM intelligence_claims ORDER BY asserted_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [IntelligenceClaim.from_dict(json.loads(r[0])) for r in rows]

    def rebuild_graph_from_observations(self) -> tuple[int, int]:
        """Truncate and transactionally rebuild graph tables from authoritative observations and discrepancies.
        
        Guarantees that the graph can be completely regenerated from authoritative Layer 1 and 2 records.
        Returns (nodes_count, edges_count).
        """
        from .graph_engine import GraphEngine
        with self._connect() as conn:
            conn.execute("DELETE FROM graph_edges")
            conn.execute("DELETE FROM graph_nodes")
            engine = GraphEngine(conn)

            # 1. Rebuild from real observations joined with real events
            obs_rows = conn.execute("""
                SELECT o.payload, e.payload
                FROM real_observations o
                JOIN real_events e ON e.event_id = o.evidence_id
                ORDER BY o.observed_at ASC
            """).fetchall()

            for obs_json, ev_json in obs_rows:
                obs = RealObservation.from_dict(json.loads(obs_json))
                ev = RealCollectionEvent.from_dict(json.loads(ev_json))
                nodes, edges = engine.extract_from_observation(ev, obs)
                for node in nodes:
                    engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)

            # 2. Rebuild from real discrepancies
            disc_rows = conn.execute("SELECT payload FROM real_discrepancies ORDER BY analyzed_at ASC").fetchall()
            for (disc_json,) in disc_rows:
                disc = RealDiscrepancyReport.from_dict(json.loads(disc_json))
                node, edges = engine.extract_from_discrepancy(disc)
                engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)

            # 3. Ensure nodes exist for any registered intelligence claims
            claim_rows = conn.execute("SELECT subject_uri, layer, asserted_at FROM intelligence_claims").fetchall()
            for s_uri, l_val, ass_at in claim_rows:
                node_exists = conn.execute("SELECT 1 FROM graph_nodes WHERE node_id = ?", (s_uri,)).fetchone()
                if not node_exists:
                    c_name = s_uri.split(":")[-1]
                    n_type = "domain" if ":domain:" in s_uri else "claim"
                    conn.execute("""
                        INSERT INTO graph_nodes (
                            node_id, node_type, canonical_name, layer,
                            first_observed_at, last_observed_at, properties_json, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, '{}', '{}')
                    """, (s_uri, n_type, c_name, l_val, ass_at, ass_at))

            nodes_count = conn.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]
            edges_count = conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]
            return nodes_count, edges_count

    def ingest_release_bundle(
        self,
        observations: list[RealObservation],
        events: list[RealCollectionEvent],
        discrepancies: list[RealDiscrepancyReport] | None = None,
        *,
        publisher: str,
        release_sequence: int,
        manifest_sha256: str,
        is_historical: bool = False,
    ) -> bool:
        """Atomically persist a verified release bundle and advance the consumer release journal.
        
        Transactional Guarantee:
        - All events, observations, discrepancies, graph syncs, and the consumer release record
          are committed in a SINGLE SQLite transaction.
        - If a crash or error occurs at any point during persistence, all records are rolled back.
        - Historical inspection (is_historical=True) persists data without advancing the release journal.
        - Returns True if newly committed, False if already present identically (idempotent).
        """
        discrepancies = discrepancies or []
        events_by_id = {ev.event_id: ev for ev in events}

        with self._connect() as conn:
            # Check consumer_releases journal
            if not is_historical:
                row = conn.execute(
                    "SELECT manifest_sha256, status FROM consumer_releases WHERE publisher = ? AND release_sequence = ?",
                    (publisher, release_sequence),
                ).fetchone()
                if row is not None:
                    if row[0] == manifest_sha256:
                        # Already committed identically: idempotent success
                        return False
                    raise sqlite3.IntegrityError(
                        f"conflicting release for publisher '{publisher}' sequence {release_sequence}: "
                        f"existing manifest SHA-256 '{row[0]}' != incoming '{manifest_sha256}'"
                    )

            from .graph_engine import GraphEngine
            engine = GraphEngine(conn)

            # Persist events & observations
            for obs in observations:
                ev = events_by_id.get(obs.evidence_id)
                if ev is None:
                    # Check if event already exists in database
                    ev_row = conn.execute("SELECT payload FROM real_events WHERE event_id = ?", (obs.evidence_id,)).fetchone()
                    if ev_row is None:
                        raise ValueError(f"missing supporting event {obs.evidence_id} for observation {obs.observation_id}")
                    ev = RealCollectionEvent.from_dict(json.loads(ev_row[0]))

                # Insert event if not present
                ev_canonical = canonical_json(ev.to_dict())
                existing_ev = conn.execute("SELECT payload FROM real_events WHERE event_id = ?", (ev.event_id,)).fetchone()
                if existing_ev is None:
                    conn.execute("""
                        INSERT INTO real_events (
                            event_id, schema, subject, kind, observed_at,
                            response_code, raw_sha256, raw_evidence_status,
                            raw_payload, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ev.event_id, REAL_EVENT_SCHEMA, ev.request.subject, ev.request.kind,
                        ev.observed_at, ev.response_code, ev.raw_sha256, ev.raw_evidence_status,
                        ev.raw_payload, ev_canonical
                    ))
                elif existing_ev[0] != ev_canonical:
                    raise sqlite3.IntegrityError(f"conflicting real_event with event_id {ev.event_id}")

                # Insert observation if not present
                obs_canonical = canonical_json(obs.to_dict())
                existing_obs = conn.execute("SELECT payload FROM real_observations WHERE observation_id = ?", (obs.observation_id,)).fetchone()
                if existing_obs is None:
                    conn.execute("""
                        INSERT INTO real_observations (
                            observation_id, evidence_id, subject_type, subject,
                            kind, observed_at, status, source_id, method,
                            synthetic, confidence, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        obs.observation_id, obs.evidence_id,
                        "domain" if obs.kind in {"dns_a", "dns_aaaa"} else "ip",
                        obs.subject, obs.kind, obs.observed_at, obs.status, obs.source_id,
                        obs.method, 0, obs.confidence, obs_canonical
                    ))
                elif existing_obs[0] != obs_canonical:
                    raise sqlite3.IntegrityError(f"conflicting real_observation with observation_id {obs.observation_id}")

                # Automatic graph sync
                nodes, edges = engine.extract_from_observation(ev, obs)
                for node in nodes:
                    engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)

            # Persist discrepancies
            for disc in discrepancies:
                disc_canonical = canonical_json(disc.to_dict())
                existing_disc = conn.execute("SELECT payload FROM real_discrepancies WHERE analysis_id = ?", (disc.analysis_id,)).fetchone()
                if existing_disc is None:
                    conn.execute("""
                        INSERT INTO real_discrepancies (
                            analysis_id, subject, kind, analyzed_at, verdict, category, confidence, ruleset_version, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        disc.analysis_id, disc.subject, disc.kind, disc.analyzed_at,
                        disc.verdict, disc.category, disc.confidence, disc.ruleset_version, disc_canonical
                    ))
                elif existing_disc[0] != disc_canonical:
                    raise sqlite3.IntegrityError(f"conflicting real_discrepancy with analysis_id {disc.analysis_id}")

                node, edges = engine.extract_from_discrepancy(disc)
                engine.upsert_node(node)
                for edge in edges:
                    engine.insert_edge(edge)

            # Record consumer release
            if not is_historical:
                now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                conn.execute("""
                    INSERT INTO consumer_releases (
                        publisher, release_sequence, manifest_sha256, accepted_at,
                        total_observations, total_events, total_discrepancies, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'COMMITTED')
                """, (
                    publisher, release_sequence, manifest_sha256, now_iso,
                    len(observations), len(events), len(discrepancies)
                ))

            return True

    def get_last_consumer_release_sequence(self, publisher: str) -> int:
        """Return the highest committed release sequence for the given publisher."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(release_sequence) FROM consumer_releases WHERE publisher = ? AND status = 'COMMITTED'",
                (publisher,),
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else 0

    def get_consumer_release(self, publisher: str, release_sequence: int) -> dict[str, Any] | None:
        """Return journal record for specific publisher and sequence."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT publisher, release_sequence, manifest_sha256, accepted_at,
                       total_observations, total_events, total_discrepancies, status
                FROM consumer_releases
                WHERE publisher = ? AND release_sequence = ?
                """,
                (publisher, release_sequence),
            ).fetchone()
            if row is None:
                return None
            return {
                "publisher": row[0],
                "release_sequence": row[1],
                "manifest_sha256": row[2],
                "accepted_at": row[3],
                "total_observations": row[4],
                "total_events": row[5],
                "total_discrepancies": row[6],
                "status": row[7],
            }
