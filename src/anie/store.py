"""Local SQLite observation store. Prepared statements; indexed, append-only snapshots."""
from __future__ import annotations

from pathlib import Path
from contextlib import contextmanager
import json
import sqlite3
from collections.abc import Iterable
from .observations import Observation, canonical_json


class ObservationStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("PRAGMA busy_timeout = 10000")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS observations (
                observation_id TEXT PRIMARY KEY,
                subject_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                kind TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS observations_by_subject_time ON observations(subject_type,subject,observed_at,observation_id)")
            conn.execute("PRAGMA user_version=1")

    def insert(self, observations: Iterable[Observation]) -> int:
        rows = []
        for ob in observations:
            rows.append((ob.observation_id, "domain" if ob.kind in {"dns_a", "dns_aaaa"} else "ip", ob.subject, ob.kind, ob.observed_at, canonical_json(ob.to_dict())))
            if len(rows) > 10000:
                raise ValueError("batch size must not exceed 10000")
        with self._connect() as conn:
            previous = conn.total_changes
            conn.executemany("INSERT OR IGNORE INTO observations (observation_id,subject_type,subject,kind,observed_at,payload) VALUES (?,?,?,?,?,?)", rows)
            return conn.total_changes - previous

    def all(self) -> list[Observation]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM observations ORDER BY observed_at, observation_id").fetchall()
        return [Observation.from_dict(json.loads(row[0])) for row in rows]

    def by_subject(self, subject: str) -> list[Observation]:
        with self._connect() as conn:
            rows = conn.execute("SELECT payload FROM observations WHERE subject=? ORDER BY observed_at, observation_id", (subject,)).fetchall()
        return [Observation.from_dict(json.loads(row[0])) for row in rows]
