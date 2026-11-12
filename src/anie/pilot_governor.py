"""Durable pilot governor and deterministic alternation scheduler for ANIE Phase 2.1.

Enforces strict policy invariants for the 72-hour unattended pilot:
1. Max authorized runs: Exactly 3 daily batches under current authorization.
2. Anti-duplication: At most 1 batch per calendar day (UTC); duplicate timer fires are denied.
3. Anti-catchup: Catch-up executions after system downtime are strictly blocked.
4. Deterministic A/AAAA alternation across days:
   - Day 1: example.com (dns_a),    iana.org (dns_aaaa)
   - Day 2: example.com (dns_aaaa), iana.org (dns_a)
   - Day 3: example.com (dns_a),    iana.org (dns_aaaa)
5. Fail-closed: Ceases execution immediately on ceiling exhaustion or security block.
6. Durable persistence: State is committed to SQLite with ACID transaction safety.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .collection_policy import ScopeDenied

MAX_AUTHORIZED_PILOT_RUNS = 3

# Canonical deterministic query schedule for the 72-hour pilot
PILOT_DAY_QUERIES: dict[int, list[tuple[str, str]]] = {
    1: [("example.com", "dns_a"), ("iana.org", "dns_aaaa")],
    2: [("example.com", "dns_aaaa"), ("iana.org", "dns_a")],
    3: [("example.com", "dns_a"), ("iana.org", "dns_aaaa")],
}


class PilotGovernor:
    """Stateful supervisor for bounded 72-hour daily pilot progression."""

    def __init__(
        self,
        db_path: str | Path,
        max_runs: int = MAX_AUTHORIZED_PILOT_RUNS,
    ):
        self.db_path = Path(db_path)
        self.max_runs = int(max_runs)
        if self.max_runs <= 0:
            raise ValueError(f"max_runs must be positive: {self.max_runs}")
        self._init_db()

    @contextmanager
    def _connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
        )
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pilot_schedule_state (
                        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        day_number INTEGER NOT NULL,
                        authorized_max_runs INTEGER NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('PLANNED', 'COMPLETED', 'FAILED', 'BLOCKED')),
                        execution_date_utc TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        batch_id TEXT,
                        query_plan TEXT NOT NULL,
                        error_reason TEXT
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pilot_date 
                    ON pilot_schedule_state(execution_date_utc)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pilot_status 
                    ON pilot_schedule_state(status)
                """)
        except (sqlite3.Error, OSError) as exc:
            raise ScopeDenied(f"failed to initialize pilot state database: {exc}") from exc

    def get_completed_runs_count(self) -> int:
        """Return the count of completed pilot runs."""
        with self._connect() as conn:
            cur = conn.cursor()
            row = cur.execute(
                "SELECT COUNT(*) FROM pilot_schedule_state WHERE status = 'COMPLETED'"
            ).fetchone()
            return int(row[0]) if row else 0

    def check_and_plan_pilot_batch(
        self,
        now_dt: datetime | None = None,
    ) -> tuple[int, int, list[tuple[str, str]]]:
        """Atomically validate pilot constraints and reserve the next scheduled run.

        Returns:
            (run_id, day_number, query_plan)
        
        Raises:
            ScopeDenied: If pilot limits are exceeded, duplicate run attempted, or pilot blocked.
        """
        now = now_dt or datetime.now(timezone.utc)
        today_utc = now.strftime("%Y-%m-%d")
        now_iso = now.isoformat(timespec="seconds").replace("+00:00", "Z")

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                # 1. Check for critical block state
                blocked = cur.execute(
                    "SELECT run_id, error_reason FROM pilot_schedule_state WHERE status = 'BLOCKED' LIMIT 1"
                ).fetchone()
                if blocked:
                    raise ScopeDenied(
                        f"pilot is in BLOCKED state from run {blocked[0]}: {blocked[1]}; "
                        "operator inspection and reset required"
                    )

                # 2. Count completed runs
                completed_row = cur.execute(
                    "SELECT COUNT(*) FROM pilot_schedule_state WHERE status = 'COMPLETED'"
                ).fetchone()
                completed_count = int(completed_row[0]) if completed_row else 0

                if completed_count >= self.max_runs:
                    raise ScopeDenied(
                        f"72-hour pilot authorization ceiling reached: {completed_count}/{self.max_runs} "
                        "daily batches completed. Renewed operator authorization required."
                    )

                # 3. Check anti-duplication & anti-catchup on calendar date
                existing_today = cur.execute(
                    "SELECT run_id, status FROM pilot_schedule_state WHERE execution_date_utc = ? AND status IN ('COMPLETED', 'PLANNED')",
                    (today_utc,),
                ).fetchone()
                if existing_today:
                    raise ScopeDenied(
                        f"pilot batch already executed or active for date {today_utc} (run_id: {existing_today[0]}, status: {existing_today[1]}); "
                        "duplicate or catch-up execution blocked"
                    )

                # 4. Determine next day number and query plan
                day_number = completed_count + 1
                if day_number not in PILOT_DAY_QUERIES:
                    raise ScopeDenied(f"no query alternation schedule defined for day {day_number}")

                query_plan = PILOT_DAY_QUERIES[day_number]
                plan_json = json.dumps(query_plan)

                # 5. Atomically insert planned run record
                cur.execute(
                    """
                    INSERT INTO pilot_schedule_state (
                        day_number, authorized_max_runs, status, execution_date_utc,
                        started_at, query_plan
                    ) VALUES (?, ?, 'PLANNED', ?, ?, ?)
                    """,
                    (day_number, self.max_runs, today_utc, now_iso, plan_json),
                )
                run_id = cur.lastrowid
                cur.execute("COMMIT")
                return run_id, day_number, query_plan
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def record_pilot_outcome(
        self,
        run_id: int,
        outcome: str,
        batch_id: str | None = None,
        error_reason: str | None = None,
        now_dt: datetime | None = None,
    ) -> None:
        """Record batch execution completion status in persistent pilot state."""
        now = now_dt or datetime.now(timezone.utc)
        completed_iso = now.isoformat(timespec="seconds").replace("+00:00", "Z")

        status_map = {
            "SUCCESS": "COMPLETED",
            "PARTIAL": "FAILED",
            "FAILED": "FAILED",
            "SKIPPED": "FAILED",
            "BLOCKED": "BLOCKED",
        }
        db_status = status_map.get(outcome.upper(), "FAILED")

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE pilot_schedule_state
                SET status = ?, completed_at = ?, batch_id = ?, error_reason = ?
                WHERE run_id = ?
                """,
                (db_status, completed_iso, batch_id, error_reason, run_id),
            )
