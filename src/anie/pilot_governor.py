"""Durable pilot governor and deterministic alternation scheduler for ANIE Phase 2.1.

Enforces strict policy invariants for the fixed 72-hour (3-calendar-day) pilot:
1. Fixed 3-day authorization window:
   - Exactly three consecutive UTC calendar dates [D1, D2, D3], beginning with the approved start date.
   - No collection permitted outside those three calendar dates (before D1 or after D3).
2. Rate & query envelope:
   - Maximum one batch attempt per authorized calendar date.
   - Maximum two approved DNS queries per batch.
3. Strict sequential progression:
   - A missed day remains missed; it does not roll over or delay the calendar schedule.
   - A failed or partial batch does not extend authorization to a fourth calendar date.
4. Deterministic query schedule:
   - Day 1 (D1): example.com (dns_a),    iana.org (dns_aaaa)
   - Day 2 (D2): example.com (dns_aaaa), iana.org (dns_a)
   - Day 3 (D3): example.com (dns_a),    iana.org (dns_aaaa)
5. Fail-closed:
   - Ceases execution immediately on ceiling exhaustion, date expiry, or critical security block.
   - Writes an unprivileged completion sentinel (/var/lib/anie/pilot_completed.sentinel)
     upon completing Day 3 or upon authorization window expiry.
6. Durable persistence: State is committed to SQLite with ACID transaction safety.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

from .collection_policy import ScopeDenied

MAX_AUTHORIZED_PILOT_RUNS = 3
DEFAULT_SENTINEL_NAME = "pilot_completed.sentinel"

# Canonical deterministic query schedule for each of the 3 pilot calendar days
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
        sentinel_path: str | Path | None = None,
        pilot_start_date: str | None = None,
    ):
        self.db_path = Path(db_path)
        self.max_runs = int(max_runs)
        if self.max_runs <= 0:
            raise ValueError(f"max_runs must be positive: {self.max_runs}")
        self.sentinel_path = Path(sentinel_path) if sentinel_path else self.db_path.parent / DEFAULT_SENTINEL_NAME
        self.override_start_date = pilot_start_date
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
                        status TEXT NOT NULL CHECK(status IN ('PLANNED', 'COMPLETED', 'FAILED', 'MISSED', 'BLOCKED')),
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
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pilot_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)
        except (sqlite3.Error, OSError) as exc:
            raise ScopeDenied(f"failed to initialize pilot state database: {exc}") from exc

    def get_start_date(self, now_dt: datetime | None = None) -> date | None:
        """Retrieve the anchored start date from metadata, or override if provided."""
        if self.override_start_date:
            try:
                return datetime.strptime(self.override_start_date, "%Y-%m-%d").date()
            except ValueError as exc:
                raise ValueError(f"invalid pilot_start_date format: {self.override_start_date!r}") from exc

        with self._connect() as conn:
            cur = conn.cursor()
            row = cur.execute("SELECT value FROM pilot_metadata WHERE key = 'start_date_utc'").fetchone()
            if row:
                return datetime.strptime(row[0], "%Y-%m-%d").date()
        return None

    def _anchor_start_date(self, conn: sqlite3.Connection, start_d: date) -> None:
        """Persist the immutable pilot start date anchor."""
        start_str = start_d.strftime("%Y-%m-%d")
        conn.execute(
            "INSERT OR IGNORE INTO pilot_metadata (key, value) VALUES ('start_date_utc', ?)",
            (start_str,),
        )

    def initialize_pilot(self, start_date_str: str) -> dict[str, Any]:
        """Atomically initialize and anchor the immutable pilot start date.

        Invariants:
        1. Initialize start_date_str only if no start date exists.
        2. Accept an existing identical date without modification (idempotent).
        3. Reject any conflicting existing date with ScopeDenied.
        4. Reject initialization if prior pilot activity exists in pilot_schedule_state.
        5. Never reset or overwrite existing pilot state.
        """
        try:
            target_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        except ValueError as exc:
            raise ValueError(f"invalid start date format '{start_date_str}', expected YYYY-MM-DD") from exc

        target_str = target_date.strftime("%Y-%m-%d")

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    "SELECT value FROM pilot_metadata WHERE key = 'start_date_utc'"
                ).fetchone()
                existing_start = row[0] if row else None

                runs_count_row = cur.execute(
                    "SELECT COUNT(*) FROM pilot_schedule_state"
                ).fetchone()
                runs_count = runs_count_row[0] if runs_count_row else 0

                if existing_start is not None:
                    if existing_start == target_str:
                        cur.execute("COMMIT")
                        return {
                            "status": "ALREADY_INITIALIZED",
                            "start_date_utc": existing_start,
                            "authorized_window": self.get_authorized_dates(),
                            "message": f"Pilot start date is already anchored to {existing_start}; no changes made.",
                        }
                    else:
                        raise ScopeDenied(
                            f"conflicting pilot start date already anchored: existing '{existing_start}' "
                            f"!= requested '{target_str}'. Start date is immutable and cannot be overwritten."
                        )

                if runs_count > 0:
                    raise ScopeDenied(
                        f"cannot initialize pilot start date: pilot_schedule_state already contains {runs_count} "
                        "recorded runs without an anchored start date. Manual inspection required."
                    )

                cur.execute(
                    "INSERT INTO pilot_metadata (key, value) VALUES ('start_date_utc', ?)",
                    (target_str,),
                )
                cur.execute("COMMIT")

                return {
                    "status": "INITIALIZED",
                    "start_date_utc": target_str,
                    "authorized_window": self.get_authorized_dates(),
                    "message": f"Pilot successfully initialized with immutable start date {target_str}.",
                }
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def get_authorized_dates(self, now_dt: datetime | None = None) -> list[str]:
        """Return the list of exactly 3 authorized consecutive UTC dates (YYYY-MM-DD)."""
        start_d = self.get_start_date(now_dt)
        if not start_d:
            return []
        return [(start_d + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(self.max_runs)]

    def get_completed_runs_count(self) -> int:
        """Return the count of completed pilot runs."""
        with self._connect() as conn:
            cur = conn.cursor()
            row = cur.execute(
                "SELECT COUNT(*) FROM pilot_schedule_state WHERE status = 'COMPLETED'"
            ).fetchone()
            return int(row[0]) if row else 0

    def is_pilot_completed(self, now_dt: datetime | None = None) -> bool:
        """Check if 72-hour pilot authorization is fully exhausted, expired, or sentinel exists."""
        if self.sentinel_path.exists():
            return True
        now = now_dt or datetime.now(timezone.utc)
        today = now.date()
        start_d = self.get_start_date(now)
        if start_d:
            end_d = start_d + timedelta(days=self.max_runs - 1)
            if today > end_d:
                return True
        return self.get_completed_runs_count() >= self.max_runs

    def write_completion_sentinel(self, now_iso: str | None = None) -> Path:
        """Write an observable, unprivileged sentinel file to halt future recurring triggers."""
        now_str = now_iso or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.sentinel_path.parent.mkdir(parents=True, exist_ok=True)

        summary = self.get_pilot_summary()
        manifest = {
            "schema": "anie.pilot-completed-sentinel.v1",
            "status": "72_HOUR_PILOT_COMPLETED",
            "completed_at": now_str,
            "authorized_window": summary.get("authorized_window", []),
            "completed_batches": summary.get("completed_batches", 0),
            "failed_attempts": summary.get("failed_attempts", 0),
            "missed_days": summary.get("missed_days", 0),
            "runs": summary.get("runs", []),
            "notice": (
                "The fixed 72-hour pilot authorization window has concluded. "
                "Further collection attempts are permanently denied by this sentinel "
                "and systemd service condition evaluation. Renewed operator authorization is required."
            ),
        }

        tmp_path = self.sentinel_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        tmp_path.replace(self.sentinel_path)
        return self.sentinel_path

    def check_and_plan_pilot_batch(
        self,
        now_dt: datetime | None = None,
    ) -> tuple[int, int, list[tuple[str, str]]]:
        """Atomically validate pilot constraints and reserve the next scheduled run.

        Enforces:
        - Exactly three consecutive UTC calendar dates [D1, D2, D3].
        - Maximum 1 batch attempt per calendar date.
        - Maximum 2 approved DNS queries per batch.
        - A missed day remains missed; it does not roll over.
        - A failed attempt does not extend authorization to a fourth date.
        - Rejection of any attempt before D1 or after D3.

        Returns:
            (run_id, day_number, query_plan)
        
        Raises:
            ScopeDenied: If pilot limits are exceeded, date is unauthorized, or pilot blocked.
        """
        now = now_dt or datetime.now(timezone.utc)
        today = now.date()
        today_utc = today.strftime("%Y-%m-%d")
        now_iso = now.isoformat(timespec="seconds").replace("+00:00", "Z")

        # 0. Fast sentinel file check
        if self.sentinel_path.exists():
            raise ScopeDenied(
                f"72-hour pilot authorization is completed or expired (sentinel file '{self.sentinel_path.name}' present). "
                "Further collection attempts are permanently blocked."
            )

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

                # 2. Reconcile or anchor the start date
                start_d = self.get_start_date(now)
                if not start_d:
                    start_d = today
                    self._anchor_start_date(conn, start_d)

                end_d = start_d + timedelta(days=self.max_runs - 1)
                start_str = start_d.strftime("%Y-%m-%d")
                end_str = end_d.strftime("%Y-%m-%d")

                # 3. Check window date boundaries
                if today < start_d:
                    raise ScopeDenied(
                        f"pilot authorization window has not yet begun (starts: {start_str}, today: {today_utc}). "
                        "Collection is prohibited before the approved start date."
                    )
                if today > end_d:
                    # Authorization expired: write completion sentinel
                    self.write_completion_sentinel(now_iso)
                    raise ScopeDenied(
                        f"72-hour pilot authorization window expired on {end_str} "
                        f"(authorized dates: {self.get_authorized_dates(now)}; today: {today_utc}). "
                        "Authorization is strictly finite and does not extend to subsequent dates. "
                        "Renewed operator authorization required."
                    )

                # Current day index (1, 2, or 3)
                day_offset = (today - start_d).days
                day_number = day_offset + 1

                # 4. Reconcile any stale/crashed PLANNED reservations
                stale_planned = cur.execute(
                    "SELECT run_id, execution_date_utc, started_at FROM pilot_schedule_state WHERE status = 'PLANNED'"
                ).fetchall()
                crashed_today = False
                for s_id, s_date, s_started in stale_planned:
                    cur.execute(
                        """
                        UPDATE pilot_schedule_state 
                        SET status = 'FAILED', completed_at = ?, error_reason = ? 
                        WHERE run_id = ?
                        """,
                        (now_iso, f"interrupted: process crashed or terminated before completion (started {s_started})", s_id),
                    )
                    if s_date == today_utc:
                        crashed_today = True

                # 5. Reconcile any prior days in the window that were missed
                for past_offset in range(day_offset):
                    past_date = (start_d + timedelta(days=past_offset)).strftime("%Y-%m-%d")
                    past_run = cur.execute(
                        "SELECT run_id FROM pilot_schedule_state WHERE execution_date_utc = ?",
                        (past_date,),
                    ).fetchone()
                    if not past_run:
                        # Record missed day
                        past_day_num = past_offset + 1
                        past_plan = json.dumps(PILOT_DAY_QUERIES.get(past_day_num, []))
                        cur.execute(
                            """
                            INSERT INTO pilot_schedule_state (
                                day_number, authorized_max_runs, status, execution_date_utc,
                                started_at, completed_at, query_plan, error_reason
                            ) VALUES (?, ?, 'MISSED', ?, ?, ?, ?, 'no execution attempt recorded on scheduled date')
                            """,
                            (past_day_num, self.max_runs, past_date, now_iso, now_iso, past_plan),
                        )

                # 6. Enforce crash fail-closed on same calendar day
                if crashed_today:
                    raise ScopeDenied(
                        f"pilot batch attempt on {today_utc} was interrupted before completion; "
                        "automatic restart on the same calendar day is prohibited to prevent duplicate network queries. "
                        "Operator inspection required."
                    )

                # 7. Check anti-duplication on calendar date (Max 1 attempt per day)
                existing_today = cur.execute(
                    "SELECT run_id, status FROM pilot_schedule_state WHERE execution_date_utc = ? AND status IN ('COMPLETED', 'FAILED', 'MISSED')",
                    (today_utc,),
                ).fetchone()
                if existing_today:
                    raise ScopeDenied(
                        f"pilot batch already executed or attempted for date {today_utc} (run_id: {existing_today[0]}, status: {existing_today[1]}); "
                        "maximum one batch attempt per calendar date"
                    )

                # 8. Check overall completed ceiling
                completed_row = cur.execute(
                    "SELECT COUNT(*) FROM pilot_schedule_state WHERE status = 'COMPLETED'"
                ).fetchone()
                completed_count = int(completed_row[0]) if completed_row else 0
                if completed_count >= self.max_runs:
                    self.write_completion_sentinel(now_iso)
                    raise ScopeDenied(
                        f"72-hour pilot authorization ceiling reached: {completed_count}/{self.max_runs} "
                        "daily batches completed. Renewed operator authorization required."
                    )

                # 9. Query plan for today's explicit calendar day
                if day_number not in PILOT_DAY_QUERIES:
                    raise ScopeDenied(f"no query alternation schedule defined for day {day_number}")

                query_plan = PILOT_DAY_QUERIES[day_number]
                plan_json = json.dumps(query_plan)

                # 10. Atomically insert planned run record
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

            # If this is Day 3 (the final authorized date) or max runs completed, write sentinel
            day_num_row = cur.execute("SELECT day_number FROM pilot_schedule_state WHERE run_id = ?", (run_id,)).fetchone()
            if day_num_row and day_num_row[0] >= self.max_runs:
                self.write_completion_sentinel(completed_iso)

    def get_pilot_summary(self, now_dt: datetime | None = None) -> dict[str, Any]:
        """Return human-readable summary of pilot progression distinguishing completed, failed, and missed days."""
        now = now_dt or datetime.now(timezone.utc)
        with self._connect() as conn:
            cur = conn.cursor()
            runs = cur.execute(
                "SELECT run_id, day_number, execution_date_utc, status, started_at, completed_at, batch_id, error_reason "
                "FROM pilot_schedule_state ORDER BY run_id ASC"
            ).fetchall()

        completed = sum(1 for r in runs if r[3] == "COMPLETED")
        failed = sum(1 for r in runs if r[3] == "FAILED")
        missed = sum(1 for r in runs if r[3] == "MISSED")

        auth_dates = self.get_authorized_dates(now)

        return {
            "authorized_window": auth_dates,
            "max_runs": self.max_runs,
            "completed_batches": completed,
            "failed_attempts": failed,
            "missed_days": missed,
            "is_completed": self.is_pilot_completed(now),
            "sentinel_exists": self.sentinel_path.exists(),
            "runs": [
                {
                    "run_id": r[0],
                    "day_number": r[1],
                    "date": r[2],
                    "status": r[3],
                    "started_at": r[4],
                    "completed_at": r[5],
                    "batch_id": r[6],
                    "error_reason": r[7],
                }
                for r in runs
            ],
        }
