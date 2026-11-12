"""Bounded, resource-governed batch orchestrator for ANIE first-party intelligence.

Part of ANIE Phase 2 PR 3 (Bounded Batch Orchestration).

Designed specifically for constrained hosts such as Oracle Cloud VM.Standard.E2.1.Micro
(1 GiB usable RAM, remote block storage).

Key Architectural Invariants:
1. One-Shot Execution: Discrete execution; terminates after processing batch.
   No persistent daemon or un-timeoutable background thread.
2. Pilot Envelope: Maximum 2 distinct domains (example.com, iana.org), A and AAAA only.
   At most 1 query per domain per batch to strictly satisfy the 30-minute per-domain cooldown.
   Ceiling of <= 4 total queries per batch.
3. Preflight Resource Safeguards:
   - Minimum available host RAM: 200 MiB (abstains if below threshold to safeguard host).
   - Minimum available storage: 500 MiB.
   - Fail-closed host metrics: unknown memory metrics prevent live collection.
   - Advisory process locking covering the complete execution critical section.
   - SQLite schema readiness and quick integrity checks.
4. Dry-Run Default & Telemetry Correctness: Safe offline dry-run by default.
   Dry-run reports queries_attempted=0, queries_succeeded=0, queries_failed=0, records_persisted=0,
   and reports queries_planned separately.
   Real network collection requires explicit operator authorization (--mode live AND ANIE_LIVE_COLLECTION_AUTHORIZED=1).
5. Monotonic Batch Deadline: A single monotonic deadline governs the entire batch execution.
   Remaining budget is passed to sequential collection operations; queries abort if budget is exhausted.
   Total budget bounded at <= 25.0s to allow systemd TimeoutStartSec (30s) cleanup headroom.
6. Structured Telemetry: Emits single-line JSON records with bounded rotation (<= 5 MiB).
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time
from typing import Any, Callable
import uuid

from .collection_policy import ScopeDenied
from .doh_collector import (
    DEFAULT_TOTAL_TIMEOUT_SECONDS,
    DohCollector,
    RESOLVER_IDENTITY,
    SOURCE_ID,
)
from .doh_governor import (
    ALLOWED_QUERY_KINDS,
    ALLOWED_TARGET_DOMAINS,
    DEFAULT_TARGET_COOLDOWN_SECONDS,
    DohRateGovernor,
    MAX_DOMAINS_PER_BATCH,
    validate_batch_domains,
    validate_target,
)
from .real_models import RealCollectionEvent, RealObservation
from .real_store import RealObservationStore

DEFAULT_MIN_MEMORY_MB = 200
DEFAULT_MIN_DISK_MB = 500
DEFAULT_BATCH_TIMEOUT_SECONDS = 20.0
MAX_BATCH_TIMEOUT_SECONDS = 25.0  # Leaves >= 5s headroom before systemd 30s TimeoutStartSec
MAX_QUERIES_PER_BATCH = 4
MAX_LOG_SIZE_BYTES = 5 * 1024 * 1024  # 5 MiB
VALID_MODES = frozenset({"dry_run", "live"})


def _validate_threshold(val: Any, name: str) -> int:
    """Validate that a memory or disk threshold is a positive finite integer."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{name} must be a positive integer: got {val!r}")
    if math.isnan(val) or math.isinf(val) or val <= 0:
        raise ValueError(f"{name} must be a positive finite number > 0: got {val}")
    int_val = int(val)
    if int_val != val:
        raise ValueError(f"{name} must be an integer: got {val}")
    return int_val


def _validate_timeout(val: Any) -> float:
    """Validate that timeout is positive, finite, and <= MAX_BATCH_TIMEOUT_SECONDS."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"timeout_seconds must be a positive float: got {val!r}")
    if math.isnan(val) or math.isinf(val) or val <= 0.0:
        raise ValueError(f"timeout_seconds must be a positive finite number > 0: got {val}")
    f_val = float(val)
    if f_val > MAX_BATCH_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout_seconds ({f_val:.2f}s) exceeds maximum allowed {MAX_BATCH_TIMEOUT_SECONDS:.1f}s "
            "to guarantee systemd TimeoutStartSec (30s) cleanup headroom"
        )
    return f_val


def get_available_memory_mb() -> int | None:
    """Read available host memory in MiB without external dependencies.
    
    Returns None if memory metrics cannot be determined (fail-closed).
    """
    # 1. Linux /proc/meminfo (Standard on Oracle Linux / Ubuntu)
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemAvailable:"):
                        return int(line.split()[1]) // 1024
        except (OSError, ValueError, IndexError):
            pass

    # 2. Windows ctypes fallback
    if sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return int(stat.ullAvailPhys // (1024 * 1024))
        except Exception:
            pass

    # Fail-closed: do not invent an unverified fallback metric
    return None


def get_available_disk_mb(path: str | Path) -> int:
    """Read available filesystem storage in MiB for path."""
    try:
        p = Path(path)
        while not p.exists() and p.parent != p:
            p = p.parent
        usage = shutil.disk_usage(str(p))
        return int(usage.free // (1024 * 1024))
    except (OSError, ValueError):
        return 0


@contextmanager
def acquire_collector_lock(lock_path: Path):
    """Advisory process lock preventing concurrent collector executions."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+", encoding="utf-8")
    try:
        if sys.platform == "win32":
            import msvcrt

            try:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise BlockingIOError(f"collector lock held by another process: {exc}") from exc
        else:
            import fcntl

            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise BlockingIOError(f"collector lock held by another process: {exc}") from exc
        yield f
    finally:
        try:
            if sys.platform == "win32":
                import msvcrt

                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            f.close()


def check_sqlite_integrity(db_path: Path) -> tuple[bool, str]:
    """Verify SQLite database file integrity if present."""
    if not db_path.exists():
        return True, "database file does not yet exist (will be initialized)"
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        try:
            cursor = conn.execute("PRAGMA quick_check")
            result = cursor.fetchone()
            if result and result[0] == "ok":
                return True, "ok"
            return False, f"quick_check failed: {result}"
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return False, f"database operational check error: {exc}"


@dataclass
class PreflightReport:
    passed: bool
    mem_available_mb: int
    disk_available_mb: int
    checks: dict[str, str] = field(default_factory=dict)
    failure_reason: str | None = None
    operational_error: bool = False


def run_preflight_checks(
    quota_db_path: Path,
    store_db_path: Path,
    lock_path: Path | None = None,
    log_path: Path | None = None,
    min_mem_mb: int = DEFAULT_MIN_MEMORY_MB,
    min_disk_mb: int = DEFAULT_MIN_DISK_MB,
    mem_fn: Callable[[], int | None] | None = None,
    disk_fn: Callable[[Path], int] | None = None,
) -> PreflightReport:
    """Execute host and environment preflight safety checks."""
    checks: dict[str, str] = {}
    read_mem = mem_fn or get_available_memory_mb
    read_disk = disk_fn or get_available_disk_mb

    # Validate thresholds
    min_mem_mb = _validate_threshold(min_mem_mb, "min_mem_mb")
    min_disk_mb = _validate_threshold(min_disk_mb, "min_disk_mb")

    # 1. Host Memory check (fail-closed if unknown)
    avail_mem = read_mem()
    if avail_mem is None:
        checks["memory_mb"] = "unknown"
        return PreflightReport(
            passed=False,
            mem_available_mb=-1,
            disk_available_mb=0,
            checks=checks,
            failure_reason="operational error: host memory availability cannot be determined",
            operational_error=True,
        )

    checks["memory_mb"] = f"{avail_mem} (min: {min_mem_mb})"
    if avail_mem < min_mem_mb:
        return PreflightReport(
            passed=False,
            mem_available_mb=avail_mem,
            disk_available_mb=0,
            checks=checks,
            failure_reason=f"insufficient available RAM: {avail_mem} MiB < {min_mem_mb} MiB threshold",
            operational_error=False,
        )

    # 2. Host Storage checks
    quota_disk = read_disk(quota_db_path)
    store_disk = read_disk(store_db_path)
    avail_disk = min(quota_disk, store_disk)
    checks["disk_mb"] = f"{avail_disk} (min: {min_disk_mb})"
    if avail_disk < min_disk_mb:
        return PreflightReport(
            passed=False,
            mem_available_mb=avail_mem,
            disk_available_mb=avail_disk,
            checks=checks,
            failure_reason=f"insufficient available disk: {avail_disk} MiB < {min_disk_mb} MiB threshold",
            operational_error=False,
        )

    # 3. Directory writability checks
    paths_to_verify = [quota_db_path.parent, store_db_path.parent]
    if log_path is not None:
        paths_to_verify.append(log_path.parent)
    if lock_path is not None:
        paths_to_verify.append(lock_path.parent)

    for p in paths_to_verify:
        try:
            p.mkdir(parents=True, exist_ok=True)
            test_file = p / f".anie_test_write_{uuid.uuid4().hex}"
            test_file.touch()
            test_file.unlink()
            checks[f"writable_{p.name}"] = "ok"
        except OSError as exc:
            return PreflightReport(
                passed=False,
                mem_available_mb=avail_mem,
                disk_available_mb=avail_disk,
                checks=checks,
                failure_reason=f"storage path '{p}' is unwritable: {exc}",
                operational_error=True,
            )

    # 4. Database integrity checks
    for p, label in ((quota_db_path, "quota_db"), (store_db_path, "store_db")):
        ok, msg = check_sqlite_integrity(p)
        checks[f"{label}_integrity"] = msg
        if not ok:
            return PreflightReport(
                passed=False,
                mem_available_mb=avail_mem,
                disk_available_mb=avail_disk,
                checks=checks,
                failure_reason=f"database integrity failure for {label}: {msg}",
                operational_error=True,
            )

    return PreflightReport(
        passed=True,
        mem_available_mb=avail_mem,
        disk_available_mb=avail_disk,
        checks=checks,
    )


@dataclass
class BatchConfig:
    domains: list[str] = field(default_factory=lambda: ["example.com", "iana.org"])
    query_mode: str = "alternate"  # "alternate", "dns_a", "dns_aaaa"
    explicit_queries: list[tuple[str, str]] | None = None
    mode: str = "dry_run"  # "dry_run" (default) or "live"
    quota_db_path: Path = field(default_factory=lambda: Path("local-data/doh_quota.sqlite"))
    store_db_path: Path = field(default_factory=lambda: Path("local-data/real_intelligence.sqlite"))
    log_file_path: Path | None = None
    lock_file_path: Path | None = None
    min_mem_mb: int = DEFAULT_MIN_MEMORY_MB
    min_disk_mb: int = DEFAULT_MIN_DISK_MB
    timeout_seconds: float = DEFAULT_BATCH_TIMEOUT_SECONDS
    pilot_mode: bool = False
    pilot_db_path: Path | None = None
    pilot_sentinel_path: Path | None = None

    def __post_init__(self):
        if self.mode not in VALID_MODES:
            raise ValueError(f"invalid execution mode '{self.mode}': must be one of {sorted(VALID_MODES)}")
        self.min_mem_mb = _validate_threshold(self.min_mem_mb, "min_mem_mb")
        self.min_disk_mb = _validate_threshold(self.min_disk_mb, "min_disk_mb")
        self.timeout_seconds = _validate_timeout(self.timeout_seconds)


@dataclass
class BatchReport:
    batch_id: str
    started_at: str
    completed_at: str
    duration_seconds: float
    mode: str
    outcome: str  # "SUCCESS", "SKIPPED", "PARTIAL", "FAILED"
    reason: str | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    preflight: dict[str, Any] = field(default_factory=dict)
    queries_planned: int = 0
    queries_attempted: int = 0
    queries_succeeded: int = 0
    queries_failed: int = 0
    queries_skipped: int = 0
    records_persisted: dict[str, list[str]] = field(
        default_factory=lambda: {"observation_ids": [], "event_ids": []}
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def emit_telemetry(
    record: dict[str, Any],
    log_path: Path | None,
    max_bytes: int = MAX_LOG_SIZE_BYTES,
) -> bool:
    """Emit single-line structured JSON execution record with size-bounded rotation.
    
    Returns True if emitted successfully or if log_path is None, False on error.
    """
    if log_path is None:
        return True

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if log_path.exists() and log_path.stat().st_size > max_bytes:
            backup = log_path.with_suffix(".jsonl.1")
            if backup.exists():
                backup.unlink()
            log_path.rename(backup)

        line = json.dumps(record, separators=(",", ":")) + "\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
        return True
    except OSError as exc:
        sys.stderr.write(f"ANIE telemetry logging error: {exc}\n")
        sys.stderr.flush()
        return False


class BatchOrchestrator:
    """Bounded, policy-governed one-shot batch execution orchestrator."""

    def __init__(
        self,
        config: BatchConfig,
        collector_factory: Callable[..., Any] | None = None,
        mem_fn: Callable[[], int | None] | None = None,
        disk_fn: Callable[[Path], int] | None = None,
    ):
        self.config = config
        self._collector_factory = collector_factory
        self._mem_fn = mem_fn
        self._disk_fn = disk_fn

    def determine_batch_queries(self) -> list[tuple[str, str]]:
        """Determine sequential queries satisfying the 30-minute per-domain cooldown."""
        if self.config.pilot_mode:
            from .pilot_governor import PilotGovernor
            pilot_db = self.config.pilot_db_path or self.config.quota_db_path
            gov = PilotGovernor(pilot_db, sentinel_path=self.config.pilot_sentinel_path)
            run_id, day_num, raw_queries = gov.check_and_plan_pilot_batch()
            self._pilot_run_id = run_id
            self._pilot_day_number = day_num
        elif self.config.explicit_queries is not None:
            raw_queries = self.config.explicit_queries
        elif self.config.query_mode in ("dns_a", "dns_aaaa"):
            raw_queries = [(d, self.config.query_mode) for d in self.config.domains]
        else:
            # Query alternation mode: inspect last persisted record per domain
            raw_queries = []
            store = None
            if self.config.store_db_path.exists():
                try:
                    store = RealObservationStore(self.config.store_db_path)
                except Exception as exc:
                    if self.config.mode == "live":
                        raise RuntimeError(
                            f"failed to initialize real observation store for query alternation: {exc}"
                        ) from exc
                    store = None

            for d in self.config.domains:
                next_kind = "dns_a"
                if store is not None:
                    try:
                        obs = store.by_subject(d)
                        if obs:
                            last_obs = obs[-1]
                            if last_obs.kind == "dns_a":
                                next_kind = "dns_aaaa"
                            else:
                                next_kind = "dns_a"
                    except Exception as exc:
                        if self.config.mode == "live":
                            raise RuntimeError(
                                f"failed to read previous observations for '{d}' from real store: {exc}"
                            ) from exc
                raw_queries.append((d, next_kind))

        # 1. Canonicalize domains and check uniqueness
        canonical_queries: list[tuple[str, str]] = []
        canonical_domains: list[str] = []
        for domain, kind in raw_queries:
            if not isinstance(domain, str):
                raise ScopeDenied(f"domain must be a string: got {type(domain)}")
            c_domain = domain.strip().lower().rstrip(".")
            canonical_domains.append(c_domain)
            canonical_queries.append((c_domain, kind))

        # 2. Pilot batch envelope: <= 2 domains
        validate_batch_domains(canonical_domains)

        # 3. Pilot cooldown invariant: duplicate domain within one batch is strictly forbidden
        if len(canonical_domains) != len(set(canonical_domains)):
            raise ScopeDenied(
                "pilot envelope prohibits duplicate domains within one batch "
                "to satisfy the 30-minute per-domain cooldown; use alternating batches"
            )

        # 4. Overall ceiling: <= 4 total queries per batch
        if len(canonical_queries) > MAX_QUERIES_PER_BATCH:
            raise ScopeDenied(
                f"batch query count ({len(canonical_queries)}) exceeds maximum ceiling of {MAX_QUERIES_PER_BATCH}"
            )

        # 5. Validate all kinds and targets
        for domain, kind in canonical_queries:
            validate_target(domain, kind)

        return canonical_queries

    def _record_pilot_outcome(self, report: BatchReport) -> None:
        """Persist pilot batch outcome into durable pilot schedule state if in pilot mode."""
        if self.config.pilot_mode and hasattr(self, "_pilot_run_id") and self._pilot_run_id is not None:
            try:
                from .pilot_governor import PilotGovernor
                pilot_db = self.config.pilot_db_path or self.config.quota_db_path
                gov = PilotGovernor(pilot_db, sentinel_path=self.config.pilot_sentinel_path)
                gov.record_pilot_outcome(
                    run_id=self._pilot_run_id,
                    outcome=report.outcome,
                    batch_id=report.batch_id,
                    error_reason=report.reason,
                )
            except Exception as exc:
                sys.stderr.write(f"ANIE warning: failed to record pilot outcome in state db: {exc}\n")

    def execute_batch(self) -> BatchReport:
        """Execute one bounded batch run under host-health and policy governance."""
        t0 = time.monotonic()
        batch_id = f"batch_{uuid.uuid4().hex[:16]}"
        now_utc = datetime.now(timezone.utc)
        start_iso = now_utc.isoformat(timespec="seconds").replace("+00:00", "Z")

        # 1. Enforce exact allowlist of execution modes fail-closed
        if self.config.mode not in VALID_MODES:
            completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            report = BatchReport(
                batch_id=batch_id,
                started_at=start_iso,
                completed_at=completed_iso,
                duration_seconds=time.monotonic() - t0,
                mode=str(self.config.mode),
                outcome="FAILED",
                reason=f"invalid execution mode '{self.config.mode}': must be one of {sorted(VALID_MODES)}",
            )
            emit_telemetry(report.to_dict(), self.config.log_file_path)
            return report

        # 2. Validate Live Mode Authorization Gate
        if self.config.mode == "live":
            auth_env = os.environ.get("ANIE_LIVE_COLLECTION_AUTHORIZED")
            if auth_env != "1":
                completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                report = BatchReport(
                    batch_id=batch_id,
                    started_at=start_iso,
                    completed_at=completed_iso,
                    duration_seconds=time.monotonic() - t0,
                    mode=self.config.mode,
                    outcome="FAILED",
                    reason="live collection unauthorized: ANIE_LIVE_COLLECTION_AUTHORIZED=1 environment required",
                )
                emit_telemetry(report.to_dict(), self.config.log_file_path)
                return report

        # 3. Advisory Process Lock (protects complete execution critical section)
        lock_target = self.config.lock_file_path or (self.config.quota_db_path.parent / "collector.lock")
        try:
            with acquire_collector_lock(lock_target):
                # 4. Scope and Query Envelope Determination
                try:
                    batch_queries = self.determine_batch_queries()
                except (ScopeDenied, ValueError, RuntimeError) as exc:
                    completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    report = BatchReport(
                        batch_id=batch_id,
                        started_at=start_iso,
                        completed_at=completed_iso,
                        duration_seconds=time.monotonic() - t0,
                        mode=self.config.mode,
                        outcome="FAILED",
                        reason=f"scope validation error: {exc}",
                        scope={"domains": self.config.domains, "queries_requested": self.config.query_mode},
                    )
                    self._record_pilot_outcome(report)
                    emit_telemetry(report.to_dict(), self.config.log_file_path)
                    return report

                # 5. Host Safeguard Preflight Checks
                preflight = run_preflight_checks(
                    quota_db_path=self.config.quota_db_path,
                    store_db_path=self.config.store_db_path,
                    lock_path=self.config.lock_file_path,
                    log_path=self.config.log_file_path,
                    min_mem_mb=self.config.min_mem_mb,
                    min_disk_mb=self.config.min_disk_mb,
                    mem_fn=self._mem_fn,
                    disk_fn=self._disk_fn,
                )

                if not preflight.passed:
                    completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    # Distinguish genuine resource shortages (SKIPPED) from operational errors (FAILED)
                    outcome = "FAILED" if preflight.operational_error else "SKIPPED"
                    report = BatchReport(
                        batch_id=batch_id,
                        started_at=start_iso,
                        completed_at=completed_iso,
                        duration_seconds=time.monotonic() - t0,
                        mode=self.config.mode,
                        outcome=outcome,
                        reason=preflight.failure_reason,
                        scope={"queries": batch_queries},
                        preflight=asdict(preflight),
                        queries_planned=len(batch_queries),
                        queries_skipped=len(batch_queries),
                    )
                    self._record_pilot_outcome(report)
                    emit_telemetry(report.to_dict(), self.config.log_file_path)
                    return report

                # 6. Dry-Run Execution: purely planned, zero live operations reported
                if self.config.mode == "dry_run":
                    completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    report = BatchReport(
                        batch_id=batch_id,
                        started_at=start_iso,
                        completed_at=completed_iso,
                        duration_seconds=time.monotonic() - t0,
                        mode="dry_run",
                        outcome="SUCCESS",
                        scope={"queries": batch_queries},
                        preflight=asdict(preflight),
                        queries_planned=len(batch_queries),
                        queries_attempted=0,
                        queries_succeeded=0,
                        queries_failed=0,
                        queries_skipped=0,
                        records_persisted={"observation_ids": [], "event_ids": []},
                    )
                    self._record_pilot_outcome(report)
                    emit_telemetry(report.to_dict(), self.config.log_file_path)
                    return report

                # 7. Live Collection Execution under monotonic overall batch deadline
                batch_deadline = t0 + self.config.timeout_seconds
                governor = DohRateGovernor(self.config.quota_db_path)
                store = RealObservationStore(self.config.store_db_path)

                if self._collector_factory is not None:
                    collector = self._collector_factory(
                        rate_governor=governor, timeout_seconds=self.config.timeout_seconds
                    )
                else:
                    collector = DohCollector(
                        rate_governor=governor, timeout_seconds=self.config.timeout_seconds
                    )

                succeeded = 0
                failed = 0
                persisted_obs: list[str] = []
                persisted_events: list[str] = []

                for domain, kind in batch_queries:
                    remaining_timeout = batch_deadline - time.monotonic()
                    if remaining_timeout <= 0:
                        failed += 1
                        sys.stderr.write(
                            f"ANIE query error for {domain} {kind}: overall batch deadline "
                            f"({self.config.timeout_seconds:.2f}s) exhausted\n"
                        )
                        continue

                    try:
                        try:
                            event, obs = collector.collect(
                                domain, kind, timeout_seconds=remaining_timeout
                            )
                        except TypeError:
                            event, obs = collector.collect(domain, kind)
                        store.insert_record(event, obs)
                        persisted_obs.append(obs.observation_id)
                        persisted_events.append(event.event_id)
                        succeeded += 1
                    except Exception as exc:
                        failed += 1
                        sys.stderr.write(f"ANIE query error for {domain} {kind}: {exc}\n")

                completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                outcome = "SUCCESS" if failed == 0 else ("PARTIAL" if succeeded > 0 else "FAILED")
                report = BatchReport(
                    batch_id=batch_id,
                    started_at=start_iso,
                    completed_at=completed_iso,
                    duration_seconds=time.monotonic() - t0,
                    mode="live",
                    outcome=outcome,
                    scope={"queries": batch_queries},
                    preflight=asdict(preflight),
                    queries_planned=len(batch_queries),
                    queries_attempted=len(batch_queries),
                    queries_succeeded=succeeded,
                    queries_failed=failed,
                    records_persisted={"observation_ids": persisted_obs, "event_ids": persisted_events},
                )
                self._record_pilot_outcome(report)
                emit_telemetry(report.to_dict(), self.config.log_file_path)
                return report

        except BlockingIOError as exc:
            completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            report = BatchReport(
                batch_id=batch_id,
                started_at=start_iso,
                completed_at=completed_iso,
                duration_seconds=time.monotonic() - t0,
                mode=self.config.mode,
                outcome="SKIPPED",
                reason=f"concurrency lock contention: {exc}",
                preflight={},
            )
            self._record_pilot_outcome(report)
            emit_telemetry(report.to_dict(), self.config.log_file_path)
            return report
        except Exception as exc:
            completed_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            report = BatchReport(
                batch_id=batch_id,
                started_at=start_iso,
                completed_at=completed_iso,
                duration_seconds=time.monotonic() - t0,
                mode=self.config.mode,
                outcome="FAILED",
                reason=f"unhandled batch error: {exc}",
                preflight={},
            )
            self._record_pilot_outcome(report)
            emit_telemetry(report.to_dict(), self.config.log_file_path)
            return report


def main(argv: list[str] | None = None) -> int:
    """Entry point for python -m anie.orchestrator."""
    from .cli import main as cli_main

    args = ["collect-batch"] + (argv if argv is not None else sys.argv[1:])
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
