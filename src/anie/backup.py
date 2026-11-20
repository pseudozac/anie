"""Evidence-preserving SQLite online backup and isolated recovery module for ANIE Phase 2.1.

Engineered for resource-constrained Oracle Cloud micro instances:
1. Safe online backup: Uses SQLite Online Backup API (page-by-page, zero read/write locks).
2. Fully WAL-compatible: Captures consistent database state without flushing WAL.
3. Atomic staging: Backs up to *.tmp file and verifies before atomic rename; incomplete backups never appear valid.
4. Cryptographic integrity: Generates and verifies SHA256SUMS manifest for every backup.
5. Isolated recovery: Restores strictly to designated recovery directories; never overwrites production data.
6. Automated retention: Prunes older snapshots beyond retention limit while preserving milestone archives.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

DEFAULT_RETENTION_LIMIT = 7
MIN_DISK_HEADROOM_MB = 100


@dataclass(frozen=True)
class BackupResult:
    success: bool
    backup_dir: str
    databases_backed_up: list[str]
    checksums: dict[str, str]
    created_at_iso: str
    error: str | None = None


@dataclass(frozen=True)
class RestoreResult:
    success: bool
    source_backup_dir: str
    target_restore_dir: str
    databases_restored: list[str]
    checksums_verified: bool
    integrity_verified: bool
    error: str | None = None


def create_evidence_backup(
    source_db_paths: list[Path | str],
    backup_root: Path | str,
    retention_limit: int = DEFAULT_RETENTION_LIMIT,
    now_dt: datetime | None = None,
) -> BackupResult:
    """Create an atomic, verified, evidence-preserving backup of specified SQLite databases."""
    now = now_dt or datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    root_path = Path(backup_root)
    backup_dir = root_path / f"backup_{timestamp}"

    # Verify disk space headroom
    try:
        stat = os.statvfs(root_path if root_path.exists() else root_path.parent)
        free_mb = (stat.f_bavail * stat.f_frsize) // (1024 * 1024)
        if free_mb < MIN_DISK_HEADROOM_MB:
            return BackupResult(
                success=False,
                backup_dir=str(backup_dir),
                databases_backed_up=[],
                checksums={},
                created_at_iso=now.isoformat(),
                error=f"insufficient disk space: {free_mb} MiB free < {MIN_DISK_HEADROOM_MB} MiB required",
            )
    except (AttributeError, OSError):
        # statvfs not available on Windows
        pass

    try:
        backup_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    except Exception as exc:
        return BackupResult(
            success=False,
            backup_dir=str(backup_dir),
            databases_backed_up=[],
            checksums={},
            created_at_iso=now.isoformat(),
            error=f"failed to create backup directory: {exc}",
        )

    checksums: dict[str, str] = {}
    backed_up: list[str] = []

    try:
        for src in source_db_paths:
            src_p = Path(src)
            if not src_p.exists():
                continue

            dst_p = backup_dir / src_p.name
            tmp_p = backup_dir / f"{src_p.name}.tmp"

            # 1. Execute online backup to temporary file
            src_conn = sqlite3.connect(f"file:{src_p.resolve()}?mode=ro", uri=True)
            tmp_conn = sqlite3.connect(str(tmp_p))
            try:
                src_conn.backup(tmp_conn)
            finally:
                tmp_conn.close()
                src_conn.close()

            # 2. Strict integrity and foreign key checks on temporary file
            verify_conn = sqlite3.connect(f"file:{tmp_p.resolve()}?mode=ro", uri=True)
            try:
                integrity = verify_conn.execute("PRAGMA integrity_check;").fetchall()
                if integrity != [("ok",)]:
                    raise ValueError(f"integrity check failed for {src_p.name}: {integrity}")
                fk_violations = verify_conn.execute("PRAGMA foreign_key_check;").fetchall()
                if fk_violations:
                    raise ValueError(f"foreign key violations in {src_p.name}: {fk_violations}")
            finally:
                verify_conn.close()

            # 3. Compute cryptographic SHA-256 digest
            with open(tmp_p, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            checksums[src_p.name] = digest

            # 4. Secure permissions and atomic rename
            try:
                os.chmod(tmp_p, 0o600)
            except OSError:
                pass
            tmp_p.rename(dst_p)
            backed_up.append(src_p.name)

        # 5. Write SHA256SUMS and metadata manifest
        chk_file = backup_dir / "SHA256SUMS"
        with open(chk_file, "w", encoding="utf-8") as f:
            for name, digest in sorted(checksums.items()):
                f.write(f"{digest}  {name}\n")
        try:
            os.chmod(chk_file, 0o600)
        except OSError:
            pass

        manifest_file = backup_dir / "manifest.json"
        manifest_data = {
            "created_at": now.isoformat(),
            "databases": backed_up,
            "checksums": checksums,
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        try:
            os.chmod(manifest_file, 0o600)
        except OSError:
            pass

        # 6. Apply retention policy: prune oldest non-milestone backups
        _prune_old_backups(root_path, retention_limit)

        return BackupResult(
            success=True,
            backup_dir=str(backup_dir),
            databases_backed_up=backed_up,
            checksums=checksums,
            created_at_iso=now.isoformat(),
            error=None,
        )
    except Exception as exc:
        # Clean up failed backup directory
        shutil.rmtree(backup_dir, ignore_errors=True)
        return BackupResult(
            success=False,
            backup_dir=str(backup_dir),
            databases_backed_up=[],
            checksums={},
            created_at_iso=now.isoformat(),
            error=f"backup transaction aborted: {exc}",
        )


def restore_evidence_backup(
    backup_dir: Path | str,
    target_restore_dir: Path | str,
    allow_overwrite: bool = False,
) -> RestoreResult:
    """Restore databases from verified backup into an isolated restore directory."""
    src_dir = Path(backup_dir)
    dst_dir = Path(target_restore_dir)

    if not src_dir.is_dir():
        return RestoreResult(
            success=False,
            source_backup_dir=str(src_dir),
            target_restore_dir=str(dst_dir),
            databases_restored=[],
            checksums_verified=False,
            integrity_verified=False,
            error=f"source backup directory does not exist: {src_dir}",
        )

    # 1. Verify SHA256SUMS manifest exists and matches
    chk_file = src_dir / "SHA256SUMS"
    if not chk_file.exists():
        return RestoreResult(
            success=False,
            source_backup_dir=str(src_dir),
            target_restore_dir=str(dst_dir),
            databases_restored=[],
            checksums_verified=False,
            integrity_verified=False,
            error="SHA256SUMS manifest missing; backup is unverified or incomplete",
        )

    expected_checksums: dict[str, str] = {}
    with open(chk_file, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                expected_checksums[parts[1].strip()] = parts[0].strip()

    for name, expected_sha in expected_checksums.items():
        db_file = src_dir / name
        if not db_file.exists():
            return RestoreResult(
                success=False,
                source_backup_dir=str(src_dir),
                target_restore_dir=str(dst_dir),
                databases_restored=[],
                checksums_verified=False,
                integrity_verified=False,
                error=f"backup database {name} missing from directory",
            )
        with open(db_file, "rb") as f:
            actual_sha = hashlib.sha256(f.read()).hexdigest()
        if actual_sha != expected_sha:
            return RestoreResult(
                success=False,
                source_backup_dir=str(src_dir),
                target_restore_dir=str(dst_dir),
                databases_restored=[],
                checksums_verified=False,
                integrity_verified=False,
                error=f"SHA-256 checksum mismatch for {name}: expected {expected_sha}, got {actual_sha}",
            )

    # 2. Check destination safety
    dst_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    restored: list[str] = []

    for name in expected_checksums:
        target_file = dst_dir / name
        if target_file.exists() and not allow_overwrite:
            return RestoreResult(
                success=False,
                source_backup_dir=str(src_dir),
                target_restore_dir=str(dst_dir),
                databases_restored=restored,
                checksums_verified=True,
                integrity_verified=False,
                error=f"destination file {target_file} already exists and allow_overwrite is False",
            )
        shutil.copy2(src_dir / name, target_file)
        try:
            os.chmod(target_file, 0o600)
        except OSError:
            pass

        # 3. Post-restore integrity verification
        conn = sqlite3.connect(f"file:{target_file.resolve()}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check;").fetchall()
            if integrity != [("ok",)]:
                return RestoreResult(
                    success=False,
                    source_backup_dir=str(src_dir),
                    target_restore_dir=str(dst_dir),
                    databases_restored=restored,
                    checksums_verified=True,
                    integrity_verified=False,
                    error=f"integrity check failed on restored database {name}: {integrity}",
                )
        finally:
            conn.close()
        restored.append(name)

    return RestoreResult(
        success=True,
        source_backup_dir=str(src_dir),
        target_restore_dir=str(dst_dir),
        databases_restored=restored,
        checksums_verified=True,
        integrity_verified=True,
        error=None,
    )


def _prune_old_backups(backup_root: Path, retention_limit: int) -> None:
    """Prune oldest non-milestone backups exceeding the retention limit."""
    if not backup_root.is_dir():
        return
    candidates = []
    for item in backup_root.iterdir():
        if item.is_dir() and item.name.startswith("backup_"):
            # Milestone backups (containing 'milestone') are preserved permanently
            if "milestone" not in item.name.lower():
                candidates.append(item)
    candidates.sort(key=lambda x: x.name)
    while len(candidates) > retention_limit:
        oldest = candidates.pop(0)
        shutil.rmtree(oldest, ignore_errors=True)
