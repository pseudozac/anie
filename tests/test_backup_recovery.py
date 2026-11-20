"""Test suite for Phase 2.1 evidence backup and isolated recovery module."""
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from anie.backup import create_evidence_backup, restore_evidence_backup


class TestBackupRecovery(unittest.TestCase):
    def test_backup_and_isolated_restore_roundtrip(self):
        """Test full backup creation and recovery with WAL database."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_p = tmp_p / "test_store.sqlite"
            backup_root = tmp_p / "backups"
            restore_target = tmp_p / "restored"

            # 1. Create source SQLite DB with WAL mode and test table
            conn = sqlite3.connect(db_p)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE items (id TEXT PRIMARY KEY, val TEXT NOT NULL)")
            conn.execute("INSERT INTO items VALUES ('item-1', 'hello-world')")
            conn.commit()
            conn.close()

            # 2. Create evidence backup
            res = create_evidence_backup([db_p], backup_root)
            self.assertTrue(res.success)
            self.assertEqual(len(res.databases_backed_up), 1)
            self.assertIn("test_store.sqlite", res.checksums)
            backup_dir = Path(res.backup_dir)
            self.assertTrue((backup_dir / "SHA256SUMS").exists())

            # 3. Restore to isolated target directory
            restore_res = restore_evidence_backup(backup_dir, restore_target)
            self.assertTrue(restore_res.success)
            self.assertTrue(restore_res.checksums_verified)
            self.assertTrue(restore_res.integrity_verified)

            # 4. Verify restored database contents
            restored_db = restore_target / "test_store.sqlite"
            self.assertTrue(restored_db.exists())
            r_conn = sqlite3.connect(restored_db)
            row = r_conn.execute("SELECT val FROM items WHERE id='item-1'").fetchone()
            self.assertEqual(row[0], "hello-world")
            r_conn.close()

    def test_restore_detects_checksum_tampering(self):
        """Restore must fail closed if any database file was tampered with."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_p = tmp_p / "store.sqlite"
            backup_root = tmp_p / "backups"
            restore_target = tmp_p / "restored"

            conn = sqlite3.connect(db_p)
            conn.execute("CREATE TABLE t (x INT)")
            conn.execute("INSERT INTO t VALUES (42)")
            conn.commit()
            conn.close()

            res = create_evidence_backup([db_p], backup_root)
            self.assertTrue(res.success)
            backup_dir = Path(res.backup_dir)

            # Tamper with the backup file
            backed_file = backup_dir / "store.sqlite"
            with open(backed_file, "ab") as f:
                f.write(b"corrupting_tamper_bytes")

            # Restore must fail closed
            restore_res = restore_evidence_backup(backup_dir, restore_target)
            self.assertFalse(restore_res.success)
            self.assertIn("checksum mismatch", restore_res.error)

    def test_restore_rejects_missing_checksum_manifest(self):
        """Incomplete backup lacking SHA256SUMS must be rejected."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_p = tmp_p / "store.sqlite"
            backup_root = tmp_p / "backups"
            restore_target = tmp_p / "restored"

            conn = sqlite3.connect(db_p)
            conn.execute("CREATE TABLE t (x INT)")
            conn.close()

            res = create_evidence_backup([db_p], backup_root)
            backup_dir = Path(res.backup_dir)

            # Remove SHA256SUMS
            (backup_dir / "SHA256SUMS").unlink()

            restore_res = restore_evidence_backup(backup_dir, restore_target)
            self.assertFalse(restore_res.success)
            self.assertIn("SHA256SUMS manifest missing", restore_res.error)

    def test_restore_prevents_accidental_overwrite(self):
        """Restore must refuse to overwrite existing target files unless allow_overwrite=True."""
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_p = tmp_p / "store.sqlite"
            backup_root = tmp_p / "backups"
            restore_target = tmp_p / "restored"

            conn = sqlite3.connect(db_p)
            conn.execute("CREATE TABLE t (x INT)")
            conn.close()

            res = create_evidence_backup([db_p], backup_root)
            backup_dir = Path(res.backup_dir)

            restore_target.mkdir(parents=True)
            existing_target = restore_target / "store.sqlite"
            existing_target.write_text("existing_content")

            restore_res = restore_evidence_backup(backup_dir, restore_target, allow_overwrite=False)
            self.assertFalse(restore_res.success)
            self.assertIn("already exists", restore_res.error)


if __name__ == "__main__":
    unittest.main()
