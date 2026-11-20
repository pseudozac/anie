import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from anie.cli import main
from anie.demo import demo_observations


class TestCLI(unittest.TestCase):
    def test_demo_end_to_end(self):
        with TemporaryDirectory() as tmp:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["demo", "--out", str(Path(tmp) / "demo")]), 0)
                self.assertEqual(main(["verify", "--dir", str(Path(tmp) / "demo" / "publication")]), 0)

    def test_ingest_only_synthetic(self):
        with TemporaryDirectory() as tmp:
            f = Path(tmp) / "fixture.json"
            f.write_text(json.dumps([demo_observations()[0].to_dict()]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["ingest", "--db", str(Path(tmp) / "db.sqlite"), "--input", str(f)]), 0)

    def test_cli_backup_and_restore(self):
        import sqlite3
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db1 = tmp_p / "db1.sqlite"
            conn = sqlite3.connect(str(db1))
            try:
                conn.executescript("CREATE TABLE t (id INT); INSERT INTO t VALUES (42);")
            finally:
                conn.close()

            backup_out = tmp_p / "backups"
            buf = io.StringIO()
            with redirect_stdout(buf):
                ret = main(["backup", "--dbs", str(db1), "--out", str(backup_out)])
            self.assertEqual(ret, 0)
            rep = json.loads(buf.getvalue())
            self.assertTrue(rep["success"])
            backup_dir = rep["backup_dir"]

            restore_target = tmp_p / "restored"
            buf2 = io.StringIO()
            with redirect_stdout(buf2):
                ret2 = main(["restore", "--backup-dir", backup_dir, "--target", str(restore_target)])
            self.assertEqual(ret2, 0)
            restore_rep = json.loads(buf2.getvalue())
            self.assertTrue(restore_rep["success"])
            self.assertTrue((restore_target / "db1.sqlite").exists())
