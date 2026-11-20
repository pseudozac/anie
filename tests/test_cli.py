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

    def test_cli_keygen(self):
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            buf = io.StringIO()
            with redirect_stdout(buf):
                ret = main(["keygen", "--out", str(tmp_p), "--key-id", "cli-key-1"])
            self.assertEqual(ret, 0)
            rep = json.loads(buf.getvalue())
            self.assertTrue(rep["keygen"])
            self.assertEqual(rep["key_id"], "cli-key-1")
            self.assertTrue((tmp_p / "cli-key-1.priv").exists())
            self.assertTrue((tmp_p / "cli-key-1.pub").exists())
            self.assertTrue((tmp_p / "cli-key-1.meta.json").exists())

    def test_cli_provenance_and_hash_chain_workflow(self):
        from test_real_models import sample_event, sample_observation
        from anie.real_store import RealObservationStore

        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            db_path = tmp_p / "real.sqlite"
            store = RealObservationStore(db_path)
            ev = sample_event()
            obs = sample_observation(event=ev)
            store.insert_record(ev, obs)

            # 1. Keygen
            key_dir = tmp_p / "keys"
            with redirect_stdout(io.StringIO()):
                ret = main(["keygen", "--out", str(key_dir), "--key-id", "operator-1"])
            self.assertEqual(ret, 0)
            priv_key = key_dir / "operator-1.priv"
            pub_key = key_dir / "operator-1.pub"

            # 2. Publish release 1 candidate
            pub1 = tmp_p / "pub1"
            with redirect_stdout(io.StringIO()):
                ret = main([
                    "publish-real",
                    "--db", str(db_path),
                    "--out", str(pub1),
                    "--as-of", "2026-11-12T10:00:00Z",
                    "--sequence", "1",
                    "--commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--published-at", "2026-11-12T10:05:00Z",
                ])
            self.assertEqual(ret, 0)

            # 3. Inspect candidate 1
            buf_insp = io.StringIO()
            with redirect_stdout(buf_insp):
                ret = main(["inspect-candidate", "--dir", str(pub1)])
            self.assertEqual(ret, 0)
            insp_data = json.loads(buf_insp.getvalue())
            self.assertEqual(insp_data["status"], "CANDIDATE_INTEGRITY_VERIFIED")
            self.assertEqual(insp_data["release_sequence"], 1)

            # 4. Sign release 1
            with redirect_stdout(io.StringIO()):
                ret = main([
                    "sign-real",
                    "--dir", str(pub1),
                    "--key-file", str(priv_key),
                    "--key-id", "operator-1",
                    "--sequence", "1",
                    "--commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--issued-at", "2026-11-12T10:10:00Z",
                    "--expires-at", "2026-11-20T10:10:00Z",
                ])
            self.assertEqual(ret, 0)

            # 5. Verify release 1 with sequence tracker
            state_file = tmp_p / "verifier_state.json"
            buf_ver1 = io.StringIO()
            with redirect_stdout(buf_ver1):
                ret = main([
                    "verify-real",
                    "--dir", str(pub1),
                    "--key-file", str(pub_key),
                    "--key-id", "operator-1",
                    "--expected-commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--state-file", str(state_file),
                    "--init-state",
                    "--require-hash-chain",
                    "--now", "2026-11-12T10:15:00Z",
                ])
            self.assertEqual(ret, 0)
            res1 = json.loads(buf_ver1.getvalue())
            self.assertTrue(res1["authenticated"])
            self.assertTrue(res1["hash_chain_verified"])

            # 6. Publish release 2 chained to release 1 via --prev-release
            pub2 = tmp_p / "pub2"
            with redirect_stdout(io.StringIO()):
                ret = main([
                    "publish-real",
                    "--db", str(db_path),
                    "--out", str(pub2),
                    "--as-of", "2026-11-12T11:00:00Z",
                    "--sequence", "2",
                    "--prev-release", str(pub1),
                    "--commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--published-at", "2026-11-12T11:05:00Z",
                ])
            self.assertEqual(ret, 0)

            # 7. Sign release 2
            with redirect_stdout(io.StringIO()):
                ret = main([
                    "sign-real",
                    "--dir", str(pub2),
                    "--key-file", str(priv_key),
                    "--key-id", "operator-1",
                    "--sequence", "2",
                    "--commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--issued-at", "2026-11-12T11:10:00Z",
                    "--expires-at", "2026-11-20T11:10:00Z",
                ])
            self.assertEqual(ret, 0)

            # 8. Verify release 2: verifies hash chain and advances sequence to 2
            buf_ver2 = io.StringIO()
            with redirect_stdout(buf_ver2):
                ret = main([
                    "verify-real",
                    "--dir", str(pub2),
                    "--key-file", str(pub_key),
                    "--key-id", "operator-1",
                    "--expected-commit", "a64ddad12c2603ed0ef968542b26d1a14af836e2",
                    "--state-file", str(state_file),
                    "--require-hash-chain",
                    "--now", "2026-11-12T11:15:00Z",
                ])
            self.assertEqual(ret, 0)
            res2 = json.loads(buf_ver2.getvalue())
            self.assertTrue(res2["authenticated"])
            self.assertTrue(res2["hash_chain_verified"])
            self.assertEqual(res2["release_sequence"], 2)
            self.assertEqual(res2["prev_manifest_sha256"], res1["manifest_sha256"])
