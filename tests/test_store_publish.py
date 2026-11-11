import gzip
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from anie.demo import demo_observations
from anie.observations import Observation
from anie.publish import publish_synthetic, verify_release
from anie.store import ObservationStore

AS_OF = "2026-11-11T10:00:00Z"


class TestStorePublish(unittest.TestCase):
    def test_store_idempotence(self):
        with TemporaryDirectory() as tmp:
            db = ObservationStore(Path(tmp) / "state.db")
            sample = demo_observations()
            self.assertEqual(db.insert(sample), len(sample))
            self.assertEqual(db.insert(sample), 0)
            self.assertEqual(len(db.all()), len(sample))

    def test_publish_verify_and_determinism(self):
        with TemporaryDirectory() as tmp:
            samples = demo_observations()
            first = publish_synthetic(samples, Path(tmp) / "one", AS_OF)
            second = publish_synthetic(list(reversed(samples)), Path(tmp) / "two", AS_OF)
            self.assertEqual(first, second)
            self.assertTrue(verify_release(Path(tmp) / "one")["verified"])
            self.assertEqual((Path(tmp) / "one" / "intelligence.jsonl.gz").read_bytes(), (Path(tmp) / "two" / "intelligence.jsonl.gz").read_bytes())

    def test_refuses_data_non_synthetic_and_overwrite(self):
        with TemporaryDirectory() as tmp:
            samples = demo_observations()
            raw = samples[0].to_dict()
            raw["method"] = "dns"
            raw["synthetic"] = False
            samples.append(Observation.from_dict(raw))
            with self.assertRaises(PermissionError):
                publish_synthetic(samples, Path(tmp) / "out", AS_OF)
            samples.pop()
            publish_synthetic(samples, Path(tmp) / "out", AS_OF)
            with self.assertRaises(FileExistsError):
                publish_synthetic(samples, Path(tmp) / "out", AS_OF)

    def test_tampered_gzip_rejected(self):
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            publish_synthetic(demo_observations(), dest, AS_OF)
            f = dest / "intelligence.jsonl.gz"
            data = bytearray(f.read_bytes())
            data[-5] ^= 1
            f.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                verify_release(dest)

    def test_bad_evidence_reference_rejected_even_when_rehashed(self):
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            publish_synthetic(demo_observations(), dest, AS_OF)
            from hashlib import sha256
            f = dest / "intelligence.jsonl.gz"
            with gzip.open(f, "rt", encoding="utf-8") as stream:
                rows = [json.loads(line) for line in stream]
            rows[0]["evidence_ids"] = ["obs_missing"]
            with gzip.open(f, "wt", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")
            manifest_file = dest / "manifest.json"
            manifest = json.loads(manifest_file.read_text())
            entry = next(e for e in manifest["files"] if e["file"] == f.name)
            entry["sha256"] = sha256(f.read_bytes()).hexdigest()
            entry["bytes"] = f.stat().st_size
            manifest_file.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unresolved evidence"):
                verify_release(dest)
