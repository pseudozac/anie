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
