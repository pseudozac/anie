from pathlib import Path
from tempfile import TemporaryDirectory
import gzip
import json
import unittest
from anie.demo import demo_observations
from anie.publish import publish_synthetic


class TestSchema(unittest.TestCase):
    def test_json_schema_if_dependency_available(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema optional CI validation tool unavailable")
        schema = json.loads((Path(__file__).resolve().parent.parent / "schemas" / "intelligence-v1.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        with TemporaryDirectory() as tmp:
            publish_synthetic(demo_observations(), tmp, "2026-11-11T10:00:00Z")
            with gzip.open(Path(tmp) / "intelligence.jsonl.gz", "rt") as f:
                for line in f:
                    jsonschema.validate(json.loads(line), schema)
