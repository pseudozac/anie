"""Reference AEGIS-style reader: verify, then consume ANIE findings offline.

Does NOT connect to AEGIS, modify its databases or trust ANIE outlier
assessments as incident verdicts. Run after `anie demo`.

  python examples/aegis_readonly_consumer.py local-data/demo/publication
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import sys
from anie.publish import verify_release


def read_for_aegis(directory: str | Path) -> list[dict]:
    directory = Path(directory)
    verify_release(directory)
    with gzip.open(directory / "intelligence.jsonl.gz", "rt", encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream]
    return [{
        "ioc_type": r["indicator"]["type"],
        "ioc": r["indicator"]["value"],
        "finding": r["finding"]["statement"],
        "anie_ai_status": r["assessment"]["ai"]["status"],
        "maliciousness": r["finding"]["maliciousness"],
        "evidence_ids": r["evidence_ids"],
        "assessed_at": r["assessed_at"],
    } for r in records]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python examples/aegis_readonly_consumer.py DIR")
    rows = read_for_aegis(sys.argv[1])
    print(json.dumps({"loaded": len(rows), "novelty_outliers": [r for r in rows if r["anie_ai_status"] == "outlier"]}, indent=2))
