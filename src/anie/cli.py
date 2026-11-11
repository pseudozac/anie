"""Offline ANIE command-line interface. No network code in v0.1."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .demo import demo_observations
from .observations import Observation
from .publish import publish_synthetic, verify_release
from .store import ObservationStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ANIE v0.1: offline synthetic intelligence research")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo", help="generate synthetic observations and a verified local dataset")
    p.add_argument("--out", required=True)
    p = sub.add_parser("ingest", help="ingest synthetic observations from a local JSON array")
    p.add_argument("--db", required=True)
    p.add_argument("--input", required=True)
    p = sub.add_parser("publish", help="create local synthetic-only versioned dataset")
    p.add_argument("--db", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--as-of", required=True)
    p = sub.add_parser("verify", help="verify local synthetic dataset and recompute findings")
    p.add_argument("--dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            base = Path(args.out)
            base.mkdir(parents=True, exist_ok=True)
            store = ObservationStore(base / "anie.sqlite")
            inserted = store.insert(demo_observations())
            manifest = publish_synthetic(store.all(), base / "publication", "2026-11-11T10:00:00Z")
            result = verify_release(base / "publication")
            print(json.dumps({"inserted": inserted, "publication": str(base / "publication"), **result}, indent=2))
        elif args.command == "ingest":
            path = Path(args.input)
            if path.stat().st_size > 5_000_000:
                raise ValueError("input file too large")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, list) or len(raw) > 10000:
                raise ValueError("input must be a bounded JSON array")
            observations = [Observation.from_dict(x) for x in raw]
            if any(not o.synthetic for o in observations):
                raise PermissionError("v0.1 ingestion only accepts synthetic fixtures")
            print(json.dumps({"inserted": ObservationStore(args.db).insert(observations)}))
        elif args.command == "publish":
            store = ObservationStore(args.db)
            result = publish_synthetic(store.all(), args.out, args.as_of)
            print(json.dumps({"published": True, "files": result["files"]}, indent=2))
        elif args.command == "verify":
            print(json.dumps(verify_release(args.dir), indent=2))
        return 0
    except (ValueError, PermissionError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f"ANIE error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
