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
    p = sub.add_parser("collect-batch", help="execute bounded one-shot batch collection")
    p.add_argument("--domains", nargs="+", default=["example.com", "iana.org"], help="target domains (max 2)")
    p.add_argument("--kind", choices=["alternate", "dns_a", "dns_aaaa"], default="alternate", help="query record kind")
    p.add_argument("--mode", choices=["dry_run", "live"], default="dry_run", help="execution mode (default: dry_run)")
    p.add_argument("--live", action="store_true", help="enable live execution (requires ANIE_LIVE_COLLECTION_AUTHORIZED=1)")
    p.add_argument("--quota-db", default="local-data/doh_quota.sqlite", help="path to persistent SQLite quota database")
    p.add_argument("--store-db", default="local-data/real_intelligence.sqlite", help="path to real intelligence SQLite database")
    p.add_argument("--log-file", default=None, help="path to telemetry log file")
    p.add_argument("--lock-file", default=None, help="path to advisory concurrency lock file")
    p.add_argument("--min-mem-mb", type=int, default=200, help="minimum required host RAM in MiB")
    p.add_argument("--min-disk-mb", type=int, default=500, help="minimum required disk capacity in MiB")
    p.add_argument("--timeout", type=float, default=25.0, help="overall batch execution timeout")
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
        elif args.command == "collect-batch":
            from .orchestrator import BatchConfig, BatchOrchestrator
            mode = "live" if (args.live or args.mode == "live") else "dry_run"
            config = BatchConfig(
                domains=args.domains,
                query_mode=args.kind,
                mode=mode,
                quota_db_path=Path(args.quota_db),
                store_db_path=Path(args.store_db),
                log_file_path=Path(args.log_file) if args.log_file else None,
                lock_file_path=Path(args.lock_file) if args.lock_file else None,
                min_mem_mb=args.min_mem_mb,
                min_disk_mb=args.min_disk_mb,
                timeout_seconds=args.timeout,
            )
            orchestrator = BatchOrchestrator(config)
            report = orchestrator.execute_batch()
            print(report.to_json())
            if report.outcome == "FAILED":
                return 1
            return 0
        return 0
    except (ValueError, PermissionError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f"ANIE error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
