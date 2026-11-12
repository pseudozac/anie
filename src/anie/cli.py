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
    p = sub.add_parser("publish-real", help="export deterministic first-party intelligence dataset")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--out", required=True, help="path to output publication directory")
    p.add_argument("--as-of", required=True, help="cutoff timestamp (UTC ISO format)")
    p.add_argument("--publisher", default="anie-first-party", help="publisher identity")
    p.add_argument("--sequence", type=int, default=1, help="monotonically increasing release sequence")
    p.add_argument("--commit", default=None, help="source repository commit hash")
    p.add_argument("--published-at", default=None, help="optional fixed publication timestamp for reproducible manifest")
    p = sub.add_parser("sign-real", help="detached offline Ed25519 signing of candidate release")
    p.add_argument("--dir", required=True, help="path to unsigned candidate release directory")
    p.add_argument("--key-file", required=True, help="path to operator Ed25519 private key (PEM or 32 raw bytes)")
    p.add_argument("--key-id", required=True, help="operator key identifier")
    p.add_argument("--sequence", type=int, required=True, help="expected release sequence (must match manifest)")
    p.add_argument("--publisher", default="anie-first-party", help="expected publisher (must match manifest)")
    p.add_argument("--commit", default=None, help="expected source commit (must match manifest if given)")
    p.add_argument("--issued-at", default=None, help="optional ISO-8601 signature issuance timestamp (defaults to now)")
    p.add_argument("--expires-at", default=None, help="optional ISO-8601 signature expiration timestamp (defaults to issued_at + 30 days)")
    p.add_argument("--valid-days", type=int, default=30, help="validity window in days if expires-at is not set")
    p = sub.add_parser("verify-real", help="verify integrity, evidence, and Ed25519 signature of real dataset")
    p.add_argument("--dir", required=True, help="path to publication directory")
    p.add_argument("--key-file", default=None, help="path to operator-pinned Ed25519 public key file (required for authenticated verification)")
    p.add_argument("--key-id", default=None, help="expected key ID (default: key-1)")
    p.add_argument("--state-file", default=None, help="path to sequence tracking state file for rollback protection")
    p.add_argument("--init-state", action="store_true", help="explicitly initialize state file if missing")
    p.add_argument("--allow-rollback", action="store_true", help="allow historical verification without rollback error")
    p.add_argument("--integrity-only", action="store_true", help="inspect candidate release integrity without cryptographic authentication")
    p.add_argument("--now", default=None, help="optional frozen timestamp for verification")
    p.add_argument("--expected-publisher", default="anie-first-party", help="expected publisher identity")
    p.add_argument("--expected-commit", default=None, help="expected source repository commit hash")
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
    p.add_argument("--timeout", type=float, default=20.0, help="overall batch execution timeout")
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
        elif args.command == "publish-real":
            from .real_publish import publish_real
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            manifest = publish_real(
                store,
                args.out,
                args.as_of,
                publisher_identity=args.publisher,
                release_sequence=args.sequence,
                source_commit=args.commit,
                published_at=args.published_at,
            )
            print(json.dumps({"published": True, "manifest": manifest}, indent=2))
            return 0
        elif args.command == "sign-real":
            from datetime import datetime, timedelta, timezone
            from .real_publish import (
                load_private_key_file,
                sign_manifest_detached,
                verify_real_release,
            )
            # 1. Validate candidate release integrity before signing
            verify_real_release(args.dir, integrity_only=True)
            # 2. Strict key loading
            priv_key = load_private_key_file(args.key_file)
            now_dt = datetime.now(timezone.utc)
            issued_iso = args.issued_at or now_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
            if args.expires_at:
                expires_iso = args.expires_at
            else:
                issued_parsed = datetime.fromisoformat(issued_iso.replace("Z", "+00:00"))
                expires_iso = (issued_parsed + timedelta(days=args.valid_days)).isoformat(timespec="seconds").replace("+00:00", "Z")
            attestation = sign_manifest_detached(
                args.dir,
                priv_key,
                key_id=args.key_id,
                release_sequence=args.sequence,
                issued_at=issued_iso,
                expires_at=expires_iso,
                publisher_identity=args.publisher,
                source_commit=args.commit,
            )
            print(json.dumps({"signed": True, "attestation": attestation}, indent=2))
            return 0
        elif args.command == "verify-real":
            from .real_publish import (
                RealReleaseTrust,
                ReleaseSequenceTracker,
                TrackerStateError,
                TrackerStateLostError,
                load_public_key_file,
                verify_real_release,
            )
            if not args.integrity_only and not args.key_file:
                print(
                    "ANIE error: --key-file is required for authenticated verification; "
                    "pass --integrity-only to inspect unsigned candidate release",
                    file=sys.stderr,
                )
                return 2

            trust = None
            if args.key_file:
                pub_bytes = load_public_key_file(args.key_file)
                key_id = args.key_id or "key-1"
                trust = RealReleaseTrust.from_single_key(
                    key_id=key_id,
                    public_key_raw=pub_bytes,
                    valid_from="2026-01-01T00:00:00Z",
                    valid_until="2030-01-01T00:00:00Z",
                    expected_publisher=args.expected_publisher,
                    expected_source_commit=args.expected_commit,
                )

            tracker = None
            if args.state_file:
                tracker = ReleaseSequenceTracker(args.state_file, auto_init=args.init_state)

            res = verify_real_release(
                args.dir,
                trust=trust,
                integrity_only=args.integrity_only,
                now=args.now,
                allow_rollback=args.allow_rollback,
                sequence_tracker=tracker,
                allow_uninitialized_state=args.init_state,
            )
            print(json.dumps(res, indent=2))
            if not args.integrity_only and not res.get("authenticated"):
                return 1
            if args.integrity_only and not res.get("evidence_integrity_valid"):
                return 1
            return 0
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
            if report.outcome in ("SUCCESS", "SKIPPED"):
                return 0
            # Distinguish PARTIAL and FAILED outcomes with non-zero exit code
            return 1
        return 0
    except (ValueError, PermissionError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f"ANIE error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
