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
    p.add_argument("--sign-key", default=None, help="optional path to Ed25519 private key for detached signing")
    p.add_argument("--key-id", default=None, help="key ID for detached signature (required if --sign-key is given)")
    p = sub.add_parser("verify-real", help="verify integrity, evidence, and Ed25519 signature of real dataset")
    p.add_argument("--dir", required=True, help="path to publication directory")
    p.add_argument("--key-file", default=None, help="optional path to operator-pinned Ed25519 public key file")
    p.add_argument("--key-id", default=None, help="expected key ID (default: key-1)")
    p.add_argument("--state-file", default=None, help="path to sequence tracking state file for rollback protection")
    p.add_argument("--allow-rollback", action="store_true", help="allow historical verification without rollback error")
    p.add_argument("--now", default=None, help="optional frozen timestamp for verification")
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
            from datetime import datetime, timedelta, timezone
            from .real_publish import publish_real, sign_manifest_detached
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            manifest = publish_real(
                store,
                args.out,
                args.as_of,
                publisher_identity=args.publisher,
                release_sequence=args.sequence,
                source_commit=args.commit,
            )
            attestation = None
            if args.sign_key:
                if not args.key_id:
                    raise ValueError("--key-id is required when --sign-key is provided")
                from cryptography.hazmat.primitives import serialization
                key_path = Path(args.sign_key)
                key_bytes = key_path.read_bytes()
                try:
                    priv_key = serialization.load_pem_private_key(key_bytes, password=None)
                except Exception:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                    priv_key = Ed25519PrivateKey.from_private_bytes(key_bytes[:32])
                now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                expires_iso = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
                attestation = sign_manifest_detached(
                    args.out,
                    priv_key,
                    key_id=args.key_id,
                    release_sequence=args.sequence,
                    issued_at=now_iso,
                    expires_at=expires_iso,
                    publisher_identity=args.publisher,
                    source_commit=args.commit,
                )
            result = {"published": True, "manifest": manifest}
            if attestation:
                result["attestation"] = attestation
            print(json.dumps(result, indent=2))
            return 0
        elif args.command == "verify-real":
            from .real_publish import RealReleaseTrust, ReleaseSequenceTracker, verify_real_release
            trust = None
            if args.key_file:
                key_path = Path(args.key_file)
                key_bytes = key_path.read_bytes()
                if len(key_bytes) == 32:
                    pub_bytes = key_bytes
                else:
                    from cryptography.hazmat.primitives import serialization
                    pub = serialization.load_pem_public_key(key_bytes)
                    pub_bytes = pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                key_id = args.key_id or "key-1"
                trust = RealReleaseTrust.from_single_key(
                    key_id=key_id,
                    public_key_raw=pub_bytes,
                    valid_from="2026-01-01T00:00:00Z",
                    valid_until="2027-01-01T00:00:00Z",
                )
            tracker = ReleaseSequenceTracker(args.state_file) if args.state_file else None
            res = verify_real_release(
                args.dir,
                trust=trust,
                now=args.now,
                allow_rollback=args.allow_rollback,
                sequence_tracker=tracker,
            )
            print(json.dumps(res, indent=2))
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
