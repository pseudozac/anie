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
    p.add_argument("--prev-manifest", default=None, help="SHA-256 digest of previous release manifest (for sequence > 1)")
    p.add_argument("--prev-release", default=None, help="path to previous release directory from which to resolve prev-manifest digest")
    p.add_argument("--commit", default=None, help="source repository commit hash")
    p.add_argument("--published-at", default=None, help="optional fixed publication timestamp for reproducible manifest")
    p.add_argument("--include-discrepancies", action="store_true", help="include discrepancy reports partition in release (v3 manifest)")
    p.add_argument("--include-claims", action="store_true", help="include intelligence claims partition in release (v4 manifest)")
    p = sub.add_parser("analyze-discrepancy", help="evaluate multi-resolver observations for a subject from database and generate discrepancy report")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--subject", required=True, help="target domain name to analyze")
    p.add_argument("--record-type", default=None, help="optional DNS record kind filter (e.g. dns_a, dns_aaaa)")
    p.add_argument("--window-seconds", type=float, default=60.0, help="maximum temporal clustering window in seconds (default: 60)")
    p.add_argument("--store", action="store_true", help="persist generated discrepancy report into database")
    p = sub.add_parser("domain-history", help="display multi-resolver historical intelligence summary for domain")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--subject", required=True, help="target domain name")
    p.add_argument("--record-type", default=None, help="optional DNS record kind filter")
    p = sub.add_parser("keygen", help="generate offline Ed25519 operator signing keypair with 0600 permissions")
    p.add_argument("--out", default=".", help="output directory for key files (default: .)")
    p.add_argument("--key-id", default="operator-key-1", help="operator key identifier")
    p.add_argument("--force", action="store_true", help="overwrite existing key files")
    p = sub.add_parser("inspect-candidate", help="inspect unsigned candidate release integrity and summarize observations")
    p.add_argument("--dir", required=True, help="path to candidate release directory")
    p = sub.add_parser("sign-real", help="detached offline Ed25519 signing of candidate release")
    p.add_argument("--dir", required=True, help="path to unsigned candidate release directory")
    p.add_argument("--key-file", required=True, help="path to operator Ed25519 private key (PEM or 32 raw bytes)")
    p.add_argument("--key-id", required=True, help="operator key identifier")
    p.add_argument("--sequence", type=int, required=True, help="expected release sequence (must match manifest)")
    p.add_argument("--prev-manifest", default=None, help="expected SHA-256 digest of previous manifest (must match candidate manifest)")
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
    p.add_argument("--require-hash-chain", action="store_true", help="require unbroken release hash chain")
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
    p.add_argument("--pilot", action="store_true", help="enable strictly bounded 72-hour pilot governor and query alternation")
    p.add_argument("--pilot-start-date", default=None, help="explicit starting UTC date (YYYY-MM-DD) for 72-hour pilot window")
    p.add_argument("--sentinel-file", default=None, help="path to pilot completed sentinel file")
    p = sub.add_parser("preflight", help="execute security preflight assertions")
    p.add_argument("--require-firewall", action="store_true", help="require kernel firewall rule presence")
    p.add_argument("--imds-ip", default="169.254.169.254", help="target IMDS IP to verify blocked")
    p = sub.add_parser("pilot-status", help="display current 72-hour pilot progression and state")
    p.add_argument("--quota-db", default="/var/lib/anie/doh_quota.sqlite", help="path to doh_quota.sqlite database")
    p.add_argument("--sentinel-file", default=None, help="path to pilot completed sentinel file")
    p.add_argument("--pilot-start-date", default=None, help="explicit starting UTC date (YYYY-MM-DD) for 72-hour pilot window")
    p = sub.add_parser("init-pilot", help="atomically initialize and anchor immutable pilot start date")
    p.add_argument("--start-date", default="2026-11-14", help="approved UTC start date (YYYY-MM-DD)")
    p.add_argument("--quota-db", default="/var/lib/anie/doh_quota.sqlite", help="path to doh_quota.sqlite database")
    p.add_argument("--sentinel-file", default=None, help="path to pilot completed sentinel file")
    p = sub.add_parser("backup", help="create verified online SQLite backup of databases")
    p.add_argument("--dbs", nargs="+", default=["/var/lib/anie/real_intelligence.sqlite", "/var/lib/anie/doh_quota.sqlite"], help="SQLite databases to back up")
    p.add_argument("--out", default="/var/lib/anie/backups", help="destination directory for backup snapshots")
    p.add_argument("--retention", type=int, default=7, help="number of non-milestone snapshots to retain")
    p = sub.add_parser("restore", help="validate and restore SQLite backup into isolated directory")
    p.add_argument("--backup-dir", required=True, help="source backup directory containing SHA256SUMS")
    p.add_argument("--target", required=True, help="isolated destination directory for restored databases")
    p.add_argument("--allow-overwrite", action="store_true", help="permit overwriting existing files in destination")
    p = sub.add_parser("evaluate-intelligence", help="execute ground-truth benchmark and output intelligence quality report")
    p.add_argument("--db", default=None, help="optional path to SQLite database; uses in-memory if omitted")
    p.add_argument("--out", default=None, help="optional output path to write evaluation report JSON")
    p = sub.add_parser("export-ioc-feed", help="export canonical threat intelligence IOC feed via consumer contract")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--out", default=None, help="optional output path to write IOC feed JSON")
    p.add_argument("--as-of", default=None, help="historical point-in-time cutoff (UTC ISO)")
    p.add_argument("--min-confidence", type=float, default=0.0, help="minimum confidence threshold (0.0 to 1.0)")
    p.add_argument("--layer", default=None, help="optional layer filter (e.g. HYPOTHESIS, VALIDATED)")
    p = sub.add_parser("prune-retention", help="execute evidence-preserving retention pruning and compaction")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--obs-ttl", type=int, default=90, help="observation TTL in days (default: 90)")
    p.add_argument("--evt-ttl", type=int, default=180, help="raw event TTL in days (default: 180)")
    p.add_argument("--no-vacuum", action="store_true", help="skip incremental vacuum compaction")
    p = sub.add_parser("project-storage", help="calculate empirical storage, WAL, backup, and release growth projections")
    p.add_argument("--profile", choices=["pilot", "production", "scale"], default=None, help="filter by workload profile")
    p.add_argument("--days", type=int, choices=[30, 90, 180, 365], default=None, help="filter by projection horizon days")
    p = sub.add_parser("detect-anomalies", help="detect temporal infrastructure anomalies and generate calibrated hypothesis claims")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--as-of", default=None, help="historical point-in-time cutoff (UTC ISO)")
    p.add_argument("--min-confidence", type=float, default=0.70, help="minimum confidence threshold (default: 0.70)")
    p.add_argument("--ruleset", default=None, help="optional ruleset version filter")
    p.add_argument("--store", action="store_true", help="persist detected claims into database")
    p.add_argument("--out", default=None, help="optional output path to write detection JSON summary")
    p = sub.add_parser("query-graph", help="query entity neighborhood, edges, and supporting evidence lineage")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--entity", required=True, help="target entity identifier (domain, IP, ASN, CIDR, or canonical URI)")
    p.add_argument("--depth", type=int, default=1, choices=[0, 1, 2, 3, 4, 5], help="neighborhood traversal depth (default: 1)")
    p.add_argument("--direction", choices=["IN", "OUT", "BOTH"], default="BOTH", help="edge traversal direction (default: BOTH)")
    p.add_argument("--layer", default=None, help="optional layer filter (e.g. FACT, DERIVED, HYPOTHESIS)")
    p.add_argument("--as-of", default=None, help="historical point-in-time cutoff (UTC ISO)")
    p.add_argument("--out", default=None, help="optional output path to write query result JSON")
    p = sub.add_parser("export-graph-markdown", help="export interconnected Obsidian-compatible Markdown knowledge vault")
    p.add_argument("--db", required=True, help="path to real intelligence SQLite database")
    p.add_argument("--out", required=True, help="destination directory for Obsidian vault")
    p.add_argument("--as-of", default=None, help="historical point-in-time cutoff (UTC ISO)")
    p.add_argument("--min-confidence", type=float, default=0.0, help="minimum confidence threshold (default: 0.0)")
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
            from hashlib import sha256
            from .real_publish import publish_real
            from .real_store import RealObservationStore
            prev_sha = args.prev_manifest
            if args.prev_release and not prev_sha:
                prev_dir = Path(args.prev_release)
                manifest_file = prev_dir / "manifest.json"
                if not manifest_file.exists():
                    raise FileNotFoundError(f"previous manifest not found in '{prev_dir}'")
                prev_sha = sha256(manifest_file.read_bytes()).hexdigest()

            store = RealObservationStore(args.db)
            manifest = publish_real(
                store,
                args.out,
                args.as_of,
                publisher_identity=args.publisher,
                release_sequence=args.sequence,
                prev_manifest_sha256=prev_sha,
                source_commit=args.commit,
                published_at=args.published_at,
                include_discrepancies=args.include_discrepancies,
                include_claims=getattr(args, "include_claims", False),
            )
            print(json.dumps({"published": True, "manifest": manifest}, indent=2))
            return 0
        elif args.command == "keygen":
            from .real_publish import generate_keypair
            res = generate_keypair(args.out, args.key_id, force=args.force)
            print(json.dumps({"keygen": True, **res}, indent=2))
            return 0
        elif args.command == "inspect-candidate":
            from .real_publish import inspect_candidate
            summary = inspect_candidate(args.dir)
            print(json.dumps(summary, indent=2))
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
                prev_manifest_sha256=args.prev_manifest,
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
                    require_hash_chain=args.require_hash_chain,
                    allow_rollback=args.allow_rollback,
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
                pilot_mode=args.pilot,
                pilot_sentinel_path=Path(args.sentinel_file) if args.sentinel_file else None,
                pilot_start_date=args.pilot_start_date,
            )
            orchestrator = BatchOrchestrator(config)
            report = orchestrator.execute_batch()
            print(report.to_json())
            if report.outcome in ("SUCCESS", "SKIPPED"):
                return 0
            # Distinguish PARTIAL and FAILED outcomes with non-zero exit code
            return 1
        elif args.command == "preflight":
            from .preflight_hardening import main as preflight_main
            sub_argv = ["--imds-ip", args.imds_ip]
            if args.require_firewall:
                sub_argv.append("--require-firewall")
            return preflight_main(sub_argv)
        elif args.command == "pilot-status":
            from .pilot_governor import PilotGovernor
            gov = PilotGovernor(args.quota_db, sentinel_path=args.sentinel_file, pilot_start_date=args.pilot_start_date)
            print(json.dumps(gov.get_pilot_summary(), indent=2))
            return 0
        elif args.command == "init-pilot":
            from .pilot_governor import PilotGovernor
            gov = PilotGovernor(args.quota_db, sentinel_path=args.sentinel_file)
            res = gov.initialize_pilot(args.start_date)
            print(json.dumps(res, indent=2))
            return 0
        elif args.command == "backup":
            from dataclasses import asdict
            from .backup import create_evidence_backup
            res = create_evidence_backup(args.dbs, args.out, retention_limit=args.retention)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.success else 1
        elif args.command == "restore":
            from dataclasses import asdict
            from .backup import restore_evidence_backup
            res = restore_evidence_backup(args.backup_dir, args.target, allow_overwrite=args.allow_overwrite)
            print(json.dumps(asdict(res), indent=2))
            return 0 if res.success else 1
        elif args.command == "analyze-discrepancy":
            from .discrepancy_engine import DiscrepancyEngine
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            all_obs = store.all_observations()
            subj_obs = [o for o in all_obs if o.subject == args.subject]
            kind = args.record_type or (subj_obs[0].kind if subj_obs else "dns_a")
            if args.record_type:
                subj_obs = [o for o in subj_obs if o.kind == args.record_type]
            if not subj_obs:
                print(f"ANIE error: no observations found for subject '{args.subject}'", file=sys.stderr)
                return 1
            all_events = store.all_events()
            engine = DiscrepancyEngine(window_seconds=args.window_seconds)
            report = engine.analyze(args.subject, kind, subj_obs, all_events)
            if args.store:
                store.insert_discrepancy(report)
            print(json.dumps(report.to_dict(), indent=2))
            return 0
        elif args.command == "domain-history":
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            summary = store.get_historical_summary(args.subject, record_type=args.record_type)
            print(json.dumps(summary, indent=2))
            return 0
        elif args.command == "evaluate-intelligence":
            import tempfile
            from .intelligence_evaluator import IntelligenceEvaluator
            from .real_store import RealObservationStore
            if args.db:
                store = RealObservationStore(args.db)
                evaluator = IntelligenceEvaluator(store)
                rep = evaluator.evaluate()
            else:
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_db = Path(tmpdir) / "eval.sqlite"
                    store = RealObservationStore(tmp_db)
                    evaluator = IntelligenceEvaluator(store)
                    rep = evaluator.evaluate()
            out_dict = rep.to_dict()
            if args.out:
                Path(args.out).write_text(json.dumps(out_dict, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(out_dict, indent=2))
            return 0
        elif args.command == "export-ioc-feed":
            from .consumer_contract import AnieIntelligenceClient
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            client = AnieIntelligenceClient(store)
            feed = client.export_canonical_ioc_feed(
                as_of=args.as_of,
                min_confidence=args.min_confidence,
                layer=args.layer,
            )
            out_dict = feed.to_dict()
            if args.out:
                Path(args.out).write_text(json.dumps(out_dict, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(out_dict, indent=2))
            return 0
        elif args.command == "prune-retention":
            from .real_store import RealObservationStore
            from .retention import RetentionPolicy, safe_prune_retention
            store = RealObservationStore(args.db)
            policy = RetentionPolicy(
                observation_ttl_days=args.obs_ttl,
                event_ttl_days=args.evt_ttl,
                compact_vacuum=not args.no_vacuum,
            )
            report = safe_prune_retention(store, policy)
            print(json.dumps(report.to_dict(), indent=2))
            return 0
        elif args.command == "project-storage":
            from .retention import StorageGrowthModel
            if args.profile and args.days:
                proj = StorageGrowthModel.project(args.profile, args.days)
                print(json.dumps(proj.__dict__, indent=2))
            else:
                projections = StorageGrowthModel.generate_full_report()
                if args.profile:
                    projections = [p for p in projections if p.profile_name == args.profile]
                if args.days:
                    projections = [p for p in projections if p.days == args.days]
                print(json.dumps([p.__dict__ for p in projections], indent=2))
            return 0
        elif args.command == "detect-anomalies":
            from collections import Counter
            from .real_store import RealObservationStore
            from .temporal_intelligence import EvidenceGraphDetector
            store = RealObservationStore(args.db)
            with store._connect() as conn:
                detector = EvidenceGraphDetector(conn)
                claims = detector.analyze_all(as_of=args.as_of)

            filtered = [c for c in claims if c.confidence >= args.min_confidence]
            if args.ruleset:
                filtered = [c for c in filtered if c.ruleset_version == args.ruleset]

            stored_count = 0
            if args.store:
                for c in filtered:
                    if store.insert_claim(c):
                        stored_count += 1

            type_counts = dict(Counter(c.claim_type for c in filtered))
            summary = {
                "total_claims": len(filtered),
                "stored_claims": stored_count,
                "claims_by_type": type_counts,
                "claims": [c.to_dict() for c in filtered],
            }
            if args.out:
                Path(args.out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({
                "total_claims": len(filtered),
                "stored_claims": stored_count,
                "claims_by_type": type_counts,
                "sample_claims": [c.to_dict() for c in filtered[:5]],
            }, indent=2))
            return 0
        elif args.command == "query-graph":
            from .canonical_entities import parse_entity_uri
            from .graph_engine import GraphEngine
            from .graph_models import format_node_id
            from .real_store import RealObservationStore

            entity_in = args.entity.strip()
            if entity_in.startswith("anie:entity:"):
                node_id = entity_in
            else:
                etype, evalue = parse_entity_uri(entity_in)
                node_id = format_node_id(etype, evalue)

            store = RealObservationStore(args.db)
            with store._connect() as conn:
                engine = GraphEngine(conn)
                layer_filter = [args.layer.upper()] if args.layer else None
                hood = engine.get_k_hop_neighborhood(
                    node_id,
                    max_depth=args.depth,
                    layer_filter=layer_filter,
                )
                if args.direction == "OUT":
                    hood["edges"] = [e for e in hood["edges"] if e["source_id"] == node_id]
                elif args.direction == "IN":
                    hood["edges"] = [e for e in hood["edges"] if e["target_id"] == node_id]

                evidence = engine.trace_evidence_lineage(node_id)
                hood["evidence_lineage"] = evidence

            if args.out:
                Path(args.out).write_text(json.dumps(hood, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(hood, indent=2))
            return 0
        elif args.command == "export-graph-markdown":
            from .graph_engine import GraphEngine
            from .real_store import RealObservationStore
            store = RealObservationStore(args.db)
            with store._connect() as conn:
                engine = GraphEngine(conn)
                res = engine.export_obsidian_vault(args.out)
            print(json.dumps({"exported": True, **res}, indent=2))
            return 0
        return 0
    except (ValueError, PermissionError, FileNotFoundError, FileExistsError, json.JSONDecodeError) as exc:
        print(f"ANIE error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
