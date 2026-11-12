#!/usr/bin/env python3
"""Reproducible Phase 2 Offline Acceptance Runner and Host-Readiness Assessment.

Executes offline acceptance verification with mocked RFC 8484 DNS wire responses,
ephemeral Ed25519 signing keys, and measured resource scaling under host constraints.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any

# Ensure repository src and tests are in path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anie.real_models import (
    REAL_EVENT_SCHEMA,
    FactualVerification,
    RealCollectionEvent,
    RealCollectionRequest,
    RealObservation,
)
from anie.real_store import RealObservationStore
from anie.doh_governor import DohRateGovernor
from anie.orchestrator import BatchOrchestrator, BatchConfig
from anie.real_publish import (
    publish_real,
    verify_real_release,
    sign_manifest_detached,
    export_canonical_dataset,
    ReleaseSequenceTracker,
    RealReleaseTrust,
    TrustedKey,
    canonical_json,
    TrackerStateError,
    TrackerStateLostError,
)
from test_real_models import sample_event, sample_observation, sample_request


def get_platform_memory_mb() -> tuple[float, float, str]:
    """Return (current_rss_mb, peak_rss_mb, method_name)."""
    if sys.platform.startswith("linux"):
        try:
            current_mb = 0.0
            peak_mb = 0.0
            try:
                with open("/proc/self/status", "r", encoding="ascii") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            current_mb = float(line.split()[1]) / 1024.0
                        elif line.startswith("VmHWM:"):
                            peak_mb = float(line.split()[1]) / 1024.0
            except OSError:
                pass
            if peak_mb <= 0.0:
                import resource
                peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
                current_mb = peak_mb
            return current_mb, peak_mb, "linux_proc_status"
        except Exception:
            pass
    elif sys.platform == "win32":
        try:
            import ctypes
            import ctypes.wintypes
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ('cb', ctypes.wintypes.DWORD),
                    ('PageFaultCount', ctypes.wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t),
                    ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t),
                    ('PeakPagefileUsage', ctypes.c_size_t),
                ]
            fn = ctypes.windll.psapi.GetProcessMemoryInfo
            fn.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.wintypes.DWORD]
            fn.restype = ctypes.wintypes.BOOL
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            h = ctypes.windll.kernel32.GetCurrentProcess()
            if fn(h, ctypes.byref(pmc), pmc.cb):
                return pmc.WorkingSetSize / (1024.0 * 1024.0), pmc.PeakWorkingSetSize / (1024.0 * 1024.0), "win32_workingset"
        except Exception:
            pass
    return 0.0, 0.0, "unavailable"


def make_mock_wire_dns_response(domain: str, kind: str) -> bytes:
    """Generate minimal valid RFC 1035 / RFC 8484 DNS response wire bytes."""
    hdr = b"\x12\x34\x85\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    labels = b""
    for part in domain.split("."):
        labels += bytes([len(part)]) + part.encode("ascii")
    labels += b"\x00"
    qtype = b"\x00\x01" if kind == "dns_a" else b"\x00\x1c"
    question = labels + qtype + b"\x00\x01"
    ans_name = b"\xc0\x0c"
    ttl = b"\x00\x00\x01\x2c"  # 300s
    if kind == "dns_a":
        rdlength = b"\x00\x04"
        rdata = b"\x5d\xb8\xd8\x22"  # 93.184.216.34
    else:
        rdlength = b"\x00\x10"
        rdata = b"\x26\x06\x28\x00\x02\x20\x00\x01\x02\x48\x18\x93\x25\xc8\x19\x46"
    answer = ans_name + qtype + b"\x00\x01" + ttl + rdlength + rdata
    return hdr + question + answer


def make_mock_collector(domain_responses: dict[tuple[str, str], bytes] | None = None):
    responses = domain_responses or {}
    class MockCollector:
        def __init__(self, rate_governor=None, timeout_seconds=None):
            self.gov = rate_governor
        def collect(self, domain: str, kind: str, timeout_seconds: float | None = None):
            if self.gov:
                self.gov.check_and_reserve(domain, "cloudflare_doh", timeout=timeout_seconds)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            wire = responses.get((domain, kind), make_mock_wire_dns_response(domain, kind))
            req = sample_request(subject=domain, kind=kind, observed_at=now)
            ev = sample_event(request=req, raw_payload=wire, observed_at=now)
            val = ("93.184.216.34",) if kind == "dns_a" else ("2606:2800:220:1:248:1893:25c8:1946",)
            obs = sample_observation(subject=domain, kind=kind, observed_at=now, values=val, event=ev)
            return ev, obs
    return MockCollector


def run_acceptance_tests(verbose: bool = True) -> dict[str, Any]:
    """Execute complete Phase B end-to-end integration acceptance test suite."""
    report: dict[str, Any] = {}

    with tempfile.TemporaryDirectory() as tmp_root:
        base_dir = Path(tmp_root)
        q_db = base_dir / "quota.sqlite"
        s_db = base_dir / "real_intelligence.sqlite"
        lock_file = base_dir / "collector.lock"
        telemetry_file = base_dir / "telemetry.jsonl"
        release_dir = base_dir / "release-01"
        verifier_state = base_dir / "verifier_state.json"

        # 1. Bounded batch execution under mock DoH
        if verbose:
            print("[1/10] Executing bounded batch under mocked DoH transport...")
        batch_cfg = BatchConfig(
            domains=["example.com", "iana.org"],
            mode="live",
            quota_db_path=q_db,
            store_db_path=s_db,
            lock_file_path=lock_file,
            log_file_path=telemetry_file,
            timeout_seconds=10.0,
        )
        mock_factory = lambda **kw: make_mock_collector()(**kw)
        orch = BatchOrchestrator(batch_cfg, collector_factory=mock_factory, mem_fn=lambda: 512, disk_fn=lambda p: 2000)

        os.environ["ANIE_LIVE_COLLECTION_AUTHORIZED"] = "1"
        try:
            batch_rep = orch.execute_batch()
        finally:
            os.environ.pop("ANIE_LIVE_COLLECTION_AUTHORIZED", None)

        assert batch_rep.outcome == "SUCCESS", f"Batch execution failed: {batch_rep.reason}"
        assert batch_rep.queries_succeeded == 2, f"Expected 2 queries, got {batch_rep.queries_succeeded}"
        report["batch_execution"] = {
            "outcome": batch_rep.outcome,
            "queries_succeeded": batch_rep.queries_succeeded,
            "duration_seconds": round(batch_rep.duration_seconds, 4),
        }

        # 2. SQLite persistence, foreign keys, and collision rejection
        if verbose:
            print("[2/10] Verifying SQLite persistence, foreign keys, and collision constraints...")
        store = RealObservationStore(s_db)
        with store._connect() as conn:
            obs_cnt = conn.execute("SELECT count(*) FROM real_observations").fetchone()[0]
            ev_cnt = conn.execute("SELECT count(*) FROM real_events").fetchone()[0]
            assert obs_cnt == 2, f"Expected 2 observations, got {obs_cnt}"
            assert ev_cnt == 2, f"Expected 2 events, got {ev_cnt}"

            # Referential integrity: deleting referenced event must fail
            ev_id = conn.execute("SELECT event_id FROM real_events LIMIT 1").fetchone()[0]
            try:
                conn.execute("DELETE FROM real_events WHERE event_id = ?", (ev_id,))
                raise AssertionError("Expected foreign key violation, but delete succeeded!")
            except sqlite3.IntegrityError:
                pass

            # Collision rejection: inserting conflicting record with matching ID must fail
            obs_row = conn.execute("SELECT payload FROM real_observations LIMIT 1").fetchone()[0]
            obs_dict = json.loads(obs_row)
            conflicting_payload = dict(obs_dict)
            conflicting_payload["values"] = ["99.99.99.99"]
            try:
                conn.execute(
                    """
                    INSERT INTO real_observations (
                        observation_id, evidence_id, subject_type, subject, kind,
                        observed_at, status, source_id, method, synthetic, confidence, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        obs_dict["observation_id"], obs_dict["evidence_id"],
                        "domain" if obs_dict["kind"] in {"dns_a", "dns_aaaa"} else "ip",
                        obs_dict["subject"], obs_dict["kind"], obs_dict["observed_at"],
                        obs_dict["status"], obs_dict["source_id"], obs_dict["method"],
                        0, None, json.dumps(conflicting_payload),
                    )
                )
                raise AssertionError("Expected collision IntegrityError, but insert succeeded!")
            except sqlite3.IntegrityError:
                pass
        report["sqlite_persistence"] = "verified"

        # 3. Raw evidence hashes & provenance
        if verbose:
            print("[3/10] Verifying SHA-256 raw wire evidence integrity...")
        with store._connect() as conn:
            rows = conn.execute("SELECT event_id, raw_payload, raw_sha256 FROM real_events").fetchall()
            for eid, raw_b, raw_h in rows:
                calc_h = hashlib.sha256(raw_b).hexdigest()
                assert calc_h == raw_h, f"Hash mismatch for {eid}"
        report["evidence_integrity"] = "verified"

        # 4. Canonical publication export
        if verbose:
            print("[4/10] Exporting unsigned canonical publication...")
        as_of = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        exported_obs, exported_evs = export_canonical_dataset(store, as_of=as_of)
        assert len(exported_obs) == 2
        assert len(exported_evs) == 2

        manifest = publish_real(
            (exported_obs, exported_evs),
            release_dir,
            as_of=as_of,
            release_sequence=1,
            publisher_identity="anie-first-party",
            published_at=as_of,
        )
        assert (release_dir / "manifest.json").exists()
        assert (release_dir / "real_observations.jsonl.gz").exists()
        assert (release_dir / "real_events.jsonl.gz").exists()
        report["canonical_export"] = {
            "total_observations": manifest["total_observations"],
            "total_events": manifest["total_events"],
            "manifest_sha256": hashlib.sha256((release_dir / "manifest.json").read_bytes()).hexdigest(),
        }

        # 5. Candidate integrity inspection
        if verbose:
            print("[5/10] Validating candidate integrity (--integrity-only)...")
        cand_res = verify_real_release(release_dir, integrity_only=True)
        assert cand_res["status"] == "CANDIDATE_INTEGRITY_VERIFIED"
        assert cand_res["authenticated"] is False
        assert cand_res["structural_valid"] is True
        assert cand_res["evidence_integrity_valid"] is True
        assert cand_res["publisher_authenticated"] is False
        assert cand_res["anti_rollback_verified"] is False
        report["candidate_integrity"] = "verified"

        # 6. Detached Ed25519 signing (simulated operator environment)
        if verbose:
            print("[6/10] Detached Ed25519 signing in simulated air-gapped operator environment...")
        priv_key = Ed25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes_raw()
        key_id = "test-operator-key-2026"
        key_fp = hashlib.sha256(pub_bytes).hexdigest()

        sign_manifest_detached(
            release_dir,
            priv_key,
            key_id=key_id,
            release_sequence=1,
            issued_at=as_of,
            expires_at="2027-01-01T00:00:00Z",
            publisher_identity="anie-first-party",
        )
        assert (release_dir / "signature.ed25519.json").exists()
        report["detached_signing"] = {"key_id": key_id, "fingerprint": key_fp}

        # 7. Consumer authenticated verification
        if verbose:
            print("[7/10] Consumer authenticated verification with pinned key...")
        trust = RealReleaseTrust(
            trusted_keys={
                key_id: TrustedKey(
                    key_id=key_id,
                    public_key_raw=pub_bytes,
                    valid_from="2026-01-01T00:00:00Z",
                    valid_until="2027-01-01T00:00:00Z",
                )
            }
        )
        tracker = ReleaseSequenceTracker(verifier_state)
        tracker.initialize()

        auth_res = verify_real_release(release_dir, trust=trust, sequence_tracker=tracker)
        assert auth_res["status"] == "AUTHENTICATED"
        assert auth_res["authenticated"] is True
        assert auth_res["publisher_authenticated"] is True
        assert auth_res["anti_rollback_verified"] is True
        report["consumer_verification"] = "authenticated"

        # 8. Anti-rollback enforcement and sequential advancement
        if verbose:
            print("[8/10] Verifying anti-rollback advancement and replay rejection...")
        rel2_dir = base_dir / "release-02"
        publish_real(
            (exported_obs, exported_evs),
            rel2_dir,
            as_of=as_of,
            release_sequence=2,
            publisher_identity="anie-first-party",
            published_at=as_of,
        )
        sign_manifest_detached(
            rel2_dir,
            priv_key,
            key_id=key_id,
            release_sequence=2,
            issued_at=as_of,
            expires_at="2027-01-01T00:00:00Z",
            publisher_identity="anie-first-party",
        )
        auth_res2 = verify_real_release(rel2_dir, trust=trust, sequence_tracker=tracker)
        assert auth_res2["release_sequence"] == 2
        assert auth_res2["anti_rollback_verified"] is True

        # Replay sequence 1
        try:
            verify_real_release(release_dir, trust=trust, sequence_tracker=tracker)
            raise AssertionError("Replay sequence 1 must fail!")
        except ValueError as exc:
            assert "replayed or downgraded" in str(exc)

        # Replay sequence 2
        try:
            verify_real_release(rel2_dir, trust=trust, sequence_tracker=tracker)
            raise AssertionError("Replay sequence 2 must fail!")
        except ValueError as exc:
            assert "replayed or downgraded" in str(exc)

        # Historical audit with allow_rollback=True
        audit_res = verify_real_release(release_dir, trust=trust, sequence_tracker=tracker, allow_rollback=True)
        assert audit_res["authenticated"] is True
        assert audit_res["anti_rollback_verified"] is False
        report["anti_rollback"] = "verified_monotonic_and_replay_rejected"

        # 9. Adversarial tampering, corruption, and anti-contamination
        if verbose:
            print("[9/10] Testing adversarial tampering, corruption, and anti-contamination...")
        tamper_dir = base_dir / "tampered"
        shutil.copytree(release_dir, tamper_dir)

        # Manifest modification
        m_path = tamper_dir / "manifest.json"
        m_dict = json.loads(m_path.read_text(encoding="utf-8"))
        m_dict["notice"] = "Tampered notice"
        m_path.write_text(canonical_json(m_dict) + "\n", encoding="utf-8")
        try:
            verify_real_release(tamper_dir, trust=trust)
            raise AssertionError("Tampered manifest must fail!")
        except ValueError as exc:
            assert "signed manifest SHA-256 mismatch" in str(exc) or "signature verification failed" in str(exc)

        # Partition modification
        shutil.rmtree(tamper_dir)
        shutil.copytree(release_dir, tamper_dir)
        obs_gz = tamper_dir / "real_observations.jsonl.gz"
        obs_bytes = bytearray(obs_gz.read_bytes())
        obs_bytes[10] = (obs_bytes[10] + 1) % 256
        obs_gz.write_bytes(bytes(obs_bytes))
        try:
            verify_real_release(tamper_dir, trust=trust)
            raise AssertionError("Tampered partition must fail!")
        except ValueError as exc:
            assert "SHA-256 integrity mismatch" in str(exc) or "size mismatch" in str(exc)

        # Raw evidence corruption
        shutil.rmtree(tamper_dir)
        shutil.copytree(release_dir, tamper_dir)
        ev_gz = tamper_dir / "real_events.jsonl.gz"
        lines = []
        with gzip.open(ev_gz, "rt", encoding="utf-8") as gz_in:
            for l in gz_in:
                lines.append(json.loads(l))
        lines[0]["raw_payload_b64"] = "QUFBQQ=="
        with gzip.open(ev_gz, "wt", encoding="utf-8") as gz_out:
            for l in lines:
                gz_out.write(json.dumps(l) + "\n")
        m_file = tamper_dir / "manifest.json"
        m_raw = json.loads(m_file.read_text(encoding="utf-8"))
        m_raw["files"][1]["sha256"] = hashlib.sha256(ev_gz.read_bytes()).hexdigest()
        m_raw["files"][1]["bytes"] = ev_gz.stat().st_size
        m_file.write_text(canonical_json(m_raw) + "\n", encoding="utf-8")
        try:
            verify_real_release(tamper_dir, integrity_only=True)
            raise AssertionError("Corrupted raw evidence must fail!")
        except ValueError as exc:
            assert "raw_sha256 mismatch" in str(exc) or "raw evidence verification failed" in str(exc)

        # State corruption
        corrupt_state = base_dir / "corrupted_state.json"
        corrupt_state.write_text("CORRUPTED_JSON", encoding="utf-8")
        try:
            ReleaseSequenceTracker(corrupt_state).get_last_accepted_sequence("chan")
            raise AssertionError("Corrupted state must raise TrackerStateError!")
        except TrackerStateError:
            pass

        # Synthetic contamination
        try:
            sample_observation(synthetic=True)
            raise AssertionError("Creating synthetic RealObservation must fail!")
        except ValueError:
            pass

        report["adversarial_defenses"] = "all_passed_fail_closed"

        # 10. Process restart persistence
        if verbose:
            print("[10/10] Verifying persistence across separate process restart...")
        py_code = (
            "import sys, sqlite3\n"
            f"sys.path.insert(0, {repr(str(ROOT / 'src'))})\n"
            "from anie.real_publish import ReleaseSequenceTracker\n"
            f"conn = sqlite3.connect({repr(str(s_db))})\n"
            "cnt = conn.execute('SELECT count(*) FROM real_observations').fetchone()[0]\n"
            "conn.close()\n"
            "assert cnt == 2\n"
            f"tracker = ReleaseSequenceTracker({repr(str(verifier_state))})\n"
            "seq = tracker.get_last_accepted_sequence('anie-first-party')\n"
            "assert seq == 2\n"
        )
        proc = subprocess.run([sys.executable, "-c", py_code], capture_output=True, text=True)
        assert proc.returncode == 0, f"Subprocess failed: {proc.stderr}"
        report["process_restart_persistence"] = "verified"

    return report


def run_scaling_benchmark(sizes: list[int] | None = None, verbose: bool = True) -> list[dict[str, Any]]:
    """Measure SQLite export, publication, and verification performance and memory scaling."""
    target_sizes = sizes or [2, 50, 200, 1000, 3000, 5000]
    results = []

    if verbose:
        print("\n" + "=" * 70)
        print("SCALING BENCHMARK: RESOURCE SCALING & MEMORY ASSESSMENT")
        print("=" * 70)

    for n in target_sizes:
        with tempfile.TemporaryDirectory() as tmp_dir:
            b_dir = Path(tmp_dir)
            db_path = b_dir / "bench.sqlite"
            rel_path = b_dir / "release"
            store = RealObservationStore(db_path)

            t_insert_start = time.monotonic()
            for i in range(n):
                now_str = datetime.fromtimestamp(1762940000 + i, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                wire = make_mock_wire_dns_response("example.com", "dns_a")
                req = sample_request(subject="example.com", kind="dns_a", observed_at=now_str)
                ev = sample_event(request=req, raw_payload=wire, observed_at=now_str)
                obs = sample_observation(subject="example.com", kind="dns_a", observed_at=now_str, values=(f"93.184.216.{i % 250}",), event=ev)
                store.insert_record(ev, obs)
            t_insert = time.monotonic() - t_insert_start

            # Measure publish
            tracemalloc.start()
            t_pub_start = time.monotonic()
            exp_obs, exp_ev = export_canonical_dataset(store, as_of="2030-01-01T00:00:00Z")
            publish_real((exp_obs, exp_ev), rel_path, as_of="2030-01-01T00:00:00Z", release_sequence=1)
            t_pub = time.monotonic() - t_pub_start
            _, pub_peak_heap = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Measure verify
            tracemalloc.start()
            t_ver_start = time.monotonic()
            verify_real_release(rel_path, integrity_only=True)
            t_ver = time.monotonic() - t_ver_start
            _, ver_peak_heap = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            curr_rss, peak_rss, mem_method = get_platform_memory_mb()
            db_size_kb = db_path.stat().st_size / 1024.0
            obs_gz_kb = (rel_path / "real_observations.jsonl.gz").stat().st_size / 1024.0
            ev_gz_kb = (rel_path / "real_events.jsonl.gz").stat().st_size / 1024.0

            stat = {
                "records": n,
                "db_size_kb": round(db_size_kb, 1),
                "obs_gz_kb": round(obs_gz_kb, 2),
                "ev_gz_kb": round(ev_gz_kb, 2),
                "insert_duration_s": round(t_insert, 3),
                "publish_duration_s": round(t_pub, 3),
                "verify_duration_s": round(t_ver, 3),
                "publish_peak_heap_kb": round(pub_peak_heap / 1024.0, 1),
                "verify_peak_heap_kb": round(ver_peak_heap / 1024.0, 1),
                "process_peak_rss_mb": round(peak_rss, 2),
                "memory_method": mem_method,
            }
            results.append(stat)
            if verbose:
                print(
                    f"N={n:5d} | DB: {db_size_kb:7.1f} KB | Pub: {t_pub:6.3f}s | "
                    f"Pub Heap: {pub_peak_heap/1024.0:7.1f} KB | Ver Heap: {ver_peak_heap/1024.0:6.1f} KB | "
                    f"Peak RSS: {peak_rss:5.1f} MiB ({mem_method})"
                )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="ANIE Phase 2 Offline Acceptance Runner")
    parser.add_argument("--check", action="store_true", help="Run complete Phase B acceptance checks")
    parser.add_argument("--benchmark", action="store_true", help="Run Phase C memory and scaling benchmark")
    parser.add_argument("--sizes", type=str, default="200,3000,5000", help="Comma-separated dataset sizes for benchmark")
    parser.add_argument("--output-json", type=Path, help="Path to write structured JSON results")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose logging")
    args = parser.parse_args()

    # Default to running checks if no flags specified
    do_check = args.check or (not args.check and not args.benchmark)
    do_bench = args.benchmark
    verbose = not args.quiet

    output_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "python_version": sys.version,
    }

    try:
        if do_check:
            if verbose:
                print("=" * 70)
                print("ANIE PHASE 2 INTEGRATION ACCEPTANCE TEST SUITE")
                print("=" * 70)
            output_data["acceptance"] = run_acceptance_tests(verbose=verbose)
            if verbose:
                print("\nALL 10 PHASE B ACCEPTANCE CHECKS PASSED FAIL-CLOSED.")

        if do_bench:
            size_list = [int(s.strip()) for s in args.sizes.split(",") if s.strip()]
            output_data["benchmark"] = run_scaling_benchmark(sizes=size_list, verbose=verbose)

        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(output_data, indent=2) + "\n", encoding="utf-8")
            if verbose:
                print(f"\nStructured results saved to {args.output_json}")

        return 0
    except Exception as exc:
        print(f"\nERROR: Acceptance runner failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
