"""Deterministic compressed artifacts and integrity verification.

SHA-256 detects accidental or untrusted changes only when the manifest hash is
received through a trusted channel. This v0.1 release is NOT cryptographically signed.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import gzip
import json
import os

from . import SCHEMA
from .engine import build_intelligence
from .observations import Observation, canonical_json, utc_iso

FILES = {"observations.jsonl.gz", "intelligence.jsonl.gz"}
MANIFEST_SCHEMA = "anie.dataset-manifest.v1"


def _write_gzip(path: Path, records: list[dict]) -> dict:
    payload = b"".join((canonical_json(record) + "\n").encode("utf-8") for record in records)
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
            stream.write(payload)
    return {"file": path.name, "sha256": sha256(path.read_bytes()).hexdigest(), "records": len(records), "bytes": path.stat().st_size}


def publish_synthetic(observations: list[Observation], output_dir: str | Path, as_of: str) -> dict:
    """Offline synthetic-only publisher. Reject any real data, even one observation."""
    if not observations:
        raise ValueError("cannot publish empty dataset")
    if len(observations) > 10000:
        raise ValueError("prototype publication bounded to 10000 observations")
    if any(not ob.synthetic for ob in observations):
        raise PermissionError("v0.1 publisher is SYNTHETIC-ONLY; real/public data publishing requires a reviewed policy")
    as_of = utc_iso(as_of)
    output = Path(output_dir)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("output directory must be empty; no overwriting previous releases")
    output.mkdir(parents=True, exist_ok=True)
    observations = sorted(observations, key=lambda o: (o.observed_at, o.observation_id))
    intelligence = build_intelligence(observations, as_of)
    entries = [
        _write_gzip(output / "observations.jsonl.gz", [{"observation_id": o.observation_id, **o.to_dict()} for o in observations]),
        _write_gzip(output / "intelligence.jsonl.gz", intelligence),
    ]
    manifest = {
        "schema": MANIFEST_SCHEMA, "intelligence_schema": SCHEMA,
        "dataset_type": "synthetic_demo_only", "assessed_at": as_of,
        "integrity": "sha256_untrusted_manifest_not_a_signature",
        "files": entries,
        "notice": "Illustrative simulated observations. Not threat intelligence and not real-world findings.",
    }
    (output / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify_release(directory: str | Path) -> dict:
    directory = Path(directory)
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("missing or unsafe manifest")
    if manifest_path.stat().st_size > 65536:
        raise ValueError("manifest exceeds size limit")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("dataset_type") != "synthetic_demo_only":
        raise ValueError("unsupported or non-synthetic manifest")
    if not isinstance(manifest.get("files"), list) or {e.get("file") for e in manifest["files"]} != FILES or len(manifest["files"]) != 2:
        raise ValueError("unexpected file manifest")
    contents: dict[str, list[dict]] = {}
    for entry in manifest["files"]:
        name = entry["file"]
        file = directory / name
        if not file.is_file() or file.is_symlink() or file.stat().st_size > 20_000_000:
            raise ValueError("missing, unsafe or oversized artifact")
        if sha256(file.read_bytes()).hexdigest() != entry.get("sha256") or file.stat().st_size != entry.get("bytes"):
            raise ValueError(f"integrity mismatch: {name}")
        # Streamed decompression limit: protects consumers from gzip bombs.
        with gzip.open(file, "rb") as f:
            data = f.read(32_000_001)
        if len(data) > 32_000_000:
            raise ValueError("expanded dataset exceeds bound")
        lines = data.splitlines()
        if len(lines) != entry.get("records") or len(lines) > 10000:
            raise ValueError("record count mismatch")
        contents[name] = [json.loads(line) for line in lines]
    ids = set()
    for rec in contents["observations.jsonl.gz"]:
        if "observation_id" not in rec:
            raise ValueError("missing observation ID")
        provided = rec["observation_id"]
        raw = {k: v for k, v in rec.items() if k != "observation_id"}
        ob = Observation.from_dict(raw)
        if not ob.synthetic or ob.observation_id != provided or provided in ids:
            raise ValueError("invalid, non-synthetic, or duplicate observation")
        ids.add(provided)
    for rec in contents["intelligence.jsonl.gz"]:
        if rec.get("schema") != SCHEMA or rec.get("synthetic") is not True:
            raise ValueError("invalid intelligence schema or origin")
        if not set(rec.get("evidence_ids", [])).issubset(ids):
            raise ValueError("unresolved evidence reference")
        if rec.get("finding", {}).get("maliciousness") != "undetermined":
            raise ValueError("synthetic intelligence must never claim maliciousness")
    # Recompute derived intelligence to detect internally inconsistent, re-hashed artifacts.
    observations = [Observation.from_dict({k: v for k, v in rec.items() if k != "observation_id"}) for rec in contents["observations.jsonl.gz"]]
    expected = build_intelligence(observations, manifest["assessed_at"])
    if expected != contents["intelligence.jsonl.gz"]:
        raise ValueError("intelligence records disagree with evidence and model")
    return {"verified": True, "observations": len(observations), "intelligence_records": len(expected), "dataset_type": manifest["dataset_type"], "integrity_note": "SHA-256 verification is not publisher authentication"}
