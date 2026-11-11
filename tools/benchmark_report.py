"""Reproducible ANIE offline temporal benchmark CLI (no external access)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from anie.benchmarks import DEFAULT_SEED, benchmark_snapshot, profiled_benchmark
from anie.observations import canonical_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ANIE synthetic temporal model evaluation")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--check", type=Path, help="fail if tracked deterministic snapshot differs")
    parser.add_argument("--print-snapshot", action="store_true", help="print canonical snapshot for intentional updates")
    parser.add_argument("--report", type=Path, help="optional full local-data JSON diagnostic report")
    args = parser.parse_args(argv)
    try:
        report, resources = profiled_benchmark(args.seed)
        snapshot = benchmark_snapshot(report)
        print(json.dumps({
            "schema": report["schema"],
            "dataset_type": report["dataset_type"],
            "seed": args.seed,
            "scenarios": len(report["per_case"]),
            "training_entities": report["training_entities"],
            "observations": report["observations"],
            "abstentions": report["abstention_reasons"],
            "metrics": report["methods"],
            "resources": resources,
            "limitations": "Synthetic infrastructure novelty only; not maliciousness, ownership attribution or real-world accuracy",
        }, sort_keys=True, indent=2))
        if args.print_snapshot:
            print("ANIE_SNAPSHOT_BEGIN")
            print(canonical_json(snapshot))
            print("ANIE_SNAPSHOT_END")
        if args.check:
            expected = json.loads(args.check.read_text(encoding="utf-8"))
            if expected != snapshot:
                print("FAIL: benchmark snapshot differs; review causes before intentional update", file=sys.stderr)
                return 1
            print("PASS: deterministic benchmark snapshot agrees with committed reference")
        if args.report:
            if args.report.exists():
                raise FileExistsError("report path already exists; refusing overwrite")
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(canonical_json({"report": report, "resources": resources}) + "\n", encoding="utf-8")
            print(f"Diagnostics saved locally: {args.report}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
