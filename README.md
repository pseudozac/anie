# ANIE — AI-Native Internet Intelligence Engine

**v0.2.0 research prototype • offline-first • synthetic data only • no API keys • no live internet collection**

ANIE is an independent, open-source-oriented research engine that transforms structured internet observations into **evidence-linked, time-aware intelligence records**. It is intended to supply a future consumer such as AEGIS without giving ANIE access to private cases, credentials, browser history or customer telemetry.

## What works today

- Validate and normalize complete point-in-time DNS A/AAAA and IP RDAP network/ASN observations.
- Append-only, idempotent SQLite storage with indexed lookup and UTC timestamps.
- Distinguish successful empty answers from collection failures; avoid unsupported cross-source comparisons.
- Temporal infrastructure-change features plus real, lightweight **unsupervised kNN novelty detection**.
- Produce reproducible gzip JSONL intelligence and evidence artifacts with SHA-256 manifests.
- Verify checksums, evidence references and independently recompute findings.
- Synthetic-only data publication guard; network-free CPU demonstration and unit tests.
- **v0.2 offline collector foundation:** explicit per-target request budgets, DNS A/AAAA/PTR fixture processing, RDAP network/autnum validation, outcome-preserving collection events, append-only collection ledger and pure public-destination/redirect checks (no network I/O).

**Important:** ANIE does not currently gather real internet data. Its ML distance is not an attack verdict, confidence, maliciousness probability or production-grade model. This prototype does not publish to GitHub or provision any cloud resource.

## Run immediately (Python 3.10+)

From the repository root, with no package installation:

```bash
PYTHONPATH=src python -m anie demo --out ./local-data/demo
PYTHONPATH=src python -m anie verify --dir ./local-data/demo/publication
PYTHONPATH=src python -m unittest discover -s tests -v
```

Or install locally:

```bash
python -m pip install -e .
anie demo --out ./local-data/demo
anie verify --dir ./local-data/demo/publication
```

The demo simulates **32 unchanged domains, one changing domain and one IP with registry context**, using reserved documentation addresses and domains. It generates a SQLite store, compressed intelligence artifacts and a manifest. The model should mark the changing synthetic domain as an outlier **without claiming it is malicious**.

After generation, examine the machine-readable records:

```python
import gzip, json
with gzip.open("local-data/demo/publication/intelligence.jsonl.gz", "rt") as file:
    for line in file:
        finding = json.loads(line)
        if finding["assessment"]["ai"]["status"] == "outlier":
            print(json.dumps(finding, indent=2))
```

## Offline collector demonstration (v0.2)

```bash
PYTHONPATH=src python examples/offline_collection_demo.py
```

This tests a fixture-only DNS/RDAP collector with a separately validated collection-event schema. No sockets or external providers are contacted. See [v0.2 collection design and limitations](docs/COLLECTOR_V02.md).

## Reusable commands

```bash
anie ingest --db ./local-data/state.sqlite --input ./examples/synthetic-observations.json
anie publish --db ./local-data/state.sqlite --out ./local-data/publication --as-of 2026-11-11T10:00:00Z
anie verify --dir ./local-data/publication
```

Only synthetically flagged records are accepted for v0.1 ingest/publication. The output location must be empty; no existing releases are silently overwritten. There is deliberately **no CLI command that can fetch or probe an internet target**.

## Integration contract

`schemas/intelligence-v1.schema.json` documents output records. Each one contains an indicator, evidence-based finding, provenance references, model version, feature values, observation time and explicit uncertainty. Consumers must verify the release first and apply their own security policies. The prototype's manifest hashes are **not digital signatures**; a trusted distribution channel and signed attestations are prerequisites for production.

## Repo status and license

This is a public, synthetic-only v0.1.0 research prototype, not an operational internet scanner. The project is distributed under the bundled Apache License 2.0. No private AEGIS code or dataset is included.

See [architecture and limitations](docs/ARCHITECTURE.md), [research plan](docs/RESEARCH_PLAN.md), and [security policy](SECURITY.md).

### AEGIS-style consumer demonstration

The separate example script verifies the dataset and prepares read-only IOC-context records:

```bash
PYTHONPATH=src python examples/aegis_readonly_consumer.py local-data/demo/publication
```

This is **not yet an AEGIS API integration**; it demonstrates the independent consumer contract without touching private cases or existing correlation rules.

## Repository development and governance

- [Agent instructions](AGENTS.md) and [specialized agents](.github/agents/) help contributors and coding agents follow the same evidence-first boundaries.
- [Task-specific Agent Skills](.agents/skills/) cover observation contracts, model evaluation, collector threat modeling, and releases.
- [Development workflow](docs/DEVELOPMENT_WORKFLOW.md), [threat model](docs/THREAT_MODEL.md), [public data policy](docs/DATA_PUBLICATION_POLICY.md) and [release process](docs/RELEASE_PROCESS.md) document mandatory review gates.
- [Contributing](CONTRIBUTING.md), [community conduct](CODE_OF_CONDUCT.md), [security](SECURITY.md) and [changelog](CHANGELOG.md) apply to the public project.

Before opening a PR, run `PYTHONPATH=src python -m unittest discover -s tests -v` and `python tools/check_repo.py`. The public repository includes **only offline/synthetic collection** at this stage. No workflow publishes datasets, provisions cloud resources or automatically deploys services.

## Synthetic temporal ML benchmark

ANIE includes a **chronological, replayable evaluation** comparing its unsupervised kNN novelty distance with two no-ML baselines on fabricated infrastructure patterns. It reports precision, recall, false alarms, abstentions and Python memory/timing diagnostics. Synthetic novelty is **not** evidence of attack or maliciousness.

```bash
PYTHONPATH=src python tools/benchmark_report.py --print-snapshot
```

See [Temporal Benchmark methodology](docs/TEMPORAL_BENCHMARK.md). The committed deterministic reference in `benchmarks/expected_snapshot.json` is checked by CI once established. This is a fixed synthetic time-split test, not a real-world accuracy claim.
