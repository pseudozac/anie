---
name: observation-contract
description: Use when changing normalization, DNS/RDAP records, SQLite observations, temporal comparisons, evidence IDs or public intelligence schemas.
---

# Observation contract: evidence before verdict

1. Read `AGENTS.md`, `src/anie/observations.py`, `src/anie/temporal.py`, `schemas/intelligence-v1.schema.json`.
2. State the kind, subject normalization, completeness, UTC collection time, source ID, method and validity semantics. Preserve `ok`, `empty`, `error` as distinct values; failed lookup is never a negative answer.
3. Keep point-in-time DNS answer sets complete, bounded and normalized. Compare successive comparable snapshots from the same source and record family. Do not infer ownership or maliciousness from any connection.
4. Require deterministic content-based evidence references. Do not silently rewrite historical evidence or publish unsupported model confidence.
5. Make backwards-incompatible contract changes by proposing a new schema version and consumer test, not by mutating `anie.intelligence.v1` silently.
6. Test malformed input, repeated ingestion, empty/error/missing source, cross-source disagreement, timezones, future timestamps, conflicting same-time answers and evidence-reference integrity.
7. Run `PYTHONPATH=src python -m unittest discover -s tests -v`; report test results and remaining uncertainty.

Never introduce a live network request under the pretext of a parser change; review `collector-threat-model` separately.
