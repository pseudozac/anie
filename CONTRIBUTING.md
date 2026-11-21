# Contributing to ANIE

Thank you for contributing to ANIE's evidence-first, AI-native internet intelligence research.

Read [AGENTS.md](AGENTS.md) and [docs/DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) before proposing or changing code.

## Getting started

- Python 3.10+; no paid APIs or external services required.
- Follow Spec-Driven Development: open an issue/spec, use a feature branch, and submit a focused pull request. Include fixtures and regression tests for every behavior change.
- Run the full test suite and repository governance check:
  ```powershell
  $env:PYTHONPATH="src;."
  python -m unittest discover -s tests -v
  python tools/check_repo.py
  ```
- Generate and verify offline synthetic intelligence:
  ```powershell
  python -m anie demo --out ./local-data/demo
  python -m anie verify --dir ./local-data/demo/publication
  ```
- Document security, privacy, licensing, performance, and contract impacts in the pull request template.

## Research claims and data safety

Statistical novelty, clustering distance, or temporal change are strictly empirical drift indicators—**not malicious verdicts, threat classifications, or calibrated confidence**. Report baselines, observation windows, cohort sizes, missing evidence, and failure modes. Never submit real customer telemetry, private credentials, internal investigation context, or unlicensed third-party datasets.

Live network collection is governed by strict fail-closed preflight hardening, target allowlists, and operator authorization under [docs/PILOT_SCOPE_AND_COLLECTION_POLICY.md](docs/PILOT_SCOPE_AND_COLLECTION_POLICY.md). All new telemetry vectors must be designed and verified offline with mock fixtures before any live execution. Egress from production collectors is restricted to authorized DoH endpoints. Private provenance signing keys are strictly air-gapped from collector runtimes.

Open a synthetic bug report or feature proposal through GitHub Issues. Do **not** disclose vulnerabilities through public issues; use [SECURITY.md](SECURITY.md).
