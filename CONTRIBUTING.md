# Contributing to ANIE

Thank you for contributing to ANIE's evidence-first, AI-native internet intelligence research.

Read [AGENTS.md](AGENTS.md) and [docs/DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) before proposing or changing code.

## Getting started

- Python 3.10+; no paid APIs or external services required.
- Use a branch and a small pull request; include synthetic fixtures and tests for every behavior change.
- Run `PYTHONPATH=src python -m unittest discover -s tests -v` and `python tools/check_repo.py`.
- A new `PYTHONPATH=src python -m anie demo --out ./local-data/demo` produces offline synthetic data; the output directory must be empty.
- Document security, privacy, licensing, performance and contract changes in the PR template.

## Research claims and data safety

AI anomaly labels are not malicious verdicts or calibrated confidence. Report baselines, evaluation windows, cohort size, missing evidence, and failure cases. Do not submit real customer telemetry, live URLs, private data, secrets or unlicensed third-party datasets.

The v0.1 repository has **no authorized network collection or public real-data feed**. A crawler/collector/active-scanning proposal needs explicit scope, threat model, licensing/retention review and owner authorization before any live execution. Build and test offline first.

Open a synthetic bug report or feature proposal through GitHub Issues. Do **not** disclose vulnerabilities through public issues; use [SECURITY.md](SECURITY.md).
