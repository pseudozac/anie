# ANIE development workflow — v1

This document is the operating process for owners, human contributors and code agents. The repository root `AGENTS.md` provides the mandatory invariants.

## Architecture boundary

ANIE is a public, independent intelligence **producer**, not an AEGIS plugin. It publishes machine-consumable, evidence-backed and appropriately licensed findings. AEGIS may later be an opt-in read-only consumer. SNOOP's browser evidence and AEGIS private case artifacts never automatically flow into a public ANIE dataset.

## 1. Triage and scope

Start with a GitHub issue or a concise design proposal containing: goal, expected output, validation plan, security/terms/privacy impact, estimated cost, affected schemas, required permissions and explicitly excluded work.

Use one of these risk classes:
- **Low:** docs, tests or offline code with unchanged output contract; no network, credentials, public real data, permissions or release.
- **Medium:** schema/model changes; new dependencies; dataset format/retention; reproducibility or downstream consumer changes. Requires dedicated compatibility and model-review evidence.
- **High:** outbound collectors, crawling, active probing, cloud resources, release/publishing, identity/secrets, Actions permissions, cross-repo integrations, real-world dataset distribution. Needs a written threat-model/data-rights review and explicit owner authorization **before live effects**.

## 2. Implement safely

Use a short-lived branch, one bounded objective and a small PR. Agent guidance is in `AGENTS.md`, Copilot specialist roles in `.github/agents/`, and task-specific skills in `.agents/skills/`.

- No background jobs, cloud changes, automatic network requests, external provider submission, live dataset ingestion, real-browsing capture or changes to AEGIS.
- Synthetic fixtures only until an approved source-activation milestone. The v0.1 publisher should refuse real data.
- Prefer Python standard library; new dependencies require supply-chain, license, size and cost justification.
- Version public schemas and model definitions, and preserve older findings/provenance for reproducibility.

## 3. Validate

From repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python tools/check_repo.py
PYTHONPATH=src python -m anie demo --out ./local-data/development-demo
PYTHONPATH=src python -m anie verify --dir ./local-data/development-demo/publication
```

Use a fresh demo directory or remove only your own generated local-data. Do not claim a test passed unless it ran. In PRs give exact commands, skipped tests, benchmark corpus, model baselines and results. Include negative tests for malformed inputs, unknown provenance, stale data, tampering, bounded resources and contradictory sources.

## 4. PR/CI review

Open a PR into `main`. PR template covers security, data, compatibility and rollback. `CODEOWNERS` identifies the maintainer but **does not enforce** review without matching branch-protection settings. GitHub Actions runs offline multi-Python tests, a policy check and synthetic replay with read-only token permissions. Dependabot proposes dependency updates; never auto-merge blindly.

Check exact PR head and all required status jobs. Investigate failed checks; do not weaken tests to manufacture a pass. High-risk changes cannot proceed until the owner records the exact approved operation, targets and cost/terms scope.

## 5. Release and feedback

No automatic release or cloud deployment exists in v0.1. Follow `docs/RELEASE_PROCESS.md` and `docs/DATA_PUBLICATION_POLICY.md` for reviewed source, verified compatibility and signed artifact plans. Never treat unsigned SHA-256 files as publisher-authenticated.

Record follow-up issues for limitations. Verified real-world observations can only enter a future public data flow after legal/privacy approval; no covert user telemetry or unconsented private sources.

## Maintainer GitHub settings (manual, after PR review)

Under repository Settings:
1. **Branches / Rulesets:** protect `main` from deletion and force pushes; require pull requests and the exact unique CI jobs after verifying their check names. For a solo maintainer, do not mandate one external approval unless a second reviewer is available.
2. **Advanced Security:** enable CodeQL default setup, secret scanning/push protection and Dependabot security updates where GitHub offers them; review and remediate alerts.
3. **Private vulnerability reporting:** enable it, then confirm `SECURITY.md` points to a working private channel.
4. **Actions:** default `GITHUB_TOKEN` permissions to read-only; no untrusted privileged triggers, unattended publishing, repository secrets for public PR tests, or self-hosted runners accessible to internal resources.

The presence of configuration files does not prove these UI settings were enabled.
