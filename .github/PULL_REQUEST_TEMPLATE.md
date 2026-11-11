## Purpose and scope

<!-- What changes, why, and what remains out of scope? -->

## Risk and data classification

- [ ] Offline synthetic-only change (no network or data publication)
- [ ] Network/collector capability (requires separate authorization and threat-model review)
- [ ] Public data/schema/release impact (requires owner approval and compatibility review)
- [ ] Model/score impact (requires time-split evaluation and abstention checks)
- [ ] Security/CI/permissions impact (requires supply-chain and workflow review)

**Risk:** Low / Medium / High

## Evidence and validation

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v`
- [ ] `python tools/check_repo.py`
- [ ] Synthetic demo + verifier, where relevant
- [ ] Tests cover errors, missing data, input limits, and unexpected cases
- [ ] No secret, PII, private AEGIS/SNOOP data, provider-restricted datasets, or real IOC in fixtures/logs
- [ ] Every AI-derived claim is labeled as model inference, not observed fact or threat verdict
- [ ] Docs and versioned contracts updated as necessary

**Commands/results (include failures and skipped checks):**

## Security, privacy, licensing and cost review

**External network, credentials, persistence, publication, data retention, billing:**

## Rollback / compatibility impact

## Owner authorization needed

<!-- Specify exact operations requiring approval. No approval is implied by this PR. -->
