# ANIE release process — manual approval only

This document is a checklist and release design, not permission for unattended GitHub releases, cloud deployments, publication or package uploads.

## Source/version policy

- Use `vMAJOR.MINOR.PATCH` Git tags after review. `pyproject.toml` and `src/anie/__init__.py` should agree.
- For wire-schema incompatibilities, create a new schema version; do not silently change meaning of `anie.intelligence.v1`.
- Model changes require a new immutable model version and evidence-backed evaluation.
- Maintain explicit release notes and known limits, with reproducible source commit and build instructions.

## Release GO/NO-GO

1. Review exact commit, PR(s) and CI job conclusions; record release scope and authorized operator.
2. Run and record unit tests, policy check, synthetic demo, manifest verification and consumer replay on the **same candidate**.
3. Check source dependency licenses, Actions permissions, secrets and vulnerabilities.
4. Inspect every proposed public artifact for real targets, private data, personal identifiers, license violations, unsupported malware claims and incorrect versions.
5. Produce checksums and tie the artifacts to the exact commit. For authenticity, plan signed GitHub attestations or an equivalent independently verifiable signature and public key; current `manifest.json` is unsigned.
6. Obtain explicit owner decision before tagging or publishing. Do not auto-create releases from PRs, model output or CI.
7. After a release, verify published asset bytes, source-to-artifact provenance and independent consumer compatibility. Record rollback/revocation advice for downstream consumers.

## Not currently enabled

Automatic dataset publisher, GitHub Releases workflow, PyPI trusted publishing, cloud runtime, managed signing keys, release artifact attestation, live real-data feeds.

Once a public dataset pipeline is approved, keep source code, low-churn manifests, and bulk data snapshots separate. Avoid committing rapidly changing databases to Git history or relying on GitHub Actions as a continuous internet crawler.

## Authenticated consumer design (Issue #6)

See [independent release trust design](RELEASE_TRUST_DESIGN.md). The current offline verifier uses a separately pinned manifest digest, **not a publisher signature**. No release signing, deployment or public real-data distribution is enabled.
