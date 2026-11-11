---
name: dataset-release
description: Use when designing or auditing JSONL snapshots, model/schema versions, GitHub Releases, public feeds or AEGIS consumer contracts.
---

# Dataset publication and compatibility

1. Read `AGENTS.md`, `docs/RELEASE_PROCESS.md`, `docs/DATA_PUBLICATION_POLICY.md`, `src/anie/publish.py`, and public schema.
2. Prove every finding's evidence IDs resolve and its model version, collection method, UTC observation time, assessment time and freshness are explicit.
3. Distinguish factual observations from model inference, forecast, analyst assertion and unverified hypothesis. Abstain where evidence is missing.
4. Review license/provenance and privacy line by line. **v0.1 public datasets must be synthetic only**; do not reclassify real targets as synthetic.
5. Generate into a new empty directory, compare deterministic hashes, run independent `anie verify`, recompute findings and check data bounds.
6. Require a reproducible manifest tied to a reviewed source commit. SHA-256 checksums alone do **not** authenticate the publisher; verified signatures and trust anchors are still future work.
7. Validate consumer compatibility without connecting to private AEGIS, reusing its secrets, or modifying existing assessments.
8. Produce a release GO/NO-GO report and obtain explicit owner approval before tagging, uploading, publishing or changing retention.

Document model-evaluation and legal uncertainty rather than silently broadening the scope of the public feed.
