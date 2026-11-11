# Architecture and trust boundaries — ANIE v0.1

## Mission

ANIE is designed to produce portable, evidence-backed intelligence artifacts. AEGIS is a private, independent investigator and potential consumer; ANIE does not need access to AEGIS identity, infrastructure or case data.

## Implemented now

1. **Observation normalization:** strict bounded snapshots. `ok` means complete nonempty answer set, `empty` means a successful complete empty answer set, `error` means failure. `error` never implies absence.
2. **Temporal analysis:** compare complete same-source DNS snapshots by type; retain UTC timestamps and evidence IDs. Stale data remains visibly stale.
3. **Lightweight ML:** unsupervised robust-normalized k-nearest-neighbor novelty distance among sufficiently observed domains. This is an exploratory baseline and **not** maliciousness classification, confidence, or a discovery of compromise. No data exfiltration or online training.
4. **SQLite:** indexed append-only observations; exact duplicate ingestion is idempotent.
5. **Publication:** reproducible gzip JSONL artifacts and SHA-256 checksums. The verifier recomputes every intelligence record from observations.
6. **Consumer contract:** apps can verify data locally and ingest the schema without running ML.

## Not implemented

Live DNS, RDAP, HTTP, TLS collection; active scanning; autonomous crawling; browser extensions; scheduled cloud jobs; production databases; private ANIE/AEGIS integration; trained attack-detection model; genuine real-world findings; authenticated signatures; public dataset release; privacy/license clearance for third-party data.

## High-level flow

```text
synthetic observation fixtures
     -> strict validation
     -> append-only SQLite snapshot store
     -> per-source temporal change features
     -> unsupervised robust kNN novelty baseline
     -> evidence-linked JSON intelligence
     -> versioned gzip snapshot + SHA-256 manifest
     -> verified, offline reader (future AEGIS adapter)
```

## Future network-collection threat model

When live collection is eventually approved, each collector must have its own scope-limited egress policy, per-host concurrency/rate limits, robots/site policy for web crawling, strict redirect ceilings, DNS rebinding protections, and explicit prohibitions on probing private networks, link-local, cloud metadata endpoints, and targets outside authorized scope. The default policy should prevent AI from expanding collection scope autonomously. Neither source content nor model suggestions are executable instructions.

## Data publication and legal controls

Even public DNS and registration data can contain sensitive or personal content. A future collector must enforce minimization, retention limits, source-specific licensing, provenance, opt-out handling, review gates and documented permitted redistributions. Synthetic-only publication in v0.1 is intentional.

## ML boundary

This model compares four engineered DNS metrics against observed peers. With fewer than 21 comparable entities it abstains. Its outlier label is *novelty*, not suspiciousness, risk or a calibrated probability. All evaluations and model parameters are reproduced from the published synthetic observation corpus. Future models must be separately validated on unseen time windows and adversarial data.

## Scalability boundary

The v0.1 model is bounded to 500 comparable entities, and a publish batch to 10,000 observations. The nearest-neighbor implementation is quadratic in cohort size; it is a research baseline, not a production internet graph or streaming index. Future versions should use partitioned temporal storage, feature rollups, approximate nearest neighbor indexing, immutable public datasets, and signed provenance.
