# ANIE threat model — v0.2 offline collector design and future network gates

## Assets and trust boundaries

Assets: published code/CI, public evidence provenance, intelligence schemas, model quality, local SQLite observations, future public releases, future collection credentials, reputation of the project and downstream decisions.

Boundary A: external/public internet -> future collectors (untrusted DNS/RDAP/HTTP/TLS data).
Boundary B: collector/parser -> observation store (potential malformed, forged, missing or replayed data).
Boundary C: observations -> features/ML -> intelligence outputs (bias, time leakage, false attribution).
Boundary D: internal/publication stage -> public GitHub artifacts (licensing, private data leakage, integrity).
Boundary E: public ANIE releases -> private AEGIS/other consumers (untrusted artifact supply chain).
Boundary F: external PRs -> CI and repository configuration (supply-chain, workflow privilege).

## Threats and controls

| Threat | Baseline control | Future gate |
| --- | --- | --- |
| SSRF / DNS rebinding / redirect to private services | No live v0.2 network client; pure simulated address/redirect validation and exact fixture-scope policy | Target allowlist; IP/CIDR classification; redirect and DNS revalidation; egress sandbox |
| Internet-service abuse or terms violation | No scanning/crawling in v0.2 | Ownership/authorization, robots/site terms, per-host budgets, stop switch, abuse contact |
| Malformed/oversized payloads and decompression bombs | Bounded JSON fields and artifact verification | Resource budget fuzzing, streaming parser limits, memory/time caps |
| Poisoned evidence, stale data, or source collusion | Source IDs, timestamps, explicit error states, evidence-linked findings | Origin authentication, freshness/validity rules, source reliability studies |
| Misleading ML confidence or false attribution | Novelty-only score, no malicious verdict, no fake probabilities | Time-split benchmark, provenance audit, calibration/abstention policy |
| Public disclosure of private data | Synthetic-only ingestion/publication | Data classification, license/PII reviews, retention and deletion response |
| Compromised published dataset | Local SHA-256 integrity and replay, not signature | Signed provenance, immutable manifest, reproducible release, consumer trust anchors |
| Malicious PR or compromised Action | No secrets in PR tests, least-privilege workflow token, pin actions | Branch rules, CodeQL, secret scanning and reviewed dependency updates |
| Prompt injection / agent-induced unsafe collection | Untrusted content is data; agent instructions never grant authority | Deterministic policy engine, tool sandbox, human approvals |

## Risk posture

v0.2 is offline, synthetic only. It adds strict synthetic fixture parser, explicit target and query budgets, an append-only collection-event ledger and modeled public-egress checks. **These checks are not an egress firewall or a real transport.** Therefore real network collector security controls are **design requirements, not implemented mitigations**. Nothing here authorizes live scans or proves future public-data redistribution rights.

Before adding *any* live collection: document source and terms, target scope, geographies if relevant, host/path permissions, response rate, consent, identity, egress isolation, IP rebinding defenses, budget, retention, complaints/opt-out and test evidence. Any high-impact response or active probing requires a separate explicit authorization.

Before connecting AEGIS: review immutable dataset provenance, verification keys, schema compatibility, unsafe/unexpected URLs, resource bounds, fail-closed behavior and the consumer's local policy. AEGIS must never interpret an ANIE model anomaly as an automatic customer verdict or response authorization.

## v0.4 offline acquisition design limitations

`OfflineRdapBootstrap` parses untrusted *synthetic* IANA-style bootstrap metadata with bounded size and HTTPS-only URL syntax checks; it cannot authenticate a registry feed, resolve a hostname or validate the socket destination. `OfflineCollectionScheduler` enforces local cache and synthetic query budgets but is not a durable cross-worker rate limiter, a network egress sandbox or a production DNS resolver. Future live activation requires separately documented permitted endpoints, source terms, real TLS and IP routing controls, rate compliance, opt-out, retention, and an explicit operational decision. See [v0.4 design](ACQUISITION_V04.md).
