# Public dataset and privacy publication policy

**Current state: DENY real-data publication.** The v0.1 repository may publish **only explicitly synthetic**, fictional data generated using reserved test domains/IP ranges. No production dataset, crawler or publisher job is authorized.

Public repository or open-source licensing does not license unrelated data. DNS/registration details, webpages, security advisories and certificates may carry terms, privacy, attribution and retention obligations, even if the bytes were freely reachable.

## Future publication gate (not yet granted)

Every proposed dataset must document:
- Source, acquisition method, source permission/terms and redistribution/license conditions
- Whether content includes personal data, credentials, emails, user browsing history, private IPs, customer IOCs, host identifiers or malware
- Evidence timestamps, timezone, validity/freshness, data provenance and collection biases
- Appropriate minimization/redaction, purpose, retention and deletion/complaint/opt-out process
- Exact schema and model version, content bounds, checksum, publisher authentication/signature
- Independent reviewer and owner approval, sample artifact and rollback/revocation mechanism

Never publish private AEGIS, SNOOP, customer, account, cookie, form, email, case, or telemetry artifacts by default. An AI model may generate hypotheses from approved public data but may not authorize collection or disclosure.

## Release types

- **Source release:** code and synthetic fixtures; reviewed and versioned.
- **Synthetic demo dataset:** marked `synthetic_demo_only`; cannot be represented as threat intelligence.
- **Real internet observation dataset:** future work, separately reviewed, source and license bound.
- **Private or organization data:** out of scope for public ANIE; never auto-export.

There is currently no signed publishing infrastructure, no provenance trust root, no live collector consent record and no real-data release approval. SHA-256 manifest consistency checks are **not** authenticity.
