# ANIE release authenticity and independent consumer design (Issue #6)

**Status: design + offline trust-pin verifier. No signed publisher, live dataset, public release, or AEGIS connection exists.**

## Threat boundary and trust

A checksum downloaded with the same artifact **cannot authenticate its publisher**: an attacker can replace both. The shipped `ConsumerTrustPolicy` requires a manifest SHA-256 pinned through a separate authenticated operator channel. This is an integrity check against a trusted digest, **not a digital signature**, and it is vulnerable if the pin-distribution channel is compromised. A GitHub URL alone does not replace a verified signature.

Future production design: use a transparency-logged Sigstore/GitHub Artifact Attestation bound to the reviewed GitHub repository, workflow identity, source commit, and artifact digest; alternatively use a separately controlled offline signing key with explicitly pinned public-key fingerprint and documented rotation/revocation. Verification must reject unsigned artifacts, mismatched identities, unsupported algorithms and expired/revoked trust roots. **Neither signature option is implemented here.** The pure `validate_release_provenance` function checks metadata consistency only and explicitly returns `publisher_signature_verified=False`.

## Three independently versioned release types

1. **Source release:** reviewed code/tag/commit; no automatic releases.
2. **Raw public evidence snapshot:** future `anie.observations.vN`, source- and rights-bound, timestamps and collection method; **not yet authorized or implemented**.
3. **Derived intelligence snapshot:** `anie.intelligence.v1` plus immutable model version and referenced observation IDs. Findings must not infer maliciousness from novelty.

The existing `anie.dataset-manifest.v1` contains synthetic-only observation and intelligence files. This milestone does **not** change its bytes, schema, observation IDs, or historical release replay. A future authenticated manifest version must contain source commit, exact build recipe, source-specific rights, dataset version, model version, input snapshot digest, output digest, signing identity, attestation reference, assessment time, validity bounds, revocation location and supported consumer range.

## Offline trust-pin verification

```python
from hashlib import sha256
from pathlib import Path
from anie.release_trust import ConsumerTrustPolicy, verify_pinned_synthetic_release

# EXAMPLE ONLY: Obtain digest through an independently authenticated channel.
# Do NOT derive the trust pin from the same downloaded untrusted directory.
trusted_pin = "..."  # 64 hex characters supplied by an approved operator
result = verify_pinned_synthetic_release(
    Path("local-data/demo/publication"),
    ConsumerTrustPolicy(trusted_pin, max_age_seconds=30 * 86400),
    now="2026-11-11T11:00:00Z",
)
assert result["verified"] and not result["publisher_signature_verified"]
```

The verifier fails closed for untrusted manifest hash, unsupported schema, non-synthetic dataset, future-dated or stale assessment, corrupt/oversized gzip, unresolved evidence IDs, and inconsistencies against the deterministic model. It does not touch private AEGIS or trigger incident response.

## AEGIS read-only consumer protocol (design only)

- Download to an untrusted quarantine directory with strict byte and decompression limits.
- Verify signature/attestation against independently pinned trust roots and exact source workflow/commit (future work); require authorized data license and version.
- Validate manifest, evidence graph, model version and freshness before any parsing into a staging database.
- Apply immutable import transaction; idempotently identify by content digest; never overwrite analyst evidence or previous assessments.
- Fail closed on corruption, stale or conflicting source versions. Keep the last verified, non-expired snapshot; otherwise mark external enrichment unavailable. Never interpret unavailable as benign.
- Rollback by atomically restoring the previous trusted snapshot pointer, retaining audit history. Key revocation must invalidate affected future imports and trigger re-evaluation of cached trust.
- AEGIS continues making its own evidence-based findings. ANIE novelty is context, not a verdict or authority to contain endpoints.

No AEGIS implementation, credentials or production data are included in this PR.

## Hosting and cost tradeoffs

| Option | Appropriate use | Limits / cost risk |
| --- | --- | --- |
| GitHub source tags/releases | Low-frequency signed source and small synthetic examples | Release quotas and artifact provenance; do not use for unbounded continuously updated datasets |
| GitHub Actions artifacts | CI test evidence and short-lived staging | Retention limits, quota and supply-chain permissions; not a long-lived public intelligence feed |
| R2 / other object storage | Future versioned immutable public snapshots | Storage, operations, egress and custom-domain costs vary; no zero-cost guarantee |
| Consumer-local SQLite / Neon | Index only validated snapshots, avoid repeated downloads | Retention, storage growth, and provider billing limits |

Default decision: **do not deploy distribution infrastructure**. Stay with offline demo files until rights, signing identity, actual data volume and spending cap are approved.

## Activation gates

1. GitHub branch protection / required CI and repository security settings verified (Issue #3 remains open).
2. Owner approves source/rights/privacy scope and release cadence.
3. Cryptographic signature verification against independent trust anchors is implemented and adversarially tested.
4. Real-world source provenance and data-retention rules approved; synthetic-only until then.
5. AEGIS consumer compatibility and rollback tested against its private environment in a separate authorized change.
6. Cost ceiling, storage and bandwidth forecasts approved; no uncontrolled public endpoint.

**Decision: NO-GO for authenticated real-world dataset publication. GO for offline design tests only.**
