---
name: collector-threat-model
description: Use before proposing a DNS, RDAP, HTTP, certificate, crawling, sensor or active network collection feature; requires review before live access.
---

# Collector security and authorization review

**v0.1 permits no network collection.** Completing this skill yields a design proposal, not authorization.

1. Specify collector purpose, source, lawful basis/terms, allowed target list, identity, schedule, egress destination and ownership of output.
2. Map trust boundaries: DNS/redirect resolution, untrusted headers/bodies, parsing, storage, public release, logs, model-generated suggestions and cloud credentials.
3. Explicitly deny internal, loopback, link-local, metadata and private targets; implement revalidation after DNS resolution and every redirect for future HTTP clients.
4. Define connect/read/time budgets, per-host/per-domain rate and concurrency limits, cancellation, user agent/abuse contact, robots/site policy and opt-out.
5. Avoid active scanning absent target ownership or explicit permission. A model may rank preapproved targets but must never expand scope autonomously.
6. Plan sensitive-data minimization, source-specific licensing, retention/deletion, encrypted private secrets (if eventually needed), and public distribution approval.
7. Test malformed and oversized responses, DNS rebinding, redirects to local networks, IPv6 quirks, timeouts, 429/cooldown, denial and partial failures using local fixtures.
8. Submit a design PR with risks, zero-cost estimate, rollback, fixtures, and exact owner approval request. No live queries until that approval and separate implementation gate.

Read `docs/THREAT_MODEL.md` and `docs/DATA_PUBLICATION_POLICY.md` for the complete checklist.
