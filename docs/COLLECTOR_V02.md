# ANIE v0.2 — offline collector policy and evidence design

**State:** Safe offline research prototype. **No internet requests, DNS resolver, socket client, web crawler, scanning or live publishing have been enabled.**

## Purpose

This milestone validates future first-party DNS/RDAP collection semantics without spending money, contacting internet services, or requiring private AEGIS data. The only shipped transport is `FixtureTransport`, an in-memory reader of explicit synthetic responses.

## Request/response flow

1. An explicitly configured `CollectionPolicy` authorizes the exact canonical target + query kind. Empty default allowlist denies every request.
2. `CollectionBudget.reserve` accounts for each attempted fixture read and its target. The response is bounded by per-response and total byte budgets.
3. `FixtureTransport` returns only preloaded, in-memory JSON-compatible fixtures; absent keys fail closed.
4. The parser produces a validated `Observation` in the existing `anie.intelligence.v1` evidence shape plus a new `CollectionEvent` in `anie.collection-event.v1`. The latter retains DNS RCODE / HTTP status context and a SHA-256 of the synthetic fixture payload.
5. `CollectionLedger` stores collection-event metadata in independent append-only SQLite tables, preserving v0.1 `Observation` content IDs and release behavior. Collection events are not automatically included in v0.1 releases or public feeds.

### DNS semantics (RFC 2308 / RFC 9520)

| Simulated response | Observation | Collection event |
|---|---|---|
| Complete `NOERROR` A/AAAA/PTR answer | `ok` | `ANSWER` |
| Complete `NOERROR`, empty answer, explicit NODATA proof | `empty` | `NODATA` |
| `NXDOMAIN` | `empty` | `NXDOMAIN` |
| `SERVFAIL`, `REFUSED` | `error` | Original RCODE |
| Timeout, rate limit, upstream unavailable | `error` | Distinct transport outcome |
| Truncated, incomplete, mismatched question or malformed data | `error` | `INVALID_RESPONSE` |

The pre-decoded fixture contract requires `complete=true`, `truncated=false`, matching question name/type and, for NODATA, `negative_proof="NODATA"`. This prototype is **not** an authoritative wire DNS parser; real implementations must verify referrals, DNSSEC/AD, answer aliases and negative caching semantics independently.

### RDAP semantics (RFC 9083 / RFC 9224)

A successful synthetic `HTTP 200` IP network object must contain a range and/or compatible CIDR extension that actually includes the requested IP. The parser records only the containing prefix, not unrelated PII-rich registrar response fields.

`HTTP 404`, `429` and `5xx` map to errors (unavailable/rate-limited), not evidence of benign or nonexistent IPs.

`parse_autnum_fixture(ASxxxx, response)` separately validates `autnum` ranges. **An autnum response alone does not prove an IP-to-ASN association.** The existing legacy `rdap_asn` observation type is intentionally not produced from `autnum` fixtures; a future ASN subject and independent routing-provenance contract needs its own versioned design.

## Scope model

- Exact normalized domain/IP allowlists; empty policy denies all.
- Explicit kind allowlist, per-target and total request limits, payload byte limits, timeout setting, redirect budget and bounded concurrency configuration.
- Synthetic documentation IPs (RFC 5737/3849) may occur in offline fixtures; `ensure_global_ip` and `validate_resolved_addresses` reject those as future **network destinations**.
- Future redirect validation requires HTTPS, port 443, exact allowlist, bounded hops, and every resolved A/AAAA address publicly routable. **Checks must repeat at every DNS resolution and redirect; actual socket connection must be pinned to the validated address and independently blocked by egress firewall.** This prototype only implements pure predicates, not the egress firewall.
- The policy does not grant any live network capability; an injected arbitrary transport is rejected by `OfflineCollector`.

## Offline execution

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python examples/offline_collection_demo.py
python tools/check_repo.py
```

No network, cloud, API key or third-party dependency is required. The example uses exclusively RFC documentation domains/addresses and writes only local SQLite event metadata.

## Next gate before live source activation

Document target ownership/permission and terms; approved DNS resolver/RDAP authoritative bootstrap per RFC 9224; source redistribution rights; bounded network egress and DNS rebinding controls; privacy/PII minimization; retention and opt-out; expected scheduling and costs; and independent adversarial tests. The owner’s delegation of software development does not itself approve unrestricted real-world scanning or public redistribution.

References: [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308), [RFC 9520](https://www.rfc-editor.org/rfc/rfc9520), [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083), [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224).
