# ANIE v0.4 — Controlled real-world DNS pilot

**Status:** Implemented behind an explicit one-shot operator command. **No live query runs in CI, at import, during package installation, or when ANIE starts normally.** No live RDAP yet.

## Exactly permitted scope

| Control | Limit |
| --- | --- |
| Subject | Only `example.com` (IANA example domain) |
| Query types | Exactly A and AAAA, once each |
| Remote service | `https://cloudflare-dns.com/dns-query` |
| Transport | RFC 8484 HTTPS GET with `application/dns-message` (NOT nonstandard JSON) |
| Connection | TLS >=1.2, verified SNI/hostname; socket pinned to validated global IP |
| Requests | 2 per *explicit CLI invocation*; no retries, redirects, redirects-to-RDAP, scans or crawling |
| Timeout | 5 seconds per request |
| Response cap | 65,535 bytes per response |
| Storage, sharing, monetization | None: results in memory and optionally printed to the operator's local console |
| Secrets, cloud, model agency | None |
| Attribution | Public recursive DNS response via Cloudflare; **not** authoritative ownership, threat verdict, or reliable historical passive DNS |

The code verifies **all** resolver-host A/AAAA resolved IPs are globally routable and creates TLS connections pinned to the chosen validated address while verifying the Cloudflare hostname. The fixed hostname cannot be supplied by a model, query, response, redirect or untrusted source. The GET request includes no cookies and uses `Connection: close`; any non-HTTP-200 status, malformed DNS answer, unsupported CNAME, oversized response, wrong media type, TCP/TLS error or timeout fails closed. It never attempts an alternate endpoint.

### Dry-run (safe default)

```bash
python tools/live_dns_pilot.py
```

The dry run prints exactly two planned URLs and makes **zero** network requests.

### Actual two-query pilot (manual action only)

```bash
python tools/live_dns_pilot.py --execute --ack "I approve two DNS queries for example.com"
```

This is an explicit operator action after reviewing the scope and Cloudflare terms; **do not run in GitHub Actions or an unattended job**. The output includes `synthetic: false`, `method: dns`, precise UTC observation timestamps, source ID, record values and response TTL. It is not written to SQLite, is never exported into a synthetic release and is not connected to private AEGIS.

**Operational caveats:** The two-request maximum is per run; repeated manually invoked runs are not covered by a durable across-process budget. The host's own DNS resolver is used only to locate the Cloudflare DoH endpoint, not to resolve the investigated target. DNS response authority, DNSSEC, CNAME chains and recursive resolver provenance require additional validation. Live RDAP transport, signed real-data exports, source attribution/legal review, persistent rate limiting and retention controls remain separate milestones.

### Why not bulk queries yet?

Cloudflare's public resolver is available without API keys, but it has terms of use and is not an unlimited commercial intelligence feed. A first-party internet intelligence engine needs provenance, permitted usage, caching, privacy and repeatable collection windows before scaling. No source license to redistribute real-world observations is assumed.

### RDAP bootstrap compatibility correction

The official IANA IPv4 RDAP registry currently contains **paired HTTPS and HTTP base URLs** for some services. RFC 9224 allows this while recommending secure transport. ANIE now keeps the verified HTTPS alternatives when an HTTP entry has an *exact HTTPS counterpart* and rejects HTTP-only or unpaired HTTP services. It still does not fetch or connect to a returned RDAP URL. Use the official registry at https://data.iana.org/rdap/ipv4.json for independent source review; no IANA file is committed or distributed by this milestone.

## Activation and next steps

The current code allows the manually initiated, exact two-query pilot only. It remains inappropriate for autonomous target discovery, scanning or a production crawler. Before **any wider collection**, establish durable per-provider and tenant rate limits, authenticated IANA snapshot retrieval, permitted provider targets and terms, opt-out/privacy policy, evidence validity, storage retention, safe error handling, revised public release licensing, and verified source identity. Any ANIE-to-AEGIS integration remains read-only and separately reviewed.

**References**

- [RFC 8484: DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484)
- [Cloudflare DoH wire-format documentation](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/)
- [Cloudflare resolver terms](https://developers.cloudflare.com/1.1.1.1/terms-of-use/)
- [RFC 9224: RDAP bootstrap service registry](https://www.rfc-editor.org/rfc/rfc9224)
- [IANA IPv4 RDAP bootstrap data](https://data.iana.org/rdap/ipv4.json)
