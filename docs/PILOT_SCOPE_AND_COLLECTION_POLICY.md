# ANIE — Pilot Scope & Collection Policy
## Governed First-Party DNS Intelligence Collection

- **Policy Document:** `POL-M3.5-PILOT-01`
- **Effective Milestone:** M3.5
- **Enforcement Level:** Mandatory / Fail-Closed

---

## 1. Ethical Governance & Strict Non-Involvement Mandate

ANIE is a specialized, first-party empirical DNS intelligence observatory. It is designed to observe public, passive internet infrastructure behaviors through standard recursive resolvers.

### Inviolable Governance Principles:
1. **No Broad Internet Crawling:** ANIE never executes indiscriminate web crawls, search engine scrapes, or bulk domain dictionary attacks.
2. **No Active Port Scanning or Probing:** ANIE strictly interacts with public DNS-over-HTTPS (DoH) APIs. It never connects directly to origin web servers, sends SYN scans, opens TCP handshakes to target infrastructure, or grabs HTTP/TLS banners.
3. **No PII or Sensitive Entity Targeting:** Targets are strictly restricted to public internet routing, nameserver infrastructure, CDN distributions, and authoritative endpoints. Individuals' personal domains, private email servers, or employee endpoints are prohibited from collection seed lists.
4. **No Evasion or Spoofing:** ANIE never alters source IPs, bypasses network rate limits, rotates proxies to evade throttling, or uses botnet-like traffic distribution.

---

## 2. Seed List Scope & Selection Criteria

The pilot targets an initial corpus of 25–50 core internet infrastructure domains categorized into three operational classes:

### Class A: Root & Authoritative Infrastructure
- `root-servers.net` (Root zone nameservers)
- `iana.org` / `icann.org` (Internet Assigned Numbers Authority)
- `arpa` (Address and Routing Parameter Area infrastructure)
- Major ccTLD and gTLD authority nameservers (`com`, `net`, `org`)

### Class B: Content Delivery & Anycast Infrastructure
- Cloudflare: `cloudflare.com`, `1.1.1.1`
- Fastly: `fastly.com`
- Akamai: `akamai.com`
- Google Infrastructure: `google.com`, `dns.google`
- AWS CloudFront: `cloudfront.net`

### Class C: Standard Enterprise Dual-Stack Reference
- `example.com` / `example.org` (RFC 2606 reserved reference targets)
- `wikipedia.org` (High-traffic dual-stack Wikimedia Foundation infrastructure)

---

## 3. Rate Limits, Workload Arithmetic & Cooldown Governance

Collection is mediated by the fail-closed `DohRateGovernor` backed by SQLite ACID transactions:

| Metric | Strict Threshold | Failure Action |
| :--- | :--- | :--- |
| **Per-Resolver Rate Limit** | Maximum 1 request / second | Throttled / Sleep |
| **Per-Domain Frequency** | Maximum 1 query / 10 minutes | Refused / Cached |
| **Max Queries per Hourly Window** | 60 queries total across all domains | Fail-closed skip |
| **Batch Timeout Deadline** | 30.0 seconds monotonic | Immediate batch termination |
| **Consecutive Failure Cooldown** | 3 failures $\implies$ 1-hour backoff | Cooldown enforced in DB |

### 3.1 Pilot Workload Arithmetic & Hourly Batch Reconciliation

The governed pilot executes an empirical baseline of 25 domains across 3 independent resolvers every 4 hours:
- **Queries per 4-Hour Cycle:** $25 \text{ domains} \times 3 \text{ resolvers} = 75 \text{ queries/cycle}$.
- **Daily Cycles:** $24 \text{ hours} / 4 \text{ hours} = 6 \text{ cycles/day}$.
- **Total Daily Workload:** $75 \text{ queries/cycle} \times 6 \text{ cycles/day} = \mathbf{450 \text{ requests/day}}$ (before retries).

#### Batch Partitioning & Rate-Governor Compliance:
Executing 75 queries in a single unpartitioned batch would violate the 60-query hourly threshold ($75 > 60$) and risk exceeding the 30.0-second timeout deadline. To reconcile the workload with operational limits:
1. Each 4-hour collection epoch is partitioned into **2 staggered hourly sub-batches**:
   - **Hour 0:** Sub-batch 1 runs 13 domains $\times 3 \text{ resolvers} = \mathbf{39 \text{ queries}}$ (execution time $\approx 13\text{--}15\text{ s} \le 30\text{ s}$ deadline).
   - **Hour 1:** Sub-batch 2 runs 12 domains $\times 3 \text{ resolvers} = \mathbf{36 \text{ queries}}$ (execution time $\approx 12\text{--}14\text{ s} \le 30\text{ s}$ deadline).
   - **Hours 2 & 3:** Quiet cooldown window ($0 \text{ queries}$).
2. Each sub-batch strictly honors $\le 39 < 60 \text{ queries/hour}$ per resolver and completes within half the 30-second monotonic deadline.

---

## 4. Transparent Resolver Governance

All queries are executed exclusively via DNS-over-HTTPS (DoH) to three independent, privacy-governed public recursive resolvers:
1. **Cloudflare DNS:** `https://cloudflare-dns.com/dns-query` (1.1.1.1)
2. **Google Public DNS:** `https://dns.google/resolve` (8.8.8.8)
3. **Quad9:** `https://dns.quad9.net/dns-query` (9.9.9.9)

Every query records exact resolver source provenance, response headers, response codes, and round-trip times to enable full discrepancy and security filtering analysis.

---

## 5. Operational Activation Gate

Live collection remains permanently disabled by default. Activation requires:
1. Execution environment variable `ANIE_LIVE_COLLECTION_AUTHORIZED=1`.
2. Clean preflight verification (available host RAM $\ge 200$ MiB, available disk $\ge 500$ MiB, database integrity verified).
3. Explicit operational sign-off by repository owner in an immutable release log.
