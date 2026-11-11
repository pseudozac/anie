# Security policy

This is an OFFLINE, SYNTHETIC-ONLY research prototype, not a live security scanner.

- No collection network client, credential store, production deployment or data publishing automation exists in v0.1.
- Reports cannot declare an IOC malicious; novelty scores are not calibrated probabilities.
- Publish and verify only accept synthetic records. Do not introduce real datasets, private domains, customer logs, personal data or secrets into a public repository.
- Dataset hashes check consistency, **not** publisher identity or authenticity. Signed releases and trusted signing keys are future work.
- Public contributions must not add active scanning, unrestricted scraping, secret-bearing fixtures, prompt-injection-trusting agents, or unreviewed provider integrations.
- Any future live collector needs documented authorization, public/private IP restrictions, egress controls, SSRF resistance, rate budgets, site restrictions, and privacy review.

Report vulnerabilities privately to the repository maintainers after a public repository is created and its reporting channel is configured. Do not post exploitation details as public issues.


## Disclosure status and scope

This is a newly public research repository. The project does **not** currently verify that private vulnerability reporting is enabled; do not assume a public issue is confidential. The maintainer must enable GitHub private vulnerability reporting and test the channel before inviting external reports. See [maintainer setup checklist](docs/DEVELOPMENT_WORKFLOW.md#maintainer-github-settings-manual-after-pr-review).

No deployed ANIE collector, live-data pipeline or public intelligence feed is part of v0.1. Please do not test suspected vulnerabilities against systems you do not own or have permission to assess.
