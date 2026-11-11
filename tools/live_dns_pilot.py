"""ANIE's fixed-scope public DNS pilot — DRY-RUN by default.

Dry-run:
  python tools/live_dns_pilot.py

REAL DNS (MANUAL OPERATOR OPT-IN, exactly TWO HTTPS requests):
  python tools/live_dns_pilot.py --execute \
      --ack "I approve two DNS queries for example.com"

Never run this with CI, untrusted agent input, or customer/private targets.
No disk writes, scheduled collection or dataset publishing.
"""
from __future__ import annotations

import argparse
import json

from anie.live_dns_pilot import PILOT_ACK, request_plan, run_live_dns_pilot


def main() -> int:
    parser = argparse.ArgumentParser(description="One-shot bounded ANIE DNS pilot")
    parser.add_argument("--execute", action="store_true", help="Opt in to EXACTLY two real DNS-over-HTTPS requests")
    parser.add_argument("--ack", default="", help="Exact manually approved pilot scope phrase")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({
            "mode": "DRY_RUN",
            "network_requests": 0,
            "operator_confirmation_needed": True,
            "max_requests": 2,
            "endpoint": "https://cloudflare-dns.com/dns-query",
            "requests": [{"kind": r.kind, "target": r.domain,
                          "url": r.url, "accept": r.accept} for r in request_plan()],
        }, indent=2))
        return 0
    if args.ack != PILOT_ACK:
        parser.error("real query denied; exact --ack scope confirmation is required")
    rows = run_live_dns_pilot(acknowledge_scope=args.ack)
    print(json.dumps({
        "mode": "ONE_SHOT_REAL_DNS",
        "source": "cloudflare_doh:pilot",
        "requests_attempted": len(rows),
        "stored": False,
        "published": False,
        "observations": rows,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
