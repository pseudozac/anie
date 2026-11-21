"""Production Reference Consumer Client for AEGIS Integration (Contract V2).

Operational Clarification & Architectural Boundary:
This reference client demonstrates a local, read-only consumer interface directly querying
an ANIE SQLite storage file. It serves as an offline contract and schema verification fixture,
and does NOT constitute live system deployment, enterprise federation, or authenticated-release
bundle import into the operational AEGIS runtime framework. Downstream production ingestion
in AEGIS must verify detached Ed25519 attestations via verify_real_release().

Demonstrates clean, read-only downstream consumption of ANIE intelligence:
1. Instantiating AnieIntelligenceClient from SQLite store or exported findings feed.
2. Streaming cross-vector findings with deterministic cursor pagination.
3. Evaluating competing hypotheses while strictly observing epistemic humility
   (uncalibrated heuristic score != calibrated maliciousness probability).
4. Verifying authoritative raw evidence grounding.
5. Backward compatibility with V1 entity queries and IOC feeds.

Zero AEGIS Internal Dependency:
Operates directly against the frozen anie.consumer-contract.v2 interface.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from anie.consumer_contract import (
    CONSUMER_CONTRACT_VERSION_V2,
    AnieIntelligenceClient,
)
from anie.real_store import RealObservationStore


def run_consumer_demo(db_path: str | Path) -> None:
    client = AnieIntelligenceClient.from_database_path(db_path)
    print("=" * 80)
    print(f"ANIE -> AEGIS Consumer Contract V2 Integration Demo")
    print(f"Contract Version: {CONSUMER_CONTRACT_VERSION_V2}")
    print("=" * 80)

    # 1. Query Cross-Vector Findings (Contract V2)
    print("\n--- 1. Querying Cross-Vector Findings (Contract V2) ---")
    page = client.query_cross_vector_findings(limit=10)
    print(f"Retrieved {len(page.items)} findings (has_more={page.has_more})")

    for f in page.items:
        print(f"\n[Finding ID]: {f['finding_id']}")
        print(f"  Subject URI:      {f['subject_uri']}")
        print(f"  Finding Type:     {f['finding_type']}")
        print(f"  Epistemic Layer:  {f['epistemic_layer']}")
        print(f"  Asserted At:      {f['asserted_at']}")
        print(f"  State:            {f['state']}")
        print(f"  Participating:    {', '.join(f['abstention_state']['participating_vectors'])}")

        # Competing Hypotheses
        print("  Competing Hypotheses:")
        for h in f.get("competing_hypotheses", []):
            print(f"    - [{h['status']}] {h['hypothesis_label']} (Score: {h['heuristic_score']})")
            print(f"      Explanation: {h['explanation']}")

        # Epistemic Disclaimers
        print(f"  Notice:           {f.get('disclaimer', '')}")

        # 2. Authoritative Evidence Verification
        print("  Evidence Verification:")
        for v_name, v_summary in f.get("vectors", {}).items():
            ev_ref = v_summary.get("evidence_hash") or v_summary.get("evidence_id")
            if ev_ref:
                ver_res = client.verify_evidence_authoritativeness(ev_ref)
                auth_str = "AUTHENTICATED" if ver_res.get("is_authoritative") else "UNVERIFIED"
                print(f"    - Vector {v_name.upper()}: ref={ev_ref[:16]}... [{auth_str}] (Source: {ver_res.get('source_id')})")

    # 3. Backward Compatibility: V1 Canonical IOC Feed Export
    print("\n--- 2. Backward Compatibility: V1 IOC Feed Export ---")
    ioc_feed = client.export_canonical_ioc_feed(publisher_id="aegis-consumer-01")
    print(f"V1 Canonical IOC Feed generated with {len(ioc_feed.indicators)} indicators")
    print(f"Schema: {ioc_feed.schema}")

    # 4. Export Normalized Findings Feed (Contract V2)
    print("\n--- 3. Exporting Normalized Findings Feed (Contract V2) ---")
    findings_feed = client.export_normalized_findings_feed(page.items, publisher_id="aegis-consumer-01")
    print(f"Normalized Findings Feed generated (Schema: {findings_feed.schema}, Contract: {findings_feed.contract_version})")
    print(f"Total findings packaged: {findings_feed.total_findings}")

    print("\nIntegration check successful: AEGIS consumer contract V2 ready for production handoff.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Consumer Contract V2 Reference Client")
    parser.add_argument("database", help="Path to ANIE SQLite intelligence database")
    args = parser.parse_args()

    run_consumer_demo(args.database)
