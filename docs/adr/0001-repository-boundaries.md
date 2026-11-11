# ADR-0001: Independent public intelligence producer, private consumers

**Status:** Accepted for prototype architecture  
**Date:** 2026-11-11

## Context

AEGIS is a private investigation workspace. SNOOP is a proposed opt-in browser sensor. ANIE aims to build independently collected, AI-enriched, time-aware intelligence without depending on commercial threat-intelligence APIs. The open-source project should serve AEGIS but must not need private customer information or credentials.

## Decision

Keep ANIE as a standalone Python package and public source repository. Public artifacts are immutable versioned data contracts with source/evidence provenance; consumers verify and index them locally. ANIE must not directly access private AEGIS storage. v0.1 supports offline synthetic data only. Any future network collection and publication is gated by explicit review.

## Consequences

Pros: modular model development, reproducible open research, low-cost offline CI, independent consumer interoperability and clean privacy boundary.

Cons: versioned schema compatibility, source and dataset publication policy, hosted collection costs, signing and verification requirements. The Git repository is not an unlimited live database; use low-churn manifests and appropriate signed data releases as the corpus grows.
