# ANIE research plan

Research question: can temporal first-party internet observations and uncertainty-aware AI produce reusable, evidence-backed intelligence more efficiently than repeated undirected collection?

## Evaluation before claims

- Baseline: deterministic change detection without machine learning.
- Model: robust kNN novelty baseline on a strictly time-separated corpus.
- Dataset: initially synthetic with known infrastructure transitions; later separately authorized public-domain samples.
- Metrics: novelty precision/recall at predeclared thresholds, historical timeliness, false attribution count, cost per useful evidence change, calibration when probabilistic forecasts are introduced.
- Guardrails: missing-data abstention, collector-source separation, error != empty, source/time provenance, no private/public mixture, replayable output.

## Next increments (not yet built)

1. Review and implement opt-in DNS and RDAP internet collectors after authorization, rate and provider terms review.
2. Add independently verified TLS and HTTP metadata under strict target allowlists.
3. Add source-specific relationship edges with first/last observed and competing hypotheses.
4. Train time-split models and compare their value against the deterministic baseline.
5. Add authenticated signed releases, public-data privacy review, and a read-only AEGIS adapter behind a feature flag.
6. Plan SNOOP separately as an opt-in browser sensor; its private observations must never flow to ANIE's public corpus by default.
