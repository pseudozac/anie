---
name: model-evaluation
description: Use when implementing or reviewing anomaly detection, temporal ML, scoring, feature extraction, forecasting, confidence, metrics, and experiments.
---

# Scientific model evaluation

1. Read `AGENTS.md`, `docs/RESEARCH_PLAN.md`, `src/anie/ml.py`, and the existing deterministic baseline.
2. Write a falsifiable hypothesis, feature definitions, time horizons, training/test split and datasets. All examples in v0.1 are synthetic.
3. **Prevent leakage:** a model at time T must not use observations, labels or decisions from after T. Keep model training and evaluation data provenance traceable.
4. Include a non-ML baseline and at least one naive baseline; compare improvements using predeclared metrics, confidence intervals where supported, runtime and storage.
5. Test sparse cohorts, missing values, duplicate/contradictory observations, source bias, infrastructure churn and adversarial examples. Define abstention and failure outputs.
6. Novelty distance is **not** a probability, threat score, or calibrated confidence. Do not claim compromise or attribution from statistical outlier status.
7. Report reproducible commands, exact corpus size and limitations. Hold back claims when no ground truth or no valid split exists.
8. Keep model access read-only to public/synthetic observations, and require deterministic policy gates before any proposed collection action.

No fabricated accuracy percentages, real-world efficacy claims or automatic retraining from unverified AEGIS outcomes.
