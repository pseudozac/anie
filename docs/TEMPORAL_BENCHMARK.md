# ANIE temporal ML benchmark — v1 (synthetic only)

## Question

Does ANIE's existing `RobustKNNNovelty` identify **synthetically unusual infrastructure patterns** more effectively than a simple change check, under controlled historical-only training? If not, record that finding rather than promoting a model merely because it is AI.

**Important:** This is a model engineering regression experiment, **not** a malicious-domain classifier, attacker attribution method, real-world accuracy estimate, or statistical confidence calibration.

## Strict chronological design

- Fixed deterministic seed: `20261111`. Inputs are invented `.example.test` names and RFC 5737 documentation-only IPv4 addresses.
- Training cutoff: `2026-11-01T12:00:00Z`, with snapshots on October 29, October 31 and November 1. The model's medians, scales and threshold are fitted on **historical training snapshots only**, without reading synthetic labels.
- Evaluation cutoff: `2026-11-11T12:00:00Z`. The disjoint evaluation seven-day feature window is November 4–11, with observations beginning November 6. No training snapshot lies inside the evaluation feature window.
- One fixed chronological holdout split: **not rolling-origin cross-validation**. Future evaluations need multiple folds, independent sources and real-world labeled outcomes, with ethics/privacy review.
- Model and baselines are predeclared in source. Re-tuning thresholds to improve these fixed synthetic labels would invalidate the evaluation.

## Three compared methods

1. `ml_knn_novelty`: the existing CPU-only unsupervised, robust-normalized nearest-neighbor distance. The threshold is fitted to training data. The output `outlier` is not maliciousness or a probability.
2. `deterministic_large_change`: fixed threshold of at least two complete DNS answer-set changes OR latest answer set of at least four unique IPs. An interpretable non-ML baseline.
3. `naive_any_dns_change`: flag any change between complete comparable DNS snapshots. A simple change baseline.

All three use the **same evidence eligibility gate**: abstain on stale/missing recent observations, fewer than two comparable recent snapshots, conflicting same-source snapshots, or cross-source disagreement. Errors remain separate from negative answers. An error alone does not label an IOC malicious or trigger positive predictions.

## Synthetic scenario categories

- Stable domains and benign shared/multi-tenant hosting
- Routine migrations, and simulated owner changes that **cannot be inferred from DNS** (the owner-change label is hidden metadata, not evidence)
- Intermittent timeouts with successful recovery
- Intentionally unusual rapid IP rotation and large multi-address fanout
- Stale records, insufficient history, conflicting same-source results and conflicting independent sources

The positive class means **deliberately unusual infrastructure pattern in a fabricated scenario**, not malware, exploit, attack, phishing or compromise. The negative class means not chosen as a novelty target, **not verified benign**.

## Reporting

Counts include TP/FP/TN/FN and **positive/negative abstentions**. Precision, recall across all positive cases, recall among evaluated cases, evaluated-only false positive rate and coverage are explicitly labeled. Undefined rates are `null`. Zero malicious verdicts/owner attribution are policy properties, not empirical threat-performance statistics.

- `train_observation_sha256` and `heldout_observation_sha256` prove the deterministic corpus used for the comparison; they do not authenticate a public publisher.
- Per-case predictions and evidence references can be audited; deterministic predictions are recorded via a golden SHA-256 fingerprint in `benchmarks/expected_snapshot.json`.
- `elapsed_ms` and Python `tracemalloc` peak allocated bytes are **runtime diagnostics**, not stable golden values, full RSS, or latency/SLO guarantees.
- The script reports synthetic cohort composition, model version and abstention reasons. The versioned snapshot is enforced by GitHub CI.

## Run offline

```bash
PYTHONPATH=src python tools/benchmark_report.py --check benchmarks/expected_snapshot.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

To inspect full per-case diagnostics locally, use `--report local-data/temporal-benchmark.json`. To intentionally regenerate the golden snapshot after a reviewed model/corpus change, use `--print-snapshot`; copy the generated JSON to the versioned file and explain the differences in the PR. Never silently replace the snapshot to make CI pass.

## Limitations and next scientific steps

This experiment uses a **small, constructed and correlated scenario family** rather than independent real traffic. The deterministic comparator may match or exceed ML; report both faithfully. Labels reflect only injected novelty, not observed adversarial behavior. Future work: repeated forward-chain splits, cross-provider sampling, representative out-of-distribution benign churn, calibrated confidence when warranted, ablation/feature leakage checks, concept drift and uncertainty tests. A claim of real-world improvement requires independent real data, explicit rights/consent and external validation.

Rationale for time-aware splits and leakage prevention: [scikit-learn TimeSeriesSplit documentation](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html), [common data leakage pitfalls](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).
