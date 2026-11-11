"""CPU-only robust k-nearest-neighbor novelty baseline (unsupervised ML).

Scores are relative distances within the observed cohort. They are NOT risk,
maliciousness probabilities, or statistically calibrated confidence.
"""
from __future__ import annotations

from math import sqrt
from statistics import median

MODEL_VERSION = "anie.robust-knn-novelty.v0.1"


def _quantile(sorted_values: list[float], probability: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * probability
    low = int(pos)
    frac = pos - low
    return sorted_values[low] * (1 - frac) + sorted_values[min(low + 1, len(sorted_values) - 1)] * frac


class RobustKNNNovelty:
    """Simple auditable nearest-neighbor estimator, no third-party runtime dependency."""
    def __init__(self, min_peers: int = 20, k: int = 5):
        self.min_peers = min_peers
        self.k = k
        self._vectors: dict[str, tuple[float, ...]] = {}
        self._medians: tuple[float, ...] = ()
        self._scales: tuple[float, ...] = ()
        self._threshold: float | None = None

    def fit(self, data: dict[str, tuple[float, ...]]) -> "RobustKNNNovelty":
        if len(data) > 500:
            raise ValueError("v0.1 model is bounded to 500 entities; use future indexed implementation")
        if not data:
            self._vectors = {}
            self._threshold = None
            return self
        widths = {len(vec) for vec in data.values()}
        if widths != {4}:
            raise ValueError("expected four numerical features per domain")
        self._vectors = dict(sorted(data.items()))
        cols = list(zip(*self._vectors.values()))
        self._medians = tuple(float(median(col)) for col in cols)
        self._scales = tuple(max(1.0, float(median([abs(x - center) for x in col])) * 1.4826) for col, center in zip(cols, self._medians))
        if len(data) <= self.min_peers:
            self._threshold = None
        else:
            loo = sorted(self._distance_for(subject, vector) for subject, vector in self._vectors.items())
            self._threshold = max(0.5, 1.5 * _quantile(loo, 0.90))
        return self

    def _distance_for(self, subject: str, vector: tuple[float, ...]) -> float:
        scores = []
        for peer_subject, peer in self._vectors.items():
            if peer_subject == subject:
                continue
            scores.append(sqrt(sum(((v - p) / scale) ** 2 for v, p, scale in zip(vector, peer, self._scales))))
        scores.sort()
        return sum(scores[:self.k]) / min(self.k, len(scores)) if scores else 0.0

    def evaluate(self, subject: str, vector: tuple[float, ...], *, has_comparison: bool) -> dict:
        if not has_comparison:
            return {"status": "insufficient_history", "novelty_distance": None, "threshold": None, "baseline_size": len(self._vectors)}
        if self._threshold is None:
            return {"status": "insufficient_cohort", "novelty_distance": None, "threshold": None, "baseline_size": len(self._vectors)}
        score = self._distance_for(subject, vector)
        return {
            "status": "outlier" if score > self._threshold else "within_cohort",
            "novelty_distance": round(score, 6),
            "threshold": round(self._threshold, 6),
            "baseline_size": len(self._vectors),
        }
