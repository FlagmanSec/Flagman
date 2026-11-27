"""The false-alarm budget: a split conformal threshold.

The idea, step by step:

1. Keep some **normal** flows aside, never used for training: the
   calibration set, n flows.
2. Give each one a score (higher means more suspicious).
3. Take as threshold the k-th smallest score, with k = ⌈(n+1)(1−α)⌉.
4. Raise an alert when a new flow's score is above the threshold.

If new normal traffic is **exchangeable** with the calibration flows
(roughly: it comes from the same mix, in no particular order, as when the
traffic does not change), a new normal flow is above the threshold with
probability at most α. That is a promise about the average over many
calibration sets, not about one day of traffic, and it says nothing when
the traffic changes: the drift monitor (drift.py) watches for that. It is
never a guarantee for a real network.

When n is too small for α (k > n), no threshold keeps the promise, and the
answer is "no alert": ``threshold`` returns infinity. n must be at least
1/α − 1: 999 normal calibration flows for α = 0.001.

Source: Angelopoulos and Bates, "A Gentle Introduction to Conformal
Prediction and Distribution-Free Uncertainty Quantification",
arXiv:2107.07511 (v6, 2022), section 1.1: the threshold is the
⌈(n+1)(1−α)⌉/n empirical quantile of the calibration scores, and Theorem 1
gives the 1−α coverage for i.i.d. data, averaged over the calibration and
test points ("marginal coverage").
"""

from __future__ import annotations

import math

import numpy as np


def threshold(scores: np.ndarray, alpha: float) -> float:
    """The ⌈(n+1)(1−α)⌉-th smallest calibration score (infinity if n is too small)."""
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")
    values = np.sort(np.asarray(scores, dtype=float))
    if np.isnan(values).any():
        raise ValueError("a calibration score is missing")
    n = len(values)
    k = rank(n, alpha)
    if k > n:
        return math.inf
    return float(values[k - 1])


def rank(n: int, alpha: float) -> int:
    """k = ⌈(n+1)(1−α)⌉, rounded first so that 1000 × 0.999 counts as 999."""
    return math.ceil(round((n + 1) * (1 - alpha), 9))


def smallest_calibration_set(alpha: float) -> int:
    """The fewest calibration flows that allow a finite threshold at this α."""
    n = max(1, math.floor((1 - alpha) / alpha) - 2)
    while rank(n, alpha) > n:
        n += 1
    return n


def alerts(scores: np.ndarray, limit: float) -> np.ndarray:
    """True where a score is strictly above the threshold."""
    return np.asarray(scores, dtype=float) > limit
