"""Summaries over runs, and paired tests between two ways of deciding.

- ``mean_std``: the mean and the sample standard deviation over runs.
- ``wilcoxon``: the Wilcoxon signed-rank test on paired values, one pair
  per run (the same fold and seed). With few runs it cannot say much: with
  5 pairs, the smallest two-sided p-value possible is 2/2⁵ = 0.0625.
- ``mcnemar``: the exact McNemar test on the same flows: only the flows
  where the two disagree count (one right, the other wrong), and under
  "no difference" each side wins half of them (a binomial test).
"""

from __future__ import annotations

import numpy as np
from scipy import stats


def mean_std(values: list[float]) -> dict:
    kept = [v for v in values if v is not None]
    if not kept:
        return {"mean": None, "std": None, "runs": 0}
    return {"mean": float(np.mean(kept)),
            "std": float(np.std(kept, ddof=1)) if len(kept) > 1 else None, "runs": len(kept)}


def wilcoxon(first: list[float], second: list[float]) -> dict:
    """Two-sided signed-rank test of first against second, paired by position."""
    pairs = [(a, b) for a, b in zip(first, second, strict=True) if a is not None and b is not None]
    differences = np.array([a - b for a, b in pairs])
    result = {"pairs": len(pairs),
              "median_difference": float(np.median(differences)) if len(pairs) else None}
    if len(pairs) < 2 or not differences.any():
        return {**result, "statistic": None, "p_value": 1.0}
    test = stats.wilcoxon(differences)
    return {**result, "statistic": float(test.statistic), "p_value": float(test.pvalue)}


def mcnemar(first_right: np.ndarray, second_right: np.ndarray) -> dict:
    """Exact McNemar test: are the two equally often right on the same flows?"""
    first_right = np.asarray(first_right, dtype=bool)
    second_right = np.asarray(second_right, dtype=bool)
    only_first = int((first_right & ~second_right).sum())
    only_second = int((~first_right & second_right).sum())
    disagree = only_first + only_second
    p_value = stats.binomtest(only_first, disagree, 0.5).pvalue if disagree else 1.0
    return {"only_first_right": only_first, "only_second_right": only_second,
            "p_value": float(p_value)}
