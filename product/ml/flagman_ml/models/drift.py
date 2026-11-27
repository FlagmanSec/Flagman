"""The drift monitor: is the traffic still like the calibration traffic?

The false-alarm budget (conformal.py) only holds while new normal traffic
is like the calibration traffic. Networks change (new devices, new
software, another time of year), so three checks compare a recent window
of flows with the calibration set:

1. **alert rate**: the share of recent flows that raised an alert, against
   the budget α. If the window is mostly normal traffic, a rate well above
   α means the budget no longer holds (or an attack is going on). A
   one-sided binomial test gives the p-value.
2. **anomaly scores**: a two-sample Kolmogorov-Smirnov test between the
   calibration flows' anomaly scores and the recent ones.
3. **features**: the population stability index (PSI) of each feature,
   recent window against calibration, over the calibration's deciles (and
   one bin for empty values).

The limits (``p_limit``, ``psi_limit``) are starting points to tune on the
team's own traffic, not standards. A flag means "look, and probably
recalibrate", not "the model is wrong".
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy import stats

from flagman_ml.flows import Schema

FLOOR = 1e-4  # a share of 0 would make the logarithm of the PSI infinite


@dataclass(frozen=True)
class DriftLimits:
    p_limit: float = 0.01
    psi_limit: float = 0.2


def alert_rate(alerts: np.ndarray, alpha: float) -> dict:
    """Share of alerts in the window, and how surprising it is under α."""
    alerts = np.asarray(alerts, dtype=bool)
    count, total = int(alerts.sum()), len(alerts)
    p_value = stats.binomtest(count, total, alpha, alternative="greater").pvalue if total else 1.0
    return {"flows": total, "alerts": count, "rate": count / total if total else 0.0,
            "budget": alpha, "p_value": float(p_value)}


def score_shift(reference: np.ndarray, recent: np.ndarray) -> dict:
    """Kolmogorov-Smirnov test between calibration and recent anomaly scores."""
    if len(reference) == 0 or len(recent) == 0:
        return {"statistic": None, "p_value": 1.0}
    result = stats.ks_2samp(reference, recent)
    return {"statistic": float(result.statistic), "p_value": float(result.pvalue)}


def psi(reference: pd.Series, recent: pd.Series) -> float:
    """Population stability index of one feature (0 means the same mix)."""
    if isinstance(reference.dtype, pd.CategoricalDtype):
        ref = reference.astype(str).value_counts(normalize=True, dropna=False)
        new = recent.astype(str).value_counts(normalize=True, dropna=False)
    else:
        numbers = reference.astype(float).dropna()
        deciles = np.quantile(numbers, np.linspace(0, 1, 11)) if len(numbers) else []
        edges = np.unique(deciles)  # equal deciles merge into one edge
        ref, new = _shares(reference, edges), _shares(recent, edges)
    ref, new = ref.align(new, fill_value=0.0)
    ref, new = np.maximum(ref.to_numpy(), FLOOR), np.maximum(new.to_numpy(), FLOOR)
    return float(np.sum((new - ref) * np.log(new / ref)))


def _shares(values: pd.Series, edges: np.ndarray) -> pd.Series:
    """Share of values per bin between the edges, plus one bin for empty values."""
    values = values.astype(float)
    bins = np.searchsorted(edges[1:-1], values.to_numpy(), side="right").astype(float)
    bins[values.isna().to_numpy()] = -1
    return pd.Series(bins).value_counts(normalize=True)


def drift_report(
    schema: Schema, reference_inputs: pd.DataFrame, recent_inputs: pd.DataFrame,
    reference_scores: np.ndarray, recent_scores: np.ndarray, recent_alerts: np.ndarray,
    alpha: float, limits: DriftLimits = DriftLimits(),
) -> dict:
    """All three checks, and the flags they raise."""
    rate = alert_rate(recent_alerts, alpha)
    shift = score_shift(reference_scores, recent_scores)
    stability = {name: psi(reference_inputs[name], recent_inputs[name])
                 for name in schema.feature_names}
    moved = sorted(name for name, value in stability.items() if value > limits.psi_limit)
    flags = []
    if rate["p_value"] < limits.p_limit:
        flags.append("more alerts than the false-alarm budget explains")
    if shift["p_value"] < limits.p_limit:
        flags.append("anomaly scores moved since calibration")
    if moved:
        flags.append(f"features moved since calibration: {', '.join(moved)}")
    return {"alert_rate": rate, "anomaly_scores": shift, "psi": stability,
            "limits": {"p_limit": limits.p_limit, "psi_limit": limits.psi_limit},
            "flags": flags}
