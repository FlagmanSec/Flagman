"""Evaluation metrics, each small enough to check by hand.

Every function takes plain arrays, so the tests can use tiny examples.

- ``rate``: a share with its exact 95% confidence interval (Clopper and
  Pearson, through scipy's binomial test), so "0.8% false alarms" comes
  with how sure that number is.
- ``detection_at_fpr``: the share of attack flows caught when the
  threshold lets through at most a given share of normal flows (one point
  of the ROC curve). The threshold is read on the test flows themselves:
  it describes a score, it is never how Flagman sets its thresholds.
- ``precision_at_base_rate``: Bayes' rule. When attacks are rare, even a
  small false-alarm rate makes most alerts false.
- ``calibration_error``: the expected calibration error (ECE) of Guo et
  al. (ICML 2017, section 2): the top-class probabilities in M
  equal-width bins (M = 15 in their experiments), and the gap between
  accuracy and confidence in each bin, weighted by its share of flows.
- ``per_class_f1``, ``detection_by_class``, ``alerts_per_day``.
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import f1_score

CONFIDENCE = 0.95  # of every interval
FPR_TARGETS = (0.001, 0.005, 0.01)
BASE_RATES = (0.001, 0.01)
ECE_BINS = 15
DAY_MS = 86_400_000


def rate(count: int, total: int, confidence: float = CONFIDENCE) -> dict:
    """count / total, with its exact confidence interval."""
    if total == 0:
        return {"count": 0, "total": 0, "rate": None, "low": None, "high": None}
    interval = stats.binomtest(count, total).proportion_ci(confidence, method="exact")
    return {"count": int(count), "total": int(total), "rate": count / total,
            "low": float(interval.low), "high": float(interval.high)}


def threshold_for_fpr(normal: np.ndarray, fpr: float) -> float:
    """The lowest normal score that leaves at most a share ``fpr`` of normal
    scores strictly above it (minus infinity when every flow may pass)."""
    ordered = np.sort(np.asarray(normal, dtype=float))
    allowed = math.floor(round(fpr * len(ordered), 9))  # normal flows allowed above
    return -math.inf if allowed >= len(ordered) else float(ordered[len(ordered) - allowed - 1])


def detection_at_fpr(normal: np.ndarray, attack: np.ndarray, fpr: float) -> dict:
    """Detection when at most a share ``fpr`` of normal flows score above the threshold."""
    limit = threshold_for_fpr(normal, fpr)
    return {"fpr_target": fpr, "normal_flows": len(normal),
            "enough_normal_flows": len(normal) >= 1 / fpr,
            "fpr": float(np.mean(np.asarray(normal) > limit)) if len(normal) else None,
            "detection": float(np.mean(np.asarray(attack) > limit)) if len(attack) else None}


def detection_at_fpr_two_scores(normal: tuple[np.ndarray, np.ndarray],
                                attack: tuple[np.ndarray, np.ndarray], fpr: float) -> dict:
    """The same with Flagman's rule: each score gets half the share, and a
    flow above either threshold is caught."""
    limits = [threshold_for_fpr(scores, fpr / 2) for scores in normal]
    caught_normal = (normal[0] > limits[0]) | (normal[1] > limits[1])
    caught_attack = (attack[0] > limits[0]) | (attack[1] > limits[1])
    return {"fpr_target": fpr, "normal_flows": len(normal[0]),
            "enough_normal_flows": len(normal[0]) >= 2 / fpr,
            "fpr": float(caught_normal.mean()) if len(caught_normal) else None,
            "detection": float(caught_attack.mean()) if len(caught_attack) else None}


def precision_at_base_rate(detection: float, false_alarm: float, base_rate: float) -> float | None:
    """Share of alerts that are attacks when a share ``base_rate`` of flows are attacks."""
    true_alerts = detection * base_rate
    false_alerts = false_alarm * (1 - base_rate)
    total = true_alerts + false_alerts
    return true_alerts / total if total else None


def calibration_error(confidence: np.ndarray, correct: np.ndarray, bins: int = ECE_BINS) -> dict:
    """ECE over equal-width bins of the top-class probability, and each bin."""
    confidence = np.asarray(confidence, dtype=float)
    correct = np.asarray(correct, dtype=bool)
    if len(confidence) == 0:
        return {"ece": None, "bins": []}
    edges = np.linspace(0, 1, bins + 1)
    # Bin m holds the probabilities in ((m-1)/M, m/M]; a probability of 0 goes to the first.
    index = np.clip(np.searchsorted(edges, confidence, side="left") - 1, 0, bins - 1)
    rows, ece = [], 0.0
    for m in range(bins):
        inside = index == m
        if not inside.any():
            continue
        accuracy, mean_confidence = correct[inside].mean(), confidence[inside].mean()
        ece += inside.mean() * abs(accuracy - mean_confidence)
        rows.append({"low": float(edges[m]), "high": float(edges[m + 1]),
                     "flows": int(inside.sum()), "accuracy": float(accuracy),
                     "confidence": float(mean_confidence)})
    return {"ece": float(ece), "bins": rows}


def per_class_f1(truth: pd.Series, decided: pd.Series) -> dict:
    """F1 of each class present in the truth, and their mean (macro-F1).
    A decision of unknown_suspicious is wrong for every class."""
    classes = sorted(set(truth))
    if not classes:
        return {"macro_f1": None, "f1": {}}
    scores = f1_score(truth, decided, labels=classes, average=None, zero_division=0)
    return {"macro_f1": float(np.mean(scores)),
            "f1": dict(zip(classes, map(float, scores), strict=True))}


def detection_by_class(truth: pd.Series, decided: pd.Series) -> dict:
    """For each attack class: flows, the share that raised an alert, the
    share named with the right class, and what they were called."""
    result = {}
    for name in sorted(set(truth) - {"normal"}):
        mine = decided[truth == name]
        result[name] = {"flows": int(len(mine)), "alerted": float((mine != "normal").mean()),
                        "named": float((mine == name).mean()),
                        "decisions": {k: int(v) for k, v in mine.value_counts().items()}}
    return result


def alerts_per_day(frame: pd.DataFrame, alert: np.ndarray) -> dict:
    """Alerts per day of capture, for each feature file (time span from its flows)."""
    result = {}
    work = frame[["source", "flow_start_ms", "flow_end_ms"]].assign(alert=np.asarray(alert))
    for source, part in work.groupby("source", sort=True):
        days = (part["flow_end_ms"].max() - part["flow_start_ms"].min()) / DAY_MS
        alerts = int(part["alert"].sum())
        result[source] = {"alerts": alerts, "days": float(days),
                          "per_day": alerts / days if days > 0 else None}
    return result
