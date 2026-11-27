"""The decision for each flow, including attacks nobody labelled.

Two scores, each with its own conformal threshold (conformal.py), and
each given half of the false-alarm budget α, so that together a normal
flow raises an alert with probability at most α (on traffic exchangeable
with the calibration traffic):

- **suspicion**: 1 − P(normal), from the calibrated classifier, computed
  as the sum of the attack classes' probabilities (the same number, but
  without the rounding of 1 − 0.9999999...);
- **anomaly**: the Isolation Forest's score.

The decision:

1. neither score above its threshold: ``normal``;
2. otherwise an alert. Its class is the classifier's top class when that
   class is an attack and its probability is at least ``min_confidence``;
3. in every other case (low confidence, or a flow the classifier calls
   normal but the forest finds unusual) the class is
   ``unknown_suspicious``: something is wrong, and it looks like nothing
   the models were trained on. This is the open-set rule: low confidence
   and a high anomaly score give "unknown suspicious".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

UNKNOWN = "unknown_suspicious"


@dataclass(frozen=True)
class Thresholds:
    alpha: float  # the false-alarm budget for normal flows, shared by both scores
    suspicion: float  # threshold on 1 - P(normal), at alpha / 2
    anomaly: float  # threshold on the anomaly score, at alpha / 2
    min_confidence: float  # below it, an alert's class is unknown_suspicious

    def as_dict(self) -> dict:
        return asdict(self)


def suspicion_scores(proba: pd.DataFrame) -> np.ndarray:
    """1 − P(normal) for each flow, as the sum of the other classes' probabilities."""
    if "normal" not in proba:
        raise ValueError("the classifier was trained without normal flows")
    return proba.drop(columns="normal").sum(axis=1).to_numpy()


def decide(proba: pd.DataFrame, anomaly: np.ndarray, limits: Thresholds) -> pd.DataFrame:
    """One row per flow: the decision and the numbers behind it."""
    suspicion = suspicion_scores(proba)
    p_normal = proba["normal"].to_numpy()
    top = proba.idxmax(axis=1).to_numpy()
    confidence = proba.max(axis=1).to_numpy()
    suspicious = suspicion > limits.suspicion
    anomalous = np.asarray(anomaly) > limits.anomaly
    alert = suspicious | anomalous
    named = (top != "normal") & (confidence >= limits.min_confidence)
    decision = np.where(~alert, "normal", np.where(named, top, UNKNOWN))
    return pd.DataFrame({
        "decision": decision, "top_class": top, "confidence": confidence,
        "p_normal": p_normal, "suspicion": suspicion, "anomaly": anomaly,
        "suspicious": suspicious, "anomalous": anomalous,
    }, index=proba.index)
