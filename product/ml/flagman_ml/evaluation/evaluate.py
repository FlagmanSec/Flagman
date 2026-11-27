"""The metrics of one run: a trained model's decisions on the test flows.

Everything is measured on the test files only. Background, unlabelled and
conflicting flows are left out of every metric except alerts per day,
where every flow counts (an alert on background traffic still reaches the
person reading the dashboard).

Three ways of deciding are compared on the same flows:

- ``two scores``: Flagman's rule (each score at α/2, see models/openset.py);
- ``classifier only``: suspicion alone, at α;
- ``anomaly only``: the anomaly score alone, at α.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from flagman_ml.evaluation import metrics as m
from flagman_ml.evaluation.paired import mcnemar
from flagman_ml.flows import Schema
from flagman_ml.labels.classes import NOT_SCORED
from flagman_ml.models.classifier import probabilities
from flagman_ml.models.conformal import threshold


def evaluate(frame: pd.DataFrame, predictions: pd.DataFrame, models: dict, schema: Schema,
             alpha: float) -> dict:
    """All metrics of one run, as a JSON-ready dict."""
    per_day = m.alerts_per_day(frame, (predictions["decision"] != "normal").to_numpy())
    keep = ~frame["label"].isin(NOT_SCORED)
    if "conflict" in frame:
        keep &= ~frame["conflict"].astype(bool)
    truth, p = frame.loc[keep, "label"], predictions[keep.to_numpy()]
    normal = (truth == "normal").to_numpy()
    attack = ~normal
    reference = models["reference"]
    alone = {name: threshold(reference[name], alpha) for name in ("suspicion", "anomaly")}
    rules = {"two scores": (p["decision"] != "normal").to_numpy(),
             "classifier only": p["suspicion"].to_numpy() > alone["suspicion"],
             "anomaly only": p["anomaly"].to_numpy() > alone["anomaly"]}
    right = {name: alert == attack for name, alert in rules.items()}
    scores = {"suspicion": p["suspicion"].to_numpy(), "anomaly": p["anomaly"].to_numpy()}
    known = set(models["classifier"].classes_)
    return {
        "flows": {"test": int(len(frame)), "scored": int(keep.sum()),
                  "classes": {k: int(v) for k, v in truth.value_counts().sort_index().items()}},
        "unseen_classes": sorted(set(truth) - known),
        "budget": {
            "alpha": alpha,
            "false_alarms": m.rate(int(rules["two scores"][normal].sum()), int(normal.sum())),
            "suspicion": m.rate(int(p["suspicious"].to_numpy()[normal].sum()), int(normal.sum())),
            "anomaly": m.rate(int(p["anomalous"].to_numpy()[normal].sum()), int(normal.sum())),
        },
        "rules": {name: {"false_alarms": m.rate(int(alert[normal].sum()), int(normal.sum())),
                         "detection": m.rate(int(alert[attack].sum()), int(attack.sum())),
                         "against_two_scores": mcnemar(right[name], right["two scores"])}
                  for name, alert in rules.items()},
        "at_fpr": {str(target): {
            "suspicion": m.detection_at_fpr(scores["suspicion"][normal],
                                            scores["suspicion"][attack], target),
            "anomaly": m.detection_at_fpr(scores["anomaly"][normal], scores["anomaly"][attack],
                                          target),
            "two scores": m.detection_at_fpr_two_scores(
                (scores["suspicion"][normal], scores["anomaly"][normal]),
                (scores["suspicion"][attack], scores["anomaly"][attack]), target)}
            for target in m.FPR_TARGETS},
        "precision": precision(rules["two scores"], normal, attack),
        "f1": m.per_class_f1(truth, p["decision"]),
        "by_class": m.detection_by_class(truth, p["decision"]),
        "calibration": calibration(frame[keep], p, models, schema, known),
        "alerts_per_day": per_day,
    }


def precision(alert: np.ndarray, normal: np.ndarray, attack: np.ndarray) -> dict:
    """Precision of Flagman's alerts if attacks were this rare (Bayes' rule)."""
    if not normal.any() or not attack.any():
        return {}
    detection, false_alarm = alert[attack].mean(), alert[normal].mean()
    return {str(base): m.precision_at_base_rate(float(detection), float(false_alarm), base)
            for base in m.BASE_RATES}


def calibration(frame: pd.DataFrame, p: pd.DataFrame, models: dict, schema: Schema,
                known: set[str]) -> dict:
    """ECE before and after temperature scaling, on flows of classes the model knows."""
    mine = frame["label"].isin(known).to_numpy()
    if not mine.any():
        empty = m.calibration_error(np.array([]), np.array([]))
        return {"temperature": float(models["classifier"].temperature),
                "calibrated": empty, "uncalibrated": empty}
    truth = frame["label"].to_numpy()[mine]
    raw = probabilities(models["classifier"], frame.loc[mine, schema.feature_names],
                        calibrated=False)
    return {"temperature": float(models["classifier"].temperature),
            "calibrated": m.calibration_error(p["confidence"].to_numpy()[mine],
                                              p["top_class"].to_numpy()[mine] == truth),
            "uncalibrated": m.calibration_error(raw.max(axis=1).to_numpy(),
                                                raw.idxmax(axis=1).to_numpy() == truth)}
