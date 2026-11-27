"""Training: from labelled flows to the models and their thresholds.

1. Keep the flows that may train or score (data.scored).
2. Split by feature file: the named calibration files are kept aside.
3. LightGBM on the training flows, its temperature set on the calibration
   flows (classifier.py).
4. Isolation Forest on the training set's normal flows only.
5. Conformal thresholds from the calibration set's normal flows: one for
   1 − P(normal), one for the anomaly score, each at α/2.

The calibration files need normal traffic. They should also hold attacks:
the temperature is set on whatever classes they hold, so a calibration set
of normal flows only teaches it about normal traffic (the report warns
about the classes it misses).

Example::

    frame = attach_labels(flows, "results/labels/lab.parquet")
    models, report = train(frame, flows.schema, calibration=["day2.parquet"])
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np
import pandas as pd

from flagman_ml.flows import Schema
from flagman_ml.models.anomaly import AnomalySettings, anomaly_scores, fit_anomaly
from flagman_ml.models.classifier import (
    TEMPERATURES,
    ClassifierSettings,
    fit_classifier,
    probabilities,
)
from flagman_ml.models.conformal import smallest_calibration_set, threshold
from flagman_ml.models.data import anomaly_matrix, scored, split_by_source
from flagman_ml.models.openset import Thresholds, suspicion_scores

# The drift monitor keeps at most this many normal calibration flows.
REFERENCE_FLOWS = 20_000


@dataclass(frozen=True)
class TrainSettings:
    alpha: float = 0.01  # false-alarm budget for normal flows
    min_confidence: float = 0.5
    drop_conflicts: bool = True
    classifier: ClassifierSettings = field(default_factory=ClassifierSettings)
    anomaly: AnomalySettings = field(default_factory=AnomalySettings)


def train(
    frame: pd.DataFrame, schema: Schema, calibration: list[str],
    settings: TrainSettings = TrainSettings(),
) -> tuple[dict, dict]:
    """(models, report). ``frame`` comes from labels.attach_labels."""
    names = schema.feature_names
    training, held = split_by_source(scored(frame, settings.drop_conflicts), calibration)
    normal_held = held[held["label"] == "normal"]
    normal_training = training[training["label"] == "normal"]
    if normal_held.empty or normal_training.empty:
        raise ValueError("both the training and the calibration files need normal flows: "
                         "the false-alarm budget is set on normal traffic")
    classifier = fit_classifier(training[names], training["label"], held[names],
                                held["label"], settings.classifier)
    forest = fit_anomaly(anomaly_matrix(normal_training[names], schema), settings.anomaly)

    suspicion = suspicion_scores(probabilities(classifier, normal_held[names]))
    anomaly = anomaly_scores(forest, anomaly_matrix(normal_held[names], schema))
    half = settings.alpha / 2
    limits = Thresholds(alpha=settings.alpha, suspicion=threshold(suspicion, half),
                        anomaly=threshold(anomaly, half), min_confidence=settings.min_confidence)
    keep = reference_rows(len(normal_held), settings.classifier.seed)
    models = {
        "classifier": classifier,
        "forest": forest,
        "thresholds": limits,
        # For the drift monitor: what normal traffic looked like at calibration.
        "reference": {"inputs": normal_held[names].iloc[keep].reset_index(drop=True),
                      "anomaly": anomaly[keep], "suspicion": suspicion[keep]},
    }
    return models, report(training, held, limits, classifier.temperature, settings, calibration)


def reference_rows(n: int, seed: int) -> np.ndarray:
    """Every row, or a fixed random sample of REFERENCE_FLOWS rows in order."""
    if n <= REFERENCE_FLOWS:
        return np.arange(n)
    return np.sort(np.random.default_rng(seed).choice(n, REFERENCE_FLOWS, replace=False))


def report(training: pd.DataFrame, held: pd.DataFrame, limits: Thresholds, temperature: float,
           settings: TrainSettings, calibration: list[str]) -> dict:
    """What was trained on what, and the thresholds: written into bundle.json."""
    normal = int((held["label"] == "normal").sum())
    needed = smallest_calibration_set(settings.alpha / 2)
    warnings = []
    if normal < needed:
        warnings.append(
            f"{normal} normal calibration flows, fewer than the {needed} that a budget of "
            f"{settings.alpha} needs: the thresholds are infinite and no flow raises an alert")
    if any(np.isclose(temperature, bound, rtol=0.01) for bound in TEMPERATURES):
        warnings.append(f"the temperature stopped at {temperature:.3g}, a bound of the search: "
                        "the calibration flows are too few or too easy to set it")
    absent = sorted(set(training["label"]) - set(held["label"]))
    if absent:
        warnings.append(f"no calibration flow of {absent}: the temperature was set "
                        "without them")
    return {
        "classes": sorted(training["label"].unique()),
        "flows": {"training": counts(training), "calibration": counts(held)},
        "files": {"training": sorted(training["source"].unique()),
                  "calibration": sorted(calibration)},
        "normal_calibration_flows": normal,
        "smallest_calibration_set": needed,
        "temperature": temperature,
        "thresholds": {k: (None if v == float("inf") else v) for k, v in limits.as_dict().items()},
        "settings": asdict(settings),
        "warnings": warnings,
    }


def counts(frame: pd.DataFrame) -> dict[str, int]:
    values = frame["label"].value_counts()
    return {name: int(values[name]) for name in sorted(values.index)}
