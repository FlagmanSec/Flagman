"""Ablations: how much does the classifier lean on the suspect features?

LightGBM is trained on the training files and scored on held-out files
(macro-F1: the F1 score of each class, averaged, so that every class
counts the same however rare it is), three ways:

1. with every feature;
2. without the watched features (``schema.watched()``);
3. without each flagged feature (separability.py), one at a time.

A large drop when a feature is removed means the model leans on it; if
that feature describes the testbed, the score with it is not to be
trusted. A small drop means that other features carry the same
information.

The held-out files must be validation files, never the final test files:
what the audit shows decides which features to keep, and a choice made on
the test files would make their scores look better than they are.

Example::

    result = ablations(frame, schema, held_out=["day4.parquet"], flagged=["duration_ms"])
    [(run["name"], run["macro_f1"], run["drop"]) for run in result["runs"]]
"""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import f1_score

from flagman_ml.flows import Schema
from flagman_ml.models.classifier import ClassifierSettings, make_booster
from flagman_ml.models.data import split_by_source

MAX_SINGLE_ABLATIONS = 10  # one training each: keep the audit's run time bounded


def macro_f1(truth: pd.Series, predicted) -> tuple[float, dict[str, float]]:
    """Macro-F1 over the classes of the held-out flows, and each class's F1."""
    labels = sorted(set(truth))
    per_class = f1_score(truth, predicted, labels=labels, average=None, zero_division=0)
    return float(per_class.mean()), dict(zip(labels, map(float, per_class), strict=True))


def fit_and_score(training: pd.DataFrame, held: pd.DataFrame, features: list[str],
                  settings: ClassifierSettings) -> dict:
    model = make_booster(settings).fit(training[features], training["label"])
    score, per_class = macro_f1(held["label"], model.predict(held[features]))
    return {"features": len(features), "macro_f1": score, "f1": per_class}


def ablations(frame: pd.DataFrame, schema: Schema, held_out: list[str], flagged: list[str],
              settings: ClassifierSettings | None = None) -> dict:
    """Every run: its name, the features removed, macro-F1 and the drop."""
    settings = settings or ClassifierSettings()
    training, held = split_by_source(frame, held_out)
    names = schema.feature_names
    watched = sorted(schema.watched())
    plans = [("all features", [])]
    if watched:
        plans.append(("without the watched features", watched))
    plans += [(f"without {name}", [name]) for name in flagged[:MAX_SINGLE_ABLATIONS]]
    runs = []
    for title, removed in plans:
        kept = [name for name in names if name not in removed]
        runs.append({"name": title, "removed": removed,
                     **fit_and_score(training, held, kept, settings)})
    for run in runs:
        run["drop"] = runs[0]["macro_f1"] - run["macro_f1"]
    return {"training_files": sorted(training["source"].unique()),
            "held_out_files": sorted(held_out),
            "not_ablated": flagged[MAX_SINGLE_ABLATIONS:], "runs": runs}
