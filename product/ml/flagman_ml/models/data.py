"""Turn labelled flows into what the models need.

- ``scored``: keeps the flows that may train or score a model (not
  ``background`` or ``unlabelled``, and by default no labelling conflict).
- ``split_by_source``: training and calibration sets by feature file (a day
  or a session), never at random. Flows of one capture are related (the
  same machines, the same minutes), so a random split would put near-copies
  on both sides and make the models look better than they are.
- ``anomaly_matrix``: numbers only, for the Isolation Forest. Each category
  value gets its own 0/1 column; an undefined real value becomes -1, which
  stands apart because every real feature is 0 or more.
"""

from __future__ import annotations

import pandas as pd

from flagman_ml.flows import Schema
from flagman_ml.labels.classes import NOT_SCORED

MISSING = -1.0


def scored(frame: pd.DataFrame, drop_conflicts: bool = True) -> pd.DataFrame:
    """Flows whose label may train or score a model."""
    keep = ~frame["label"].isin(NOT_SCORED)
    if drop_conflicts and "conflict" in frame:
        keep &= ~frame["conflict"].astype(bool)
    return frame[keep].reset_index(drop=True)


def split_by_source(
    frame: pd.DataFrame, calibration: list[str]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(training, calibration): the calibration set is the named feature files."""
    sources = set(frame["source"])
    unknown = sorted(set(calibration) - sources)
    if unknown:
        raise ValueError(f"no flows from {unknown} (known files: {sorted(sources)})")
    on_calibration = frame["source"].isin(calibration)
    training, held = frame[~on_calibration], frame[on_calibration]
    if training.empty or held.empty:
        raise ValueError("both the training and the calibration sets need flows")
    return training.reset_index(drop=True), held.reset_index(drop=True)


def anomaly_matrix(inputs: pd.DataFrame, schema: Schema) -> pd.DataFrame:
    """The features as numbers only, with the same columns for every file."""
    columns = []
    for feature in schema.features:
        values = inputs[feature.name]
        if feature.kind == "category":
            columns.append(pd.get_dummies(values, prefix=feature.name, prefix_sep="=",
                                          dtype=float))
        else:
            columns.append(values.astype(float).fillna(MISSING).rename(feature.name))
    return pd.concat(columns, axis=1)
