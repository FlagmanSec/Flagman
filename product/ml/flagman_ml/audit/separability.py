"""How well does each feature, alone, separate each class from the rest?

For every feature and every class: the area under the ROC curve (AUC) of
that one feature used as a score for "this flow is of this class".

- 0.5: the feature alone says nothing about the class;
- 1.0 or 0.0: one threshold on this one feature separates the class
  perfectly (0.0: the class has the low values).

**Separability** is max(AUC, 1 − AUC), so both directions count.

A feature that alone nearly separates a class (separability at or above
``LIMIT``) is a warning sign. Either the attack really is that simple (a
scan sends one packet and gets no answer), or the feature describes the
testbed instead of the attack: the lab's link speed, a tool's fixed
timing. Flagged features on the schema's watch list (``schema.watched()``)
are the first to suspect. The audit only points; a person decides, with
the ablations (ablation.py) as evidence.

How it is computed:

- numbers: an undefined value counts as −1, below every real value. The
  AUC comes from ranks (the Mann-Whitney statistic):
  AUC = (R − n₁(n₁ + 1)/2) / (n₁ n₀), where R is the sum of the ranks of
  the class's n₁ flows among all flows, n₀ the other flows, and tied
  values share their average rank (a tie counts one half);
- categories: each value is replaced by the share of the class among the
  flows with that value. That share is computed on the same flows, so for
  a category with many rare values the result is too high.

Example::

    table = separability(frame, schema)
    table[table["flagged"]]   # feature, class, auc, separability, watched
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

from flagman_ml.flows import Schema
from flagman_ml.models.data import MISSING

LIMIT = 0.99


def auc_from_ranks(ranks: np.ndarray, positive: np.ndarray) -> float:
    """The AUC of a score whose ranks are given, for the flows marked positive."""
    n1 = int(positive.sum())
    n0 = len(positive) - n1
    if n1 == 0 or n0 == 0:
        return float("nan")
    return float((ranks[positive].sum() - n1 * (n1 + 1) / 2) / (n1 * n0))


def class_share(values: pd.Series, positive: np.ndarray) -> np.ndarray:
    """Each flow's category value replaced by the share of the class among
    the flows with that value (an empty value is a value of its own)."""
    keys = values.astype(str).to_numpy()  # an empty value becomes "nan"
    return pd.Series(positive.astype(float)).groupby(keys).transform("mean").to_numpy()


def separability(frame: pd.DataFrame, schema: Schema, limit: float = LIMIT) -> pd.DataFrame:
    """One row per (feature, class): auc, separability, watched, flagged."""
    labels = frame["label"].to_numpy()
    classes = sorted(set(labels))
    watched = schema.watched()
    rows = []
    for feature in schema.features:
        column = frame[feature.name]
        if feature.kind != "category":
            ranks = stats.rankdata(column.astype(float).fillna(MISSING).to_numpy())
        for name in classes:
            positive = labels == name
            if feature.kind == "category":
                ranks = stats.rankdata(class_share(column, positive))
            auc = auc_from_ranks(ranks, positive)
            rows.append({"feature": feature.name, "class": name, "auc": auc,
                         "separability": max(auc, 1 - auc), "watched": feature.name in watched})
    table = pd.DataFrame(rows)
    table["flagged"] = table["separability"] >= limit
    return table


def flagged_features(table: pd.DataFrame) -> list[str]:
    """The flagged features, most separating first, each once."""
    flagged = table[table["flagged"]].sort_values(["separability", "feature"],
                                                  ascending=[False, True])
    return list(dict.fromkeys(flagged["feature"]))
