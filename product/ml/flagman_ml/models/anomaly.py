"""Isolation Forest, trained on normal traffic only.

An Isolation Forest cuts the data at random again and again; an unusual
flow ends up alone after few cuts. Trained on normal flows only, it scores
how unlike normal traffic a flow is, whatever the attack, so it can flag
attacks that no dataset labelled (see openset.py).

The score here is "higher means more unusual": the opposite sign of
scikit-learn's ``score_samples``.

Example::

    forest = fit_anomaly(anomaly_matrix(normal_inputs, schema))
    anomaly_scores(forest, anomaly_matrix(inputs, schema))
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


@dataclass(frozen=True)
class AnomalySettings:
    trees: int = 200
    flows_per_tree: int = 256  # scikit-learn's default sample size
    seed: int = 0
    threads: int = 2


def fit_anomaly(normal: pd.DataFrame, settings: AnomalySettings = AnomalySettings()):
    """Fit the forest on the matrix of normal flows (data.anomaly_matrix)."""
    if normal.empty:
        raise ValueError("the Isolation Forest needs normal flows to learn from")
    forest = IsolationForest(
        n_estimators=settings.trees,
        max_samples=min(settings.flows_per_tree, len(normal)),
        random_state=settings.seed,
        n_jobs=settings.threads,
    )
    return forest.fit(normal)


def anomaly_scores(forest: IsolationForest, matrix: pd.DataFrame) -> np.ndarray:
    """How unusual each flow is for normal traffic (higher = more unusual)."""
    return -forest.score_samples(matrix)
