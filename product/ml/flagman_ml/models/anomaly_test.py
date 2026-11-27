import pandas as pd
import pytest

from flagman_ml.models.anomaly import AnomalySettings, anomaly_scores, fit_anomaly
from flagman_ml.models.data import anomaly_matrix
from flagman_ml.synthetic import synthetic_flows

FAST = AnomalySettings(trees=50)


def matrix(counts, seed):
    frame, schema = synthetic_flows(counts, seed=seed)
    return anomaly_matrix(frame[schema.feature_names], schema)


def test_attacks_look_more_unusual_than_normal_traffic():
    forest = fit_anomaly(matrix({"normal": 400}, seed=1), FAST)
    normal = anomaly_scores(forest, matrix({"normal": 200}, seed=2))
    scans = anomaly_scores(forest, matrix({"scan": 200}, seed=3))
    floods = anomaly_scores(forest, matrix({"dos": 200}, seed=4))
    assert scans.mean() > normal.mean()
    assert floods.mean() > normal.mean()


def test_the_forest_needs_normal_flows():
    with pytest.raises(ValueError, match="normal flows"):
        fit_anomaly(pd.DataFrame(), FAST)
