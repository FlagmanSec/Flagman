import numpy as np
import pandas as pd

from flagman_ml.audit.ablation import ablations, macro_f1
from flagman_ml.models.classifier import ClassifierSettings
from flagman_ml.synthetic import synthetic_flows

FAST = ClassifierSettings(trees=30, min_flows_per_leaf=5)


def only_the_fingerprint_tells_the_classes_apart():
    """Normal-looking flows, half of them labelled scan at random; only the
    planted first_response_ms (a watched feature) gives the label away."""
    frame, schema = synthetic_flows({"normal": 800}, seed=3)
    rng = np.random.default_rng(3)
    frame["label"] = np.where(rng.random(800) < 0.5, "scan", "normal")
    frame["first_response_ms"] = np.where(frame["label"] == "scan", 7.0, 1007.0)
    frame["source"] = np.where(frame.index < 600, "day1.parquet", "day2.parquet")
    return frame, schema


def test_removing_the_feature_a_model_leans_on_shows_a_large_drop():
    frame, schema = only_the_fingerprint_tells_the_classes_apart()
    result = ablations(frame, schema, ["day2.parquet"], ["first_response_ms"], FAST)
    runs = {run["name"]: run for run in result["runs"]}
    assert runs["all features"]["macro_f1"] == 1.0
    assert runs["without first_response_ms"]["drop"] > 0.3  # back to guessing
    assert runs["without the watched features"]["drop"] > 0.3
    assert result["training_files"] == ["day1.parquet"]


def test_macro_f1_counts_every_class_the_same():
    truth = pd.Series(["normal"] * 98 + ["scan"] * 2)
    predicted = ["normal"] * 100  # every scan missed
    score, per_class = macro_f1(truth, predicted)
    assert per_class["scan"] == 0.0
    assert np.isclose(score, (per_class["normal"] + 0.0) / 2)
