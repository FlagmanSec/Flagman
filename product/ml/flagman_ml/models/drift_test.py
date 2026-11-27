import numpy as np
import pandas as pd

from flagman_ml.models.drift import alert_rate, drift_report, psi, score_shift
from flagman_ml.synthetic import synthetic_flows


def test_psi_is_zero_for_the_same_mix_and_grows_when_it_moves():
    rng = np.random.default_rng(0)
    reference = pd.Series(rng.normal(size=5000))
    assert psi(reference, reference) == 0
    assert psi(reference, pd.Series(rng.normal(size=5000))) < 0.05
    assert psi(reference, pd.Series(rng.normal(loc=1, size=5000))) > 0.2


def test_psi_counts_empty_values_and_categories():
    reference = pd.Series([1.0, 2.0, np.nan, np.nan])
    assert psi(reference, pd.Series([np.nan] * 4)) > 0.2
    assert psi(pd.Series([np.nan] * 4), pd.Series([np.nan] * 4)) == 0  # no number at all
    colours = pd.Series(pd.Categorical(["a", "a", "b", "b"]))
    assert psi(colours, pd.Series(pd.Categorical(["b", "b", "b", "b"]))) > 0.2


def test_the_alert_rate_is_compared_with_the_budget():
    calm = alert_rate(np.array([True] * 10 + [False] * 990), alpha=0.01)
    assert calm["rate"] == 0.01 and calm["p_value"] > 0.4
    busy = alert_rate(np.array([True] * 40 + [False] * 960), alpha=0.01)
    assert busy["p_value"] < 1e-6


def test_score_shift_needs_scores_on_both_sides():
    assert score_shift(np.array([]), np.array([1.0]))["p_value"] == 1.0


def test_the_report_flags_only_what_moved():
    reference, schema = synthetic_flows({"normal": 600}, seed=1)
    same, _ = synthetic_flows({"normal": 600}, seed=2)
    names = schema.feature_names
    rng = np.random.default_rng(3)
    scores = rng.normal(size=600)
    quiet = drift_report(schema, reference[names], same[names], scores, rng.normal(size=600),
                         np.zeros(600, dtype=bool), alpha=0.01)
    assert quiet["flags"] == []

    moved = same[names].copy()
    moved["duration_ms"] = moved["duration_ms"] * 10  # every flow lasts ten times longer
    loud = drift_report(schema, reference[names], moved, scores, rng.normal(loc=2, size=600),
                        np.ones(600, dtype=bool), alpha=0.01)
    assert len(loud["flags"]) == 3
    assert "duration_ms" in loud["flags"][2]
