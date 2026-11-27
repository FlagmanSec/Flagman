import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import roc_auc_score

from flagman_ml.audit.separability import auc_from_ranks, flagged_features, separability
from flagman_ml.synthetic import synthetic_flows


def test_the_rank_formula_gives_the_usual_auc_even_with_ties():
    rng = np.random.default_rng(0)
    values = rng.integers(0, 5, 300).astype(float)  # many ties
    positive = rng.random(300) < 0.3
    assert np.isclose(auc_from_ranks(stats.rankdata(values), positive),
                      roc_auc_score(positive, values))


def test_a_planted_testbed_fingerprint_is_flagged_and_marked_watched():
    frame, schema = synthetic_flows({"normal": 200, "brute_force": 200}, seed=1,
                                    shortcut="first_response_ms")
    table = separability(frame, schema).set_index(["feature", "class"])
    planted = table.loc[("first_response_ms", "brute_force")]
    assert planted["separability"] == 1.0 and planted["flagged"] and planted["watched"]
    # A feature drawn the same way for every class says nothing.
    assert abs(table.loc[("fin_rev", "brute_force"), "auc"] - 0.5) < 0.1


def test_categories_count_through_the_share_of_the_class_per_value():
    frame, schema = synthetic_flows({"normal": 100, "scan": 100}, seed=2)
    table = separability(frame, schema).set_index(["feature", "class"])
    # Only the made-up scans are half-open: tcp_outcome alone separates them.
    assert table.loc[("tcp_outcome", "scan"), "separability"] == 1.0
    assert table.loc[("protocol", "scan"), "separability"] == 0.5  # always tcp


def test_flagged_features_come_once_each_most_separating_first():
    table = pd.DataFrame({
        "feature": ["a", "b", "b", "c"], "class": ["x", "x", "y", "x"],
        "separability": [0.995, 1.0, 0.999, 0.9], "flagged": [True, True, True, False]})
    assert flagged_features(table) == ["b", "a"]
