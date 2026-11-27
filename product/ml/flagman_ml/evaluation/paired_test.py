import math

import numpy as np

from flagman_ml.evaluation.paired import mcnemar, mean_std, wilcoxon


def test_mean_and_sample_standard_deviation():
    assert mean_std([1.0, 2.0, 3.0]) == {"mean": 2.0, "std": 1.0, "runs": 3}
    assert mean_std([5.0])["std"] is None
    assert mean_std([None])["runs"] == 0


def test_with_five_pairs_the_smallest_p_value_is_one_sixteenth():
    result = wilcoxon([0.9, 0.8, 0.85, 0.95, 0.7], [0.5, 0.4, 0.45, 0.6, 0.3])
    assert result["pairs"] == 5
    assert math.isclose(result["p_value"], 2 / 2**5)


def test_no_difference_gives_p_one():
    assert wilcoxon([0.5, 0.6], [0.5, 0.6])["p_value"] == 1.0


def test_mcnemar_counts_only_the_flows_where_they_disagree():
    first = np.array([True] * 10 + [True] * 8 + [False] * 2)
    second = np.array([True] * 10 + [False] * 8 + [True] * 2)
    result = mcnemar(first, second)
    assert (result["only_first_right"], result["only_second_right"]) == (8, 2)
    assert math.isclose(result["p_value"], 0.109375)  # exact binomial, 10 discordant flows
