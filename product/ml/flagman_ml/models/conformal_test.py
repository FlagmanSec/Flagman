import math

import numpy as np
import pytest

from flagman_ml.models.conformal import alerts, smallest_calibration_set, threshold


def test_the_threshold_is_the_kth_smallest_calibration_score():
    scores = np.arange(1, 20)  # 19 calibration flows scoring 1, 2, ..., 19
    # alpha = 0.1: k = ceil(20 * 0.9) = 18, so the 18th smallest score.
    assert threshold(scores, 0.1) == 18
    # alpha = 0.25: k = ceil(20 * 0.75) = 15.
    assert threshold(scores, 0.25) == 15


def test_it_is_the_k_over_n_empirical_quantile_of_the_paper():
    # The usual empirical quantile (the inverse of the empirical distribution).
    # NumPy's method="higher" places positions from 0 to n-1 and lands one
    # rank higher: slightly more cautious, not the paper's definition.
    rng = np.random.default_rng(3)
    for n, alpha in ((50, 0.1), (999, 0.001), (5000, 0.01)):
        scores = rng.exponential(size=n)
        level = math.ceil((n + 1) * (1 - alpha)) / n
        assert threshold(scores, alpha) == np.quantile(scores, level, method="inverted_cdf")


def test_too_few_calibration_flows_means_no_alert():
    scores = np.arange(1, 20)  # 19 flows cannot support alpha = 0.01
    assert threshold(scores, 0.01) == math.inf
    assert not alerts([1e9], threshold(scores, 0.01)).any()


def test_the_smallest_calibration_set_for_a_budget():
    assert smallest_calibration_set(0.1) == 9
    assert smallest_calibration_set(0.001) == 999
    for alpha in (0.1, 0.05, 0.01, 0.001):
        n = smallest_calibration_set(alpha)
        assert threshold(np.arange(n), alpha) < math.inf
        assert threshold(np.arange(n - 1), alpha) == math.inf


def test_on_exchangeable_normal_traffic_the_false_alarm_rate_stays_within_the_budget():
    # Many repetitions: each draws a calibration set and new flows from the
    # same distribution. On average the share of new flows above the
    # threshold is at most alpha (here 0.05), and close to it.
    rng = np.random.default_rng(7)
    rates = []
    for _ in range(400):
        limit = threshold(rng.normal(size=199), 0.05)
        rates.append(alerts(rng.normal(size=1000), limit).mean())
    assert 0.045 < np.mean(rates) <= 0.05 + 0.002  # 0.002: room for chance


def test_when_traffic_changes_the_promise_is_gone():
    rng = np.random.default_rng(8)
    limit = threshold(rng.normal(size=999), 0.01)
    shifted = rng.normal(loc=1.0, size=10_000)  # the network changed
    assert alerts(shifted, limit).mean() > 0.05  # far above the 1% budget


@pytest.mark.parametrize("alpha", [0, 1, -0.1, 1.5])
def test_alpha_must_be_a_probability(alpha):
    with pytest.raises(ValueError):
        threshold([1.0, 2.0], alpha)
