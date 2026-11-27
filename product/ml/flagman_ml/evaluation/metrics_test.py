import math

import numpy as np
import pandas as pd
import pytest

from flagman_ml.evaluation import metrics as m


def test_a_rate_comes_with_its_exact_interval():
    result = m.rate(5, 100)
    assert result["rate"] == 0.05
    assert result["low"] < 0.05 < result["high"]
    assert m.rate(0, 0)["rate"] is None


def test_detection_at_a_false_alarm_rate_on_numbers_checked_by_hand():
    normal = np.arange(1, 1001)  # 1000 normal flows scoring 1 .. 1000
    attack = np.array([999.5, 995.5, 990.5, 500.0])
    # 0.1%: one normal flow may pass, so the threshold is 999 and only 999.5 is caught.
    assert m.detection_at_fpr(normal, attack, 0.001) == {
        "fpr_target": 0.001, "normal_flows": 1000, "enough_normal_flows": True,
        "fpr": 0.001, "detection": 0.25}
    # 1%: ten may pass (threshold 990): three of the four attacks are caught.
    assert m.detection_at_fpr(normal, attack, 0.01)["detection"] == 0.75


def test_too_few_normal_flows_is_said():
    result = m.detection_at_fpr(np.arange(100), np.array([1000.0]), 0.001)
    assert not result["enough_normal_flows"]
    assert result["fpr"] == 0  # with 100 flows, 0.1% allows none


def test_the_two_score_rule_gives_half_the_rate_to_each_score():
    rng = np.random.default_rng(0)
    normal = (rng.normal(size=4000), rng.normal(size=4000))
    attack = (rng.normal(loc=3, size=500), rng.normal(size=500))
    result = m.detection_at_fpr_two_scores(normal, attack, 0.01)
    assert result["fpr"] <= 0.01
    assert 0.5 < result["detection"] < 1


def test_precision_follows_bayes_rule():
    # 90% detection, 1% false alarms, 1 flow in 1000 an attack:
    # 0.0009 true alerts for 0.00999 false ones, so about 8% of alerts are real.
    assert math.isclose(m.precision_at_base_rate(0.9, 0.01, 0.001), 0.0009 / (0.0009 + 0.00999))
    assert m.precision_at_base_rate(0.0, 0.0, 0.01) is None


def test_calibration_error_by_hand():
    # Two bins used: 0.9 (right 1 time in 2) and 0.6 (right 2 times in 2).
    confidence = np.array([0.9, 0.9, 0.6, 0.6])
    correct = np.array([True, False, True, True])
    result = m.calibration_error(confidence, correct, bins=10)
    assert math.isclose(result["ece"], 0.5 * abs(0.5 - 0.9) + 0.5 * abs(1.0 - 0.6))
    assert [b["flows"] for b in result["bins"]] == [2, 2]


def test_a_probability_on_a_bin_edge_goes_to_the_lower_bin():
    result = m.calibration_error(np.array([0.5, 0.0, 1.0]), np.array([True, True, True]), bins=2)
    assert [(b["low"], b["high"], b["flows"]) for b in result["bins"]] == [(0.0, 0.5, 2),
                                                                            (0.5, 1.0, 1)]


def test_macro_f1_counts_unknown_suspicious_as_wrong():
    truth = pd.Series(["scan", "scan", "normal", "normal"])
    decided = pd.Series(["scan", "unknown_suspicious", "normal", "normal"])
    result = m.per_class_f1(truth, decided)
    assert result["f1"]["normal"] == 1.0
    assert math.isclose(result["f1"]["scan"], 2 / 3)  # precision 1, recall 1/2


def test_detection_by_class_counts_alerts_and_names():
    truth = pd.Series(["dos", "dos", "dos", "normal"])
    decided = pd.Series(["dos", "scan", "normal", "normal"])
    assert m.detection_by_class(truth, decided) == {"dos": {
        "flows": 3, "alerted": pytest.approx(2 / 3), "named": pytest.approx(1 / 3),
        "decisions": {"dos": 1, "scan": 1, "normal": 1}}}


def test_alerts_per_day_uses_each_file_time_span():
    frame = pd.DataFrame({"source": ["a", "a", "b"], "flow_start_ms": [0, 0, 0],
                          "flow_end_ms": [m.DAY_MS // 2, 10, m.DAY_MS * 2]})
    result = m.alerts_per_day(frame, np.array([True, True, True]))
    assert result["a"] == {"alerts": 2, "days": 0.5, "per_day": 4.0}
    assert result["b"]["per_day"] == 0.5
