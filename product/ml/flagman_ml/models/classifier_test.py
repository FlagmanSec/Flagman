import numpy as np
import pandas as pd
import pytest

from flagman_ml.models.classifier import (
    ClassifierSettings,
    fit_classifier,
    fit_temperature,
    probabilities,
)
from flagman_ml.synthetic import synthetic_flows

FAST = ClassifierSettings(trees=30, min_flows_per_leaf=5)


def labelled(counts, seed):
    frame, schema = synthetic_flows(counts, seed=seed)
    return frame[schema.feature_names], frame["label"]


def test_probabilities_have_one_column_per_class_and_sum_to_one():
    train_x, train_y = labelled({"normal": 200, "scan": 60, "brute_force": 60}, seed=1)
    cal_x, cal_y = labelled({"normal": 100, "scan": 30, "brute_force": 30}, seed=2)
    model = fit_classifier(train_x, train_y, cal_x, cal_y, FAST)
    proba = probabilities(model, cal_x)
    assert list(proba.columns) == ["brute_force", "normal", "scan"]
    assert np.allclose(proba.sum(axis=1), 1)
    assert (proba.idxmax(axis=1) == cal_y).mean() > 0.95  # easy made-up classes


def test_the_temperature_never_changes_the_top_class():
    train_x, train_y = labelled({"normal": 200, "scan": 60, "brute_force": 60}, seed=1)
    cal_x, cal_y = labelled({"normal": 100, "scan": 30, "brute_force": 30}, seed=2)
    model = fit_classifier(train_x, train_y, cal_x, cal_y, FAST)
    calibrated = probabilities(model, cal_x)
    raw = probabilities(model, cal_x, calibrated=False)
    assert (calibrated.idxmax(axis=1) == raw.idxmax(axis=1)).all()


def test_the_temperature_softens_a_model_that_is_too_sure():
    # Raw scores that are right only 70% of the time but very confident:
    # the best temperature is above 1 (less sure).
    rng = np.random.default_rng(0)
    truth = rng.integers(0, 2, 1000)
    guess = np.where(rng.random(1000) < 0.7, truth, 1 - truth)
    scores = np.zeros((1000, 2))
    scores[np.arange(1000), guess] = 8.0  # about 0.9997 for the guessed class
    assert fit_temperature(scores, truth) > 1


def test_two_classes_work_too():
    train_x, train_y = labelled({"normal": 100, "scan": 50}, seed=1)
    cal_x, cal_y = labelled({"normal": 50, "scan": 20}, seed=2)
    model = fit_classifier(train_x, train_y, cal_x, cal_y, FAST)
    assert np.allclose(probabilities(model, cal_x).sum(axis=1), 1)


def test_calibration_classes_must_have_been_trained_on():
    train_x, train_y = labelled({"normal": 100, "scan": 50}, seed=1)
    cal_x, cal_y = labelled({"normal": 50, "brute_force": 20}, seed=2)
    with pytest.raises(ValueError, match="brute_force"):
        fit_classifier(train_x, train_y, cal_x, cal_y, FAST)


def test_training_needs_two_classes():
    train_x, train_y = labelled({"normal": 100}, seed=1)
    with pytest.raises(ValueError, match="two classes"):
        fit_classifier(train_x, train_y, train_x, train_y, FAST)


def test_the_same_data_and_settings_give_the_same_model():
    train_x, train_y = labelled({"normal": 200, "scan": 60}, seed=1)
    cal_x, cal_y = labelled({"normal": 100, "scan": 30}, seed=2)
    first = probabilities(fit_classifier(train_x, train_y, cal_x, cal_y, FAST), cal_x)
    again = probabilities(fit_classifier(train_x, train_y, cal_x, cal_y, FAST), cal_x)
    pd.testing.assert_frame_equal(first, again)
