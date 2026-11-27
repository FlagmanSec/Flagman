"""The classifier: LightGBM, then calibrated probabilities.

LightGBM (gradient-boosted decision trees) learns which class a flow
belongs to from its 37 features; it handles categories and empty values
itself. Its probabilities are often too sure (or not sure enough): among
flows given 0.9, maybe seven in ten belong to that class. A second step,
**calibration**, fits a correction on flows kept aside (the calibration
files), so that "0.9" means about nine in ten on traffic like theirs.

The correction is **temperature scaling**. LightGBM gives one raw score
per class, and its probabilities are the softmax of those scores. Here the
scores are divided by one number, the temperature T, before the softmax:
T above 1 makes the model less sure, T below 1 more sure. T is the value
that makes the calibration flows' true classes most likely (the lowest
negative log-likelihood). One number for every class means that:

- there is one number to fit, not one or two per class, and it can be set
  when the calibration files do not hold every class (with splits by day,
  a day holds some attacks only);
- it never changes which class comes first, only how sure the model is.

Corrections per class (Platt scaling, isotonic regression) can fix more,
but need every class in the calibration files: scikit-learn 1.9.1's
CalibratedClassifierCV takes its classes from the calibration labels, and
failed on the lab files, whose calibration file has no scan. They are not
used.

Source: Guo, Pleiss, Sun and Weinberger, "On Calibration of Modern Neural
Networks", ICML 2017, PMLR 70:1321-1330, section 4.2: "Temperature
scaling, the simplest extension of Platt scaling, uses a single scalar
parameter T > 0 for all classes", "T is optimized with respect to NLL on
the validation set", and it "does not affect the model's accuracy".

Example::

    model = fit_classifier(train_inputs, train_labels, cal_inputs, cal_labels)
    model.temperature                # 1.3: the raw model was too sure
    probabilities(model, inputs)     # one column per class, rows sum to 1
"""

from __future__ import annotations

from dataclasses import dataclass

import lightgbm
import numpy as np
import pandas as pd
from scipy import optimize, special

# The range searched for the temperature. A temperature at a bound means
# the calibration flows could not set it (too few, or all too easy).
TEMPERATURES = (0.1, 10.0)


@dataclass(frozen=True)
class ClassifierSettings:
    trees: int = 200
    learning_rate: float = 0.05
    leaves: int = 31
    min_flows_per_leaf: int = 20
    seed: int = 0
    threads: int = 2  # the runbook's VM has 2 to 4 virtual CPUs


class CalibratedClassifier:
    """LightGBM and its temperature."""

    def __init__(self, booster: lightgbm.LGBMClassifier, temperature: float):
        self.booster = booster
        self.temperature = temperature
        self.classes_ = np.asarray(booster.classes_)

    def predict_proba(self, inputs: pd.DataFrame, calibrated: bool = True) -> np.ndarray:
        """Probabilities, calibrated by default (``calibrated=False``: LightGBM's own)."""
        scores = raw_scores(self.booster, inputs)
        return special.softmax(scores / (self.temperature if calibrated else 1.0), axis=1)


def fit_classifier(
    train_inputs: pd.DataFrame, train_labels: pd.Series,
    calibration_inputs: pd.DataFrame, calibration_labels: pd.Series,
    settings: ClassifierSettings = ClassifierSettings(),
) -> CalibratedClassifier:
    """Train LightGBM on the training flows, set its temperature on the others."""
    if train_labels.nunique() < 2:
        raise ValueError("training needs at least two classes (normal and an attack)")
    missing = sorted(set(calibration_labels) - set(train_labels))
    if missing:
        raise ValueError(f"classes in the calibration set but not in training: {missing}")
    booster = make_booster(settings).fit(train_inputs, train_labels)
    truth = pd.Index(booster.classes_).get_indexer(calibration_labels)
    temperature = fit_temperature(raw_scores(booster, calibration_inputs), truth)
    return CalibratedClassifier(booster, temperature)


def make_booster(settings: ClassifierSettings = ClassifierSettings()) -> lightgbm.LGBMClassifier:
    """The LightGBM classifier, before training (the audit's ablations use it too)."""
    return lightgbm.LGBMClassifier(
        n_estimators=settings.trees,
        learning_rate=settings.learning_rate,
        num_leaves=settings.leaves,
        min_child_samples=settings.min_flows_per_leaf,
        random_state=settings.seed,
        n_jobs=settings.threads,
        deterministic=True,  # the same data and settings give the same model
        force_row_wise=True,
        verbose=-1,
    )


def raw_scores(booster: lightgbm.LGBMClassifier, inputs: pd.DataFrame) -> np.ndarray:
    """One raw score per class. With two classes LightGBM gives only the
    second class's score; the first one's is then 0 (same probabilities)."""
    raw = np.asarray(booster.predict(inputs, raw_score=True), dtype=float)
    return np.column_stack([np.zeros(len(raw)), raw]) if raw.ndim == 1 else raw


def fit_temperature(scores: np.ndarray, truth: np.ndarray) -> float:
    """The temperature with the lowest negative log-likelihood of the true classes."""
    rows = np.arange(len(scores))

    def nll(log_t: float) -> float:
        scaled = scores / np.exp(log_t)
        return float(np.mean(special.logsumexp(scaled, axis=1) - scaled[rows, truth]))

    best = optimize.minimize_scalar(nll, bounds=np.log(TEMPERATURES), method="bounded",
                                    options={"xatol": 1e-4})
    return float(np.exp(best.x))


def probabilities(model: CalibratedClassifier, inputs: pd.DataFrame,
                  calibrated: bool = True) -> pd.DataFrame:
    """Probability of each class, one column per class."""
    return pd.DataFrame(model.predict_proba(inputs, calibrated), columns=list(model.classes_),
                        index=inputs.index)
