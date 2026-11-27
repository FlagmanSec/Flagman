import numpy as np
import pandas as pd

from flagman_ml.models.openset import UNKNOWN, Thresholds, decide

LIMITS = Thresholds(alpha=0.01, suspicion=0.5, anomaly=0.6, min_confidence=0.7)


def one_flow(normal, scan, anomaly):
    proba = pd.DataFrame({"normal": [normal], "scan": [scan]})
    return decide(proba, np.array([anomaly]), LIMITS).iloc[0]


def test_no_score_above_its_threshold_is_normal():
    assert one_flow(normal=0.9, scan=0.1, anomaly=0.3)["decision"] == "normal"


def test_a_sure_attack_gets_its_class():
    row = one_flow(normal=0.1, scan=0.9, anomaly=0.3)
    assert row["decision"] == "scan"
    assert row["suspicious"] and not row["anomalous"]


def test_an_unusual_flow_the_classifier_calls_normal_is_unknown_suspicious():
    row = one_flow(normal=0.9, scan=0.1, anomaly=0.8)
    assert row["decision"] == UNKNOWN
    assert row["anomalous"] and not row["suspicious"]


def test_an_alert_with_low_confidence_is_unknown_suspicious():
    # Suspicious (1 - 0.4 > 0.5) but the top class is only 0.6 sure.
    assert one_flow(normal=0.4, scan=0.6, anomaly=0.3)["decision"] == UNKNOWN


def test_infinite_thresholds_never_alert():
    limits = Thresholds(alpha=0.01, suspicion=np.inf, anomaly=np.inf, min_confidence=0.5)
    proba = pd.DataFrame({"normal": [0.0], "scan": [1.0]})
    assert decide(proba, np.array([99.0]), limits).iloc[0]["decision"] == "normal"
