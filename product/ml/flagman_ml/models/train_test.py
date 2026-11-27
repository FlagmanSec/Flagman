import math

import numpy as np
import pandas as pd
import pytest

from flagman_ml.flows import Flows
from flagman_ml.models.anomaly import AnomalySettings
from flagman_ml.models.bundle import schema_record
from flagman_ml.models.classifier import ClassifierSettings
from flagman_ml.models.openset import UNKNOWN
from flagman_ml.models.predict import predict
from flagman_ml.models.train import TrainSettings, train
from flagman_ml.synthetic import synthetic_flows

FAST = TrainSettings(alpha=0.05, classifier=ClassifierSettings(trees=30, min_flows_per_leaf=5),
                     anomaly=AnomalySettings(trees=50))
TABLE = {"idle_timeout_ms": 60000}  # any flow table settings, the same everywhere


def two_days():
    day1, schema = synthetic_flows({"normal": 400, "scan": 100, "brute_force": 100}, seed=1,
                                   source="day1.parquet")
    day2, _ = synthetic_flows({"normal": 400, "scan": 50, "brute_force": 50}, seed=2,
                              source="day2.parquet")
    return pd.concat([day1, day2], ignore_index=True), schema


def decisions(models, schema, counts, seed):
    frame, _ = synthetic_flows(counts, seed=seed, source="day3.parquet")
    metadata = {"schema": schema_record(schema), "flow_table": TABLE}
    return predict(models, metadata, Flows(frame, schema, TABLE))["decision"]


def test_training_reports_what_it_trained_on():
    frame, schema = two_days()
    models, report = train(frame, schema, ["day2.parquet"], FAST)
    assert report["classes"] == ["brute_force", "normal", "scan"]
    assert report["files"] == {"training": ["day1.parquet"], "calibration": ["day2.parquet"]}
    assert report["flows"]["calibration"] == {"brute_force": 50, "normal": 400, "scan": 50}
    assert report["normal_calibration_flows"] == 400
    # The made-up classes are so easy that every calibration flow is right
    # and sure: the temperature goes as low as the search allows, and says so.
    assert len(report["warnings"]) == 1 and "temperature" in report["warnings"][0]
    assert math.isfinite(models["thresholds"].suspicion)
    assert math.isfinite(models["thresholds"].anomaly)


def test_new_normal_traffic_like_the_calibration_traffic_stays_near_the_budget():
    frame, schema = two_days()
    models, _ = train(frame, schema, ["day2.parquet"], FAST)
    alerts = decisions(models, schema, {"normal": 2000}, seed=3) != "normal"
    # The budget is 5% on average over calibration sets; one set of 400
    # flows can land a little above it, so allow some room.
    assert alerts.mean() < 0.05 + 0.02


def test_known_attacks_get_their_class():
    frame, schema = two_days()
    models, _ = train(frame, schema, ["day2.parquet"], FAST)
    found = decisions(models, schema, {"scan": 200, "brute_force": 200}, seed=4)
    assert (found.iloc[:200] == "scan").mean() > 0.9
    assert (found.iloc[200:] == "brute_force").mean() > 0.9


def test_an_attack_never_seen_in_training_still_raises_alerts():
    frame, schema = two_days()
    models, _ = train(frame, schema, ["day2.parquet"], FAST)
    found = decisions(models, schema, {"dos": 200}, seed=5)
    assert (found != "normal").all()
    # The class it gets can be wrong: here the classifier calls these floods
    # scans, and is sure of it, so the open-set rule does not say "unknown".
    # Leave-one-attack-type-out evaluation measures how often this happens.
    assert set(found) <= {"scan", "brute_force", UNKNOWN}


def test_a_flow_unlike_normal_traffic_that_the_classifier_calls_normal_is_unknown():
    frame, schema = two_days()
    models, _ = train(frame, schema, ["day2.parquet"], FAST)
    odd, _ = synthetic_flows({"normal": 200}, seed=6)
    for name in ("payload_bytes_fwd", "payload_mean_fwd", "payload_max_fwd", "payload_std_fwd"):
        odd[name] = odd[name] * 1000  # normal-looking flows, but huge uploads
    metadata = {"schema": schema_record(schema), "flow_table": TABLE}
    result = predict(models, metadata, Flows(odd, schema, TABLE))
    # The classifier never saw uploads like these and calls them normal; the
    # forest finds them unlike normal traffic: "unknown suspicious".
    assert (result["top_class"] == "normal").all()
    assert result["anomalous"].mean() > 0.9
    assert (result.loc[result["anomalous"], "decision"] == UNKNOWN).all()


def test_too_few_normal_calibration_flows_means_no_alert_and_a_warning():
    frame, schema = two_days()
    keep = (frame["source"] == "day1.parquet") | (frame["label"] != "normal") | (frame["row"] < 20)
    few = frame[keep]
    models, report = train(few, schema, ["day2.parquet"], TrainSettings(
        alpha=0.01, classifier=FAST.classifier, anomaly=FAST.anomaly))
    assert report["normal_calibration_flows"] == 20
    assert models["thresholds"].suspicion == np.inf
    assert report["thresholds"]["suspicion"] is None  # JSON has no infinity
    assert "fewer than the 199" in report["warnings"][0]


def test_calibration_without_normal_flows_is_refused():
    frame, schema = two_days()
    no_normal = frame[~((frame["source"] == "day2.parquet") & (frame["label"] == "normal"))]
    with pytest.raises(ValueError, match="normal flows"):
        train(no_normal, schema, ["day2.parquet"], FAST)
