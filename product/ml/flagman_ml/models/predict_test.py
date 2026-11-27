import numpy as np
import pytest

from flagman_ml.flows import Flows
from flagman_ml.models.bundle import schema_record
from flagman_ml.models.predict import IncompatibleFlows, check_compatible, predict
from flagman_ml.models.train import train
from flagman_ml.models.train_test import FAST, TABLE, two_days
from flagman_ml.synthetic import synthetic_flows


def test_one_row_per_flow_with_the_decision_and_every_probability():
    frame, schema = two_days()
    models, _ = train(frame, schema, ["day2.parquet"], FAST)
    new, _ = synthetic_flows({"normal": 5, "scan": 5}, seed=9, source="day3.parquet")
    metadata = {"schema": schema_record(schema), "flow_table": TABLE}
    result = predict(models, metadata, Flows(new, schema, TABLE))
    assert len(result) == 10
    assert list(result.columns[:2]) == ["source", "row"]
    assert {"decision", "top_class", "confidence", "suspicion", "anomaly"} <= set(result.columns)
    probabilities = result[["p_brute_force", "p_normal", "p_scan"]]
    assert np.allclose(probabilities.sum(axis=1), 1)


def test_flows_cut_with_other_flow_table_settings_are_refused():
    frame, schema = synthetic_flows({"normal": 3})
    metadata = {"schema": schema_record(schema), "flow_table": TABLE}
    with pytest.raises(IncompatibleFlows, match="flow table"):
        check_compatible(Flows(frame, schema, {"idle_timeout_ms": 1}), metadata)


def test_flows_with_another_feature_schema_are_refused():
    frame, schema = synthetic_flows({"normal": 3})
    record = schema_record(schema)
    record["features"][0]["categories"].append("sctp")  # one more protocol
    with pytest.raises(IncompatibleFlows, match="schema"):
        check_compatible(Flows(frame, schema, TABLE), {"schema": record, "flow_table": TABLE})
