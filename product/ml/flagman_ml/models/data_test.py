import pandas as pd
import pytest

from flagman_ml.models.data import MISSING, anomaly_matrix, scored, split_by_source
from flagman_ml.synthetic import synthetic_flows


def flows(source="a.parquet", seed=0):
    frame, schema = synthetic_flows({"normal": 6, "scan": 4}, seed=seed, source=source)
    return frame, schema


def test_scored_drops_background_unlabelled_and_conflicts():
    frame, _ = flows()
    frame.loc[0, "label"] = "background"
    frame.loc[1, "label"] = "unlabelled"
    frame["conflict"] = False
    frame.loc[2, "conflict"] = True
    kept = scored(frame)
    assert len(kept) == 7
    assert len(scored(frame, drop_conflicts=False)) == 8


def test_the_calibration_set_is_whole_files_never_random_rows():
    a, _ = flows("day1.parquet")
    b, _ = flows("day2.parquet", seed=1)
    training, held = split_by_source(pd.concat([a, b], ignore_index=True), ["day2.parquet"])
    assert set(training["source"]) == {"day1.parquet"}
    assert set(held["source"]) == {"day2.parquet"}


def test_a_split_needs_known_files_and_flows_on_both_sides():
    frame, _ = flows("day1.parquet")
    with pytest.raises(ValueError, match="no flows from"):
        split_by_source(frame, ["day9.parquet"])
    with pytest.raises(ValueError, match="both"):
        split_by_source(frame, ["day1.parquet"])


def test_the_anomaly_matrix_has_the_same_columns_for_any_flows():
    frame, schema = flows()
    names = schema.feature_names
    everything = anomaly_matrix(frame[names], schema)
    scans_only = anomaly_matrix(frame[frame["label"] == "scan"][names], schema)
    assert list(everything.columns) == list(scans_only.columns)
    assert "tcp_outcome=half_open" in everything.columns
    assert everything.dtypes.eq(float).all()


def test_an_undefined_value_becomes_minus_one():
    frame, schema = synthetic_flows({"dos": 3})
    matrix = anomaly_matrix(frame[schema.feature_names], schema)
    assert (matrix["gap_mean_ms_rev"] == MISSING).all()
