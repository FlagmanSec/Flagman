import math

import pytest

from flagman_ml.export.lightgbm_text import check_export, export_classifier, input_matrix
from flagman_ml.models.bundle import schema_record
from flagman_ml.models.classifier import ClassifierSettings, fit_classifier
from flagman_ml.synthetic import synthetic_flows

SMALL = ClassifierSettings(trees=10, min_flows_per_leaf=5)


def metadata_for(schema) -> dict:
    return {"schema": schema_record(schema),
            "report": {"thresholds": {"suspicion": 0.5, "anomaly": 0.6},
                       "settings": {"min_confidence": 0.5}}}


def test_a_category_becomes_its_position_in_the_schema_and_empty_stays_nan():
    frame, schema = synthetic_flows({"normal": 2, "dos": 1}, seed=0)
    frame.loc[1, "protocol"] = "udp"
    matrix = input_matrix(frame, schema)
    protocol = schema.feature_names.index("protocol")
    assert list(schema.categories()["protocol"]) == ["tcp", "udp", "icmp", "other"]
    assert matrix[:, protocol].tolist() == [0.0, 1.0, 0.0]
    gap = schema.feature_names.index("gap_min_ms_rev")
    assert math.isnan(matrix[2, gap])  # a dos flow gets no answer: no gaps


@pytest.mark.parametrize("counts, raw", [
    ({"normal": 200, "scan": 60, "dos": 40}, "one per class"),
    ({"normal": 200, "scan": 60}, "one, for the second class; the first class scores 0"),
])
def test_the_exported_model_gives_the_same_raw_scores(tmp_path, counts, raw):
    frame, schema = synthetic_flows(counts, seed=1)
    inputs, labels = frame[schema.feature_names], frame["label"]
    model = fit_classifier(inputs, labels, inputs, labels, SMALL)
    record = export_classifier({"classifier": model}, metadata_for(schema), tmp_path)
    assert record["raw_scores"] == raw
    assert record["classes"] == sorted(counts)
    assert record["inputs"][0] == {"name": "protocol", "kind": "category",
                                   "codes": {"tcp": 0, "udp": 1, "icmp": 2, "other": 3}}
    assert (tmp_path / "classifier.txt").read_text().startswith("tree\n")
    assert check_export(tmp_path, inputs, schema, {"classifier": model}) < 1e-12
