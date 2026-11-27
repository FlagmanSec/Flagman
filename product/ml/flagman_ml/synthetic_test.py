import numpy as np

from flagman_ml.synthetic import lab_schema, synthetic_flows


def test_synthetic_flows_have_the_real_schema_and_the_asked_counts():
    frame, schema = synthetic_flows({"normal": 30, "scan": 10}, seed=1)
    assert schema == lab_schema()
    assert list(frame.columns) == ["source", "row", *schema.feature_names, "label"]
    assert frame["label"].value_counts().to_dict() == {"normal": 30, "scan": 10}
    assert frame["row"].tolist() == list(range(40))
    for name, categories in schema.categories().items():
        assert list(frame[name].cat.categories) == list(categories)


def test_the_same_seed_gives_the_same_flows():
    first, _ = synthetic_flows({"normal": 20}, seed=4)
    again, _ = synthetic_flows({"normal": 20}, seed=4)
    other, _ = synthetic_flows({"normal": 20}, seed=5)
    assert first.equals(again)
    assert not first.equals(other)


def test_a_planted_shortcut_gives_one_value_per_class():
    frame, _ = synthetic_flows({"normal": 20, "scan": 20}, shortcut="first_response_ms")
    values = frame.groupby("label")["first_response_ms"].unique()
    assert values["normal"].tolist() == [7.0]
    assert values["scan"].tolist() == [1007.0]


def test_a_side_that_sent_nothing_has_no_timing():
    frame, _ = synthetic_flows({"dos": 10})
    assert (frame["packets_rev"] == 0).all()
    assert np.isnan(frame["gap_mean_ms_rev"]).all()
