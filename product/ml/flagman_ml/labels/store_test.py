import pytest

from flagman_ml.flows import read_flows
from flagman_ml.labels import (
    LabelsMismatch, attach_labels, label_flows, load_mapping, read_ground_truth, read_labels,
    write_labels,
)
from flagman_ml.testing import DATA, fixture, rewrite


def labelled(flows, path):
    mapping = load_mapping(DATA / "labels/lab.toml")
    events = read_ground_truth(mapping.format, fixture("lab-ground-truth.csv"))
    labels, report = label_flows(flows.frame, events, mapping)
    provenance = {
        "mapping": {"name": mapping.name, "sha256": mapping.sha256},
        "flow_files": [{"name": f.name, "sha256": f.sha256} for f in flows.files],
        "report": report,
    }
    write_labels(labels, path, provenance)
    return labels


def test_labels_join_back_to_their_flows(tmp_path):
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    labelled(flows, tmp_path / "labels.parquet")
    joined = attach_labels(flows, tmp_path / "labels.parquet")
    assert len(joined) == 24
    assert joined.loc[0, "label"] == "brute_force"
    assert joined.loc[0, "packets_fwd"] == 14  # the features are still there


def test_the_footer_says_where_the_labels_come_from(tmp_path):
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    labelled(flows, tmp_path / "labels.parquet")
    labels, provenance = read_labels(tmp_path / "labels.parquet")
    assert list(labels.columns) == ["source", "row", "label", "dataset_label", "record",
                                    "candidates", "conflict"]
    assert provenance["mapping"]["name"] == "lab.toml"
    assert provenance["flow_files"][0]["sha256"] == flows.files[0].sha256


def test_the_same_inputs_give_the_same_bytes(tmp_path):
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    labelled(flows, tmp_path / "one.parquet")
    labelled(flows, tmp_path / "two.parquet")
    assert (tmp_path / "one.parquet").read_bytes() == (tmp_path / "two.parquet").read_bytes()


def test_labels_are_never_joined_to_a_changed_feature_file(tmp_path):
    original = read_flows(fixture("lab-ssh-logins.parquet"))
    labelled(original, tmp_path / "labels.parquet")
    (tmp_path / "new").mkdir()
    changed = rewrite(fixture("lab-ssh-logins.parquet"), tmp_path / "new/lab-ssh-logins.parquet",
                      table=lambda t: t.slice(0, 23))  # same name, one flow fewer
    with pytest.raises(LabelsMismatch, match="changed since it was labelled"):
        attach_labels(read_flows(changed), tmp_path / "labels.parquet")
