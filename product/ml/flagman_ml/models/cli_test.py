"""Pipeline check on the lab files: label, train, predict, drift.

The lab files are tiny (53 normal flows), so this checks that the steps
run and write what they should. It is not a result: no number here says
how well the models detect anything.
"""

import json

import pytest

from flagman_ml.files import read_table
from flagman_ml.labels.cli import main as labels_main
from flagman_ml.models.bundle import MODEL, BundleError
from flagman_ml.models.cli import main
from flagman_ml.models.predict import KEY
from flagman_ml.testing import DATA, LAB_FILES, fixture, lab_paths


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    folder = tmp_path_factory.mktemp("lab")
    flows = [str(p) for p in lab_paths()]
    labels = folder / "labels.parquet"
    assert labels_main(["label", "--mapping", str(DATA / "labels" / "lab.toml"),
                        "--ground-truth", str(fixture("lab-ground-truth.csv")),
                        "--out", str(labels), *flows]) == 0
    model = folder / "model"
    # alpha 0.2: the calibration file has only 11 normal flows.
    assert main(["train", "--labels", str(labels), "--calibration-file",
                 "lab-ssh-logins.parquet", "--alpha", "0.2", "--trees", "50",
                 "--out", str(model), *flows]) == 0
    return folder, flows, model


def test_training_writes_a_bundle_that_names_its_data(lab):
    _, _, model = lab
    metadata = json.loads((model / "bundle.json").read_text())
    assert metadata["report"]["classes"] == ["brute_force", "normal", "scan"]
    assert metadata["report"]["files"]["calibration"] == ["lab-ssh-logins.parquet"]
    assert metadata["report"]["normal_calibration_flows"] == 11
    names = [item["name"] for item in metadata["training_data"]["flow_files"]]
    assert names == list(LAB_FILES)
    assert metadata["training_data"]["labels"]["mapping"]["dataset"] == "lab"


def test_predict_writes_one_decision_per_flow(lab, capsys):
    folder, flows, model = lab
    out = folder / "predictions.parquet"
    assert main(["predict", "--model", str(model), "--out", str(out), *flows]) == 0
    predictions, provenance = read_table(out, KEY)
    assert len(predictions) == sum(LAB_FILES.values())
    assert provenance["model"]["name"] == "model"
    counts = json.loads(capsys.readouterr().out)
    assert sum(counts.values()) == sum(LAB_FILES.values())


def test_drift_writes_a_report(lab):
    folder, _, model = lab
    report = folder / "drift.json"
    assert main(["drift", "--model", str(model), "--report", str(report),
                 str(fixture("lab-normal-traffic.parquet"))]) == 0
    written = json.loads(report.read_text())
    assert written["alert_rate"]["flows"] == LAB_FILES["lab-normal-traffic.parquet"]
    assert set(written["psi"]) >= {"duration_ms", "protocol"}


def test_outputs_are_never_replaced_without_asking(lab, capsys):
    folder, flows, model = lab
    assert main(["predict", "--model", str(model), "--out", str(model / "bundle.json"),
                 *flows]) == 2
    assert "--overwrite" in capsys.readouterr().err


def test_a_changed_model_file_is_refused(lab, tmp_path):
    _, flows, model = lab
    copy = tmp_path / "model"
    copy.mkdir()
    (copy / "bundle.json").write_text((model / "bundle.json").read_text())
    (copy / MODEL).write_bytes(b"not the trained model")
    with pytest.raises(BundleError):
        main(["predict", "--model", str(copy), "--out", str(tmp_path / "p.parquet"), *flows])
