"""The export on the lab model: a pipeline check, not a result."""

import json

from flagman_ml.export.cli import main
from flagman_ml.labels.cli import main as labels_main
from flagman_ml.models.cli import main as models_main
from flagman_ml.testing import DATA, fixture, lab_paths


def test_export_the_lab_model_and_check_it_on_the_lab_flows(tmp_path, capsys):
    flows = [str(path) for path in lab_paths()]
    assert labels_main(["label", "--mapping", str(DATA / "labels" / "lab.toml"),
                        "--ground-truth", str(fixture("lab-ground-truth.csv")),
                        "--out", str(tmp_path / "labels.parquet"), *flows]) == 0
    assert models_main(["train", "--labels", str(tmp_path / "labels.parquet"),
                        "--calibration-file", "lab-ssh-logins.parquet", "--alpha", "0.2",
                        "--trees", "20", "--out", str(tmp_path / "model"), *flows]) == 0
    out = tmp_path / "export"
    args = ["--model", str(tmp_path / "model"), "--out", str(out), "--check", *flows]
    assert main(args) == 0
    record = json.loads((out / "export.json").read_text())
    assert record["classes"] == ["brute_force", "normal", "scan"]
    assert record["check"]["flows"] == 1081
    assert record["check"]["largest_raw_score_difference"] < 1e-12
    assert len(record["inputs"]) == 37
    capsys.readouterr()
    assert main(args) == 2  # export.json exists: --overwrite needed
