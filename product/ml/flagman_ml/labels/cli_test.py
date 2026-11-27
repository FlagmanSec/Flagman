import json

from flagman_ml.labels.cli import main
from flagman_ml.labels.store import read_labels
from flagman_ml.testing import DATA, fixture, lab_paths


def label_args(tmp_path):
    return ["label", "--mapping", str(DATA / "labels/lab.toml"),
            "--ground-truth", str(fixture("lab-ground-truth.csv")),
            "--out", str(tmp_path / "labels.parquet"),
            "--report", str(tmp_path / "report.json"),
            *map(str, lab_paths())]


def test_labelling_the_three_lab_captures(tmp_path, capsys):
    assert main(label_args(tmp_path)) == 0
    total = json.loads(capsys.readouterr().out)
    assert total["labels"] == {"brute_force": 28, "normal": 53, "scan": 1000}
    assert (total["flows"], total["matched"], total["conflicts"]) == (1081, 1039, 0)
    assert (total["records"], total["records_used"]) == (7, 7)
    report = json.loads((tmp_path / "report.json").read_text())
    assert [item["file"] for item in report["files"]] == [p.name for p in lab_paths()]
    labels, provenance = read_labels(tmp_path / "labels.parquet")
    assert len(labels) == 1081
    assert provenance["ground_truth"][0]["records"] == 7


def test_existing_results_are_never_replaced_without_overwrite(tmp_path, capsys):
    assert main(label_args(tmp_path)) == 0
    assert main(label_args(tmp_path)) == 2
    assert "--overwrite" in capsys.readouterr().err
    assert main([*label_args(tmp_path), "--overwrite"]) == 0


def test_the_offsets_command_finds_no_shift_on_the_lab(capsys):
    args = ["offsets", "--mapping", str(DATA / "labels/lab.toml"),
            "--ground-truth", str(fixture("lab-ground-truth.csv")), *map(str, lab_paths())]
    assert main(args) == 0
    assert "best: time_offset_ms = 0 (+0.00 h), 1039 flows matched" in capsys.readouterr().out
