"""Pipeline check on the lab files (not a result: they are far too few)."""

import json

from flagman_ml.audit.cli import main
from flagman_ml.labels.cli import main as labels_main
from flagman_ml.testing import DATA, fixture, lab_paths


def test_the_audit_writes_its_report(tmp_path, capsys):
    flows = [str(p) for p in lab_paths()]
    labels = tmp_path / "labels.parquet"
    assert labels_main(["label", "--mapping", str(DATA / "labels" / "lab.toml"),
                        "--ground-truth", str(fixture("lab-ground-truth.csv")),
                        "--out", str(labels), *flows]) == 0
    out = tmp_path / "audit.json"
    assert main(["--labels", str(labels), "--held-out-file", "lab-ssh-logins.parquet",
                 "--trees", "20", "--out", str(out), *flows]) == 0
    report = json.loads(out.read_text())
    assert {row["class"] for row in report["separability"]} == {"brute_force", "normal", "scan"}
    assert report["ablation"]["held_out_files"] == ["lab-ssh-logins.parquet"]
    assert report["ablation"]["runs"][0]["name"] == "all features"
    assert "pairs at or above 0.99" in capsys.readouterr().out
