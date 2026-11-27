"""The lab pipeline check: Suricata's recorded alerts on the three lab
captures, matched to the flows Flagman extracted from the same captures.
A check of the code, not a result: the two rules (fixtures/suricata/
local.rules) were written for this check, and ET Open was not used."""

import json
import shutil
import sys

import pytest

from flagman_ml.files import sha256_of
from flagman_ml.flows import read_flows
from flagman_ml.labels.cli import main as labels_main
from flagman_ml.labels.store import attach_labels
from flagman_ml.suricata.cli import main
from flagman_ml.suricata.store import (
    SuricataMismatch,
    attach_suricata,
    read_matches,
    write_matches,
)
from flagman_ml.testing import DATA, ML_ROOT, fixture, lab_paths

CAPTURES = ("lab-attack-chain", "lab-normal-traffic", "lab-ssh-logins")
PCAPS = ML_ROOT.parent / "core" / "testdata" / "pcap"


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    folder = tmp_path_factory.mktemp("suricata")
    flows = [str(path) for path in lab_paths()]
    assert labels_main(["label", "--mapping", str(DATA / "labels" / "lab.toml"),
                        "--ground-truth", str(fixture("lab-ground-truth.csv")),
                        "--out", str(folder / "labels.parquet"), *flows]) == 0
    for capture in CAPTURES:
        assert main(["match", "--eve", str(fixture(f"suricata/{capture}/eve.json.gz")),
                     "--out", str(folder / f"{capture}.parquet"),
                     str(fixture(f"{capture}.parquet"))]) == 0
    return folder


@pytest.mark.parametrize("capture", CAPTURES)
def test_the_recorded_files_name_the_committed_rules_and_captures(capture):
    # Fails when local.rules or a capture changes without recording again
    # (make-suricata-fixtures.sh).
    record = json.loads(fixture(f"suricata/{capture}/run.json").read_text())
    assert record["rules"]["sha256"] == sha256_of(fixture("suricata/local.rules"))
    assert record["capture"]["sha256"] == sha256_of(PCAPS / f"{capture}.pcap")
    assert record["suricata"] == "This is Suricata version 7.0.3 RELEASE"


def test_every_recorded_alert_lands_on_a_lab_flow(lab):
    found = {capture: read_matches(lab / f"{capture}.parquet")[1]["counts"]
             for capture in CAPTURES}
    assert {c: (v["alerts"], v["unmatched"], v["flows_alerted"]) for c, v in found.items()} == {
        "lab-attack-chain": (1006, 0, 995), "lab-normal-traffic": (20, 0, 20),
        "lab-ssh-logins": (9, 0, 9)}


def test_the_suricata_file_says_which_suricata_and_rules(lab):
    provenance = read_matches(lab / "lab-ssh-logins.parquet")[1]
    assert provenance["run"]["suricata"] == "This is Suricata version 7.0.3 RELEASE"
    assert provenance["run"]["rules"]["name"] == "local.rules"
    assert provenance["eve"]["name"] == "eve.json.gz" and provenance["origin"] is None


def test_alerted_flows_by_class_on_the_lab(lab):
    flows = read_flows(*lab_paths())
    frame = attach_labels(flows, lab / "labels.parquet")
    frame, used = attach_suricata(flows, frame, sorted(lab.glob("lab-*.parquet")))
    alerted = frame.assign(alerted=frame["suricata_alerts"] > 0).groupby(
        ["source", "label"])["alerted"].agg(["size", "sum"])
    assert {key: tuple(map(int, row)) for key, row in alerted.iterrows()} == {
        ("lab-attack-chain.parquet", "brute_force"): (15, 15),
        ("lab-attack-chain.parquet", "scan"): (1000, 980),  # the first 20 SYNs do not count
        ("lab-normal-traffic.parquet", "normal"): (42, 20),  # 40 page loads in 10 s
        ("lab-ssh-logins.parquet", "brute_force"): (13, 7),
        ("lab-ssh-logins.parquet", "normal"): (11, 2)}
    assert [item["flow_file"] for item in used] == [f"{c}.parquet" for c in CAPTURES]


def test_match_refuses_an_eve_file_of_unknown_or_other_origin(lab, tmp_path, capsys):
    eve = tmp_path / "eve.json.gz"
    shutil.copy(fixture("suricata/lab-ssh-logins/eve.json.gz"), eve)  # without run.json
    flows = str(fixture("lab-ssh-logins.parquet"))
    assert main(["match", "--eve", str(eve), "--out", str(tmp_path / "x.parquet"), flows]) == 2
    assert "--origin" in capsys.readouterr().err
    assert main(["match", "--eve", str(eve), "--origin", "copied in a test",
                 "--out", str(tmp_path / "x.parquet"), flows]) == 0
    assert read_matches(tmp_path / "x.parquet")[1]["origin"] == "copied in a test"
    other = str(fixture("lab-normal-traffic.parquet"))  # another capture
    assert main(["match", "--eve", str(fixture("suricata/lab-ssh-logins/eve.json.gz")),
                 "--out", str(tmp_path / "y.parquet"), other]) == 2
    assert "not the same capture" in capsys.readouterr().err
    assert main(["match", "--eve", str(eve), "--origin", "again",
                 "--out", str(tmp_path / "x.parquet"), flows]) == 2  # no --overwrite


def test_attach_refuses_a_changed_feature_file_or_two_files_for_one(lab, tmp_path):
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    table, provenance = read_matches(lab / "lab-ssh-logins.parquet")
    changed = tmp_path / "changed.parquet"
    write_matches(table, changed, {**provenance, "flow_file": {**provenance["flow_file"],
                                                               "sha256": "0" * 64}})
    with pytest.raises(SuricataMismatch, match="changed since"):
        attach_suricata(flows, flows.frame, [changed])
    with pytest.raises(SuricataMismatch, match="two Suricata files"):
        attach_suricata(flows, flows.frame, [lab / "lab-ssh-logins.parquet"] * 2)
    with pytest.raises(SuricataMismatch, match="not a Flagman Suricata file"):
        read_matches(lab / "labels.parquet")


def test_run_through_the_command_line(tmp_path, capsys):
    script = tmp_path / "stand-in.py"
    script.write_text("import sys\nprint('stand-in')\nif sys.argv[1:] != ['-V']:\n"
                      "    open(sys.argv[sys.argv.index('-l') + 1] + '/eve.json', 'w').close()\n")
    program = tmp_path / "suricata"
    program.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    program.chmod(0o755)
    capture, config = tmp_path / "day.pcap", tmp_path / "suricata.yaml"
    capture.write_bytes(b"x")
    config.write_text("%YAML 1.1\n")
    args = ["run", "--capture", str(capture), "--rules", str(fixture("suricata/local.rules")),
            "--config", str(config), "--suricata", str(program), "--out", str(tmp_path / "out")]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["suricata"] == "stand-in"
    assert main(args) == 2  # eve.json exists: --overwrite needed
    assert main([*args, "--overwrite"]) == 0
