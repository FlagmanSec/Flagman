"""A whole plan on made-up days written as real feature files: a pipeline
check of the harness, not a result. The plan is run once, by the
``evaluated`` fixture in flagman_ml/conftest.py."""

import json

import pandas as pd
import pytest

from flagman_ml.evaluation.cli import main
from flagman_ml.evaluation.plan import Fold, PlanError, load_plan
from flagman_ml.evaluation.run import planned_runs, with_suricata


def test_every_planned_run_is_written_once(evaluated):
    _, plan, results = evaluated
    names = [name for name, *_ in planned_runs(load_plan(plan))]
    assert names == ["test-day3-seed0", "test-day3-seed1", "test-day3-seed0-without-brute_force",
                     "test-day3-seed0-without-scan"]
    assert sorted(p.stem for p in (results / "runs").glob("*.json")) == sorted(names)


def test_a_run_records_its_data_and_metrics(evaluated):
    _, _, results = evaluated
    run = json.loads((results / "runs" / "test-day3-seed0.json").read_text())
    assert [f["name"] for f in run["files"]["test"]] == ["day3.parquet"]
    metrics = run["metrics"]
    assert metrics["unseen_classes"] == ["dos"]  # day 1 has no dos
    assert metrics["budget"]["false_alarms"]["total"] == 300
    assert set(metrics["rules"]) == {"two scores", "classifier only", "anomaly only", "suricata"}
    assert set(metrics["at_fpr"]) == {"0.001", "0.005", "0.01"}
    assert metrics["by_class"]["dos"]["flows"] == 30
    assert metrics["alerts_per_day"]["day3.parquet"]["days"] > 0.9


def test_the_summary_pairs_runs_and_lists_left_out_classes(evaluated):
    _, _, results = evaluated
    summary = json.loads((results / "summary.json").read_text())
    assert summary["main"]["macro-F1"]["runs"] == 2
    assert summary["paired"]["detection: two scores vs anomaly only"]["pairs"] == 2
    assert set(summary["left_out"]) == {"brute_force", "scan"}
    assert summary["left_out"]["scan"]["test_flows"] == 40
    assert summary["enough_normal_flows"]["0.01"] == 2  # 300 flows, 200 needed
    assert summary["enough_normal_flows"]["0.001"] == 0  # 2,000 needed


def test_runs_already_written_are_not_run_again(evaluated, capsys):
    _, plan, _ = evaluated
    assert main(["--plan", str(plan), "--out", str(evaluated[0] / "results")]) == 0
    assert capsys.readouterr().out.count("wrote") == 1  # only the summary


def test_suricata_is_scored_like_flagman_on_the_same_flows(evaluated):
    # Made-up alerts (conftest.suricata_alerts): every dos flow, every other
    # scan flow, no brute force, one normal flow in 30.
    _, _, results = evaluated
    run = json.loads((results / "runs" / "test-day3-seed0.json").read_text())
    rule = run["metrics"]["rules"]["suricata"]
    assert (rule["false_alarms"]["count"], rule["false_alarms"]["total"]) == (10, 300)
    assert (rule["detection"]["count"], rule["detection"]["total"]) == (50, 110)
    assert rule["against_two_scores"]["p_value"] <= 1
    assert run["metrics"]["suricata"]["by_class"] == {
        "brute_force": {"flows": 40, "alerted": 0.0}, "dos": {"flows": 30, "alerted": 1.0},
        "scan": {"flows": 40, "alerted": 0.5}}
    recorded = run["files"]["test"][0]["suricata"]
    assert recorded["origin"] == "made up by synthetic.write_eve" and recorded["run"] is None
    assert recorded["counts"]["unmatched"] == 0
    summary = json.loads((results / "summary.json").read_text())
    assert summary["main"]["detection, Suricata"]["mean"] == 50 / 110
    assert summary["paired"]["detection: two scores vs suricata"]["pairs"] == 2
    assert summary["by_class"]["dos"]["suricata"]["mean"] == 1.0


def test_a_fold_needs_suricata_for_all_its_test_files_or_none():
    fold = Fold("f", ("a",), ("b",), ("day2.parquet", "day3.parquet"))
    test = pd.DataFrame({"source": ["day2.parquet", "day3.parquet"],
                         "suricata_alerts": [None, 1.0]})
    with pytest.raises(PlanError, match="no Suricata file for day2.parquet"):
        with_suricata(test, fold)
    assert with_suricata(test.iloc[1:], fold)["suricata_alerts"].dtype == "int64"
