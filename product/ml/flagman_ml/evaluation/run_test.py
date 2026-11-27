"""A whole plan on made-up days written as real feature files: a pipeline
check of the harness, not a result. The plan is run once, by the
``evaluated`` fixture in flagman_ml/conftest.py."""

import json

from flagman_ml.evaluation.cli import main
from flagman_ml.evaluation.plan import load_plan
from flagman_ml.evaluation.run import planned_runs


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
    assert set(metrics["rules"]) == {"two scores", "classifier only", "anomaly only"}
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
