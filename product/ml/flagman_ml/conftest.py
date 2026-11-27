"""Shared test fixtures (pytest reads this file by itself).

``evaluated``: a whole evaluation plan run once on made-up days written as
real feature files (synthetic.py), for the evaluation and report tests.
"""

from pathlib import Path

import pytest

from flagman_ml.evaluation.cli import main
from flagman_ml.synthetic import write_day, write_labels

DAYS = {"day1.parquet": {"normal": 300, "scan": 80, "brute_force": 80},
        "day2.parquet": {"normal": 300, "scan": 40, "brute_force": 40},
        "day3.parquet": {"normal": 300, "scan": 40, "brute_force": 40, "dos": 30}}


def write_plan(folder: Path) -> Path:
    (folder / "flows").mkdir()
    labelled = {folder / "flows" / name: write_day(folder / "flows" / name, counts, seed=i, day=i)
                for i, (name, counts) in enumerate(DAYS.items(), start=1)}
    write_labels(folder / "labels.parquet", labelled)
    flows = ", ".join(f'"{folder / "flows" / name}"' for name in DAYS)
    plan = folder / "plan.toml"
    plan.write_text(f"""
name = "made-up-days"
alpha = 0.05
seeds = [0, 1]
leave_one_attack_out = true

[model]
trees = 20
min_flows_per_leaf = 5

[datasets.made_up]
labels = "{folder / 'labels.parquet'}"
flows = [{flows}]

[[folds]]
name = "test-day3"
train = ["day1.parquet"]
calibration = ["day2.parquet"]
test = ["day3.parquet"]
""")
    return plan


@pytest.fixture(scope="session")
def evaluated(tmp_path_factory):
    folder = tmp_path_factory.mktemp("evaluation")
    plan = write_plan(folder)
    assert main(["--plan", str(plan), "--out", str(folder / "results")]) == 0
    return folder, plan, folder / "results" / "made-up-days"
