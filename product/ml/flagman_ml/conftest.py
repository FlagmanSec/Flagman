"""Shared test fixtures (pytest reads this file by itself).

``evaluated``: a whole evaluation plan run once on made-up days written as
real feature files (synthetic.py), for the evaluation and report tests.
The test day also gets made-up Suricata alerts (``suricata_alerts``), so that
Suricata is scored as a fourth way of deciding.
"""

from pathlib import Path

import numpy as np
import pytest

from flagman_ml.evaluation.cli import main
from flagman_ml.suricata.cli import main as suricata_main
from flagman_ml.synthetic import write_day, write_eve, write_labels

DAYS = {"day1.parquet": {"normal": 300, "scan": 80, "brute_force": 80},
        "day2.parquet": {"normal": 300, "scan": 40, "brute_force": 40},
        "day3.parquet": {"normal": 300, "scan": 40, "brute_force": 40, "dos": 30}}
ORIGIN = "made up by synthetic.write_eve"


def suricata_alerts(labels) -> np.ndarray:
    """Made-up Suricata verdicts on day 3: every dos flow, every other scan
    flow, no brute force, and one normal flow in 30."""
    position = np.arange(len(labels))
    return ((labels == "dos") | ((labels == "scan") & (position % 2 == 0))
            | ((labels == "normal") & (position % 30 == 0))).to_numpy()


def write_plan(folder: Path) -> Path:
    (folder / "flows").mkdir()
    labelled = {folder / "flows" / name: write_day(folder / "flows" / name, counts, seed=i, day=i)
                for i, (name, counts) in enumerate(DAYS.items(), start=1)}
    write_labels(folder / "labels.parquet", labelled)
    day3 = folder / "flows" / "day3.parquet"
    write_eve(folder / "eve.json", day3, suricata_alerts(labelled[day3]))
    assert suricata_main(["match", "--eve", str(folder / "eve.json"), "--origin", ORIGIN,
                          "--out", str(folder / "suricata-day3.parquet"), str(day3)]) == 0
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
suricata = ["{folder / 'suricata-day3.parquet'}"]

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
