"""An evaluation plan: which files train, calibrate and test, and how often.

A plan is a TOML file. Paths are relative to the folder the command runs
in (product/ml). Folds name feature files by file name; a name must be
unique across the plan's datasets.

Example (``plans/README.md`` has more)::

    name = "unsw-by-day"
    alpha = 0.01
    seeds = [0, 1, 2]
    leave_one_attack_out = true

    [datasets.unsw]
    labels = "results/labels/unsw-nb15.parquet"
    flows = ["flows/unsw/day1.parquet", "flows/unsw/day2.parquet", "flows/unsw/day3.parquet"]

    [[folds]]
    name = "test-day3"
    train = ["day1.parquet"]
    calibration = ["day2.parquet"]
    test = ["day3.parquet"]

- **Splits by day or session**: each role takes whole files, never rows.
- **Cross-dataset holdouts**: a fold may test on files of another dataset
  (its own labels file); classes it never trained on count as unseen.
- **Leave-one-attack-type-out**: with ``leave_one_attack_out = true``,
  every fold is run again once per attack class of its training side,
  without that class (first seed only, to bound the run time).
- **Suricata**: a dataset may list Suricata files
  (``suricata = ["results/suricata/day3.parquet"]``, written by
  ``python -m flagman_ml.suricata match``). A fold whose test files all
  have one scores Suricata as a fourth way of deciding.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class PlanError(ValueError):
    """A plan that cannot be run as written."""


@dataclass(frozen=True)
class Dataset:
    name: str
    labels: Path
    flows: tuple[Path, ...]
    suricata: tuple[Path, ...] = ()  # Suricata files (flagman_ml.suricata match)


@dataclass(frozen=True)
class Fold:
    name: str
    train: tuple[str, ...]
    calibration: tuple[str, ...]
    test: tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    name: str
    alpha: float
    seeds: tuple[int, ...]
    datasets: dict[str, Dataset]
    folds: tuple[Fold, ...]
    leave_one_attack_out: bool = False
    min_confidence: float = 0.5
    model: dict = field(default_factory=dict)  # trees, min_flows_per_leaf, threads

    def locate(self, file_name: str) -> tuple[Dataset, Path]:
        for dataset in self.datasets.values():
            for path in dataset.flows:
                if path.name == file_name:
                    return dataset, path
        raise PlanError(f"no dataset of the plan lists a feature file named {file_name}")


def load_plan(path: str | Path) -> Plan:
    with open(path, "rb") as file:
        raw = tomllib.load(file)
    try:
        datasets = {name: Dataset(name, Path(item["labels"]), tuple(map(Path, item["flows"])),
                                  tuple(map(Path, item.get("suricata", []))))
                    for name, item in raw["datasets"].items()}
        folds = tuple(Fold(item["name"], tuple(item["train"]), tuple(item["calibration"]),
                           tuple(item["test"])) for item in raw["folds"])
        plan = Plan(name=raw["name"], alpha=float(raw["alpha"]),
                    seeds=tuple(raw.get("seeds", [0])), datasets=datasets, folds=folds,
                    leave_one_attack_out=bool(raw.get("leave_one_attack_out", False)),
                    min_confidence=float(raw.get("min_confidence", 0.5)),
                    model=dict(raw.get("model", {})))
    except KeyError as missing:
        raise PlanError(f"{path}: missing {missing}") from None
    check(plan)
    return plan


def check(plan: Plan) -> None:
    if not 0 < plan.alpha < 1:
        raise PlanError("alpha must be between 0 and 1")
    if not plan.seeds or not plan.folds:
        raise PlanError("a plan needs at least one seed and one fold")
    names = [path.name for dataset in plan.datasets.values() for path in dataset.flows]
    if len(names) != len(set(names)):
        raise PlanError("two feature files of the plan have the same name: rename one")
    unknown = sorted(set(plan.model) - {"trees", "min_flows_per_leaf", "threads"})
    if unknown:
        raise PlanError(f"unknown model settings: {unknown}")
    for fold in plan.folds:
        roles = [*fold.train, *fold.calibration, *fold.test]
        if len(roles) != len(set(roles)):
            raise PlanError(f"fold {fold.name}: a file has two roles")
        if not (fold.train and fold.calibration and fold.test):
            raise PlanError(f"fold {fold.name}: train, calibration and test all need files")
        for name in roles:
            plan.locate(name)
    if len({fold.name for fold in plan.folds}) != len(plan.folds):
        raise PlanError("two folds have the same name")
