"""Running a plan: one training and one test per fold, seed and left-out class.

Each run trains the models on the fold's training and calibration files
(flagman_ml.models.train), decides on its test files, and measures
(evaluate.py). Runs are written one JSON file each, so a long campaign
that stops can be continued: runs already written are skipped.

Example::

    plan = load_plan("plans/lab-synthetic.toml")
    for written in run_plan(plan, Path("results/evaluation")):
        print(written)
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pandas as pd

from flagman_ml.evaluation.evaluate import evaluate
from flagman_ml.evaluation.plan import Fold, Plan, PlanError
from flagman_ml.files import replace_atomically, sha256_of
from flagman_ml.flows import Flows, Schema, read_flows
from flagman_ml.labels.classes import ATTACKS
from flagman_ml.labels.store import attach_labels
from flagman_ml.models.anomaly import AnomalySettings
from flagman_ml.models.bundle import library_versions, schema_record
from flagman_ml.models.classifier import ClassifierSettings
from flagman_ml.models.predict import predict
from flagman_ml.models.train import TrainSettings, train


def load_labelled(plan: Plan, names: tuple[str, ...]) -> tuple[pd.DataFrame, Schema, dict, list]:
    """The named feature files with their labels, dataset by dataset."""
    groups: dict[str, list[Path]] = {}
    for name in names:
        dataset, path = plan.locate(name)
        groups.setdefault(dataset.name, []).append(path)
    frames, schema, table, files = [], None, None, []
    for dataset_name, paths in groups.items():
        flows = read_flows(*paths)
        if schema is None:
            schema, table = flows.schema, flows.flow_table
        elif flows.schema != schema or flows.flow_table != table:
            raise PlanError(f"{dataset_name}: other feature schema or flow table settings")
        labelled = attach_labels(flows, plan.datasets[dataset_name].labels)
        frames.append(labelled.assign(dataset=dataset_name))
        files += [{"name": f.name, "dataset": dataset_name, "sha256": f.sha256}
                  for f in flows.files]
    return pd.concat(frames, ignore_index=True), schema, table, files


def settings(plan: Plan, seed: int) -> TrainSettings:
    model = plan.model
    threads = model.get("threads", 2)
    classifier = ClassifierSettings(trees=model.get("trees", 200),
                                    min_flows_per_leaf=model.get("min_flows_per_leaf", 20),
                                    seed=seed, threads=threads)
    return TrainSettings(alpha=plan.alpha, min_confidence=plan.min_confidence,
                         classifier=classifier, anomaly=AnomalySettings(seed=seed, threads=threads))


def run_one(plan: Plan, fold: Fold, seed: int, left_out: str | None = None) -> dict:
    """Train on the fold without ``left_out``, test, and measure."""
    frame, schema, table, train_files = load_labelled(plan, fold.train + fold.calibration)
    if left_out:
        frame = frame[frame["label"] != left_out]
    models, report = train(frame, schema, list(fold.calibration), settings(plan, seed))
    test, test_schema, test_table, test_files = load_labelled(plan, fold.test)
    if test_schema != schema or test_table != table:
        raise PlanError(f"fold {fold.name}: test files of another schema or flow table")
    metadata = {"schema": schema_record(schema), "flow_table": table}
    predictions = predict(models, metadata, Flows(test, schema, table))
    return {"plan": plan.name, "fold": fold.name, "seed": seed, "left_out": left_out,
            "files": {"training": train_files, "test": test_files},
            "labels": {name: {"file": str(d.labels), "sha256": sha256_of(d.labels)}
                       for name, d in plan.datasets.items()},
            "training": report, "libraries": library_versions(),
            "metrics": evaluate(test, predictions, models, schema, plan.alpha)}


def attacks_to_leave_out(plan: Plan, fold: Fold) -> list[str]:
    frame, *_ = load_labelled(plan, fold.train)
    return sorted(set(frame["label"]) & set(ATTACKS))


def planned_runs(plan: Plan) -> Iterator[tuple[str, Fold, int, str | None]]:
    for fold in plan.folds:
        for seed in plan.seeds:
            yield f"{fold.name}-seed{seed}", fold, seed, None
        if plan.leave_one_attack_out:
            for name in attacks_to_leave_out(plan, fold):
                yield f"{fold.name}-seed{plan.seeds[0]}-without-{name}", fold, plan.seeds[0], name


def run_plan(plan: Plan, out: Path) -> Iterator[Path]:
    """Run every planned run not written yet; yields each file written."""
    folder = out / plan.name / "runs"
    folder.mkdir(parents=True, exist_ok=True)
    for run_name, fold, seed, left_out in planned_runs(plan):
        target = folder / f"{run_name}.json"
        if target.exists():
            continue
        result = run_one(plan, fold, seed, left_out)
        tmp = target.with_name(target.name + ".part")
        text = json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
        tmp.write_text(text + "\n", encoding="utf-8")
        replace_atomically(tmp, target)
        yield target
