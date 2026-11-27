"""Command line: ``python -m flagman_ml.models`` (run from product/ml).

Train on labelled feature files, keeping some files aside for calibration::

    python -m flagman_ml.models train --labels results/labels/lab.parquet \\
        --calibration-file lab-ssh-logins.parquet --alpha 0.2 \\
        --out results/models/lab fixtures/lab-*.parquet

Decide on new feature files (one row per flow)::

    python -m flagman_ml.models predict --model results/models/lab \\
        --out results/predictions/lab.parquet fixtures/lab-*.parquet

Compare a recent window of traffic with the calibration traffic::

    python -m flagman_ml.models drift --model results/models/lab \\
        --report results/drift/lab.json fixtures/lab-normal-traffic.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from flagman_ml.files import sha256_of, write_table
from flagman_ml.flows import Flows, read_flows
from flagman_ml.labels.store import attach_labels, read_labels
from flagman_ml.models.anomaly import AnomalySettings
from flagman_ml.models.bundle import load_bundle, save_bundle, schema_record
from flagman_ml.models.classifier import ClassifierSettings
from flagman_ml.models.drift import DriftLimits, drift_report
from flagman_ml.models.predict import KEY, predict
from flagman_ml.models.train import TrainSettings, train


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    target = args.out if args.command != "drift" else args.report
    if target.exists() and not args.overwrite:
        print(f"refusing to replace {target}: add --overwrite", file=sys.stderr)
        return 2
    flows = read_flows(*args.flows)
    return {"train": run_train, "predict": run_predict, "drift": run_drift}[args.command](
        args, flows)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.models",
                                  description="Train, use and watch the detection models.")
    commands = top.add_subparsers(dest="command", required=True)
    texts = {"train": "train the models and set the false-alarm thresholds",
             "predict": "write one decision per flow",
             "drift": "check whether recent traffic still looks like the calibration traffic"}
    for name, text in texts.items():
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("flows", nargs="+", type=Path, help="feature files (flagmand extract)")
        command.add_argument("--overwrite", action="store_true", help="replace existing outputs")
        if name != "train":
            command.add_argument("--model", required=True, type=Path, help="a trained bundle")
    fit = commands.choices["train"]
    fit.add_argument("--labels", required=True, type=Path, help="labels file (flagman_ml.labels)")
    fit.add_argument("--calibration-file", required=True, action="append", dest="calibration",
                     help="name of a feature file kept aside for calibration (repeat)")
    fit.add_argument("--out", required=True, type=Path, help="the bundle folder to write")
    fit.add_argument("--alpha", type=float, default=0.01,
                     help="false-alarm budget for normal flows (default 0.01)")
    fit.add_argument("--min-confidence", type=float, default=0.5)
    fit.add_argument("--trees", type=int, default=200)
    fit.add_argument("--min-flows-per-leaf", type=int, default=20)
    fit.add_argument("--seed", type=int, default=0)
    fit.add_argument("--threads", type=int, default=2)
    commands.choices["predict"].add_argument("--out", required=True, type=Path,
                                             help="the predictions file to write (Parquet)")
    drift = commands.choices["drift"]
    drift.add_argument("--report", required=True, type=Path, help="the JSON report to write")
    drift.add_argument("--p-limit", type=float, default=0.01)
    drift.add_argument("--psi-limit", type=float, default=0.2)
    return top


def flow_files(flows: Flows) -> list[dict]:
    return [{"name": f.name, "sha256": f.sha256, "rows": f.rows, "capture": f.capture}
            for f in flows.files]


def run_train(args: argparse.Namespace, flows: Flows) -> int:
    classifier = ClassifierSettings(trees=args.trees, min_flows_per_leaf=args.min_flows_per_leaf,
                                    seed=args.seed, threads=args.threads)
    settings = TrainSettings(alpha=args.alpha, min_confidence=args.min_confidence,
                             classifier=classifier,
                             anomaly=AnomalySettings(seed=args.seed, threads=args.threads))
    frame = attach_labels(flows, args.labels)
    models, report = train(frame, flows.schema, args.calibration, settings)
    _, provenance = read_labels(args.labels)
    metadata = {
        "kind": "flagman model bundle", "format": 1,
        "schema": schema_record(flows.schema), "flow_table": flows.flow_table,
        "training_data": {"flow_files": flow_files(flows),
                          "labels": {"name": args.labels.name, "sha256": sha256_of(args.labels),
                                     "mapping": provenance.get("mapping")}},
        "report": report,
    }
    save_bundle(args.out, models, metadata)
    for warning in report["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    print(json.dumps({"bundle": str(args.out), "classes": report["classes"],
                      "thresholds": report["thresholds"]}, indent=2))
    return 0


def run_predict(args: argparse.Namespace, flows: Flows) -> int:
    models, metadata = load_bundle(args.model)
    predictions = predict(models, metadata, flows)
    write_table(predictions, args.out, KEY, {
        "model": {"name": args.model.name, "model_sha256": metadata["model_sha256"]},
        "flow_files": flow_files(flows), "thresholds": metadata["report"]["thresholds"]})
    counts = predictions["decision"].value_counts()
    print(json.dumps({name: int(counts[name]) for name in sorted(counts.index)}, indent=2))
    return 0


def run_drift(args: argparse.Namespace, flows: Flows) -> int:
    models, metadata = load_bundle(args.model)
    predictions = predict(models, metadata, flows)
    reference = models["reference"]
    report = drift_report(
        flows.schema, reference["inputs"], flows.inputs(), reference["anomaly"],
        predictions["anomaly"].to_numpy(), (predictions["decision"] != "normal").to_numpy(),
        models["thresholds"].alpha, DriftLimits(args.p_limit, args.psi_limit))
    report["model"] = {"name": args.model.name, "model_sha256": metadata["model_sha256"]}
    report["flow_files"] = flow_files(flows)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n".join(report["flags"]) or "no drift flag")
    return 0
