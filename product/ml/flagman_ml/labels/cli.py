"""Command line: ``python -m flagman_ml.labels`` (run from product/ml).

Label feature files::

    python -m flagman_ml.labels label \\
        --mapping data/labels/lab.toml \\
        --ground-truth fixtures/lab-ground-truth.csv \\
        --out results/labels/lab.parquet --report results/labels/lab.json \\
        fixtures/lab-*.parquet

Find the time offset of a dataset whose time zone is not stated::

    python -m flagman_ml.labels offsets --mapping data/labels/ctu-13.toml \\
        --ground-truth capture20110818-2.binetflow flows/ctu-52.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from flagman_ml.files import sha256_of
from flagman_ml.flows import SchemaError, read_flows
from flagman_ml.labels.formats import read_ground_truth
from flagman_ml.labels.label import label_flows
from flagman_ml.labels.mapping import Mapping, load_mapping
from flagman_ml.labels.offset import candidate_offsets, offset_scores
from flagman_ml.labels.store import write_labels


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    mapping = load_mapping(args.mapping)
    events = read_events(mapping, args.ground_truth)
    if args.command == "label":
        return run_label(args, mapping, events)
    return run_offsets(args, mapping, events)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.labels",
                                  description="Label flows with a dataset's ground truth.")
    commands = top.add_subparsers(dest="command", required=True)
    for name, text in (("label", "write a labels file for feature files"),
                       ("offsets", "find the time offset between captures and ground truth")):
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("flows", nargs="+", type=Path, help="feature files (flagmand extract)")
        command.add_argument("--mapping", required=True, type=Path, help="data/labels/*.toml")
        command.add_argument("--ground-truth", required=True, action="append", type=Path,
                             help="a ground-truth file of the dataset (repeat for several)")
    label = commands.choices["label"]
    label.add_argument("--out", required=True, type=Path, help="the labels file to write")
    label.add_argument("--report", type=Path, help="also write the counts as JSON here")
    label.add_argument("--overwrite", action="store_true", help="replace existing outputs")
    offsets = commands.choices["offsets"]
    offsets.add_argument("--max-hours", type=int, default=14)
    offsets.add_argument("--step-minutes", type=int, default=15)
    offsets.add_argument("--top", type=int, default=5, help="how many offsets to show")
    return top


def read_events(mapping: Mapping, paths: list[Path]) -> pd.DataFrame:
    for path in paths:
        if path.name not in mapping.ground_truth:
            print(f"note: {path.name} is not among the files {mapping.name} was written for "
                  f"{list(mapping.ground_truth)}", file=sys.stderr)
    tables = [read_ground_truth(mapping.format, p, mapping.time_zone, mapping.time_format)
              for p in paths]
    return pd.concat(tables, ignore_index=True)


def run_label(args: argparse.Namespace, mapping: Mapping, events: pd.DataFrame) -> int:
    outputs = [p for p in (args.out, args.report) if p is not None]
    existing = [str(p) for p in outputs if p.exists()]
    if existing and not args.overwrite:
        print(f"refusing to replace {existing}: add --overwrite", file=sys.stderr)
        return 2
    all_labels, files, reports, first = [], [], [], None
    for path in args.flows:  # one file at a time keeps memory small
        flows = read_flows(path)
        if first is None:
            first = flows
        elif (flows.schema, flows.flow_table) != (first.schema, first.flow_table):
            raise SchemaError(f"{path.name}: other schema or flow table settings than "
                              f"{first.files[0].name}")
        labels, report = label_flows(flows.frame, events, mapping)
        all_labels.append(labels)
        file = flows.files[0]
        files.append({"name": file.name, "sha256": file.sha256, "rows": file.rows,
                      "capture": file.capture})
        reports.append({"file": file.name, **report})
    labels = pd.concat(all_labels, ignore_index=True)
    if labels.duplicated(["source", "row"]).any():
        raise ValueError("two feature files have the same name: rename one")
    summary = totals(labels, reports, len(events))
    provenance = {
        "mapping": {"name": mapping.name, "sha256": mapping.sha256,
                    "dataset": mapping.dataset, "source": mapping.source},
        "ground_truth": [{"name": p.name, "sha256": sha256_of(p),
                          "records": int((events["file"] == p.name).sum())}
                         for p in args.ground_truth],
        "flow_files": files,
        "report": {"total": summary, "files": reports},
    }
    write_labels(labels, args.out, provenance)
    text = json.dumps(provenance["report"], indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def totals(labels: pd.DataFrame, reports: list[dict], records: int) -> dict:
    matched = labels["record"].notna()
    counts = labels["label"].value_counts()
    return {
        "flows": int(len(labels)),
        "matched": int(matched.sum()),
        "unmatched": int((~matched).sum()),
        "conflicts": int(labels["conflict"].sum()),
        "labels": {name: int(counts[name]) for name in sorted(counts.index)},
        "records": int(records),
        "records_used": int(labels.loc[matched, "record"].nunique()),
        "files": len(reports),
    }


def run_offsets(args: argparse.Namespace, mapping: Mapping, events: pd.DataFrame) -> int:
    flows = read_flows(*args.flows)
    offsets = candidate_offsets(args.max_hours, args.step_minutes)
    scores = offset_scores(flows.frame, events, offsets, mapping.time_tolerance_ms)
    print(f"{len(flows.frame)} flows, {len(events)} records, tolerance "
          f"{mapping.time_tolerance_ms} ms; best offsets first:")
    print(scores.head(args.top).to_string(index=False))
    best = scores.iloc[0]
    print(f"\nbest: time_offset_ms = {int(best['offset_ms'])} "
          f"({best['offset_ms'] / 3_600_000:+.2f} h), {int(best['flows_matched'])} flows matched")
    return 0
