"""Command line: ``python -m flagman_ml.audit`` (run from product/ml).

The shortcut audit of labelled feature files::

    python -m flagman_ml.audit --labels results/labels/lab.parquet \\
        --held-out-file lab-ssh-logins.parquet \\
        --out results/audit/lab.json fixtures/lab-*.parquet

Separability is measured on the training side (every file but the held-out
ones); the ablations train there and score on the held-out files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from flagman_ml.audit.ablation import ablations
from flagman_ml.audit.separability import LIMIT, flagged_features, separability
from flagman_ml.files import sha256_of
from flagman_ml.flows import read_flows
from flagman_ml.labels.store import attach_labels
from flagman_ml.models.classifier import ClassifierSettings
from flagman_ml.models.data import scored


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.audit",
                                  description="Look for features that describe the testbed.")
    top.add_argument("flows", nargs="+", type=Path, help="feature files (flagmand extract)")
    top.add_argument("--labels", required=True, type=Path, help="labels file (flagman_ml.labels)")
    top.add_argument("--held-out-file", required=True, action="append", dest="held_out",
                     help="name of a validation feature file for the ablations (repeat); "
                          "never a final test file")
    top.add_argument("--out", required=True, type=Path, help="the JSON report to write")
    top.add_argument("--limit", type=float, default=LIMIT,
                     help=f"separability that flags a feature (default {LIMIT})")
    top.add_argument("--trees", type=int, default=200)
    top.add_argument("--seed", type=int, default=0)
    top.add_argument("--threads", type=int, default=2)
    top.add_argument("--overwrite", action="store_true", help="replace an existing report")
    return top


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.out.exists() and not args.overwrite:
        print(f"refusing to replace {args.out}: add --overwrite", file=sys.stderr)
        return 2
    flows = read_flows(*args.flows)
    frame = scored(attach_labels(flows, args.labels))
    training_side = frame[~frame["source"].isin(args.held_out)]
    table = separability(training_side, flows.schema, args.limit)
    flagged = flagged_features(table)
    settings = ClassifierSettings(trees=args.trees, seed=args.seed, threads=args.threads)
    report = {
        "flow_files": [{"name": f.name, "sha256": f.sha256} for f in flows.files],
        "labels": {"name": args.labels.name, "sha256": sha256_of(args.labels)},
        "limit": args.limit,
        "watched": flows.schema.watched(),
        "flagged": table[table["flagged"]].to_dict("records"),
        "separability": table.to_dict("records"),
        "ablation": ablations(frame, flows.schema, args.held_out, flagged, settings),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    watched = flows.schema.watched()
    names = [f"{name} (watched)" if name in watched else name for name in flagged]
    print(f"{len(report['flagged'])} (feature, class) pairs at or above {args.limit}; "
          f"features: {', '.join(names) or 'none'}")
    for run in report["ablation"]["runs"]:
        print(f"{run['name']}: macro-F1 {run['macro_f1']:.3f} (drop {run['drop']:+.3f})")
    return 0
