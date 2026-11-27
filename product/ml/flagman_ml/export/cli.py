"""Command line: ``python -m flagman_ml.export`` (run from product/ml).

Export a model bundle's classifier, and check the export on feature files::

    python -m flagman_ml.export --model results/models/lab \\
        --out results/export/lab --check fixtures/lab-*.parquet

``--check`` loads ``classifier.txt`` again, feeds it the input matrix of
those flows, and writes into ``export.json`` the largest difference from
the bundle's own raw scores (0 means the same numbers).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from flagman_ml.export.lightgbm_text import RECORD, check_export, export_classifier
from flagman_ml.flows import read_flows
from flagman_ml.models.bundle import load_bundle
from flagman_ml.models.predict import check_compatible


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if (args.out / RECORD).exists() and not args.overwrite:
        print(f"refusing to replace {args.out / RECORD}: add --overwrite", file=sys.stderr)
        return 2
    models, metadata = load_bundle(args.model)
    record = export_classifier(models, metadata, args.out)
    if args.check:
        flows = read_flows(*args.check)
        check_compatible(flows, metadata)
        record["check"] = {
            "files": [{"name": f.name, "sha256": f.sha256} for f in flows.files],
            "flows": len(flows.frame),
            "largest_raw_score_difference": check_export(args.out, flows.inputs(),
                                                         flows.schema, models)}
        (args.out / RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
    print(json.dumps(record.get("check", {}), indent=2, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.export",
                                  description="Export the classifier as a LightGBM text model.")
    top.add_argument("--model", required=True, type=Path, help="a model bundle folder")
    top.add_argument("--out", required=True, type=Path, help="folder for classifier.txt")
    top.add_argument("--check", nargs="*", type=Path, default=[],
                     help="feature files to compare the export with the bundle on")
    top.add_argument("--overwrite", action="store_true", help="replace an existing export")
    return top
