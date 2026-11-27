"""Command line: ``python -m flagman_ml.reports`` (run from product/ml).

Write the Markdown report of an evaluation (and, optionally, an audit)::

    python -m flagman_ml.reports --evaluation results/evaluation/unsw-by-day \\
        --audit results/audit/unsw.json --out results/reports/unsw-by-day.md

The report lists the files it was made from, with their checksums.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flagman_ml.reports.evaluation import evaluation_report


def main(argv: list[str] | None = None) -> int:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.reports",
                                  description="Write a report from results JSON files only.")
    top.add_argument("--evaluation", required=True, type=Path,
                     help="a plan's folder in results/evaluation (with summary.json)")
    top.add_argument("--audit", type=Path, help="an audit report (results/audit/*.json)")
    top.add_argument("--out", required=True, type=Path, help="the Markdown file to write")
    top.add_argument("--overwrite", action="store_true", help="replace an existing report")
    args = top.parse_args(argv)
    if args.out.exists() and not args.overwrite:
        print(f"refusing to replace {args.out}: add --overwrite", file=sys.stderr)
        return 2
    markdown, sources = evaluation_report(args.evaluation, args.audit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(f"wrote {args.out} from {len(sources)} files")
    return 0
