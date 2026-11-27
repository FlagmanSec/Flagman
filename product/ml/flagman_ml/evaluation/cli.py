"""Command line: ``python -m flagman_ml.evaluation`` (run from product/ml).

Run a plan, then summarise its runs::

    python -m flagman_ml.evaluation --plan plans/unsw-by-day.toml

Runs go to results/evaluation/<plan name>/runs/ (one JSON file each; runs
already written are skipped, so a stopped campaign continues), and the
summary to results/evaluation/<plan name>/summary.json. ``--summary-only``
summarises what is there without running anything.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from flagman_ml.evaluation.plan import load_plan
from flagman_ml.evaluation.run import run_plan
from flagman_ml.evaluation.summary import write_summary


def main(argv: list[str] | None = None) -> int:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.evaluation",
                                  description="Run an evaluation plan and summarise it.")
    top.add_argument("--plan", required=True, type=Path, help="the plan (TOML)")
    top.add_argument("--out", type=Path, default=Path("results/evaluation"),
                     help="where runs and summaries go (default results/evaluation)")
    top.add_argument("--summary-only", action="store_true", help="do not run, only summarise")
    args = top.parse_args(argv)
    plan = load_plan(args.plan)
    if not args.summary_only:
        for written in run_plan(plan, args.out):
            print(f"wrote {written}")
    print(f"wrote {write_summary(args.out / plan.name)}")
    return 0
