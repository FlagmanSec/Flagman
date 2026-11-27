"""The evaluation report: Markdown written only from results JSON files.

Sources: ``summary.json`` of a plan, the run files it lists (with their
checksums), and optionally an audit report. Every number is a value of
those files, formatted by ``numbers.fmt``; a test checks it.
"""

from __future__ import annotations

import json
from pathlib import Path

from flagman_ml.files import sha256_of
from flagman_ml.reports.numbers import table


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluation_report(folder: Path, audit: Path | None = None) -> tuple[str, list[Path]]:
    """(Markdown, the files it was made from)."""
    summary_path = folder / "summary.json"
    summary = load(summary_path)
    sources = [summary_path]
    runs = {}
    for name, checksum in summary["runs"].items():
        path = folder / "runs" / name
        if sha256_of(path) != checksum:
            raise ValueError(f"{path} changed since the summary was written: summarise again")
        runs[name] = load(path)
        sources.append(path)
    main = {name: run for name, run in runs.items() if not run["left_out"]}
    parts = [
        f"# Evaluation report: {summary['plan']}",
        f"Made from `{summary_path}` (SHA-256 `{sha256_of(summary_path)}`) and the run files "
        "it lists. Every number below is read from those files; none is typed by hand.",
        f"False-alarm budget α: {table_value(summary['alpha'])}. Runs with every class: "
        f"{table_value(len(main))}; runs with an attack class left out: "
        f"{table_value(len(runs) - len(main))}.",
        "## Main results (mean ± standard deviation over runs)",
        table(["Metric", "Mean", "Std", "Runs"],
              [[label, v["mean"], v["std"], v["runs"]] for label, v in summary["main"].items()]),
        "Runs whose test files hold enough normal flows to measure each false-alarm rate "
        "(two scores, each at half the rate):",
        table(["False-alarm rate", "Runs with enough normal flows"],
              [[f"`{target}`", count] for target, count in
               summary["enough_normal_flows"].items()]),
        "## False-alarm budget: observed against configured",
        f"Exact (Clopper-Pearson) intervals at confidence {table_value(summary['confidence'])}.",
        table(["Run", "Normal flows", "False alarms", "Low", "High", "Budget"],
              [[f"`{name}`", b["false_alarms"]["total"], b["false_alarms"]["rate"],
                b["false_alarms"]["low"], b["false_alarms"]["high"], b["alpha"]]
               for name, b in ((n, r["metrics"]["budget"]) for n, r in main.items())]),
        "## Paired tests (Wilcoxon signed-rank, paired by run)",
        table(["Comparison", "Pairs", "Median difference", "p-value"],
              [[label, t["pairs"], t["median_difference"], t["p_value"]]
               for label, t in summary["paired"].items()]),
        "## Detection by attack class (mean share of flows that raised an alert)",
        table(["Class", "Flagman", "Suricata", "Runs"],
              [[name, v["flagman"]["mean"], v["suricata"]["mean"], v["flagman"]["runs"]]
               for name, v in summary.get("by_class", {}).items()]),
        "## Attacks left out of training",
        left_out_table(summary["left_out"]),
        "## Alerts per day",
        table(["Run", "File", "Alerts", "Days", "Alerts per day"],
              [[f"`{name}`", f"`{source}`", d["alerts"], d["days"], d["per_day"]]
               for name, run in main.items()
               for source, d in run["metrics"]["alerts_per_day"].items()]),
    ]
    parts += suricata_section(main)
    if audit is not None:
        parts += audit_section(load(audit), audit)
        sources.append(audit)
    return "\n\n".join(parts) + "\n", sources


def table_value(value) -> str:
    return table(["x"], [[value]]).splitlines()[2].strip("| ").strip()


def left_out_table(left_out: dict) -> str:
    if not left_out:
        return "No run left a class out."
    return table(["Class", "Runs", "Test flows", "Alerted (mean)", "False alarms (mean)"],
                 [[name, v["runs"], v["test_flows"], v["alerted"]["mean"],
                   v["false_alarms"]["mean"]] for name, v in left_out.items()]) + "\n\n" + \
        table(["Class", "Decision", "Flows"],
              [[name, f"`{decision}`", count] for name, v in left_out.items()
               for decision, count in v["decisions"].items()])


def suricata_section(main: dict) -> list[str]:
    """Where Suricata's alerts come from, and how many matched no flow."""
    rows = [(name, item["suricata"]) for name, run in main.items()
            for item in run["files"]["test"] if item.get("suricata")]
    if not rows:
        return []
    return [
        "## Suricata: where its alerts come from",
        "Each test file's alerts were matched to Flagman's flows by their ends, protocol and "
        "time (flagman_ml/suricata). Unmatched alerts belong to no Flagman flow.",
        table(["Run", "Test file", "Suricata", "Rules", "Alerts", "Unmatched", "Flows alerted"],
              [[f"`{name}`", f"`{s['flow_file']}`", origin(s), rules(s), s["counts"]["alerts"],
                s["counts"]["unmatched"], s["counts"]["flows_alerted"]]
               for name, s in rows]),
    ]


def origin(suricata: dict) -> str:
    if suricata.get("run"):
        return f"`{suricata['run']['suricata']}`"
    return f"no run record: `{suricata.get('origin')}`"


def rules(suricata: dict) -> str:
    if suricata.get("run"):
        rules_file = suricata["run"]["rules"]
        return f"`{rules_file['name']}` (SHA-256 `{rules_file['sha256'][:12]}`)"
    return "–"


def audit_section(audit: dict, path: Path) -> list[str]:
    flagged = sorted(audit["flagged"], key=lambda row: -row["separability"])
    return [
        "## Shortcut audit",
        f"From `{path}` (SHA-256 `{sha256_of(path)}`). Flagged at separability "
        f"{table_value(audit['limit'])} or more.",
        table(["Feature", "Class", "Separability", "Watched"],
              [[f"`{r['feature']}`", r["class"], r["separability"], r["watched"]]
               for r in flagged]) if flagged else "No feature was flagged.",
        table(["Ablation", "Features", "Macro-F1", "Drop"],
              [[r["name"], r["features"], r["macro_f1"], r["drop"]]
               for r in audit["ablation"]["runs"]]),
    ]
