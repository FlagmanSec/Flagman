"""The summary of a plan's runs: mean ± std, paired tests, attacks left out.

Read from the run files only (results/evaluation/<plan>/runs/*.json), so
every number in the summary, and in the reports built from it, traces
back to a run file.

- **main**: for each metric, the mean and standard deviation over the
  runs that left nothing out (every fold and seed).
- **paired**: Flagman's two-score rule against each score alone, paired
  by run (Wilcoxon signed-rank), on detection and on false alarms.
- **left_out**: for each attack class left out of training, how often its
  test flows still raised an alert, and what they were called.
"""

from __future__ import annotations

import json
from pathlib import Path

from flagman_ml.evaluation.metrics import BASE_RATES, CONFIDENCE, FPR_TARGETS
from flagman_ml.evaluation.paired import mean_std, wilcoxon
from flagman_ml.files import sha256_of

METRICS = {
    "false alarms, two scores": ("rules", "two scores", "false_alarms", "rate"),
    "detection, two scores": ("rules", "two scores", "detection", "rate"),
    "false alarms, classifier only": ("rules", "classifier only", "false_alarms", "rate"),
    "detection, classifier only": ("rules", "classifier only", "detection", "rate"),
    "false alarms, anomaly only": ("rules", "anomaly only", "false_alarms", "rate"),
    "detection, anomaly only": ("rules", "anomaly only", "detection", "rate"),
    **{f"detection at false-alarm rate {t}": ("at_fpr", str(t), "two scores", "detection")
       for t in FPR_TARGETS},
    **{f"precision at base rate {b}": ("precision", str(b)) for b in BASE_RATES},
    "macro-F1": ("f1", "macro_f1"),
    "ECE, calibrated": ("calibration", "calibrated", "ece"),
    "ECE, before calibration": ("calibration", "uncalibrated", "ece"),
    "temperature": ("calibration", "temperature"),
}
PAIRED = (("detection", "detection"), ("false alarms", "false_alarms"))


def value(run: dict, path: tuple[str, ...]):
    node = run["metrics"]
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def read_runs(folder: Path) -> list[tuple[str, dict]]:
    return [(path.name, json.loads(path.read_text(encoding="utf-8")))
            for path in sorted((folder / "runs").glob("*.json"))]


def summarise(folder: Path) -> dict:
    runs = read_runs(folder)
    if not runs:
        raise ValueError(f"{folder}: no run files")
    main = [run for _, run in runs if not run["left_out"]]
    summary = {
        "plan": runs[0][1]["plan"],
        "alpha": runs[0][1]["metrics"]["budget"]["alpha"],
        "confidence": CONFIDENCE,
        "runs": {name: sha256_of(folder / "runs" / name) for name, _ in runs},
        "main": {label: mean_std([value(run, path) for run in main])
                 for label, path in METRICS.items()},
        "paired": {f"{what}: two scores vs {other}": wilcoxon(
            [value(run, ("rules", "two scores", key, "rate")) for run in main],
            [value(run, ("rules", other, key, "rate")) for run in main])
            for what, key in PAIRED for other in ("classifier only", "anomaly only")},
        "left_out": left_out([run for _, run in runs if run["left_out"]]),
        # Runs with enough normal test flows to measure each false-alarm rate:
        # with fewer, "detection at 0.1%" really means "at no false alarm".
        "enough_normal_flows": {
            str(t): sum(value(run, ("at_fpr", str(t), "two scores", "enough_normal_flows")) is True
                        for run in main) for t in FPR_TARGETS},
    }
    return summary


def left_out(runs: list[dict]) -> dict:
    result: dict[str, dict] = {}
    for name in sorted({run["left_out"] for run in runs}):
        mine = [run for run in runs if run["left_out"] == name]
        found = [run["metrics"]["by_class"].get(name) for run in mine]
        decisions: dict[str, int] = {}
        for item in filter(None, found):
            for decision, count in item["decisions"].items():
                decisions[decision] = decisions.get(decision, 0) + count
        result[name] = {
            "runs": len(mine),
            "test_flows": sum(item["flows"] for item in filter(None, found)),
            "alerted": mean_std([item["alerted"] if item else None for item in found]),
            "decisions": dict(sorted(decisions.items())),
            "false_alarms": mean_std([value(run, ("rules", "two scores", "false_alarms", "rate"))
                                      for run in mine]),
        }
    return result


def write_summary(folder: Path) -> Path:
    target = folder / "summary.json"
    text = json.dumps(summarise(folder), indent=2, sort_keys=True, allow_nan=False)
    target.write_text(text + "\n", encoding="utf-8")
    return target
