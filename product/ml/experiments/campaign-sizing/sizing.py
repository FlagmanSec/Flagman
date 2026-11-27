"""Small measurements for the runbook (ml/docs/runbook.md): how fast
``flagmand extract`` runs, how big its files are, and how much memory
training takes. A pipeline check, not a result: the capture is the lab
captures repeated (repeat_pcap.py) and the training flows are made up.

Usage, from product/ml, with a flagmand built with ``--features parquet``::

    python experiments/campaign-sizing/sizing.py results/sizing \\
        ../core/target/release/flagmand

Writes ``sizing.json`` into the folder given, with the files it measured.
"""

from __future__ import annotations

import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # product/ml, for flagman_ml

from repeat_pcap import repeat  # noqa: E402

from flagman_ml.flows import read_flows  # noqa: E402
from flagman_ml.suricata.run import SuricataRun, run_suricata  # noqa: E402

LAB = HERE.parents[2] / "core/testdata/pcap"
CAPTURES = ["lab-normal-traffic.pcap", "lab-attack-chain.pcap", "lab-ssh-logins.pcap"]
COPIES = 320
TRAINING_FLOWS = [100_000, 300_000, 1_000_000]
FIXTURES = HERE.parents[1] / "fixtures"


def extract(flagmand: Path, capture: Path, out: Path) -> dict:
    """Times one ``flagmand extract``; its peak memory is the first child's."""
    start = time.perf_counter()
    subprocess.run([str(flagmand), "extract", str(capture), "--out", str(out), "--overwrite"],
                   check=True, capture_output=True)
    seconds = time.perf_counter() - start
    flows = read_flows(out)
    rows = len(flows.frame)
    return {"capture_bytes": capture.stat().st_size, "seconds": seconds,
            "megabytes_per_second": capture.stat().st_size / seconds / 1e6,
            "peak_rss_mb": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024,
            "flows": rows, "feature_file_bytes": out.stat().st_size,
            "feature_file_bytes_per_flow": out.stat().st_size / rows,
            "pandas_bytes_per_flow": int(flows.frame.memory_usage(deep=True).sum()) / rows}


def suricata(capture: Path, out: Path) -> dict | None:
    """Suricata on the same capture, with the two local test rules (not ET
    Open) and the system's own configuration: its time and the size of what
    it writes. None if Suricata is not installed."""
    if shutil.which("suricata") is None:
        return None
    rules = HERE.parents[1] / "fixtures/suricata/local.rules"
    start = time.perf_counter()
    record = run_suricata(SuricataRun(capture=capture, rules=rules, out=out))
    seconds = time.perf_counter() - start
    events: dict[str, int] = {}
    with (out / "eve.json").open(encoding="utf-8") as eve:
        for line in eve:
            kind = json.loads(line)["event_type"]
            events[kind] = events.get(kind, 0) + 1
    return {"suricata": record["suricata"], "rules": rules.name, "seconds": seconds,
            "eve_bytes": (out / "eve.json").stat().st_size, "eve_events": events,
            "files_bytes": {p.name: p.stat().st_size for p in sorted(out.iterdir())}}


def lab_files() -> dict:
    """The committed lab feature files: real flows, unlike the repeated copies,
    which compress far better than real traffic would."""
    paths = sorted(FIXTURES.glob("lab-*.parquet"))
    size, rows = sum(p.stat().st_size for p in paths), len(read_flows(*paths).frame)
    return {"files": [p.name for p in paths], "bytes": size, "flows": rows,
            "bytes_per_flow": size / rows}


def main(out: Path, flagmand: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    capture = out / f"lab-x{COPIES}.pcap"
    written = repeat([LAB / name for name in CAPTURES], COPIES, capture)
    result = {
        "note": "a pipeline check (repeated lab captures, made-up training flows), not a result",
        "machine": {"cpus": os.cpu_count(), "system": platform.platform()},
        "capture": {"copies": COPIES, "of": CAPTURES, "packets": written},
        "extract": extract(flagmand, capture, out / "flows.parquet"),
        "lab_feature_files": lab_files(),
        "suricata": suricata(capture, out / "suricata"),
        "training": [json.loads(subprocess.run(
            [sys.executable, str(HERE / "train_memory.py"), str(n)], check=True,
            capture_output=True, text=True).stdout) for n in TRAINING_FLOWS],
    }
    (out / "sizing.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]), Path(sys.argv[2])), indent=2, sort_keys=True))
