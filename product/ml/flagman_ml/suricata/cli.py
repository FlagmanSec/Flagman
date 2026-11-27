"""Command line: ``python -m flagman_ml.suricata`` (run from product/ml).

Run Suricata on a capture (``suricata`` must be installed)::

    python -m flagman_ml.suricata run --capture captures/day4.pcap \\
        --rules /var/lib/suricata/rules/suricata.rules --out results/suricata/day4

Match its alerts to the flows that Flagman extracted from the same capture::

    python -m flagman_ml.suricata match --eve results/suricata/day4/eve.json \\
        --out results/suricata/day4.parquet flows/day4.parquet

``match`` reads ``run.json`` next to the EVE file to record where the
alerts come from. An EVE file without one (written by hand, or by another
tool) needs ``--origin`` to say so in words.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from flagman_ml.files import sha256_of
from flagman_ml.flows import read_flows
from flagman_ml.suricata.eve import read_alerts
from flagman_ml.suricata.match import counts, match_alerts, per_flow
from flagman_ml.suricata.run import DEFAULT_CONFIG, SuricataRun, read_record, run_suricata
from flagman_ml.suricata.store import write_matches


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    target = args.out / "eve.json" if args.command == "run" else args.out
    if target.exists() and not args.overwrite:
        print(f"refusing to replace {target}: add --overwrite", file=sys.stderr)
        return 2
    return {"run": run_command, "match": match_command}[args.command](args)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.suricata",
                                  description="Compare with Suricata on the same captures.")
    commands = top.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run Suricata on one capture")
    run.add_argument("--capture", required=True, type=Path, help="the capture (pcap) file")
    run.add_argument("--rules", required=True, type=Path, help="the rules file to load")
    run.add_argument("--out", required=True, type=Path, help="folder for eve.json and run.json")
    run.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="suricata.yaml")
    run.add_argument("--home-net", help='HOME_NET, such as "[192.168.0.0/16]"')
    run.add_argument("--suricata", default="suricata", help="the Suricata program")
    match = commands.add_parser("match", help="match Suricata's alerts to Flagman's flows")
    match.add_argument("flows", type=Path, help="the feature file of the same capture")
    match.add_argument("--eve", required=True, type=Path, help="Suricata's eve.json (or .gz)")
    match.add_argument("--out", required=True, type=Path, help="the Suricata file to write")
    match.add_argument("--tolerance-ms", type=int, default=0,
                       help="widen each flow's time span by this much on both sides")
    match.add_argument("--origin", help="where the EVE file comes from, when it has no run.json")
    for command in (run, match):
        command.add_argument("--overwrite", action="store_true", help="replace existing outputs")
    return top


def run_command(args: argparse.Namespace) -> int:
    for name in ("eve.json", "run.json"):  # Suricata adds to an existing eve.json
        (args.out / name).unlink(missing_ok=True)
    record = run_suricata(SuricataRun(args.capture, args.rules, args.out, args.config,
                                      args.home_net, (args.suricata,)))
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


def match_command(args: argparse.Namespace) -> int:
    record = read_record(args.eve)
    if record is None and not args.origin:
        print(f"no run.json next to {args.eve}: say where it comes from with --origin",
              file=sys.stderr)
        return 2
    flows = read_flows(args.flows)
    file = flows.files[0]
    if record is not None and record["capture"]["name"] != file.capture:
        print(f"{args.eve} comes from {record['capture']['name']}, but {file.name} from "
              f"{file.capture}: not the same capture", file=sys.stderr)
        return 2
    alerts = read_alerts(args.eve)
    found = match_alerts(flows.frame, alerts, args.tolerance_ms)
    table = per_flow(flows.frame, alerts, found)
    summary = counts(alerts, found, table)
    write_matches(table, args.out, {
        "flow_file": {"name": file.name, "sha256": file.sha256, "rows": file.rows,
                      "capture": file.capture},
        "eve": {"name": args.eve.name, "sha256": sha256_of(args.eve)},
        "run": record, "origin": args.origin, "tolerance_ms": args.tolerance_ms,
        "counts": summary})
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0
