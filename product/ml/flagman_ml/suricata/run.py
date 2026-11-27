"""Running Suricata on a capture: the same capture that Flagman read.

``python -m flagman_ml.suricata run`` runs::

    suricata -c <config> -r <capture> -S <rules> -l <out> -k none --runmode single

What each option does, in the words of Suricata's command line
documentation (docs.suricata.io, "Command Line Options") and of
``suricata --list-runmodes`` (7.0.3):

- ``-c``: "Path to configuration file". By default the one the Ubuntu
  package installs, ``/etc/suricata/suricata.yaml``.
- ``-r``: "Run in pcap offline mode (replay mode) reading files from pcap
  file". Times in the alerts are then the packets' times.
- ``-S``: "a file with signatures, which will be loaded exclusively,
  regardless of the rules set in the yaml".
- ``-l``: "the default log directory": where ``eve.json`` is written.
- ``-k none``: "disable (none) all checksum checks". Flagman's packet
  decoder does not check checksums either, so both read the same packets.
- ``--runmode single``: "Single threaded pcap file mode".

``--home-net`` sets Suricata's ``HOME_NET`` address group (through
``--set vars.address-groups.HOME_NET=...``). Many rules only look at
traffic towards ``$HOME_NET``: set it to the networks that the dataset
calls internal. The Ubuntu configuration's default is
``[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]``.

The folder then holds Suricata's output and ``run.json``: Suricata's
version, the command, and the checksums of the capture, the rules and the
configuration. The match command copies ``run.json`` into the Suricata
file, so an evaluation always says which Suricata and which rules it
compared with.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from flagman_ml.files import sha256_of

DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")
RECORD = "run.json"


class SuricataFailed(RuntimeError):
    """Suricata did not finish, or wrote no EVE file."""


@dataclass(frozen=True)
class SuricataRun:
    capture: Path
    rules: Path
    out: Path
    config: Path = DEFAULT_CONFIG
    home_net: str | None = None
    program: tuple[str, ...] = ("suricata",)  # the command that starts Suricata


def command(run: SuricataRun) -> list[str]:
    """The command line, exactly as it is run."""
    args = [*run.program, "-c", str(run.config), "-r", str(run.capture), "-S", str(run.rules),
            "-l", str(run.out), "-k", "none", "--runmode", "single"]
    if run.home_net:
        args += ["--set", f"vars.address-groups.HOME_NET={run.home_net}"]
    return args


def run_suricata(run: SuricataRun) -> dict:
    """Run Suricata, keep what it printed in ``console.txt``, write ``run.json``."""
    for path in (run.capture, run.rules, run.config):
        if not path.is_file():
            raise FileNotFoundError(f"{path}: no such file")
    run.out.mkdir(parents=True, exist_ok=True)
    args = command(run)
    done = subprocess.run(args, capture_output=True, text=True, check=False)
    (run.out / "console.txt").write_text(done.stdout + done.stderr, encoding="utf-8")
    if done.returncode != 0:
        raise SuricataFailed(f"Suricata stopped with code {done.returncode}: "
                             f"see {run.out / 'console.txt'}")
    if not (run.out / "eve.json").is_file():
        raise SuricataFailed(f"Suricata wrote no {run.out / 'eve.json'}: check the eve-log "
                             "output in the configuration")
    record = {
        "suricata": version(run.program),
        "command": args,
        "capture": {"name": run.capture.name, "sha256": sha256_of(run.capture)},
        "rules": {"name": run.rules.name, "sha256": sha256_of(run.rules)},
        "config": {"name": str(run.config), "sha256": sha256_of(run.config)},
        "home_net": run.home_net,
        "recorded_utc": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    (run.out / RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8")
    return record


def version(program: tuple[str, ...]) -> str:
    """What ``suricata -V`` prints, such as "This is Suricata version 7.0.3 RELEASE"."""
    done = subprocess.run([*program, "-V"], capture_output=True, text=True, check=False)
    return (done.stdout or done.stderr).strip()


def read_record(eve: Path) -> dict | None:
    """The ``run.json`` next to an EVE file, if there is one."""
    path = eve.parent / RECORD
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
