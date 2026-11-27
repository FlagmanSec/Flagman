import json
import sys
from pathlib import Path

import pytest

from flagman_ml.files import sha256_of
from flagman_ml.suricata.run import (
    SuricataFailed,
    SuricataRun,
    command,
    read_record,
    run_suricata,
)
from flagman_ml.testing import fixture

# A stand-in for Suricata, so that these tests run where Suricata is not
# installed (CI): it answers -V, and copies a recorded EVE file into the
# -l folder ("ok"), writes nothing ("no-eve"), or fails ("fail").
STAND_IN = """
import shutil, sys
args = sys.argv[1:]
if args == ["-V"]:
    print("stand-in for Suricata, tests only")
    sys.exit(0)
if "{mode}" == "fail":
    sys.exit(3)
if "{mode}" == "ok":
    shutil.copy({eve!r}, args[args.index("-l") + 1] + "/eve.json")
"""


def stand_in(tmp_path: Path, mode: str) -> tuple[str, ...]:
    script = tmp_path / f"suricata-{mode}.py"
    eve = str(fixture("suricata/lab-ssh-logins/eve.json.gz"))
    script.write_text(STAND_IN.format(mode=mode, eve=eve), encoding="utf-8")
    return (sys.executable, str(script))


def inputs(tmp_path: Path) -> tuple[Path, Path]:
    capture, config = tmp_path / "day.pcap", tmp_path / "suricata.yaml"
    capture.write_bytes(b"not read by the stand-in")
    config.write_text("%YAML 1.1\n", encoding="utf-8")
    return capture, config


def test_the_command_line_is_the_documented_one():
    run = SuricataRun(Path("day.pcap"), Path("local.rules"), Path("out"))
    assert command(run) == ["suricata", "-c", "/etc/suricata/suricata.yaml", "-r", "day.pcap",
                            "-S", "local.rules", "-l", "out", "-k", "none",
                            "--runmode", "single"]
    homed = SuricataRun(Path("day.pcap"), Path("local.rules"), Path("out"),
                        home_net="[10.0.0.0/8]")
    assert command(homed)[-2:] == ["--set", "vars.address-groups.HOME_NET=[10.0.0.0/8]"]


def test_a_run_records_the_version_the_command_and_the_checksums(tmp_path):
    capture, config = inputs(tmp_path)
    rules = fixture("suricata/local.rules")
    run = SuricataRun(capture, rules, tmp_path / "out", config, None, stand_in(tmp_path, "ok"))
    record = run_suricata(run)
    assert record["suricata"] == "stand-in for Suricata, tests only"
    assert record["capture"] == {"name": "day.pcap", "sha256": sha256_of(capture)}
    assert record["rules"] == {"name": "local.rules", "sha256": sha256_of(rules)}
    assert record["config"]["sha256"] == sha256_of(config)
    assert record["command"] == command(run)
    assert (tmp_path / "out" / "eve.json").is_file()
    assert json.loads((tmp_path / "out" / "run.json").read_text()) == record
    assert read_record(tmp_path / "out" / "eve.json") == record
    assert read_record(tmp_path / "eve.json") is None


@pytest.mark.parametrize("mode, message", [("fail", "stopped with code 3"),
                                           ("no-eve", "wrote no")])
def test_a_failed_run_says_so(tmp_path, mode, message):
    capture, config = inputs(tmp_path)
    run = SuricataRun(capture, fixture("suricata/local.rules"), tmp_path / "out", config, None,
                      stand_in(tmp_path, mode))
    with pytest.raises(SuricataFailed, match=message):
        run_suricata(run)
    assert not (tmp_path / "out" / "run.json").exists()


def test_a_missing_capture_is_refused_before_running(tmp_path):
    run = SuricataRun(tmp_path / "none.pcap", fixture("suricata/local.rules"), tmp_path / "out")
    with pytest.raises(FileNotFoundError, match="none.pcap"):
        run_suricata(run)
