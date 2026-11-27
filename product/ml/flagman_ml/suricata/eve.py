"""Suricata's alerts, read from its EVE file.

Suricata writes what it sees as "EVE JSON": one JSON object per line, each
with an ``event_type``. Only the ``alert`` lines are read here; the others
(flows, statistics, protocol logs) are skipped.

The fields read, as Suricata 7.0.3 wrote them for the lab captures
(``fixtures/suricata/``), with the other fields left out::

    {"timestamp": "2026-11-26T22:16:19.441084+0000", "event_type": "alert",
     "src_ip": "192.168.77.66", "src_port": 37244,
     "dest_ip": "192.168.77.10", "dest_port": 22, "proto": "TCP",
     "alert": {"signature_id": 1000002, "signature": "...", ...}, ...}

``timestamp`` is the time of the packet that raised the alert, with its
time zone offset. Ports are read when the line has them; an alert without
them (ICMP, for example) is matched on addresses and protocol only.

An EVE file is data from outside the program: a line that is not JSON, or
an alert line without these fields, stops the reading and names the line.
Files ending in ``.gz`` are read through gzip.

Example::

    alerts = read_alerts("results/suricata/day4/eve.json")
    alerts["signature_id"].value_counts()
"""

from __future__ import annotations

import gzip
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd

ALERT_COLUMNS = ["line", "time_us", "protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                 "signature_id", "signature"]
# Suricata's protocol names, lower-cased, to Flagman's (the rest is "other").
# Flagman calls ICMP for IPv6 "icmp" too (flagman-core packet/decode.rs).
PROTOCOLS = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "ipv6-icmp": "icmp"}
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class EveError(ValueError):
    """An EVE file that cannot be read as Suricata alerts."""


def read_alerts(path: str | os.PathLike) -> pd.DataFrame:
    """One row per alert line, in file order, with its line number."""
    path = Path(path)
    rows = []
    with _open(path) as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise EveError(f"{path}: line {number} is not JSON ({error.msg})") from None
            if isinstance(record, dict) and record.get("event_type") == "alert":
                rows.append(_alert(record, number, path))
    frame = pd.DataFrame(rows, columns=ALERT_COLUMNS)
    return frame.astype({"line": "int64", "time_us": "int64", "protocol": str, "src_ip": str,
                         "src_port": "Int64", "dst_ip": str, "dst_port": "Int64",
                         "signature_id": "int64", "signature": str})


def time_us(text: str) -> int:
    """Microseconds since 1970-01-01 UTC, from a time like 2026-11-26T22:16:19.441084+0000."""
    moment = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z")
    return (moment - EPOCH) // timedelta(microseconds=1)


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def _alert(record: dict, number: int, path: Path) -> list:
    try:
        alert = record["alert"]
        return [number, time_us(record["timestamp"]),
                PROTOCOLS.get(str(record["proto"]).lower(), "other"),
                str(record["src_ip"]), _port(record.get("src_port")),
                str(record["dest_ip"]), _port(record.get("dest_port")),
                int(alert["signature_id"]), str(alert.get("signature", ""))]
    except (KeyError, TypeError, ValueError) as error:
        raise EveError(f"{path}: line {number} is not a complete alert ({error!r})") from None


def _port(value) -> int | None:
    if value is None:
        return None
    port = int(value)
    if not 0 <= port <= 65535:
        raise ValueError(f"port {port} out of range")
    return port
