"""Readers for each dataset's ground truth, into one common table.

Every reader returns one row per ground-truth record ("event"), with:

========== ==============================================================
start_ms   start of the record, milliseconds since 1970-01-01 UTC
end_ms     end of the record (rounded up, so the window covers it all)
protocol   tcp, udp, icmp or other; empty means any protocol
src_ip     one end of the conversation (as the dataset writes it)
src_port   its port; empty means any port
dst_ip     the other end
dst_port   its port; empty means any port
label      the dataset's own label, mapped to a class later
file       the ground-truth file's name
record     the record's position in that file, from 1 (header not counted)
========== ==============================================================

ICMP and other records always get empty ports: Flagman writes port 0 for
them, while datasets write ICMP types and codes in many ways.

Formats (the ``format`` key of a mapping file):

- ``lab_csv``: our own lab ground truth (fixtures/README.md).
- ``unsw_gt``: the UNSW-NB15 ground truth CSV.
- ``cic_flows``: CICFlowMeter CSVs, as in CIC-IDS2017.
- ``ctu_binetflow``: the labelled Argus flows of CTU-13.

The column names come from each dataset's documentation (see
product/ml/data/README.md, which says which ones are not yet verified).
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pandas as pd

ANY = {"", "-", "*", "any"}
PROTOCOLS = {
    "tcp": "tcp", "6": "tcp",
    "udp": "udp", "17": "udp",
    "icmp": "icmp", "1": "icmp", "ipv6-icmp": "icmp", "icmp6": "icmp", "icmpv6": "icmp",
    "58": "icmp",
}
EVENT_COLUMNS = [
    "file", "record", "start_ms", "end_ms", "protocol",
    "src_ip", "src_port", "dst_ip", "dst_port", "label",
]
EPOCH = pd.Timestamp(0, tz="UTC")
MILLISECOND = pd.Timedelta(milliseconds=1)


def epoch_ms(times: pd.Series, round_up: bool = False) -> pd.Series:
    """Datetimes with a time zone, as whole milliseconds since 1970 (UTC)."""
    delta = times - EPOCH
    if round_up:
        return (-((-delta) // MILLISECOND)).astype("int64")
    return (delta // MILLISECOND).astype("int64")


def local_times(text: pd.Series, time_zone: str, time_format: str | None) -> pd.Series:
    """Parse dates; dates written without a zone are taken in ``time_zone``."""
    parsed = pd.to_datetime(text, format=time_format or "ISO8601")
    if parsed.dt.tz is None:
        return parsed.dt.tz_localize(time_zone, ambiguous="raise", nonexistent="raise")
    return parsed.dt.tz_convert("UTC")


def parse_ports(values: pd.Series, where: str) -> pd.Series:
    """Ports as whole numbers: decimal or hexadecimal ("0x0016"); empty means any."""
    text = values.fillna("").astype(str).str.strip().str.lower()
    ports = pd.Series(pd.NA, index=values.index, dtype="Int64")
    hexadecimal = text.str.startswith("0x")
    ports[hexadecimal] = [int(t, 16) for t in text[hexadecimal]]
    decimal = ~hexadecimal & ~text.isin(ANY)
    try:
        ports[decimal] = pd.to_numeric(text[decimal]).astype("Int64")
    except (ValueError, TypeError):
        raise ValueError(f"{where}: a port is not a number") from None
    if ((ports < 0) | (ports > 65535)).fillna(False).any():
        raise ValueError(f"{where}: a port is outside 0-65535")
    return ports


def normalise_protocol(values: pd.Series) -> pd.Series:
    """Protocol names or numbers as tcp, udp, icmp or other (empty = any)."""
    text = values.fillna("").astype(str).str.strip().str.lower()
    names = text.map(PROTOCOLS).fillna("other").astype(object)
    names[text.isin(ANY)] = None
    return names


def require(table: pd.DataFrame, columns: list[str], path: Path) -> None:
    missing = [column for column in columns if column not in table.columns]
    if missing:
        raise ValueError(f"{path.name}: missing columns {missing}")


def read_csv(path: Path, columns: list[str]) -> pd.DataFrame:
    """Read the named columns as text; spaces around column names are ignored."""
    table = pd.read_csv(
        path, dtype=str, keep_default_na=False, encoding_errors="replace",
        usecols=lambda name: name.strip() in columns,
    )
    table.columns = table.columns.str.strip()
    require(table, columns, path)
    blank = (table[columns] == "").all(axis=1)  # empty lines carry nothing
    return table[~blank].reset_index(drop=True)


def read_lab_csv(path: Path, time_zone: str, time_format: str | None) -> pd.DataFrame:
    """Our lab ground truth: one row per attack step, times in UTC (ISO 8601)."""
    columns = ["start_utc", "end_utc", "protocol", "src_ip", "src_port",
               "dst_ip", "dst_port", "label"]
    table = read_csv(path, columns)
    return pd.DataFrame({
        "start_ms": epoch_ms(local_times(table["start_utc"], "UTC", None)),
        "end_ms": epoch_ms(local_times(table["end_utc"], "UTC", None), round_up=True),
        "protocol": table["protocol"], "src_ip": table["src_ip"], "src_port": table["src_port"],
        "dst_ip": table["dst_ip"], "dst_port": table["dst_port"], "label": table["label"],
    })


def read_unsw_gt(path: Path, time_zone: str, time_format: str | None) -> pd.DataFrame:
    """UNSW-NB15 ground truth. Times are whole seconds since 1970, unless the
    mapping gives a ``time_format``; a window covers its whole last second."""
    columns = ["Start time", "Last time", "Attack category", "Protocol",
               "Source IP", "Source Port", "Destination IP", "Destination Port"]
    table = read_csv(path, columns)
    if time_format:
        start = epoch_ms(local_times(table["Start time"], time_zone, time_format))
        end = epoch_ms(local_times(table["Last time"], time_zone, time_format)) + 999
    else:
        first = pd.to_numeric(table["Start time"], errors="coerce")
        last = pd.to_numeric(table["Last time"], errors="coerce")
        if not (first.between(1e9, 4e9).all() and last.between(1e9, 4e9).all()):
            raise ValueError(f"{path.name}: times are not seconds since 1970; set time_format")
        start, end = first.astype("int64") * 1000, last.astype("int64") * 1000 + 999
    return pd.DataFrame({
        "start_ms": start, "end_ms": end, "protocol": table["Protocol"],
        "src_ip": table["Source IP"].str.strip(), "src_port": table["Source Port"],
        "dst_ip": table["Destination IP"].str.strip(), "dst_port": table["Destination Port"],
        "label": table["Attack category"].str.strip(),
    })


def read_cic_flows(path: Path, time_zone: str, time_format: str | None) -> pd.DataFrame:
    """CICFlowMeter CSV: one labelled flow per row. Flow Duration is in
    microseconds. Needs ``time_format``: dates come in more than one style."""
    if not time_format:
        raise ValueError(f"{path.name}: the cic_flows format needs time_format in the mapping")
    columns = ["Source IP", "Source Port", "Destination IP", "Destination Port",
               "Protocol", "Timestamp", "Flow Duration", "Label"]
    table = read_csv(path, columns)
    times = local_times(table["Timestamp"].str.strip(), time_zone, time_format)
    duration = pd.to_timedelta(pd.to_numeric(table["Flow Duration"]).clip(lower=0), unit="us")
    return pd.DataFrame({
        "start_ms": epoch_ms(times), "end_ms": epoch_ms(times + duration, round_up=True),
        "protocol": table["Protocol"], "src_ip": table["Source IP"].str.strip(),
        "src_port": table["Source Port"], "dst_ip": table["Destination IP"].str.strip(),
        "dst_port": table["Destination Port"], "label": table["Label"].str.strip(),
    })


def read_ctu_binetflow(path: Path, time_zone: str, time_format: str | None) -> pd.DataFrame:
    """CTU-13 labelled bidirectional flows (Argus). Dur is in seconds."""
    columns = ["StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "Label"]
    table = read_csv(path, columns)
    times = local_times(table["StartTime"], time_zone, time_format or "%Y/%m/%d %H:%M:%S.%f")
    duration = pd.to_timedelta(pd.to_numeric(table["Dur"]).clip(lower=0), unit="s")
    return pd.DataFrame({
        "start_ms": epoch_ms(times), "end_ms": epoch_ms(times + duration, round_up=True),
        "protocol": table["Proto"], "src_ip": table["SrcAddr"], "src_port": table["Sport"],
        "dst_ip": table["DstAddr"], "dst_port": table["Dport"], "label": table["Label"],
    })


READERS = {
    "lab_csv": read_lab_csv,
    "unsw_gt": read_unsw_gt,
    "cic_flows": read_cic_flows,
    "ctu_binetflow": read_ctu_binetflow,
}


def read_ground_truth(
    fmt: str, path: str | os.PathLike, time_zone: str = "UTC", time_format: str | None = None
) -> pd.DataFrame:
    """Read one ground-truth file into the common event table."""
    path = Path(path)
    events = READERS[fmt](path, time_zone, time_format)
    events["protocol"] = normalise_protocol(events["protocol"])
    events["src_port"] = parse_ports(events["src_port"], path.name)
    events["dst_port"] = parse_ports(events["dst_port"], path.name)
    no_ports = events["protocol"].isin(["icmp", "other"])
    events.loc[no_ports, ["src_port", "dst_port"]] = pd.NA
    events.insert(0, "file", path.name)
    events.insert(1, "record", np.arange(1, len(events) + 1, dtype="int64"))
    backwards = events["end_ms"] < events["start_ms"]
    if backwards.any():
        records = events.loc[backwards, "record"].head(5).tolist()
        raise ValueError(f"{path.name}: records end before they start: {records}")
    return events[EVENT_COLUMNS].reset_index(drop=True)
