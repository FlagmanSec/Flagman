"""Made-up flows with the real feature schema, for tests only.

The lab files are real but tiny (53 normal flows), so the model tests use
flows drawn at random from simple rules instead: each class gets its own
typical values (a scan sends one or two packets and gets no answer; a
password guess lasts about three seconds; normal traffic varies a lot).
Nothing here describes real traffic, and no result is ever computed on it.

``write_day`` writes such flows as a real feature file (the lab files'
footer, made-up metadata on a given day) and returns their labels;
``write_labels`` writes the matching labels file. Together they let the
evaluation's tests split by day without any real dataset. ``write_eve``
writes made-up Suricata alerts for chosen flows of such a file, in the
EVE format that Suricata 7.0.3 wrote for the lab captures
(fixtures/suricata): no Suricata ran on made-up flows.

Example::

    frame, schema = synthetic_flows({"normal": 300, "scan": 100}, seed=1)
    frame["label"].value_counts()   # normal 300, scan 100
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from flagman_ml.files import sha256_of
from flagman_ml.flows import Schema, read_footer
from flagman_ml.labels import store
from flagman_ml.testing import fixture

DAY_MS = 86_400_000

# Typical values per class: (packets sent, packets answered, duration in ms,
# TCP outcome, destination port class).
PROFILES = {
    "normal": (20, 18, 3000.0, "established", "registered"),
    "scan": (1, 1, 1.0, "half_open", "well_known"),
    "brute_force": (14, 13, 3100.0, "established", "well_known"),
    "dos": (400, 0, 60000.0, "unanswered", "well_known"),
}


def lab_schema() -> Schema:
    return read_footer(fixture("lab-ssh-logins.parquet")).schema


def synthetic_flows(
    counts: dict[str, int], seed: int = 0, source: str = "synthetic.parquet",
    shortcut: str | None = None,
) -> tuple[pd.DataFrame, Schema]:
    """A flows table (source, row, features, label) with ``counts`` rows per class.

    ``shortcut`` names a feature that gets a different fixed value per
    class: a planted testbed fingerprint, for the shortcut audit's tests.
    """
    schema = lab_schema()
    rng = np.random.default_rng(seed)
    parts = [_class_rows(name, n, rng, schema) for name, n in counts.items()]
    frame = pd.concat(parts, ignore_index=True)
    if shortcut:
        codes = {name: float(i * 1000 + 7) for i, name in enumerate(counts)}
        frame[shortcut] = frame["label"].map(codes).astype(frame[shortcut].dtype)
    frame.insert(0, "source", source)
    frame.insert(1, "row", np.arange(len(frame), dtype="int64"))
    for name, categories in schema.categories().items():
        frame[name] = pd.Categorical(frame[name], categories=list(categories))
    return frame, schema


def _class_rows(name: str, n: int, rng: np.random.Generator, schema: Schema) -> pd.DataFrame:
    sent, answered, duration, outcome, port_class = PROFILES[name]
    spread = 0.5 if name == "normal" else 0.1  # normal traffic varies most
    fwd = np.maximum(1, rng.poisson(sent * rng.lognormal(0, spread, n)))
    rev = rng.poisson(answered * rng.lognormal(0, spread, n)) if answered else np.zeros(n, int)
    values: dict[str, object] = {}
    for feature in schema.features:
        if feature.kind == "category":
            values[feature.name] = [feature.categories[0]] * n
        elif feature.kind == "count":
            values[feature.name] = rng.poisson(1, n).astype("int64")
        else:
            values[feature.name] = rng.lognormal(3, 1, n)
    values.update(
        protocol=["tcp"] * n, tcp_outcome=[outcome] * n, dst_port_class=[port_class] * n,
        packets_fwd=fwd.astype("int64"), packets_rev=rev.astype("int64"),
        duration_ms=(duration * rng.lognormal(0, spread, n)).astype("int64"),
        syn_fwd=np.ones(n, dtype="int64"),
        payload_bytes_fwd=(fwd * rng.integers(0, 300, n)).astype("int64"),
        packets_share_rev=rev / (fwd + rev),
    )
    if not answered:  # a side that sent nothing has no timing to describe
        for side in ("gap_min_ms_rev", "gap_max_ms_rev", "gap_mean_ms_rev", "gap_std_ms_rev"):
            values[side] = np.full(n, np.nan)
    frame = pd.DataFrame(values)[schema.feature_names]
    frame["label"] = name
    return frame


def write_day(path: Path, counts: dict[str, int], seed: int, day: int) -> pd.Series:
    """A feature file of made-up flows on day ``day``; returns their labels."""
    frame, schema = synthetic_flows(counts, seed=seed, source=path.name)
    rng = np.random.default_rng(seed + 10_000)
    start = day * DAY_MS + np.sort(rng.integers(0, DAY_MS - 600_000, len(frame)))
    frame = frame.assign(
        flow_start_ms=start, flow_end_ms=start + frame["duration_ms"].to_numpy(),
        src_ip=[f"10.0.{i % 200}.{i % 250 + 1}" for i in range(len(frame))],
        src_port=rng.integers(1024, 65535, len(frame)).astype("int32"),
        dst_ip="10.1.0.1", dst_port=np.full(len(frame), 22, dtype="int32"), end_reason="closed")
    for name in schema.categories():
        frame[name] = frame[name].astype(object)
    template = pq.read_schema(fixture("lab-ssh-logins.parquet"))
    footer = dict(template.metadata)
    footer[b"flagman.source"] = path.with_suffix(".pcap").name.encode()
    table = pa.Table.from_pandas(frame[schema.columns], schema=template.remove_metadata(),
                                 preserve_index=False)
    pq.write_table(table.replace_schema_metadata(footer), path)
    return frame["label"]


def write_eve(path: Path, flows: Path, alerted: np.ndarray, signature_id: int = 1000001) -> None:
    """Made-up Suricata alerts, one per flow where ``alerted`` is true, each at
    its flow's first packet; plus one line of another event type."""
    frame = pq.read_table(flows).to_pandas()
    lines = [json.dumps({"timestamp": "1970-01-01T00:00:00.000000+0000", "event_type": "stats"})]
    for flow in frame[np.asarray(alerted, dtype=bool)].itertuples():
        moment = datetime.fromtimestamp(flow.flow_start_ms / 1000, UTC)
        lines.append(json.dumps({
            "timestamp": moment.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"), "event_type": "alert",
            "src_ip": flow.src_ip, "src_port": int(flow.src_port), "dest_ip": flow.dst_ip,
            "dest_port": int(flow.dst_port), "proto": str(flow.protocol).upper(),
            "alert": {"action": "allowed", "gid": 1, "signature_id": signature_id, "rev": 1,
                      "signature": "made-up alert", "category": "", "severity": 2}}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_labels(path: Path, labelled: dict[Path, pd.Series]) -> None:
    """A labels file for feature files written by ``write_day``."""
    parts = [pd.DataFrame({"source": flows.name, "row": np.arange(len(labels), dtype="int64"),
                           "label": labels.to_numpy(), "dataset_label": labels.to_numpy(),
                           "record": "", "candidates": 1, "conflict": False})
             for flows, labels in labelled.items()]
    store.write_labels(pd.concat(parts, ignore_index=True), path, {
        "mapping": {"dataset": "synthetic", "name": "made up by synthetic.py"},
        "flow_files": [{"name": f.name, "sha256": sha256_of(f)} for f in labelled]})
