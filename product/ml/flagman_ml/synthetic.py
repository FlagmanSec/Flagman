"""Made-up flows with the real feature schema, for tests only.

The lab files are real but tiny (53 normal flows), so the model tests use
flows drawn at random from simple rules instead: each class gets its own
typical values (a scan sends one or two packets and gets no answer; a
password guess lasts about three seconds; normal traffic varies a lot).
Nothing here describes real traffic, and no result is ever computed on it.

Example::

    frame, schema = synthetic_flows({"normal": 300, "scan": 100}, seed=1)
    frame["label"].value_counts()   # normal 300, scan 100
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from flagman_ml.flows import Schema, read_footer
from flagman_ml.testing import fixture

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
