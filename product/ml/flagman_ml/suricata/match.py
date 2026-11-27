"""Which Flagman flow each Suricata alert belongs to.

Suricata raises an alert on one packet, and the alert's time is that
packet's time. Flagman cuts packet times to whole milliseconds
(``flagman-core/src/time.rs``), and a flow's ``flow_start_ms`` and
``flow_end_ms`` are the times of its first and last packets. So the flow
that holds the packet:

1. has the same protocol and the same two ends, in either direction (the
   ports too, when the alert gives them);
2. holds the alert's time, cut to the millisecond, between its start and
   its end (each side widened by ``tolerance_ms``, 0 by default).

This is the rule of ``labels/match.py``, with each alert as a record that
lasts no time. If two flows qualify (the same ends used again within the
tolerance), the one whose time span holds the alert wins, then the nearer
one, then the first. Suricata's ``flow_id`` is not used: two runs of the
same capture gave the same alerts with other ``flow_id`` values.

An alert that matches no flow is counted as unmatched, never dropped
silently: it is a packet that Suricata saw and that no Flagman flow holds.

Each flow then gets ``suricata_alerts`` (how many alerts it holds) and
``suricata_signatures`` (the numbers of the rules that fired, sorted). A
flow with at least one alert counts as "Suricata raised an alert": the same
yes or no as Flagman's decision, so both are scored the same way.

Example::

    found = match_alerts(flows.frame, read_alerts("eve.json"))
    table = per_flow(flows.frame, alerts, found)
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from flagman_ml.labels.match import candidate_pairs

MATCH_COLUMNS = ["source", "row", "suricata_alerts", "suricata_signatures"]


def match_alerts(flows: pd.DataFrame, alerts: pd.DataFrame, tolerance_ms: int = 0) -> np.ndarray:
    """For each alert, the position of its flow in ``flows`` (-1 when none)."""
    if tolerance_ms < 0:
        raise ValueError("tolerance_ms cannot be negative")
    found = np.full(len(alerts), -1, dtype="int64")
    if alerts.empty or flows.empty:
        return found
    at_ms = alerts["time_us"].to_numpy() // 1000
    events = pd.DataFrame({
        "start_ms": at_ms, "end_ms": at_ms, "protocol": alerts["protocol"].to_numpy(),
        "src_ip": alerts["src_ip"].to_numpy(), "src_port": alerts["src_port"].to_numpy(),
        "dst_ip": alerts["dst_ip"].to_numpy(), "dst_port": alerts["dst_port"].to_numpy()})
    pairs = candidate_pairs(flows, events, offset_ms=0, tolerance_ms=tolerance_ms)
    if pairs.empty:
        return found
    before = pairs["flow_start_ms"] - pairs["start_ms"]
    after = pairs["start_ms"] - pairs["flow_end_ms"]
    pairs = pairs.assign(distance=np.maximum(np.maximum(before, after), 0))
    best = pairs.sort_values(["event", "distance", "flow"]).drop_duplicates("event")
    found[best["event"].to_numpy()] = best["flow"].to_numpy()
    return found


def per_flow(flows: pd.DataFrame, alerts: pd.DataFrame, found: np.ndarray) -> pd.DataFrame:
    """One row per flow: source, row, how many alerts it holds, and their rules."""
    matched = found >= 0
    counts = np.bincount(found[matched], minlength=len(flows)).astype("int64")
    signatures = [""] * len(flows)
    ids = alerts["signature_id"].to_numpy()[matched]
    for flow, group in pd.Series(ids).groupby(found[matched]):
        signatures[int(flow)] = ",".join(str(sid) for sid in sorted(set(group)))
    return pd.DataFrame({"source": flows["source"].to_numpy(), "row": flows["row"].to_numpy(),
                         "suricata_alerts": counts, "suricata_signatures": signatures},
                        columns=MATCH_COLUMNS)


def counts(alerts: pd.DataFrame, found: np.ndarray, table: pd.DataFrame) -> dict:
    """What the matching did, for the match file's footer and the report."""
    matched = found >= 0
    by_rule = alerts["signature_id"].value_counts().sort_index()
    return {"alerts": int(len(alerts)), "matched": int(matched.sum()),
            "unmatched": int((~matched).sum()), "flows": int(len(table)),
            "flows_alerted": int((table["suricata_alerts"] > 0).sum()),
            "alerts_by_rule": {str(sid): int(n) for sid, n in by_rule.items()},
            "unmatched_lines": [int(n) for n in alerts["line"].to_numpy()[~matched][:20]]}
