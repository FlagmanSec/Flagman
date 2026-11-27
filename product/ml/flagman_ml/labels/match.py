"""Match flows with ground-truth records by addresses, ports and time.

A flow matches a record when:

1. the two ends agree, in either direction (a dataset may write the
   answering side first, while Flagman's ``src`` is the side that sent the
   first packet);
2. the ports agree where the record gives them (an empty port matches any);
3. the protocols agree where the record gives one;
4. the times overlap, once the record's window is moved by the mapping's
   offset and widened by its tolerance on both sides.

When several records match one flow, the most specific wins (the one that
gives the most of: source port, destination port, protocol), then the one
that overlaps the flow for longest, then the first one read. A flow whose
candidates lead to different classes is marked as a conflict, so it can
be left out or checked by hand.

Example: the record "192.168.77.66 -> 192.168.77.10 port 22, any source
port, 18:09:37.217 to 18:09:41.431" matches each of the 15 SSH connections
of the lab attack chain, and nothing else in that capture.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

FLOW_COLUMNS = ["protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                "flow_start_ms", "flow_end_ms"]
PAIR_COLUMNS = ["flow", "event", "specificity", "lo_ms", "hi_ms",
                "flow_start_ms", "flow_end_ms", "start_ms", "end_ms"]
ENDS = ["protocol", "src_ip", "src_port", "dst_ip", "dst_port"]


def key_pairs(flows: pd.DataFrame, events: pd.DataFrame, tolerance_ms: int) -> pd.DataFrame:
    """Every (flow, record) pair whose ends, ports and protocol agree.

    ``flow`` and ``event`` are positions in the two tables. ``lo_ms`` and
    ``hi_ms`` bound the time offsets for which the pair's times overlap:
    the pair matches at offset ``o`` when ``lo_ms <= o <= hi_ms``.
    """
    f = flows[FLOW_COLUMNS].reset_index(drop=True)
    f["protocol"] = f["protocol"].astype(str)
    f["flow"] = np.arange(len(f))
    e = events.reset_index(drop=True).rename(columns={c: "ev_" + c for c in ENDS})
    e["event"] = np.arange(len(e))
    exact = e["ev_src_port"].notna() & e["ev_dst_port"].notna()
    pairs = pd.concat([_exact(f, e[exact]), _loose(f, e[~exact])], ignore_index=True)
    same_protocol = pairs["ev_protocol"].isna() | (pairs["ev_protocol"] == pairs["protocol"])
    pairs = pairs[same_protocol.astype(bool)].copy()
    pairs["specificity"] = (
        pairs["ev_src_port"].notna().astype(int)
        + pairs["ev_dst_port"].notna().astype(int)
        + pairs["ev_protocol"].notna().astype(int)
    )
    pairs["lo_ms"] = pairs["flow_start_ms"] - pairs["end_ms"] - tolerance_ms
    pairs["hi_ms"] = pairs["flow_end_ms"] - pairs["start_ms"] + tolerance_ms
    return pairs[PAIR_COLUMNS].astype({"flow": "int64", "event": "int64"})


def candidate_pairs(
    flows: pd.DataFrame, events: pd.DataFrame, offset_ms: int = 0, tolerance_ms: int = 0
) -> pd.DataFrame:
    """The pairs that match at this offset, with how long they overlap."""
    pairs = key_pairs(flows, events, tolerance_ms)
    pairs = pairs[(pairs["lo_ms"] <= offset_ms) & (offset_ms <= pairs["hi_ms"])].copy()
    start, end = pairs["start_ms"] + offset_ms, pairs["end_ms"] + offset_ms
    pairs["overlap_ms"] = np.minimum(pairs["flow_end_ms"], end) - np.maximum(
        pairs["flow_start_ms"], start
    )
    return pairs


def best_match(pairs: pd.DataFrame, event_classes: np.ndarray, flows: int) -> pd.DataFrame:
    """For each flow: the winning record (-1 for none), the number of
    candidates, and whether the candidates disagree on the class."""
    result = pd.DataFrame(
        {"event": np.full(flows, -1, dtype="int64"),
         "candidates": np.zeros(flows, dtype="int64"),
         "conflict": np.zeros(flows, dtype=bool)}
    )
    if pairs.empty:
        return result
    pairs = pairs.assign(cls=np.asarray(event_classes)[pairs["event"].to_numpy()])
    ranked = pairs.sort_values(
        ["flow", "specificity", "overlap_ms", "event"], ascending=[True, False, False, True]
    )
    best = ranked.drop_duplicates("flow")
    per_flow = pairs.groupby("flow")
    count, classes = per_flow.size(), per_flow["cls"].nunique()
    result.loc[best["flow"].to_numpy(), "event"] = best["event"].to_numpy()
    result.loc[count.index, "candidates"] = count.to_numpy()
    result.loc[classes.index, "conflict"] = classes.to_numpy() > 1
    return result


def _endpoint(ip: pd.Series, port: pd.Series) -> pd.Series:
    return ip.astype(str) + "|" + port.astype("Int64").astype(str)


def _unordered(a: pd.Series, b: pd.Series) -> pd.Series:
    """One key for a pair of ends, whatever their order."""
    return pd.Series(np.where(a <= b, a + "~" + b, b + "~" + a), index=a.index, dtype=str)


def _exact(f: pd.DataFrame, e: pd.DataFrame) -> pd.DataFrame:
    """Records with both ports: the two (address, port) ends must agree."""
    f_key = _unordered(_endpoint(f["src_ip"], f["src_port"]), _endpoint(f["dst_ip"], f["dst_port"]))
    e_key = _unordered(
        _endpoint(e["ev_src_ip"], e["ev_src_port"]), _endpoint(e["ev_dst_ip"], e["ev_dst_port"])
    )
    return f.assign(key=f_key).merge(e.assign(key=e_key), on="key")


def _loose(f: pd.DataFrame, e: pd.DataFrame) -> pd.DataFrame:
    """Records with an empty port: match the addresses, then the given ports."""
    f_key = _unordered(f["src_ip"].astype(str), f["dst_ip"].astype(str))
    e_key = _unordered(e["ev_src_ip"].astype(str), e["ev_dst_ip"].astype(str))
    m = f.assign(key=f_key).merge(e.assign(key=e_key), on="key")

    def port_ok(rule: str, port: str) -> pd.Series:
        return (m[rule].isna() | (m[rule] == m[port])).fillna(False).astype(bool)

    forward = (m["src_ip"] == m["ev_src_ip"]) & port_ok("ev_src_port", "src_port") & port_ok(
        "ev_dst_port", "dst_port"
    )
    backward = (m["src_ip"] == m["ev_dst_ip"]) & port_ok("ev_src_port", "dst_port") & port_ok(
        "ev_dst_port", "src_port"
    )
    return m[forward | backward]
