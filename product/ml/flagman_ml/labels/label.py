"""Label the flows of one feature file with a dataset's ground truth.

Example::

    flows = read_flows("fixtures/lab-ssh-logins.parquet")
    mapping = load_mapping("data/labels/lab.toml")
    events = read_ground_truth(mapping.format, "fixtures/lab-ground-truth.csv")
    labels, report = label_flows(flows.frame, events, mapping)
    report["labels"]   # {'brute_force': 13, 'normal': 11}

The labels table has one row per flow:

============== ==========================================================
source, row    which flow (the feature file's name and the row in it)
label          the Flagman class
dataset_label  the dataset's own label (empty when no record matched)
record         the winning record, as "file:position" (empty when none)
candidates     how many records matched the flow
conflict       true when the candidates lead to different classes
============== ==========================================================
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from flagman_ml.labels.mapping import Mapping
from flagman_ml.labels.match import best_match, candidate_pairs

LABEL_COLUMNS = ["source", "row", "label", "dataset_label", "record", "candidates", "conflict"]


def label_flows(
    frame: pd.DataFrame, events: pd.DataFrame, mapping: Mapping
) -> tuple[pd.DataFrame, dict]:
    """Label every flow of ``frame`` (from read_flows) and count the outcome."""
    events = in_time_span(events, frame, mapping)
    classes = mapping.classes_of(events["label"]).to_numpy(dtype=object)
    pairs = candidate_pairs(frame, events, mapping.time_offset_ms, mapping.time_tolerance_ms)
    best = best_match(pairs, classes, len(frame))
    won = best["event"].to_numpy()
    matched = won >= 0
    names = (events["file"] + ":" + events["record"].astype(str)).to_numpy(dtype=object)

    def pick(values: np.ndarray, default: object) -> np.ndarray:
        if len(values) == 0:
            return np.full(len(frame), default, dtype=object)
        return np.where(matched, values[np.where(matched, won, 0)], default)

    labels = pd.DataFrame({
        "source": frame["source"].to_numpy(dtype=object),
        "row": frame["row"].to_numpy(dtype="int64"),
        "label": pick(classes, mapping.default_label),
        "dataset_label": pick(events["label"].to_numpy(dtype=object), None),
        "record": pick(names, None),
        "candidates": best["candidates"].to_numpy(),
        "conflict": best["conflict"].to_numpy(),
    })
    return labels, summarise(labels, len(events), mapping)


def in_time_span(events: pd.DataFrame, frame: pd.DataFrame, mapping: Mapping) -> pd.DataFrame:
    """Only the records whose window can touch these flows' time span."""
    if frame.empty:
        return events.iloc[0:0]
    margin = mapping.time_tolerance_ms
    first = frame["flow_start_ms"].min() - mapping.time_offset_ms - margin
    last = frame["flow_end_ms"].max() - mapping.time_offset_ms + margin
    keep = (events["end_ms"] >= first) & (events["start_ms"] <= last)
    return events[keep].reset_index(drop=True)


def summarise(labels: pd.DataFrame, records_in_span: int, mapping: Mapping) -> dict:
    """The counts that every labelling run reports.

    ``records_in_span`` counts the records whose window falls in the
    capture's time span; ``records_used`` those that labelled at least one
    flow. Many unused records can mean a wrong time offset (see offset.py)
    or records of traffic that the capture does not hold.
    """
    matched = labels["record"].notna()
    counts = labels["label"].value_counts()
    return {
        "dataset": mapping.dataset,
        "flows": int(len(labels)),
        "matched": int(matched.sum()),
        "unmatched": int((~matched).sum()),
        "default_label": mapping.default_label,
        "conflicts": int(labels["conflict"].sum()),
        "labels": {name: int(counts[name]) for name in sorted(counts.index)},
        "records_in_span": int(records_in_span),
        "records_used": int(labels.loc[matched, "record"].nunique()),
    }
