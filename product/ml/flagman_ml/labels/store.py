"""Labels files: one row per flow, and where every label comes from.

A labels file is a Parquet file with the columns of ``label.LABEL_COLUMNS``.
Its footer (key ``flagman.labels``) records, as JSON:

- the mapping file (name, checksum, dataset, source link);
- every ground-truth file (name, checksum, number of records);
- every feature file (name, checksum, rows, capture);
- the counts of the run (see ``label.summarise``).

``attach_labels`` joins labels to flows by ``(source, row)``, and refuses
when a feature file's checksum differs from the one recorded: labels are
never joined to a different extraction of the same capture.

Example::

    flows = read_flows(*lab_files)
    frame = attach_labels(flows, "results/labels/lab.parquet")
    frame["label"].value_counts()
"""

from __future__ import annotations

import os

import pandas as pd

from flagman_ml.files import read_table, write_table
from flagman_ml.flows import Flows

KEY = "flagman.labels"


class LabelsMismatch(ValueError):
    """Labels that do not describe these feature files."""


def write_labels(labels: pd.DataFrame, path: str | os.PathLike, provenance: dict) -> None:
    """Write a labels file; the same inputs always give the same bytes."""
    write_table(labels, path, KEY, provenance)


def read_labels(path: str | os.PathLike) -> tuple[pd.DataFrame, dict]:
    """A labels file and its provenance."""
    found = read_table(path, KEY)
    if found is None:
        raise LabelsMismatch(f"{path}: not a Flagman labels file")
    return found


def attach_labels(flows: Flows, path: str | os.PathLike) -> pd.DataFrame:
    """The flows table with the label columns joined by (source, row)."""
    labels, provenance = read_labels(path)
    recorded = {item["name"]: item["sha256"] for item in provenance["flow_files"]}
    for file in flows.files:
        if file.name not in recorded:
            raise LabelsMismatch(f"{path}: has no labels for {file.name}")
        if recorded[file.name] != file.sha256:
            raise LabelsMismatch(
                f"{file.name} changed since it was labelled (checksum differs): label it again"
            )
    joined = flows.frame.merge(labels, on=["source", "row"], how="left", validate="one_to_one")
    if joined["label"].isna().any():
        raise LabelsMismatch(f"{path}: some flows have no label row")
    return joined
