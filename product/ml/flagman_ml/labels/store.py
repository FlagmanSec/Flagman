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

import json
import os
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from flagman_ml.files import replace_atomically
from flagman_ml.flows import Flows

KEY = "flagman.labels"


class LabelsMismatch(ValueError):
    """Labels that do not describe these feature files."""


def write_labels(labels: pd.DataFrame, path: str | os.PathLike, provenance: dict) -> None:
    """Write a labels file; the same inputs always give the same bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pandas(labels, preserve_index=False)
    table = table.replace_schema_metadata({KEY: json.dumps(provenance, sort_keys=True)})
    tmp = path.with_name(path.name + ".part")
    pq.write_table(table, tmp)
    replace_atomically(tmp, path)


def read_labels(path: str | os.PathLike) -> tuple[pd.DataFrame, dict]:
    """A labels file and its provenance."""
    table = pq.read_table(path)
    metadata = table.schema.metadata or {}
    if KEY.encode() not in metadata:
        raise LabelsMismatch(f"{path}: not a Flagman labels file")
    provenance = json.loads(metadata[KEY.encode()])
    return table.replace_schema_metadata(None).to_pandas(), provenance


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
