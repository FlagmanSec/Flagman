"""Read feature files into one pandas table.

Example::

    flows = read_flows("fixtures/lab-ssh-logins.parquet")
    len(flows.frame)            # 24 flows, one per SSH connection
    flows.inputs().shape        # (24, 37): the model inputs only

Every row gets two extra columns that name it for good:

- ``source``: the feature file's name, such as ``lab-ssh-logins.parquet``;
- ``row``: the row's position in that file, from 0.

Labels and predictions are joined back to flows by ``(source, row)``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from flagman_ml.files import sha256_of
from flagman_ml.flows.schema import Footer, Schema, SchemaError, read_footer


@dataclass(frozen=True)
class FlowFile:
    """One feature file that was read."""

    name: str  # the file's name, used as `source`
    path: Path
    rows: int
    sha256: str  # checksum of the file's bytes
    capture: str  # the capture it was extracted from
    writer: str  # the program and version that wrote it


@dataclass
class Flows:
    """Flows from one or more feature files, with their shared schema."""

    frame: pd.DataFrame  # source, row, the metadata columns, the features
    schema: Schema
    flow_table: dict
    files: list[FlowFile] = field(default_factory=list)

    def inputs(self) -> pd.DataFrame:
        """The model inputs: exactly the features listed in the footer.

        Never use "all columns": the metadata columns (addresses, ports,
        times) would let a model learn the lab instead of the attack.
        """
        return self.frame[self.schema.feature_names]


def read_flows(*paths: str | os.PathLike) -> Flows:
    """Read one or more feature files that share the same schema.

    The files must have the same feature schema and the same flow table
    settings (they decide where flows are cut, so features from different
    settings are not comparable), and different file names.
    """
    if not paths:
        raise ValueError("give at least one feature file")
    frames: list[pd.DataFrame] = []
    files: list[FlowFile] = []
    first: Footer | None = None
    for path in map(Path, paths):
        footer = read_footer(path)
        if first is None:
            first = footer
        elif footer.schema != first.schema:
            raise SchemaError(f"{path.name}: the feature schema differs from {files[0].name}")
        elif footer.flow_table != first.flow_table:
            raise SchemaError(
                f"{path.name}: extracted with other flow table settings than "
                f"{files[0].name} ({footer.flow_table} instead of {first.flow_table})"
            )
        if any(known.name == path.name for known in files):
            raise ValueError(f"two feature files are named {path.name}: rename one")
        frame = pq.read_table(path).to_pandas()
        frame.insert(0, "source", path.name)
        frame.insert(1, "row", np.arange(len(frame), dtype="int64"))
        frames.append(frame)
        files.append(
            FlowFile(path.name, path, len(frame), sha256_of(path), footer.capture, footer.writer)
        )
    assert first is not None
    frame = pd.concat(frames, ignore_index=True)
    for name, categories in first.schema.categories().items():
        frame[name] = as_category(frame[name], categories, name)
    return Flows(frame=frame, schema=first.schema, flow_table=first.flow_table, files=files)


def as_category(values: pd.Series, categories: tuple[str, ...], name: str) -> pd.Series:
    """A text column as a pandas category with the schema's fixed values.

    Fixed values keep the same codes in every file, even when a file does
    not use all of them. A value outside the schema is an error.
    """
    unknown = values.notna() & ~values.isin(categories)
    if unknown.any():
        bad = sorted(set(values[unknown]))
        raise SchemaError(f"{name}: values outside the schema: {bad}")
    return pd.Series(pd.Categorical(values, categories=list(categories)), index=values.index)
