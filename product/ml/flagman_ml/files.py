"""Small helpers about files, shared by every part of the pipeline."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


def sha256_of(path: str | os.PathLike) -> str:
    """The SHA-256 checksum of a file, as 64 hexadecimal characters.

    A checksum names the exact bytes of a file: labels record the
    checksum of the feature files they describe, and downloads check
    theirs against the dataset manifest.
    """
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def replace_atomically(tmp: Path, final: Path) -> None:
    """Move a finished temporary file to its final name in one step.

    A reader never sees a half-written file: either the old file or the
    complete new one.
    """
    os.replace(tmp, final)


def write_table(frame: pd.DataFrame, path: str | os.PathLike, key: str, provenance: dict) -> None:
    """Write a table as Parquet, with ``provenance`` as JSON under ``key`` in
    the footer. Written to a temporary name first, then moved in one step;
    the same inputs always give the same bytes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pandas(frame, preserve_index=False)
    table = table.replace_schema_metadata({key: json.dumps(provenance, sort_keys=True)})
    tmp = path.with_name(path.name + ".part")
    pq.write_table(table, tmp)
    replace_atomically(tmp, path)


def read_table(path: str | os.PathLike, key: str) -> tuple[pd.DataFrame, dict] | None:
    """A table written by write_table and its provenance (None if ``key`` is absent)."""
    table = pq.read_table(path)
    metadata = table.schema.metadata or {}
    if key.encode() not in metadata:
        return None
    return table.replace_schema_metadata(None).to_pandas(), json.loads(metadata[key.encode()])
