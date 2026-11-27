"""Suricata files: Suricata's verdict on every flow of one feature file.

A Suricata file is a Parquet file with the columns of ``match.MATCH_COLUMNS``,
written by ``python -m flagman_ml.suricata match``. Its footer (key
``flagman.suricata``) records, as JSON:

- the feature file (name, checksum, rows, capture);
- the EVE file (name, checksum) and, when one was found next to it, the
  record of the Suricata run that wrote it (``run.json``: Suricata's
  version, the rules, the configuration and the capture, with checksums);
- the counts of the matching, unmatched alerts included.

``attach_suricata`` joins these columns to flows by ``(source, row)``, and
refuses when a feature file's checksum differs from the one recorded, like
``labels.store.attach_labels``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd

from flagman_ml.files import read_table, sha256_of, write_table
from flagman_ml.flows import Flows

KEY = "flagman.suricata"


class SuricataMismatch(ValueError):
    """A Suricata file that does not describe these feature files."""


def write_matches(table: pd.DataFrame, path: str | os.PathLike, provenance: dict) -> None:
    """Write a Suricata file; the same inputs always give the same bytes."""
    write_table(table, path, KEY, provenance)


def read_matches(path: str | os.PathLike) -> tuple[pd.DataFrame, dict]:
    """A Suricata file and its provenance."""
    found = read_table(path, KEY)
    if found is None:
        raise SuricataMismatch(f"{path}: not a Flagman Suricata file")
    return found


def attach_suricata(flows: Flows, frame: pd.DataFrame,
                    paths: list[Path]) -> tuple[pd.DataFrame, list[dict]]:
    """``frame`` (the flows, one row each) with the Suricata columns of the
    files among ``paths`` that describe its feature files, and a record of
    the files used. Flows of a feature file without one get no value."""
    recorded = {file.name: file.sha256 for file in flows.files}
    tables, used = [], []
    for path in paths:
        table, provenance = read_matches(path)
        name = provenance["flow_file"]["name"]
        if name not in recorded:
            continue
        if provenance["flow_file"]["sha256"] != recorded[name]:
            raise SuricataMismatch(f"{name} changed since Suricata's alerts were matched to it "
                                   "(checksum differs): match it again")
        if any(item["flow_file"] == name for item in used):
            raise SuricataMismatch(f"two Suricata files describe {name}")
        tables.append(table)
        used.append({"file": str(path), "sha256": sha256_of(path), "flow_file": name,
                     "eve": provenance["eve"], "run": provenance.get("run"),
                     "origin": provenance.get("origin"), "counts": provenance["counts"]})
    if not tables:
        return frame, used
    joined = frame.merge(pd.concat(tables, ignore_index=True), on=["source", "row"], how="left",
                         validate="one_to_one")
    return joined, used
