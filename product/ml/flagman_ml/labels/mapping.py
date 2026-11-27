"""Mapping files: how one dataset's ground truth becomes Flagman labels.

A mapping file is a small TOML file in ``product/ml/data/labels/``::

    dataset = "lab"
    source = "https://..."            # where the dataset and its labels come from
    format = "lab_csv"                # how to read the ground truth (formats.py)
    ground_truth = ["lab-ground-truth.csv"]   # the files it was written for
    default_label = "normal"          # the class of flows no record matches
    time_zone = "UTC"                 # for ground-truth times written without a zone
    time_offset_ms = 0                # added to every ground-truth time
    time_tolerance_ms = 0             # widens each record's time window, both sides

    [classes]                         # exact dataset label -> Flagman class
    port_scan = "scan"

    [patterns]                        # regular expression -> class, tried in order
    "^flow=From-Botnet" = "botnet"

Every label found in the ground truth must map to a class: an unknown
label stops the run and lists every unknown label, so no flow is ever
labelled by accident.
"""

from __future__ import annotations

import os
import re
import tomllib
import zoneinfo
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from flagman_ml.files import sha256_of
from flagman_ml.labels.classes import check_class
from flagman_ml.labels.formats import READERS

REQUIRED = ("dataset", "source", "format", "ground_truth", "default_label")
OPTIONAL = {
    "time_zone": "UTC",
    "time_format": None,
    "time_offset_ms": 0,
    "time_tolerance_ms": 0,
    "classes": {},
    "patterns": {},
    "notes": "",
}


class MappingError(ValueError):
    """A mapping file that is incomplete or inconsistent."""


class UnmappedLabels(MappingError):
    """Ground-truth labels that the mapping file does not cover."""

    def __init__(self, dataset: str, labels: list[str]):
        self.labels = labels
        shown = ", ".join(repr(label) for label in labels[:20])
        more = f" and {len(labels) - 20} more" if len(labels) > 20 else ""
        super().__init__(f"{dataset}: no class for the labels {shown}{more}")


@dataclass(frozen=True)
class Mapping:
    dataset: str
    source: str
    format: str
    ground_truth: tuple[str, ...]
    default_label: str
    time_zone: str
    time_format: str | None
    time_offset_ms: int
    time_tolerance_ms: int
    classes: dict[str, str] = field(hash=False)
    patterns: tuple[tuple[re.Pattern, str], ...]
    notes: str
    name: str  # the mapping file's name
    sha256: str  # checksum of the mapping file, kept with every labels file

    def class_of(self, label: str) -> str | None:
        """The class of one dataset label, or None when nothing matches."""
        if label in self.classes:
            return self.classes[label]
        for pattern, name in self.patterns:
            if pattern.search(label):
                return name
        return None

    def classes_of(self, labels: pd.Series) -> pd.Series:
        """The class of every label, or UnmappedLabels listing the unknown ones."""
        table = {label: self.class_of(label) for label in labels.dropna().unique()}
        unmapped = sorted(label for label, name in table.items() if name is None)
        if unmapped:
            raise UnmappedLabels(self.dataset, unmapped)
        return labels.map(table)


def load_mapping(path: str | os.PathLike) -> Mapping:
    """Read and check a mapping file."""
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise MappingError(f"{path.name}: not valid TOML ({error})") from None
    missing = [key for key in REQUIRED if key not in raw]
    unknown = sorted(set(raw) - set(REQUIRED) - set(OPTIONAL))
    if missing or unknown:
        raise MappingError(f"{path.name}: missing keys {missing}, unknown keys {unknown}")
    values = {**OPTIONAL, **raw}
    where = path.name
    if values["format"] not in READERS:
        known = sorted(READERS)
        raise MappingError(f"{where}: unknown format {values['format']!r} (known: {known})")
    try:
        zoneinfo.ZoneInfo(values["time_zone"])
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise MappingError(f"{where}: unknown time zone {values['time_zone']!r}") from None
    try:
        check_class(values["default_label"], f"{where} default_label")
        classes = {
            k: check_class(v, f"{where} [classes] {k}") for k, v in values["classes"].items()
        }
        patterns = tuple(
            (re.compile(k), check_class(v, f"{where} [patterns] {k}"))
            for k, v in values["patterns"].items()
        )
    except re.error as error:
        raise MappingError(f"{where}: bad regular expression ({error})") from None
    except ValueError as error:
        raise MappingError(str(error)) from None
    if not classes and not patterns:
        raise MappingError(f"{where}: give [classes] or [patterns]")
    return Mapping(
        dataset=values["dataset"],
        source=values["source"],
        format=values["format"],
        ground_truth=tuple(values["ground_truth"]),
        default_label=values["default_label"],
        time_zone=values["time_zone"],
        time_format=values["time_format"],
        time_offset_ms=int(values["time_offset_ms"]),
        time_tolerance_ms=int(values["time_tolerance_ms"]),
        classes=classes,
        patterns=patterns,
        notes=values["notes"],
        name=path.name,
        sha256=sha256_of(path),
    )
