"""Helpers shared by the tests (never used by the pipeline itself)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

ML_ROOT = Path(__file__).resolve().parents[1]  # product/ml
FIXTURES = ML_ROOT / "fixtures"
DATA = ML_ROOT / "data"

# The lab feature files and their number of flows (see fixtures/README.md).
LAB_FILES = {
    "lab-attack-chain.parquet": 1015,
    "lab-normal-traffic.parquet": 42,
    "lab-ssh-logins.parquet": 24,
}


def fixture(name: str) -> Path:
    return FIXTURES / name


def lab_paths() -> list[Path]:
    return [fixture(name) for name in LAB_FILES]


def rewrite(
    source: Path,
    target: Path,
    table: Callable[[pa.Table], pa.Table] = lambda t: t,
    footer: Callable[[dict], dict] = lambda f: f,
) -> Path:
    """Copy a feature file, changing its rows and/or its footer on the way.

    ``footer`` receives and returns the footer as a dict of text values,
    with the schema already decoded from JSON under ``flagman.schema``.
    """
    original = pq.read_table(source)
    raw = {k.decode(): v.decode() for k, v in original.schema.metadata.items()}
    raw["flagman.schema"] = json.loads(raw["flagman.schema"])
    raw = footer(raw)
    raw["flagman.schema"] = json.dumps(raw["flagman.schema"])
    changed = table(original.replace_schema_metadata(None))
    pq.write_table(changed.replace_schema_metadata(raw), target)
    return target
