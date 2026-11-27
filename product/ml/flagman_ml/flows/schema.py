"""The feature schema that every feature file carries in its footer.

``flagmand extract`` (Rust) writes the list of features into the Parquet
footer, under the key ``flagman.schema``. Python reads it from there and
keeps no copy of its own, so the two sides cannot drift apart.

Example::

    footer = read_footer("fixtures/lab-ssh-logins.parquet")
    footer.schema.version              # 1
    footer.schema.feature_names[:3]    # ['protocol', 'dst_port_class', 'tcp_outcome']
    footer.capture                     # 'lab-ssh-logins.pcap'
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import pyarrow.parquet as pq

# The schema versions this code understands. When the Rust side moves to a
# new version, add it here on purpose, after reading what changed.
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

# The footer keys that flagman-parquet writes (see its README).
KEY_SCHEMA_VERSION = "flagman.schema_version"
KEY_SCHEMA = "flagman.schema"
KEY_FLOW_TABLE = "flagman.flow_table"
KEY_SOURCE = "flagman.source"
KEY_WRITER = "flagman.writer"
FOOTER_KEYS = (KEY_SCHEMA_VERSION, KEY_SCHEMA, KEY_FLOW_TABLE, KEY_SOURCE, KEY_WRITER)

KINDS = ("category", "count", "real")


class SchemaError(ValueError):
    """A feature file that this code cannot read safely."""


@dataclass(frozen=True)
class Feature:
    """One model input, as the Rust feature crate describes it."""

    name: str
    kind: str  # "category", "count" or "real"
    unit: str  # "ms", "bytes", "packets", ... ("" for categories)
    categories: tuple[str, ...]  # the allowed values (categories only)
    watch: str | None  # why it may describe the lab instead of the attack


@dataclass(frozen=True)
class Schema:
    """The columns of a feature file: metadata first, then the features."""

    version: int
    features: tuple[Feature, ...]
    metadata: tuple[str, ...]  # never model inputs
    reasons: tuple[tuple[str, str], ...]  # (metadata column, why never an input)

    @property
    def feature_names(self) -> list[str]:
        return [feature.name for feature in self.features]

    @property
    def columns(self) -> list[str]:
        return [*self.metadata, *self.feature_names]

    def categories(self) -> dict[str, tuple[str, ...]]:
        """Each category feature and its allowed values, in a fixed order."""
        return {f.name: f.categories for f in self.features if f.kind == "category"}

    def watched(self) -> dict[str, str]:
        """Features that may be testbed fingerprints, with the reason."""
        return {f.name: f.watch for f in self.features if f.watch}


@dataclass(frozen=True)
class Footer:
    """Everything a feature file says about itself."""

    schema: Schema
    flow_table: dict  # the flow table's timeouts and limit
    capture: str  # the capture file's name
    writer: str  # the program and version that wrote the file


def read_footer(path: str | os.PathLike) -> Footer:
    """Read and check the footer of one feature file."""
    arrow_schema = pq.read_schema(path)
    raw = {k.decode(): v.decode() for k, v in (arrow_schema.metadata or {}).items()}
    missing = [key for key in FOOTER_KEYS if key not in raw]
    if missing:
        raise SchemaError(
            f"{path}: not a Flagman feature file (no {', '.join(missing)} in the footer)"
        )
    schema = parse_schema(raw[KEY_SCHEMA])
    if raw[KEY_SCHEMA_VERSION] != str(schema.version):
        raise SchemaError(f"{path}: the footer gives two different schema versions")
    if arrow_schema.names != schema.columns:
        raise SchemaError(f"{path}: the columns differ from the schema in the footer")
    return Footer(
        schema=schema,
        flow_table=json.loads(raw[KEY_FLOW_TABLE]),
        capture=raw[KEY_SOURCE],
        writer=raw[KEY_WRITER],
    )


def parse_schema(text: str) -> Schema:
    """Turn the footer's schema JSON into a Schema, checking it on the way."""
    raw = json.loads(text)
    version = raw.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise SchemaError(
            f"feature schema version {version} is not supported "
            f"(supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )
    features = tuple(
        Feature(
            name=item["name"],
            kind=item["kind"],
            unit=item["unit"],
            categories=tuple(item.get("categories") or ()),
            watch=item.get("watch"),
        )
        for item in raw["features"]
    )
    for feature in features:
        if feature.kind not in KINDS:
            raise SchemaError(f"{feature.name}: unknown kind {feature.kind!r}")
        if (feature.kind == "category") != bool(feature.categories):
            raise SchemaError(f"{feature.name}: only categories have a list of values")
    metadata = tuple(item["name"] for item in raw["metadata"])
    reasons = tuple((item["name"], item["never_an_input_because"]) for item in raw["metadata"])
    names = [*metadata, *(f.name for f in features)]
    if len(set(names)) != len(names):
        raise SchemaError("a column name appears twice in the schema")
    return Schema(version=version, features=features, metadata=metadata, reasons=reasons)
