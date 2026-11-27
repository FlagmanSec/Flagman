# flagman-parquet

Writes **feature files**: the features of every flow of a capture, one row
per flow, in the [Apache Parquet](https://parquet.apache.org/docs/) format.
Parquet stores data column by column, with a type for each column and
proper empty values, and Python's data tools (pandas, pyarrow) read it
directly. The phase 3 Python pipeline (`product/ml`) trains on these files.

Only `flagmand extract` uses this crate, and only when flagmand is built
with its `parquet` feature:

```bash
cargo build --release -p flagmand --features parquet
target/release/flagmand extract capture.pcap --out flows.parquet
```

The sensor never writes Parquet, and the normal build (and so the router
build, Edge) does not contain this crate at all. CI checks that.

## What a file holds

One row per finished flow. The columns, in order:

1. **Metadata** (7 columns): `flow_start_ms`, `flow_end_ms`, `src_ip`,
   `src_port`, `dst_ip`, `dst_port`, `end_reason`. They say who talked to
   whom, when, and how the flow ended. They are **never model inputs**:
   Python uses them only to label flows (match them with a dataset's
   ground truth) and to split data by day. The reason for each one is in
   the [feature crate's README](../flagman-features/README.md#left-out-on-purpose).
2. **Features** (37 columns, schema version 1), in the order of
   `flagman_features::schema`. The [feature crate's README](../flagman-features/README.md)
   explains each one.

| Columns | Parquet type | Empty values |
|---|---|---|
| `flow_start_ms`, `flow_end_ms` | INT64, milliseconds since 1970-01-01 UTC | never |
| `src_ip`, `dst_ip` | STRING, such as `192.168.1.10` or `fe80::1` | never |
| `src_port`, `dst_port` | INT32; 0 for ICMP and other protocols | never |
| `end_reason` | STRING: `idle`, `closed`, `active_timeout`, `evicted`, `stopped` | never |
| category features (`protocol`, `dst_port_class`, `tcp_outcome`) | STRING | never |
| count features | INT64 | never |
| real features | DOUBLE | null when not defined for the flow (for example the mean data size of a side that sent nothing) |

The `src` side is the flow's initiator (the side of the first packet).

**Row order:** the order in which the flows ended, the order the live
sensor would report them. Flows that ended together come by start time,
then by flow key.

## The footer

Every file stores, in Parquet's key-value metadata:

| Key | Value |
|---|---|
| `flagman.schema_version` | the feature schema version, such as `1` |
| `flagman.schema` | the schema as JSON: every feature (name, unit, kind, categories, shortcut note) and every metadata column with the reason it is never an input |
| `flagman.flow_table` | the flow table's timeouts and limit, as JSON. They decide where flows are cut, so a model must be used with the same values |
| `flagman.source` | the capture file's name (not its folder) |
| `flagman.writer` | the program and version, such as `flagmand 0.1.0` |

Reading it from Python:

```python
import json
import pyarrow.parquet as pq

table = pq.read_table("flows.parquet")
footer = pq.read_schema("flows.parquet").metadata
schema = json.loads(footer[b"flagman.schema"])
features = [f["name"] for f in schema["features"]]  # the only model inputs
```

Python should always take the feature list from the footer, never from
"all columns", so a metadata column can never become an input by mistake.

## Same capture, same bytes

Extracting the same capture twice gives byte-identical files. Nothing in a
file depends on the clock or the machine: the packets' own timestamps drive
every timeout, the flow table breaks ties by flow key (see
`flagman-core/src/flow/table.rs`), and the writer adds no date.
`flagmand/tests/extract.rs` runs the program twice on each lab capture and
compares the files; without the tie-break the attack chain capture gave
different files on each try.

## Choices

- **Pinned version** (`parquet = "=60.2.0"` in the workspace): the crate
  changes its interface often, so an update is a deliberate change.
- **No default features:** no Arrow and no compression libraries. On a
  4-core machine the crate and its own dependencies add about 8 s to a
  debug build and about 6.5 s to a clippy run (measured with a cold cache).
- **Not compressed:** compression would add libraries to the build. Python
  can recompress a file (for example with zstd) when space matters.
- **Row groups of 65,536 rows** (Parquet's unit of storage): rows wait in
  memory only until a group is full, so memory stays bounded whatever the
  size of the capture.
- Decision record: [ADR 0013](../../../docs/adr/0013-feature-files-in-parquet-from-an-optional-crate.md).

## Files

| File | What it does |
|---|---|
| `src/columns.rs` | The columns: names, Parquet types, writing one column of a row group |
| `src/writer.rs` | `FeatureFileWriter`: rows in, row groups and the footer out |
| `src/read.rs` | `summary`: rows, columns and footer of a file (used by tests) |
| `src/writer_tests.rs` | Writes a few flows and reads them back with the parquet crate's own reader |

Run the tests with `cargo test -p flagman-parquet`.
