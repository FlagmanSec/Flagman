# 0013. Write feature files in Parquet, from an optional crate

Status: proposed (phase 3 branch; accepted when phase 3 starts)
Date: 2026-11-27

## Context

Phase 3 trains models in Python on features that the Rust code computes
([ADR 0012](0012-features-computed-inside-the-flow-table.md)). A capture
of a public dataset holds hundreds of thousands of flows, so the file
between Rust and Python must be compact, typed (counts, real numbers,
text, empty values) and read by pandas without custom code. It must also
carry the feature schema and its version, so a model always knows what it
was trained on.

The sensor itself never needs this file. The router (Edge, 1 GB of memory)
must not grow, and CI must stay quick. Seraj asked for the Parquet code in
its own crate, behind a cargo feature that is off by default, with a
pinned version.

Evaluation (phase 3) compares runs, so the same capture must always give
the same file.

## Decision

- Feature files are [Apache Parquet](https://parquet.apache.org/docs/)
  files, written by a new crate, `flagman-parquet`, with the Rust
  `parquet` crate pinned to exactly 60.2.0 and its default features off:
  no Arrow, no compression libraries.
- `flagmand extract capture.pcap --out flows.parquet` writes them. It
  exists only when flagmand is built with its `parquet` feature, which is
  off by default. Without it, the command is hidden and explains how to
  get it. CI checks that the normal flagmand build has no Parquet code.
- `extract` runs the sensor's own capture loop and engine on the file,
  with a flow table that also computes features (`Engine<FeatureState>`),
  so recorded and live features come from the same code. The engine and
  the capture loop became generic for this, with the sensor's types as
  defaults, so the sensor's code does not change.
- One row per flow: 7 metadata columns (never model inputs) then the 37
  features. The footer stores the schema version, the schema as JSON, the
  flow table's settings, the capture's name and the program's version.
  Rows come in the order flows ended, in groups of 65,536.
- The same capture gives byte-identical files: the flow table now breaks
  ties by flow key wherever the hash table's order could show (flows
  ending together, the choice of flows to end when the table is full).
  A test runs the program twice on each lab capture and compares the files.

## Consequences

- Python reads the files with pyarrow or pandas in one line, and takes the
  list of features from the footer.
- Building the crate adds about 8 s to a debug build and about 6.5 s to a
  clippy run on a 4-core machine with a cold cache (measured 2026-11-27);
  CI caches compiled dependencies between runs.
- Files are not compressed. Python can recompress them when space matters.
- An update of the `parquet` crate is a deliberate change: its interface
  changes often, and the byte-identical test will show any change in the
  files.
- The tie-break also applies to the sensor: when the table is full and
  several flows were last active in the same millisecond, the smallest
  keys are ended first instead of whichever the hash table listed first.
  No detector result depends on that choice; every test is unchanged.

## Alternatives considered

- **CSV:** no types, no empty values (an empty string or a made-up
  number), real numbers rounded to text, larger files and slow to read.
  The schema would need a second file.
- **Arrow IPC / Feather:** good for Python too, but needs the Arrow crates,
  a much larger build than the plain Parquet writer.
- **JSON lines:** simple, but several times larger and slow to read for
  hundreds of thousands of rows.
- **The sensor's SQLite database:** Python can read it, but the schema and
  its version would live outside the data, and the sensor's database would
  grow columns it does not use.
- **Parquet always built in:** simpler, but the router build would carry
  code it never uses, against Seraj's instruction.
