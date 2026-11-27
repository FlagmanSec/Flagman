# Flagman core (Rust)

The sensor: one Cargo workspace with one crate per responsibility. The
arrows show who uses whom; `flagman-core` uses nobody.

```text
flagmand ──▶ flagman-capture ──┐
   │    ──▶ flagman-suricata ──┤
   │    ──▶ flagman-api ──▶ flagman-store ──▶ flagman-core
   └────────────────────────────────────────▶ flagman-core

with the `parquet` feature only (phase 3, `flagmand extract`):
flagmand ──▶ flagman-parquet ──▶ flagman-features ──▶ flagman-core
```

| Crate | Job |
|---|---|
| [`flagman-core`](crates/flagman-core/README.md) | Detection logic: packets to flows, alerts and incidents. No I/O. |
| [`flagman-capture`](crates/flagman-capture/README.md) | Packets from an interface (libpcap) or a `.pcap` file |
| [`flagman-suricata`](crates/flagman-suricata/README.md) | Reads Suricata's `eve.json` alerts |
| [`flagman-store`](crates/flagman-store/README.md) | SQLite: writes results, answers the dashboard's questions |
| [`flagman-api`](crates/flagman-api/README.md) | The HTTP API and the dashboard files, behind a token |
| [`flagmand`](crates/flagmand/README.md) | The program: command line, threads, configuration |
| [`flagman-features`](crates/flagman-features/README.md) | Phase 3: per-flow features for machine learning, computed inside the flow table. Not used by the sensor yet |
| [`flagman-parquet`](crates/flagman-parquet/README.md) | Phase 3: writes features to Parquet files for `flagmand extract`. Only in builds with flagmand's `parquet` feature |

`testdata/pcap/` holds real lab captures used by the end-to-end tests
([its README](testdata/pcap/README.md) explains every number).

## Build and test

Needs Rust (the version is pinned in `rust-toolchain.toml`; `rustup`
installs it automatically) and `libpcap-dev`.

```bash
cargo build --release -p flagmand        # the program: target/release/flagmand
cargo test                               # every test of every crate
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs the last three on every change to `product/`, then the same lints
and tests for `flagmand extract`, which only exists with a cargo feature:

```bash
cargo build --release -p flagmand --features parquet   # adds `flagmand extract`
cargo test -p flagmand --features parquet
```

CI also checks that the normal build of `flagmand` does not contain the
Parquet code, so the router build stays small.
