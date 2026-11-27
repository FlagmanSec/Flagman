# flagmand

The Flagman program. `flagmand --help` lists its commands:

| Command | What it does |
|---|---|
| `flagmand run` | Watches an interface and serves the dashboard (the service runs this) |
| `flagmand replay FILE.pcap` | Analyses a capture and prints what it found; `--serve` opens the results in the dashboard |
| `flagmand extract FILE.pcap --out flows.parquet` | Writes the features of every flow to a Parquet file, for machine learning. Only in builds made with `--features parquet` (see below) |
| `flagmand interfaces` | Lists the interfaces it can watch |
| `flagmand token` | Prints the dashboard link with its token |

| File | What it does |
|---|---|
| `main.rs`, `cli.rs` | Command-line parsing and dispatch |
| `config.rs` | Reads and checks `flagman.toml`; every setting has a default |
| `run.rs` | Live mode: checks everything first, starts the threads, stops them in order |
| `pipeline.rs` | The capture loop shared by live mode, replay mode and `extract` |
| `writer.rs` | The storage thread |
| `suricata.rs` | The thread that follows Suricata's log |
| `server.rs` | Starts the web server; warns when it is not on loopback |
| `shutdown.rs` | Ctrl-C and `systemctl stop`: a clean stop, or an immediate exit on the second signal |
| `token.rs` | Creates and reads the dashboard token (file mode `0600`) |
| `replay.rs`, `replay/tests.rs` | Replay mode, and the end-to-end tests on the lab captures |
| `extract.rs`, `extract/tests.rs` | `flagmand extract` (only with the `parquet` feature), and its tests on the lab captures |
| `tests/extract.rs` | Runs the program twice on each lab capture: the two files must be byte-identical |

Tests: `cargo test -p flagmand`, and `cargo test -p flagmand --features
parquet` for `extract`.

## The `parquet` feature (machine learning, phase 3)

`flagmand extract` exists only in builds made with:

```bash
cargo build --release -p flagmand --features parquet
```

The feature is off by default. The sensor never needs it, and the router
build (Edge) must stay small; without it, `extract` is hidden from
`--help` and explains how to get it. With it, `extract` runs the same
capture loop and engine as `replay` and the live sensor, with a flow table
that also computes the features (see
[`flagman-features`](../flagman-features/README.md)), and writes them with
[`flagman-parquet`](../flagman-parquet/README.md). Rows are written as
`FILE.partial` and renamed when complete; use the sensor's own
`flagman.toml` (`--config`) so the timeouts match what it sees live.
