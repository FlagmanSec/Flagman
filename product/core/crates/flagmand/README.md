# flagmand

The Flagman program. `flagmand --help` lists its commands:

| Command | What it does |
|---|---|
| `flagmand run` | Watches an interface and serves the dashboard (the service runs this) |
| `flagmand replay FILE.pcap` | Analyses a capture and prints what it found; `--serve` opens the results in the dashboard |
| `flagmand interfaces` | Lists the interfaces it can watch |
| `flagmand token` | Prints the dashboard link with its token |

| File | What it does |
|---|---|
| `main.rs`, `cli.rs` | Command-line parsing and dispatch |
| `config.rs` | Reads and checks `flagman.toml`; every setting has a default |
| `run.rs` | Live mode: checks everything first, starts the threads, stops them in order |
| `pipeline.rs` | The capture loop shared by live and replay modes |
| `writer.rs` | The storage thread |
| `suricata.rs` | The thread that follows Suricata's log |
| `server.rs` | Starts the web server; warns when it is not on loopback |
| `shutdown.rs` | Ctrl-C and `systemctl stop`: a clean stop, or an immediate exit on the second signal |
| `token.rs` | Creates and reads the dashboard token (file mode `0600`) |
| `replay.rs`, `replay/tests.rs` | Replay mode, and the end-to-end tests on the lab captures |

Tests: `cargo test -p flagmand`.
