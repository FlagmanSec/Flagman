> Markdown copy of [`2026-11-27-phase-3-extract.docx`](2026-11-27-phase-3-extract.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: flagmand extract

*Context document for draft pull request 2 of the phase 3 toolkit, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/02-extract`, built on `phase-3/01-features` (pull request #3). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (item B), with the Parquet instructions of 26 November |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-extract.docx`, with a Markdown copy next to it |

### Contents

1. The short version
2. Why a feature file, and why Parquet
3. How extract runs the live code
4. Same capture, same bytes
5. What a feature file holds
6. The cargo feature, the router build and CI time
7. The parity test, written for phase 2
8. Changes to flagman-core, file by file
9. How it was checked
10. Known limits
11. What comes next
12. Use of AI

## 1. The short version

- Pull request 1 taught the flow table to compute 37 features per flow. This pull request writes them to a file that Python can train on: `flagmand extract capture.pcap --out flows.parquet`.
- `extract` runs **the sensor’s own capture loop and engine** on the capture file, exactly like `flagmand replay`, with a flow table that also computes features. So a recorded flow gets its features from the same code, packet by packet, as a live one.
- Running it twice on the same capture gives **byte-identical** files. A test runs the real program twice on each lab capture and compares the files. Without the fix for ties described in section 4, the attack chain capture gave different files 3 times out of 3.
- The Parquet code sits in its own crate, `flagman-parquet`, behind a cargo feature of flagmand that is **off by default**. The normal build, and so the router build, does not contain it; CI checks that on every change.
- The live-versus-replay parity test is **written** in the phase 2 plan (item 2.9), **not built**, as the prompt asked. The one known difference between the two modes is pinned by a test.
- Small runs on the lab captures are **pipeline checks, not results**: they show the code runs, never how well Flagman detects anything.

## 2. Why a feature file, and why Parquet

The models of phase 3 are trained in Python (LightGBM and scikit-learn), but the features are computed in Rust, by the sensor’s code. Something has to carry them from one to the other. The file must:

- keep each column’s type: whole numbers, real numbers, text, and real **empty values** (a mean data size does not exist for a side that sent nothing);
- be compact and quick to read, because a capture from a public dataset holds hundreds of thousands of flows;
- carry its own **schema** (the list of features and its version), so a model always knows what it was trained on.

[Apache Parquet](https://parquet.apache.org/docs/) does all three. It stores a table column by column, with a type per column, and pandas reads it in one line. CSV would lose the types and the empty values and round every real number to text; JSON would be several times bigger; Arrow’s own format would need much larger Rust libraries. [ADR 0013](https://github.com/FlagmanSec/Flagman/blob/phase-3/02-extract/product/docs/adr/0013-feature-files-in-parquet-from-an-optional-crate.md) lists the alternatives.

## 3. How extract runs the live code

The live sensor works in a loop: read a packet from the network card, give it to the **engine** (decode, flow table, detectors, incidents), send the results to the database. `flagmand replay` runs the same loop, `pipeline::capture_loop`, with a capture file instead of the network card. `extract` uses that loop too:

```text
capture file
  └─> capture loop (pipeline.rs, as in live mode and replay)
        └─> Engine<FeatureState>: decode, flow table, detectors
              └─> finished flows: record + features (alerts unused)
                    └─> flagman-parquet ──> flows.parquet
```

Two small changes made that possible without touching the sensor’s behaviour:

1. **The engine takes the flow table’s extra state as a type parameter.** `Engine<X = ()>`: the sensor’s engine is `Engine<()>`, made with `Engine::new` as before; `extract` makes an `Engine<FeatureState>` with `Engine::with_extra`. The `= ()` default means every existing line that says `Engine` still means the sensor’s engine. What the engine outputs for a finished flow follows the same pattern: `Output<F = FlowRecord>`.
2. **The capture loop and its output sink do the same.** `capture_loop` accepts any `Engine<X>`, and `OutputSink<F = FlowRecord>` receives whatever a finished flow is. Live mode and replay call it exactly as before; `extract` passes a sink that writes finished flows to the file and ignores alerts, incidents and traffic counts.

The detectors still run during `extract`, because the engine is the live engine. That costs a little time, but it means nothing in the flow path differs from live mode. A test checks it on the three lab captures: the sensor’s engine and the feature engine produce exactly the same flow records, in the same order (1,015, 42 and 24 flows).

The file is written as `flows.parquet.partial` and renamed only when complete, so a failed run never leaves a half-written file that looks finished. An existing output is never replaced without `--overwrite`. `--config` takes the sensor’s `flagman.toml`, so the timeouts that cut flows are the same as live.

## 4. Same capture, same bytes

Phase 3 compares evaluation runs, so the same capture must always give the same file. Two things could make it change from one run to the next:

- **The clock.** Nothing reads it: the packets’ own timestamps drive every timeout, as in replay. The live loop’s “no packet for 250 ms” event never happens with a file.
- **The hash table.** The flow table keeps its flows in a hash table, whose order changes with every run (Rust gives each table random keys, to resist attacks on its hashing). The order leaked out in two places: flows that ended in the same housekeeping round and started in the same millisecond came out in hash order, and when the table was full, the choice between flows last active in the same millisecond also followed hash order.

The fix: flow keys are now ordered (protocol, then the two endpoints), and the table breaks every such tie by key. Ended flows are sorted by start time, then key (`in_start_order` in `flow/table.rs`), and a full table ends the smallest keys first among equally old flows (`make_room`). Two new tests check both; they failed when the tie-break was removed for a try.

The proof is end to end: `flagmand/tests/extract.rs` runs the real program twice, as two separate processes (so the hash tables get new random keys each time), on each lab capture, and compares the two files byte for byte. With the tie-break removed, the attack chain capture gave different files 3 times out of 3; with it, the files are identical. The nmap scan opens many connections in the same millisecond, so it has plenty of ties.

For the sensor this changes only which of several equally old flows a full table ends first. No detector result depends on that choice, and every earlier test passes unchanged.

## 5. What a feature file holds

One row per finished flow, in the order the flows ended (the order the live sensor reports them). First 7 **metadata** columns, then the 37 features of schema version 1:

| Columns | Type | Empty values |
|---|---|---|
| `flow_start_ms`, `flow_end_ms` | whole number: milliseconds since 1970-01-01 UTC | never |
| `src_ip`, `dst_ip` | text, such as `192.168.1.10` or `fe80::1` | never |
| `src_port`, `dst_port` | whole number; 0 for ICMP and other protocols | never |
| `end_reason` | text: idle, closed, active_timeout, evicted, stopped | never |
| category features | text | never |
| count features | whole number | never |
| real features | real number | empty when not defined for the flow |

The metadata columns are **never model inputs**: they exist so Python can label flows (match them with a dataset’s list of attacks by addresses, ports and time) and split data by day. The features crate’s README gives the reason for each one.

The end of the file, its **footer**, stores five key-value pairs: the schema version, the whole schema as JSON (each feature’s name, unit, kind, categories and shortcut note, and each metadata column with the reason it is never an input), the flow table’s timeouts and limit, the capture’s name (without its folder) and the program’s version. Python must take the list of features from the footer, never “all columns”, so a metadata column can never slip into a model.

A check by hand with pyarrow 26.0.1, Python’s Parquet library: the SSH capture’s file reads as 24 rows and 44 columns, addresses as text that is never empty, real features as nullable numbers, and the five footer keys are all there. The Python tests come with the next pull request.

## 6. The cargo feature, the router build and CI time

Seraj asked for the Parquet code in its own crate, behind a feature that is off by default, with a pinned version, and for CI time to stay reasonable. In practice:

- `flagman-parquet` is the only crate that uses the Rust `parquet` crate, pinned to exactly version 60.2.0 (it changes its interface often), with its default features off: no Arrow, no compression libraries.
- flagmand has a cargo feature, `parquet`, off by default. Build it with `cargo build --release -p flagmand --features parquet`. Without it, `extract` is hidden from `--help` and, if typed anyway, says how to get it.
- CI gained three steps: clippy and the tests with `--features parquet` (including the byte-identical test), and a check that `cargo tree` of the normal flagmand build contains no `parquet`, so the router build stays small.
- Measured on a 4-core machine with nothing cached for these crates: the parquet crate and its own dependencies take about 8 s in a debug build and about 6.5 s in a clippy run. CI keeps compiled dependencies between runs, so later runs mostly rebuild Flagman’s own crates.
- Files are not compressed, because compression would add libraries to the build. Python can recompress a file when space matters.

## 7. The parity test, written for phase 2

The prompt asks to write down, not build, a test that features computed live equal features extracted from a recording of the same traffic. It is item 2.9 of `product/docs/phase-2-plan.md`. In short: in the isolated namespace lab, run `tcpdump` and a test-only `flagmand run --features-out live.parquet` on the same interface, run the lab traffic, extract the recording with the same configuration, and compare the two files flow by flow: every feature must be exactly equal.

Reading the code for this found one real difference, now pinned by a test (`a_flow_silent_past_its_timeout_is_cut_live_but_not_in_a_quiet_replay` in `engine_tests.rs`):

- Live, when no packet arrives for 250 ms, the engine runs its timeouts with the clock. A replay runs them only after a packet. So a flow that stays silent longer than its idle timeout, in a capture with **no other traffic at all**, is cut in two live but stays one flow in a replay.
- The proposed fix is to also run the timeouts that are due before adding each packet. Tried locally on the three lab captures, it changed no flow and no feature, only the order of rows, and every test passed. It is left for phase 2 because it changes the engine. Busy captures, like the public datasets, are rarely affected, because other packets keep running the timeouts.

The plan also lists the other things the test must handle: packets lost by the kernel or by tcpdump (such a run does not count), flows open at the start or the end of the run, timestamps, and the 160-byte live capture.

## 8. Changes to flagman-core, file by file

| File | Change | Why |
|---|---|---|
| `flow/key.rs` | `FlowKey` is ordered | to break ties by key |
| `flow/table.rs` | ties broken by key in `expire`, `drain` and `make_room`; `FlowTableConfig` can be written as JSON | same bytes on every run; the settings go into the file’s footer |
| `flow/progress.rs` (new) | the TCP handshake tracking, moved out of `table.rs` unchanged | keeps `table.rs` under 300 lines |
| `flow/record.rs` | `FlowEnd::as_str` (idle, closed…), the same names as in JSON | the `end_reason` column |
| `engine.rs` | `Engine<X = ()>`, `Engine::with_extra`, `Output<F = FlowRecord>` | `extract` runs the live engine with features |
| `engine_tests.rs` (new) | the engine’s tests, moved out of `engine.rs`, plus two new ones | keeps `engine.rs` under 300 lines |

In flagmand: `pipeline.rs` (generic loop and sink), `extract.rs` and its tests (new), `cli.rs` and `main.rs` (the command), `Cargo.toml` (the feature). Plus the new crate `flagman-parquet`, the CI steps, ADR 0013, and updates to the READMEs, the architecture, the reading order, the glossary, the changelog, the AI log, the phase 2 plan and the phase 3 handoff file.

## 9. How it was checked

| Where | Tests |
|---|---|
| flagman-core (5 new) | flows that start in the same millisecond end in the same order on five fresh tables; a full table always ends the same flow among equally old ones (both failed without the tie-break); end reason names match JSON; an engine with an extension gives exactly the sensor’s flows and alerts; the live/replay difference after a silence |
| flagman-parquet (6 new) | columns in schema order; the footer’s five keys; values and empty values read back with the parquet crate’s own reader; the same rows give the same bytes; groups of a fixed size; a capture without flows gives a valid empty file |
| flagmand (1 new) | the command line: `extract` needs `--out` and never overwrites by default |
| flagmand with `--features parquet` (5 new) | the extracted flows are exactly the sensor’s flows on the three lab captures; one row per flow and the footer’s source; no file left after a failure; no overwrite without `--overwrite`; the program run twice on each lab capture gives byte-identical files |

Totals: 134 Rust tests pass without the feature and 139 with it (plus 1 ignored, the flood rate sweep). `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean with and without the feature. All earlier tests pass without any change. The dashboard is not touched.

## 10. Known limits

- The live/replay difference after a long silence (section 7), pinned and with a proposed fix.
- Files are not compressed, and their size per row on a real dataset is not measured yet; the lab files are about 17 to 22 KB, mostly the footer.
- Rows come in the order flows ended, not sorted; Python sorts when it needs to.
- Stopping `extract` with Ctrl-C leaves a `.partial` file, which can be deleted.
- Timing features keep the 1 ms resolution of pull request 1.

## 11. What comes next

- Pull request 3 (`phase-3/03-ml-data`): `product/ml` with pinned Python dependencies and pytest: reading these files and their schema, labelling flows by 5-tuple and time window with a mapping file per dataset, the shortcut audit, and download scripts with SHA-256 checks and a data README with licences, sizes and citations checked at the source.
- Then the models, the false-alarm budget, evaluation, the Suricata comparison, the model export ADR and the runbook.
- The state of the whole toolkit and the prompt for the next session are in `product/docs/changes/phase-3-toolkit.md`.

## 12. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request. Every number here comes from a test listed in section 9, from a run of the command on the lab captures, or from the timings and checks described where they appear. The team reviews and merges; the AI never merges.
