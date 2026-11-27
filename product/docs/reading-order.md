# Reading order

The code is about 7,700 lines of Rust and a Svelte app. You do not need to
read all of it. This order follows one packet from the wire to the screen;
each step is a small file with a comment at the top saying what it does.

Words you may not know are in the [glossary](glossary.md).

## 1. The big picture (15 minutes)

1. [`../README.md`](../README.md): what Flagman does, how to try it.
2. [`architecture.md`](architecture.md): the pipeline, the threads, the database.

## 2. Detection: the heart of Flagman (1 hour)

All in `core/crates/flagman-core/src/`. This crate has no I/O at all: no
network, no disk, no clock. That is why it is easy to test.

| Step | File | What to look for |
|---|---|---|
| 1 | `packet/decode.rs` | bytes become addresses, ports and TCP flags; nothing can panic on bad input |
| 2 | `flow/table.rs` | packets become conversations (flows); when a flow starts and ends |
| 3 | `detect/window.rs` | "how many different X in the last 60 seconds?" |
| 4 | `detect/tracker.rs` | the logic shared by every detector: threshold, finding, update, close |
| 5 | `detect/port_scan.rs`, `host_sweep.rs`, `brute_force.rs` | each detector is short: it only says what it counts |
| 6 | `detect/signature.rs` | how Suricata alerts are grouped |
| 7 | `incident/engine.rs` | alerts become incidents; how severity is raised |
| 8 | `engine.rs` | the order in which all of the above runs for each packet |

Then read the tests next to them (`detectors_tests.rs`, `login_tests.rs`,
`table_tests.rs`, `engine_flood_tests.rs`, and the `mod tests` at the bottom
of each file).

## 3. The program around it (45 minutes)

| Step | File | What to look for |
|---|---|---|
| 9 | `core/crates/flagman-capture/src/live.rs` | opening the interface, and why we call `poll()` ourselves |
| 10 | `core/crates/flagmand/src/pipeline.rs` | the capture loop: packets in, batches out |
| 11 | `core/crates/flagmand/src/run.rs` | start-up checks, the four threads, the shutdown order |
| 12 | `core/crates/flagman-store/src/schema.rs` | the four tables |
| 13 | `core/crates/flagman-api/src/lib.rs`, `auth.rs` | the API routes and the token check |
| 14 | `core/crates/flagmand/src/replay/tests.rs` | the end-to-end tests on the real nmap capture |

## 4. The dashboard (30 minutes)

In `ui/src/`:

| Step | File | What to look for |
|---|---|---|
| 15 | `App.svelte` | sign-in with the token, then the page frame |
| 16 | `lib/api.ts`, `lib/types.ts` | every call to the API, and the shape of the answers |
| 17 | `pages/Overview.svelte` | the home page and its charts |
| 18 | `pages/IncidentDetail.svelte`, `lib/explain.ts` | how alerts are told as a story |
| 19 | `lib/i18n/en.ts` | every sentence the dashboard shows |

## 5. Running it

[`../deploy/linux/README.md`](../deploy/linux/README.md), then
[`home-test.md`](home-test.md).

## 6. Phase 3: features for machine learning (45 minutes)

On the phase 3 branches only, until phase 3 starts. Read
[ADR 0012](adr/0012-features-computed-inside-the-flow-table.md) first.

| Step | File | What to look for |
|---|---|---|
| 1 | `flagman-core/src/flow/extra.rs` | the slot for extra per-flow state; the sensor's `()` keeps nothing |
| 2 | `flagman-core/src/packet/lengths.rs` | a packet's data size, read from its headers even when the capture cut it |
| 3 | `flagman-features/README.md` | the 37 features, and every value left out on purpose and why |
| 4 | `flagman-features/src/stats.rs`, `direction.rs`, `state.rs` | statistics updated packet by packet, in constant memory |
| 5 | `flagman-features/src/features.rs`, `schema.rs` | the finished vector, its names, units and version |
| 6 | `flagman-features/tests/worked_example.rs`, `shortcuts.rs` | a conversation worked out by hand; lab leftovers that must not change a feature |
| 7 | [ADR 0013](adr/0013-feature-files-in-parquet-from-an-optional-crate.md), then `flagmand/src/extract.rs` | `flagmand extract`: the replay path with `Engine<FeatureState>`, written to a file |
| 8 | `flagman-parquet/README.md`, `src/columns.rs`, `src/writer.rs` | the columns of a feature file, its footer, and why the same capture gives the same bytes |
| 9 | `flagman-core/src/flow/table.rs` (`in_start_order`, `make_room`) and `flagmand/tests/extract.rs` | ties broken by flow key; two runs of the program compared byte for byte |

## 7. Phase 3: labelled data, in Python (40 minutes)

On the phase 3 branches only. Everything is in [`ml/`](../ml/README.md);
run `python -m pytest` there as you read.

| Step | File | What to look for |
|---|---|---|
| 10 | `ml/flagman_ml/flows/read.py`, `schema.py` | reading feature files: the feature list comes from the footer, categories keep fixed codes |
| 11 | `ml/fixtures/README.md`, `lab-ground-truth.csv` | the lab's ground truth: one row per step of the recordings |
| 12 | `ml/flagman_ml/labels/match.py`, then `match_test.py` | the matching rule (ends, ports, protocol, time), shown on tiny examples |
| 13 | `ml/data/labels/lab.toml`, then `ml/flagman_ml/labels/mapping.py` | a mapping file: dataset labels to Flagman classes, time zone, offset, tolerance |
| 14 | `ml/flagman_ml/labels/label.py`, `store.py`, `offset.py` | the labels file and its provenance; finding a time offset |
| 15 | `ml/data/README.md` | each dataset: what is verified, its terms, how to cite it |
| 16 | `ml/flagman_ml/datasets/download.py` | downloads that resume, check SHA-256, and refuse 20 GB without a yes |
