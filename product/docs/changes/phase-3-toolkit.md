# Phase 3 toolkit: state and handoff

Status: work in progress, on draft branches. Date: 2026-11-27.

Seraj asked for the phase 3 toolkit ("detection quality") ahead of
schedule: all the code, tests and documents needed to train and evaluate
Flagman's machine learning detectors, run only at small scale. The team
runs the full campaign later, on its own machines, once phase 2 is done.
This file says what exists, what is tested, what is left, and how another
session continues. It is updated with every pull request.

Small runs in this work are **pipeline checks, not results**: they prove
the code runs, never how well Flagman detects anything.

## Branches and pull requests

Each branch starts from the previous one; each pull request is a draft, to
be reviewed block by block, rebased on `main` after phase 2, and merged by
the team when phase 3 starts.

| # | Branch | Pull request | Contents | State |
|---|---|---|---|---|
| 0 | `phase-1-followups` | #2 (normal, into `main`) | the three phase 1 follow-ups | open, for the team to merge |
| 1 | `phase-3/01-features` | #3 (draft) | `flagman-features`, the flow table's extension slot, data size and TTL per packet | done |
| 2 | `phase-3/02-extract` | #4 (draft) | `flagmand extract` to Parquet, behind an off-by-default cargo feature; ties broken by flow key; byte-identical test; parity test written in the phase 2 plan | done |
| 3 | `phase-3/03-ml-data` | – | `product/ml`: reading the Parquet, labelling, shortcut audit, data download scripts | next |
| 4 | `phase-3/04-models` | – | LightGBM with calibrated probabilities, Isolation Forest, open-set rule, conformal false-alarm budget, drift monitor | to do |
| 5 | `phase-3/05-evaluation` | – | evaluation harness, Suricata comparison, reports from `results/*.json`, model export and runtime ADR draft, runbook | to do |

## What is done

### 1. Features (`phase-3/01-features`)

- `flagman-core/src/flow/extra.rs`: `FlowTable<X>` keeps an `X` per flow,
  called for every packet and once at the end. The sensor's table is
  `FlowTable<()>` and is unchanged.
- `flagman-core/src/packet/lengths.rs`: each decoded IP packet carries
  `payload_len` (data bytes, from the headers' length fields) and `ttl`.
- `flagman-features`: 37 features (schema version 1), the metadata columns
  that are never inputs, the schema as JSON, and the memory measurement.
  The crate README is the reference.
- [ADR 0012](../adr/0012-features-computed-inside-the-flow-table.md).

### 2. Extract (`phase-3/02-extract`)

- `flagmand extract capture.pcap --out flows.parquet [--config flagman.toml]
  [--overwrite]`, only in builds made with `--features parquet` (off by
  default). It runs `pipeline::capture_loop`, the loop of live mode and
  replay, with `Engine<FeatureState>`; the engine and the loop are generic
  with the sensor's types as defaults (`Engine<X = ()>`,
  `OutputSink<F = FlowRecord>`), so the sensor's code is unchanged.
- `flagman-parquet` (new crate, `parquet = "=60.2.0"`, no default
  features): one row per flow, 7 metadata columns then the 37 features,
  the schema, its version, the flow table's settings, the capture's name
  and the program's version in the footer; row groups of 65,536 rows; not
  compressed. Its README describes every column and how Python reads it.
- The flow table breaks ties by flow key (`in_start_order`, `make_room`),
  so the same capture always gives the same bytes. `FlowKey` is ordered,
  `FlowEnd::as_str` names the end reasons, `FlowTableConfig` can be written
  as JSON; the TCP handshake tracking moved to `flow/progress.rs`.
- CI: clippy and tests with `--features parquet`, and a check that the
  normal flagmand build has no Parquet code.
- `phase-2-plan.md` 2.9 describes the parity test (not built), with the
  one known difference pinned by a test.
- [ADR 0013](../adr/0013-feature-files-in-parquet-from-an-optional-crate.md).

## What is tested

| Pull request | Tests |
|---|---|
| 1 | 7 new in `flagman-core` (data size: whole, cut by the capture, padding, UDP, IPv6, broken length field; the extension slot: every packet in order, evicted flows), 22 in `flagman-features`: a worked example by hand, 8 shortcut tests (addresses, IPv6, ports, steady TTL, TTL change, link layer, clock time, TCP options), memory per flow, schema and README in step. All 93 earlier Rust tests unchanged and passing |
| 2 | 5 new in `flagman-core` (ties: same end order on every run, the same flow ended when a full table has equally old flows, both failing without the tie-break; end reason names; an engine with an extension gives the same flows and alerts as the sensor's; the live/replay difference after a silence), 6 in `flagman-parquet` (columns in schema order, footer, values and nulls read back, same rows same bytes, row groups, empty file), 1 command-line test, and with `--features parquet` 4 in `flagmand` (the extracted flows are exactly the sensor's flows on the three lab captures, one row per flow, no file left after a failure, no overwrite without `--overwrite`) and `tests/extract.rs` (the program run twice on each lab capture gives byte-identical files; without the tie-break the attack chain gave different files 3 times out of 3). 134 tests without the feature, 139 with it, plus 1 ignored. pyarrow 26.0.1 reads the files (checked by hand; the Python tests come with pull request 3) |

## What is left, in order

1. **ML data** (`phase-3/03-ml-data`): `product/ml` with pinned Python
   dependencies and pytest; reading the Parquet and its schema; labelling by
   5-tuple and time window with a mapping file per dataset; the shortcut
   audit (one feature at a time, plus ablations); download scripts with
   SHA-256 checks and `ml/data/README.md` (licence, size, citation,
   verified from the source pages).
2. **Models** (`phase-3/04-models`).
3. **Evaluation** (`phase-3/05-evaluation`), Suricata comparison, model
   export, runbook.

## Known limits

- Timing features have a 1 ms resolution (the sensor's clock).
- PSH, URG, ECE and CWR flags are not decoded, so they are not features.
- Features describe a flow when it ends; detecting during a long flow is
  for later.
- In a replay, timeouts run only after a packet. A flow silent longer than
  its timeout in a capture with no other traffic stays one flow, where the
  live sensor would cut it in two. Pinned by a test; the fix is proposed in
  the phase 2 plan (2.9). Tried on the three lab captures, the fix changed
  no flow and no feature.
- Feature files are not compressed. Their size per row on a real dataset
  is not measured yet (the lab files are about 17 to 22 KB, mostly the
  footer).
- `extract` runs the detectors too (the exact live engine), which costs
  some time; their alerts are not written.
- Rows come in the order flows ended, not sorted. Python sorts when it
  needs to.
- Stopping `extract` with Ctrl-C leaves a `.partial` file; delete it.

## Files to review first

Pull request 1:

1. [ADR 0012](../adr/0012-features-computed-inside-the-flow-table.md)
2. `core/crates/flagman-core/src/flow/extra.rs` and the diff of
   `flow/table.rs`
3. `core/crates/flagman-features/README.md`, then `src/state.rs`
4. `core/crates/flagman-features/tests/shortcuts.rs`

Pull request 2:

1. [ADR 0013](../adr/0013-feature-files-in-parquet-from-an-optional-crate.md)
2. The diff of `core/crates/flagman-core/src/flow/table.rs` (ties) and
   `engine.rs` (generic engine)
3. `core/crates/flagmand/src/extract.rs`, then `src/pipeline.rs`
4. `core/crates/flagman-parquet/README.md`, `src/columns.rs`, `src/writer.rs`
5. `core/crates/flagmand/tests/extract.rs` and `src/extract/tests.rs`
6. [The parity test](../phase-2-plan.md#29-live-and-replay-give-the-same-features-parity-test)

## Prompt for the next session

```text
You are continuing the Flagman phase 3 toolkit in FlagmanSec/Flagman.
Read product/docs/changes/phase-3-toolkit.md first: it lists the branches,
what is done and tested, and what is left in order. Read the phase 3
prompt (Flagman_phase3_toolkit_prompt.md in the project files) for the
rules: files under ~300 lines, a README per folder, tests next to the
code, every number from a results/*.json file, small runs are "pipeline
check, not a result", verify and link every fact about datasets and
tools, never write "guaranteed", defensive work only, free tools only,
downloads under ~5 GB. Every push includes a context .docx and its .md
copy in product/docs/context/. Never merge; open draft pull requests, each
branch based on the previous one (phase-3/NN-name). Continue with the
first item of "What is left", and update this file with every pull
request.
```
