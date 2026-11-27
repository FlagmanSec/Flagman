# Phase 3 toolkit: state and handoff

Status: work in progress, on draft branches. Date: 2026-11-26.

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
| 1 | `phase-3/01-features` | draft | `flagman-features`, the flow table's extension slot, data size and TTL per packet | done |
| 2 | `phase-3/02-extract` | – | `flagmand extract` to Parquet, behind an off-by-default cargo feature; determinism test; parity test written in the phase 2 plan | next |
| 3 | `phase-3/03-ml-data` | – | `product/ml`: reading the Parquet, labelling, shortcut audit, data download scripts | to do |
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

## What is tested

| Pull request | Tests |
|---|---|
| 1 | 7 new in `flagman-core` (data size: whole, cut by the capture, padding, UDP, IPv6, broken length field; the extension slot: every packet in order, evicted flows), 22 in `flagman-features`: a worked example by hand, 8 shortcut tests (addresses, IPv6, ports, steady TTL, TTL change, link layer, clock time, TCP options), memory per flow, schema and README in step. All 93 earlier Rust tests unchanged and passing |

## What is left, in order

1. **Extract** (`phase-3/02-extract`): make `Engine` and `Output` generic
   with the same default (`Engine<X = ()>`), so `flagmand extract` runs the
   exact live loop (`pipeline::capture_loop`) with `FlowTable<FeatureState>`;
   a `flagman-parquet` crate behind the cargo feature `parquet` of
   `flagmand` (off by default, version pinned); rows sorted by a total key
   and ties in the flow table broken by flow key, so two runs give the same
   bytes; schema JSON and version in the file's metadata; the parity test
   (live and replay give the same features) written in `phase-2-plan.md`.
2. **ML data** (`phase-3/03-ml-data`): `product/ml` with pinned Python
   dependencies and pytest; reading the Parquet and its schema; labelling by
   5-tuple and time window with a mapping file per dataset; the shortcut
   audit (one feature at a time, plus ablations); download scripts with
   SHA-256 checks and `ml/data/README.md` (licence, size, citation,
   verified from the source pages).
3. **Models** (`phase-3/04-models`).
4. **Evaluation** (`phase-3/05-evaluation`), Suricata comparison, model
   export, runbook.

## Known limits

- Timing features have a 1 ms resolution (the sensor's clock).
- PSH, URG, ECE and CWR flags are not decoded, so they are not features.
- Features describe a flow when it ends; detecting during a long flow is
  for later.

## Files to review first

1. [ADR 0012](../adr/0012-features-computed-inside-the-flow-table.md)
2. `core/crates/flagman-core/src/flow/extra.rs` and the diff of
   `flow/table.rs`
3. `core/crates/flagman-features/README.md`, then `src/state.rs`
4. `core/crates/flagman-features/tests/shortcuts.rs`

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
