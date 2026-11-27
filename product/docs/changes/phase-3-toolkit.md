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
| 3 | `phase-3/03-ml-data` | #5 (draft) | `product/ml`: pinned Python, reading the Parquet, labelling with a mapping file per dataset, time offset finder, download script and manifests, dataset facts | done |
| 4 | `phase-3/04-models` | – | shortcut audit, LightGBM with calibrated probabilities, Isolation Forest, open-set rule, conformal false-alarm budget, drift monitor | next |
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

### 3. ML data (`phase-3/03-ml-data`)

- `product/ml`: Python 3.13, every package pinned (`requirements.txt`),
  pytest with tests next to the code, run from that folder. Python never
  computes a feature.
- `flagman_ml/flows`: `read_flows` reads feature files into one table with
  `source` and `row` naming each flow, takes the feature list from the
  footer (`Flows.inputs()`), keeps category codes fixed, and refuses mixed
  schemas, mixed flow table settings or two files with the same name.
- `flagman_ml/labels`: readers for four ground-truth formats (`lab_csv`,
  `unsw_gt`, `cic_flows`, `ctu_binetflow`); the matching rule (two ends in
  either direction, ports and protocol where given, overlapping times
  after offset and tolerance; most specific record, then longest overlap;
  conflicts marked); strict mapping of every dataset label to a class;
  `offsets` to find a time offset; labels files with the checksums of the
  mapping, the ground truth and every feature file, which
  `attach_labels` checks before joining.
- `data/labels/*.toml`: mapping files for the lab (checked), UNSW-NB15 and
  CTU-13 (drafts to confirm on the real files) and CIC-IDS2017 (draft:
  the corrected files could not be inspected).
- `flagman_ml/datasets` and `data/manifests/*.toml`: downloads with resume,
  size and SHA-256 checks (recorded on the first download, since no
  dataset publishes them), a 20 GB guard, a disk space check, and a refusal
  of programs; CTU-13's 28 files (13 scenarios) are listed.
- `data/README.md`: UNSW-NB15, CIC-IDS2017 with Engelen et al.'s
  corrections, CTU-13 and MAWI: where the files are, sizes, terms, how to
  cite, quoted from the source pages, with "not stated" and "not
  verified" where that is the case.
- `fixtures/`: the three lab feature files (rebuilt by `make-fixtures.sh`)
  and the lab ground truth, one row per recorded step.
- CI: a Python job, and a step that extracts the lab captures again and
  compares them with `fixtures/` byte for byte. It caught a real problem
  before the first push: the first copies were made by an experimental
  build (same rows, another order).

## What is tested

| Pull request | Tests |
|---|---|
| 1 | 7 new in `flagman-core` (data size: whole, cut by the capture, padding, UDP, IPv6, broken length field; the extension slot: every packet in order, evicted flows), 22 in `flagman-features`: a worked example by hand, 8 shortcut tests (addresses, IPv6, ports, steady TTL, TTL change, link layer, clock time, TCP options), memory per flow, schema and README in step. All 93 earlier Rust tests unchanged and passing |
| 2 | 5 new in `flagman-core` (ties: same end order on every run, the same flow ended when a full table has equally old flows, both failing without the tie-break; end reason names; an engine with an extension gives the same flows and alerts as the sensor's; the live/replay difference after a silence), 6 in `flagman-parquet` (columns in schema order, footer, values and nulls read back, same rows same bytes, row groups, empty file), 1 command-line test, and with `--features parquet` 4 in `flagmand` (the extracted flows are exactly the sensor's flows on the three lab captures, one row per flow, no file left after a failure, no overwrite without `--overwrite`) and `tests/extract.rs` (the program run twice on each lab capture gives byte-identical files; without the tie-break the attack chain gave different files 3 times out of 3). 134 tests without the feature, 139 with it, plus 1 ignored. pyarrow 26.0.1 reads the files (checked by hand; the Python tests come with pull request 3) |
| 3 | 79 Python tests, in under 3 s: reading (one row per flow, inputs are only the features, fixed categories, files stacked with their names; refusals: unknown schema version, missing footer, unknown kind, same file name, other flow table settings, a category outside the schema), matching on tiny examples (either direction, empty ports, exact conversations, protocol, tolerance, offset, most specific wins, longest overlap wins, no match), the four readers on hand-written samples, mapping files (all repository files load, patterns in order, every unknown label listed, five kinds of mistakes), labelling the lab (1,000 scan, 28 brute_force, 53 normal, no conflict; 2 conflicts with 1 s of tolerance, same labels), the offset finder (a 3-hour shift found, no other offset matches), labels files (join back, provenance, same bytes twice, refusal of a changed feature file), the commands, manifests (all load, unsafe entries refused, selection) and downloads from a local web server (checked download, resume, server without ranges, wrong checksum, no checksum without `--record`, file already there, the 20 GB guard, the disk check). Rust tests unchanged |

## What is left, in order

1. **Models** (`phase-3/04-models`): the shortcut audit (how well each
   feature alone separates the classes, and ablations without the features
   of `schema.watched()`; flag possible testbed fingerprints), LightGBM
   with calibrated probabilities, Isolation Forest trained on normal
   traffic only, the open-set rule (low confidence and high anomaly score
   give "unknown suspicious"), the split conformal threshold (the
   ⌈(n+1)(1−α)⌉-th smallest calibration score; the bound holds only when
   traffic is exchangeable, never "guaranteed") and the drift monitor. They
   train on `attach_labels(read_flows(...), labels)` and leave out
   `NOT_SCORED` classes.
2. **Evaluation** (`phase-3/05-evaluation`): splits by day or session,
   leave-one-attack-type-out, cross-dataset holdouts, detection at fixed
   false-alarm rates, precision at a realistic base rate, ECE, observed
   against configured budget, per-class F1, alerts per day, mean ± std,
   paired tests; the Suricata comparison (a hand-written EVE file if none
   can be recorded); reports from `results/*.json`; model export and the
   runtime ADR draft; the runbook.
3. **Checks when the data is downloaded** (by the team; this session's
   network could not reach the dataset servers): record every SHA-256 in
   the manifests; check the UNSW-NB15 ground truth's name, columns and time
   format; read the Engelen et al. download page and finish
   `cic-ids2017.toml`; find the CTU-13 time offset with `offsets`; pick one
   small MAWI trace.

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
- No real dataset file was downloaded in this work: the dataset servers
  were out of this session's network reach (refused or not found), and the
  CIC-IDS2017 folder is a registration form. The download script is tested
  against a local web server only.
- The UNSW-NB15, CTU-13 and CIC-IDS2017 mapping files are drafts: the
  readers follow the documented columns, checked on hand-written samples,
  not on the real files.
- CTU-13 publishes botnet-only captures: they test botnet detection, not
  false alarms. MAWI has no ground truth: it counts alerts, it never labels
  normal traffic.
- The lab ground truth's windows were read from the captures themselves,
  because the recording scripts did not log their times.
- Labelling holds one feature file's flows and the ground-truth records of
  its time span in memory at once; very large single files have not been
  tried.

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

Pull request 3:

1. `ml/README.md`, then `ml/fixtures/README.md` (the lab ground truth)
2. `ml/flagman_ml/labels/match.py` with `match_test.py` (the rule on tiny
   examples)
3. `ml/data/labels/*.toml` (the class choices, listed in their README)
4. `ml/data/README.md` (dataset facts; check the "not verified" points)
5. `ml/flagman_ml/datasets/download.py` with `download_test.py`
6. `.github/workflows/product-ci.yml` (the Python job, the freshness step)

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
downloads under ~5 GB. Python lives in product/ml (python -m pytest
there, Python 3.13, requirements.txt pinned). Every push includes a
context .docx and its .md copy in product/docs/context/. Never merge; open draft pull requests, each
branch based on the previous one (phase-3/NN-name). Continue with the
first item of "What is left", and update this file with every pull
request.
```
