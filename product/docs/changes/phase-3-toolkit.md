# Phase 3 toolkit: state and handoff

Status: the toolkit is complete, on draft branches; the full campaign is
the team's. Date: 2026-11-27.

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
| 4 | `phase-3/04-models` | #6 (draft) | shortcut audit, LightGBM with temperature scaling, Isolation Forest, open-set rule, conformal false-alarm budget, drift monitor, model bundles, ADR 0014 | done |
| 5 | `phase-3/05-evaluation` | #7 (draft) | evaluation harness (plans, folds and seeds, attacks left out, cross-dataset tests, metrics, mean ± std, paired tests) and reports written only from `results/*.json` | done |
| 6 | `phase-3/06-suricata` | #8 (draft) | the Suricata comparison (`suricata -r`, EVE alerts matched to flows, Suricata scored in the evaluation), EVE test files recorded on the lab captures | done |
| 7 | `phase-3/07-export-runbook` | #9 (draft) | model export (LightGBM text; ONNX tried), runtime measurements and ADR 0015 (draft), the runbook with its sizing runs | done |

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

### 4. Models (`phase-3/04-models`)

- `flagman_ml/models`: `train` splits the labelled flows by file (the
  `--calibration-file` files are kept aside), trains LightGBM on the
  others and calibrates its probabilities by temperature scaling on the
  calibration files (one number for all classes, so a calibration day
  that holds some attacks only is fine), trains an Isolation Forest on the
  training files' normal flows, and sets two split conformal thresholds
  on the calibration files' normal flows, each at α/2: suspicion
  (1 − P(normal)) and the anomaly score. `predict` writes a decision per
  flow (`normal`, an attack class, or `unknown_suspicious`) with every
  probability; `drift` compares a recent window with the calibration
  flows (binomial test of the alert rate, KS test of the anomaly scores,
  PSI per feature). Bundles hold the models and `bundle.json` (data
  checksums, schema, flow table, thresholds, temperature, warnings,
  library versions, the model file's checksum, checked before loading).
- `flagman_ml/audit`: single-feature separability (AUC from ranks, every
  feature against every class, flagged at 0.99, watched features marked)
  and ablations (macro-F1 on validation files with all features, without
  the watched ones, without each of the ten most separating flagged ones).
- `flagman_ml/synthetic.py`: made-up flows with the real schema, for the
  model tests only.
- [ADR 0014](../adr/0014-two-scores-a-conformal-false-alarm-budget-and-temperature-scaling.md).
  Sources read and quoted: Angelopoulos and Bates (arXiv:2107.07511 v6,
  section 1.1) for the threshold, Guo et al. (ICML 2017, PMLR
  70:1321-1330, section 4.2) for temperature scaling.
- Changed from the plan: probabilities are calibrated by temperature
  scaling, not per class. scikit-learn 1.9.1's `CalibratedClassifierCV`
  takes its classes from the calibration labels and failed on the lab
  files (no scan in the calibration file); with splits by day, that is
  the usual case.

### 5. Evaluation and reports (`phase-3/05-evaluation`)

- `flagman_ml/evaluation`: a plan (TOML, `ml/plans/`) lists datasets
  (labels file and feature files) and folds (training, calibration and
  test files, always whole files). Each fold runs per seed; with
  `leave_one_attack_out`, again without each attack class of its training
  files (first seed); a fold may test on another dataset. Each run trains,
  decides and writes `results/evaluation/<plan>/runs/<run>.json`: the
  budget (false alarms on normal test flows against α, exact
  Clopper-Pearson intervals, each score against α/2), three ways of
  deciding (two scores, classifier alone at α, anomaly score alone at α,
  with McNemar tests), detection at 0.1%, 0.5% and 1% false alarms (and
  whether the test had enough normal flows to measure it), precision at
  base rates of 0.1% and 1%, per-class F1 and macro-F1, detection and
  naming per class, ECE before and after calibration (15 bins), alerts per
  day per file. Runs already written are skipped. `summary.json`: mean ±
  std over runs, Wilcoxon tests paired by run, the classes left out.
- `flagman_ml/reports`: Markdown from `summary.json`, the run files (their
  checksums checked) and an audit report; every number goes through one
  formatting function, and a test checks that each number of a report is
  a value of its source files.
- `synthetic.write_day` and `write_labels`: made-up days written as real
  feature files with labels files, so the harness is tested end to end
  (the three lab files cannot make a fold).
- `train` now sets aside calibration flows of a class absent from training
  (with a warning) instead of failing: with splits by day, a calibration
  day can hold an attack the training days do not.

### 6. Suricata comparison (`phase-3/06-suricata`)

- `flagman_ml/suricata`: `run` runs `suricata -c <config> -r <capture>
  -S <rules> -l <out> -k none --runmode single` (optionally `--set
  vars.address-groups.HOME_NET=...`) and writes `run.json` (Suricata's
  version, the command, the checksums of the capture, rules and
  configuration). `match` reads the alert lines of `eve.json` (or `.gz`),
  gives each alert to the Flagman flow with the same protocol and ends
  whose first and last packets hold the alert's packet time (cut to the
  millisecond, as Flagman cuts its times; the labelling rule of
  `labels/match.py`), counts unmatched alerts, and writes a Suricata file
  (per flow: alerts and rule numbers; footer: feature file and EVE
  checksums, `run.json`, counts). It refuses an EVE file from another
  capture, and an EVE file without `run.json` unless `--origin` says
  where it comes from.
- The evaluation: a dataset may list Suricata files (`suricata = [...]`);
  a fold whose test files all have one scores Suricata as a fourth way of
  deciding (false alarms, detection, McNemar against the two scores,
  precision at the base rates, each attack class, alerts per day). The
  summary adds the Suricata metrics, Wilcoxon tests against it and the
  mean alerted share per attack class for Flagman and Suricata; the
  report adds those and where Suricata's alerts come from.
- Test files **recorded**, not hand-written: Suricata 7.0.3 (Ubuntu
  24.04.5 package) on the three lab captures with two local rules
  (`ml/fixtures/suricata/local.rules`), because rules.emergingthreats.net
  is refused by this session's network proxy (checked again on
  2026-11-27). All 1,035 alerts land on a lab flow. A few hand-written
  lines in `eve_test.py` cover what the recordings lack, marked as such.
- Found while building it: two Suricata runs of the same capture gave the
  same alerts in the same order but other `flow_id` values, so matching
  does not use `flow_id`.

### 7. Export, runtime and runbook (`phase-3/07-export-runbook`)

- `flagman_ml/export`: `python -m flagman_ml.export --model <bundle> --out
  <folder> [--check FILES]` writes `classifier.txt` (LightGBM's text
  model) and `export.json` (the 37 inputs in order, category codes, empty
  values as NaN, classes, how raw scores become probabilities, the
  temperature, thresholds and confidence, checksums, the LightGBM
  version). `--check` reloads the text model, feeds it the numeric input
  matrix and records the largest raw score difference from the bundle
  (below 1e-12 on the lab model). The Isolation Forest is not exported.
- `ml/experiments/model-runtime`: the classifier run three ways outside
  Python, on made-up flows (`2026-11-27-measurements.json`). Generated C
  code (`codegen.py`, written here) and LightGBM's C API both gave exactly
  LightGBM's raw scores; ONNX Runtime gave probabilities within 8.6e-8.
  Medians of 5 runs, one flow at a time on one thread: 5.5 µs per flow
  for generated code, 31.9 µs for the C API, 31.8 µs for ONNX Runtime
  (timed from Python). `bench_test.py` checks the two exact results in CI
  with a C compiler only. The Isolation Forest converted to ONNX gave
  scores within 2.6e-7.
- [ADR 0015](../adr/0015-model-runtime.md), a draft: it proposes generated
  code for both editions, with LightGBM's text file as the source, and
  lists what to check before accepting it (the router, the Rust build, a
  forest generator, how models are updated). Nothing in the sensor uses a
  model yet.
- [`ml/docs/runbook.md`](../../ml/docs/runbook.md): the campaign on a VM
  with 2 to 4 CPUs and 1 to 8 GB, with commands, disk, time, memory, the
  results layout and how to continue after a crash.
  `ml/experiments/campaign-sizing` measured its numbers on the lab
  captures repeated 320 times (102 MB) and on made-up training flows
  (`2026-11-27-sizing.json`). Two findings shape it. Suricata's `eve.json`
  was 4.1 times the capture with Ubuntu's default configuration, hence
  "match, then compress". Training 1,000,000 flows peaked at 1,422 MB.

## What is tested

| Pull request | Tests |
|---|---|
| 1 | 7 new in `flagman-core` (data size: whole, cut by the capture, padding, UDP, IPv6, broken length field; the extension slot: every packet in order, evicted flows), 22 in `flagman-features`: a worked example by hand, 8 shortcut tests (addresses, IPv6, ports, steady TTL, TTL change, link layer, clock time, TCP options), memory per flow, schema and README in step. All 93 earlier Rust tests unchanged and passing |
| 2 | 5 new in `flagman-core` (ties: same end order on every run, the same flow ended when a full table has equally old flows, both failing without the tie-break; end reason names; an engine with an extension gives the same flows and alerts as the sensor's; the live/replay difference after a silence), 6 in `flagman-parquet` (columns in schema order, footer, values and nulls read back, same rows same bytes, row groups, empty file), 1 command-line test, and with `--features parquet` 4 in `flagmand` (the extracted flows are exactly the sensor's flows on the three lab captures, one row per flow, no file left after a failure, no overwrite without `--overwrite`) and `tests/extract.rs` (the program run twice on each lab capture gives byte-identical files; without the tie-break the attack chain gave different files 3 times out of 3). 134 tests without the feature, 139 with it, plus 1 ignored. pyarrow 26.0.1 reads the files (checked by hand; the Python tests come with pull request 3) |
| 3 | 79 Python tests, in under 3 s: reading (one row per flow, inputs are only the features, fixed categories, files stacked with their names; refusals: unknown schema version, missing footer, unknown kind, same file name, other flow table settings, a category outside the schema), matching on tiny examples (either direction, empty ports, exact conversations, protocol, tolerance, offset, most specific wins, longest overlap wins, no match), the four readers on hand-written samples, mapping files (all repository files load, patterns in order, every unknown label listed, five kinds of mistakes), labelling the lab (1,000 scan, 28 brute_force, 53 normal, no conflict; 2 conflicts with 1 s of tolerance, same labels), the offset finder (a 3-hour shift found, no other offset matches), labels files (join back, provenance, same bytes twice, refusal of a changed feature file), the commands, manifests (all load, unsafe entries refused, selection) and downloads from a local web server (checked download, resume, server without ranges, wrong checksum, no checksum without `--record`, file already there, the 20 GB guard, the disk check). Rust tests unchanged |
| 4 | 66 new Python tests (145 in all, about 7 s): the conformal threshold (the k-th smallest score by hand, the paper's quantile, too few flows means no alert, the smallest calibration set, the false-alarm rate over 400 repetitions within the budget, a shifted network above it, α checked), the split by file, the forest's matrix, LightGBM with temperature scaling (probabilities sum to 1, the top class never changes, a too-sure model is softened, two classes, refusals, same data same model), the forest (attacks score higher), each branch of the decision, PSI, the alert-rate and score tests, the drift report, bundles (round trip, changed file refused, other library versions warn), training on made-up flows (report, the false-alarm rate on new normal flows under 7% for a 5% budget, known attacks named, an unseen attack still alerts, huge uploads called normal by the classifier come out `unknown_suspicious`, too few calibration flows, no normal calibration flow refused), predictions (columns, refusals of another flow table or schema), separability (the rank formula against scikit-learn with ties, a planted watched fingerprint flagged, categories), ablations (macro-F1 falls from 1.0 when the planted feature is removed), and the commands on the lab files (pipeline checks). Rust tests unchanged |
| 5 | 31 new Python tests (176 in all, about 10 s): every metric on numbers checked by hand (intervals, detection at a false-alarm rate, too few normal flows, the two-score rule, Bayes' rule, ECE by hand and on bin edges, macro-F1 with `unknown_suspicious`, detection per class, alerts per day), mean ± std, Wilcoxon (smallest p-value with 5 pairs), exact McNemar, plans (the example plan loads; seven kinds of mistakes refused), a whole plan on made-up days (runs written once, leave-one-out runs, unseen classes, summary, runs not run twice), the report (every number from its source files; changed run files refused), calibration flows of an untrained class set aside. Rust tests unchanged |
| 6 | 29 new Python tests (205 in all, about 10 s): the recorded files name the committed rules and captures (checksums), reading EVE lines (the recorded alerts, times with a zone offset, ICMP without ports, other protocols, gzip, four kinds of broken lines named by number), matching on hand-checked flows (answer side first, the later of two flows with the same ends, a time cut to the millisecond, ports, protocols, the tolerance and the nearer flow), counts per flow, the runner with a stand-in program (the documented command, `run.json`, failures), the commands on the recorded lab files (every alert matched, alerted flows per class, refusals), and Suricata scored in a whole plan on made-up days with made-up alerts. Suricata itself is not needed by the tests. |
| 7 | 7 new Python tests (212 in all, about 15 s): the export (category codes and empty values in the input matrix, an exact reload for three classes and for two, the command on the lab model with its refusal to overwrite), generated C code and the C API program giving exactly LightGBM's raw scores on 300 made-up flows with empty values (needs a C compiler; skipped without one), and the long capture of the sizing runs. The ONNX part of the measurements needs extra packages and is not part of the tests. Rust tests unchanged |

## What is left, in order

1. **Review and merge** (the team): #2 into `main`, then #3 to #9 in
   order, each rebased on `main` after phase 2. Never merged by Claude.
2. **Checks when the data is downloaded** (the team; this session's
   network could not reach the dataset servers): record every SHA-256 in
   the manifests; check the UNSW-NB15 ground truth's name, columns and time
   format; read the Engelen et al. download page and finish
   `cic-ids2017.toml`; find the CTU-13 time offset with `offsets`; pick one
   small MAWI trace; write the evaluation plans from the real file names.
3. **The campaign**, with [the runbook](../../ml/docs/runbook.md),
   including Suricata with ET Open (`sudo suricata-update`, then
   `python -m flagman_ml.suricata run` with `--home-net` set to each
   dataset's internal networks).
4. **Decide ADR 0015** with the campaign's models: measure on the router
   (phase 2.5), choose how Rust builds the generated code, write the
   Isolation Forest generator and its exact-score test, and decide how
   models are updated. Wiring the model into `flagmand` comes after that,
   in a later phase.
5. Optional, CI: the "Install libpcap" step failed once on #3 because the
   runner image's Microsoft package source answered 403 (it passed on the
   one re-run). The step could refresh only Ubuntu's package lists; to
   check on a runner first.

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
- The models were only run on made-up flows and the 1,081 lab flows. On
  the lab files the pipeline check runs, and shows nothing more: 11 normal
  calibration flows, unlike the training ones, so the thresholds are the
  largest calibration scores and most scans pass as normal. Their
  run time and memory on a real dataset are not measured.
- The false-alarm budget holds on average for normal traffic exchangeable
  with the calibration traffic; it is never a guarantee for a real
  network. The union bound (α/2 per score) is cautious.
- An attack never seen in training can get a known class with high
  confidence (made-up floods come out as `scan`); leave-one-attack-type-out
  evaluation measures it.
- Temperature scaling is set on the classes the calibration files hold,
  and cannot fix one class's calibration alone.
- Model bundles are joblib files, which run code when loaded: load only
  this project's own bundles. The library versions must match
  `requirements.txt` (a warning says when they differ).
- The drift monitor's limits (p-value 0.01, PSI 0.2) are starting points,
  not standards. Its alert-rate test assumes the window is mostly normal
  traffic.
- The evaluation was only run on made-up days. Detection at 0.1% false
  alarms needs 1,000 normal test flows per score (2,000 for the two-score
  rule); with 5 runs, the smallest Wilcoxon p-value is 0.0625.
  Leave-one-attack-type-out runs use the first seed only.
- No evaluation plan for a real dataset is committed: the capture file
  names are to be checked on the downloaded files.
- Suricata was only run on the three lab captures, with two local rules
  written for the check; ET Open was never run here. The lab alerts check
  the code and say nothing about Suricata's quality.
- Suricata scores a flow yes or no (at least one alert): it has no score
  to move, so it has no "detection at a false-alarm rate", and its alerts
  are not named with Flagman's classes.
- Rules that use thresholds (such as "the 21st request in 10 seconds")
  alert on some flows of an attack and not others (20 of the 1,000 lab
  scan flows raised none: the rule alerts only after its 20th match).
  Scoring per flow counts each flow, so a rule
  that alerts once per attack scores a low detection even when it found
  the attack.
- `--home-net` must name each dataset's internal networks, or rules that
  look at traffic towards `$HOME_NET` stay silent.
- Matching needs the same capture for both tools (checked by name through
  `run.json`) and assumes Suricata's alert time is the time of a packet of
  the flow, as it was for every lab alert.
- The runtime measurements used made-up flows on one shared x86-64 cloud
  machine, not the router. ONNX Runtime was timed from Python only, and
  the C API one flow per call only. Library sizes are those of the PyPI
  packages for x86-64.
- `codegen.py` follows LightGBM v4.7.0's split rules (numbers, categories,
  missing values) and was checked on made-up flows only. Generated Rust
  was not tried, and the Isolation Forest has no generator yet.
- The runbook's numbers come from small runs: the lab captures repeated
  (small packets, and flows that compress far better than real ones) and
  made-up training flows. Nothing was run on a full dataset, and
  Suricata-Update and ET Open are untested here.

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

Pull request 4:

1. [ADR 0014](../adr/0014-two-scores-a-conformal-false-alarm-budget-and-temperature-scaling.md)
2. `ml/flagman_ml/models/README.md`, then `conformal.py` with
   `conformal_test.py`
3. `ml/flagman_ml/models/openset.py` with `openset_test.py`
4. `ml/flagman_ml/models/classifier.py` (temperature scaling) and
   `train.py` with `train_test.py`
5. `ml/flagman_ml/audit/README.md`, `separability.py`, `ablation_test.py`
6. `ml/flagman_ml/models/drift.py` (the limits to tune)

Pull request 5:

1. `ml/flagman_ml/evaluation/README.md`, then `metrics_test.py` and
   `metrics.py`
2. `ml/plans/README.md` and `example.toml`
3. `ml/flagman_ml/evaluation/evaluate.py` and `run.py`
4. `ml/flagman_ml/reports/report_test.py` and `evaluation.py`

Pull request 6:

1. `ml/flagman_ml/suricata/README.md`
2. `ml/flagman_ml/suricata/match.py` with `match_test.py`
3. `ml/fixtures/suricata/local.rules` and the Suricata part of
   `ml/fixtures/README.md`
4. `ml/flagman_ml/suricata/cli_test.py` (the lab pipeline check)
5. The Suricata parts of `evaluation/evaluate.py`, `run.py`, `summary.py`
   and `reports/evaluation.py`

Pull request 7:

1. [ADR 0015 (draft)](../adr/0015-model-runtime.md)
2. `ml/flagman_ml/export/README.md`, then `lightgbm_text.py` with
   `lightgbm_text_test.py`
3. `ml/experiments/model-runtime/codegen.py` with `bench_test.py` (the
   split rules, checked against LightGBM)
4. `ml/docs/runbook.md`, with `ml/experiments/campaign-sizing/README.md`
   for where its numbers come from

## Prompt for the next session

```text
You are continuing the Flagman phase 3 toolkit in FlagmanSec/Flagman. The
toolkit is complete on seven draft pull requests (#3 to #9, stacked on #2).
Read product/docs/changes/phase-3-toolkit.md first: it lists the branches,
what is done and tested, what is left in order, and the known limits.
Read the phase 3 prompt (Flagman_phase3_toolkit_prompt.md in the project
files) for the rules: files under ~300 lines, a README per folder, tests
next to the code, every number from a results file, small runs are
"pipeline check, not a result", verify and link every fact, never write
"guaranteed", defensive work only, free tools only, downloads under
~5 GB. Python lives in product/ml (python -m pytest there, Python 3.13,
requirements.txt pinned). Every push includes a context .docx and its .md
copy in product/docs/context/. Never merge and never force-push.
Start by reading the open review comments and CI on #2 to #9 and answer
them on the branch they concern; a fix on a lower branch is merged up
into the branches above it. When the team has downloaded a dataset, help
with the checks of item 2 of "What is left" and follow
product/ml/docs/runbook.md. Update this file with every pull request.
```
