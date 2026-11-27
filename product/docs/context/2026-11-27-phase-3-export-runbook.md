> Markdown copy of [`2026-11-27-phase-3-export-runbook.docx`](2026-11-27-phase-3-export-runbook.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: model export, runtime and runbook

*Context document for draft pull request 7 of the phase 3 toolkit, the last one, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/07-export-runbook`, built on `phase-3/06-suricata` (pull request #8). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (items E and F) |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-export-runbook.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. What the prompt asked
3. The model export
4. Three ways to run the model in the sensor
5. What was measured
6. The draft decision (ADR 0015)
7. The runbook
8. How it was checked
9. A note on CI
10. Known limits
11. What is left
12. Use of AI

## 1. The short version

- `python -m flagman_ml.export` writes the trained classifier in LightGBM’s own text format, with a file that holds everything else a program needs to run it. It then reloads the file and checks that it gives the same scores.
- Three ways to run the classifier outside Python were measured on made-up flows: LightGBM’s C library, the trees turned into C code, and ONNX Runtime. The generated code and the C library gave exactly LightGBM’s scores, and the generated code was the fastest and the smallest.
- ADR 0015 is a **draft**. It proposes generated code for both editions and lists what to check before the team decides. Nothing in the sensor uses a model yet, as the prompt asked.
- `product/ml/docs/runbook.md` explains how to run the whole campaign later on a VM with 2 to 4 CPUs and 1 to 8 GB of memory. Its disk, time and memory figures come from small runs that are saved in a file.
- 7 new Python tests (212 in all, about 15 seconds). Everything measured here is a **pipeline check, not a result**. With this pull request the toolkit is complete; the campaign is the team’s.

## 2. What the prompt asked

Item E: “Export the trained LightGBM model in its text format and try ONNX. Write a draft ADR for the model runtime (codegen vs ONNX Runtime vs LightGBM C API), with small measurements if possible. Wiring the model into the Rust sensor is not part of this session.”

Item F: “`ml/docs/runbook.md`: how we run the full campaign later on a 2–4 vCPU Linux VM with 1–8 GB RAM. It covers commands, expected disk and time, where the results go, and how to resume after a crash.”

The brief adds, for the runtime: “Tree ensembles compiled to native code (codegen) vs ONNX Runtime vs the LightGBM C API, per edition. Measure latency and memory.”

## 3. The model export

```text
python -m flagman_ml.export --model results/models/lab \
    --out results/export/lab --check fixtures/lab-*.parquet
```

- `classifier.txt` is LightGBM’s text model, written by LightGBM itself (`Booster.save_model`). Any program linked with LightGBM’s C library can load it.
- `export.json` holds what the trees do not: the 37 inputs in order, the number given to each category value, how an empty value is given (NaN, “not a number”), the class order, how raw scores become probabilities (softmax of the raw scores divided by the temperature), the two thresholds and the confidence the decision uses, the checksums and the LightGBM version.
- **Raw scores** are what the trees add up for each class, before they become probabilities. A runtime must give the same raw scores as Python, or the thresholds set in Python no longer mean the same false-alarm rate.

A worked example, from `lightgbm_text_test.py`. The trees cannot read the word “udp”, so each category value is given as its position in the schema’s list of values. For `protocol`, that is tcp 0, udp 1, icmp 2 and other 3. pandas gives the same values the same codes, so the trees see the same numbers in Python and in any runtime. A value the flow does not have is given as NaN.

- `--check` reloads `classifier.txt`, gives it those numbers for each flow of the feature files, and records the largest difference from the bundle’s own raw scores. On the lab model (1,081 flows, 3 classes) the difference is below 1e-12, the test’s limit. It refuses to replace an existing export unless `--overwrite` is given.
- The Isolation Forest (the anomaly score) is not exported: scikit-learn’s forests have no LightGBM text form. ADR 0015 weighs the options.

## 4. Three ways to run the model in the sensor

The sensor is written in Rust and has no Python. Something has to run the trees inside `flagmand`, once for each flow that ends. A tree is a list of yes/no questions (“is the number of packets at most 4.5?”) that ends in a number; the classifier adds up those numbers over its 800 trees.

1. **LightGBM’s C API.** LightGBM is also a C library. The sensor would load `classifier.txt` at start and ask the library for each flow’s scores. Measured from a small C program, `capi_bench.c`.
2. **Generated code (“codegen”).** A small Python program, `codegen.py` (84 lines), turns every tree into C `if` tests, compiled into the program. No library is needed. It follows LightGBM’s own rules for each split, including empty values, read in LightGBM v4.7.0’s source (`include/LightGBM/tree.h`).
3. **ONNX Runtime.** ONNX is a file format for trained models, and ONNX Runtime is Microsoft’s program that runs such files. The converters onnxmltools (for LightGBM) and skl2onnx (for scikit-learn) wrote the two models in it. Measured from Python only.

## 5. What was measured

All the numbers below come from `product/ml/experiments/model-runtime/2026-11-27-measurements.json`. Setup: a classifier with the default settings, trained on 30,000 made-up flows. With 4 classes, that is 200 rounds × 4 = 800 trees and 12,141 leaves. It scored 2,000 made-up flows one at a time, on one thread, five times over, on one shared cloud machine (Intel Xeon at 2.10 GHz, 4 CPUs).

|  | LightGBM C API | Generated C code | ONNX Runtime |
|---|---|---|---|
| Same scores as LightGBM | yes, difference 0.0 | yes, difference 0.0 | probabilities within 8.6e-8; same top class for all 2,000 flows |
| Time per flow (median of 5 runs) | 31.9 µs (27.9 to 36.5) | 5.5 µs (5.3 to 6.6) | 31.8 µs (30.1 to 34.8), from Python |
| Memory | the model adds 4,648 KB | the whole program uses 2,860 KB | the model adds 20,616 KB |
| Model on disk | 1,480,139 bytes (text) | in a 594,216-byte program; 1,970,704 bytes of C, 18.0 s to compile | 890,294 bytes |
| Library to ship | 9,247,120 bytes; needs libstdc++ and libgomp | none (only the C library) | 34,824,680 bytes; needs libstdc++ |
| Isolation Forest | cannot run it | needs its own generator, not written | converted; scores within 2.6e-7 |
| Licence | MIT | our own code | MIT (converters: Apache-2.0) |

- “Difference 0.0” means the same numbers, bit for bit. A CI test (`bench_test.py`) checks it again on every push: a small model, 300 made-up flows, some with empty values, and only a C compiler needed besides the usual packages.
- Python’s own LightGBM, for reference, took a median of 134.7 µs per flow one at a time.
- The licences come from the packages’ own metadata, the library sizes from the x86-64 packages on PyPI (lightgbm 4.7.0, onnxruntime 1.32.0), and the libraries each one needs from `ldd`.
- The ONNX files store their thresholds as 32-bit numbers (`nodes_values`) and take 32-bit inputs, while LightGBM uses 64-bit numbers. So a value very close to a threshold could go the other way. On these 2,000 flows, no top class changed.

## 6. The draft decision (ADR 0015)

Status: draft, not decided. The team decides after the full campaign, with the real models.

What it proposes:

- Both editions (Pro on a Linux PC, Edge on the OpenWrt One router) run the classifier as generated code. In this check it gave exactly LightGBM’s scores, was about 5.8 times faster than the C API (31.9 / 5.5), used the least memory, and adds no library to build for the router.
- LightGBM’s text file stays the source the code is generated from, with `export.json`.
- The Isolation Forest gets its own generator, to write and test. Until then, ONNX is the only tried way to run it outside Python.
- The C API stays the fallback for Pro, if the team wants to change models without building `flagmand` again.

What to check before accepting it:

1. Measure on the router (phase 2 step 2.5), with the campaign’s models.
2. Choose how Rust builds the generated code (compile the C with a build script, or generate Rust), and time the build.
3. Write the Isolation Forest generator and its exact-score test.
4. Decide how models are updated: with generated code, a new model means a new build and release.

The alternatives and their costs are in the ADR: the C API (exact and easy to update, but a 9.2 MB library and slower here), ONNX Runtime (one runtime for both models, but the largest library, the most memory and 32-bit numbers), and LightGBM’s own C++ generator (not checked).

## 7. The runbook

`product/ml/docs/runbook.md` takes the person running the campaign through the steps in order: a checklist before starting, setting up the VM, disk, memory, time, the commands for each dataset, where every result goes, and what to do after a crash.

Its numbers come from `product/ml/experiments/campaign-sizing/2026-11-27-sizing.json`. Those runs used the three lab captures repeated 320 times (102 MB, 1,224,000 packets, 345,920 flows) and made-up training flows. Real data will differ, so the runbook says to time the first file of every step.

| Step | Measured on the small runs |
|---|---|
| `flagmand extract` | 2.1 s for 102 MB (48.3 MB/s), at most 102.6 MB of memory |
| Suricata 7.0.3, two local rules | 8.4 s; its `eve.json` was 4.1 times the capture (419,417,238 bytes) |
| Feature files | 51 bytes per flow for the lab files; 384 bytes per flow in memory |
| Training 100,000 / 300,000 / 1,000,000 flows | at most 470.9 / 632.1 / 1,422.3 MB of memory; 9.1 / 15.7 / 56.9 s |

Two findings shape the runbook:

- **Suricata’s log is the trap.** Ubuntu’s default configuration logs every flow as well as the alerts. If the ratio held, 100 GB of captures would need about 400 GB of `eve.json`. So the runbook works one capture at a time: run, match, then compress (the matcher reads `.gz` files).
- **Training is what grows.** From these points, a 1 GB VM fits about 150,000 training flows per run, and a 2 GB VM about 1,000,000. The 4 and 8 GB figures are straight-line guesses, marked as such.

After a crash: downloads resume from `name.part`; `extract` writes `.partial` and renames when complete; finished evaluation runs are skipped; a cut Suricata log cannot be matched by mistake (no `run.json`). The runbook has a table for each step.

Two facts found while writing it: Ubuntu 24.04’s own Python is 3.12 while the code needs 3.13, and Suricata-Update is a separate Ubuntu package. Both are in the setup section.

## 8. How it was checked

- 7 new tests. They cover the export (category codes and empty values, an exact reload for three classes and for two, the command on the lab model and its refusal to overwrite). They also cover generated code and the C API program giving exactly LightGBM’s scores, and the long capture of the sizing runs (two copies, 600 s apart).
- 212 tests pass in about 15 seconds; warnings count as failures. The ONNX part needs extra packages (pinned in `experiments/model-runtime/requirements.txt`), so it is not part of the tests.
- Both measurement files can be made again with one command each (see each folder’s README). Every number in the ADR, the runbook and this document is a value of those files, of a test, or of a dataset page quoted in `ml/data/README.md`.
- The linter passes on the new files. Each new Python file is at most 246 lines, and each new folder has a README.

## 9. A note on CI

On pull request #3, the first “Sensor (Rust)” run failed before building anything. The runner’s `apt-get update` stopped because the runner image’s Microsoft package source answered “403 Forbidden”. That source has nothing to do with Flagman. The one re-run passed, and the pull request is green. A note on #3 explains it and proposes a fix for the team to decide: the step could refresh only Ubuntu’s package lists. The handoff lists it as optional.

## 10. Known limits

- The runtime measurements used made-up flows on one shared x86-64 machine, not the router. ONNX Runtime was timed from Python only, and the C API one flow per call only.
- `codegen.py` was checked on made-up flows only. Generated Rust was not tried, and the Isolation Forest has no generator yet.
- The runbook’s numbers come from small runs: repeated lab captures (small packets, and flows that compress far better than real ones) and made-up training flows. Nothing was run on a full dataset. Suricata-Update and ET Open are untested here, because the rules server was out of this session’s reach.
- Times vary from run to run on a shared machine: the five C API runs range from 27.9 to 36.5 µs.

## 11. What is left

1. The team reviews and merges: #2 into `main`, then #3 to #9 in order, each rebased on `main` after phase 2.
2. When the data is downloaded: the checks listed in the handoff (checksums, the UNSW-NB15 ground truth, the CIC-IDS2017 corrections, the CTU-13 time offset, the plans).
3. The campaign, following the runbook, with Suricata and ET Open.
4. Deciding ADR 0015 with the real models, then wiring the runtime into `flagmand` in a later phase.

The full list, the known limits of every pull request and the prompt for a next session are in `product/docs/changes/phase-3-toolkit.md`.

## 12. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request, and ran the measurements in its cloud session. Every number here comes from a test or a committed results file. The team reviews and merges; the AI never merges.
