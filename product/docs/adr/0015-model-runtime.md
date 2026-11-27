# 0015. How the sensor runs the trained models (draft)

Status: draft, not decided. The team decides after the full phase 3
campaign; nothing in the sensor uses a model yet.
Date: 2026-11-27

## Context

The phase 3 models are trained in Python
([ADR 0014](0014-two-scores-a-conformal-false-alarm-budget-and-temperature-scaling.md)):
a LightGBM classifier (gradient-boosted trees, 37 inputs) and an Isolation
Forest from scikit-learn. The sensor is written in Rust
([ADR 0001](0001-rust-sensor-core.md)) and has no Python, so something
else has to run the trees inside `flagmand`, once for each flow that ends.

It has to work for both editions:

- **Pro**, on a Linux PC.
- **Edge**, on the OpenWrt One router, which has 1 GB of memory. Its
  processor type is to be confirmed on the device before anything is built
  for it ([phase-2-plan.md](../phase-2-plan.md), step 2.5).

What the runtime must do:

- **Give the scores Python gave.** The alert thresholds are set on the
  calibration scores in Python (ADR 0014). If the sensor computed slightly
  different scores, the false-alarm budget α would no longer be the one
  measured.
- Use little memory and little time per flow, so that it fits on the router.
- Have a free licence and build for both editions.

The brief names three ways: compile the trees to native code ("codegen"),
ONNX Runtime, or LightGBM's C API.

## What was measured

[`ml/experiments/model-runtime`](../../ml/experiments/model-runtime/README.md)
tried all three. Every number below comes from its
[`2026-11-27-measurements.json`](../../ml/experiments/model-runtime/2026-11-27-measurements.json).

**This is a pipeline check, not a result.** The model was trained on
made-up flows with the default settings: 200 rounds × 4 classes = 800
trees, 12,141 leaves. It scored 2,000 made-up flows one at a time, on one
thread, five times over, on one shared cloud machine (Intel Xeon @ 2.10
GHz, 4 CPUs). The real models and the router will give other numbers.

| | LightGBM C API | Generated C code | ONNX Runtime |
|---|---|---|---|
| Same scores as LightGBM in Python | yes, largest difference 0.0 | yes, largest difference 0.0 | probabilities within 8.6e-8; same top class for 2,000 of 2,000 flows |
| Time per flow (median of 5 runs) | 31.9 µs | 5.5 µs | 31.8 µs, timed from Python, which adds its own cost |
| Memory | the model adds 4,648 KB | the whole program uses 2,860 KB | the model adds 20,616 KB |
| The model on disk | text file, 1,480,139 bytes | built into the program (594,216 bytes); the C source is 1,970,704 bytes and took 18.0 s to compile | .onnx file, 890,294 bytes |
| Library to ship | `lib_lightgbm.so`, 9,247,120 bytes, which needs `libstdc++` and `libgomp` | none: the program needs only the C library | `libonnxruntime.so.1.32.0`, 34,824,680 bytes, which needs `libstdc++` |
| Isolation Forest | cannot run it | needs its own generator, not written yet | converted with skl2onnx, scores within 2.6e-7 |
| Changing the model | replace the text file | build `flagmand` again | replace the .onnx file |
| Licence | MIT | our own code | MIT (the converters onnx, onnxmltools and skl2onnx: Apache-2.0) |

Where the facts come from:

- The licences are from the packages' own metadata (`pip`), as installed.
- The library sizes are those of the x86-64 packages from PyPI (lightgbm
  4.7.0, onnxruntime 1.32.0).
- The libraries each one needs are from `ldd` on those packages.
- The two "difference 0.0" results are also checked in CI by `bench_test.py`.
  It runs a small model on 300 flows, some of them with empty values. Besides
  the usual Python packages, it needs only a C compiler.

## Proposed decision (to confirm)

- **Both editions run the classifier as generated code.** The trees become
  one C function, compiled into `flagmand`. In this check it gave exactly
  LightGBM's scores, was the fastest of the three (31.9 / 5.5 = about 5.8
  times faster than the C API), used the least memory, and adds no library to
  build or ship for the router. Pro and Edge would run the same code.
- **LightGBM's text file stays the source** the code is generated from.
  `flagman_ml/export` writes it with `export.json`, which holds the input
  order, category codes, classes, temperature and thresholds.
- **The Isolation Forest becomes generated code too**, with a generator to
  write and test against scikit-learn's own scores. Until then, ONNX is the
  only way to run it outside Python that has been tried, and it worked
  (within 2.6e-7).
- **The C API stays the fallback for Pro**, if the team wants to change
  models without building `flagmand` again.

### To check before accepting it

1. Measure on the router (phase 2.5), with the models from the full
   campaign: their sizes and times will differ from these.
2. Choose how Rust builds the generated code: compile the C with a build
   script (the `cc` crate), or generate Rust instead. Measure the build
   time. C took 18.0 s here, and Rust was not tried.
3. Write the Isolation Forest generator and its exact-score test.
4. Decide how models are updated. With generated code, each new model is a
   new `flagmand` build and release.
5. Optional: time ONNX Runtime from C or Rust. It was timed from Python
   only, so its 31.8 µs includes Python's own call cost.

## Consequences

If the proposal is accepted:

- `flagmand` gains a build step that turns the exported model into code,
  and CI checks the generated code against LightGBM, as `bench_test.py`
  already does for the measurement program.
- A model change means a new build and a new release of each edition.
  Retraining has to follow the release schedule.
- No machine learning library runs inside the sensor, so nothing new needs
  building for the router, and the licences are unchanged.

## Alternatives considered

- **LightGBM's C API.** It gives exactly the same scores, and a new model
  is a new file. But it ships a 9.2 MB library that needs `libstdc++` and
  `libgomp`, both of which must also build for the router. It was about
  5.8 times slower per flow here, and it cannot run the Isolation Forest.
- **ONNX Runtime.** One runtime and one file format would serve both
  models, and a new model is a new file. But it had the largest library
  (34.8 MB) and added the most memory (20.6 MB). It also needs two more
  converters to pin and test (onnxmltools and skl2onnx). And the converted
  files use 32-bit numbers: inputs, and thresholds stored as `nodes_values`.
  LightGBM uses 64-bit numbers, so a value very close to a threshold could
  go the other way. That changed no top class in this check.
- **LightGBM's own code generator** (its `convert_model` task, which uses
  `Tree::ToIfElse`). It writes C++, and we did not check whether that code
  builds without LightGBM's sources. We wrote our own generator
  (`codegen.py`, 84 lines) so that the check needs only Python and a C
  compiler.
