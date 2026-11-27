# Model runtime: three ways to run the classifier outside Python

The sensor is written in Rust and has no Python, so the trained model has
to run some other way. This folder measures the three ways the brief names,
for [ADR 0015 (draft)](../../../docs/adr/0015-model-runtime.md):

1. **LightGBM's C API**: a C program loads `classifier.txt` (the text model
   that `flagman_ml/export` writes) with LightGBM's own library.
2. **Generated code** ("codegen"): `codegen.py` turns the model's trees into
   one C function, which is compiled into the program. No library at all.
3. **ONNX Runtime**: the model is converted to the ONNX format
   (onnxmltools for LightGBM, skl2onnx for the Isolation Forest) and run by
   Microsoft's ONNX Runtime. Measured from Python only.

**A pipeline check, not a result.** The model is trained on made-up flows
(`flagman_ml/synthetic.py`) with the default settings, and everything ran on
one shared cloud machine. The numbers compare the three ways with each
other; they say nothing about detection, and the real models and the router
will give other sizes and times.

## Files

| File | What it does |
|---|---|
| `measure.py` | trains the model, exports it, runs every measurement, writes `measurements.json` |
| `codegen.py` | LightGBM trees (`Booster.dump_model()`) to one C function, following LightGBM's split rules |
| `codegen_bench.c` | times the generated function, one flow at a time |
| `capi_bench.c` | times LightGBM's C API, one flow at a time (`LGBM_BoosterPredictForMatSingleRowFast`, one thread) |
| `ort_bench.py` | times ONNX Runtime in a fresh Python process, one thread |
| `bench_test.py` | checks that the generated code and the C API program give exactly LightGBM's raw scores |
| `requirements.txt` | the extra ONNX packages, exact versions |
| `2026-11-27-measurements.json` | the measurements the ADR cites |

## Run it

From `product/ml`, in a Python with `requirements.txt` and this folder's
`requirements.txt` installed, with a C compiler (`cc`):

```bash
python -m pip install -r requirements.txt -r experiments/model-runtime/requirements.txt
python experiments/model-runtime/measure.py results/model-runtime
```

It takes about a minute (compiling the generated code is most of it) and
writes `results/model-runtime/measurements.json` with the files it measured.
Without the ONNX packages, the `onnx` part records the import error and the
rest still runs. The test needs no ONNX package:
`python -m pytest experiments`.

## Reading `measurements.json`

- `microseconds_per_flow`: time to score one flow, measured over all 2,000
  test flows, one at a time. Each timing ran `repeats` times (5): `runs`
  holds each run and `median` their median.
- `largest_difference`: the largest gap between that way's raw scores and
  LightGBM's own (`raw_scores` in `flagman_ml/models/classifier.py`). 0.0
  means the same numbers, bit for bit.
- ONNX gives probabilities, not raw scores, so its check is
  `largest_probability_difference` against LightGBM's probabilities
  (temperature 1), plus `same_top_class`: the share of flows whose most
  likely class is the same (1.0 = all of them).
- `rss_kb_*`: the process memory (resident set size, from
  `/proc/self/status`) before and after loading the model.
- `iterations` (C API): boosting rounds in the model, as LightGBM reports
  them (200 rounds × 4 classes = 800 trees).

## What the file says (2026-11-27)

| | C API | Generated code | ONNX Runtime |
|---|---|---|---|
| Same scores as LightGBM | yes, difference 0.0 | yes, difference 0.0 | probabilities within 8.6e-8; same top class for all 2,000 flows |
| Time per flow, median of 5 runs (range) | 31.9 µs (27.9 to 36.5) | 5.5 µs (5.3 to 6.6) | 31.8 µs (30.1 to 34.8), from Python |
| Memory the model adds | 4,648 KB (6,476 to 11,124 KB) | whole program 2,860 KB | 20,616 KB (61,088 to 81,704 KB) |
| Model on disk | 1,480,139 bytes (text) | built into a 594,216-byte program | 890,294 bytes (.onnx) |
| Library | `lib_lightgbm.so`, 9,247,120 bytes | none | `libonnxruntime.so.1.32.0`, 34,824,680 bytes |

Python's LightGBM, for reference, took a median of 134.7 µs per flow one
at a time (runs from 63.6 to 242.8 µs) and 27.4 µs per flow in one batch of
2,000. The Isolation Forest converted to ONNX gave scores within 2.6e-7 of
scikit-learn's.

## Limits

- One machine (Intel Xeon @ 2.10 GHz, 4 CPUs, shared in the cloud). The
  five runs of the C API range from 27.9 to 36.5 µs, 31% apart; Python's
  own LightGBM varies far more (63.6 to 242.8 µs).
- ONNX Runtime was timed from Python, so its time per flow includes
  Python's own call cost; from C or Rust it would be lower. Not measured.
- The C API was timed one flow per call; LightGBM's batch calls were not
  timed from C.
- Library sizes are those of the x86-64 packages from PyPI. Builds for the
  router will differ.
- Asked for every output, ONNX Runtime warns that the converted model's
  `label` output has another shape than declared. `ort_bench.py` asks only
  for the `probabilities` output (the one the check compares), and the
  warning does not appear.
- The ONNX file stores thresholds as 32-bit floats (`nodes_values`) and
  takes 32-bit inputs, while LightGBM uses 64-bit numbers: a value very
  close to a threshold could go the other way. It changed no top class here.
