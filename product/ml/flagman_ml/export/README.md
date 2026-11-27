# export: the classifier, for a runtime outside Python

The sensor has no Python. This folder writes the trained classifier in
LightGBM's own text format, with everything else a runtime needs, and
checks that the written file gives the same scores.
[ADR 0015 (draft)](../../../docs/adr/0015-model-runtime.md) compares the
ways a runtime could run it. Wiring it into the sensor comes later.

| File | What it does |
|---|---|
| `lightgbm_text.py` | `export_classifier` writes `classifier.txt` and `export.json`; `input_matrix` builds the inputs a runtime gives the trees; `check_export` compares the export with the bundle |
| `cli.py` | `python -m flagman_ml.export` |
| `lightgbm_text_test.py` | an example: category codes, empty values, and an exact reload |
| `cli_test.py` | the command on the lab model: 1,081 flows, difference below 1e-12 |

## Run it

From `product/ml`, on a model bundle written by `python -m flagman_ml.models train`:

```bash
python -m flagman_ml.export --model results/models/lab \
    --out results/export/lab --check fixtures/lab-*.parquet
```

It writes into `results/export/lab`:

- `classifier.txt`: LightGBM's text model (`Booster.save_model`). Any
  program linked with LightGBM's C library can load it.
- `export.json`: the 37 inputs in order, the code of each category value
  (for `protocol`: tcp 0, udp 1, icmp 2, other 3), how an empty value is
  given (NaN), the class order, how raw scores become probabilities
  (softmax of the raw scores divided by the temperature), the two
  thresholds and the confidence the decision uses, the checksums and the
  LightGBM version. With `--check`, it also holds the feature files used
  and the largest raw score difference found on their flows.

It refuses to replace an existing `export.json` unless you add `--overwrite`.

## What is not exported

The Isolation Forest (the anomaly score). scikit-learn's forests have no
LightGBM text form. ADR 0015 (draft) weighs the options: generated code, or
ONNX, which `experiments/model-runtime` tried.
