# Flagman ML (phase 3: detection quality)

Python code that labels flows, trains and tests models, and writes the
reports of phase 3. It works on **feature files**: Parquet files that the
Rust program writes with `flagmand extract capture.pcap --out flows.parquet`
(see [flagman-parquet](../core/crates/flagman-parquet/README.md)).

**Python never computes features.** The sensor and the models use the same
Rust code for every number, so a model sees in the lab exactly what it will
see live. Python reads the list of features from each file's footer, never
from "all columns".

## Setup

Python 3.13, from this folder:

```bash
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt   # exact versions, see the file
python -m pytest                             # about 80 tests, a few seconds
```

Run every command from this folder (`product/ml`): the code is not
installed as a package.

## What is here

| Folder or file | What it does |
|---|---|
| `flagman_ml/` | the code, with its tests next to it ([README](flagman_ml/README.md)) |
| `data/` | the datasets: licences, sizes, citations, mapping files and download manifests ([README](data/README.md)) |
| `fixtures/` | small real files for the tests, made from the lab captures ([README](fixtures/README.md)) |
| `requirements.txt` | every Python package, pinned to one version |
| `pyproject.toml` | settings of the test runner |
| `results/` | outputs (labels, models, reports); never committed, rebuilt by the commands |

## From a capture to labelled flows

```bash
# 1. Features (Rust), one file per capture
cargo run --release --manifest-path ../core/Cargo.toml -p flagmand --features parquet -- \
    extract day1.pcap --out flows/day1.parquet

# 2. Labels (Python), with the dataset's mapping file and ground truth
python -m flagman_ml.labels label --mapping data/labels/unsw-nb15.toml \
    --ground-truth data/downloads/unsw-nb15/UNSW-NB15_GT.csv \
    --out results/labels/unsw-nb15.parquet --report results/labels/unsw-nb15.json \
    flows/*.parquet
```

Try it on the lab files, in a few seconds:

```bash
python -m flagman_ml.labels label --mapping data/labels/lab.toml \
    --ground-truth fixtures/lab-ground-truth.csv \
    --out results/labels/lab.parquet fixtures/lab-*.parquet
```

## Reading order

1. [`flagman_ml/flows/`](flagman_ml/flows/README.md): reading feature files.
2. [`flagman_ml/labels/`](flagman_ml/labels/README.md): matching flows with
   a dataset's ground truth.
3. [`data/README.md`](data/README.md): the datasets, and what is verified
   about them.
4. [`flagman_ml/datasets/`](flagman_ml/datasets/README.md): downloading with
   checks.

The models, the evaluation and the reports come in the next steps of
phase 3: see [the handoff](../docs/changes/phase-3-toolkit.md).
