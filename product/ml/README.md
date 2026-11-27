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
python -m pytest                             # about 140 tests, under 10 seconds
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

## From labelled flows to decisions

```bash
# 3. The shortcut audit: features that alone separate a class
python -m flagman_ml.audit --labels results/labels/lab.parquet \
    --held-out-file lab-ssh-logins.parquet --out results/audit/lab.json \
    fixtures/lab-*.parquet

# 4. Train, keeping whole files aside for calibration
python -m flagman_ml.models train --labels results/labels/lab.parquet \
    --calibration-file lab-ssh-logins.parquet --alpha 0.2 \
    --out results/models/lab fixtures/lab-*.parquet

# 5. A decision per flow, then the drift check on recent traffic
python -m flagman_ml.models predict --model results/models/lab \
    --out results/predictions/lab.parquet fixtures/lab-*.parquet
python -m flagman_ml.models drift --model results/models/lab \
    --report results/drift/lab.json fixtures/lab-normal-traffic.parquet
```

On the lab files these are pipeline checks, not results: 1,081 flows from
three short recordings say nothing about how well Flagman detects.

## Reading order

1. [`flagman_ml/flows/`](flagman_ml/flows/README.md): reading feature files.
2. [`flagman_ml/labels/`](flagman_ml/labels/README.md): matching flows with
   a dataset's ground truth.
3. [`data/README.md`](data/README.md): the datasets, and what is verified
   about them.
4. [`flagman_ml/datasets/`](flagman_ml/datasets/README.md): downloading with
   checks.
5. [`flagman_ml/audit/`](flagman_ml/audit/README.md): the shortcut audit.
6. [`flagman_ml/models/`](flagman_ml/models/README.md): the models, the
   false-alarm budget and the drift monitor.

The evaluation and the reports come in the next step of phase 3: see
[the handoff](../docs/changes/phase-3-toolkit.md).
