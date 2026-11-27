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
python -m pytest                             # about 200 tests, about 10 seconds
```

Run every command from this folder (`product/ml`): the code is not
installed as a package.

## What is here

| Folder or file | What it does |
|---|---|
| `flagman_ml/` | the code, with its tests next to it ([README](flagman_ml/README.md)) |
| `data/` | the datasets: licences, sizes, citations, mapping files and download manifests ([README](data/README.md)) |
| `fixtures/` | small real files for the tests, made from the lab captures ([README](fixtures/README.md)) |
| `plans/` | evaluation plans: which files train, calibrate and test ([README](plans/README.md)) |
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

## From decisions to numbers

```bash
# 6. Optional: Suricata on the same test captures, matched to Flagman's flows
python -m flagman_ml.suricata run --capture captures/day4.pcap \
    --rules /var/lib/suricata/rules/suricata.rules --out results/suricata/day4
python -m flagman_ml.suricata match --eve results/suricata/day4/eve.json \
    --out results/suricata/day4.parquet flows/day4.parquet

# 7. Evaluate: train and test per fold and seed, as a plan says (plans/)
python -m flagman_ml.evaluation --plan plans/my-plan.toml

# 8. The report, written only from the results JSON files
python -m flagman_ml.reports --evaluation results/evaluation/my-plan \
    --audit results/audit/my-data.json --out results/reports/my-plan.md
```

The three lab files cannot make a fold (training, calibration and test
files, each with normal traffic), so the evaluation's tests run a plan on
made-up days written as feature files: again a pipeline check. The
Suricata tests read alerts that Suricata 7.0.3 really wrote for the lab
captures, with two local rules instead of ET Open
([`fixtures/README.md`](fixtures/README.md)).

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
7. [`flagman_ml/evaluation/`](flagman_ml/evaluation/README.md) and
   [`plans/`](plans/README.md): measuring on whole files never seen.
8. [`flagman_ml/suricata/`](flagman_ml/suricata/README.md): Suricata on the
   same captures, scored the same way.
9. [`flagman_ml/reports/`](flagman_ml/reports/README.md): reports from
   results files only.

The model export and the runbook come next: see
[the handoff](../docs/changes/phase-3-toolkit.md).
