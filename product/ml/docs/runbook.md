# Runbook: the full phase 3 campaign on a small Linux VM

This page is for the person who runs the whole campaign later, on a Linux
virtual machine with 2 to 4 virtual CPUs and 1 to 8 GB of memory. It gives
the commands in order, the disk and time to expect, where every result
goes, and how to continue after a crash.

**Nothing here has been run on a full dataset yet.** The sizes and times
come from small runs on one shared cloud machine with 4 CPUs (pipeline
checks, not results), saved in
[`experiments/campaign-sizing/2026-11-27-sizing.json`](../experiments/campaign-sizing/2026-11-27-sizing.json).
Each number below says where it comes from. Time the first file of every
step on the real data, then plan the rest from that.

Run every command from `product/ml` unless a step says otherwise.

## 0. Before you start

- [ ] **The team's yes for big downloads.** The brief asks before any
  dataset of 20 GB or more. The download tool refuses such a selection
  unless you add `--allow-large`, and it also refuses one that does not fit
  on the disk.
- [ ] **Only the public datasets in `data/manifests/`.** Never download a
  program from a dataset folder. The tool refuses a manifest that names a
  program (`.exe`), and the CTU-13 manifest leaves out the malware samples
  that its folders also hold ([`data/README.md`](../data/README.md)).
- [ ] **Run it inside `tmux`**, so the campaign survives a dropped SSH
  connection: `tmux new -s campaign`, and `tmux attach -t campaign` to
  come back.
- [ ] **The disk** (section 2) and **the memory** (section 3) fit the
  datasets you chose.

## 1. Set up the VM (once)

Ubuntu 24.04 is assumed, because CI uses it. On Ubuntu 24.04.5, `apt-cache
policy python3` shows Python 3.12, while this code needs Python 3.13
(`pyproject.toml`), so install Python 3.13 from a source the team trusts.

```bash
sudo apt-get update
sudo apt-get install -y git build-essential libpcap-dev suricata suricata-update
# Rust: install rustup (https://rustup.rs). The version comes from
# product/core/rust-toolchain.toml.
git clone <the repository> && cd <the repository>/product

# The sensor, with `flagmand extract` (the parquet feature)
(cd core && cargo build --release -p flagmand --features parquet)

# The Python side
cd ml
python3.13 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest            # every test should pass before the campaign
```

Suricata-Update is a separate Ubuntu package (`apt-cache policy
suricata-update`), hence the last name above. For Suricata's rules, run
`sudo suricata-update` once for the whole campaign. Its documentation says that this downloads the Emerging Threats
Open ruleset and merges it into `/var/lib/suricata/rules/suricata.rules`
([Suricata-Update](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)).
This session could not reach the ruleset's server, so this step is
untested.

## 2. Disk: what each step writes

| What | Size | Where the number comes from |
|---|---|---|
| UNSW-NB15 captures | "100 GB of the raw traffic" | the dataset page, in [`data/README.md`](../data/README.md) |
| CIC-IDS2017 captures | 51 GB (5 days) | the same |
| CTU-13 botnet captures | about 85 GB, or 14 GB without scenario 51 | the same |
| Feature files | 51 bytes per flow for the lab files. Plan for up to 384 bytes per flow (the size in memory) until the first real file shows its own | `lab_feature_files` and `extract.pandas_bytes_per_flow` in the sizing file |
| Suricata's `eve.json` | 4.1 times the capture on the repeated lab capture. It held 345,920 flow events (Ubuntu's default configuration logs every flow) and 331,200 alerts | `suricata.eve_bytes` / `extract.capture_bytes`, `suricata.eve_events` |
| Suricata's `fast.log` | 69,584,960 bytes for the same 102 MB capture | `suricata.files_bytes` |
| Labels, runs, reports, models | small next to the above | |

**Suricata's logs are the trap.** If that ratio held, 100 GB of captures
would need about 400 GB of `eve.json`. So work one capture at a
time: run, match, then compress. `gzip eve.json` keeps every byte, and the
matcher also reads `eve.json.gz`. Then delete `fast.log`, which the
matcher does not use. You could also give `--config` a copy of
`suricata.yaml` that logs only alerts. `run.json` records that file's
checksum, so the report says which configuration ran.

## 3. Memory: what fits in 1 to 8 GB

`flagmand extract` stays small, whatever the capture: 102.6 MB at most for
345,920 flows. Its flow table is capped, and it writes in row groups of
65,536 rows ([flagman-parquet](../../core/crates/flagman-parquet/README.md)).
Labelling reads one feature file at a time.

Training is what grows. These peaks were measured on made-up flows with
the default settings (LightGBM on 2 threads), with a quarter as many
calibration flows again (`training` in the sizing file):

| Training flows | Peak memory | Time |
|---|---|---|
| 100,000 | 470.9 MB | 9.1 s |
| 300,000 | 632.1 MB | 15.7 s |
| 1,000,000 | 1,422.3 MB | 56.9 s |

Between 300,000 and 1,000,000 flows, the peak grows by about 1.13 MB per
1,000 flows ((1,422.3 − 632.1) / 700). Here is a guess for each VM size.
It leaves about 0.5 GB for the system and for the test files that an
evaluation run also holds. Above 1,000,000 flows, it is a straight-line
guess, not a measurement.

| VM memory | Training flows per run, about |
|---|---|
| 1 GB | 150,000 |
| 2 GB | 1,000,000 |
| 4 GB | 2,500,000 (guess) |
| 8 GB | 6,000,000 (guess) |

Count the flows of a fold's training files: the table assumes calibration
files a quarter that size. If a run does not fit:

- Give the fold fewer or smaller files. The plan chooses them.
- On a 1 or 2 GB VM, add a swap file. The run will be slower, but it is
  less likely to be killed:
  `sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`.
- Run one step at a time, with nothing else running.

## 4. Time: what to expect

| Step | Rate measured | For 100 GB, if the rate held |
|---|---|---|
| Download | your bandwidth | about 2 h 13 min at 100 Mbit/s (100 × 10⁹ × 8 / 10⁸ s) |
| `flagmand extract` | 48.3 MB/s, 1,224,000 packets in 2.1 s | about 35 min |
| Suricata, with 2 rules | 102,096,344 bytes in 8.4 s (12.2 MB/s) | about 2 h 20 min; ET Open has many more rules, so time the first capture |
| Training | the table in section 3 | |

The lab packets are small: the 102 MB capture holds 1,224,000 of them,
about 83 bytes each in the file. Real captures may have larger packets, and
then `extract` may be limited by the disk instead.

An evaluation trains once per run. Each fold has one run per seed and,
with `leave_one_attack_out`, one more run per attack class in its training
files, with the first seed only (`planned_runs` in
`flagman_ml/evaluation/run.py`). The example plan has 2 folds and 5 seeds.
With 3 attack classes in the training files, that makes 2 × (5 + 3) = 16
runs. Multiply by the time of one run.

## 5. The campaign, step by step

For each dataset (here `unsw-nb15`; the file names of its captures are
still to be checked, see `data/README.md`):

```bash
D=unsw-nb15
# 1. Download with checks. No dataset publishes checksums, so the first time,
#    --record prints each file's size and SHA-256: paste them into the manifest
#    and commit it. Add --allow-large only after the team's yes (20 GB or more).
#    UNSW-NB15 and CIC-IDS2017 are downloaded by hand: put the files in
#    data/downloads/$D, then run `verify`, which prints the same lines.
python -m flagman_ml.datasets download --manifest data/manifests/$D.toml \
    --dest data/downloads/$D --record

# 2. Features, one file per capture. A finished file is skipped.
mkdir -p results/flows/$D
for capture in data/downloads/$D/*.pcap; do
    out=results/flows/$D/$(basename "$capture" .pcap).parquet
    [ -e "$out" ] || ../core/target/release/flagmand extract "$capture" --out "$out"
done

# 3. Labels. If few flows match, look for a clock offset first, on one or
#    two files (`offsets` loads all the files it is given). Check the name of
#    the ground truth file on the download (data/README.md gives two spellings).
python -m flagman_ml.labels label --mapping data/labels/$D.toml \
    --ground-truth data/downloads/$D/UNSW-NB15_GT.csv \
    --out results/labels/$D.parquet --report results/labels/$D.json \
    results/flows/$D/*.parquet

# 4. The shortcut audit, with validation files held out (never the test files)
python -m flagman_ml.audit --labels results/labels/$D.parquet \
    --held-out-file <a validation file>.parquet --out results/audit/$D.json \
    results/flows/$D/*.parquet

# 5. Optional: Suricata on each test capture, then match and compress
python -m flagman_ml.suricata run --capture data/downloads/$D/<capture>.pcap \
    --rules /var/lib/suricata/rules/suricata.rules --home-net "<the dataset's internal networks>" \
    --out results/suricata/$D/<capture>
python -m flagman_ml.suricata match --eve results/suricata/$D/<capture>/eve.json \
    --out results/suricata/$D/<capture>.parquet results/flows/$D/<capture>.parquet
gzip results/suricata/$D/<capture>/eve.json && rm results/suricata/$D/<capture>/fast.log

# 6. Write plans/$D.toml (whole files per role; see plans/README.md), then
#    evaluate. Run the same command again after a stop: finished runs are skipped.
python -m flagman_ml.evaluation --plan plans/$D.toml

# 7. The report, from the results files only
python -m flagman_ml.reports --evaluation results/evaluation/<plan name> \
    --audit results/audit/$D.json --out results/reports/<plan name>.md

# 8. The model to ship: train on the files the team chose (never the test
#    files), then export it and check the export on some feature files
python -m flagman_ml.models train --labels results/labels/$D.parquet \
    --calibration-file <calibration file>.parquet \
    --out results/models/$D <training and calibration files>
python -m flagman_ml.export --model results/models/$D --out results/export/$D \
    --check <some feature files>
```

Each tool's README explains its options and checks: `flagman_ml/<tool>/README.md`.

## 6. Where the results go

Everything below is ignored by git (`product/ml/.gitignore`). Commit only
the reports and the files they cite, when the team decides to.

```text
product/ml/
├── data/downloads/<dataset>/        downloads, checked against the manifest
└── results/
    ├── flows/<dataset>/*.parquet     feature files (flagmand extract)
    ├── labels/<dataset>.parquet      one label per flow, with checksums; .json = counts
    ├── audit/<dataset>.json          the shortcut audit
    ├── suricata/<dataset>/<capture>/ eve.json.gz, run.json, Suricata's own logs
    ├── suricata/<dataset>/<capture>.parquet   Suricata's alerts matched to flows
    ├── evaluation/<plan>/runs/*.json one file per run; summary.json gathers them
    ├── reports/<plan>.md             the report
    ├── models/<dataset>/             the trained bundle
    └── export/<dataset>/             classifier.txt and export.json
```

Keep a record of the versions with the results: `pip freeze`,
`flagmand --version` and `suricata -V`. `run.json` already records
Suricata's version and the checksums of the capture, rules and configuration.

## 7. After a crash: how to continue

In general, run the same command again. The table says what a crash can
leave behind at each step.

| Step | What a crash leaves | What to do |
|---|---|---|
| download | `name.part` | run the same command: it resumes where it stopped (when the server allows it), then checks the size and SHA-256. A mismatch is kept as `name.bad` to look at. |
| `flagmand extract` | `<out>.partial` (removed on an error, but not if the process was killed) | run the loop again: finished files are skipped. Delete a leftover `.partial`. Add `--overwrite` to redo one file. |
| labels, Suricata match, predictions | nothing: these tables are written under a temporary name and renamed when complete (`write_table` in `flagman_ml/files.py`) | run again |
| Suricata run | a cut `eve.json` without `run.json` (Suricata writes `eve.json` as it goes, `run.json` only at the end) | `match` refuses an `eve.json` without `run.json`, so the cut file cannot be used by mistake. Run `run` again with `--overwrite`. |
| audit, model training, report, export | a JSON or Markdown file written at the very end, without a temporary name, so a kill during that write could cut it | run again. If the step refuses because its output exists and you doubt it, redo it with `--overwrite`. |
| evaluation | `runs/<run>.json.part` | run the same command: finished runs are skipped, and the unfinished one starts again. A run file is renamed only when complete, so the summary never reads half a run. `--summary-only` rewrites `summary.json` without training. |
| memory (the process was "Killed") | nothing | see section 3: fewer flows per fold, or a swap file. |
