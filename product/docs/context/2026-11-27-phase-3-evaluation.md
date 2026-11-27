> Markdown copy of [`2026-11-27-phase-3-evaluation.docx`](2026-11-27-phase-3-evaluation.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: evaluation and reports

*Context document for draft pull request 5 of the phase 3 toolkit, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/05-evaluation`, built on `phase-3/04-models` (pull request #6). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (items C5 and C7) |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-evaluation.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. Why evaluation needs rules
3. Plans, folds, seeds and runs
4. Attacks left out, and other datasets
5. What each run measures
6. Summaries and paired tests
7. Reports written only from results files
8. How it was checked
9. Known limits
10. What comes next
11. Use of AI

## 1. The short version

- This pull request adds the **evaluation harness** (`python -m flagman_ml.evaluation --plan plans/<name>.toml`) and the **reports** (`python -m flagman_ml.reports`).
- A **plan** says which whole feature files train, calibrate and test the models, for how many seeds, and whether each attack class is left out of training in turn. A fold may test on another dataset’s files.
- Each run writes one JSON file of metrics: false alarms against the budget α with an exact interval, detection at 0.1%, 0.5% and 1% false alarms, precision at a realistic base rate, ECE before and after calibration, per-class F1 and macro-F1, what happened to each attack class, and alerts per day.
- A summary gives the mean ± standard deviation over runs, paired tests, and the classes left out. Reports are written **only from those files**, and a test checks that every number of a report is a value of its source files.
- 31 new Python tests (176 in all, about 10 seconds). The harness runs end to end on made-up days written as real feature files: a **pipeline check, not a result**. No real dataset was evaluated.

## 2. Why evaluation needs rules

In CS395, 39.6% of normal flows raised an alarm, mostly through a lab shortcut (`sttl = 254` in UNSW-NB15: see ADR 0014 and the glossary). The rules here prevent the usual ways a score looks better than it is:

1. **Whole files, never random rows.** Flows of one capture look alike (same machines, same tools, same hour). A random split puts close relatives on both sides, and the score then rewards remembering the capture.
2. **Test files are used once, at the end.** Choices (features to drop, settings) are made on validation files, never on test files.
3. **False alarms at the rates a home can bear.** At 10,000 flows a day, 1% false alarms means 100 false alerts a day. Detection is measured at 0.1%, 0.5% and 1%.
4. **Rare attacks.** When 1 flow in 1,000 is an attack, precision (the share of alerts that are real) can be low even when detection and false alarms look good. Bayes’ rule shows it.
5. **Uncertainty shown.** Every false-alarm rate comes with an exact interval; results are given as mean ± standard deviation over runs; comparisons come with paired tests.
6. **New attacks.** Leaving each attack class out of training shows what happens to an attack nobody labelled.

## 3. Plans, folds, seeds and runs

A plan is a short TOML file. Here is part of `ml/plans/example.toml`, which shows every field:

```text
name = "example"
alpha = 0.01
seeds = [0, 1, 2, 3, 4]
leave_one_attack_out = true

[datasets.first]
labels = "results/labels/first-dataset.parquet"
flows = ["flows/first/day1.parquet", "flows/first/day2.parquet", ...]

[[folds]]
name = "test-day4"
train = ["day1.parquet", "day2.parquet"]
calibration = ["day3.parquet"]
test = ["day4.parquet"]
```

- A **fold** is one choice of training, calibration and test files. A **seed** fixes the randomness of the models. A **run** is one fold with one seed.
- The plan is checked before anything runs. A file in two roles, an unknown file, a fold without test files, a budget outside 0 to 1, no seed, a missing name or an unknown model setting stops it with a clear message (seven tests).
- Each run is written to `results/evaluation/<plan>/runs/<run>.json` as soon as it ends. A stopped campaign continues: runs already written are skipped.
- Each run records the feature files and labels files it used, with their checksums, the training report and the library versions.

## 4. Attacks left out, and other datasets

- **Leave one attack type out.** With `leave_one_attack_out = true`, each fold runs again once per attack class of its training files, without that class in training and calibration (first seed only, to bound the run time). The test flows of that class are then an attack the models never saw. The summary says how often they still raised an alert, and what they were called: `unknown_suspicious`, or a wrong known class.
- **Cross-dataset holdouts.** A fold may test on another dataset’s files, each dataset with its own labels file. All files must come from the same feature schema and flow table settings (checked). The test’s classes that the models never trained on are listed as unseen.
- A change in training made this possible: a calibration file may now hold an attack class that the training files do not (normal with splits by day). Those flows are set aside from the temperature, with a warning, instead of stopping the run.

## 5. What each run measures

On the test files only. Background, unlabelled and conflicting flows are left out of every metric except alerts per day, where every flow counts.

| Metric | What it says |
|---|---|
| Budget | false alarms on normal flows against α, with an exact (Clopper-Pearson) 95% interval; each score against α/2 |
| Three ways of deciding | Flagman’s two scores, the classifier alone at α, the anomaly score alone at α: false alarms and detection for each, and a McNemar test of each against the two scores on the same flows |
| Detection at a false-alarm rate | at 0.1%, 0.5% and 1%: one point of the ROC curve of each score and of the two-score rule (each score at half the rate), with whether the test had enough normal flows to measure it |
| Precision at a base rate | the share of alerts that would be real if 1 flow in 1,000 (or in 100) were an attack, by Bayes’ rule from the run’s detection and false alarms |
| F1 | F1 of each class of the test flows and their mean (macro-F1); `unknown_suspicious` counts as wrong for every class |
| Per class | for each attack class: the share that raised an alert, the share named right, and every decision |
| Calibration | ECE before and after temperature scaling, on classes the model knows, with each bin: 15 equal-width bins, as in Guo et al. (ICML 2017) |
| Alerts per day | alerts per day of capture, per test file, from the flows’ start and end times |

The thresholds behind “detection at 0.1% false alarms” are read on the test flows: that number describes a score. Flagman itself always sets its thresholds on the calibration files.

Two worked examples from the tests. With 1,000 normal flows scoring 1 to 1,000, “0.1% false alarms” lets one normal flow through, so the threshold is 999; of four attacks scoring 999.5, 995.5, 990.5 and 500, one is caught (detection 0.25), and at 1% three are. With 90% detection, 1% false alarms and 1 attack in 1,000 flows, precision is 0.0009 / (0.0009 + 0.00999): about 8% of alerts are real.

## 6. Summaries and paired tests

- `summary.json` gives, for each main metric, the mean and standard deviation over the runs that left nothing out.
- **Paired tests**: the two-score rule against each score alone, on detection and on false alarms, with the Wilcoxon signed-rank test paired by run. With few runs it cannot say much: with 5 pairs, the smallest two-sided p-value possible is 2/2⁵ = 0.0625 (a test checks it).
- Inside each run, the exact **McNemar** test compares two ways of deciding on the same flows: only the flows where one is right and the other wrong count.
- For each class left out: the runs, its test flows, the mean share that raised an alert, the decisions they got, and the false alarms of those runs.
- The summary also counts the runs whose test files held enough normal flows for each false-alarm rate: with fewer than 2,000 normal test flows, “detection at 0.1% false alarms” for the two-score rule really means “at no false alarm”.

## 7. Reports written only from results files

- `python -m flagman_ml.reports --evaluation results/evaluation/<plan> [--audit results/audit/<x>.json] --out results/reports/<plan>.md` writes a Markdown report: main results, observed against configured budget per run, paired tests, attacks left out and their decisions, alerts per day, and the shortcut audit.
- It names its source files with their SHA-256 checksums, and refuses a run file changed since the summary was written.
- Every number goes through one formatting function (4 significant digits). A test reads every number of a report (outside code spans, which hold names and checksums) and checks that it is a value of the source files.

## 8. How it was checked

- 31 new tests: each metric on numbers checked by hand (the two worked examples above, the ECE of a 4-flow example, bin edges, macro-F1 with `unknown_suspicious`, alerts per day), the summary statistics and both paired tests, the plan checks and the example plan, a whole plan on three made-up days (four runs written once, the classes left out, an unseen class, the summary, no run twice), the report rule, and the set-aside calibration flows.
- The made-up days are written by `synthetic.write_day` as real feature files, with the lab files’ footer and made-up metadata, and labelled by `synthetic.write_labels`. The three lab files cannot make a fold: training, calibration and test each need normal flows, and only two of the three files hold any.
- Warnings count as failures; the linter passes on the new files; the longest Python file has 205 lines; each new folder has a README.

## 9. Known limits

- No real dataset was evaluated: the harness ran on made-up days only.
- Detection at 0.1% false alarms needs 1,000 normal test flows for one score, 2,000 for the two-score rule.
- With 5 runs, paired tests cannot go below p = 0.0625. More folds help more than more seeds.
- Leave-one-attack-type-out runs use the first seed only.
- No plan for a real dataset is committed: the capture file names are to be checked on the downloaded files.

## 10. What comes next

- Pull request 6 (`phase-3/06-suricata`): the Suricata comparison, as a fourth way of deciding in the evaluation. Suricata 7.0.3 can be installed in this session, but the ET Open rules server is out of its network reach.
- Pull request 7 (`phase-3/07-export-runbook`): the model export (LightGBM text, ONNX if it works), the runtime ADR draft and the runbook.
- The full list is in `product/docs/changes/phase-3-toolkit.md`.

## 11. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request. Every number here comes from a test or from the code’s constants. The team reviews and merges; the AI never merges.
