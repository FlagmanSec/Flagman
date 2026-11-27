# flagman_ml/evaluation

Measuring the models honestly: on whole files they never saw, at the
false-alarm rates a home network can bear, with the uncertainty shown.

## The idea, step by step

1. A **plan** (TOML, see [plans/](../../plans/README.md)) lists the
   datasets (a labels file and feature files each) and the **folds**: for
   each, the files that train, the files that calibrate, and the files that
   test. Always whole files (days or sessions), never random rows.
2. Each fold runs once per **seed**. A run trains the models
   (`flagman_ml.models.train`), decides on the test files, and measures.
3. With `leave_one_attack_out = true`, each fold also runs once per attack
   class of its training files **without that class**: the class is then
   an attack the models never saw, as a new attack would be.
4. A fold may test on another dataset's files (**cross-dataset holdout**):
   its classes that the models never trained on count as unseen.
5. Each run is one JSON file in `results/evaluation/<plan>/runs/`; the
   **summary** (`summary.json`) gives the mean ± standard deviation over
   runs, the paired tests, and what happened to each class left out.

## What a run measures

On the test files only (background, unlabelled and conflicting flows are
left out, except for alerts per day):

| Metric | What it says |
|---|---|
| `budget` | false alarms on normal flows against the budget α, with an exact interval; each score against α/2 |
| `rules` | false alarms and detection of three ways of deciding: Flagman's two scores, the classifier alone at α, the anomaly score alone at α; McNemar tests against the two scores |
| `at_fpr` | detection at 0.1%, 0.5% and 1% false alarms (one point of the ROC curve of each score, and of the two-score rule), and whether there were enough normal flows to measure it |
| `precision` | the share of alerts that would be real attacks if 1 flow in 1,000 (or in 100) were an attack (Bayes' rule) |
| `f1` | F1 of each class of the test flows and their mean (macro-F1); `unknown_suspicious` counts as wrong |
| `by_class` | for each attack class: the share that raised an alert, the share named right, and every decision |
| `calibration` | ECE before and after temperature scaling (15 equal-width bins, as Guo et al. 2017), with each bin |
| `alerts_per_day` | alerts per day of capture, per test file, counting every flow |

## Files

| File | What it does |
|---|---|
| `metrics.py` | each metric, on plain arrays (`metrics_test.py` checks them by hand) |
| `paired.py` | mean ± std, the Wilcoxon signed-rank test over runs, the exact McNemar test over flows |
| `plan.py` | reading and checking a plan |
| `evaluate.py` | the metrics of one run |
| `run.py` | running a plan: training, testing, writing one file per run, skipping runs already written |
| `summary.py` | the summary of a plan's runs |
| `cli.py` | the command |

## Command

```bash
python -m flagman_ml.evaluation --plan plans/my-plan.toml
python -m flagman_ml.reports --evaluation results/evaluation/my-plan \
    --out results/reports/my-plan.md
```

A stopped campaign continues where it stopped: runs already written are
skipped. `--summary-only` summarises without running.

## Limits

- Detection at 0.1% false alarms needs at least 1,000 normal test flows
  for one score (2,000 for the two-score rule); the summary counts the
  runs that had enough.
- With few runs, the paired tests cannot say much: with 5 pairs the
  smallest two-sided Wilcoxon p-value is 0.0625.
- Leave-one-attack-type-out runs use the first seed only, to bound the run
  time.
- The tests run a plan on made-up days (`synthetic.py`): a pipeline check
  of the harness, not a result.
