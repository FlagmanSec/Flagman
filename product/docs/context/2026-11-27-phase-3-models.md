> Markdown copy of [`2026-11-27-phase-3-models.docx`](2026-11-27-phase-3-models.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: models and the false-alarm budget

*Context document for draft pull request 4 of the phase 3 toolkit, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/04-models`, built on `phase-3/03-ml-data` (pull request #5). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (items C2, C3 and C4) |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-models.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. The idea, step by step
3. Splitting by file, never at random
4. The classifier and its calibration
5. The anomaly detector
6. The false-alarm budget
7. The decision for each flow
8. The drift monitor
9. Model bundles
10. The shortcut audit
11. The pipeline check on the lab files
12. A change from the plan: temperature scaling
13. How it was checked
14. Known limits
15. What comes next
16. Use of AI

## 1. The short version

- This pull request adds the detection models to `product/ml`: a **classifier** (LightGBM) whose probabilities are calibrated, an **anomaly detector** (Isolation Forest) trained on normal traffic only, a **false-alarm budget** α that the user chooses, a **decision** per flow (normal, an attack class, or `unknown_suspicious`), and a **drift monitor** that says when the budget may no longer hold.
- It also adds the **shortcut audit**: for every feature and every class, how well that feature alone separates the class, with the features that may describe the testbed marked, and ablations that show how much a model leans on them.
- Three commands: `python -m flagman_ml.models train | predict | drift`, and `python -m flagman_ml.audit`. Every output records the checksums of its inputs.
- The budget is a **promise about average behaviour on traffic like the calibration traffic**, never a guarantee for a real network. The documents never say “guaranteed”.
- 66 new Python tests (145 in all, about 7 seconds), on made-up flows and the lab files. On the lab files the commands run end to end: a **pipeline check, not a result**.
- The design and its alternatives are in ADR 0014.

## 2. The idea, step by step

1. Some feature files (whole days or sessions) are kept aside: the **calibration set**. The other files train the models.
2. The classifier learns the classes from the training flows. Its probabilities are then **calibrated** on the calibration flows, so that “0.9” means about nine in ten.
3. The anomaly detector learns what normal traffic looks like, from the training files’ normal flows only. It scores any flow by how unlike normal traffic it is, whatever the attack, even one that no dataset labelled.
4. Each flow gets two scores: **suspicion** (one minus the probability of normal) and the **anomaly score**. On the calibration set’s normal flows, each score gets a threshold for half the budget, α/2.
5. A new flow is an **alert** when either score is above its threshold. An alert gets the classifier’s class when that class is an attack it is sure of (probability 0.5 or more); any other alert is `unknown_suspicious`.
6. Later, the drift monitor compares recent traffic with the calibration traffic.

## 3. Splitting by file, never at random

Flows of one capture are related: the same machines, the same minutes, often near-copies of each other. If random rows went to training and calibration, near-copies would sit on both sides, and the thresholds would be set on flows the models have, in effect, already seen. The false-alarm rate on a new day would then come out above the budget.

So `train` takes `--calibration-file NAME` (repeatable): whole feature files are kept aside. It refuses a name it does not know, and a split that leaves either side empty. Both sides need normal flows, because the budget is set on normal traffic. Classes that never train or score a model (`background`, `unlabelled`) and labelling conflicts are left out first.

## 4. The classifier and its calibration

LightGBM is a free library of gradient-boosted decision trees: many small trees, each one correcting the previous ones. It reads the 37 features, including the three categories and empty values, without any preparation. The settings are fixed and the training is deterministic (the same data and settings give the same model, which a test checks). It uses two threads by default, for a small machine: the runbook, in the next pull request, plans for 2 to 4 virtual CPUs.

Its probabilities are often too sure or not sure enough. **Temperature scaling** corrects them with one number: LightGBM gives one raw score per class, its probabilities are the softmax of those scores, and the scores are divided by the temperature T before the softmax. T above 1 makes the model less sure, T below 1 more sure. T is the value that makes the calibration flows’ true classes most likely (the lowest negative log-likelihood), searched between 0.1 and 10.

- One number for all classes means it can be set when the calibration files hold some classes only, which is the usual case with splits by day.
- It never changes which class comes first, only how sure the model is (a test checks it).
- Source, read and quoted: Guo, Pleiss, Sun and Weinberger, “On Calibration of Modern Neural Networks”, ICML 2017, PMLR 70:1321-1330, section 4.2: “Temperature scaling, the simplest extension of Platt scaling, uses a single scalar parameter T > 0 for all classes”, “T is optimized with respect to NLL on the validation set”, and it “does not affect the model’s accuracy”.
- When T stops at a bound of the search, training warns: the calibration flows were too few, or all too easy.

## 5. The anomaly detector

An Isolation Forest cuts the data at random again and again; an unusual flow ends up alone after few cuts. Trained on normal flows only, its score says how unlike normal traffic a flow is. It needs numbers only, so each category value gets its own 0/1 column, and an empty value becomes −1, which stands apart because every real feature is 0 or more. The columns are the same for every file, because the categories come from the schema.

A test shows it on made-up flows: scans and floods score higher on average than new normal flows.

## 6. The false-alarm budget

The threshold for one score, step by step:

1. Take the n normal calibration flows and their scores.
2. Sort the scores and take the k-th smallest, with k = ⌈(n+1)(1−α)⌉ (⌈ ⌉ means rounding up).
3. A new flow whose score is above it raises an alert.

Worked example from the tests: 19 calibration scores 1, 2, …, 19 and α = 0.1 give k = ⌈20 × 0.9⌉ = 18, so the threshold is 18.

If new normal traffic is **exchangeable** with the calibration flows (roughly: it comes from the same mix, as when the network has not changed), a new normal flow is above the threshold with probability at most α. That is an average over calibration sets, and it says nothing once the traffic changes. Source, read and quoted: Angelopoulos and Bates, arXiv:2107.07511 v6, section 1.1 and Theorem 1 (stated for i.i.d. data, with marginal coverage). A test draws 400 calibration sets and checks that the average false-alarm rate lands between 4.5% and 5.2% for a 5% budget; another shows the rate jumping far above the budget when the traffic shifts.

Flagman has two scores, so each gets α/2. A normal flow raises an alert if it passes either threshold, which has probability at most α/2 + α/2 = α (the union bound). Both scores often flag the same flows, so the rate seen can be well below α.

When n is too small, k is larger than n and no threshold keeps the promise: the threshold is infinite, nothing raises an alert, and training warns. The smallest calibration sets:

| Budget α | Each score gets | Normal calibration flows needed |
|---|---|---|
| 0.2 (the lab check only) | 0.1 | 9 |
| 0.05 | 0.025 | 39 |
| 0.01 | 0.005 | 199 |
| 0.001 | 0.0005 | 1,999 |

## 7. The decision for each flow

| Alert? (either score above its threshold) | The classifier’s top class | Decision |
|---|---|---|
| no | any class | `normal` |
| yes | an attack class, with a probability of 0.5 or more | that class |
| yes | an attack class, with a probability below 0.5 | `unknown_suspicious` |
| yes | `normal` (so the forest found the flow unusual, or the suspicion is above its threshold while normal still comes first) | `unknown_suspicious` |

This is the open-set rule: an alert that the classifier cannot name with confidence is called “something suspicious that looks like nothing we trained on” instead of being given a wrong name. `predict` writes, for every flow, the decision, the top class and its probability, suspicion, the anomaly score, which score raised the alert, and the probability of every class (the evaluation needs them for the calibration error).

Two tests on made-up flows show both sides. Flows with huge uploads, which the classifier never saw and calls normal, are found unusual by the forest and come out `unknown_suspicious`. Made-up floods, a class left out of training, all raise alerts, but the classifier calls them scans and is sure of it, so they come out as `scan`: an unseen attack can get a wrong known name. The evaluation’s leave-one-attack-type-out runs measure how often that happens on real data.

## 8. The drift monitor

`python -m flagman_ml.models drift` compares a recent window of flows with the calibration flows kept in the bundle (at most 20,000 of them), three ways:

- **Alert rate**: the share of recent flows that raised an alert, against the budget, with a one-sided binomial test. If the window is mostly normal traffic, a rate well above α means the budget no longer holds, or that an attack is going on.
- **Anomaly scores**: a Kolmogorov-Smirnov test between the calibration flows’ scores and the recent ones.
- **Features**: the population stability index (PSI) of each feature, over the calibration flows’ deciles, with one more bin for empty values (and the value shares for categories).

A flag means “look, and probably calibrate again on recent normal traffic”, not “the model is wrong”. The limits (a p-value of 0.01, a PSI of 0.2) are starting points to tune on the team’s own traffic, not standards.

## 9. Model bundles

`train` writes a folder with two files:

- `model.joblib`: the classifier, the forest, the thresholds and the drift monitor’s reference flows;
- `bundle.json`: the classes, the flow counts per class on each side, the thresholds, the temperature, the settings, the warnings, the feature schema and flow table settings it was trained with, the checksums of the feature files and the labels file, the library versions, and the SHA-256 of `model.joblib`.

Loading a joblib file runs code stored in it, so bundles are loaded only from this project’s own results, and only after the checksum matches (a changed file is refused, a test checks it). A bundle saved with other library versions loads with a warning. `predict` refuses flows extracted with another feature schema or other flow table settings.

## 10. The shortcut audit

A shortcut is a detail of how a dataset was recorded that happens to separate attacks from normal traffic. In CS395, a TTL value of 254 did this on UNSW-NB15. The audit looks for such details before training.

- **Single-feature separability.** For every feature and every class, the AUC of that feature alone as a score for the class: 0.5 says nothing, 1.0 (or 0.0) separates perfectly. Separability is the larger of AUC and 1 − AUC. At 0.99 or more the pair is flagged. The AUC comes from ranks (the Mann-Whitney statistic, ties counted one half; a test checks it against scikit-learn), an empty value counts as −1, and a category value is replaced by the share of the class among the flows with that value.
- **Watched features** are marked: durations, the first response time, the largest packet sizes and the gaps between packets, which the feature schema lists because they depend on the network where traffic was recorded.
- **Ablations.** LightGBM trained on the training files and scored on held-out **validation** files (never the final test files, because the audit guides which features to keep), with every feature, without the watched features, and without each of the ten most separating flagged features. Macro-F1 averages the F1 of each class, so rare classes count. A large drop means the model leans on what was removed.

A flagged feature is not proof of a shortcut: a scan really does get no answer. The audit points, and a person decides. A test builds flows whose only clue is a planted watched feature: macro-F1 is 1.0 with it, and drops by more than 0.3 without it.

## 11. The pipeline check on the lab files

The commands, run from `product/ml` on the three lab feature files:

```text
python -m flagman_ml.labels label --mapping data/labels/lab.toml \
    --ground-truth fixtures/lab-ground-truth.csv --out results/labels/lab.parquet fixtures/lab-*.parquet
python -m flagman_ml.audit --labels results/labels/lab.parquet \
    --held-out-file lab-ssh-logins.parquet --out results/audit/lab.json fixtures/lab-*.parquet
python -m flagman_ml.models train --labels results/labels/lab.parquet \
    --calibration-file lab-ssh-logins.parquet --alpha 0.2 --out results/models/lab fixtures/lab-*.parquet
python -m flagman_ml.models predict --model results/models/lab \
    --out results/predictions/lab.parquet fixtures/lab-*.parquet
python -m flagman_ml.models drift --model results/models/lab \
    --report results/drift/lab.json fixtures/lab-normal-traffic.parquet
```

What they printed and wrote (every number below comes from that run):

| Step | Output |
|---|---|
| Audit | 30 of the 111 (feature, class) pairs flagged; macro-F1 0.200 on the SSH file with every feature, and the same in every ablation |
| Train | training files: 1,000 scan, 42 normal, 15 brute_force; calibration file: 13 brute_force, 11 normal. Two warnings: the temperature stopped at the bound of 10, and the calibration file has no scan |
| Thresholds | suspicion 0.843, anomaly 0.786: with 11 normal calibration flows and α/2 = 0.1, k = ⌈12 × 0.9⌉ = 11, the largest score |
| Predict | 1,078 normal, 1 scan, 2 unknown_suspicious; 999 of the 1,000 scans were decided normal |
| Drift | on the normal-traffic file: the anomaly scores and 17 features moved since calibration; the alert rate (2 of 42) stayed under the budget |

This shows the commands work and that their warnings fire. It says nothing about how well the models detect: 53 normal flows from two short recordings, and calibration normal flows (SSH logins with a key, a stopped server) that are unlike the training ones, which is exactly what the drift report says. Real datasets, with thousands of normal calibration flows, are needed for any result.

## 12. A change from the plan: temperature scaling

The plan was scikit-learn’s `CalibratedClassifierCV`, which calibrates each class on its own (Platt scaling or isotonic regression). On the lab files it failed: scikit-learn 1.9.1 takes its list of classes from the calibration labels, and the calibration file has no scan, so the classes did not line up (an `IndexError` inside scikit-learn). With splits by day that is the usual case, since a day of a public dataset often holds some attacks only. Temperature scaling needs one number for all classes and works with the classes the calibration files hold. The cost: it cannot fix the calibration of one class alone.

## 13. How it was checked

- 66 new Python tests: the threshold by hand and against the paper’s quantile, the average false-alarm rate over 400 repetitions, too few flows, a shifted network; the split by file; LightGBM with temperature scaling; the forest; each branch of the decision; PSI, the alert-rate and score tests and the drift report; bundles; training on made-up flows (including the unseen attack and the huge uploads); predictions and their refusals; separability and ablations with planted fingerprints; and every command on the lab files.
- `synthetic.py` makes the made-up flows: each class has simple typical values with the real feature schema. Nothing in it describes real traffic, and no result is ever computed on it.
- Warnings count as failures in the tests. A linter (ruff, run by hand) passes on the new files. Every Python file is under 210 lines; each new folder has a README.
- Both papers were read on their source pages by AI agents and quoted; the conformal threshold was checked against NumPy’s quantile with the definition the paper uses.

## 14. Known limits

- Only made-up flows and the 1,081 lab flows were used. Run time and memory on a real dataset are not measured.
- The budget holds on average, for normal traffic exchangeable with the calibration traffic; never a guarantee for a real network.
- An attack never seen in training can get a known class with high confidence.
- Temperature scaling is set on the classes the calibration files hold.
- Bundles are joblib files: load only this project’s own.
- The drift limits are starting points; its alert-rate test assumes the window is mostly normal traffic.
- For categories, separability is computed on the same flows it scores, so it is too high for a category with many rare values (Flagman’s three categories have 4 to 6 values).

## 15. What comes next

- Pull request 5 (`phase-3/05-evaluation`): splits by day or session, leave-one-attack-type-out, cross-dataset holdouts, detection at 0.1%, 0.5% and 1% false alarms, precision at a realistic base rate, the calibration error (ECE; Guo et al. use 15 equal-width bins), observed against configured budget, per-class F1, alerts per day, mean ± std, paired tests; the Suricata comparison; reports from results files; the model export and its ADR draft; the runbook.
- The full list, with the checks for the team when the data is downloaded, is in `product/docs/changes/phase-3-toolkit.md`.

## 16. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request. The two papers were read on their source pages by AI agents and quoted. Every number here comes from a test or from the run of the commands on the lab files shown in section 11. The team reviews and merges; the AI never merges.
