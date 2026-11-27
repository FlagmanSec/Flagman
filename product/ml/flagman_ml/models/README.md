# flagman_ml/models

The detection models: how a flow becomes `normal`, an attack class, or
`unknown_suspicious`, with a false-alarm rate that the user chooses (α).
The design and its alternatives are in
[ADR 0014](../../../docs/adr/0014-two-scores-a-conformal-false-alarm-budget-and-temperature-scaling.md).

## The idea in five steps

1. **Split by file.** Some feature files (whole days or sessions) are kept
   aside as the **calibration set**; the others train the models. Never
   random rows: flows of one capture are related, and near-copies on both
   sides would make the models look better than they are.
2. **Classifier.** LightGBM learns the classes from the training flows.
   Its probabilities are then **calibrated** on the calibration flows with
   one number, the temperature, so that "0.9" means about nine in ten.
3. **Anomaly detector.** An Isolation Forest learns what normal traffic
   looks like, from the training files' normal flows only. It scores any
   flow by how unlike normal traffic it is, whatever the attack.
4. **False-alarm budget.** Two scores per flow: suspicion (1 − P(normal))
   and the anomaly score. On the calibration set's normal flows, each gets
   the split conformal threshold for half the budget, α/2. A flow is an
   alert when either score is above its threshold. If new normal traffic
   is like the calibration traffic (exchangeable), at most a share α of
   normal flows raise an alert, on average. That is never a guarantee for
   a real network.
5. **Decision.** No alert: `normal`. An alert whose top class is an
   attack with a probability of at least 0.5: that class. Any other
   alert: `unknown_suspicious`.

The **drift monitor** then compares recent traffic with the calibration
traffic, and says when the budget may no longer hold.

## Files, in reading order

| File | What it does |
|---|---|
| `conformal.py` | the threshold: the ⌈(n+1)(1−α)⌉-th smallest calibration score; infinite (no alert) when n is too small |
| `data.py` | the flows that may train (no background, unlabelled or conflicts), the split by file, the numbers-only matrix for the forest |
| `classifier.py` | LightGBM and temperature scaling |
| `anomaly.py` | the Isolation Forest |
| `openset.py` | the decision for each flow |
| `train.py` | the five steps above, and the training report |
| `predict.py` | a decision per flow; refuses flows of another schema or flow table |
| `drift.py` | alert rate, anomaly scores and features, recent against calibration |
| `bundle.py` | saving and loading the models with a checksum and the library versions |
| `cli.py` | the commands |

Read `conformal_test.py` and `openset_test.py` first: they show the
threshold and the decision on numbers small enough to check by hand.
`train_test.py` shows the whole chain on made-up flows
([`synthetic.py`](../synthetic.py)), including an attack the models never
saw.

## Commands

From `product/ml`, after labelling (see [labels](../labels/README.md)):

```bash
# Train: lab-ssh-logins.parquet is the calibration file. alpha 0.2 only
# because it holds 11 normal flows; real data uses 0.01 or less.
python -m flagman_ml.models train --labels results/labels/lab.parquet \
    --calibration-file lab-ssh-logins.parquet --alpha 0.2 \
    --out results/models/lab fixtures/lab-*.parquet

# A decision per flow, written as Parquet next to the probabilities
python -m flagman_ml.models predict --model results/models/lab \
    --out results/predictions/lab.parquet fixtures/lab-*.parquet

# Is a recent window of traffic still like the calibration traffic?
python -m flagman_ml.models drift --model results/models/lab \
    --report results/drift/lab.json fixtures/lab-normal-traffic.parquet
```

`train` writes a bundle folder: `model.joblib` and `bundle.json` (classes,
flow counts per split, thresholds, temperature, settings, warnings,
schema, flow table, checksums of the training data, library versions).
Loading a joblib file runs code: only load bundles made by this project.

## How many calibration flows

The threshold needs at least 1/(α/2) − 1 normal calibration flows: 199
for α = 0.01, 1,999 for α = 0.001 (`smallest_calibration_set`). With
fewer, the thresholds are infinite, nothing raises an alert, and `train`
warns. More flows make the false-alarm rate of one calibration set closer
to α.

## Limits

- The budget holds on average over calibration sets, for normal traffic
  exchangeable with the calibration traffic. A network changes; watch the
  drift report, and calibrate again on recent normal traffic.
- Both scores take half the budget (the union bound). They often flag the
  same flows, so the false-alarm rate seen can be well below α.
- An attack never seen in training can get a known class with high
  confidence: in `train_test.py`, made-up floods come out as `scan`.
  Leave-one-attack-type-out evaluation measures how often.
- Temperature scaling sets one number for all classes, on the classes the
  calibration files hold. It never changes the top class.
- On the lab files, the pipeline check runs, and that is all it shows: 11
  normal calibration flows, unlike the training ones (the drift report
  flags them), so the thresholds are the largest calibration scores.
