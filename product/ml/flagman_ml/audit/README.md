# flagman_ml/audit

The **shortcut audit**: looking for features that describe how a dataset
was recorded instead of the attack. A model that learns such a shortcut
looks very good on that dataset and raises false alarms elsewhere (in
CS395, a TTL value of 254 did this on UNSW-NB15).

Two steps:

1. **Single-feature separability** (`separability.py`). For every feature
   and every class, the AUC of that feature alone as a score for the
   class, and separability = max(AUC, 1 − AUC). At or above 0.99 the pair
   is **flagged**: one threshold on one feature nearly separates the
   class. Either the attack is that simple (a scan gets no answer), or the
   feature is a testbed fingerprint. Features on the schema's watch list
   (`schema.watched()`: durations, first response time, the largest
   packet, gaps between packets) are marked `watched`: they are the first
   to suspect.
2. **Ablations** (`ablation.py`). LightGBM trained on the training files,
   scored on held-out validation files (macro-F1), with every feature,
   without the watched features, and without each flagged feature (the
   ten most separating ones). A large drop means the model leans on what
   was removed.

The audit points; a person decides which features to drop, with the
report as evidence. The held-out files must be **validation files, never
the final test files**: a feature choice made on the test files would
make their scores look better than they are.

## Files

| File | What it does |
|---|---|
| `separability.py` | AUC from ranks for numbers (an empty value counts as −1), and from the class's share per value for categories |
| `ablation.py` | the three kinds of runs and their macro-F1 |
| `cli.py` | the command and its JSON report |

`separability_test.py` checks the rank formula against scikit-learn and
finds a planted fingerprint; `ablation_test.py` builds flows whose only
clue is a planted watched feature, and shows macro-F1 falling from 1.0
when it is removed.

## Command

From `product/ml`, after labelling:

```bash
python -m flagman_ml.audit --labels results/labels/lab.parquet \
    --held-out-file lab-ssh-logins.parquet \
    --out results/audit/lab.json fixtures/lab-*.parquet
```

The report (`results/audit/*.json`) holds every (feature, class) pair,
the flagged ones, the watch list with its reasons, and each ablation run
with its macro-F1, F1 per class, and drop against "all features".

## Limits

- For categories, the share of the class per value is computed on the
  same flows it scores, so separability is too high when a category has
  many rare values (Flagman's three categories have few values).
- A flagged feature is not proof of a shortcut: a scan really does get no
  answer. The ablation and the cross-dataset evaluation are the evidence.
- On the lab files, nearly everything is flagged and macro-F1 is low:
  1,081 flows from three short recordings. A pipeline check, not a result.
