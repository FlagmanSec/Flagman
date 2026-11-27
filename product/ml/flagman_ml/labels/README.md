# labels: which flows are attacks

Datasets say what happened in their own words: a list of attacks with
times and addresses (UNSW-NB15), or a label on every flow of their own flow
tool (CIC-IDS2017, CTU-13). Flagman cuts flows with its own flow table, so
its flows are not the dataset's flows. This folder joins the two: each
Flagman flow takes the label of the ground-truth record that describes the
same conversation at the same time.

## The rule

A flow matches a record when the two ends agree (in either direction), the
ports agree where the record gives them, the protocols agree where it gives
one, and the times overlap once the record's window is moved by the
mapping's offset and widened by its tolerance. When several records match,
the most specific one wins (more ports and protocol given), then the one
that overlaps longest, then the first in the file. A flow whose candidates
lead to different classes is marked `conflict`. A flow that matches nothing
gets the mapping's `default_label`: `normal` when the ground truth lists
attacks only (UNSW-NB15, the lab), `unlabelled` when it lists every flow
(CIC-IDS2017, CTU-13), because a flow the dataset does not describe is not
known to be normal.

Every label found in the ground truth must map to a class: one unknown
label stops the run and lists all of them. Two classes never train or
score: `background` and `unlabelled` (see `classes.py`).

## Commands

```bash
python -m flagman_ml.labels label --mapping data/labels/lab.toml \
    --ground-truth fixtures/lab-ground-truth.csv \
    --out results/labels/lab.parquet --report results/labels/lab.json \
    fixtures/lab-*.parquet
python -m flagman_ml.labels offsets --mapping data/labels/lab.toml \
    --ground-truth fixtures/lab-ground-truth.csv fixtures/lab-*.parquet
```

`label` writes one row per flow (`source`, `row`, `label`, `dataset_label`,
`record`, `candidates`, `conflict`) and prints the counts. The file's
footer records the checksums of the mapping, the ground truth and every
feature file, and the counts. `attach_labels(flows, path)` joins labels to
flows and refuses if a feature file changed since it was labelled.

`offsets` tries every offset from -14 h to +14 h in 15-minute steps and
shows which one matches the most flows: for datasets whose time zone is not
stated. Write the winner into the mapping file, with how it was found.

Read the counts: many `unmatched` flows, `conflicts`, or `records_used`
far below `records_in_span` all mean something to check (the offset, the
tolerance, or a capture that does not hold the recorded traffic).

| File | What it does |
|---|---|
| `classes.py` | Flagman's classes, and the two that never train or score |
| `mapping.py` | reads and checks a mapping file (`data/labels/*.toml`) |
| `formats.py` | one reader per ground-truth format, into one table of records |
| `match.py` | the matching rule above |
| `offset.py` | finding the time offset |
| `label.py` | labels one feature file and counts the outcome |
| `store.py` | labels files: writing, reading, joining to flows |
| `cli.py`, `__main__.py` | the commands |

Tests: `*_test.py` next to each file. `formats_test.py` reads small
hand-written samples in each dataset's documented columns (made-up values,
documentation addresses); the other tests use the real lab files.
