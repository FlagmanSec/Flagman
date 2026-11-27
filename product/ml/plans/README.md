# Evaluation plans

A plan says which feature files train, calibrate and test the models, how
many seeds to run, and whether to leave each attack class out in turn.
Run one with `python -m flagman_ml.evaluation --plan plans/<name>.toml`
from `product/ml`. The format is described in
[`flagman_ml/evaluation/plan.py`](../flagman_ml/evaluation/plan.py);
`example.toml` shows every field.

Rules that keep results honest:

- **Whole files only.** Each role takes whole feature files (a day or a
  session of capture), never random rows.
- **Calibration files need normal traffic**: at least 2/α − 1 normal flows
  (199 for α = 0.01). Attacks in them help set the temperature.
- **Test files are used once, at the end.** Choices (features to drop,
  settings) are made on validation files, with the audit
  (`flagman_ml.audit`), never on test files.
- **Cross-dataset holdouts** test on another dataset's files. All files
  must be extracted with the same feature schema and flow table settings.
- **Suricata** is compared on the same test files when the dataset lists
  their Suricata files (`suricata = [...]`, written by
  `python -m flagman_ml.suricata match`, see
  [`flagman_ml/suricata/README.md`](../flagman_ml/suricata/README.md)).
  A fold must have one for every test file, or none.

No plan for a real dataset is committed yet: the file names of each
dataset's captures are to be checked on the downloaded files (see
[`data/README.md`](../data/README.md)).
