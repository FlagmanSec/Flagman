# flagman_ml/reports

Reports written **only from results JSON files**. A report never computes
or types a number: it formats values read from `results/evaluation/...`
(and, optionally, `results/audit/*.json`), names those files with their
SHA-256 checksums, and refuses run files changed since the summary.

| File | What it does |
|---|---|
| `numbers.py` | `fmt`, the one way numbers are printed (4 significant digits), and the helpers of the traceability test |
| `evaluation.py` | the evaluation report: main results, observed against configured budget, paired tests, attacks left out, alerts per day, the shortcut audit |
| `cli.py` | the command |

```bash
python -m flagman_ml.reports --evaluation results/evaluation/my-plan \
    --audit results/audit/my-data.json --out results/reports/my-plan.md
```

`report_test.py` checks the rule: every number of a report (outside
`code` spans, which hold names and checksums) must be a value of one of
its source files, as `fmt` prints it.
