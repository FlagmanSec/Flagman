# flagman_ml

The Python package of the ML pipeline. Each folder does one job; tests sit
next to the code, in files ending in `_test.py`.

| Folder or file | What it does |
|---|---|
| `flows/` | reads feature files and their schema ([README](flows/README.md)) |
| `labels/` | labels flows from a dataset's ground truth ([README](labels/README.md)) |
| `datasets/` | downloads dataset files and checks them ([README](datasets/README.md)) |
| `audit/` | the shortcut audit: features that may describe the testbed ([README](audit/README.md)) |
| `models/` | classifier, anomaly detector, false-alarm budget, decisions, drift ([README](models/README.md)) |
| `evaluation/` | plans of splits by file, runs, metrics, summaries ([README](evaluation/README.md)) |
| `reports/` | Markdown reports written only from results JSON files ([README](reports/README.md)) |
| `files.py` | checksums, safe file replacement, tables with provenance, used by all of the above |
| `synthetic.py` | made-up flows with the real schema, and made-up days written as feature files, for the tests only |
| `testing.py` | helpers for the tests only (paths of the test files, rewriting a feature file) |
| `conftest.py` | a fixture shared by the evaluation and report tests (pytest reads it by itself) |

Every command runs as `python -m flagman_ml.<folder>` from `product/ml`;
add `--help` to see its options.
