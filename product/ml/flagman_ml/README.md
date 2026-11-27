# flagman_ml

The Python package of the ML pipeline. Each folder does one job; tests sit
next to the code, in files ending in `_test.py`.

| Folder or file | What it does |
|---|---|
| `flows/` | reads feature files and their schema ([README](flows/README.md)) |
| `labels/` | labels flows from a dataset's ground truth ([README](labels/README.md)) |
| `datasets/` | downloads dataset files and checks them ([README](datasets/README.md)) |
| `files.py` | checksums and safe file replacement, used by all of the above |
| `testing.py` | helpers for the tests only (paths of the test files, rewriting a feature file) |

Every command runs as `python -m flagman_ml.<folder>` from `product/ml`;
add `--help` to see its options.
