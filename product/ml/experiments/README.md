# Experiments

Small measurements that support a decision record or the runbook. They
are not part of `flagman_ml`, and nothing in `flagman_ml` imports them.
Their tests run with all the others (`python -m pytest` from
`product/ml`: `pyproject.toml` lists this folder in `testpaths`).

| Folder | What it measures | Used by |
|---|---|---|
| [model-runtime](model-runtime/README.md) | three ways to run the trained classifier outside Python | [ADR 0015 (draft)](../../docs/adr/0015-model-runtime.md) |
| [campaign-sizing](campaign-sizing/README.md) | time, disk and memory of each campaign step, on small runs | the [runbook](../docs/runbook.md) |
