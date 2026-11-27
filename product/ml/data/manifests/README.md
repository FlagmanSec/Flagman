# Download manifests

One TOML file per dataset lists the files to download: where each one goes,
its address, its size as the source page shows it, and its exact size and
SHA-256 once recorded. The format is described in
[`flagman_ml/datasets/manifest.py`](../../flagman_ml/datasets/manifest.py);
the commands in [`flagman_ml/datasets/`](../../flagman_ml/datasets/README.md).

| File | Files listed | How |
|---|---|---|
| `ctu-13.toml` | the botnet-only capture(s) and the labelled flows of all 13 scenarios (28 files) | script |
| `unsw-nb15.toml` | the ground truth CSV; captures to add once their names are known | by hand, then `verify` |
| `cic-ids2017.toml` | none yet: no file name could be verified | by hand, then `verify` |
| `mawi.toml` | none yet: pick one small trace by hand | script, once listed |

No dataset publishes checksums for these files, so every `sha256` starts
empty. The first download (`--record`) or check (`verify`) prints the size
and checksum: paste them here and commit them. Never add a program, an
archive of programs, or an archive whose contents are not known: a test
refuses `.exe` names.
