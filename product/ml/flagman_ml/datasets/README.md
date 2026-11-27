# datasets: downloading with checks

Downloads the files listed in a dataset manifest (`data/manifests/*.toml`)
and checks every byte:

- a file already in place is checked (size and SHA-256), not downloaded;
- a broken transfer resumes where it stopped (when the server allows it);
- a file gets its final name only after its size and SHA-256 match the
  manifest; a mismatch is kept as `name.bad` to look at;
- none of the datasets publishes checksums, so the first download needs
  `--record`: it prints each file's size and SHA-256, to paste into the
  manifest and commit. Later downloads are checked against them;
- a selection of 20 GB or more is refused without `--allow-large` (ask the
  team first), and so is one that does not fit on the disk;
- a manifest that names a program (`.exe`) is refused: some dataset folders
  hold the malware samples they recorded, and we never download them.

```bash
python -m flagman_ml.datasets list --manifest data/manifests/ctu-13.toml
python -m flagman_ml.datasets download --manifest data/manifests/ctu-13.toml \
    --dest data/downloads/ctu-13 --only ctu-47/capture20110816.binetflow --record
python -m flagman_ml.datasets verify --manifest data/manifests/unsw-nb15.toml \
    --dest data/downloads/unsw-nb15
```

`--only NAME` and `--skip NAME` choose files (repeat them for several).
Requests carry a generic name (`flagman-ml-download/0.1`) and nothing
about the person running them.

| File | What it does |
|---|---|
| `manifest.py` | reads and checks a manifest |
| `download.py` | the size guard, downloads with resume, checks |
| `cli.py`, `__main__.py` | the commands |
| `manifest_test.py` | every manifest of the repository loads; unsafe entries are refused |
| `download_test.py` | downloads from a small web server on the test machine (no internet) |
