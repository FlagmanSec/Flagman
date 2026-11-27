# Mapping files

One TOML file per dataset says how its ground truth becomes Flagman labels:
which reader to use, the default label, the time zone, offset and
tolerance, and which dataset label goes to which class. The format is
described in [`flagman_ml/labels/mapping.py`](../../flagman_ml/labels/mapping.py).

| File | Dataset | State |
|---|---|---|
| `lab.toml` | our lab captures | checked by the tests on the real files |
| `unsw-nb15.toml` | UNSW-NB15 | draft: columns and time format to check on the real ground truth file |
| `cic-ids2017.toml` | CIC-IDS2017 with Engelen et al.'s corrected labels | draft: file names, columns and date style not verified (their page could not be read) |
| `ctu-13.toml` | CTU-13 | file names verified; time zone not stated, find the offset on the first scenario |

Each file starts with comments that say where its facts come from; the
facts themselves, with links, are in [../README.md](../README.md). A test
loads every file here, so a broken mapping fails CI.

Choices made in these files, to revisit with the team:

- UNSW-NB15 categories with no clear match elsewhere (Fuzzers, Analysis,
  Backdoors, Generic, Shellcode, Worms) keep a class of their own;
  Reconnaissance maps to `scan`.
- CIC-IDS2017 flows labelled as attempted are left out (`unlabelled`); web
  brute force is `brute_force`, cross-site scripting and SQL injection are
  `web_attack`.
- CTU-13 To-Botnet and To-Normal flows are `background`, like Background.
- Lab steps 3 to 5 of the SSH capture (key logins, a stopped server) are
  `normal`.
