# Changelog

Notable changes to the Flagman product (this `product/` folder). The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased] - phase 3 toolkit (draft branches)

Built ahead of schedule on the `phase-3/…` branches, to merge when phase 3
starts. Details: [docs/changes/phase-3-toolkit.md](docs/changes/phase-3-toolkit.md).

### Added

- `flagman-features`: 37 per-flow features for machine learning, computed
  packet by packet inside the flow table, in constant memory (262 more
  bytes per flow), with a versioned schema. Addresses, exact ports, clock
  times and raw TTL are never features; tests prove that changing them,
  the link layer or the sender's TCP options leaves every feature the same
  ([ADR 0012](docs/adr/0012-features-computed-inside-the-flow-table.md)).
- The flow table can keep extra state per flow (`FlowTable<X>`); the
  sensor's table keeps nothing, so detection is unchanged.
- Decoded packets carry their data size (read from the headers, so right
  with a short capture) and their TTL.
- `flagmand extract capture.pcap --out flows.parquet`: the features of
  every flow, one row per flow, in a Parquet file that stores its own
  schema. It runs the sensor's capture loop and engine, so recorded and
  live features come from the same code. Only in builds made with
  `--features parquet` (off by default, so the router build stays small;
  CI checks it), through the new crate `flagman-parquet`
  ([ADR 0013](docs/adr/0013-feature-files-in-parquet-from-an-optional-crate.md)).
- The same capture always gives a byte-identical file; a test runs the
  program twice on each lab capture and compares the files.
- The phase 2 plan describes the live/replay parity test (2.9), and a test
  pins the one known difference (a flow silent past its timeout in an
  otherwise silent capture).
- `product/ml`, the Python pipeline (Python 3.13, every package pinned in
  `requirements.txt`): reads feature files with the schema from their
  footer; labels each flow from a dataset's ground truth by its two ends,
  ports, protocol and time, through a mapping file per dataset (the lab,
  UNSW-NB15, CTU-13, and a draft for CIC-IDS2017); finds the time offset of
  a ground truth written in an unstated time zone; writes labels files that
  record the checksum of every input.
- `python -m flagman_ml.datasets`: downloads that resume, check size and
  SHA-256, refuse 20 GB or more without a clear yes, and never fetch a
  program; manifests for CTU-13 (all 13 scenarios), UNSW-NB15, CIC-IDS2017
  and MAWI; `ml/data/README.md` with each dataset's verified facts, terms
  and citations, and what could not be verified.
- CI: a Python job (tests on the lab files and made-up flows, no
  download), and a check that the Python test files match a fresh
  extraction of the lab captures.
- `python -m flagman_ml.models train | predict | drift`: LightGBM with
  probabilities calibrated by temperature scaling, an Isolation Forest
  trained on normal flows only, a false-alarm budget α set by split
  conformal thresholds on calibration files kept aside (α/2 for each
  score), the open-set decision (`unknown_suspicious`), a drift monitor
  (alert rate, anomaly scores, PSI per feature), and model bundles with a
  checksum and the library versions
  ([ADR 0014](docs/adr/0014-two-scores-a-conformal-false-alarm-budget-and-temperature-scaling.md)).
- `python -m flagman_ml.audit`: the shortcut audit (single-feature
  separability of every feature for every class, with the watched features
  marked, and ablations measured by macro-F1 on validation files).
- `python -m flagman_ml.evaluation --plan plans/<name>.toml`: runs a plan of
  folds (whole training, calibration and test files) and seeds, with every
  attack class left out in turn and tests on other datasets; measures the
  observed against the configured false-alarm budget (exact intervals),
  detection at 0.1%, 0.5% and 1% false alarms, precision at a base rate,
  ECE, per-class F1 and macro-F1, and alerts per day; summarises mean ± std
  and paired tests (Wilcoxon, McNemar).
- `python -m flagman_ml.reports`: Markdown reports written only from the
  results JSON files, naming them with their checksums; a test checks that
  every number of a report is a value of those files.

### Changed (phase 3 toolkit)

- The flow table breaks ties by flow key: flows that end together come out
  in the same order on every run, and a full table always ends the same
  flows when several were last active in the same millisecond. No detector
  result depends on it; every earlier test is unchanged.
- The engine and the capture loop take the flow table's extra state as a
  type parameter (`Engine<X = ()>`); the sensor's code is unchanged.

## [0.1.0] - unreleased

Phase 1: Linux Pro. Details and checks: [docs/changes/phase-1-linux-pro.md](docs/changes/phase-1-linux-pro.md).

### Added

- `flagmand`, the sensor program: live capture with libpcap (headers only),
  replay of `.pcap` files, and the `interfaces` and `token` commands.
- Detectors for network sweeps, port scans (TCP and UDP) and login attempts,
  plus Suricata alerts read from `eve.json`. Alerts are grouped by host
  into incidents, with MITRE ATT&CK tactics and techniques.
- SQLite storage with automatic deletion of old data.
- A local API protected by a token, and a dashboard with an overview,
  incidents, incident details and a traffic list, in English, French and
  Arabic, in light and dark themes.
- A Linux installer and a hardened systemd service.
- Real lab captures of an nmap attack and of normal traffic, with
  end-to-end tests.
- Documentation for beginners: reading order, architecture, glossary, threat
  model, home test guide, decision records, AI-use log.
- Continuous integration for `product/`.
- A real OpenSSH lab capture (`lab-ssh-logins.pcap`) with failed and
  successful logins, and the script that records it.
- "Detector saturated" in the dashboard's health strip and in the replay
  summary, when a full table had to make room.
- A Markdown copy next to each context document, so that it can be
  reviewed in a diff.
- The phase 2 plan, as a series of small pull requests
  ([docs/phase-2-plan.md](docs/phase-2-plan.md)).

### Changed (after the review of phase 1)

- A full detector table now forgets its least active entries instead of
  ignoring newcomers, and a full flow table ends its least recently active
  flows instead of refusing new ones. Before, about 830 fake addresses per
  second kept the detectors full and hid a real scan.
- Login attempts are counted from finished connections: only refused ones,
  and ones closed within 30 s, on devices inside the home network. Before,
  every new connection to a login port counted, including successful logins
  (git over SSH, VS Code Remote, Ansible). In the nmap lab capture the count
  drops from 16 to 15: nmap's single probe of port 22 is no longer counted.
- A Suricata alert on traffic from the internet to one of your devices is
  filed under your device, not under the outside server. The dashboard
  calls the incident's device "Host" instead of "Source".
- The documents no longer present the normal capture (500 packets) as proof
  that there are no false alarms. The home test gains a week of normal use,
  which will give the real false alarm rate.

### Changed (phase 1 follow-ups)

- Login attempts on servers on the internet are reported again, with their
  own threshold: 30 failed attempts on one server within 60 s
  (`outbound_min_attempts`), against 10 inside the home. A device of yours
  that guesses passwords elsewhere may be infected; normal git over SSH
  stays quiet. The default of `local_targets_only` becomes `false`.
  **Existing installations keep `local_targets_only = true`** from their
  `/etc/flagman/flagman.toml` (the installer never overwrites it): set it
  to `false` to turn the internet watch on.
  [ADR 0011](docs/adr/0011-watch-logins-to-internet-servers.md).
- A new `ignore_logins` setting silences one login (source, target, port)
  for the login rule only. The advice on login alerts, in English, French
  and Arabic, now points there instead of `ignore_sources`, which hides a
  device from every detector, scans included.
- A test now pins a known limit: a flood of new connections that fills the
  flow table can end a login attempt before the server answers, and that
  attempt is not counted. With a 1,000-flow table, logins are lost from 320
  new connections per second; with the default 100,000 flows the same
  mechanism gives about 31,000. Phase 2 measures it on the router
  ([phase 2 plan](docs/phase-2-plan.md), 2.6). No detector change.
