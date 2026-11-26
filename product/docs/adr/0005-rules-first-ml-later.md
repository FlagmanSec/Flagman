# 0005. Start with rule-based detectors and Suricata; add machine learning later

Status: accepted
Date: 2026-11-26

## Context

The CS395 project trains classifiers on the UNSW-NB15 dataset. Two open
points from that work matter here: the gap between cross-validation and
test-set scores, and weak classes (DoS, Analysis, Backdoor). Also, the
UNSW-NB15 features were computed by other tools on another network; our
sensor does not produce the same features yet, and a home network has no
labelled attacks to learn from.

The first goal for the product is clear: detect nmap scans and login
attempts on a home network, explain them in plain words, and raise no false
alarms during normal use.

## Decision

- Phase 1 uses explainable rules: distinct ports, addresses or connection
  attempts counted in a 60-second sliding window, with thresholds in
  `flagman.toml`.
- Known attacks come from Suricata's signatures, read from its log.
- Machine learning comes back as an extra detector once Flagman records
  flow features from real home traffic that we can label and evaluate
  ourselves, with numbers traced to files, as in the research rules.

## Consequences

- Every alert can say exactly why it fired ("1,000 ports in 60 seconds").
- The rules are tested on real nmap traffic recorded in an isolated lab
  (`core/testdata/pcap/`).
- Rules miss slow scans (spread over more than the window) and new attack
  types. Suricata covers part of the second gap.
- Thresholds need checking on a real home network: that is the purpose of
  [home-test.md](../home-test.md).

## Alternatives considered

- **Ship the CS395 model now**: its features do not match what the sensor
  sees, and its open issues would turn into false alarms at home.
- **Anomaly detection from day one**: needs a learning period and produces
  alerts that are hard to explain to a non-expert.
