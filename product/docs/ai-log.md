# Use of generative AI

The project brief asks us to declare where generative AI was used. One row
per working session; newest last.

| Date | Tool | What it produced | Asked for by |
|---|---|---|---|
| 2026-11-26 | Claude Code (Anthropic's AI coding assistant) | All of phase 1 in `product/`: the Rust sensor, the dashboard, the installer and service, the lab capture script and captures, the tests, and these documents | Seraj |
| 2026-11-26 | Claude Code | The fixes asked for in Seraj's review of phase 1: full tables, the login rule, Suricata filing, "Detector saturated", the OpenSSH lab script and recording, ADRs 0008 to 0010, the phase 2 plan, the Markdown copies of the context documents, and the review context document | Seraj |
| 2026-11-26 | Claude Code | The three phase 1 follow-ups: login attempts on internet servers with their own threshold (ADR 0011), the `ignore_logins` exception and its advice in three languages, the test that pins the flood limit, and the follow-ups context document | Seraj |
| 2026-11-26 | Claude Code | Phase 3 toolkit, pull request 1: the `flagman-features` crate, the flow table's extension slot, data size and TTL per packet, ADR 0012, and its context document | Seraj |
| 2026-11-27 | Claude Code | Phase 3 toolkit, pull request 2: `flagmand extract` and the `flagman-parquet` crate behind the off-by-default `parquet` feature, the generic engine and capture loop, ties broken by flow key, the byte-identical test, the CI steps, the parity test in the phase 2 plan (2.9), ADR 0013, and its context document | Seraj |
| 2026-11-27 | Claude Code | Phase 3 toolkit, pull request 3: the Python pipeline in `product/ml` (pinned dependencies, reading feature files, labelling by ends, ports and time with a mapping file per dataset, the time offset finder, labels files with checksums), the download script with size and SHA-256 checks, the dataset facts in `ml/data/README.md` (read on the source pages by AI agents and quoted, with what could not be verified said so), the lab ground truth, the CI job, and its context document | Seraj |

## How the AI's work was checked

- **Tests**: Rust unit and end-to-end tests, dashboard unit tests, strict
  linting and type checks, all run again by CI on every change.
- **Real traffic**: the detectors were run on real nmap traffic and real
  OpenSSH logins recorded in an isolated lab of two network namespaces (no
  real network involved), and on normal traffic, where they must stay
  quiet.
- **Human review**: Seraj reviewed phase 1, re-ran every check, and tested
  a flood of fake addresses, which found the first problem fixed above.
- **Looking at the result**: screenshots of every dashboard page in light
  and dark, in English, French and Arabic, and at phone width.
- **External facts** (nmap behaviour, Suricata setup and its alert
  fields) were checked against the official pages, which the documents
  link to. OpenSSH's defaults were read from the installed server itself
  (`sshd -T`).
- **Numbers** in the documents come from the code's defaults, the test
  files, or command output written in
  [changes/phase-1-linux-pro.md](changes/phase-1-linux-pro.md).

## Limits

- Phase 1 arrived as one pull request of 17,760 lines, too big to read
  line by line. Phase 2 comes in small pull requests for that reason
  ([phase-2-plan.md](phase-2-plan.md)); [reading-order.md](reading-order.md)
  suggests a path through phase 1.
- The home network test has not been run yet: [home-test.md](home-test.md).
- The AI wrote no attack tools. The only traffic generators are the two lab
  scripts in `core/testdata/pcap/`, which can only reach their own two
  isolated network namespaces. The SSH one tries wrong passwords only
  against its own throwaway SSH server, started for the recording and
  stopped after it, and creates no account on the computer.
