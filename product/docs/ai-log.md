# Use of generative AI

The project brief asks us to declare where generative AI was used. One row
per working session; newest last.

| Date | Tool | What it produced | Asked for by |
|---|---|---|---|
| 2026-11-26 | Claude Code (Anthropic's AI coding assistant) | All of phase 1 in `product/`: the Rust sensor, the dashboard, the installer and service, the lab capture script and captures, the tests, and these documents | Seraj |

## How the AI's work was checked

- **Tests**: Rust unit and end-to-end tests, dashboard unit tests, strict
  linting and type checks, all run again by CI on every change.
- **Real traffic**: the detectors were run on real nmap traffic recorded in
  an isolated lab of two network namespaces (no real network involved), and
  on normal traffic, where they must stay quiet.
- **Looking at the result**: screenshots of every dashboard page in light
  and dark, in English, French and Arabic, and at phone width.
- **External facts** (nmap behaviour, Suricata setup) were checked against
  the official pages, which the documents link to.
- **Numbers** in the documents come from the code's defaults, the test
  files, or command output written in
  [changes/phase-1-linux-pro.md](changes/phase-1-linux-pro.md).

## Limits

- No person has reviewed the code line by line yet. The pull request is the
  place to do it; [reading-order.md](reading-order.md) suggests a path.
- The home network test has not been run yet: [home-test.md](home-test.md).
- The AI wrote no attack tools. The only traffic generator is the lab script
  in `core/testdata/pcap/`, which can only reach its own two isolated
  network namespaces.
