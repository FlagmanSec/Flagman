# Phase 1: Linux Pro

Date: 2026-11-26. Requested by Seraj.

## What was asked

- Build the Linux Pro version first, in the `FlagmanSec/Flagman` repository.
- It will be tested on a Linux PC on a home network, and must detect nmap
  scans and other intrusion attempts.
- A dashboard in the spirit of Suricata's.
- Edge (on an OpenWrt One router, 1 GB of memory) is tested in about three
  weeks. Windows comes later, only if Linux gives excellent results.

## What changed

Everything is new and lives in `product/`, except the CI workflow, which
GitHub requires in `.github/workflows/` (it only runs for `product/`). No
CS395 file was changed.

| Part | Where | Summary |
|---|---|---|
| Sensor | `core/` | Six Rust crates: capture, detection, Suricata reader, storage, API, and the `flagmand` program |
| Dashboard | `ui/` | Svelte app: overview, incidents, incident details, traffic list; English, French, Arabic; light and dark |
| Installation | `deploy/linux/` | Installer, hardened systemd service, commented configuration |
| Test data | `core/testdata/pcap/` | A real nmap attack and normal traffic, recorded in an isolated lab, and the script that records them |
| Documentation | `docs/`, a README in every folder | For reviewers who are new to the subject |
| CI | `.github/workflows/product-ci.yml` | Rust and dashboard checks on every change to `product/` |

## How it was checked

All commands run from `product/core` or `product/ui`.

| Check | Command | Result |
|---|---|---|
| Rust tests | `cargo test` | 73 passed: flagman-core 39, flagman-store 7, flagman-capture 2, flagman-api 7, flagman-suricata 5, flagmand 13 |
| Rust lints | `cargo clippy --all-targets -- -D warnings` | no warnings |
| Rust format | `cargo fmt --check` | clean |
| Replay of the nmap attack | `flagmand replay testdata/pcap/lab-attack-chain.pcap` | 1 incident, critical, from 192.168.77.66: host sweep 255 hosts, port scan 1,000 ports, login attempts 16 connections (output in [the product README](../../README.md)) |
| Replay of normal traffic | `flagmand replay testdata/pcap/lab-normal-traffic.pcap` | No incidents found |
| Dashboard types | `npm run check` | 0 errors, 0 warnings |
| Dashboard tests | `npm test` | 46 passed |
| Dashboard build | `npm run build` | builds |
| Service hardening | `systemd-analyze security --offline=true ../deploy/linux/flagman.service` | "Overall exposure level for flagman.service: 2.2 OK" (systemd 255) |

The two replay results are also automated in
`core/crates/flagmand/src/replay/tests.rs`, together with the exact counts,
the ATT&CK tactics, and a check that replaying cannot overwrite an existing
database by accident.

Checked by hand, once, in the isolated namespace lab (not automated yet):

- `flagmand run` on the victim's interface detected the nmap scan while it
  happened, and the dashboard showed it;
- an alert line added to a test `eve.json` was merged into the same incident;
- API calls without the token were refused with 401;
- the kernel dropped no packets;
- Ctrl-C stopped the program cleanly, with exit code 0, even on a quiet
  network.

Every dashboard page was looked at in screenshots: light and dark, English,
French and Arabic, desktop and phone width (no horizontal scrolling on a
390-pixel-wide phone screen).

## Known limits

1. On one PC, Flagman sees that PC's traffic and the network's broadcasts,
   not the traffic between two other devices. Edge is the answer.
2. Scans slower than the 60-second window are missed.
3. No HTTPS and a single token: see [the threat model](../threat-model.md).
4. Not tested yet: a real home network, Wi-Fi interfaces, runs of several
   days, memory use under heavy traffic, and Suricata's log permissions on
   a real installation.

## Next steps

1. Seraj runs [home-test.md](../home-test.md) and fills in its results table.
2. Adjust thresholds and wording from those results.
3. Edge: build for the OpenWrt One when it arrives, and measure memory and
   CPU use there.
