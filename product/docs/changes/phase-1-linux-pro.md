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
| Rust tests | `cargo test --locked` | 87 passed: flagman-core 52, flagman-store 7, flagman-capture 2, flagman-api 7, flagman-suricata 5, flagmand 14 |
| Rust lints | `cargo clippy --all-targets --locked -- -D warnings` | no warnings |
| Rust format | `cargo fmt --check` | clean |
| Replay of the nmap attack | `flagmand replay testdata/pcap/lab-attack-chain.pcap` | 1 incident, critical, host 192.168.77.66: host sweep 255 hosts, port scan 1,000 ports, login attempts 15 connections (output in [the product README](../../README.md)) |
| Replay of normal traffic | `flagmand replay testdata/pcap/lab-normal-traffic.pcap` | No incidents found (500 packets: this shows little, see Known limits) |
| Replay of real SSH logins | `flagmand replay testdata/pcap/lab-ssh-logins.pcap` | 1 incident, high, host 192.168.77.66: login attempts 23 connections (the 40-second session is left out) |
| Dashboard types | `npm run check` | 0 errors, 0 warnings |
| Dashboard tests | `npm test` | 49 passed |
| Dashboard build | `npm run build` | builds |
| Service hardening | `systemd-analyze security --offline=true ../deploy/linux/flagman.service` | "Overall exposure level for flagman.service: 2.2 OK" (systemd 255) |

The first push had 73 Rust and 46 dashboard tests, and counted 16 login
attempts in the nmap recording; the numbers above are after the review
fixes (next section).

The three replay results are also automated in
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

## Changes after the review

Seraj reviewed the first push, re-ran every check, and asked for these
changes before merging. The full story is in
[the review context document](../context/2026-11-26-review-fixes.md).

| Review point | What changed | Decision record |
|---|---|---|
| A flood of fake addresses filled the detectors' tables, and a real scan that came after went unseen | A full table forgets its least active tenth instead of ignoring newcomers; the flow table ends its least recently active flows. The dashboard shows **Detector saturated** | [ADR 0008](../adr/0008-full-tables-forget-the-least-active.md) |
| Every connection to SSH counted as a login attempt, including logins that work | Only refused connections, and ones closed within 30 s, to devices inside the home network. Set from a new recording of a real OpenSSH server | [ADR 0009](../adr/0009-login-attempts-from-finished-connections.md) |
| 500 packets of normal traffic do not prove there are no false alarms | The documents say so; the home test gains a week of normal use | – |
| A Suricata alert from an outside server opened an incident "from" that server | Such an alert is filed under the home device that received it | [ADR 0010](../adr/0010-suricata-alerts-filed-under-the-home-device.md) |
| A Word file cannot be reviewed in a diff | Each context document has a Markdown copy next to it | – |
| One pull request of 17,760 lines is too big to review | Phase 2 comes as several small pull requests: [the plan](../phase-2-plan.md) | – |

Checked for these changes, besides the table above:

- an engine test replays the case from the review (60,000 packets from
  fake addresses, with a real scan of 1,000 ports in the middle) and finds
  the scan; it fails with the code of the first push;
- `tcpdump` confirms the counts of the SSH recording: 24 connections, 5 of
  them refused (commands in
  [the recordings' README](../../core/testdata/pcap/README.md));
- the **Detector saturated** item was looked at in screenshots in English,
  French (dark theme) and Arabic.

## Follow-ups after the merge

Three points from the follow-up review, in their own pull request. The
full story is in
[the follow-ups context document](../context/2026-11-26-phase-1-followups.md).

| Point | What changed | Checked by |
|---|---|---|
| A home device guessing passwords on internet servers was never reported | Internet servers are watched again, with their own threshold: 30 failed attempts a minute (`outbound_min_attempts`). Git over SSH stays quiet | `guessing_passwords_on_an_internet_server_is_reported` (fails with the old default), `quick_logins_to_an_internet_server_stay_silent`, `local_targets_only_turns_the_internet_watch_off`; [ADR 0011](../adr/0011-watch-logins-to-internet-servers.md) |
| The advice told owners to silence a script's device with `ignore_sources`, which also hid its scans | New `ignore_logins` setting (source, target, port), for the login rule only. The advice points there in English, French and Arabic | `ignore_logins_silences_one_login_and_nothing_else`, a configuration test, two dashboard tests |
| A heavy flood can end a login attempt before it is counted | No detector change: a test pins the limit, and phase 2 measures it on the router | `engine_flood_tests.rs` (known limit 8 below) |

## Known limits

1. On one PC, Flagman sees that PC's traffic and the network's broadcasts,
   not the traffic between two other devices. Edge is the answer.
2. Scans slower than the 60-second window are missed.
3. No HTTPS and a single token: see [the threat model](../threat-model.md).
4. The normal recording is 500 packets of simple traffic, so the false
   alarm rate is not known yet. It will come from the home test week.
5. A quick successful login to an SSH server inside the home network looks
   like a failed one, so scripts that log in often to a machine at home can
   raise a login alert ([ADR 0009](../adr/0009-login-attempts-from-finished-connections.md)).
   One `ignore_logins` entry silences that login.
6. "Inside the home network" means a private address; a home that uses
   public IPv6 addresses is not recognised yet.
7. Not tested yet: a real home network, Wi-Fi interfaces, runs of several
   days, memory and processor use under heavy traffic, and Suricata's log
   permissions on a real installation.
8. A flood of new connections that fills the flow table can end a login
   attempt while it waits for the server's answer; the attempt is then not
   counted. With a 1,000-flow table, logins are lost from 320 new
   connections per second; with the default 100,000 flows the same
   mechanism gives about 31,000 (`engine_flood_tests.rs`). Phase 2
   measures it on the router ([plan](../phase-2-plan.md), 2.6).
9. Password guessing on an internet server is reported only from 30
   attempts a minute on that server: slower guessing, and spraying a few
   tries over many servers, are not
   ([ADR 0011](../adr/0011-watch-logins-to-internet-servers.md)).

## Next steps

1. Seraj runs [home-test.md](../home-test.md) for a week and fills in its
   results table.
2. Phase 2, as small pull requests: thresholds tuned from those results,
   then Edge on the OpenWrt One ([phase-2-plan.md](../phase-2-plan.md)).
