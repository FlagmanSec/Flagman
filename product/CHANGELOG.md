# Changelog

Notable changes to the Flagman product (this `product/` folder). The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

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

### Fixed

- The install guides no longer tell Ubuntu users to install `nodejs` with
  apt: Ubuntu 24.04 ships Node.js 18, too old for the dashboard (it needs
  20.19 or newer). They now use the NodeSource repository. The repository's
  main README now describes Flagman and how to install it; the CS395
  research README moved to `RESEARCH.md`.
