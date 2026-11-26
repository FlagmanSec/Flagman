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
  plus Suricata alerts read from `eve.json`. Alerts are grouped by source
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
