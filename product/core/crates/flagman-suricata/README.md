# flagman-suricata

Reads the alerts that Suricata writes to its EVE JSON log
(`/var/log/suricata/eve.json`). Flagman never links to Suricata's code: it
only reads the log, so Suricata's licence (GPL-2.0) does not extend to
Flagman.

| File | What it does |
|---|---|
| `eve.rs` | `parse_alert_line`: one JSON line to a `SignatureHit`; anything else is skipped |
| `tail.rs` | `EveTailer`: follows the file like `tail -F`, survives log rotation, ignores lines over 1 MiB |

Tests: `cargo test -p flagman-suricata`.
