# Architecture decision records

One file per decision: the situation, what we chose, what we gave up. When a
decision changes, add a new record that replaces the old one; do not edit
history.

| # | Decision | Status |
|---|---|---|
| [0001](0001-rust-sensor-core.md) | Write the sensor in Rust | accepted |
| [0002](0002-product-folder-in-research-repo.md) | Keep the product in `product/` inside the CS395 repository | accepted |
| [0003](0003-libpcap-capture-with-poll.md) | Capture with libpcap, non-blocking, waiting with `poll()` | accepted |
| [0004](0004-sqlite-storage.md) | Store everything in one SQLite file | accepted |
| [0005](0005-rules-first-ml-later.md) | Start with rule-based detectors and Suricata; add machine learning later | accepted |
| [0006](0006-svelte-dashboard-and-charts.md) | Svelte dashboard with hand-made SVG charts and a checked palette | accepted |
| [0007](0007-api-token-on-localhost.md) | Require a token for the API, even on localhost | accepted |
| [0008](0008-full-tables-forget-the-least-active.md) | A full table forgets its least active entries, never the newcomer | accepted |
| [0009](0009-login-attempts-from-finished-connections.md) | Judge login attempts by how each connection ended | accepted |
| [0010](0010-suricata-alerts-filed-under-the-home-device.md) | File Suricata alerts from the internet under the home device | accepted |
| [0011](0011-watch-logins-to-internet-servers.md) | Watch login attempts on internet servers with a higher threshold | accepted |
| [0012](0012-features-computed-inside-the-flow-table.md) | Compute machine learning features inside the flow table | proposed (phase 3) |

Template for a new record:

```markdown
# NNNN. Title

Status: proposed | accepted | replaced by NNNN
Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Alternatives considered
```
