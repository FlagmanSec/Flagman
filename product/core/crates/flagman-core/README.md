# flagman-core

The detection logic, with no input or output of its own: no network, no
disk, no clock. Packets go in, results come out. Time comes from packet
timestamps, so a replayed capture behaves exactly like live traffic.

| Folder or file | What it does |
|---|---|
| `packet/` | Decodes captured bytes into addresses, ports, TCP flags, ARP |
| `flow/` | The flow meter: one entry per conversation, reported when it ends |
| `detect/` | The detectors: port scan, host sweep, brute force, Suricata hits |
| `incident/` | Groups alerts by host into incidents, sets severity |
| `traffic.rs` | Packets and bytes per protocol, for the charts |
| `engine.rs` | Runs all of the above for each packet, in order |
| `alert.rs`, `health.rs`, `ids.rs`, `net.rs`, `time.rs` | Shared types and small helpers |
| `testutil.rs` | Builds test packets by hand |

Start with `engine.rs`, then follow the order in
[docs/reading-order.md](../../../docs/reading-order.md).

Tests sit next to the code (`mod tests`) and in `detect/detectors_tests.rs`,
`detect/login_tests.rs` (the login rule), `flow/table_tests.rs` and
`engine_flood_tests.rs` (a known limit under a flood). Run them with
`cargo test -p flagman-core`.
