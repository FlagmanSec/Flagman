# flagman-store

SQLite storage ([ADR 0004](../../../docs/adr/0004-sqlite-storage.md)).
The sensor's writer thread writes; the API reads, with its own connection.

| File | What it does |
|---|---|
| `schema.rs` | The four tables and their indexes, versioned with `PRAGMA user_version` |
| `write.rs` | Saves flows, alerts, incidents and traffic counts; deletes old rows |
| `query_dashboard.rs` | The overview page: totals, charts, top devices and services |
| `query_incidents.rs` | Incident list, one incident with its alerts, status changes |
| `query_flows.rs` | The connections list and its filters |
| `rows.rs` | The shapes sent to the dashboard as JSON |

All times are milliseconds since 1970 (UTC). No packet contents are stored.

Tests: `cargo test -p flagman-store` (they use an in-memory database).
