# flagman-api

The local HTTP API behind the dashboard, built with `axum`. It also serves
the dashboard's files. The route list is at the top of `src/lib.rs` and in
[docs/architecture.md](../../../docs/architecture.md).

| File | What it does |
|---|---|
| `lib.rs` | The router: routes, token check, security headers, dashboard files |
| `auth.rs` | Checks `Authorization: Bearer <token>` in constant time ([ADR 0007](../../../docs/adr/0007-api-token-on-localhost.md)) |
| `headers.rs` | Content Security Policy and other security headers |
| `routes_dashboard.rs`, `routes_incidents.rs` | One function per route |
| `params.rs` | Reads and checks query parameters (periods, filters, limits) |
| `error.rs`, `state.rs` | Error answers and the shared state |

Tests: `cargo test -p flagman-api`. They call the router directly, without
opening a port.
