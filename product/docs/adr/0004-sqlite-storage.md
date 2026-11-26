# 0004. Store everything in one SQLite file

Status: accepted
Date: 2026-11-26

## Context

Flagman keeps flows, alerts, incidents and per-minute traffic counts on the
same machine, for days to months. There is one writer (the sensor) and one
reader (the dashboard). The budget is zero, and a router has little memory
and no room for a database server.

## Decision

- One SQLite file (`/var/lib/flagman/flagman.db`), through `rusqlite` with
  SQLite compiled in (the `bundled` feature), so no system library is needed.
- WAL mode, so the dashboard can read while the sensor writes.
- One writer thread with its own connection; the API opens its own.
- `PRAGMA user_version` records the schema version, for future migrations.
- Old rows are deleted every hour: flows and per-minute traffic after 7
  days, alerts and incidents after 90 days (both in `flagman.toml`).

## Consequences

- Nothing to install or run besides Flagman; a backup is a copy of one file.
- Only one process writes at a time, which is exactly our case.
- Heavy analytics over months of flows would be slow; that is not the goal
  of a home sensor.

## Alternatives considered

- **PostgreSQL or Elasticsearch**: powerful, but a server to run and too
  heavy for a router.
- **JSON log files**: simple to write, but every dashboard question would
  mean reading everything.
