# Architecture

Flagman is one program, `flagmand`, plus a dashboard that runs in the
browser. This page follows the data from the network card to the screen.

## The pipeline

```text
 network interface                       Suricata (optional, its own program)
        │ libpcap, first 160 bytes                 │ writes eve.json
        ▼                                          ▼
 ┌───────────────────────────────┐      ┌──────────────────────┐
 │ capture loop (main thread)    │◀─────│ Suricata reader      │
 │                               │ hits │ (follows eve.json)   │
 │  Engine, for every packet:    │      └──────────────────────┘
 │   1. decode headers           │
 │   2. flow meter               │
 │   3. detectors                │
 │   4. incidents                │
 │   5. traffic counters         │
 └──────────────┬────────────────┘
                │ batches of results
                ▼
 ┌───────────────────────────────┐
 │ storage writer thread         │──────▶  SQLite file (WAL mode)
 └───────────────────────────────┘                 ▲ reads
                                                   │
 ┌───────────────────────────────┐                 │
 │ web server (2 worker threads) │─────────────────┘
 │ /api/... + the dashboard files│◀──── browser, with the token
 └───────────────────────────────┘
```

### 1. Capture (`flagman-capture`)

libpcap opens the interface in promiscuous mode and keeps the first 160
bytes of each packet: enough for the Ethernet, IP and TCP/UDP headers, not
the contents. In replay mode, packets come from a `.pcap` file instead; both
sources implement the same `PacketSource` trait, so the rest of the program
cannot tell the difference.

libpcap's own timeout does not fire when no packets arrive on Linux, so a
quiet network would make Flagman unable to stop. The capture is therefore
non-blocking, and Flagman waits for packets with `poll()` and a 250 ms
timeout ([ADR 0003](adr/0003-libpcap-capture-with-poll.md)).

### 2. Engine (`flagman-core`)

The engine is pure logic: no network, no disk, no clock. Time comes from
packet timestamps. This makes every rule testable with hand-made packets,
and makes replay behave exactly like live capture.

- **Decode** (`packet/decode.rs`): addresses, ports, TCP flags, ARP.
- **Flow meter** (`flow/table.rs`): groups packets into conversations. A
  flow ends when TCP closes it, after a quiet period (120 s TCP, 60 s UDP,
  30 s other), or after 300 s for long transfers. At most 100,000 flows are
  tracked at once, so memory stays bounded.
- **Detectors** (`detect/`): each one counts distinct things per key in a
  60-second sliding window (ports per scanner and target, addresses per
  scanner, connection attempts per guesser and service). Crossing the
  threshold opens a *finding*, which becomes an alert. The alert is updated
  every 5 seconds while it grows, and closed after 120 quiet seconds.
- **Incidents** (`incident/engine.rs`): alerts from the same source join
  the same incident while the gaps stay under 30 minutes. Severity is the
  highest alert severity, raised one level when two or more ATT&CK tactics
  are involved.
- **Traffic counters** (`traffic.rs`): packets and bytes per protocol,
  flushed every 5 seconds for the charts.

Every value above is a default from the code or `flagman.toml`, and can be
changed there.

### 3. Suricata reader (`flagman-suricata`)

When Suricata is installed, Flagman follows its `eve.json` log (like
`tail -F`, surviving log rotation), keeps the `alert` lines, and passes them
to the engine. Suricata stays a separate program: Flagman only reads its
log, so Suricata's GPL licence does not apply to Flagman's code.

### 4. Storage (`flagman-store`)

One SQLite file with four tables: `flows`, `alerts`, `incidents` and
`traffic_minutes` (see `schema.rs`). The writer thread is the only one that
writes; the API has its own read connection. SQLite's WAL mode lets both
work at the same time. Old rows are deleted every hour: flows and
per-minute traffic after 7 days, alerts and incidents after 90 days.

### 5. API and dashboard (`flagman-api`, `ui/`)

A small HTTP server on `127.0.0.1:8750` serves the dashboard files and a
JSON API. Every `/api/` call needs the token
([ADR 0007](adr/0007-api-token-on-localhost.md)).

| Route | Returns |
|---|---|
| `GET /api/health` | sensor status: packets, drops, Suricata |
| `GET /api/dashboard?range=1h` | everything the overview page shows |
| `GET /api/incidents?range=7d&min_severity=high&status=open` | incident list |
| `GET /api/incidents/{id}` | one incident with its alerts and flows |
| `POST /api/incidents/{id}/status` | marks it open, confirmed, false positive or resolved |
| `GET /api/alerts?range=24h` | recent alerts |
| `GET /api/flows?range=1h&ip=…&port=…&protocol=tcp` | finished flows |

The dashboard is a Svelte app compiled to static files
([ADR 0006](adr/0006-svelte-dashboard-and-charts.md)). It refreshes the
overview every 10 seconds, the other pages every 15 seconds (once a minute
in replay mode, where nothing changes), and the health strip every 5 seconds.

## Threads and shutdown

| Thread | Job |
|---|---|
| main | capture and engine |
| writer | writes batches to SQLite, deletes old rows every hour |
| Suricata reader | follows `eve.json` every 500 ms |
| web | answers the browser (a small tokio runtime with 2 workers) |

Batches travel through bounded channels, so a slow disk slows the writer
down instead of filling memory. Ctrl-C or `systemctl stop` sets a stop flag;
the capture loop finishes the current batch and closes every open flow and
alert, then the writer saves the last batch, then the web server stops. A
second Ctrl-C exits at once.

## Where things live on an installed system

| Path | What |
|---|---|
| `/usr/local/bin/flagmand` | the program |
| `/etc/flagman/flagman.toml` | configuration |
| `/var/lib/flagman/flagman.db` | the database |
| `/var/lib/flagman/api-token` | the dashboard token (readable by the `flagman` user only) |
| `/usr/share/flagman/ui/` | the dashboard files |
| `/etc/systemd/system/flagman.service` | the service |
