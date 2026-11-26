# Threat model

What could go wrong with Flagman itself, and what protects against it.
This covers phase 1 (Linux Pro, one PC). It uses STRIDE, a checklist of six
kinds of threat: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service, **E**levation of privilege.

## What we protect

| Asset | Why it matters |
|---|---|
| The machine Flagman runs on | Flagman reads raw network traffic, so it needs special rights. A flaw must not turn into control of the PC. |
| What the database knows | Which devices talk to which, and when. That is private, even without packet contents. |
| The alerts themselves | An attacker who can hide or fake alerts defeats the point of an IDS. |
| The dashboard token | It opens all of the above. |

## Who might attack

1. **A device on the home network**: a compromised IoT device, a guest's
   laptop. It can send any packet it likes, including malformed ones.
2. **A web page in the owner's browser**: any site can make the browser send
   requests to `http://127.0.0.1:…`.
3. **Another user account on the same PC**.
4. **Someone who reads the screen or the logs** (a screenshot, a shared
   terminal, a bookmark).

Out of scope for phase 1: someone with root on the PC (they can do anything,
including stopping Flagman), and physical access.

## Threats and protections

| STRIDE | Threat | Protection | Where |
|---|---|---|---|
| T, D, E | A crafted packet crashes Flagman or runs code | Parsing in safe Rust with the `etherparse` crate; every length checked; errors are counted, never panics; only 160 bytes per packet are read | `packet/decode.rs`, `flagman-capture` |
| D | A flood of packets or fake connections fills memory | At most 100,000 flows and 50,000 keys per detector are tracked. Detector windows only keep 60 s; channels between threads are bounded; `MemoryMax=512M` in the service is a last resort | `flow/table.rs`, `detect/tracker.rs`, `detect/window.rs`, `flagman.service` |
| D | A flood fills the tables on purpose, so that a real attack finds no room and goes unseen (found in the review of phase 1: about 830 fake addresses per second hid a real scan) | A full table never refuses a newcomer: it forgets its least active tenth first (detectors: fewest distinct values, quiet for longest; flows: quiet for longest). A real scanner collects values within seconds and stays. The strip says **Detector saturated** and the replay summary says so too. Tested with the review's attack: 60,000 fake addresses, then a 1,000-port scan | `detect/tracker.rs`, `flow/table.rs`, `engine.rs` tests, `HealthStrip.svelte` |
| D | A flood of new connections ends a login attempt before the server answers, so it is not counted (found in the follow-up review) | Known limit, pinned by a test: with a 1,000-flow table logins are lost from 320 new connections per second, and the same mechanism gives about 31,000 with the default 100,000 flows. Phase 2 measures it on the router (plan item 2.6) | `engine_flood_tests.rs`, `flow/table.rs` |
| D | A flood hides an attack because packets are dropped | The kernel's drop counter is shown at the top of every page ("Dropped by the kernel") | `health.rs`, dashboard health strip |
| S | An attacker forges source addresses to blame another device | Not prevented: an IDS reports what it sees. The incident page says which address the packets came *from*; ARP-level spoofing detection is future work | – |
| T | An attacker on the network hides an alert | Flagman is passive and has no network-facing port other than the dashboard on `127.0.0.1`; there is nothing to send it commands | `flagman-api`, `flagman.toml` |
| I | A web page reads the alerts through the browser | Every API call needs `Authorization: Bearer <token>`. Browsers never add that header to cross-site requests, and the API sends no CORS headers, so other sites cannot read the answers | `flagman-api/src/auth.rs`, [ADR 0007](adr/0007-api-token-on-localhost.md) |
| I | A DNS-rebinding page reaches the API under its own name | The same token check: the page does not have the token. Checking the `Host` header as a second layer is future work | `auth.rs` |
| I | The token leaks through the address bar, a bookmark or the history | The token is in the `#` part of the link, which browsers never send to the server; the dashboard removes it from the address bar right after reading it | `ui/src/lib/token.ts` |
| I | The token leaks through another account on the PC | The token file is created with mode `0600`, in `/var/lib/flagman` (mode `0750`), owned by the `flagman` user | `flagmand/src/token.rs`, `flagman.service` |
| I | Traffic contents end up in the database | Only headers are captured; the database has no column for contents | `schema.rs` |
| I | The dashboard is opened from another device over plain HTTP | Off by default (`127.0.0.1`). The recommended way is an SSH tunnel. Setting `listen = "0.0.0.0:…"` makes Flagman print a warning, because the token then crosses the network unencrypted | `flagmand/src/server.rs`, `deploy/linux/README.md` |
| I, T | Script injection in the dashboard through a crafted field (a Suricata signature name, a hostname) | Svelte escapes all text by default and no raw HTML is used; the Content Security Policy only allows scripts from the dashboard itself; the dashboard cannot be framed by another site; ATT&CK links are built only from validated IDs | `ui/`, `flagman-api/src/headers.rs`, `ui/src/lib/attack.ts` |
| E | A bug in Flagman gives an attacker root | Flagman runs as the unprivileged `flagman` user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`, `NoNewPrivileges`, a read-only system (`ProtectSystem=strict`), no home folders, a system-call filter, and more. `systemd-analyze security flagman` rates the unit 2.2 ("OK"); lower is safer | `flagman.service` |
| R | Nobody knows who marked an incident as a false positive | Phase 1 has a single user; the time of the change is stored (`status_changed_at`). Per-user accounts are future work | `schema.rs` |
| T, D | A malicious or huge `eve.json` line | Lines over 1 MiB are dropped; each line is parsed into fixed fields; anything that is not a well-formed alert is skipped | `flagman-suricata/src/tail.rs`, `eve.rs` |

## Known gaps (to fix in later phases)

1. **No HTTPS.** Fine on `127.0.0.1` or through SSH; not fine on an open
   network.
2. **One token, no accounts.** Anyone with the link has full access.
   `sudo flagmand token` prints it; deleting the token file and restarting
   creates a new one.
3. **Spoofed sources** are reported as they appear.
4. **One PC sees little.** On a switched network, Flagman on a PC sees its
   own traffic and broadcasts, not the traffic between two other devices.
   The router version (Edge) is the answer. See [home-test.md](home-test.md).

## How to report a problem

Open an issue in the repository, or tell the team directly for anything
sensitive.
