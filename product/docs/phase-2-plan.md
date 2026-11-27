# Phase 2 plan: several small pull requests

Status: proposed, for the team to agree on. Date: 2026-11-26; 2.9 added
on 2026-11-27 with the phase 3 toolkit.

Phase 1 arrived as one pull request of 17,760 lines, which Seraj's review
found too big to read block by block. Phase 2 comes as a series of small
pull requests instead, each about one subject, so that each can be read
in one sitting.

## Rules for every phase 2 pull request

- **One subject.** If a description needs "and also", it is two pull
  requests.
- **Small.** Aim for a few hundred changed lines of code, not counting
  test data and lock files. Split anything much bigger.
- **Complete.** Each one brings its own tests, updates the READMEs, the
  changelog and, when a choice was made, a decision record (ADR).
- **Explained.** Each push comes with a context document in
  [`context/`](context/README.md): a Word file and its Markdown copy.
- **Green.** CI passes before review is requested.
- **Numbers from files.** A threshold or limit changes only with the data
  that justifies it, kept in the repository (without home addresses).

## The order

Seraj's plan after phase 1 sets the order: first a week of
[home testing](home-test.md) on a real network, then thresholds tuned with
those numbers, then Edge on the OpenWrt One. Pull requests that do not need
the home data can be prepared during the test week.

| # | Pull request | Needs | Can start |
|---|---|---|---|
| 2.1 | Tune thresholds from the home test week | the week's results ([home-test.md](home-test.md), step 9) | after the test week |
| 2.2 | A "home network" setting, like Suricata's `HOME_NET` | nothing | now |
| 2.3 | Database versions and upgrades, then store why each connection ended | nothing | now |
| 2.4 | (Only if 2.1 shows it is needed) Read the PC's own SSH log to tell good logins from bad ones | 2.1 | after 2.1 |
| 2.5 | Build Flagman for the OpenWrt One | the router, to confirm its processor type | when the router is available |
| 2.6 | Fit the router: memory limits and a start-up script | 2.5 | after 2.5 |
| 2.7 | Install package and guide for the router | 2.6 | after 2.6 |
| 2.8 | What the router sees, and the dashboard on it | 2.7 | after 2.7 |
| 2.9 | Live and replay give the same features (parity test) | `flagmand extract`, from the phase 3 toolkit | once that pull request is merged |

## Linux, driven by the home test

### 2.1 Tune thresholds from the home test week

- **Why:** the defaults (15 addresses, 20 ports, 10 login attempts in
  60 s, 30 s for a login attempt) were chosen from the lab recordings and
  the tools' documentation, not from a real home.
- **What:** change a default in `detect/config.rs` and
  `deploy/linux/flagman.toml` only where the week's results show a false
  alarm or a missed test, and write the reason next to it. Add the
  results, without addresses, to `docs/changes/`.
- **Checked by:** the existing replay tests must still find the lab
  attacks; a new test for each false alarm that was fixed.

### 2.2 A "home network" setting

- **Why:** today "inside your network" means a private address (10/8,
  172.16/12, 192.168/16, fc00::/7, link-local). A home that uses public
  IPv6 addresses is not recognised, which affects the network sweep
  detector, the login detector (which threshold a server gets,
  [ADR 0011](adr/0011-watch-logins-to-internet-servers.md)) and where Suricata
  alerts are filed ([ADR 0010](adr/0010-suricata-alerts-filed-under-the-home-device.md)).
- **What:** one `home_networks` list in `flagman.toml`, defaulting to the
  private ranges, used by all three. When a Suricata alert carries its own
  `alert.target` field (only rules that use the `target` keyword do, see
  ADR 0010), use it.
- **Checked by:** unit tests with a public IPv6 home network; the replays
  give the same results as today with the default list.

### 2.3 Database versions and upgrades

- **Why:** a later version that changes a table must not break the
  database of an existing installation. Flows already know why they ended
  (closed, idle, evicted…), but the database cannot store it yet.
- **What:** record a schema version in the database file and add a small
  upgrade step per version. Then add the end reason to the `flows` table
  and show it in the connection lists.
- **Checked by:** a test that opens a phase 1 database, upgrades it, and
  keeps every row; the store tests.

### 2.4 (Optional) Read the PC's own SSH log

- **Why:** from packet headers alone, a quick successful login looks like
  a failed one ([ADR 0009](adr/0009-login-attempts-from-finished-connections.md)).
  The SSH server's own log knows the difference.
- **When:** only if the home test week shows false alarms from scripts
  that log in to a machine at home. Reading the log needs more rights for
  the service, so it should be opt-in.

## Edge, on the OpenWrt One

The brief gives the router 1 GB of memory. Before anything is built,
confirm on the device which processor architecture it reports and which
OpenWrt version it runs:

```bash
uname -m
cat /etc/openwrt_release
```

### 2.5 Build Flagman for the router

- **What:** cross-compile `flagmand` for the architecture found above,
  and add a CI job that builds it. No change to what Flagman does.
- **Checked by:** the binary starts on the router and replays the lab
  recordings with the same results as on Linux.

### 2.6 Fit the router

- **What:** make the memory limits (flows tracked, detector entries)
  configurable with smaller router defaults, measure memory and processor
  use with the lab recordings and a generated flood, and add a start-up
  script for OpenWrt's service manager (procd) to replace the systemd
  service.
- **Also measure, during the flood:** the rate at which login attempts
  start to be missed. When the table is full, a login connection that is
  still open can be ended as *evicted*, and an evicted attempt never
  counts (one that had already closed still does). A flow is pushed out
  once it has been silent for about 0.9 × table size ÷ flood rate seconds,
  and a failed SSH attempt in `lab-ssh-logins.pcap` is silent for up to
  2.9 s while the server delays its answer. The phase 1 follow-up test
  `flagman-core/src/engine_flood_tests.rs` pins this with a 1,000-flow
  table: logins are still seen at 310 new connections per second and lost
  from 320 (`cargo test -p flagman-core flood_rate -- --ignored
  --nocapture` prints the sweep). With the default 100,000 flows the same
  formula gives about 31,000 new connections per second; the smaller
  router table will lower it, so the pull request reports the router's
  number.
- **Checked by:** measured numbers written in the pull request; Flagman
  stays within the chosen memory budget during the flood.

### 2.7 Install package and guide

- **What:** an OpenWrt package (in the format the router's OpenWrt version
  uses), and `deploy/openwrt/README.md` for beginners.

### 2.8 What the router sees, and the dashboard on it

- **What:** check on the device which interface carries the home traffic,
  and whether traffic between two home devices passes through the
  router's processor at all (it may be switched without reaching it).
  Then adapt [home-test.md](home-test.md) for the router and serve the
  dashboard from it.

## Machine learning groundwork

### 2.9 Live and replay give the same features (parity test)

Written now, built later: Seraj's phase 3 brief asks for this test to be
described, not built yet. Nothing below exists today except the pinned
difference in the first bullet of "Known differences".

- **Why:** phase 3 trains models on features extracted from recordings
  (`flagmand extract`) and runs them on features computed live. If the two
  differ, a model's scores on recordings say nothing about what it does
  live, which is the first lesson of the CS395 project. `extract` already
  runs the live code (the same capture loop, engine and flow table, see
  `flagmand/src/extract.rs`); this test checks the whole chain on real
  traffic, from the network card to the feature file.
- **What to build:**
  1. A way to save features in live mode, for this test only:
     `flagmand run --features-out live.parquet`, behind the same `parquet`
     cargo feature, with `Engine<FeatureState>` and the writer `extract`
     uses. The normal sensor does not change.
  2. A lab script, like `core/testdata/pcap/record-lab-captures.sh`: in the
     isolated namespace lab, start `tcpdump -w lab.pcap` and
     `flagmand run --features-out live.parquet` on the same interface, run
     the normal and attack traffic, include the quiet case below, wait
     until every flow has ended, then stop both.
  3. `flagmand extract lab.pcap --out replay.parquet --config flagman.toml`,
     with the same configuration file as the live run.
  4. A comparison (a pytest in `product/ml`): match rows on protocol,
     addresses, ports and start time. Every flow must be in both files,
     with all 37 features exactly equal (same code, same packets).
- **Known differences to settle first:**
  - **Timeouts during a silence.** Live, the capture returns every 250 ms
    when no packet arrives, and the engine then runs its timeouts with the
    clock (at most once per second). A replay runs them only after a
    packet. So a flow that stays silent longer than its idle timeout, in a
    capture with no other traffic at all, is cut in two live but stays one
    flow in a replay. `flagman-core/src/engine_tests.rs` pins this today
    (`a_flow_silent_past_its_timeout_is_cut_live_but_not_in_a_quiet_replay`).
    Proposed fix: in `Engine::process_frame`, also run the timeouts that
    are due *before* adding the packet. Tried locally on 2026-11-27 on the
    three lab captures: no flow and no feature changed, only the order of
    rows in the files, and every test still passed. Busy captures, like
    the public datasets, are rarely affected, because other packets run
    the timeouts.
  - **Lost packets.** Live, the kernel drops packets when the sensor falls
    behind (`kernel_dropped` in the sensor's health); tcpdump reports its
    own drops when it stops. A run with drops on either side does not
    count; the script checks both and starts again.
  - **The first and last flows.** Flows already open when the capture
    starts look `midstream` in both files. Flows still open at the end are
    `stopped` at slightly different moments, so the script waits until
    every flow has ended before stopping, and the comparison leaves out
    `stopped` flows.
  - **Timestamps.** Both programs read the kernel's timestamp of the same
    packet, so they should agree; the comparison checks it. If they do
    not, it records the largest difference, and only the timing features
    may then differ by 1 ms.
  - **Capture length.** Flagman captures 160 bytes per packet live, while
    tcpdump records whole packets by default. Data sizes come from the
    headers (`payload_len`), so the features must not change; the test
    confirms it.
- **Checked by:** the comparison passes on a lab run with no lost packets;
  its numbers (flows on each side, mismatches) are kept in
  `docs/changes/`.
