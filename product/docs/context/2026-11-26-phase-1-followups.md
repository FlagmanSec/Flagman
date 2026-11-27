> Markdown copy of [`2026-11-26-phase-1-followups.docx`](2026-11-26-phase-1-followups.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman Linux Pro: three follow-ups after the merge

*Context document for the pull request from branch phase-1-followups, 26 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-1-followups`, a normal pull request into `main`, for the team to review and merge |
| Commits | `f448014` moves the login detector’s tests to their own file, with no change to any test<br>The next commit holds the three follow-ups and this document |
| Requested by | Seraj, in section 3.0 of the phase 3 toolkit prompt |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request (see section 9) |
| This file | `product/docs/context/2026-11-26-phase-1-followups.docx`, with a Markdown copy next to it (`.md`) that says the same thing |

### Contents

1. The short version
2. Follow-up 1: password guessing on internet servers is reported again
3. Follow-up 2: silence one login, not a whole device
4. Follow-up 3: a heavy flood can hide login attempts
5. What changes for an existing installation
6. How it was checked
7. Files changed, and where to start reading
8. What is still open
9. Use of AI
10. Glossary

## 1. The short version

The phase 3 prompt starts with three small points left over from the review of phase 1. They come in their own pull request, separate from the phase 3 work, so that the team can merge them right away.

1. **Password guessing on internet servers is reported again.** Before, only servers inside the home were watched, so a device of yours that guesses passwords on servers on the internet (which may mean it is infected) was never reported. Now those servers are watched too, with a higher threshold: 30 failed attempts on one server within 60 seconds, against 10 inside the home. Normal git over SSH stays quiet.
2. **One login can be silenced without hiding a whole device.** A new setting, `ignore_logins`, silences one login (a source, a target and a port) for the login rule only. The advice on login alerts, in English, French and Arabic, now points there instead of `ignore_sources`, which hides a device from every detector, scans included.
3. **A known limit is now measured and pinned by a test.** A flood of new connections that fills the flow table can end a login attempt before it is counted. With a small 1,000-flow table, logins are lost from 320 new connections per second; with the default 100,000 flows, the same mechanism gives about 31,000. No detector change: phase 2 measures it on the router.

Everything passes: 93 Rust tests (87 at the merge) plus 1 measurement test that runs on demand, 51 dashboard tests (49 at the merge), `cargo fmt`, `clippy -D warnings` and the dashboard type check.

## 2. Follow-up 1: password guessing on internet servers is reported again

### 2.1 The problem

ADR 0009 (accepted in the review of phase 1) made the login detector count only connections that were refused, or closed within 30 seconds. To keep git over SSH to GitHub quiet, it also watched only servers inside the home network, with the setting `local_targets_only = true`.

The side effect: a device in the home that guesses passwords on servers on the internet was never reported. The prompt calls this typical botnet behaviour. A device that has been taken over is used against other people’s servers, and telling the owner about it is one of the reasons to run an IDS at home.

### 2.2 Why not simply watch everything with the same threshold

Flagman reads only packet headers, never the password. From headers, a quick successful login looks like a failed one. The lab recording `lab-ssh-logins.pcap` (a real OpenSSH server) shows the timings:

| What happened | Connection length in the lab |
|---|---|
| A successful login that runs one command (like `git fetch`) | 0.24 s |
| One wrong password | 3.1 s |
| Six wrong passwords, until the server hangs up | 17.8 s |

Every `git fetch` or `git push` over SSH is one short connection. A person working by hand makes a few a minute, but a script can make more, so the threshold of 10 used inside the home would raise false alarms on internet servers.

### 2.3 What changed

The detector now has two counters: one for servers inside the home, one for servers on the internet. The settings, under `[detect.brute_force]` in `flagman.toml`:

| Setting | Default | Meaning |
|---|---|---|
| `min_attempts` | 10 (unchanged) | Failed attempts on one server inside the home, within 60 s |
| `outbound_min_attempts` | 30 (new) | The same, for one server on the internet |
| `local_targets_only` | `false` (was `true`) | `true` turns the internet counter off, as in phase 1 |
| `max_attempt_secs` | 30 (unchanged) | A connection open longer than this is a working session, never an attempt |

### 2.4 How the detector decides, step by step

1. A connection to a login port (SSH 22, RDP 3389, and the other ports in the `ports` list) ends.
2. Was it a failed attempt? Only if it was refused, or set up and closed within 30 s (the ADR 0009 rule, unchanged).
3. Is this exact login (source, target, port) in `ignore_logins`? Then it is not counted (section 3).
4. Is the server inside the home (a private address)? Then it goes to the home counter, threshold 10. Otherwise it goes to the internet counter, threshold 30, unless `local_targets_only` is `true`, in which case it is not counted.
5. The counter keeps, for each (guesser, server, port), the client ports seen in the last 60 s. A retransmission reuses its port, so it counts once. When the count reaches the threshold, an alert opens.
6. The alert says which case it is: its details carry `outbound: true` for an internet server. It has the same severity (high) and is filed under the home device, the guesser.

### 2.5 Why 30

From the lab timings above, a tool that opens a new connection for each password makes about 19 connections a minute for each connection it runs in parallel (60 ÷ 3.1). With two in parallel it makes about 38, above 30, so it is reported. A person running git by hand stays far below. 30 is a starting value, like the other thresholds; the home test week will tell whether it is right.

### 2.6 What the dashboard says

The alert page explains why it matters and what to check. In English, for an internet server:

- **Why:** “Here the guesser is one of your own devices, and the server is on the internet. If it is not one of your tools, the device may be infected and used to attack others, and those servers may then block your internet address.”
- **What to check:** “Find out what runs on 192.168.1.20: a script, a backup or sync tool, or a program you do not know. If it is your own tool, add an exception for this login only, under [detect.brute_force] in flagman.toml: ignore_logins = [{ source = "192.168.1.20", target = "203.0.113.5", port = 22 }]. If you do not recognise it, disconnect 192.168.1.20 from the network and check it for malware.”

The addresses in this example are made up: 203.0.113.5 is from a block reserved for documentation ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)). The French and Arabic texts say the same.

### 2.7 Limits, written in ADR 0011

- A slow guesser stays under 30: one connection at a time with one password each (about 19 a minute), or several passwords per connection.
- Spraying, one or two tries on each of many servers, is a different pattern and is not caught, because each server’s count stays low. A later detector could count servers per device.
- A script that runs more than 30 git commands a minute against the same server, or an app that opens a new database connection for every request to a database on the internet (ports 1433, 3306, 5432), raises an alert. One `ignore_logins` entry silences that login only.

The decision and the alternatives that were rejected are in [ADR 0011](../adr/0011-watch-logins-to-internet-servers.md). ADR 0009 now says at the top which part ADR 0011 changed.

## 3. Follow-up 2: silence one login, not a whole device

### 3.1 The problem

When a login alert came from the owner’s own script, the advice said to add the script’s device to `ignore_sources`. That setting silences a device for **every** detector, so a real scan from that device would be hidden too.

### 3.2 What changed

A new list, `ignore_logins`, under `[detect.brute_force]`. Each entry is one login: the device that logs in, the server, and the server’s port.

```text
[detect.brute_force]
ignore_logins = [
  { source = "192.168.1.20", target = "192.168.1.10", port = 22 },
]
```

- Only that login is silenced. The same device logging in to another server is still counted, and its scans are still reported. A test checks all three.
- Each entry needs all three fields. A missing field, a misspelt one or a bad address stops the program at start-up with an error, like every other setting.
- `ignore_sources` still exists, for a device that should be silenced for everything (for example a router that draws a map of the network on purpose).

### 3.3 The advice, in three languages

The advice on every login alert now gives the exact line to add, with the alert’s own addresses and port filled in, instead of pointing to `ignore_sources`.

In Arabic, which reads right to left, a line of code inside a sentence can come out scrambled. The code is wrapped in invisible “left-to-right isolate” marks (U+2066 and U+2069), the same marks the Arabic texts already put around commands such as `journalctl -u ssh`. The new texts were rendered in a browser at desktop width (760 pixels) and phone width (390 pixels), and the position of each part of the code was measured: it keeps its left-to-right order, also when it wraps onto a second line.

## 4. Follow-up 3: a heavy flood can hide login attempts

The prompt asked for no detector change here: measure the limit, pin it with a test, and write it down. This section explains the mechanism step by step.

### 4.1 The mechanism

1. The flow table keeps at most 100,000 connections at once, so that memory stays bounded.
2. When it is full, it ends the least recently active tenth of its connections to make room (ADR 0008). Those connections end with the reason “evicted”.
3. A failed SSH login has a quiet pause: after a wrong password, the server waits on purpose before answering. In `lab-ssh-logins.pcap`, that pause is 2.89 s in every single-password attempt, and the longest pause in a six-password attempt is 2.93 s.
4. During a flood, a connection that has been quiet for longer than about 0.9 × table size ÷ flood rate seconds is among the least recently active tenth, so it is ended as evicted.
5. An evicted attempt never counts: only refused connections and closed ones do. The packets that come after the eviction form a new connection that starts in the middle, which the login rule ignores. (An attempt that had already closed before it was evicted still counts.)
6. So logins are lost once that quiet time drops below the server’s pause: when the flood rate is above 0.9 × table size ÷ 2.9 s.

### 4.2 The measurement

The new test file `engine_flood_tests.rs` replays, through the real engine, 10 failed logins 3.1 s apart, mixed with a flood of fake connection requests from many addresses, with a small table of 1,000 connections. All times come from the packets’ own timestamps, as in a replay: the engine never reads the computer’s clock, so the result is the same on every machine.

| Flood (new connections per second) | Login attempts seen? | Connections evicted |
|---|---|---|
| 250 | yes | 7,100 |
| 300 | yes | 8,700 |
| 310 | yes | 9,000 |
| 320 | **no** | 9,300 |
| 350 | no | 10,300 |
| 400 | no | 11,900 |
| 1,000 | no | 31,100 |

The formula predicts the turning point: 0.9 × 1,000 ÷ 2.9 ≈ 310. The table is printed by `cargo test -p flagman-core flood_rate -- --ignored --nocapture`.

### 4.3 The tests that pin it

- `a_light_flood_does_not_hide_login_attempts`: at 200 per second, the table evicts connections and the login alert still comes out.
- `known_limit_a_heavy_flood_hides_login_attempts`: at 1,000 per second, the alert does not come out. If a later change removes the limit, this test fails, and its message says to update the known limit in the documents.
- `measure_the_flood_rate_where_logins_are_lost`: prints the table above; it runs only on demand.

### 4.4 What it means for a real installation

With the default table of 100,000 connections, the same formula gives about 31,000 new connections per second (0.9 × 100,000 ÷ 2.9). That is an estimate from the formula, not a measurement on real hardware. The router will have a smaller table, so a lower limit: item 2.6 of the phase 2 plan now asks for this rate to be measured on the router and written in its pull request. The limit is also listed as known limit 8 in `phase-1-linux-pro.md` and in the threat model.

## 5. What changes for an existing installation

- The installer never overwrites `/etc/flagman/flagman.toml`. Phase 1 wrote `local_targets_only = true` there, so an existing installation keeps the old behaviour: internet servers are not watched.
- To turn the internet watch on, edit that file, set `local_targets_only = false`, and restart with `sudo systemctl restart flagman`. A setting missing from the file takes its default, so `outbound_min_attempts` is 30 without adding it.
- Alerts already in the database read as before: a login alert stored without the new `outbound` field is read as an alert about a server in the home.
- If Seraj’s home test already runs phase 1, set `local_targets_only = false` there to test the new rule during the test week.

The changelog says this in bold, under “Changed (phase 1 follow-ups)”.

## 6. How it was checked

### 6.1 New tests

| Test | What it proves |
|---|---|
| `guessing_passwords_on_an_internet_server_is_reported` | 30 failed attempts in a minute on an internet server raise one alert, marked `outbound`. It fails with the old default (`local_targets_only = true`): that was checked by running it with the old value |
| `quick_logins_to_an_internet_server_stay_silent` | 20 quick logins in a minute (like git) to an internet server: no alert. The same 20 to a server in the home: alert |
| `local_targets_only_turns_the_internet_watch_off` | 40 attempts on an internet server, silent when the setting is `true` |
| `ignore_logins_silences_one_login_and_nothing_else` | The excepted login is silent; the same device on another server still alerts; its port scan is still reported |
| `a_login_exception_names_a_source_a_target_and_a_port` | An `ignore_logins` entry is read from `flagman.toml`; an entry without a port is refused |
| `typos_and_bad_values_are_reported` (extended) | `outbound_min_attempts = 0` is refused at start-up |
| `a_light_flood_…`, `known_limit_a_heavy_flood_…` | Section 4.3 |
| Two dashboard tests | Login alerts point to an exception for that login only; an internet server gets its own advice |

“Fails before, passes after”: the first test fails on `main`. The `ignore_logins` tests cannot even compile on `main`, because the setting does not exist there. The flood tests describe the current behaviour on purpose (no detector change was asked), so they pass on both.

### 6.2 Totals

| Check | At the merge of phase 1 | Now |
|---|---|---|
| Rust tests (`cargo test --locked`) | 87 passed | 93 passed, 1 on demand |
| Dashboard tests (`npm test`) | 49 passed | 51 passed |
| `cargo fmt --check`, `cargo clippy -D warnings` | clean | clean |
| Dashboard type check (`npm run check`) | 0 errors, 0 warnings | 0 errors, 0 warnings |

### 6.3 Commands to repeat the checks

```text
cd product/core
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
cargo test --locked -p flagman-core login
cargo test -p flagman-core flood_rate -- --ignored --nocapture

cd ../ui
npm ci && npm run check && npm test
```

## 7. Files changed, and where to start reading

Start with [ADR 0011](../adr/0011-watch-logins-to-internet-servers.md), then `detect/brute_force.rs` (171 lines), then its tests in `detect/login_tests.rs`, then `engine_flood_tests.rs`.

| File (under `product/`) | What changed |
|---|---|
| `core/crates/flagman-core/src/detect/brute_force.rs` | Two counters (home and internet), the `ignore_logins` check, `outbound` on the alert |
| `…/detect/config.rs` | `outbound_min_attempts`, `ignore_logins`, `local_targets_only` now `false` by default |
| `…/detect/login_tests.rs` | The login rule’s tests, moved out of `detectors_tests.rs` in the first commit, then 4 new ones |
| `…/alert.rs` | `outbound` in the login alert details; old rows read as `false` |
| `…/engine_flood_tests.rs` (new), `…/engine.rs` | The flood tests; 4 lines in `engine.rs` to include them |
| `core/crates/flagmand/src/config.rs` | Checks the new setting; one new test |
| `deploy/linux/flagman.toml` | The new settings, with comments |
| `ui/src/lib/explain.ts`, `types.ts`, `i18n/en.ts`, `fr.ts`, `ar.ts`, `explain.test.ts` | The advice for both cases, in three languages, and its tests |
| `docs/adr/0011-…` (new), `0009-…`, `adr/README.md` | The decision; ADR 0009 says which part changed |
| `docs/phase-2-plan.md` | Item 2.6 measures the flood limit on the router |
| `docs/changes/phase-1-linux-pro.md` | A “Follow-ups after the merge” section; known limits 8 and 9 |
| `CHANGELOG.md`, `README.md`, `docs/architecture.md`, `glossary.md`, `home-test.md`, `threat-model.md`, `reading-order.md`, `ai-log.md`, the recordings’ README, the `flagman-core` README | The same facts, where each document mentions the login rule |

## 8. What is still open

- The home test week will tell whether 10 (home) and 30 (internet) are the right thresholds.
- Spraying (a few tries on many servers) needs another detector, later.
- The flood limit on the router is measured in phase 2 (item 2.6).
- Existing installations need the manual change in section 5.
- The phase 3 toolkit continues on separate draft branches (`phase-3/01-features` and the ones after it), each based on the previous one. None of it is in this pull request.

## 9. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, the tests and the documents of this pull request at Seraj’s request, following the phase 3 prompt. Every number in this document comes from a test or a command listed in section 6, or from the lab recording’s README. A row was added to `docs/ai-log.md`. The team reviews and merges; the AI never merges.

## 10. Glossary

| Word | Meaning |
|---|---|
| Evicted | Ended by the flow table to make room when it is full, not because the connection finished |
| Flow table | Flagman’s list of the connections it is following, at most 100,000 at once |
| Login exception | An `ignore_logins` entry: one source, one server and one port that the login rule never reports |
| Internet server (outbound) | A server outside the home network, here one your device logs in to |
| Isolate marks | Invisible Unicode characters that keep a piece of left-to-right text (an address, a line of code) in order inside right-to-left Arabic text |
| Spraying | Trying one or two passwords on each of many servers, instead of many passwords on one |
| Threshold | The count that turns normal into suspicious: here 10 failed logins a minute on a home server, 30 on an internet server |
