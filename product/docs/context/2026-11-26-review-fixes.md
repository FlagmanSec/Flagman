> Markdown copy of [`2026-11-26-review-fixes.docx`](2026-11-26-review-fixes.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman Linux Pro: fixes after the phase 1 review

*Context document for the second push to pull request #1, 26 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `claude/project-thread-k6g47y`, pull request #1, not merged yet |
| Commits | `63b35d8` was the last commit of the first push (the phase 1 context document)<br>The next commit holds every change below, and this document |
| Requested by | Seraj, in the review of pull request #1 |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request (see section 11) |
| This file | `product/docs/context/2026-11-26-review-fixes.docx`, with a Markdown copy next to it (`.md`) that says the same thing |

### Contents

1. The short version
2. What the review found, and what was done
3. Fix 1: a flood can no longer blind the detectors
4. Fix 2: only failed logins count as login attempts
5. Fix 3: Suricata alerts from the internet are filed under your device
6. Honest wording about false alarms
7. Markdown copies of the context documents
8. Phase 2 in smaller pull requests
9. How it was checked
10. What is still open
11. Use of AI
12. Glossary

Appendix: commands to check everything yourself.

## 1. The short version

Seraj reviewed pull request #1, ran every check again (73 Rust tests, 46 dashboard tests, the two replays) and confirmed that the phase 1 claims hold. The review found two problems to fix before merging, one claim that went further than the evidence, and three smaller points. This push answers all of them, on the same pull request.

#### What changed

- **Fix 1, a blind spot under a flood.** When its memory was full, Flagman ignored every new address, so 50,000 made-up addresses could hide a real scan. Now a full table forgets its least active entries, the real scanner stays, and the dashboard shows **Detector saturated**.
- **Fix 2, login attempts.** Every connection to SSH used to count, including logins that work (git over SSH, VS Code Remote, Ansible). Now a connection counts only if the server refused it or it closed within 30 seconds, and only for servers inside your network. The rule was set from a new recording of a real SSH server in the lab.
- **Fix 3, Suricata grouping.** A Suricata alert whose source is a server on the internet is now filed under the device in your network that received it, not under that server.
- **Honest wording.** The normal recording is only 500 packets, so it does not prove that Flagman gives no false alarms. The documents now say so, and the home test gains a week of normal use to measure the real rate.
- **Markdown copies** of the context documents, so that they can be reviewed in a diff.
- **A phase 2 plan** made of eight small pull requests instead of one big one.

#### Numbers that changed

| What | First push | Now |
|---|---|---|
| Rust tests | 73 | 87 |
| Dashboard tests | 46 | 49 |
| Login attempts found in the nmap recording | 16 | 15: nmap’s single probe of port 22 no longer counts (section 4.6) |
| Lab recordings | 2 | 3 (new: real SSH logins) |
| Decision records (ADRs) | 7 | 10 |

## 2. What the review found, and what was done

| # | Seraj’s finding | What was done | Section |
|---|---|---|---|
| 1 | An attacker can blind the detectors: once 50,000 sources are tracked, new ones are ignored (`tracker.rs:123`). After 50,000 made-up addresses, a real 1,000-port scan went undetected. | A full table forgets its least active entries instead of ignoring newcomers. **Detector saturated** shows on the dashboard. | 3 |
| 2 | The login detector counts every connection to port 22, including logins that succeed (`brute_force.rs:52`). | Only connections that were refused, or closed within 30 s, to servers inside your network. | 4 |
| 3 | The normal recording is only 500 packets, so “no false alarms” is not proven yet. | The wording is fixed everywhere, and the home test gains a week of normal use. | 6 |
| 4 | A Suricata alert whose source is an outside server opens an incident “from” that server. | Such an alert is filed under the home device that received it. | 5 |
| 5 | A .docx in git cannot be reviewed in a diff. | A Markdown copy next to each context document. | 7 |
| 6 | One pull request of 17,760 lines is too big to review block by block. | Phase 2 is planned as small pull requests. | 8 |

## 3. Fix 1: a flood can no longer blind the detectors

### 3.1 The problem

Flagman remembers things in tables. The flow meter keeps one entry per live conversation. Each detector keeps one entry per key: for example, for each pair (scanner, target), the ports it tried during the last 60 seconds. Memory must stay bounded, or a flood of packets could fill it and crash the program, so each detector follows at most 50,000 keys and the flow meter at most 100,000 conversations.

The problem was what happened when a table was full: the first push simply ignored newcomers. Someone could first send packets from 50,000 made-up addresses, and any real scan after that went unseen, without any warning. Seraj tested it and saw a real 1,000-port scan go undetected. Filling 50,000 entries within the 60-second window takes about 830 packets per second, which any device on a home network can send.

### 3.2 The fix: forget the least active, never the newcomer

A newcomer is now always accepted. When a table is full, it first makes room by forgetting its least active tenth: 5,000 keys for a detector, 10,000 conversations for the flow meter.

- **In a detector**, “least active” is decided in this order: first the keys without an open alert, then the ones that counted the fewest different things (a made-up address that sent one packet has counted 1; a scanner has counted dozens or hundreds), then the ones that have been quiet for longest.
- **In the flow meter**, it is the conversations that have been quiet for longest. They are ended early and reported with the reason “evicted”, so they still reach the database and the login detector.
- **Nothing in progress disappears silently.** If a forgotten key had an open alert that grew since its last update, that last count is still published.
- **Why a tenth at once:** finding the least active entries means looking at the whole table. Doing it once per 5,000 newcomers, instead of for every packet, keeps the cost small.

Why the real scanner survives: while made-up one-packet addresses fill the table, they are always the first to go, because each of them has counted one thing. A scanner has counted more, and once it crosses the threshold it has an open alert, which puts it last in line.

### 3.3 “Detector saturated” on the dashboard

When a table had to make room, the top strip of the dashboard shows **Detector saturated**, with the time it last happened. It is a warning for 10 minutes, then turns grey, so it stays visible without raising the alarm forever. Hovering over it says how many entries were forgotten and how many connections were ended early. It is translated too: “Détecteur saturé” in French and “الكاشف مُشبَع” in Arabic. A replay prints the same information at the end of its summary:

```text
Detector saturated: to stay within its memory limit, it forgot <number> of its least
active entries and ended <number> connections early.
```

What it means for you: someone may be flooding the network, or the network is much bigger than the limits. Detection keeps working, but the quietest entries were dropped to make room.

### 3.4 How it is tested

- **The case from the review, end to end** (`engine.rs`, test `a_flood_of_fake_addresses_does_not_hide_a_real_scan`): 60,000 connection requests from made-up addresses (10.x.x.x), one per millisecond, with a real scan of ports 1 to 1,000 from 192.168.1.66 sent in the middle, alongside fake packets 55,000 to 56,000. The test checks that the port scan alert names 192.168.1.66 with 1,000 ports, and that the saturation was recorded. With the code of the first push, this test fails: the scan is not found.
- **Detector table** (`detect/tracker.rs`): a full table forgets its least active keys, not the newcomer; a flood of made-up sources cannot hide a real scan; a forgotten alert still reports its last count.
- **Flow meter** (`flow/table_tests.rs`): a full table ends its least recently active flow; in a table of 100, a flood of 1,000 new flows cannot push out an active connection.
- **Dashboard** (`lib/health.test.ts`): the item is absent while the sensor was never full, is a warning while recent and then a quiet note, and measures time from the last packet in replay mode.

ADR 0008 (`product/docs/adr/0008-full-tables-forget-the-least-active.md`) records the decision. The alternatives were to keep ignoring newcomers (the problem), to remove the single oldest entry each time (more code for the same effect), or to have no limit (a flood would use all the memory of the PC, and later of the 1 GB router).

## 4. Fix 2: only failed logins count as login attempts

### 4.1 The problem

The login detector raises an alert when one device makes 10 or more login attempts on one service of one machine within 60 seconds. In the first push, every new connection to a login port (SSH, RDP, FTP and others) counted as an attempt. Normal tools open many short SSH connections: git over SSH, VS Code Remote and Ansible can pass 10 a minute, so they would look like password guessing.

### 4.2 Measuring what a failed login looks like

Flagman only sees packet headers (addresses, ports, flags, sizes and times), never the password or the server’s answer, which are encrypted anyway. To learn what headers can tell apart, a new lab recording was made: `lab-ssh-logins.pcap`. A real SSH server (OpenSSH 9.6p1) ran inside the isolated lab, with throwaway keys and settings in a temporary folder. The wrong passwords were for `admin`, a user that does not exist, and no account was created on the computer. Five steps, measured from the recording:

| Step | Connections | Each lasted | Packets (to / from server) | Counted now? |
|---|---|---|---|---|
| 1. One wrong password | 10 | 3.1 s | 14 / 13 | yes: closed within 30 s |
| 2. Wrong passwords until the server hangs up (six, OpenSSH’s default `MaxAuthTries`) | 3 | 17.8 s | 19 / 23 | yes: closed within 30 s |
| 3. A key login kept open (`sleep 40`), like a working session | 1 | 40.3 s | 23 / 18 | **no**: open longer than 30 s |
| 4. A key login running one command (`true`), like git or Ansible | 5 | 0.24 s | 22 / 18 | yes: the known limit (section 4.5) |
| 5. The server is stopped: connection refused | 5 | 0 s | 1 / 1 | yes: refused |

### 4.3 What the recording teaches

- **Failed logins are not short.** Servers slow down wrong passwords on purpose: 3.1 s for one, 17.8 s for six.
- **The fastest login of all is a successful one that runs one command** (0.24 s).
- **Packet counts look alike** for failed and successful logins: 13 to 23 packets each way.
- **What headers can tell:** whether the server refused the connection, and whether a session stayed open. A session that stays open is a login that worked.

### 4.4 The new rule

A connection to a login port now counts as one login attempt when it has ended and:

1. the server **refused** it (it answered the connection request with a reset), or
2. the connection was **set up and then closed within 30 seconds** (`max_attempt_secs = 30`: enough for the 17.8 s of six wrong passwords, with room to spare).

It does not count when:

- it stays open longer than 30 seconds: a working session;
- nobody answers, for example a firewall that drops port 22: no password can be tried;
- it is half-open, like nmap’s probe during a port scan: the port answered, but the client reset the connection before any login;
- the server is on the internet (`local_targets_only = true`), so `git push` to GitHub never counts.

The threshold did not change: 10 attempts from one device on one service of one machine within 60 seconds. Because only the end of a connection shows how it went, the login detector now looks at connections when they end, not when they start, and the alert appears about 5 seconds after the last attempt closes. Scans and sweeps still look at connections when they start, so they are as fast as before.

### 4.5 The known limit

From headers alone, a quick successful login (step 4) looks exactly like a failed one. So ten git commands in a minute to an SSH server **inside** your network would still raise an alert. Servers on the internet are not watched by default, which covers the most common case (GitHub, cloud machines). If it happens at home, add the address of the machine that runs the scripts to `ignore_sources` in `flagman.toml`. The home test week will show whether more is needed; one option in the phase 2 plan is to read the SSH server’s own log, which knows whether a login worked.

### 4.6 Why the nmap recording now gives 15, not 16

The nmap recording contains 15 connections from a small Python loop, each closed by the server within a second, plus the connection request that nmap’s port scan sent to port 22. That probe is half-open: the port answered, and nmap reset the connection without trying to log in. It used to count; now it does not. tcpdump confirms both numbers: 16 connection requests to port 22, and 15 connections closed by the server (commands in the appendix).

### 4.7 How it is tested

- **Detector tests** (`detect/detectors_tests.rs`): wrong passwords and refused connections count; a full round of six wrong passwords lasting 17.8 s counts; working sessions never count; unanswered and half-open connections are not login attempts; servers on the internet are not watched by default; the same connection reported several times counts once.
- **Replay of the real SSH recording** (`flagmand/src/replay/tests.rs`): exactly one incident, from 192.168.77.66, severity high, with one login alert counting 23 connections on port 22 (10 + 3 + 5 + 5). Of the 24 connections to port 22, only the 40-second session is left out.

ADR 0009 (`product/docs/adr/0009-login-attempts-from-finished-connections.md`) records the rule and the options that were set aside: counting every connection (the problem); “closed within a second or two”, which would miss password guessing and still count quick logins; comparing who sent more bytes, which depends on the server’s software and keys; and reading the server’s log, which only works for the PC Flagman runs on.

## 5. Fix 3: Suricata alerts from the internet are filed under your device

### 5.1 The problem

Incidents group alerts by device. In the first push, that device was always the alert’s source. That is right for Flagman’s own detectors, where the source is the scanner or the password guesser. But many Suricata rules match the answer of a server. Suricata’s own test, `curl http://testmynids.org/uid/index.html` (rule 2100498), raises an alert whose source is the testmynids.org server. So the incident said it came “from” an outside server, and one PC’s Suricata alerts were split into one incident per server.

### 5.2 The rule now

- A Suricata alert whose source is outside your network and whose destination is inside is filed under the destination: your device.
- Every other alert stays filed under its source, including a scan from the internet: the scanner is the one to look at.
- The alert keeps its real source and destination, so the incident page still says which server sent the matching traffic.
- The dashboard now calls the incident’s device **Host** instead of **Source**. The database column keeps its old name (`src_ip`), so existing database files stay valid.

### 5.3 Limits

- “Inside” means a private address (10/8, 172.16/12, 192.168/16, fc00::/7 and link-local). A home that uses public IPv6 addresses is not recognised yet. A “home network” setting, like Suricata’s `HOME_NET`, is planned in phase 2 (pull request 2.2).
- Suricata can say itself which side is the target, in its `alert.source` and `alert.target` fields, but only “if target keyword is used in the signature” ([Suricata’s EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)). We have not counted how many rules use it, so Flagman cannot rely on it. Using it when it is present is part of pull request 2.2.
- Someone on the internet who scans a forwarded port and also triggers a Suricata rule appears in two incidents: one under them (the scan) and one under your device (the rule).

### 5.4 How it is tested

Two tests in `incident/engine.rs`: a Suricata alert from the internet is filed under the home device, and behaviour alerts (scans, sweeps, logins) stay with their source even when it is on the internet. ADR 0010 (`product/docs/adr/0010-suricata-alerts-filed-under-the-home-device.md`) records the decision.

## 6. Honest wording about false alarms

The first push said that replaying normal traffic “gives no incident at all”. That is true, but the normal recording is 500 packets over 10 seconds: 40 web page loads, 5 small UDP packets and 5 pings. It shows that the detectors stay quiet on that sample. It does not show that Flagman gives no false alarms in a real home, where printers, phones, smart TVs and the router behave in many other ways.

- The recordings’ README now says exactly that.
- The home test guide gains **step 9, a week of normal use**: for each incident, note the day, the kind of alert and the host, whether it was real or a false alarm and what caused it, and whether **Detector saturated** ever appeared. Its results table gains rows for this week, for a normal SSH login that must not raise an alert, and for the saturation warning.
- Step 5 of the home test (login attempts) now explains what counts, and the two cases that give no alert on purpose.
- The thresholds will be tuned from the week’s numbers, in the first pull request of phase 2.

## 7. Markdown copies of the context documents

A Word file is a zip archive, so GitHub cannot show what changed inside it. Each context document now has a Markdown copy next to it, in `product/docs/context/`, generated from the same text as the Word file, so the two say the same thing. GitHub shows the Markdown copy as a page, and a later change appears line by line in the diff.

- `2026-11-26-linux-pro-phase-1.md` is the copy of the phase 1 document. The Word file itself is unchanged. The copy starts with a note saying that some details changed after the review, and points to this document.
- `2026-11-26-review-fixes.docx` and `2026-11-26-review-fixes.md` are this document.

From now on, every push comes with both.

## 8. Phase 2 in smaller pull requests

Phase 1 was one pull request of 17,760 lines. Phase 2 will be a series of small ones, each about one subject, with its own tests, documents and context document. The order follows Seraj’s plan: a week of home testing, then thresholds tuned with those numbers, then Edge on the OpenWrt One. The full plan, with what each pull request changes and how it will be checked, is in `product/docs/phase-2-plan.md`.

| # | Pull request | Can start |
|---|---|---|
| 2.1 | Tune thresholds from the home test week | after the test week |
| 2.2 | A “home network” setting, like Suricata’s `HOME_NET` | now |
| 2.3 | Database versions and upgrades, then store why each connection ended | now |
| 2.4 | Only if 2.1 shows it is needed: read the PC’s own SSH log | after 2.1 |
| 2.5 | Build Flagman for the OpenWrt One | when the router is available |
| 2.6 | Fit the router: memory limits and a start-up script | after 2.5 |
| 2.7 | Install package and guide for the router | after 2.6 |
| 2.8 | What the router sees, and the dashboard on it | after 2.7 |

Before anything is built for the router, its processor architecture and OpenWrt version are to be confirmed on the device itself (`uname -m` and `cat /etc/openwrt_release`), rather than taken from a web page.

## 9. How it was checked

All commands were run from `product/core` or `product/ui` on 26 November 2026.

| Check | Command | Result |
|---|---|---|
| Rust tests | `cargo test --locked` | 87 passed: flagman-core 52, flagman-store 7, flagman-capture 2, flagman-api 7, flagman-suricata 5, flagmand 14 |
| Rust lints | `cargo clippy --all-targets --locked -- -D warnings` | no warnings |
| Rust format | `cargo fmt --check` | clean |
| Replay, nmap attack | `flagmand replay testdata/pcap/lab-attack-chain.pcap` | 1 incident, critical, host 192.168.77.66: sweep 255 hosts, port scan 1,000 ports, login attempts 15 connections |
| Replay, normal traffic | `flagmand replay testdata/pcap/lab-normal-traffic.pcap` | No incidents found |
| Replay, real SSH logins | `flagmand replay testdata/pcap/lab-ssh-logins.pcap` | 1 incident, high, host 192.168.77.66: login attempts 23 connections |
| Dashboard types | `npm run check` | 0 errors, 0 warnings |
| Dashboard tests | `npm test` | 49 passed |
| Dashboard build | `npm run build` | builds |

The real output of the nmap replay:

```text
Replayed lab-attack-chain.pcap: 2676 packets (0 unreadable) in 0.01 s.
1 incident found:
  #1 critical, host 192.168.77.66, 2026-11-26 18:09:31 UTC to 2026-11-26 18:09:41 UTC
      login attempts on 192.168.77.10 port 22: 15 connections [high]
      port scan of 192.168.77.10: 1000 ports [medium]
      host sweep: 255 hosts [medium]
```

Also checked:

- The flood test of section 3.4 was run against the code of the first push, where it fails, and against the new code, where it passes.
- A generated flood capture was also replayed through the real program, which found the scan and printed the saturation line. That file is about 4 MB and is not in the repository; the engine test covers the same case.
- tcpdump confirms both recordings: in the nmap one, 16 connection requests to port 22 and 15 connections closed by the server; in the SSH one, 24 connections to port 22, 5 of them refused.
- The **Detector saturated** item was looked at in screenshots, in English, in French with the dark theme, and in Arabic (right to left).
- OpenSSH’s default limits were read from the installed server itself (`sshd -T`), not from memory: `MaxAuthTries 6` and `LoginGraceTime 120`.

## 10. What is still open

- **The false alarm rate is unknown** until the home test week.
- **Quick successful logins** to an SSH server inside your network still count as login attempts (section 4.5).
- **Homes with public IPv6 addresses** are not recognised as “inside” yet (section 5.3).
- **Why a connection ended** is known to the program but not stored in the database yet (pull request 2.3).
- **Speed under a real flood** has not been measured on real hardware. The tests check what is detected, not how many packets per second Flagman keeps up with.
- **This push is not merged yet.** It waits for Seraj’s review.

## 11. Use of AI

Claude Code, an AI coding assistant made by Anthropic, wrote this push at Seraj’s request, from Seraj’s review: the code changes, the tests, the SSH lab script and its recording, the documents, and this document. The project’s AI-use log (`product/docs/ai-log.md`) has a row for it.

- Every number in this document comes from the code’s defaults, a test, a recording in the repository, or the output of a command in section 9. The flood numbers from the review (50,000 addresses, about 830 packets per second, a 1,000-port scan) are Seraj’s.
- External facts link to their source: Suricata’s documentation for its alert fields. OpenSSH’s defaults were read from the installed program.
- Safety: the SSH lab script only reaches its own two isolated network namespaces. It starts a throwaway SSH server for the recording, tries wrong passwords only against it, stops it afterwards, and creates no account on the computer. Flagman itself still only watches; it blocks nothing.
- The work was checked by running it (section 9), not only by reading it. A person still has to review it, and the pull request is the place for that.

## 12. Glossary

| Word | Meaning |
|---|---|
| Diff | The line-by-line view of what changed in a file, as GitHub shows it. |
| Eviction | Removing entries from a full table to make room. Flagman removes the least active tenth. |
| Detector saturated | The dashboard’s warning that a table was full and had to make room. |
| Flood | Many packets sent on purpose, often from made-up addresses, to overload a program. |
| Flow end reason | Why a conversation ended: closed by TCP, idle, running too long (active timeout), evicted, or stopped with the program. |
| Refused connection | The server answered the connection request with a reset (RST), usually because nothing listens on that port. |
| Half-open connection | The server accepted the connection request, but the client reset it before finishing the handshake. nmap’s default scan does this. |
| Host (of an incident) | The device an incident is about: usually the source of its alerts; for a Suricata alert from the internet, your device that received it. |
| `max_attempt_secs` | How long a connection may last and still count as a login attempt: 30 seconds by default. |
| `local_targets_only` | Watch only login servers inside your network. On by default. |
| `MaxAuthTries` | OpenSSH’s limit of password tries per connection: 6 by default. |
| `HOME_NET` | Suricata’s setting that lists your network’s addresses. |

## Appendix: commands to check everything yourself

From the repository folder, on Linux, with Rust, Node.js and tcpdump installed:

```text
cd product/core
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check

cargo build --release -p flagmand
for f in lab-attack-chain lab-ssh-logins lab-normal-traffic; do
  ./target/release/flagmand replay testdata/pcap/$f.pcap --db /tmp/$f.db --overwrite
done

cd testdata/pcap
SYN='tcp dst port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
FIN='tcp src port 22 and tcp[tcpflags] & tcp-fin != 0'
RST='tcp src port 22 and tcp[tcpflags] & tcp-rst != 0'
tcpdump -nn -r lab-attack-chain.pcap "$SYN" | wc -l   # 16 connection requests
tcpdump -nn -r lab-attack-chain.pcap "$FIN" | wc -l   # 15 closed by the server
tcpdump -nn -r lab-ssh-logins.pcap "$SYN" | wc -l     # 24 connections
tcpdump -nn -r lab-ssh-logins.pcap "$RST" | wc -l     # 5 refused

cd ../../../ui
npm ci && npm run check && npm test && npm run build
```

To run only the three flood tests of section 3.4: `cargo test --locked -p flagman-core a_flood_of`.
