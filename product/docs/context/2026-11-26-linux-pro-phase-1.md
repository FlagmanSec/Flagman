> **About this file.** This is a Markdown copy of
> [`2026-11-26-linux-pro-phase-1.docx`](2026-11-26-linux-pro-phase-1.docx),
> generated from the same text, so that it can be read and reviewed in a diff.
> It describes phase 1 as it was first pushed. Some details changed after
> Seraj's review on 26 November 2026; they are listed in
> [`2026-11-26-review-fixes.md`](2026-11-26-review-fixes.md).

# Flagman Linux Pro: what was built, and why

*Context document for the phase 1 push, 26 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `claude/project-thread-k6g47y`, merged into `main` through a pull request |
| Commits | `44596c4`: sensor core, program and lab recordings<br>`0324c3c`: dashboard, documentation and CI<br>The next commit adds this document |
| Requested by | Seraj |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request (see section 10) |
| This file | `product/docs/context/2026-11-26-linux-pro-phase-1.docx` |

### Contents

1. The short version
2. What changed in the repository
3. How Flagman works, step by step
4. Why it is built this way
5. Safety and security
6. How it was tested
7. How to run it
8. What is not done yet, and what comes next
9. Where to read more
10. Use of AI, and what you can say about it
11. Glossary

Appendix: commands to check everything yourself.

## 1. The short version

You asked for the Linux Pro version of Flagman first: a program that runs on a Linux PC on your home network, notices when someone runs an nmap scan or tries to break in, and shows it on a dashboard in the spirit of Suricata’s. Windows waits until Linux gives excellent results, and the router version (Edge, on the OpenWrt One) follows in about three weeks. This push is that first Linux version.

#### What you get

- **A sensor program** called `flagmand`, written in Rust. It watches one network interface, keeps only packet headers, and detects network sweeps, port scans and login attempts. When Suricata is installed, it also reads Suricata’s alerts.
- **A dashboard** in the browser: an overview with charts, the incident list, each incident told as a short story, and a traffic list. In English, French and Arabic, light and dark, and it works on a phone.
- **An installer and a locked-down Linux service**, so Flagman starts with the computer and runs with as few rights as possible.
- **Real recordings of an nmap attack**, made in an isolated virtual lab, and tests that replay them to prove that detection works.
- **Documentation for beginners**: a README in every folder, a reading order, the architecture, a glossary, a threat model, a home test guide, seven decision records and an AI-use log.
- **Automatic checks on GitHub (CI)** that run every test whenever the product folder changes.

#### What is proven

- Replaying the recorded nmap attack gives exactly one incident, rated critical, with the network sweep (255 addresses), the port scan (1,000 ports) and the login attempts (16 connections).
- Replaying normal traffic gives no incident at all.
- 73 Rust tests and 46 dashboard tests pass. The strict lint and type checks report no warnings.

#### What is not proven yet

- Detection on your real home network. That is the home test (section 7.3).
- Wi-Fi interfaces, runs lasting several days, memory use under heavy traffic, and Suricata’s log permissions on a real installation.

#### What you should do next

1. Look at the pull request. Section 9 says what to read first.
2. Run the home test on your Linux PC (`product/docs/home-test.md`) and fill in its results table.
3. Send the results. The thresholds and wording get adjusted from them, then Edge starts.

## 2. What changed in the repository

Every new file is inside `product/`, except one: the CI workflow, `.github/workflows/product-ci.yml`, because GitHub only reads workflows from that folder. It only runs when something in `product/` changes.

**No existing file was modified or deleted.** The CS395 research (`README.md`, `notebooks/`, `src/`, `results/`, `requirements.txt`) is exactly as it was. Before this document was added, the branch added 175 files and 17,750 lines, and removed none. You can check it yourself:

```text
git diff --stat main..claude/project-thread-k6g47y | tail -1
git diff --name-only main..claude/project-thread-k6g47y | cut -d/ -f1 | sort | uniq -c
```

The second command should only list `product` and `.github`.

| Folder | Files | What is inside |
|---|---|---|
| `product/core/crates/flagman-core` | 33 | The detection logic. It has no network, disk or clock of its own, which makes it easy to test. |
| `product/core/crates/flagman-capture` | 7 | Reads packets from a network interface or from a recording |
| `product/core/crates/flagman-suricata` | 5 | Reads Suricata’s alerts |
| `product/core/crates/flagman-store` | 10 | The SQLite database |
| `product/core/crates/flagman-api` | 11 | The web API behind the dashboard, protected by a token |
| `product/core/crates/flagmand` | 14 | The program itself: commands, settings, threads |
| `product/core` (workspace files) | 4 | Cargo.toml, Cargo.lock, rust-toolchain.toml, README |
| `product/core/testdata` | 4 | The lab recordings and the script that made them |
| `product/ui` | 61 | The dashboard (Svelte), with its tests |
| `product/deploy` | 5 | Installer, service file and settings file for Linux |
| `product/docs` | 17 | The documentation (before this file) |
| `product` (top level) | 3 | README, CHANGELOG, .gitignore |
| `.github/workflows` | 1 | The CI workflow |

In size: 7,724 lines of Rust and 4,634 lines of TypeScript and Svelte, tests included.

## 3. How Flagman works, step by step

### 3.1 The idea

Flagman is an intrusion detection system (IDS): it watches and explains, and it never blocks anything. It receives a copy of the packets that reach the PC’s network card, keeps only the first 160 bytes of each one (the headers: addresses, ports, flags), and looks for behaviour that normal programs do not have, such as trying 1,000 doors of the same machine within a few seconds.

### 3.2 The journey of a packet

1. **Capture.** libpcap, the library that tcpdump and Wireshark use, hands each packet to Flagman, cut to 160 bytes (`flagman-capture`).
2. **Decode.** The bytes become addresses, ports, protocol and TCP flags. A malformed packet is counted and skipped; it cannot crash the program (`flagman-core/src/packet`).
3. **Flow meter.** Packets are grouped into conversations, called flows: who talked to whom, on which port, how many packets and bytes, and for TCP how it ended, for example refused (`flagman-core/src/flow`).
4. **Detectors.** Every new conversation and every ARP request goes past the detectors, which count suspicious patterns (section 3.3).
5. **Incidents.** Alerts from the same source device are grouped into one incident (section 3.5).
6. **Storage.** A separate thread writes everything into a SQLite database file.
7. **API.** A small web server on the same PC answers the dashboard, but only when the request carries the secret token.
8. **Dashboard.** Your browser shows the results, and refreshes every 10 seconds (overview) or 15 seconds (other pages).

### 3.3 The detectors

| Detector | What it counts | Fires at (default) | Example | MITRE ATT&CK |
|---|---|---|---|---|
| Network sweep | Different local addresses that one device probes | 15 within 60 s | `sudo nmap -sn 192.168.1.0/24` | T1018 Remote System Discovery (Discovery) |
| Port scan | Different ports one device tries on one machine | 20 TCP or 30 UDP ports within 60 s | `nmap 192.168.1.10` | T1046 Network Service Discovery (Discovery) |
| Login attempts | New connections from one device to one login service of one machine | 10 within 60 s | A password-guessing tool against SSH | T1110 Brute Force (Credential Access) |
| Suricata rule | Alerts that Suricata writes to its log | Each alert; the same rule between the same two hosts becomes one alert with a count | Anything Suricata’s rules recognise | From the rule’s own MITRE tags, when it has them |

Login ports watched by default: 21 (FTP), 22 (SSH), 23 (Telnet), 110 (POP3), 143 (IMAP), 445 (SMB), 1433 (MS SQL), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL) and 5900 (VNC).

Starting severity: sweeps and port scans are medium, login attempts are high. For Suricata, its severity 1 becomes high, 2 becomes medium, and anything else low.

All thresholds can be changed in `/etc/flagman/flagman.toml`. Their defaults are in `product/core/crates/flagman-core/src/detect/config.rs`.

### 3.4 Counting in a sliding window: a worked example

Take `nmap 192.168.1.10`. nmap sends a connection request (a TCP SYN) to 1,000 ports within a few seconds. For the pair (scanner, target), Flagman keeps the list of different ports tried during the last 60 seconds:

- When the list reaches 20 ports, Flagman opens a “finding” and creates an alert.
- While the scan goes on, the alert is updated with the growing count, at most every 5 seconds.
- When the pair has been quiet for 120 seconds, the alert is closed with its final count: 1,000 ports.

Counting **different** ports, not packets, is what avoids false alarms: a slow network that resends the same packet does not look like a scan, and a program that talks a lot to port 443 is one port, not many.

### 3.5 Incidents and severity

An incident is one story to review: all the alerts from the same source device, as long as there are less than 30 minutes between them.

Its severity is the highest severity of its alerts, raised one level when the device went through two or more attack stages (ATT&CK tactics). Going from discovery to password guessing looks like an attack in progress, so it deserves more attention than either step alone. The lab recording shows it:

| Alert | Severity | Attack stage (tactic) |
|---|---|---|
| Network sweep | medium | Discovery |
| Port scan | medium | Discovery |
| Login attempts | high | Credential Access |
| **Incident** | **critical**: the highest alert is high, raised one level for two stages | Discovery and Credential Access |

### 3.6 Suricata (optional)

Suricata is a free, open-source IDS with a large set of rules for known attacks. When it is installed, Flagman follows its log, `/var/log/suricata/eve.json`, and keeps only the alert lines. It starts at the end of the file, so old alerts are ignored, and it keeps working when the log is rotated. Suricata stays a separate program under its own licence (GPL-2.0): Flagman only reads its log and contains none of its code.

### 3.7 Storage

Everything goes into one file, `/var/lib/flagman/flagman.db`, with four tables: flows, alerts, incidents, and traffic per minute. Flows and per-minute traffic are kept 7 days; alerts and incidents 90 days. Old rows are deleted every hour. No packet contents are ever stored.

### 3.8 The dashboard

- **Sign-in**: open the link that `sudo flagmand token` prints. The token is the part after `#`, which the browser never sends over the network.
- **Overview**: headline numbers, traffic over time (bytes or packets), new alerts by severity, the protocol mix (bytes and packets), the busiest devices, the most used services, recent incidents and alert types. Every chart has a “Table” button that shows the same data as a table.
- **Incidents**: the list, with filters for period, severity and status.
- **Incident details**: what happened (one sentence per alert), why it matters, what to check, links to MITRE ATT&CK, the evidence, and the connections involved. Buttons record your review: confirmed, false positive, resolved.
- **Traffic**: the connections list, filtered by address, port and protocol.
- **Top strip**: the interface being watched, packets seen, packets dropped by the kernel, the last packet, and Suricata’s status.
- **Settings**: language (English, French, Arabic) and theme (light, dark, automatic).

### 3.9 Running and stopping

Flagman runs four threads: capture and detection; the database writer; the Suricata reader; and the web server. On Ctrl-C or `systemctl stop`, it finishes the current work, closes the open alerts, saves the last results, then stops. A second Ctrl-C exits at once.

## 4. Why it is built this way

Each decision has a record in `product/docs/adr/` (ADR = architecture decision record).

| Decision | Why | What we gave up |
|---|---|---|
| Rust for the sensor (ADR 0001) | It reads hostile packets all day: Rust prevents memory errors without slowing down, and the same code must later fit a 1 GB router. | The team has to learn Rust. Machine learning stays in Python for now. |
| Everything in `product/` (ADR 0002) | Keeps the CS395 research untouched, in the repository the team asked for. | Nothing yet. It can move to its own repository later, with its history. |
| libpcap, waiting with our own `poll()` (ADR 0003) | libpcap is the standard on Linux and OpenWrt. On Linux its timeout never fires on a quiet network, so Flagman waits itself, 250 ms at a time. | Building needs `libpcap-dev`. |
| SQLite (ADR 0004) | Nothing to install or run, one file to back up, works on a router. | Not made for heavy analysis over months of data. |
| Rules first, machine learning later (ADR 0005) | Every alert can say why it fired. The CS395 model’s features do not match what the sensor sees, and there is no labelled home data yet. | Slow scans and new attack types are missed (Suricata covers part of it). |
| Svelte and hand-made charts (ADR 0006) | Small (about 45 kB of compressed JavaScript), works offline, accessible, three languages. | More of our own code to test. |
| A token, even on localhost (ADR 0007) | Any web page can send requests to 127.0.0.1; without the token it cannot read the answers. | One token for everyone; no user accounts yet. |

## 5. Safety and security

### 5.1 The ground rules of your brief, and how they are met

- **Defensive only**: Flagman watches and explains. It does not block, attack or change any traffic.
- **Attack traffic only in an isolated lab**: the only traffic generator is the lab recording script. It runs inside two Linux network namespaces joined by a virtual cable, with no route to any real network.
- **Monitor only networks you are allowed to**: stated in the product README and in the home test guide.
- **Private by design**: headers only, no packet contents stored, no cloud, no account, no telemetry. The dashboard listens on 127.0.0.1 only.

### 5.2 What protects Flagman itself

| Risk | Protection |
|---|---|
| A crafted packet crashes or takes over Flagman | Memory-safe Rust; every length is checked; bad packets are counted and skipped. |
| A flood fills the memory | At most 100,000 conversations tracked, 60-second windows, bounded queues between threads, and a 512 MB hard limit in the service. |
| A web page reads your alerts | The token is required on every API call; a strict Content Security Policy; no cross-site access. |
| Another account on the PC reads the token | The token file can only be read by the `flagman` user (mode 0600). |
| A bug gives root to an attacker | The service runs as the unprivileged `flagman` user with only two capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`), a read-only system and a system-call filter. `systemd-analyze security` rates it 2.2, “OK” (lower is safer). |

### 5.3 Known gaps

- No HTTPS yet: use the dashboard on the PC itself, or through an SSH tunnel.
- One token for everyone; no user accounts.
- Forged (spoofed) source addresses are reported as they appear.
- One PC only sees its own traffic and the network’s broadcasts (section 7.3).

Details: `product/docs/threat-model.md`.

## 6. How it was tested

### 6.1 Automatic tests

| Part | Tests | Command |
|---|---|---|
| flagman-core (decoding, flows, detectors, incidents) | 39 | `cargo test -p flagman-core` |
| flagman-store (database) | 7 | `cargo test -p flagman-store` |
| flagman-capture (reading recordings) | 2 | `cargo test -p flagman-capture` |
| flagman-api (routes, token, headers) | 7 | `cargo test -p flagman-api` |
| flagman-suricata (log parsing) | 5 | `cargo test -p flagman-suricata` |
| flagmand (settings, token, end-to-end replays) | 13 | `cargo test -p flagmand` |
| Dashboard (formatting, chart maths, translations, story sentences, addresses, links, routes, token) | 46 | `npm test` |

On top of the tests: `cargo clippy --all-targets -- -D warnings` (no warnings), `cargo fmt --check` (clean), `npm run check` (0 errors, 0 warnings) and `npm run build`. The CI workflow runs all of them again on GitHub.

### 6.2 The lab recordings: real nmap traffic, safely

To test with real attack traffic without touching a real network, the script `record-lab-captures.sh` builds a tiny virtual network inside one Linux machine: two isolated network namespaces, an attacker (192.168.77.66) and a victim (192.168.77.10), joined by a virtual cable. tcpdump records the traffic, keeping 160 bytes per packet like the sensor. The files were recorded on 26 November 2026 with Nmap 7.94SVN, tcpdump 4.99.4 and Python 3.13.

**The attack recording** (`lab-attack-chain.pcap`, 2,676 packets over 10 seconds) has three steps:

1. `nmap -sn -n 192.168.77.0/24`: host discovery. nmap asks “who has this address?” (ARP) for every address except its own: 256 − 1 = 255.
2. `nmap -n 192.168.77.10`: nmap’s default scan, a SYN scan of its 1,000 most common ports.
3. A Python loop opens 15 connections to the victim’s SSH port (22), 0.3 s apart, like a password-guessing tool.

Flagman finds one incident from 192.168.77.66, rated critical: host sweep 255, port scan 1,000, login attempts 16 (the 15 connections of step 3, plus the SYN that the scan of step 2 sent to port 22). This is the real output:

```text
Replayed lab-attack-chain.pcap: 2676 packets (0 unreadable) in … s.
1 incident found:
  #1 critical from 192.168.77.66, 2026-11-26 18:09:31 UTC to 2026-11-26 18:09:41 UTC
      login attempts on 192.168.77.10 port 22: 16 connections [high]
      port scan of 192.168.77.10: 1000 ports [medium]
      host sweep: 255 hosts [medium]
```

**The normal recording** (`lab-normal-traffic.pcap`, 500 packets over 10 seconds): 40 web page loads, 5 small UDP packets to port 5353 and 5 pings. Flagman reports “No incidents found.”

Both results are automatic tests (`product/core/crates/flagmand/src/replay/tests.rs`). You can recount the numbers with tcpdump: the commands are in `product/core/testdata/pcap/README.md`.

### 6.3 Checked by hand, once, in the same isolated lab

- `flagmand run` on the victim’s interface detected the nmap scan while it was happening, and the dashboard showed it.
- An alert line added to a test Suricata log was merged into the same incident.
- API calls without the token were refused (HTTP 401).
- The kernel dropped no packets.
- Ctrl-C stopped the program cleanly (exit code 0), even on a quiet network.

### 6.4 Visual checks

Screenshots of every page in light and dark, in English, French and Arabic, on a desktop screen and a 390-pixel-wide phone screen (no sideways scrolling), with no errors in the browser console.

### 6.5 Problems found during the work, and how they were fixed

| Problem | Cause | Fix |
|---|---|---|
| On a quiet network, Flagman could not be stopped | On Linux, libpcap’s timeout never fires while no packet arrives | Non-blocking capture, with Flagman waiting itself through `poll()`, 250 ms at a time (ADR 0003) |
| During a live scan, the dashboard’s port count stopped growing before the scan ended | The last part of a growing alert was only published when the alert closed, 120 s later | The regular timer now publishes the latest count as soon as an alert stops growing (with a test) |
| Right after a scan, the overview showed 0 packets | Traffic counts were only saved at the end of each minute | Partial counts are now saved every 5 seconds |
| `npm install` crashed | An npm bug in peer-dependency resolution | `product/ui/.npmrc` sets `legacy-peer-deps`, with a comment saying why |
| In Arabic, addresses, “#1” and commands came out in the wrong order, and arrows pointed the wrong way | Right-to-left text reorders neutral characters | Values are wrapped in invisible Unicode isolation marks, arrows flip, port labels stay left-to-right |
| The chart axis said “0 byte”; Arabic axis labels were cut off | Unit formatting at zero; a fixed left margin | “0” at the bottom of the axis; the margin now fits the longest label |
| The incident page listed up to 500 connections at once | A scan makes hundreds of connections | The first 25, with a “Show all” button |

### 6.6 What the tests do not cover yet

A real home network, Wi-Fi, runs of several days, heavy traffic, and Suricata on a real installation. The home test covers the first one.

## 7. How to run it

### 7.1 Try it without a network (replay)

```text
sudo apt install build-essential libpcap-dev nodejs npm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cd product/ui && npm ci && npm run build && cd ..
cd core
cargo run --release -p flagmand -- replay testdata/pcap/lab-attack-chain.pcap \
    --overwrite --serve --ui-dir ../ui/dist
```

Then open the link it prints (`http://127.0.0.1:8751/#token=…`) in a browser on the same machine. Ctrl-C stops it.

### 7.2 Install it on the Linux PC

```text
cd product/deploy/linux
sudo ./install.sh
systemctl status flagman      # should say "active (running)"
sudo flagmand token           # prints the dashboard link
```

Open the link on the same PC. To view the dashboard from a laptop, use an SSH tunnel: `ssh -L 8750:127.0.0.1:8750 you@the-pc`, then open the same link on the laptop. If Flagman watches the wrong interface, `flagmand interfaces` lists them, and `interface = "…"` under `[capture]` in `/etc/flagman/flagman.toml` sets it.

### 7.3 The home test, in short

The full guide is `product/docs/home-test.md`. You need the Linux PC (the sensor) and a second computer with nmap (the tester). Only test devices you own, on your own network.

| Step | Where | What to do | What should appear |
|---|---|---|---|
| 1 | Linux PC | Open the dashboard | “Watching <your interface>”, packets counting up, “None dropped” |
| 2 | Anywhere | 10 minutes of normal use | No incident |
| 3 | Tester | `sudo nmap -sn 192.168.1.0/24` (your network) | Network sweep, close to 255 addresses for a /24 |
| 4 | Tester | `sudo nmap <PC address>` | Port scan, about 1,000 TCP ports |
| 5 | Tester | 15 ssh attempts (the command is in the guide; no password is ever sent) | Login attempts on port 22; the incident becomes critical |
| 6 | Linux PC | Open the incident, check it reads clearly, mark it Resolved | – |
| 7<br>(optional) | Linux PC | Install Suricata, then `curl http://testmynids.org/uid/index.html` | A Suricata rule alert |

**Important:** Flagman on one PC sees the traffic to and from that PC, and the broadcasts of every device. It does not see your laptop scanning your phone. That is why every test targets the PC, and why the router version comes next.

**Why sudo for the sweep:** the nmap manual says that when a privileged user scans a local Ethernet network, nmap uses ARP requests, which every device receives; without privileges it only tries to connect to ports 80 and 443 of each address ([nmap host discovery](https://nmap.org/book/man-host-discovery.html)). The Suricata steps come from the [Suricata quickstart guide](https://docs.suricata.io/en/latest/quickstart.html).

## 8. What is not done yet, and what comes next

#### Not done yet

- The home network test, and checks on Wi-Fi, long runs and heavy traffic.
- HTTPS and user accounts for the dashboard.
- Detection of slow scans (spread over more than 60 seconds) and of ARP spoofing.
- Edge (the router version) and Windows.

#### Next steps

1. Your review of the pull request, and the home test.
2. Adjust thresholds and wording from the home test results.
3. Edge: build Flagman for the OpenWrt One when it arrives, and measure its memory and processor use there.
4. Later: a machine-learning detector trained on our own labelled recordings. Windows only if Linux results are excellent.

## 9. Where to read more

| Document | Path | Read it when |
|---|---|---|
| Product overview | `product/README.md` | First |
| Reading order | `product/docs/reading-order.md` | Before reviewing the code |
| Architecture | `product/docs/architecture.md` | To see how the parts fit |
| Glossary | `product/docs/glossary.md` | When a word is unclear |
| Home test | `product/docs/home-test.md` | Before testing at home |
| Threat model | `product/docs/threat-model.md` | For security questions |
| Decision records | `product/docs/adr/` | When you wonder why |
| Phase summary | `product/docs/changes/phase-1-linux-pro.md` | For the checks, in short |
| AI-use log | `product/docs/ai-log.md` | For the AI declaration |
| Installation | `product/deploy/linux/README.md` | Before installing |
| Lab recordings | `product/core/testdata/pcap/README.md` | To recount the test numbers |

## 10. Use of AI, and what you can say about it

The code, tests and documents in this push were written by Claude Code, an AI coding assistant made by Anthropic, at your request. You set the goals and made the product decisions: Linux first, a test on a home network, a dashboard in the spirit of Suricata’s, Edge on the OpenWrt One, and Windows only after excellent Linux results. As your brief requires, this is declared in `product/docs/ai-log.md`.

#### What you can say with confidence

- Flagman is defensive: it watches and explains, and never blocks or attacks.
- Attack traffic was only produced inside an isolated virtual lab with no route to any real network, and it only targeted the lab’s own virtual victim.
- The CS395 research files and results were not changed, and nothing in this push feeds the CS395 paper.
- Every number in the documents comes from the code’s settings, the test files, or a command whose output is recorded (section 6). Outside facts link to their official source.
- The work was checked with automatic tests, real recorded attack traffic and screenshots, and GitHub re-runs the checks on every change.

#### What still needs a person

- A human review of the code. The pull request is the place for it, and section 9 gives a reading order.
- The home network test.
- If you show this work in a course or in public, point to `product/docs/ai-log.md` so the use of AI is clear.

## 11. Glossary

| Word | Meaning |
|---|---|
| Packet | One unit of data on the network: a header (addresses, ports, flags), then the contents. |
| Port | A number that says which program on a machine a connection is for: 22 for SSH, 443 for secure web. |
| TCP SYN | The first message of a TCP connection (“may I connect?”). Scanners send many of them. |
| ARP | How a device finds who owns an IP address on the local network, by asking everyone (a broadcast). |
| Flow | One conversation between two addresses and ports, with its packet and byte counts. |
| Network sweep | Probing many addresses to find which devices are up (`nmap -sn`). |
| Port scan | Trying many ports of one machine to see which services answer. |
| Login attempts | Many new connections to a login service, as password-guessing tools make. |
| Alert | One suspicious behaviour, with its evidence. |
| Incident | The alerts from one source device, grouped while the gaps stay under 30 minutes. |
| Severity | Low, medium, high or critical; always shown with a shape and a word, not colour alone. |
| MITRE ATT&CK | A public catalogue of attacker behaviour: tactics (goals) and techniques (ways to reach them). |
| Suricata | A free, open-source IDS with a large rule set; Flagman reads its alerts. |
| pcap / replay | A file of recorded packets; `flagmand replay` analyses one as if it were live. |
| Token | The long random secret in the dashboard link; without it the API refuses to answer. |
| Capability | One single root power given to a program; Flagman needs only two, to capture packets. |
| IDS | Intrusion detection system: it watches and warns, and does not block. |

The full glossary is `product/docs/glossary.md`.

## Appendix: commands to check everything yourself

```text
# 1. Only product/ and .github changed
git diff --stat main..claude/project-thread-k6g47y | tail -1

# 2. Sensor: tests, lints, formatting
cd product/core
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# 3. Dashboard: install, type checks, tests, build
cd ../ui
npm ci && npm run check && npm test && npm run build

# 4. Replay the attack, then the normal traffic
cd ../core
cargo run --release -p flagmand -- \
    replay testdata/pcap/lab-attack-chain.pcap --overwrite
cargo run --release -p flagmand -- \
    replay testdata/pcap/lab-normal-traffic.pcap --db normal.db --overwrite

# 5. The service hardening score
systemd-analyze security --offline=true \
    ../deploy/linux/flagman.service | tail -1
```
