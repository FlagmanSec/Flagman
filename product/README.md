# Flagman IDS: Linux Pro

Flagman watches a home or small office network and tells you, in plain
words, when a device searches the network for machines, tries the doors
(ports) of a machine, or keeps trying to log in. It is the product that grew
out of the CS395 project in this repository. The research code at the top of
the repository is separate, and nothing in this folder changes it.

**Status: phase 1, Linux Pro.** Flagman runs on one Linux PC and watches that
PC's network interface. A router version (Edge, on an OpenWrt One) comes
next. A Windows version will be considered only after Linux gives good
results on a real home network.

## What it detects today

| Detection | Example that triggers it | Default rule (change it in `flagman.toml`) |
|---|---|---|
| Network sweep | `sudo nmap -sn 192.168.1.0/24` | one device checks 15 or more local addresses within 60 s |
| Port scan | `nmap 192.168.1.10` | one device tries 20 or more TCP ports (or 30 UDP ports) of one machine within 60 s |
| Login attempts | a password-guessing tool against SSH | 10 or more connections to a login port of a device in your network within 60 s that were refused or closed within 30 s (a session that stays open never counts) |
| Known attack patterns | anything Suricata's rules recognise | read from Suricata's `eve.json`, if Suricata is installed |

Alerts about the same device become one **incident** as long as the gaps
between them stay under 30 minutes. That device is the one behind the alerts
(the scanner, the password guesser), except for a Suricata alert on traffic
from the internet to one of your devices: that one is filed under your
device. An incident that goes through two attack stages (for example
discovery, then password guessing) is raised one severity level, because
that looks like an attack in progress. The thresholds are in
[`core/crates/flagman-core/src/detect/config.rs`](core/crates/flagman-core/src/detect/config.rs).

Memory is bounded. If a flood of fake addresses fills it, Flagman forgets the
least active entries to make room, so a real scanner is still seen, and the
dashboard shows **Detector saturated**.

## Try it in five minutes, without a network

The `replay` command analyses a recorded capture exactly as if it were live.
The repository includes a real nmap attack, recorded in an isolated lab
(see [`core/testdata/pcap/README.md`](core/testdata/pcap/README.md)).

```bash
# once: build tools, Rust and Node.js 20.19+ (see deploy/linux/README.md)
cd product/ui && npm ci && npm run build && cd ..          # the dashboard
cd core
cargo run --release -p flagmand -- replay testdata/pcap/lab-attack-chain.pcap \
    --overwrite --serve --ui-dir ../ui/dist
```

It prints what it found (this is real output):

```text
Replayed lab-attack-chain.pcap: 2676 packets (0 unreadable) in … s.
1 incident found:
  #1 critical, host 192.168.77.66, 2026-11-26 18:09:31 UTC to 2026-11-26 18:09:41 UTC
      login attempts on 192.168.77.10 port 22: 15 connections [high]
      port scan of 192.168.77.10: 1000 ports [medium]
      host sweep: 255 hosts [medium]
```

then a dashboard link such as `http://127.0.0.1:8751/#token=…`. Open it in a
browser on the same machine. Ctrl-C stops it.

## Install it and test it at home

1. [`deploy/linux/README.md`](deploy/linux/README.md): build and install
   Flagman as a service.
2. [`docs/home-test.md`](docs/home-test.md): check that it sees an nmap scan
   and login attempts on your home network, and add Suricata.

## Folder map

| Folder | What is inside |
|---|---|
| [`core/`](core/README.md) | The sensor, in Rust: capture, detection, storage, API, and the `flagmand` program |
| [`ui/`](ui/README.md) | The dashboard, in Svelte |
| [`deploy/`](deploy/README.md) | Installer, systemd service and default configuration |
| [`docs/`](docs/README.md) | How it works, why it is built this way, and how to test it |

New to the code? Start with [`docs/reading-order.md`](docs/reading-order.md).

## Ground rules

- **Defensive only.** Flagman watches and explains. It does not attack,
  block or change traffic. Blocking, if it comes later, will be opt-in.
- **Watch only networks you are allowed to watch**: your own, or one whose
  owner agreed.
- **Headers only.** Flagman keeps the first 160 bytes of each packet, enough
  for addresses and ports, and never stores packet contents.
- **Stays on the machine.** No cloud, no account, no telemetry. The dashboard
  listens on `127.0.0.1` and needs a token.

Changes are listed in [`CHANGELOG.md`](CHANGELOG.md). The use of AI tools is
declared in [`docs/ai-log.md`](docs/ai-log.md).
