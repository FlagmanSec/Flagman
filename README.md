# Flagman IDS

Flagman watches a home or small office network and tells you in plain words
when a device sweeps the network for machines, tries the ports of a machine,
or keeps trying to log in. It runs on your own machine: no cloud, no account,
no telemetry.

**Status: phase 1, Linux Pro.** This is early development, not a release.
Flagman runs on one Linux PC and watches that PC's network interface. It
detects with rules for now; machine learning comes in a later phase.

## What it detects

| Detection | Example that triggers it | Default rule |
|---|---|---|
| Network sweep | `sudo nmap -sn 192.168.1.0/24` | one device checks 15 or more local addresses within 60 s |
| Port scan | `nmap 192.168.1.10` | one device tries 20 or more TCP ports (or 30 UDP ports) of one machine within 60 s |
| Login attempts | a password-guessing tool against SSH | 10 or more connections to a login port of a device in your network within 60 s that were refused or closed within 30 s |
| Known attack patterns | anything Suricata's rules recognise | read from Suricata's `eve.json`, if Suricata is installed |

Alerts about the same device are grouped into one incident, shown in a
dashboard with an explanation and the evidence. The rules can be changed in
`/etc/flagman/flagman.toml`.

## Install on Ubuntu

These steps are for Ubuntu 24.04. Ubuntu 22.04 and Debian 12 should work the
same way. The first build takes a few minutes.

**1. Build tools**

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libpcap-dev git curl

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Node.js 22, for the dashboard
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node --version    # must be v20.19 or newer
```

Ubuntu's own `nodejs` package is too old for the dashboard (version 18 on
Ubuntu 24.04), hence the NodeSource repository above. If you already
installed Ubuntu's `nodejs` and `npm`, remove them first with
`sudo apt remove nodejs npm`.

**2. Get the code and install**

```bash
git clone https://github.com/FlagmanSec/Flagman.git
cd Flagman/product/deploy/linux
sudo ./install.sh
```

The script builds the sensor and the dashboard, creates a `flagman` system
user, and starts the `flagman` service. The service runs with only the two
network capabilities it needs.

**3. Open the dashboard**

The last lines printed are a link such as `http://127.0.0.1:8750/#token=…`.
Open it in a browser on the same PC. The link contains the access token, so
keep it private. `sudo flagmand token` prints it again.

The strip at the top should say **Watching** followed by your network
interface (for example `enp3s0` or `wlp2s0`), with **Packets seen** going up.
If it watches the wrong one (for example `docker0`), list them with
`flagmand interfaces`, set the right one in `/etc/flagman/flagman.toml`:

```toml
[capture]
interface = "wlp2s0"
```

then run `sudo systemctl restart flagman`.

## Check that it works

**Quick test, one PC.** Scan your own router from the PC running Flagman.
Flagman sees its own PC's traffic, so it reports the PC as the scanner:

```bash
sudo apt install -y nmap
ip route | grep default       # "default via 192.168.1.1": that is your router
sudo nmap 192.168.1.1         # replace with your router's address
```

Within about 10 seconds, the dashboard shows a new incident with a
**Port scan** alert of about 1,000 ports. Only scan networks you own.

**Full test.** [`product/docs/home-test.md`](product/docs/home-test.md)
uses a second computer to test the sweep, the port scan and login attempts
against the sensor, and adds Suricata.

**Without a network.** Flagman can replay a recorded attack (a real nmap
capture from an isolated lab) as if it were live. See
[`product/README.md`](product/README.md#try-it-in-five-minutes-without-a-network).

## Everyday commands

```bash
systemctl status flagman          # is it running?
journalctl -u flagman -f          # its log
sudo flagmand token               # print the dashboard link again
sudo systemctl restart flagman    # after editing /etc/flagman/flagman.toml
sudo ./install.sh --uninstall     # from product/deploy/linux
```

Uninstalling keeps your data (`/var/lib/flagman`) and settings
(`/etc/flagman`). Delete them by hand if you want them gone.

## Known limits of phase 1

- One PC sees only its own traffic, plus broadcasts from other devices. It
  does not see your laptop scanning your phone. The router version will.
- Slow scans, spread over more than a minute, are missed.
- No HTTPS yet: the dashboard listens on `127.0.0.1` only. From another
  device, use an SSH tunnel (see
  [`product/deploy/linux/README.md`](product/deploy/linux/README.md)).
- Linux only. It has not been tested over several days or on many home
  networks yet.

## What comes next

1. A week of testing on a real home network, then tuning the rules with the
   numbers we get.
2. Flagman Edge, running on a router (an OpenWrt One), which sees the
   traffic of every device. See
   [`product/docs/phase-2-plan.md`](product/docs/phase-2-plan.md).
3. Later: machine-learning detection with a controlled false-alarm rate,
   a Windows version, and a hub that collects several sensors.

## Repository

| Path | What it is |
|---|---|
| [`product/`](product/README.md) | Flagman: the sensor (Rust), the dashboard (Svelte), the installer and the docs |
| `src/`, `notebooks/`, `results/`, `requirements.txt` | The CS395 research project Flagman grew out of: a benchmark of intrusion detection models on UNSW-NB15. See [`RESEARCH.md`](RESEARCH.md). |

New to the code? Start with
[`product/docs/reading-order.md`](product/docs/reading-order.md).

## Ground rules

- **Defensive only.** Flagman watches and explains. It does not attack,
  block or change traffic.
- **Watch only networks you are allowed to watch**: your own, or one whose
  owner agreed.
- **Headers only.** Flagman keeps the first 160 bytes of each packet, enough
  for addresses and ports. It never stores packet contents.

## Team

Belhassen Draoui, Serajdin Gadmur, Imad Kouider.

The code was written with the help of Claude (Anthropic). The team reviews
it and is responsible for it. The details are in
[`product/docs/ai-log.md`](product/docs/ai-log.md).

No open-source licence has been chosen yet, so the code cannot be reused
until we add one.
