# Testing Flagman on your home network

The goal: show that Flagman, running on one Linux PC, raises an incident
when you scan that PC or try to log in to it from another device, and stays
quiet during normal use. The results decide whether Linux is good enough to
move on to the router (Edge) and, later, Windows.

**Only test devices you own, on your own network.**

## What you need

| Machine | Role | Needs |
|---|---|---|
| **Sensor** | the Linux PC running Flagman | installed with [`deploy/linux/README.md`](../deploy/linux/README.md) |
| **Tester** | another computer on the same network | `nmap` (Linux: `sudo apt install nmap`; macOS: `brew install nmap`; Windows: the installer from [nmap.org](https://nmap.org/download.html)) and an `ssh` command (built into Linux, macOS and Windows 10 or newer) |

Write down two things about the sensor, from `ip -brief address`:

- its **interface** name, for example `enp3s0` (cable) or `wlp2s0` (Wi-Fi);
- its **IP address**, for example `192.168.1.20`, and the network, for
  example `192.168.1.0/24`.

In the commands below, replace `SENSOR_IP` and `192.168.1.0/24` with yours.

## Read this first: what one PC can see

The switch inside your router sends each packet only to the device it is
for. So Flagman on one PC sees:

- everything sent to or from that PC;
- broadcasts from every device, such as ARP's "who has 192.168.1.7?".

It does **not** see your laptop scanning your phone, apart from the ARP
part. That is why every test below targets the sensor itself, and why the
router version comes next: the router sees far more of the traffic.

## Step 1: check that Flagman is watching the right interface

```bash
systemctl status flagman        # should say "active (running)"
sudo flagmand token             # prints the dashboard link: open it
```

The strip at the top of the dashboard should say **Watching enp3s0** (your
interface), with **Packets seen** going up and **None dropped**.

If it watches the wrong interface (for example `docker0`), set it in
`/etc/flagman/flagman.toml`:

```toml
[capture]
interface = "enp3s0"
```

then `sudo systemctl restart flagman`.

## Step 2: a quiet baseline (10 minutes)

Use the network as usual: browse, stream a video, let phones sync. Then look
at **Incidents**.

**Expected: no incident.** If one appears, it is very useful: open it, take
a screenshot, and mark it **False positive**. Some routers and phone apps
scan the network to draw a map of devices; if that is the cause, you can add
that device's address to `ignore_sources` in `flagman.toml`.

## Step 3: network sweep

On the tester:

```bash
sudo nmap -sn 192.168.1.0/24
```

`sudo` matters. The nmap manual says that "when a privileged user tries to
scan targets on a local ethernet network, ARP requests are used", while an
unprivileged user only sends connection attempts to ports 80 and 443 of
each address
([nmap host discovery](https://nmap.org/book/man-host-discovery.html)).
ARP requests are broadcasts, so the sensor sees all of them.

**Expected:** a new incident from the tester's address, with a **Network
sweep** alert (the dashboard refreshes every 10 seconds). For a `/24` network, nmap asks for every address but its own, so the
count should be close to 255.

## Step 4: port scan

On the tester:

```bash
sudo nmap SENSOR_IP
```

**Expected:** a **Port scan** alert in the same incident: TCP, about 1,000
ports (nmap's default list). It also works without `sudo`: nmap then makes
full connections instead of half-open ones, and Flagman counts those too.

Optional, UDP:

```bash
sudo nmap -sU --top-ports 50 SENSOR_IP
```

**Expected:** a second **Port scan** alert, this time UDP (the rule needs 30
different UDP ports in 60 s).

## Step 5: login attempts

On the tester, open 15 SSH connections in a row. Each one gives up at once:
`BatchMode=yes` means ssh never asks for a password, so no password is ever
sent. It works whether or not the sensor runs an SSH server.

Linux or macOS:

```bash
for i in $(seq 15); do ssh -o BatchMode=yes -o ConnectTimeout=3 nobody@SENSOR_IP true; done
```

Windows (PowerShell):

```powershell
1..15 | ForEach-Object { ssh -o BatchMode=yes -o ConnectTimeout=3 nobody@SENSOR_IP true }
```

**Expected:** a **Login attempts** alert on port 22 (SSH) with about 15
connections. If steps 3 to 5 happened within 30 minutes, they are one
incident. That incident now covers two attack stages (Discovery, then
Credential Access), so it is raised to **critical**.

## Step 6: read the incident

Open the incident and check that the page makes sense to someone who is not
an expert: **What happened**, **Why it matters**, **What to check**, the
evidence, and the connections. Then mark it **Resolved** (it was you).

Also check the top strip: during the scans, **Dropped by the kernel** should
still say **None dropped**. If not, note the number.

## Step 7 (optional): add Suricata

Suricata adds a large set of rules for known attacks (the free ET Open
rules, by default). Flagman reads its alerts and merges them into the same
incidents. These commands come from
the [Suricata quickstart guide](https://docs.suricata.io/en/latest/quickstart.html):

```bash
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

In `/etc/suricata/suricata.yaml`:

- set `HOME_NET` to your network, for example `"[192.168.1.0/24]"`;
- under `af-packet:`, set `- interface:` to the sensor's interface.

Suricata and Flagman can watch the same interface: each gets its own copy
of every packet. Then download the rules and restart:

```bash
sudo suricata-update            # installs the rules in /var/lib/suricata/rules
sudo systemctl restart suricata
```

Test it with the request from the quickstart guide, on the sensor:

```bash
curl http://testmynids.org/uid/index.html
```

Suricata recognises the answer (rule 2100498, "GPL ATTACK_RESPONSE id check
returned root"). **Expected in Flagman:** an incident from the address of
testmynids.org with a **Suricata rule** alert, and the top strip saying
**Suricata: reading alerts**. Flagman only reads alerts written after it
started, so run the test after Flagman is up.

If the strip says **permission denied**, the `flagman` user cannot read
`/var/log/suricata/eve.json`. Look at its owner and group with
`ls -l /var/log/suricata/eve.json`. If the group can read it (`r` in the
fifth position, as in `-rw-r-----`), add Flagman to that group and restart:
`sudo usermod -aG <group> flagman && sudo systemctl restart flagman`. We have
not tested this on your distribution yet; tell us what `ls -l` shows if it
does not work.

## Step 8 (optional): keep a recording

A recording lets us replay your test later, exactly, with
`flagmand replay`. On the sensor, before step 3:

```bash
sudo tcpdump -i enp3s0 -s 160 -w ~/flagman-home-test.pcap
```

and Ctrl-C after step 5. Like Flagman, this keeps only packet headers, but
the file still lists your devices' addresses: share it only within the team,
never in the public repository.

## Write down the results

Copy this table into your notes or the team chat:

| Test | Expected | Seen? | Time to appear | Notes |
|---|---|---|---|---|
| Baseline, 10 min | no incident | | – | |
| Network sweep (`sudo nmap -sn`) | Network sweep, about 255 addresses | | | |
| Port scan (`sudo nmap SENSOR_IP`) | Port scan, TCP, about 1,000 ports | | | |
| UDP scan (optional) | Port scan, UDP | | | |
| Login attempts (ssh loop) | Login attempts, port 22, about 15 | | | |
| Incident severity after steps 3 to 5 | critical | | – | |
| Suricata test (optional) | Suricata rule alert | | | |
| Dropped by the kernel | None dropped | | – | |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| The dashboard says "The sensor does not answer" | The service stopped | `journalctl -u flagman -n 50` shows why |
| **Packets seen** stays at 0 | Wrong interface | Step 1 |
| No sweep alert | nmap ran without `sudo`, or the tester is on another network (guest Wi-Fi) | Step 3 with `sudo`, same network as the sensor |
| No alert at all, but packets are counted | The tester's address is in `ignore_sources` | Check `flagman.toml` |
| The dashboard asks for the token again | The browser keeps it for one tab only, unless you paste it and tick **Remember on this computer** | `sudo flagmand token` prints the link again |
