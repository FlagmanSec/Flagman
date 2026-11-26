# Lab capture files

Real traffic used by the replay tests (`crates/flagmand/src/replay/tests.rs`).
The files were recorded on 2026-11-26 by `record-lab-captures.sh` and
`record-ssh-capture.sh`, inside an isolated lab of two Linux network
namespaces joined by a virtual cable:

| Machine | Address | MAC |
|---|---|---|
| attacker | 192.168.77.66 | 02:00:00:77:00:66 |
| victim (where the sensor listens) | 192.168.77.10 | 02:00:00:77:00:10 |

No real network was involved. Tools: Nmap 7.94SVN, tcpdump 4.99.4,
Python 3.13, OpenSSH 9.6p1 (Ubuntu 24.04 package). Packets are cut to
160 bytes, like the live sensor does.

## lab-attack-chain.pcap

2,676 packets over 10 seconds. Three steps, from the attacker:

1. `nmap -sn -n 192.168.77.0/24`: host discovery. On a local network, nmap
   asks "who has this address?" (ARP) for every address but its own:
   256 − 1 = **255 addresses**.
2. `nmap -n 192.168.77.10`: nmap's default scan, a SYN scan of its
   **1,000 most common ports**.
3. A Python loop opens **15 connections** to the victim's SSH port (22), like a
   password-guessing tool, 0.3 s apart.

What Flagman must find, and does: one incident from 192.168.77.66, severity
critical, with three alerts:

| Alert | Count | Why that number |
|---|---|---|
| host sweep | 255 | step 1 |
| port scan of 192.168.77.10 | 1,000 | step 2 |
| login attempts on port 22 | 15 | the 15 connections of step 3, each closed within a second. The SYN that step 2 sent to port 22 does not count: the port answered and nmap reset the connection (half-open), so no login was tried |

You can check the counts with tcpdump:

```bash
tcpdump -nn -r lab-attack-chain.pcap arp | grep -o 'who-has [0-9.]*' | sort -u | wc -l   # 255
tcpdump -nn -r lab-attack-chain.pcap 'tcp dst port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' | wc -l   # 16 requests
tcpdump -nn -r lab-attack-chain.pcap 'tcp src port 22 and tcp[tcpflags] & tcp-fin != 0' | wc -l                  # 15 closed by the server
```

(Before the review of phase 1, every connection request counted, so this
number was 16.)

## lab-normal-traffic.pcap

500 packets over 10 seconds of ordinary use: 40 web page loads from the
victim's web server (port 8080), 5 small UDP packets to port 5353 (like mDNS),
and 5 pings. Flagman must raise **no incident**.

This only shows that the detectors stay quiet on a few seconds of simple
traffic. It does **not** prove that Flagman gives no false alarms: real
homes have printers, phones, smart TVs and routers that behave in many other
ways. The real false alarm rate will come from a week of the home test
([`docs/home-test.md`](../../../docs/home-test.md), step 9).

## lab-ssh-logins.pcap

649 packets over about 2 minutes, recorded by `record-ssh-capture.sh`: the
attacker logs in to a real OpenSSH server on the victim. The server uses
throwaway keys and settings in a temporary folder; the wrong passwords are
for `admin`, a user that does not exist. Five steps, one connection each
time:

| Step | Connections | Each lasted | Packets (to / from server) | Bytes (to / from server) | Counted as a login attempt? |
|---|---|---|---|---|---|
| 1. one wrong password | 10 | 3.1 s | 14 / 13 | 4,063 / 3,921 | yes: closed within 30 s |
| 2. wrong passwords until the server hangs up (six, OpenSSH's default `MaxAuthTries`) | 3 | 17.8 s | 19 / 23 | 5,133 / 4,865 | yes: closed within 30 s |
| 3. a key login kept open (`sleep 40`), like a working session | 1 | 40.3 s | 23 / 18 | 5,209 / 5,543 | **no**: open longer than 30 s |
| 4. a key login running one command (`true`), like git or Ansible | 5 | 0.24 s | 22 / 18 | 5,143 / 5,543 | yes (the known limit, below) |
| 5. the server is stopped: connection refused | 5 | 0 s | 1 / 1 | 74 / 54 | yes: refused |

What Flagman must find: one incident from 192.168.77.66, severity high, with
one **login attempts** alert counting **23** connections (10 + 3 + 5 + 5);
the 40-second session is the only one left out. The bytes include the
Ethernet, IP and TCP headers, as Flagman counts them.

**What this recording teaches.** Servers slow down wrong passwords on purpose
(here 3.1 s for one, 17.8 s for six), so a failed login is not shorter than a
successful one: a login that runs one command and leaves is the fastest of
all (0.24 s). That is why the rule is "refused, or closed within 30 s" and
not "closed within a second or two": a shorter limit would miss step 2,
which is how password-guessing tools usually work, and would still count
step 4.

**The known limit.** From packet headers alone, a quick successful login
(step 4) looks like a failed one, so ten git commands in a minute against an
SSH server **inside** your network would raise an alert. Servers on the
internet (GitHub, cloud machines) are not watched by default
(`local_targets_only`), which covers the common case. If it happens at home,
add the machine that runs the scripts to `ignore_sources`. The home test
will tell us whether this needs more work.

You can check the counts with tcpdump:

```bash
tcpdump -nn -r lab-ssh-logins.pcap 'tcp dst port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' | wc -l   # 24 connections
tcpdump -nn -r lab-ssh-logins.pcap 'tcp src port 22 and tcp[tcpflags] & tcp-rst != 0' | wc -l                    # 5 refused
```

## Recording them again

```bash
sudo ./record-lab-captures.sh /tmp/new-captures
sudo ./record-ssh-capture.sh /tmp/new-captures
```

The first needs root, iproute2, tcpdump, nmap, python3 and ping; the second
root, iproute2, tcpdump, openssh-server, openssh-client and sshpass. Timing
and the tools' choices can differ slightly between runs and versions, so new
files may need the expected numbers in the tests to be updated.
