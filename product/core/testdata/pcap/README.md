# Lab capture files

Real traffic used by the replay tests (`crates/flagmand/src/replay/tests.rs`).
Both files were recorded on 2026-11-26 by `record-lab-captures.sh`, inside an
isolated lab of two Linux network namespaces joined by a virtual cable:

| Machine | Address | MAC |
|---|---|---|
| attacker | 192.168.77.66 | 02:00:00:77:00:66 |
| victim (where the sensor listens) | 192.168.77.10 | 02:00:00:77:00:10 |

No real network was involved. Tools: Nmap 7.94SVN, tcpdump 4.99.4,
Python 3.13. Packets are cut to 160 bytes, like the live sensor does.

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
| login attempts on port 22 | 16 | the 15 connections of step 3, plus the SYN that step 2 sent to port 22 |

You can check the counts with tcpdump:

```bash
tcpdump -nn -r lab-attack-chain.pcap arp | grep -o 'who-has [0-9.]*' | sort -u | wc -l   # 255
tcpdump -nn -r lab-attack-chain.pcap 'tcp dst port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' | wc -l   # 16
```

## lab-normal-traffic.pcap

500 packets over 10 seconds of ordinary use: 40 web page loads from the
victim's web server (port 8080), 5 small UDP packets to port 5353 (like mDNS),
and 5 pings. Flagman must raise **no incident**.

## Recording them again

```bash
sudo ./record-lab-captures.sh /tmp/new-captures
```

Needs root, iproute2, tcpdump, nmap, python3 and ping. Timing and nmap's
choices can differ slightly between runs and versions, so new files may need
the expected numbers in the tests to be updated.
