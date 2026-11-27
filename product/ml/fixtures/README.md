# Test files of the ML pipeline

Small files that the Python tests read. They are real: made from the lab
captures, not written by hand.

| File | What it is |
|---|---|
| `lab-attack-chain.parquet` | features of the 1,015 flows of `lab-attack-chain.pcap`: 1,000 scanned ports and 15 quick SSH connections |
| `lab-normal-traffic.parquet` | features of the 42 flows of `lab-normal-traffic.pcap`: 40 page loads, one UDP flow, one ping flow |
| `lab-ssh-logins.parquet` | features of the 24 SSH connections of `lab-ssh-logins.pcap` |
| `lab-ground-truth.csv` | what each step of the lab recordings was: the lab's ground truth |
| `make-fixtures.sh` | rebuilds the three feature files with `flagmand extract` |
| `suricata/` | Suricata's alerts on the three lab captures, recorded (see below) |

The captures and what happens in them are described in
[product/core/testdata/pcap/README.md](../../core/testdata/pcap/README.md).

## The feature files

`make-fixtures.sh` runs `flagmand extract` (built with `--features parquet`)
on each capture. The same capture always gives the same bytes, so CI
extracts the captures again and compares: the step "The ML test files match
a fresh extraction of the lab captures" fails when a change to the flow
table, the features or the Parquet writer changed the files. Run the script
and commit the new files when that change is intended.

## The lab ground truth

One row per step of the recording scripts (`record-lab-captures.sh` and
`record-ssh-capture.sh`), in the `lab_csv` format:

| Column | Meaning |
|---|---|
| `start_utc`, `end_utc` | the step's first and last moment, UTC, to the millisecond |
| `protocol` | `tcp` here; empty would mean any |
| `src_ip`, `src_port` | the side that started the connections (the attacker); an empty port means any |
| `dst_ip`, `dst_port` | the victim; the scan step leaves the port empty (it tried 1,000 ports) |
| `label` | the lab's own name for the step; `data/labels/lab.toml` maps it to a class |
| `note` | which capture and step, in words |

The scripts did not log their times, so the windows were read from the
captures themselves: the first packet of the step's first flow and the last
packet of its last flow. The steps of the SSH capture are only 7 to 9 ms
apart, so the windows leave no room for a tolerance (see `lab.toml`).

Labels follow what each step does, not which machine ran it:

| Step | Label | Class |
|---|---|---|
| attack chain 2: nmap scan of 1,000 ports (its SYN to port 22 included) | `port_scan` | scan |
| attack chain 3: 15 quick SSH connections | `ssh_password_guessing` | brute_force |
| SSH 1 and 2: wrong passwords (10 and 3 connections) | `ssh_password_guessing` | brute_force |
| SSH 3 and 4: logins with a key (1 and 5 connections) | `ssh_key_login` | normal |
| SSH 5: 5 connections refused, the server was stopped | `ssh_refused` | normal |

Step 1 of the attack chain (the ARP host discovery) has no row: ARP is not
an IP flow, so the flow table never sees it. The normal-traffic capture has
no attack, so its flows get the mapping's default label, normal.

Labelling the three files gives 1,000 scan, 28 brute_force and 53 normal
flows, with no conflict (`flagman_ml/labels/cli_test.py` checks these
numbers).

## The Suricata files

`suricata/<capture>/eve.json.gz` is the `eve.json` that Suricata 7.0.3
wrote for each lab capture, unchanged, compressed with `gzip -9 -n`;
`run.json` next to it records the version, the command and the checksums
(capture, rules, configuration). They were **recorded** on 2026-11-27 by
`suricata/make-suricata-fixtures.sh`, not written by hand.

The rules are the two of `suricata/local.rules`, written for this check:
many connection requests from one host in 10 seconds, and many SSH
connection requests in 60 seconds. They are **not ET Open**: the ET Open
rules server was out of reach of the session that recorded the files. The
alerts check the code (reading, matching, scoring); they say nothing about
how well Suricata detects with ET Open.

Matched to the lab flows (`flagman_ml/suricata/cli_test.py`): every one of
the 1,035 alerts lands on a flow. The rules raise alerts on 15 of 15
password-guessing flows and 980 of 1,000 scan flows of the attack chain,
but also on 20 of the 42 normal flows of `lab-normal-traffic` (its 40 web
page loads in 10 seconds are many connection requests from one host) and
2 of the 11 normal flows of `lab-ssh-logins`.

Run `suricata/make-suricata-fixtures.sh` again (with Suricata installed)
when the captures or the rules change. CI does not run Suricata: the
tests read these files.
