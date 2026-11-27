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
