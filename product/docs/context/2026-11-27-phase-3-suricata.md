> Markdown copy of [`2026-11-27-phase-3-suricata.docx`](2026-11-27-phase-3-suricata.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: Suricata comparison

*Context document for draft pull request 6 of the phase 3 toolkit, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/06-suricata`, built on `phase-3/05-evaluation` (pull request #7). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (item C6) and in the answer about the EVE file |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-suricata.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. Why compare with Suricata, and what makes it fair
3. Running Suricata
4. Reading the EVE file
5. How an alert finds its flow
6. Suricata in the evaluation and the report
7. Where the test EVE files come from
8. The lab pipeline check
9. How it was checked
10. Known limits
11. What comes next
12. Use of AI

## 1. The short version

- This pull request adds `python -m flagman_ml.suricata run`, which runs `suricata -r` on a capture and records Suricata’s version and the checksums of the capture, the rules and the configuration in `run.json`.
- It also adds `python -m flagman_ml.suricata match`, which gives each alert of Suricata’s EVE file to the Flagman flow that holds its packet, and counts the alerts that match no flow.
- A plan’s dataset can list these Suricata files. The evaluation then scores Suricata as a fourth way of deciding, on the same test flows as Flagman, and the report shows where Suricata’s alerts come from.
- The test files were **recorded**, not hand-written: Suricata 7.0.3 on the three lab captures, with two local rules. The ET Open rules server was refused by this session’s network. All 1,035 recorded alerts land on a lab flow.
- 29 new Python tests (205 in all, about 10 seconds). CI does not need Suricata. Everything here is a **pipeline check, not a result**.

## 2. Why compare with Suricata, and what makes it fair

The prompt asks for “a script that runs `suricata -r` with ET Open on the same PCAPs and maps its alerts to our flows, so both are scored the same way”. Suricata is a free IDS built on rules (signatures); ET Open is a free rule set for it. The comparison shows what Flagman’s models add to a rule-based tool, or do not add.

What keeps it fair:

1. **The same captures.** Suricata reads the capture Flagman extracted. `match` refuses an EVE file whose `run.json` names another capture.
2. **The same unit.** Flagman decides once per flow. A flow holding at least one Suricata alert counts as “Suricata raised an alert”, and a flow with ten alerts counts once.
3. **The same flows.** Background, unlabelled and conflicting flows are left out for both, as before.
4. **The same metrics.** False alarms with exact intervals, detection, each attack class, precision at the base rates, alerts per day, and a McNemar test on the same flows.

One metric does not apply: Suricata has no score to move, so it has no “detection at a false-alarm rate”. It is one point, where its rules put it.

## 3. Running Suricata

```text
python -m flagman_ml.suricata run --capture captures/day4.pcap \
    --rules /var/lib/suricata/rules/suricata.rules \
    --home-net "[192.168.0.0/16]" --out results/suricata/day4
```

It runs `suricata -c /etc/suricata/suricata.yaml -r <capture> -S <rules> -l <out> -k none --runmode single`. Each option, in the words of Suricata’s command line documentation and of `suricata --list-runmodes`:

| Option | What it does |
|---|---|
| `-r` | “Run in pcap offline mode (replay mode) reading files from pcap file” |
| `-S` | “a file with signatures, which will be loaded exclusively, regardless of the rules set in the yaml” |
| `-l` | “the default log directory”: where `eve.json` is written |
| `-k none` | “disable (none) all checksum checks”. Flagman’s decoder does not check checksums either, so both read the same packets |
| `--runmode single` | “Single threaded pcap file mode” |
| `--home-net` | sets `HOME_NET` with `--set vars.address-groups.HOME_NET=...`. Many rules only look at traffic towards it, so it must name the dataset’s internal networks |

- `run.json` records Suricata’s version (`suricata -V`), the command, and the SHA-256 of the capture, the rules and the configuration. A result therefore names the exact rules it was compared with.
- ET Open: the Suricata-Update documentation says “To download the Emerging Threats Open ruleset, it is enough to simply run: `sudo suricata-update`”, and that it merges all rules into `/var/lib/suricata/rules/suricata.rules`.
- In this session, installing Ubuntu 24.04.5’s package (`apt-get install suricata`) gave Suricata 7.0.3 (package version `1:7.0.3-1build3`).

## 4. Reading the EVE file

- Suricata writes “EVE JSON”: one JSON object per line, each with an `event_type`. Only the `alert` lines are read.
- From each alert: the time (`timestamp`, with its time zone offset, turned into microseconds since 1970 in UTC), the two ends (`src_ip`, `src_port`, `dest_ip`, `dest_port`), the protocol (`proto`, turned into Flagman’s names: tcp, udp, icmp, other) and the rule (`alert.signature_id`).
- An alert without ports (ICMP, for example) is matched on its addresses and protocol only.
- An EVE file is data from outside the program. A line that is not JSON, or an alert line without these fields, stops the reading and names the line. Files ending in `.gz` are read through gzip.

## 5. How an alert finds its flow

Suricata raises an alert on one packet, and the alert’s time is that packet’s time. Flagman cuts packet times to whole milliseconds, and a flow’s start and end are the times of its first and last packets. So an alert belongs to the flow with:

1. the same protocol and the same two ends, in either direction (the ports too, when the alert gives them);
2. a start and an end that hold the alert’s time, cut to the millisecond (each side widened by a tolerance, 0 by default).

This is the labelling rule that already joins flows to dataset ground truth, with each alert as a record that lasts no time. If two flows qualify, the one that holds the time wins, then the nearer one, then the first.

A worked example from the tests. Flow 0 goes from 10.0.0.1 port 40000 to 10.0.0.2 port 22, from 1,000 to 2,000 ms; flow 1 has the same ends, from 5,000 to 6,000 ms.

- An alert at 1,500.123 ms, written from the answering side, goes to flow 0.
- An alert at 5,000.999 ms goes to flow 1.
- An alert at 2,000.999 ms is cut to 2,000 ms and goes to flow 0.
- An alert at 3,000 ms goes to no flow (unmatched). With a tolerance of 1,000 ms it goes to flow 0, the nearer one.

Suricata’s own `flow_id` is not used: two runs on the same capture gave the same alerts, in the same order, with other `flow_id` values. **Unmatched alerts are counted, never dropped**: the Suricata file and the report give their number.

## 6. Suricata in the evaluation and the report

- A plan’s dataset may list Suricata files: `suricata = ["results/suricata/day4.parquet"]`. A fold must have one for every test file, or none; a fold with only some is refused with a clear message.
- Each run then adds `suricata` to its ways of deciding: false alarms and detection with exact intervals, and a McNemar test against Flagman’s two scores on the same flows. It also adds Suricata’s precision at the base rates, the share of each attack class it raised an alert on, and its alerts per day.
- The run file records each Suricata file used: its checksum, the EVE file’s checksum, `run.json` (or the `--origin` text) and the counts, unmatched alerts included.
- The summary adds the Suricata metrics, Wilcoxon tests of the two scores against Suricata, and for each attack class the mean share that raised an alert with Flagman and with Suricata.
- The report adds a “Detection by attack class” table and a “Suricata: where its alerts come from” table (version, rules and their checksum, alerts, unmatched alerts, flows alerted).

The evaluation test runs this on the made-up days, with made-up alerts on day 3: every dos flow, every other scan flow, no brute force, and one normal flow in 30. Suricata’s false alarms come out as 10 of 300 normal flows, its detection as 50 of 110 attack flows, and its per-class shares as 1 (dos), 0.5 (scan) and 0 (brute force), as made.

## 7. Where the test EVE files come from

Seraj’s instruction: “Say where the EVE file comes from. If you can’t record one, write it by hand following the official EVE format, and label it “hand-written” in the test and the README.”

- **Recorded, not hand-written.** Suricata 7.0.3 ran on the three lab captures through this pull request’s own `run` command (`fixtures/suricata/make-suricata-fixtures.sh`). Each `eve.json` is kept unchanged, compressed with `gzip -9 -n`, with its `run.json` next to it.
- **The rules are two local rules** (`fixtures/suricata/local.rules`), written for this check: every TCP connection request after the 20th that one host sends within 10 seconds, and every SSH connection request after the 5th within 60 seconds. Suricata’s documentation says `detection_filter` alerts “on every match after an initial threshold has been reached”.
- **Not ET Open**: this session’s network proxy refused rules.emergingthreats.net (“no rule or network setting allows this host”, checked on 27 November 2026). These alerts check the code; they say nothing about Suricata’s quality with ET Open.
- A test fails if `local.rules` or a capture changes without recording again: it compares the checksums in each `run.json` with the committed files.
- **Hand-written lines** exist only in `eve_test.py`, for cases the recordings lack: another event type, ICMP without ports, IPv6 ICMP, another protocol, and broken lines. They are marked “hand-written” in the test and in the Suricata README, and follow the format of the recorded files.
- The official “Eve JSON Format” page could not be read by this session’s web reader (the site’s robots.txt refused it), so the field names come from the files Suricata itself wrote.

## 8. The lab pipeline check

The recorded alerts, matched to the lab flows (`suricata/cli_test.py`). The alerts per capture are 1,006 (attack chain), 20 (normal traffic) and 9 (SSH logins), and none is unmatched.

| Capture | Class | Flows | Flows with a Suricata alert |
|---|---|---|---|
| lab-attack-chain | brute force | 15 | 15 |
| lab-attack-chain | scan | 1,000 | 980 |
| lab-normal-traffic | normal | 42 | 20 |
| lab-ssh-logins | brute force | 13 | 7 |
| lab-ssh-logins | normal | 11 | 2 |

How to read it: the first rule counts connection requests, so the 40 web page loads of the normal capture, made within 10 seconds, look like a scan to it. Twenty of the 1,000 scan flows raise nothing because the rule only alerts after its 20th match. This is what two simple rules do on three tiny captures. It is a check of the code, not a measure of Suricata or of Flagman.

## 9. How it was checked

- 29 new tests. They cover the recorded files’ checksums, reading EVE lines (four kinds of broken lines), matching on hand-checked flows, counts per flow, and the runner with a stand-in program (the documented command, `run.json`, failures).
- They also cover the commands on the recorded lab files (every alert matched, flows alerted per class, refusals) and Suricata scored in a whole plan on made-up days.
- The tests do not need Suricata: the `run` tests use a small stand-in program, and the rest reads the recorded files. 205 tests pass in about 10 seconds; warnings count as failures.
- The linter passes on the new and changed files. The new Python files are at most 129 lines, and the new folder has a README.

## 10. Known limits

- Suricata ran only on the three lab captures, with two local rules. ET Open was never run here.
- A flow counts yes or no. Rules with thresholds alert on some flows of an attack and not others, so a rule that alerts once per attack scores a low detection even when it found the attack.
- Suricata’s alerts are not named with Flagman’s classes, and it has no detection at a false-alarm rate.
- `--home-net` must name each dataset’s internal networks, or rules that look at traffic towards `$HOME_NET` stay silent.
- Matching assumes the alert’s time is the time of a packet of the flow, as it was for every lab alert.

## 11. What comes next

- Pull request 7 (`phase-3/07-export-runbook`): the model export (LightGBM text, ONNX if it works), the runtime ADR draft with small measurements, and the runbook.
- When the data is downloaded, the team runs Suricata with ET Open on the test captures (`sudo suricata-update`, then `run` and `match`) and lists the Suricata files in the plans.
- The full list is in `product/docs/changes/phase-3-toolkit.md`.

## 12. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request, and recorded the Suricata test files in its cloud session. Every number here comes from a test or a recorded file. The team reviews and merges; the AI never merges.
