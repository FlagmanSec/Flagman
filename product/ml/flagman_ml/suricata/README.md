# suricata: the same captures, scored the same way

Flagman is compared with [Suricata](https://suricata.io), a free
rule-based IDS, on the **same captures**. Suricata's alerts are matched to
Flagman's flows, and a flow holding at least one alert counts as "Suricata
raised an alert": the same yes or no as Flagman's decision. The evaluation
then scores both on the same flows (false alarms, detection, each attack
class, precision at a base rate, alerts per day, and a McNemar test).

## Steps

From `product/ml`, for each test capture:

```bash
# 1. Flagman's flows (already done for the evaluation)
flagmand extract captures/day4.pcap --out flows/day4.parquet
# 2. Suricata on the same capture
python -m flagman_ml.suricata run --capture captures/day4.pcap \
    --rules /var/lib/suricata/rules/suricata.rules \
    --home-net "[192.168.0.0/16]" --out results/suricata/day4
# 3. Its alerts, matched to Flagman's flows
python -m flagman_ml.suricata match --eve results/suricata/day4/eve.json \
    --out results/suricata/day4.parquet flows/day4.parquet
```

Then list the Suricata files in the plan's dataset
(`suricata = ["results/suricata/day4.parquet"]`, see `plans/README.md`).

- **Suricata** comes from the distribution: installing Ubuntu 24.04.5's
  package (`sudo apt-get install suricata`) gave Suricata 7.0.3 (package
  version `1:7.0.3-1build3`). `run` records the version it ran.
- **ET Open rules**: Suricata-Update downloads them. Its documentation
  says: "To download the Emerging Threats Open ruleset, it is enough to
  simply run: `sudo suricata-update`", and "By default suricata-update
  will merge all rules into a single file
  `/var/lib/suricata/rules/suricata.rules`"
  ([Suricata-Update](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)).
  `run` records the checksum of the rules file, so a result names the
  exact rules it was compared with. Download them once for a whole
  campaign, so that every capture is read with the same rules.
- **`--home-net`**: many rules only look at traffic towards `$HOME_NET`.
  Set it to the networks that the dataset calls internal (each dataset's
  documentation), or a rule may never fire on that dataset.

## How an alert finds its flow

`match.py` explains it step by step: same protocol, same two ends in
either direction, and the alert's packet time (cut to the millisecond, as
Flagman cuts its times) inside the flow's first and last packet. Suricata's
`flow_id` is not used: two runs of the same capture gave the same alerts
with other `flow_id` values. **Unmatched alerts are counted, never
dropped**: the Suricata file's footer and the evaluation report give their
number. A flow with several alerts counts once, like a Flagman alert.

## Where the EVE files come from

`run` writes `run.json` next to `eve.json`: Suricata's version, the
command, and the checksums of the capture, the rules and the
configuration. `match` copies it into the Suricata file, and refuses an
EVE file that comes from another capture than the feature file. An EVE
file without `run.json` (written by hand, or by another tool) needs
`--origin "..."` to say where it comes from, in words; the report shows
it.

The test files in [`fixtures/suricata`](../../fixtures/suricata) were
**recorded**, not hand-written: Suricata 7.0.3 on the three lab captures,
with two local rules written for this check (`local.rules`). The ET Open
rules server was out of reach of the session that recorded them, so these
alerts say nothing about Suricata's quality with ET Open: they check the
code. Only `eve_test.py` adds a few **hand-written** lines, in the format
of the recorded files, for cases the recordings do not have (ICMP, other
protocols, broken lines); they are marked as such in the test.

## Files

| File | What it does |
|---|---|
| `eve.py` | reads the alert lines of an EVE file (`.gz` too), and refuses broken lines with their number |
| `match.py` | finds each alert's flow, and counts alerts per flow |
| `store.py` | writes and reads Suricata files, and joins them to flows (checksums checked) |
| `run.py` | runs `suricata -r` on a capture and writes `run.json` |
| `cli.py` | `python -m flagman_ml.suricata run` and `match` |

The tests run without Suricata: `run_test.py` and `cli_test.py` use a
stand-in program for the `run` command, and the recorded files for the
rest.
