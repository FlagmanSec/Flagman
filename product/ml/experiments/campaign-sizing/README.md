# Campaign sizing: time, disk and memory from small runs

The numbers behind the [runbook](../../docs/runbook.md): how fast
`flagmand extract` and Suricata read a capture, how big their files are,
and how much memory training takes.

**A pipeline check, not a result.** The capture is the three lab
recordings repeated 320 times (102 MB, 1,224,000 packets), and the training
flows are made up. Real captures and real flows will give other numbers.
Measure the first file of each step on the real data and plan from that.

## Files

| File | What it does |
|---|---|
| `repeat_pcap.py` | writes one long capture from the lab captures, each copy 600 s after the one before, so copies never join into one flow |
| `repeat_pcap_test.py` | an example: two copies make twice the packets, 600 s apart |
| `train_memory.py` | peak memory and time of training both models on N made-up flows (one process for each N) |
| `sizing.py` | runs all of it and writes `sizing.json` |
| `2026-11-27-sizing.json` | the measurements the runbook cites |

## Run it

From `product/ml`, with a `flagmand` built with `--features parquet`, and
Suricata installed if you want its part (otherwise it is left out):

```bash
python experiments/campaign-sizing/sizing.py results/sizing ../core/target/release/flagmand
```

It takes about 2 minutes and needs about 600 MB of disk for the long
capture and Suricata's logs. Delete `results/sizing` afterwards.

## What the file says (2026-11-27, 4 CPUs, shared cloud machine)

| Step | Measured |
|---|---|
| `flagmand extract`, 102,096,344-byte capture | 2.1 s (48.3 MB/s), 345,920 flows, at most 102.6 MB of memory |
| Suricata 7.0.3, the two local test rules, Ubuntu's default configuration | 8.4 s; `eve.json` 419,417,238 bytes (4.1 times the capture) and `fast.log` 69,584,960 bytes |
| Feature files | the lab files: 55,411 bytes for 1,081 flows (51 bytes per flow); in memory (pandas), 384 bytes per flow |
| Training, 100,000 flows (+ 25,000 calibration) | 9.1 s, at most 470.9 MB |
| Training, 300,000 flows (+ 75,000) | 15.7 s, at most 632.1 MB |
| Training, 1,000,000 flows (+ 250,000) | 56.9 s, at most 1,422.3 MB |

## Limits

- The repeated capture holds the same flows 320 times, so its feature file
  compresses far better than real traffic would (4.1 bytes per flow). Use
  the lab files' 51 bytes per flow, or the in-memory 384 bytes per flow as
  a cautious bound, until a real file shows its own figure.
- The lab packets are small (the 102 MB capture holds 1,224,000 of them,
  about 83 bytes each in the file), so the extraction time is mostly time
  per packet. Captures with larger packets may be limited by the disk
  instead.
- Suricata ran with two rules, not ET Open, which this session could not
  download. Its `eve.json` holds one `flow` event for every flow
  (Ubuntu's default configuration logs them) as well as the alerts.
- The made-up flows have the real feature columns but not every column of
  a real feature file, and the evaluation also holds the test files and
  their decisions. Real peaks will be higher: keep a margin.
- Times vary from run to run on a shared machine.
