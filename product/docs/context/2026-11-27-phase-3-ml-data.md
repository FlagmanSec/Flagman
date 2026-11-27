> Markdown copy of [`2026-11-27-phase-3-ml-data.docx`](2026-11-27-phase-3-ml-data.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: labelled data in Python

*Context document for draft pull request 3 of the phase 3 toolkit, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/03-ml-data`, built on `phase-3/02-extract` (pull request #4). A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (items C1 and D) |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-27-phase-3-ml-data.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. Why flows need labels, step by step
3. Reading feature files
4. The matching rule
5. Mapping files and classes
6. Time zones and the offset finder
7. Labels files: where every label comes from
8. The datasets: what is verified and what is not
9. Downloads with checks
10. The pipeline check on the lab captures
11. CI, and the problem it caught
12. How it was checked
13. Known limits
14. What comes next
15. Use of AI

## 1. The short version

- This pull request adds `product/ml`, the Python side of phase 3. Python **never computes a feature**: it reads the feature files that `flagmand extract` (pull request 2) writes, so the models and the sensor use the same numbers.
- Its main job is **labelling**: giving each flow a class (normal, scan, brute_force, botnet, ...) by matching it with a public dataset’s ground truth, through one **mapping file** per dataset.
- It also adds a **download script** that resumes, checks every file’s size and SHA-256, refuses 20 GB or more without a clear yes, and never downloads a program; one **manifest** per dataset; and `ml/data/README.md`, with each dataset’s terms, sizes and citations quoted from the source pages, and what could not be verified said plainly.
- 79 Python tests run in under 3 seconds, on the lab feature files and on hand-written samples. A new CI job runs them; another CI step checks that the lab feature files are exactly what the current Rust code extracts.
- Labelling the three lab captures gives 1,000 scan, 28 brute_force and 53 normal flows with no conflict. That is a **pipeline check, not a result**: it shows the code works, not how well Flagman detects anything.
- No real dataset file was downloaded: the dataset servers were out of this session’s network reach. The script is tested against a small web server on the test machine, and the team runs the downloads.

## 2. Why flows need labels, step by step

1. A model learns from examples: here, flows with the right answer attached (this flow was a port scan, that one was normal). The right answers are called **labels**.
2. Public datasets come with their own record of what happened, the **ground truth**: a list of attacks with times and addresses (UNSW-NB15), or a label on every flow cut by their own tool (CIC-IDS2017, CTU-13).
3. Flagman cuts flows with its own flow table, so its flows are not the dataset’s flows: the start and end can differ, and one of their flows can be two of ours.
4. So each Flagman flow takes the label of the ground-truth record that describes **the same conversation at the same time**: same two machines, same ports where the record gives them, same protocol where it gives one, and overlapping times.
5. Everything about one dataset (how to read its file, its time zone, which of its labels means which Flagman class) sits in a small mapping file, so the code stays the same for every dataset.

## 3. Reading feature files

- `read_flows(*paths)` reads one or more feature files into one pandas table. Two columns name every flow for good: `source` (the file’s name) and `row` (its position in the file). Labels and, later, predictions join back on them.
- The list of model inputs comes from each file’s footer, never from “all columns”: `flows.inputs()` returns exactly the 37 features, so an address or a clock time can never become an input by mistake.
- The three category features keep every value of the schema, in its order, so their codes are the same in every file even when a file does not use all of them. A value outside the schema stops the reading.
- Files read together must have the same schema and the same flow table settings (the timeouts decide where flows are cut, so features made with other settings are not comparable), and different names.

## 4. The matching rule

A flow matches a record when all four hold:

1. the two ends agree, in **either direction** (a dataset may write the answering machine first, while Flagman’s source is the machine that sent the first packet);
2. the ports agree where the record gives them (an empty port matches any port);
3. the protocols agree where the record gives one;
4. the times overlap, once the record’s window is moved by the mapping’s **offset** and widened by its **tolerance** on both sides.

When several records match one flow, the most specific one wins (the one that gives more of: source port, destination port, protocol), then the one that overlaps the flow for longest, then the first one in the file. A flow whose candidates lead to different classes is marked as a **conflict**, so it can be left out or checked by hand. A flow that matches nothing gets the mapping’s **default label**.

Example from the lab: the record “192.168.77.66 to 192.168.77.10, port 22, any source port, from 18:09:37.217 to 18:09:41.431” matches each of the 15 SSH connections of the attack chain. The scan’s single SYN to port 22, at 18:09:35.141, falls in the scan’s window and not in this one, so it stays a scan.

The code joins on exact pairs of (address, port) when the record gives both ports, and on the pair of addresses otherwise, then filters by protocol and time. That keeps it fast on large files: it never compares every flow with every record.

## 5. Mapping files and classes

A mapping file is a short TOML file in `ml/data/labels/`. For the lab:

```text
dataset = "lab"
format = "lab_csv"
default_label = "normal"
time_zone = "UTC"
time_offset_ms = 0
time_tolerance_ms = 0

[classes]
port_scan = "scan"
ssh_password_guessing = "brute_force"
ssh_key_login = "normal"
ssh_refused = "normal"
```

- **Strict:** every label found in the ground truth must map to a class. One unknown label stops the run and lists all of them, so no flow is ever labelled by accident.
- **Default label:** `normal` when the ground truth lists attacks only (UNSW-NB15, the lab); `unlabelled` when it lists every flow (CIC-IDS2017, CTU-13), because a flow such a dataset does not describe is not known to be normal.
- **Two classes never train or score a model:** `background` (traffic of unknown nature) and `unlabelled`. They stay in the labels file and are counted, so reports can say how much was left out.
- Readers exist for four formats: our lab CSV, the UNSW-NB15 ground truth, CICFlowMeter CSVs (CIC-IDS2017) and CTU-13’s labelled Argus flows. ICMP and other protocols never compare ports, because Flagman writes port 0 for them while datasets write ICMP types in many ways.

Choices made in the mapping files, for the team to confirm:

| Dataset | Choice |
|---|---|
| UNSW-NB15 | Categories with no clear match elsewhere (Fuzzers, Analysis, Backdoors, Generic, Shellcode, Worms) keep a class of their own; Reconnaissance maps to scan |
| CIC-IDS2017 | Flows labelled as attempted are left out; web brute force is brute_force; cross-site scripting and SQL injection are web_attack |
| CTU-13 | To-Botnet and To-Normal flows are background, like Background: not malicious as such, per the dataset page |
| Lab | Steps 3 to 5 of the SSH capture (logins with a key, a stopped server) are normal: what a legitimate user does |

## 6. Time zones and the offset finder

Captures count time in UTC. Some datasets write their ground-truth times in local time without saying which zone: the CTU-13 and CIC-IDS2017 pages do not state it. A wrong zone shifts every record by whole hours, and then almost nothing matches.

`python -m flagman_ml.labels offsets` tries every offset from −14 h to +14 h in 15-minute steps (that covers every time zone, including ones like UTC+5:45) and counts, for each, how many flows find a record. The right offset stands out. The test writes the lab ground truth three hours ahead and checks that the finder answers −3 h, with all 1,039 attack flows matched and no other offset matching any.

## 7. Labels files: where every label comes from

- `python -m flagman_ml.labels label` writes one row per flow: `source`, `row`, `label` (the class), `dataset_label` (the dataset’s own words), `record` (which ground-truth row, as file:position), `candidates` and `conflict`.
- The file’s footer records the SHA-256 checksum of the mapping file, of every ground-truth file and of every feature file, and the counts of the run. The same inputs always give the same bytes (tested).
- `attach_labels(flows, labels)` joins labels to flows, and refuses if a feature file’s checksum differs from the recorded one: labels are never joined to a different extraction of the same capture.
- The counts point at problems: many unmatched flows, conflicts, or few of the records in the capture’s time span used, all mean something to check (the offset, the tolerance, or a capture that does not hold the recorded traffic).

## 8. The datasets: what is verified and what is not

Every fact in `ml/data/README.md` was read on its source page on 26 or 27 November 2026, by AI agents that quote the page; quotation marks mean copied text. The main points:

| Dataset | Verified | Not verified or not stated |
|---|---|---|
| UNSW-NB15 | Files in a UNSW SharePoint folder; “100 GB of the raw traffic”; ground truth columns (per the COMIDDS catalogue); the 9 categories; terms (free for academic research, commercial use to agree with the authors); the 5 papers to cite | Capture file names and dates; the time format of the ground truth (it looks like seconds since 1970); its exact file name (two spellings seen) |
| CIC-IDS2017 | Capture sizes per day (51 GB in all); attack schedule; terms (“publicly available for researchers”, cite the paper); the download folder shows a registration form | File names; time zone; checksums |
| Engelen et al. 2021 | The paper (IEEE SPW 2021, pp. 7–12), what it corrects, the “X - Attempted” label, the address of the corrected files | That page could not be read: the files’ names, format, date style and terms. The CIC mapping file is a draft until checked |
| CTU-13 | File names and sizes of all 13 scenarios (about 85 GB, 66G of it in scenario 51’s capture); full captures are private; terms (cite the paper and the project); citation with DOI | Time zone of the flow times; checksums |
| MAWI | Terms (research only, respect privacy); anonymisation method; citation; MAWILab stopped in December 2024 | Trace names, lengths and sizes (the index pages refused our tools) |

**Never downloaded:** each CTU-13 scenario folder also holds the malware sample it ran (`*.exe.zip`), and the dataset page says each scenario contains “the original executable file”. The manifests list only captures and labels, and the download script refuses any name that looks like a program.

## 9. Downloads with checks

- A file already in place is checked (size and SHA-256), not downloaded again.
- A broken transfer resumes where it stopped when the server allows it; when it does not, the file is downloaded again from the start.
- A file gets its final name only after its checks pass; a mismatch is kept as `name.bad` to look at.
- No dataset publishes checksums for these files, so the first download needs `--record`: it prints each file’s size and SHA-256, to paste into the manifest and commit. Every later download is checked against them.
- A selection of 20 GB or more is refused without `--allow-large` (the team’s rule: ask before datasets over 20 GB), and so is one that does not fit on the disk with 1 GB to spare.
- Requests carry a generic name (`flagman-ml-download/0.1`) and nothing about the person running them.

```text
python -m flagman_ml.datasets download --manifest data/manifests/ctu-13.toml \
    --dest data/downloads/ctu-13 --skip ctu-51/botnet-capture-20110818-bot.pcap --record
```

## 10. The pipeline check on the lab captures

The lab ground truth (`ml/fixtures/lab-ground-truth.csv`) has one row per step of the two recording scripts. The scripts did not log their times, so each window was read from the captures themselves: the first packet of the step’s first flow to the last packet of its last flow. The steps of the SSH capture are only 7 to 9 ms apart, so the lab mapping uses no tolerance.

| Capture | Flows | Labels |
|---|---|---|
| lab-attack-chain | 1,015 | 1,000 scan (the nmap scan, its SYN to port 22 included), 15 brute_force |
| lab-ssh-logins | 24 | 13 brute_force (wrong passwords), 11 normal (key logins and a stopped server) |
| lab-normal-traffic | 42 | 42 normal (no record matches: the default label) |
| Total | 1,081 | 1,000 scan, 28 brute_force, 53 normal; 0 conflicts; all 7 records used |

With 1 second of tolerance, the two connections at the boundary between SSH steps 2 and 3 match both steps: they are marked as conflicts and keep the right label, because their overlap with their own step is longest. A test pins this. Again, this is a pipeline check, not a result.

## 11. CI, and the problem it caught

- A new job, “ML pipeline (Python)”, installs the pinned packages with Python 3.13 and runs the 79 tests. It downloads nothing but the packages.
- A new step in the Rust job extracts the three lab captures again and compares them byte for byte with `ml/fixtures/`. If a change to the flow table, the features or the Parquet writer changes the files, CI fails and says to run `ml/fixtures/make-fixtures.sh`.
- That check found a real problem before the first push: the first copies of two lab files came from an experimental build made while testing the parity fix. They held the same rows in another order. They were rebuilt from the current code, and the check now passes.

## 12. How it was checked

- 79 Python tests: reading (and six kinds of refusal), the matching rule on tiny examples, the four readers on hand-written samples in each dataset’s documented columns (made-up values and documentation addresses, not real records), every mapping file and manifest of the repository, the lab labelling and its counts, conflicts, the offset finder, labels files and their provenance, the commands, and downloads from a local web server (resume, a server without ranges, a wrong checksum, the 20 GB guard, the disk check).
- A linter (ruff, run by hand, not added to the project) found no unused names or likely bugs; long lines were wrapped.
- Every Python file is under 210 lines; every folder has a README; the Rust code is unchanged (only CI and the test files around it changed).

## 13. Known limits

- No real dataset file was downloaded, and no real ground-truth file was read: the readers follow the documented columns and are tested on hand-written samples. The UNSW-NB15, CTU-13 and CIC-IDS2017 mapping files are drafts until checked on the real files.
- CTU-13 publishes botnet-only captures: they test botnet detection, not false alarms. MAWI has no ground truth: it counts alerts, it never labels normal traffic.
- Labelling holds one feature file’s flows, and the records of its time span, in memory at once. Very large single files have not been tried.
- The lab ground truth’s windows were read from the captures, because the recording scripts did not log their times.
- The shortcut audit moved to the next pull request, with the models it needs.

## 14. What comes next

- Pull request 4 (`phase-3/04-models`): the shortcut audit, LightGBM with calibrated probabilities, Isolation Forest trained on normal traffic only, the open-set rule, the split conformal threshold (whose bound holds only when traffic is exchangeable) and the drift monitor.
- Pull request 5: evaluation, the Suricata comparison, reports from results files, the model export ADR and the runbook.
- For the team, when downloading: record the checksums, check the UNSW-NB15 ground truth, read the Engelen et al. page and finish the CIC mapping, find the CTU-13 time offset, pick a small MAWI trace. The list is in `product/docs/changes/phase-3-toolkit.md`.

## 15. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request. Dataset facts were read on the source pages by AI agents and quoted; what they could not read is marked as not verified. Every number here comes from a test, from a run of the commands on the lab files, or from a source page named in `ml/data/README.md`. The team reviews and merges; the AI never merges.
