# Datasets

Public datasets that Flagman's models are trained and tested on. This
folder holds what describes them; the data itself is never committed
(downloads go to `data/downloads/`, which git ignores).

| Folder | What it holds |
|---|---|
| `labels/` | one **mapping file** per dataset: how its ground truth becomes Flagman classes ([labels/README.md](labels/README.md)) |
| `manifests/` | one **manifest** per dataset: the files to download, with size and checksum ([manifests/README.md](manifests/README.md)) |

**Rules** (from the project brief): attack traffic comes only from public
captures or our own isolated lab; we never download or run a program from a
dataset (some folders hold the malware samples they recorded: the download
script refuses them); downloads of 20 GB or more need the team's yes first.

**How these facts were checked.** Every fact below was read on the source
page named next to it, on 2026-11-26 or 2026-11-27. Text in quotation
marks is copied from that page. "Not stated" means the pages we read do not
say it; "not verified" means we could not read the page that would say it.
Check these points again when downloading: pages change.

## At a glance

| Dataset | What Flagman uses | How to get it | Size (as stated) | Terms | Labels |
|---|---|---|---|---|---|
| UNSW-NB15 | raw captures + ground truth CSV | by hand (SharePoint folder) | "100 GB of the raw traffic" | academic research, free | attacks only; all else normal |
| CIC-IDS2017 + Engelen et al. corrections | captures + corrected flow labels | by hand (registration form) | 51 GB of captures (5 days) | "publicly available for researchers", cite the paper | every flow labelled |
| CTU-13 | botnet-only captures + labelled flows | script (direct links) | about 85 GB, 14 GB without scenario 51 | cite the paper | every flow labelled |
| MAWI | one anonymised backbone trace | by hand, then script | not stated | "only research purposes" | **none** |

## UNSW-NB15

- **Page:** <https://research.unsw.edu.au/projects/unsw-nb15-dataset>.
  The files are in a UNSW SharePoint folder linked from it:
  <https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS>.
  Whether it needs a sign-in is not stated.
- **Size:** the page gives "100 GB of the raw traffic". The COMIDDS
  catalogue (<https://fkie-cad.github.io/COMIDDS/content/datasets/unsw_nb15>)
  gives "Packed Size: ~100 GB" and "Total Runtime: 31 hours": a 16-hour
  run with one attack per second and a 15-hour run with ten. The number
  of capture files, their names and the capture dates are not stated.
- **Ground truth:** one CSV of attack records. The official page calls it
  `UNSW-NB15_GT.csv`; COMIDDS shows `NUSW-NB15_GT.csv`. Its columns, from
  the COMIDDS sample: `Start time, Last time, Attack category, Attack
  subcategory, Protocol, Source IP, Source Port, Destination IP,
  Destination Port, Attack Name, Attack Reference, .` The time zone and
  format are not stated; the sample rows look like seconds since 1970, which
  is how the `unsw_gt` reader takes them (to check on the real file).
- **Attack categories** (official page): Fuzzers, Analysis, Backdoors, DoS,
  Exploits, Generic, Reconnaissance, Shellcode, Worms.
- **Terms** (official page): "Free use of the UNSW-NB15 dataset for academic
  research purposes is hereby granted in perpetuity. Use for commercial
  purposes should be agreed by the authors." So models trained on it need
  the authors' agreement before any commercial use.
- **Cite** (the page asks for all five):
  1. Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for
     network intrusion detection systems (UNSW-NB15 network data set)."
     MilCIS 2015, IEEE. <https://doi.org/10.1109/MilCIS.2015.7348942>
  2. Moustafa, Nour, and Jill Slay. "The evaluation of Network Anomaly
     Detection Systems: Statistical analysis of the UNSW-NB15 dataset and
     the comparison with the KDD99 dataset." Information Security Journal:
     A Global Perspective (2016): 1-14.
  3. Moustafa, Nour, et al. "Novel geometric area analysis technique for
     anomaly detection using trapezoidal area estimation on large-scale
     networks." IEEE Transactions on Big Data (2017).
  4. Moustafa, Nour, et al. "Big data analytics for intrusion detection
     system: statistical decision-making using finite dirichlet mixture
     models." Data Analytics and Decision Support for Cybersecurity,
     Springer, 2017, pp. 127-156.
  5. Sarhan, Mohanad, Siamak Layeghy, Nour Moustafa, and Marius Portmann.
     "NetFlow Datasets for Machine Learning-Based Network Intrusion
     Detection Systems." BDTA 2020 / WiCON 2020 proceedings, Springer.

## CIC-IDS2017, with the corrected labels of Engelen et al.

- **Page:** <https://www.unb.ca/cic/datasets/ids-2017.html>. Its download
  link, <http://cicresearch.ca/CICDataset/CIC-IDS-2017/>, showed a
  registration form (first and last name, email, organisation, job title,
  country) and no file list on 2026-11-27, so the files are downloaded by
  hand. No checksums are published.
- **Size** (page): captures of "Monday, Normal Activity, 11.0G", Tuesday 11G,
  Wednesday 13G, Thursday 7.8G, Friday 8.3G; the format is not stated. The
  page also names `GeneratedLabelledFlows.zip` and `MachineLearningCSV.zip`
  (no sizes). File names of the captures are not stated.
- **Attack times** (page; its time zone is not stated): Tuesday FTP-Patator
  9:20-10:20 and SSH-Patator 14:00-15:00; Wednesday DoS slowloris
  9:47-10:10, Slowhttptest 10:14-10:35, Hulk 10:43-11:00, GoldenEye
  11:10-11:23 and Heartbleed 15:12-15:32; Thursday web brute force
  9:20-10:00, XSS 10:15-10:35, SQL injection 10:40-10:42, infiltration in the
  afternoon; Friday botnet ARES 10:02-11:02, port scans in the afternoon,
  DDoS LOIT 15:56-16:16. Attacker 205.174.165.73; victim web server
  205.174.165.68 (192.168.10.50 inside).
- **Terms** (page): the labelled flows are "publicly available for
  researchers", and "If you are using our dataset, you should cite our
  related paper". No licence is named.
- **Cite:** Iman Sharafaldin, Arash Habibi Lashkari and Ali A. Ghorbani,
  "Toward Generating a New Intrusion Detection Dataset and Intrusion
  Traffic Characterization", ICISSP 2018.
- **Why the corrections.** Engelen, Rimmer and Joosen, "Troubleshooting an
  Intrusion Detection Dataset: the CICIDS2017 Case Study", 2021 IEEE
  Security and Privacy Workshops (SPW), pp. 7-12
  (paper: <https://lirias.kuleuven.be/retrieve/713070>; record:
  <https://researchportal.be/en/node/8038227>; the DOI is not stated on
  either). They found that the original flow tool cut TCP connections at
  the first FIN, so leftover packets became extra flows ("25.9 percent of
  the entire dataset"); that timeouts could swap source and destination;
  that RST did not end a flow; that the DoS Hulk attack was "ineffective";
  and they label flows with no data sent forward as "X - Attempted". In
  all, "more than 20 percent of original traffic traces are reconstructed
  or relabelled".
- **Corrected files:** the paper gives
  <https://downloads.distrinet-research.be/WTMC2021> for the regenerated
  dataset and modified feature extractor. That page **could not be read**
  from here on 2026-11-27, so the files' names, format, size, date style
  and terms are **not verified**. `labels/cic-ids2017.toml` is a draft
  until someone checks them.

## CTU-13

- **Page:** <https://www.stratosphereips.org/datasets-ctu13>. Files:
  <https://mcfp.felk.cvut.cz/publicDatasets/>, one folder per scenario,
  `CTU-Malware-Capture-Botnet-42` to `-54` (scenarios 1 to 13).
- **What is public:** "For privacy issues the complete pcap file containing
  all the background, normal and botnet data is not available." Each
  scenario has a botnet-only capture and labelled bidirectional flows
  (made with Argus) in `detailed-bidirectional-flow-labels/`. So Flagman
  gets the infected machines' traffic, not a full network: useful to test
  botnet detection, not to count false alarms.
- **Never downloaded:** each folder also holds the malware sample it ran
  (`*.exe.zip`), and `CTU-13-Dataset/` holds `only-exes-of-ctu-13.zip`.
  The page says each scenario contains "The original executable file", so
  the one-file archive `CTU-13-Dataset.tar.bz2` (1.9G) is not used either.
- **Size:** the file names and sizes of every scenario, as the folder
  listings show them, are in `manifests/ctu-13.toml`: about 85 GB in all,
  66G of it for scenario 51's capture alone (its page warns that the
  capture "ended early"). No checksums are published.
- **Labels:** columns `StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr,
  Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label`. Label
  families: From-Botnet (the botnet's traffic), To-Botnet and To-Normal
  (not malicious as such, per the dataset page), From-Normal, Background.
  The time zone of `StartTime` is not stated; the scenario timelines are
  written in CEST.
- **Terms:** no licence is named. The FAQ
  (<https://www.stratosphereips.org/datasets-faq>): "You do not need to ask
  permission from us to use our datasets as long as you cite the datasets
  appropriately". The scenario pages add: "Garcia, Sebastian. Malware
  Capture Facility Project. Retrieved from https://stratosphereips.org".
- **Cite:** Sebastian Garcia, Martin Grill, Jan Stiborek and Alejandro
  Zunino, "An empirical comparison of botnet detection methods", Computers
  & Security 45 (2014) 100-123, <https://doi.org/10.1016/j.cose.2014.05.011>.

## MAWI

- **Page:** <https://mawi.wide.ad.jp/mawi/>: daily traces of the WIDE
  transit link (samplepoint-F) "in operation since 2006/07/01".
- **Use in Flagman:** real backbone traffic to count alerts per day and
  watch for drift. It has **no ground truth**: never treat it as labelled
  normal traffic. MAWILab, which labelled anomalies in it, stopped: "The
  MAWILab operation was terminated in December 2024"
  (<http://www.fukuda-lab.org/mawilab/>).
- **Anonymised:** addresses are scrambled with a prefix-preserving method
  (a modified tcpdpriv, then Crypto-PAn since August 2015), per the FAQ
  (<https://mawi.nezu.wide.ad.jp/mawi/faq.html>). Whether payloads are cut
  is not stated.
- **Not verified:** trace length, start time, file names and sizes. The
  year index pages refused our tools (robots.txt), so `manifests/mawi.toml`
  lists no trace yet: pick one by hand; a small trace is enough to count
  alerts.
- **Terms** (page): "You may use WIDE traffic data for only research
  purposes. Actions that trespass upon users' privacy are prohibited."
- **Cite:** Kenjiro Cho, Koushirou Mitsuya and Akira Kato, "Traffic Data
  Repository at the WIDE Project", USENIX 2000 FREENIX Track.

## Downloading

Run from `product/ml` (see [the datasets package](../flagman_ml/datasets/README.md)):

```bash
python -m flagman_ml.datasets list --manifest data/manifests/ctu-13.toml
# First download: no checksum is known yet, so --record prints them.
python -m flagman_ml.datasets download --manifest data/manifests/ctu-13.toml \
    --dest data/downloads/ctu-13 --skip ctu-51/botnet-capture-20110818-bot.pcap --record
# Files downloaded by hand (UNSW-NB15, CIC-IDS2017): check them.
python -m flagman_ml.datasets verify --manifest data/manifests/unsw-nb15.toml \
    --dest data/downloads/unsw-nb15
```

Paste the printed sizes and checksums into the manifest and commit them, so
every later download is checked against the same bytes.
