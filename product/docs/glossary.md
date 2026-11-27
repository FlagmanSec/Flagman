# Glossary

Words used in the code, the docs and the dashboard, in plain language.
Sorted by theme, then alphabetically.

## Networks

| Word | Meaning |
|---|---|
| **ARP** | How a device finds the hardware (MAC) address that goes with an IP address on the local network: it shouts "who has 192.168.1.10?" to everyone (a broadcast). |
| **Broadcast** | A message sent to every device on the local network. Every machine sees it, which is why Flagman sees a network sweep even from one PC. |
| **Header** | The start of a packet: addresses, ports, flags. Flagman reads headers only. |
| **ICMP** | Control messages, such as ping. |
| **Interface** | A network card as Linux names it, such as `enp3s0` (cable) or `wlp2s0` (Wi-Fi). `flagmand interfaces` lists them. |
| **IP address** | A device's address on the network. Local (private) ones are `10.x.x.x`, `172.16.x.x` to `172.31.x.x`, `192.168.x.x`, `169.254.x.x`, and `fc00::/7` or `fe80::/10` in IPv6. |
| **MAC address** | The hardware address of a network card. |
| **Packet** | One unit of data on the network: a header, then the contents (payload). |
| **Payload** | The contents of a packet (a web page, a password…). Flagman never stores it. |
| **Port** | A number that tells which program on a machine a connection is for: 22 for SSH, 80 for web, 443 for secure web. |
| **Promiscuous mode** | Makes a network card pass up every frame it receives, not only those addressed to it. On a switched home network this mostly adds broadcasts. |
| **Service** | A program waiting for connections on a port, such as an SSH server. |
| **Switch** | The box (often inside the home router) that connects cable devices. It sends each packet only to the port of the device it is for, so one PC does not see the traffic between two others. |
| **TCP** | Connections with delivery checks (web, SSH, email). A connection starts with a **SYN** ("may I?"), a **SYN-ACK** ("yes"), and an **ACK**. A **RST** means "refused" or "stop". A **FIN** closes politely. |
| **UDP** | Single messages without a connection (DNS, video calls, mDNS). |

## Detection

| Word | Meaning |
|---|---|
| **Alert** | One suspicious behaviour, with its evidence: "192.168.1.50 tried 1,000 ports of 192.168.1.10". |
| **Brute force / login attempts** | Trying passwords again and again on a login service (SSH, RDP…). Flagman never sees the password; it sees many connections to the same login port that were refused or closed within seconds, because servers hang up after wrong passwords. A server in your network needs 10 such connections in a minute, a server on the internet 30, because your own devices log in to internet servers all the time (git over SSH). |
| **Exception** | A way to silence something you know is harmless, in `flagman.toml`. `ignore_logins` silences one login (a source, a target and a port) for the login rule only; `ignore_sources` silences a device for every detector, so its scans are hidden too. |
| **False positive** | An alert about something harmless, such as your own scan. Mark it as such on the incident page. |
| **Finding** | Inside a detector: a key (for example scanner and target) that crossed its threshold. It becomes an alert, and the alert is updated while the finding grows. |
| **Flow** | One conversation between two addresses and ports, from its first packet to its last, with packet and byte counts. |
| **Host sweep / network sweep** | Checking many addresses of the network to find which devices are up (`nmap -sn`). |
| **IDS** | Intrusion detection system: watches and warns. Flagman is an IDS. An **IPS** also blocks. |
| **Incident** | Alerts about the same device (its **host**), grouped while the gaps stay under 30 minutes. The host is usually the device behind the alerts; for a Suricata alert on traffic from the internet, it is your device that received it. One incident is one story to review. |
| **Detector saturated** | Flagman's tables reached their size limit (50,000 entries per detector, 100,000 connections), so it forgot the least active entries to make room. Usually a flood of fake addresses. Shown in the strip at the top of the dashboard. |
| **MITRE ATT&CK** | A public catalogue of attacker behaviour (<https://attack.mitre.org>). A **tactic** is a goal (Discovery, Credential Access); a **technique** is a way to reach it (T1046 Network Service Discovery). |
| **Port scan** | Trying many ports of one machine to see which services answer (`nmap 192.168.1.10`). |
| **Severity** | Low, medium, high or critical. Shown with a shape and a word, never colour alone. |
| **Signature** | A rule that recognises a known attack pattern. Suricata's free rule set (ET Open) is a large collection of them. |
| **Sliding window** | "In the last 60 seconds", recomputed as time moves. |
| **Threshold** | The count that turns normal into suspicious, such as 20 ports in 60 seconds. |

## Tools and formats

| Word | Meaning |
|---|---|
| **EVE JSON** | Suricata's log format: one JSON object per line, in `/var/log/suricata/eve.json`. |
| **libpcap** | The standard Linux library for capturing packets (used by tcpdump and Wireshark). |
| **nmap** | The best-known network scanner. Flagman's tests use it, in an isolated lab. |
| **pcap** | A file of captured packets. tcpdump and Wireshark write them; `flagmand replay` reads them. |
| **Snap length** | How many bytes of each packet are kept: 160 for Flagman. |
| **Suricata** | A free, open-source IDS with a large rule set (<https://suricata.io>). Flagman reads its alerts. |
| **tcpdump** | A command-line tool that captures and prints packets. |

## The program

| Word | Meaning |
|---|---|
| **Capability** | A single root power given to a program. Flagman needs `CAP_NET_RAW` (capture) and `CAP_NET_ADMIN` (promiscuous mode), and nothing else. |
| **flagmand** | The Flagman program ("d" for daemon, a program that runs in the background). |
| **Replay** | Running a pcap file through Flagman as if it were live. Used for tests and demos. |
| **systemd unit** | The file that tells Linux how to start, stop and restrict a service. |
| **Token** | A long random secret in the dashboard link. Without it, the API answers "401 Unauthorized". |
| **WAL** | SQLite's write-ahead log: lets the dashboard read while the sensor writes. |

## Machine learning (phase 3)

| Word | Meaning |
|---|---|
| **Feature** | One number or category that describes a flow, such as its duration or how many packets each side sent. A model learns from features only. |
| **Feature vector** | All the features of one flow, in a fixed order (37 in schema version 1). |
| **Feature schema** | The list of features with their names, units and types, and a version number stored with every file of features, so a model always knows what it was trained on. |
| **Shortcut (lab shortcut)** | A detail of how a dataset was recorded that happens to separate attacks from normal traffic, such as the TTL value `sttl = 254` in UNSW-NB15, which the CS395 model learned (39.6% false alarms). A model that learns a shortcut looks good in the lab and raises false alarms elsewhere. |
| **Data bytes (payload)** | The application's bytes inside a packet, after the IP and TCP or UDP headers. Flagman reads their size from the headers, even when it kept only the first 160 bytes of the packet. |
| **Metadata column** | A value kept next to the features (addresses, ports, times) to label flows and split data by day, never used as a model input. |
| **Running statistics** | A mean and standard deviation updated one value at a time (Welford's method), so no list of packets is ever kept. |
| **Parquet** | A file format that stores a table column by column, with a type for each column and real empty values. Python's pandas and pyarrow read it directly. Flagman's feature files are Parquet. |
| **Feature file** | The output of `flagmand extract`: one row per flow, the metadata columns then the features, with the schema stored in the file's footer. |
| **Footer (key-value metadata)** | The end of a Parquet file, where Flagman stores the schema version, the schema, the flow table's settings and the capture's name. |
| **Row group** | Parquet's unit of storage: a block of rows (65,536 in Flagman's files) written together. |
| **Cargo feature** | An optional part of a Rust program, chosen when building it. `flagmand extract` needs `--features parquet`; the normal build leaves it out. |
| **Byte-identical (deterministic)** | Running the same program twice on the same input gives exactly the same file, byte for byte. Flagman's extraction is, so two evaluation runs can be compared. |
| **Ground truth** | A dataset's own record of what happened: which traffic was an attack, when, between which machines. Labels come from it. |
| **Labelling** | Giving each flow a class (normal, scan, brute_force, ...) by matching it with the ground truth: same two ends, same ports and protocol where given, overlapping times. |
| **Mapping file** | A small TOML file per dataset (`ml/data/labels/`) that says how to read its ground truth and which of its labels goes to which Flagman class. |
| **Default label** | The class of a flow that no ground-truth record matches: `normal` when the dataset lists only attacks, `unlabelled` when it lists every flow. |
| **Background, unlabelled** | Two classes that never train or score a model: traffic of unknown nature, and flows the ground truth does not describe. They are kept and counted. |
| **Time offset, tolerance** | The offset moves every ground-truth time (for a dataset written in an unstated local time zone); the tolerance widens each record's window on both sides. |
| **Conflict (labelling)** | A flow that matches several records leading to different classes. It still gets the most specific record's class, and is marked so it can be left out. |
| **Manifest** | A TOML file per dataset (`ml/data/manifests/`) listing the files to download, with their size and SHA-256 once recorded. |
| **SHA-256 checksum** | A 64-character fingerprint of a file's exact bytes. Downloads are checked against it, and labels record the checksum of the feature files they describe. |
| **Parity test** | A check that features computed live and features extracted from a recording of the same traffic are equal. Described in the phase 2 plan (2.9), not built yet. |
| **Training, calibration, validation, test sets** | Flows split by whole files (days or sessions). The models learn from the training set; the calibration set sets the thresholds and the temperature; validation files guide choices such as which features to keep; the test set is used once, at the end, for the reported numbers. |
| **False-alarm budget (α)** | The share of normal flows allowed to raise an alert, chosen by the user, such as 0.01 (1 in 100). |
| **Conformal threshold** | The threshold set from n normal calibration flows: the ⌈(n+1)(1−α)⌉-th smallest of their scores. If new normal traffic is exchangeable with them, at most a share α of normal flows score above it, on average. Never a guarantee for a real network. |
| **Exchangeable** | Roughly: new traffic comes from the same mix as the calibration traffic, as when the network has not changed. The false-alarm budget only holds then. |
| **Calibrated probability** | A probability that means what it says: among flows given 0.9, about nine in ten are of that class. |
| **Temperature scaling** | Calibration with one number, the temperature: the classifier's raw scores are divided by it before they become probabilities. It never changes the top class. |
| **LightGBM** | A free library of gradient-boosted decision trees: many small trees, each correcting the previous ones. Flagman's classifier. |
| **Isolation Forest** | An anomaly detector that cuts the data at random; an unusual flow ends up alone after few cuts. Trained on normal flows only. |
| **Open set, unknown suspicious** | Traffic of a kind the models were never trained on. An alert whose class is not sure is called `unknown_suspicious` instead of being given a wrong name. |
| **Drift** | Traffic that no longer looks like the calibration traffic (new devices, new software). The drift monitor checks the alert rate, the anomaly scores and each feature (PSI). |
| **PSI (population stability index)** | A number saying how much the mix of a feature's values moved between two sets of flows: 0 for the same mix, larger when it moved. The drift monitor flags a feature above 0.2, a starting point to tune on your own traffic. |
| **AUC, separability** | The AUC is the chance that a random flow of a class scores higher than a random other flow (0.5: no information, 1.0: perfect). Separability is the larger of AUC and 1 − AUC. |
| **Ablation** | Training again without some features, to see how much the model leaned on them. |
| **Macro-F1** | The F1 score (a balance of precision and recall) of each class, averaged, so rare classes count as much as common ones. |
| **Fold, seed, run** | A fold is one choice of training, calibration and test files. A seed fixes the randomness of the models. A run is one fold with one seed: train, test, measure. |
| **Leave one attack type out** | Training without one attack class, then testing on it: the class plays a new attack that no dataset labelled. |
| **Cross-dataset holdout** | Training on one dataset and testing on another, to see what survives a change of network. |
| **Detection at a false-alarm rate** | The share of attacks caught when the threshold lets through at most, say, 0.1% of normal flows. One point of the ROC curve, which plots detection against false alarms for every threshold. |
| **Base rate, precision** | The base rate is the share of flows that are attacks. Precision is the share of alerts that are real. When attacks are rare, even 1% false alarms makes most alerts false. |
| **ECE (expected calibration error)** | How far probabilities are from what they claim: flows are grouped by their top probability (15 groups), and the gap between that probability and the share that were right is averaged. 0 is perfect. |
| **Confidence interval** | The range of values a measured share is compatible with. Flagman uses exact (Clopper-Pearson) intervals at 95%. |
| **Paired test (Wilcoxon, McNemar)** | Tests that compare two methods on the same runs (Wilcoxon signed-rank) or on the same flows (McNemar), so that the difference is not chance. |
| **Model bundle** | The folder `train` writes: the models (`model.joblib`) and `bundle.json`, which says what they were trained on, their thresholds, and the model file's checksum. |
| **ET Open** | The Emerging Threats Open rule set for Suricata, downloaded by `suricata-update`. The comparison with Suricata is meant to use it; the lab test files use two local rules instead. |
| **HOME_NET** | Suricata's name for the networks it protects. Many rules only look at traffic towards it, so it must name the dataset's internal networks. |
| **Unmatched alert** | A Suricata alert that no Flagman flow holds (no flow with the same ends and protocol at that time). Counted and reported, never dropped. |

## Product names

| Word | Meaning |
|---|---|
| **Pro** | Flagman on a Linux PC or server (this phase). |
| **Edge** | Flagman on a router, starting with the OpenWrt One (1 GB of memory). |
| **RTL** | Right to left, the reading direction of Arabic. The dashboard flips its layout for it. |
