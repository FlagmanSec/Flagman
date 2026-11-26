> Markdown copy of [`2026-11-26-phase-3-features.docx`](2026-11-26-phase-3-features.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Flagman phase 3 toolkit: per-flow features

*Context document for draft pull request 1 of the phase 3 toolkit, 26 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branch | `phase-3/01-features`, built on `phase-1-followups`. A draft pull request: the team merges it when phase 3 starts, after rebasing on `main` |
| Requested by | Seraj, in the phase 3 toolkit prompt (item A) |
| Written by | Claude Code, an AI coding assistant, at Seraj’s request |
| This file | `product/docs/context/2026-11-26-phase-3-features.docx`, with a Markdown copy next to it |

### Contents

1. The short version
2. Why features, and why inside the flow table
3. The change to flagman-core, step by step
4. The 37 features
5. What is left out on purpose, and the tests that prove it
6. Memory per flow
7. The schema and its version
8. How it was checked
9. What comes next
10. Use of AI

## 1. The short version

- A machine learning model does not look at packets. It looks at a short list of numbers per flow, called **features**: how long the flow lasted, how many packets each side sent, how big they were, how the TCP handshake went, and so on.
- This pull request computes 37 features for every flow, in Rust, **inside the sensor’s own flow table**, packet by packet, in constant memory. Nothing trains or runs a model yet.
- Addresses, exact ports, clock times and raw TTL values are never features. Eight tests change each of them, and also the capture’s link layer and the sender’s TCP options, and check that every feature stays exactly the same.
- The sensor itself is unchanged: its flow table keeps nothing extra, and all 93 earlier Rust tests pass without any change. 29 new tests pass.
- Features add 262 bytes per flow (about 26 MB for 100,000 flows), measured by a test.

## 2. Why features, and why inside the flow table

The CS395 project left four lessons, which the phase 3 prompt makes the requirements. This pull request answers the first two:

1. **Training features must be computed by exactly the same code that runs live.** If a Python script computes them from a dataset, the model learns numbers the sensor never produces.
2. **Datasets carry lab shortcuts**: addresses, TTL values, timing. CS395 got 39.6% false alarms because its model learned `sttl = 254` from UNSW-NB15.

So the features are computed where the sensor already follows each conversation: in `flagman-core`’s flow table. The same table runs when Flagman captures live and when it replays a capture file. Training data and live detection therefore come from one implementation. The decision is written in ADR 0012, with the alternatives that were rejected.

## 3. The change to flagman-core, step by step

The phase 3 prompt asked for the smallest possible change to `flagman-core`, with no change to how the detectors behave. There are two parts.

### 3.1 A slot for extra state per flow

1. The flow table becomes `FlowTable<X>`: next to each flow it keeps a value of type `X`.
2. For every packet of the flow, the table calls `X::add_packet` with the packet, its direction, and the flow’s record so far.
3. When the flow ends (closed, idle, timed out, evicted, or at the end of a replay), the table calls `X::finish` with the final record, and hands out the result.
4. The sensor’s table is `FlowTable<()>`: `()` is Rust’s “nothing” type, which takes no memory. Its `finish` returns the plain flow record, exactly as before, so the engine and the detectors did not change at all.
5. The feature builder uses `FlowTable<FeatureState>`: its `finish` returns the record together with the 37 features.

The new file is `flow/extra.rs` (58 lines); `flow/table.rs` changed only where it creates, updates and ends a flow.

### 3.2 Two more values per packet

The decoder now also gives each IP packet:

- `payload_len`: the number of application data bytes, after the IP and TCP or UDP headers. Flagman keeps only the first 160 bytes of each packet, so the data itself is usually cut off. Its size is still known from the headers: the IP header says how long the packet is, and the TCP header how long the TCP header is (`packet/lengths.rs`).
- `ttl`: the IPv4 time-to-live, or the IPv6 hop limit. The detectors ignore it. The features only use it as “did it change inside the flow”.

Why data bytes rather than the frame size: the frame size includes the link layer (14 bytes of Ethernet, 16 or 20 for a Linux “cooked” capture, 4 more with a VLAN tag) and the sender’s TCP options (Linux adds 12 bytes of timestamps to every packet; Windows does not by default). The same traffic would then look different depending on how and from which system it was recorded: exactly the kind of shortcut lesson 2 warns about.

## 4. The 37 features

“fwd” is what the initiator sent (the side of the first packet), “rev” what the responder sent. Times are in milliseconds, the sensor’s clock resolution. A value is empty when it is not defined, for example the mean size of a side that sent nothing.

| Features | Unit | Shortcut risk to audit |
|---|---|---|
| `protocol`, `dst_port_class` (well-known 0–1023, registered 1024–49151, dynamic 49152–65535), `tcp_outcome` | categories | none: they describe the traffic |
| `packets_fwd/rev`, `payload_bytes_fwd/rev`, `packets_share_rev`, `payload_share_rev` | packets, bytes, 0–1 | none |
| `payload_min/max/mean/std` per direction | bytes | the maximum follows the maximum segment size, which depends on the system and the network |
| `gap_min/max/mean/std_ms` per direction, `duration_ms` | ms | timing depends on the network where it was recorded |
| `first_response_ms` | ms | the network distance: a lab is much shorter than the internet |
| `syn`, `fin`, `rst`, `empty_packets` per direction | packets | none |
| `ttl_changed_fwd/rev` | 0/1 | none: the raw TTL is never kept |

The port ranges are IANA’s ([port registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml), following RFC 6335 section 8.1.2). The full table, one row per feature, is in the crate README.

The features in the “risk” column stay in this first version: they also describe real behaviour. The shortcut audit of a later pull request measures each of them alone and removes them in ablation runs; a later schema version can drop any that turn out to be lab fingerprints.

## 5. What is left out on purpose, and the tests that prove it

| Value | Kept as metadata? | Why it is never a feature |
|---|---|---|
| IP addresses | yes, for labelling | an address names one machine of one network, such as the lab’s attacker |
| MAC addresses | no | the same for the network card; the flow table does not keep them |
| Exact ports | yes, for labelling | source ports are random; which server port a lab attacked is a property of that lab |
| Clock time | yes, for splits by day | a model would learn the lab’s attack schedule |
| Raw TTL | no | it names the sender’s system (64 Linux, 128 Windows) and the number of routers; CS395’s `sttl = 254` |
| Frame size | no | depends on the link layer of the capture |
| Header sizes | no | depend on the sender’s system (TCP options) |
| Why the flow ended | yes | “evicted” and “stopped” describe the sensor, not the traffic |

Metadata columns are written next to the features only to match flows to a dataset’s ground truth and to split data by day. The schema lists them with these reasons, and the Python side will read the list of features from the schema, so it cannot pick a metadata column by mistake.

The test file `tests/shortcuts.rs` builds one ten-packet conversation and replays it through the real decoder and flow table, changing one thing at a time. Each time, all 37 features must be identical:

- other IPv4 addresses, and IPv6 instead of IPv4;
- other ports in the same class (51515 to 443 instead of 40000 to 22);
- a steady TTL of 128, 254/63 or 255/1 instead of 64;
- a VLAN tag, raw IP, or a Linux cooked capture instead of Ethernet;
- a clock time 400 days later;
- the TCP timestamps option on every packet.

A ninth case changes the server’s TTL in the middle of the flow: then exactly one feature changes, `ttl_changed_rev`.

## 6. Memory per flow

The router has 1 GB of memory, so the cost per flow matters. No list of packets is ever kept: each statistic is updated in place (a count, a mean and a sum of squared differences, Welford’s method, plus the minimum and maximum). A test counts what the flow table really allocates for 100,000 flows, the sensor’s default limit:

| Table | Bytes per flow |
|---|---|
| The sensor today (`FlowTable<()>`) | 200 |
| With features (`FlowTable<FeatureState>`) | 462 |
| The feature state alone | 200 |

Features add 262 bytes per flow (the state, plus the hash table’s spare room), about 26 MB for 100,000 flows. The test fails if this ever goes above 300 bytes. If the router needs less, the README lists two possible savings.

## 7. The schema and its version

`src/schema.rs` lists every feature with its name, unit, type and shortcut note, in output order, plus the metadata columns and why each is never an input. Its version, `SCHEMA_VERSION = 1`, and the same list as JSON will be stored in every file of features that `flagmand extract` writes (next pull request). Changing a feature means increasing the version, so a model always knows which features it was trained on. A test checks that the README names every feature, so the documentation cannot fall behind the code.

## 8. How it was checked

| Check | Result |
|---|---|
| `cargo test --locked` (whole workspace) | 122 passed, 1 on demand (93 before: all unchanged) |
| New in `flagman-core` | 5 data-size tests (whole packet, packet cut by the capture, Ethernet padding, UDP and IPv6, broken length field), 2 extension-slot tests (every packet in order, evicted flows keep their state) |
| New in `flagman-features` | 11 unit tests (statistics, directions, ports, shares, schema, README), a worked example computed by hand and checked against a two-pass formula, 8 shortcut tests, 1 memory test |
| `cargo fmt --check`, `cargo clippy --all-targets -D warnings` | clean |

```text
cd product/core
cargo test --locked -p flagman-features
cargo test -p flagman-features --test memory -- --nocapture   # prints the memory table
```

## 9. What comes next

- Pull request 2 (`phase-3/02-extract`): `flagmand extract capture.pcap --out flows.parquet`, running the same capture loop as the live sensor with features turned on, behind a cargo feature that is off by default (the router build never includes it); a test that two runs give byte-identical files; the live-versus-replay parity test written in the phase 2 plan.
- Then the Python side in `product/ml`: labelling, the shortcut audit, models, the false-alarm budget, evaluation, the Suricata comparison, data scripts and the runbook.
- The state of the whole toolkit, and the prompt for the next session, are kept in `product/docs/changes/phase-3-toolkit.md`.

## 10. Use of AI

Claude Code, Anthropic’s AI coding assistant, wrote the code, tests and documents of this pull request at Seraj’s request. Every number here comes from a test listed in section 8. The team reviews and merges; the AI never merges.
