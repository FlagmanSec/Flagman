# 0012. Compute machine learning features inside the flow table

Status: proposed (phase 3 branch; accepted when phase 3 starts)
Date: 2026-11-26

## Context

Phase 3 adds machine learning ([ADR 0005](0005-rules-first-ml-later.md):
rules first, ML later). The CS395 project taught two lessons that decide
where features are computed:

1. Training features must be computed by exactly the same code that runs
   live. If a Python script recomputes them from a dataset's CSV files, the
   model learns numbers the sensor never produces.
2. Datasets carry lab shortcuts: addresses, TTL values, timing. CS395 got
   39.6% false alarms from `sttl = 254` in UNSW-NB15.

The sensor already groups packets into flows in `flagman-core`'s flow
table, and it must stay small enough for the router (1 GB of memory).

## Decision

- Features are computed in Rust, packet by packet, **inside the flow
  table**: `FlowTable<X>` keeps an `X` next to each flow and calls it for
  every packet and once at the end (`flow/extra.rs`). The new crate
  `flagman-features` provides `X = FeatureState`. The sensor's table is
  `FlowTable<()>`: it keeps nothing extra and returns flow records as
  before, so the detectors and every existing test are unchanged.
- Each decoded IP packet gains two values: its data size, read from the
  IP and TCP length fields (so it is right with the 160-byte capture and
  does not depend on the link layer or the sender's TCP options), and its
  TTL, which the features only use as "changed inside the flow".
- Memory per flow is constant (running statistics, no packet lists):
  measured at 262 more bytes per flow, hash table spare room included.
- Features never include addresses, exact ports, clock times, raw TTL,
  frame sizes or why the sensor ended the flow. Those that help labelling
  are written next to the features as metadata, with the reason in the
  schema.
- The schema (names, units, types) has a version stored with every file of
  features. Python reads features from those files and never recomputes
  them.

## Consequences

- Training, replay and (later) live detection share one implementation.
  `flagmand extract` (next pull request) runs the live capture loop on a
  file to write features.
- Timing features have a 1 ms resolution, the sensor's clock.
- `flagman-core` changes in three places: `flow/extra.rs` (new), the
  generic flow table, and two fields of `IpPacket`. Phase 2 work on the flow
  table (memory limits, item 2.6) must keep the `X` parameter.
- The flags PSH, URG, ECE and CWR are not decoded today, so they are not
  features. Adding them changes `TcpFlags` and the schema version.

## Alternatives considered

- **A separate feature table in the new crate, mirroring the flows by
  key**: no change to `flagman-core`, but each flow's key would be stored
  twice (more memory on the router), and the two tables must end flows at
  exactly the same moment, a second copy of subtle logic.
- **Compute features in Python from the capture files** (as CICFlowMeter
  or Zeek scripts would): the sensor would then run different code live,
  which is the first CS395 lesson.
- **Use a dataset's own feature CSV files** (UNSW-NB15, CIC-IDS2017): they
  were made by other tools with other definitions, and they include the
  shortcuts above.
