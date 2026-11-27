# flagman-features

Per-flow features for Flagman's machine learning (phase 3). The crate turns
the packets of each flow into a fixed list of numbers, the **feature vector**,
that a model can learn from. Nothing here trains or runs a model.

## How it plugs in

`flagman-core`'s flow table can keep extra state next to each flow
(`FlowTable<X>`, see `flow/extra.rs` there). This crate's `FeatureState` is
that state:

```text
packet ──> decode ──> FlowTable<FeatureState> ──> flow ends ──> FeatureFlow
                          │ every packet:                     record (who, when)
                          └ FeatureState::add_packet           + FlowFeatures
```

The sensor's own table is `FlowTable<()>`, which keeps nothing extra, so
the detectors work exactly as before. Because the same flow table and the
same code compute the features in the live sensor and when a capture file is
replayed, a model is trained on exactly what it will see live. That is the
first lesson of the CS395 project.

Memory per flow is constant, whatever the number of packets: running
statistics (Welford's method, `src/stats.rs`) replace any list of packets.

## The features (schema version 1)

Directions: `_fwd` is what the initiator sent (the side of the first packet),
`_rev` what the responder sent. "Data" means application bytes after the IP
and transport headers (`payload_len`, read from the headers' length fields,
so it stays correct with Flagman's 160-byte capture). Times are in
milliseconds, the sensor's clock resolution, so gaps shorter than 1 ms count
as 0. A value is empty (`None`) when it is not defined for that flow.

| Feature | Unit | Meaning | Shortcut risk to audit |
|---|---|---|---|
| `protocol` | tcp, udp, icmp, other | transport protocol | – |
| `dst_port_class` | well_known, registered, dynamic, none | the responder's port range ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml): 0–1023, 1024–49151, 49152–65535) | – |
| `tcp_outcome` | established, half_open, rejected, unanswered, midstream, none | how the TCP handshake went (none: not TCP) | – |
| `duration_ms` | ms | first to last packet | timing depends on the network |
| `packets_share_rev` | 0–1 | responder's share of the packets | – |
| `payload_share_rev` | 0–1 | responder's share of the data bytes; empty when no data | – |
| `first_response_ms` | ms | first packet to the responder's first packet; empty when no answer | **network distance**: a lab is much shorter than the internet |
| `packets_fwd`, `packets_rev` | packets | packets per direction | – |
| `payload_bytes_fwd`, `payload_bytes_rev` | bytes | data bytes per direction | – |
| `payload_min_fwd`, `payload_min_rev` | bytes | smallest data size of a packet | – |
| `payload_max_fwd`, `payload_max_rev` | bytes | largest data size | follows the maximum segment size (operating system, network) |
| `payload_mean_fwd`, `payload_mean_rev` | bytes | mean data size | – |
| `payload_std_fwd`, `payload_std_rev` | bytes | standard deviation of the data size | – |
| `gap_min_ms_fwd`, `gap_min_ms_rev` | ms | shortest gap between two packets of one side | timing |
| `gap_max_ms_fwd`, `gap_max_ms_rev` | ms | longest gap | timing |
| `gap_mean_ms_fwd`, `gap_mean_ms_rev` | ms | mean gap | timing |
| `gap_std_ms_fwd`, `gap_std_ms_rev` | ms | standard deviation of the gaps | timing |
| `syn_fwd`, `syn_rev` | packets | packets with the SYN flag | – |
| `fin_fwd`, `fin_rev` | packets | packets with the FIN flag | – |
| `rst_fwd`, `rst_rev` | packets | packets with the RST flag | – |
| `empty_packets_fwd`, `empty_packets_rev` | packets | packets without data (handshakes, plain ACKs, probes) | – |
| `ttl_changed_fwd`, `ttl_changed_rev` | 0/1 | the TTL changed inside the flow | – |

37 features. The "risk" column is not a verdict: those features describe the
traffic too, but they can also describe the lab that recorded it. The
shortcut audit (`product/ml`, phase 3) checks each of them alone and removes
them in ablation runs; a later schema version can drop any that turn out to
be fingerprints.

## Left out on purpose

These are never model inputs. Some are written next to the features as
**metadata**, only to label flows (match them to a dataset's ground truth)
and to split data by day or session:

| Value | Kept as metadata? | Why it is not a feature |
|---|---|---|
| IP addresses (`src_ip`, `dst_ip`) | yes | an address names one machine of one network, such as the lab's attacker; a model would learn "this address is bad" |
| MAC addresses | no | the same, for the network card; the flow table does not even keep them |
| Exact ports (`src_port`, `dst_port`) | yes | the source port is picked at random by the sender's system; which server port a lab attacked is a property of that lab. `dst_port_class` keeps the useful part |
| Clock time (`flow_start_ms`, `flow_end_ms`) | yes | a model would learn the lab's attack schedule (which day, which hour) instead of the attack |
| Raw TTL or hop limit | no | it says which system sent the packet (64 for Linux, 128 for Windows) and how many routers it crossed. CS395 got 39.6% false alarms from `sttl = 254` in UNSW-NB15. Only "changed inside the flow" is kept |
| Frame size on the wire | no | it includes the link layer (14 bytes of Ethernet, 16 or 20 for a Linux "cooked" capture, 4 more with a VLAN tag), so the same traffic recorded two ways would look different. Data bytes are used instead |
| IP and TCP header sizes | no | they depend on the sender's system (Linux adds 12 bytes of TCP timestamps to every packet, Windows does not by default) |
| How the flow ended (`end_reason`) | yes | "evicted" and "stopped" describe the sensor (a full table, the end of a capture), not the traffic; a TCP close is already visible in `fin_*` and `rst_*` |

The tests in `tests/shortcuts.rs` prove the first and the last ones: the
same conversation with other addresses, other ports of the same class,
another steady TTL, another link layer (Ethernet, VLAN, raw IP, Linux cooked
capture), another clock time, or the TCP timestamps option gives exactly the
same feature vector. Only a TTL change inside the flow shows.

## Memory

Measured by `tests/memory.rs`, a counting allocator around a table of
100,000 one-packet flows (the sensor's default limit), hash table spare room
included:

| Table | Bytes per flow |
|---|---|
| `FlowTable<()>`, the sensor today | 200 |
| `FlowTable<FeatureState>` | 462 |
| `FeatureState` alone | 200 |

So features add about 262 bytes per flow, 26 MB for 100,000 flows. The test
fails if they ever add more than 300. Print the numbers with
`cargo test -p flagman-features --test memory -- --nocapture`. Possible
savings for the router, if needed: 32-bit floats for the running statistics,
and gaps measured from the flow's start instead of the clock.

## The schema and its version

`src/schema.rs` lists every feature with its name, unit, type and shortcut
note, in output order, and the metadata columns with the reason each one is
never an input. `schema_json()` gives the same as JSON; every file written by
`flagmand extract` stores it with `SCHEMA_VERSION` (see
[`flagman-parquet`](../flagman-parquet/README.md)). Python reads the list of features from there, so it can
never pick a metadata column by mistake.

**Changing a feature:** add or change it in `features.rs` and `schema.rs`,
add it to the table above (a test checks the README names every feature),
and increase `SCHEMA_VERSION`. Old files keep their own version, so a model
can always tell which features it was trained on.

## Files

| File | What it does |
|---|---|
| `src/stats.rs` | count, mean, standard deviation, min and max in constant memory |
| `src/direction.rs` | what one side of a flow sent |
| `src/state.rs` | `FeatureState`, the state the flow table keeps per flow |
| `src/features.rs` | `FlowFeatures`, the finished vector, and `FeatureFlow` |
| `src/port_class.rs` | the port ranges |
| `src/schema.rs` | names, units, types, metadata, version, JSON |
| `tests/worked_example.rs` | a ten-packet conversation worked out by hand |
| `tests/shortcuts.rs` | lab leftovers that must not change the features |
| `tests/memory.rs` | bytes per flow |

Run the tests with `cargo test -p flagman-features`.
