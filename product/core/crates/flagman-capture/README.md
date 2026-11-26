# flagman-capture

Where packets come from.

| File | What it does |
|---|---|
| `source.rs` | The `PacketSource` trait shared by both sources |
| `live.rs` | `LiveSource`: an interface through libpcap, headers only (160 bytes), non-blocking with `poll()` ([ADR 0003](../../../docs/adr/0003-libpcap-capture-with-poll.md)) |
| `file.rs` | `FileSource`: a `.pcap` or `.pcapng` file, for replay and tests |
| `pcap_writer.rs` | Writes small `.pcap` files, for tests |

Opening an interface needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for
promiscuous mode), or `sudo`. Building needs `libpcap-dev`.

Tests: `cargo test -p flagman-capture` (they use files, not interfaces).
