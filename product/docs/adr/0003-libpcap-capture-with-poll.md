# 0003. Capture with libpcap, non-blocking, waiting with `poll()`

Status: accepted
Date: 2026-11-26

## Context

The sensor needs every packet header from one interface, on Linux PCs now
and on OpenWrt later. libpcap is the standard capture library (tcpdump and
Wireshark use it) and is packaged for both.

The engine has timers: flows end after a quiet period, alerts are updated
every few seconds and closed after a quiet period, and Ctrl-C must stop the
program. These timers only run when the capture loop gets control back. On
Linux, libpcap's read timeout does not fire while no packet arrives at all
(a known behaviour of its TPACKET_V3 capture mode). In testing, a quiet
network made Flagman unable to stop.

## Decision

- Capture through the `pcap` crate (libpcap), headers only (160 bytes), in
  promiscuous mode.
- Put the capture in non-blocking mode and wait for packets ourselves with
  `poll()` (through the `rustix` crate, which wraps it safely), with a
  250 ms timeout. The loop therefore gets control at least four times a
  second, packets or not.
- Replay reads `.pcap` files through the same `PacketSource` trait, and uses
  packet timestamps as its clock.

## Consequences

- Stopping is prompt, and timers fire on time on a quiet network.
- Kernel drops are read from libpcap's statistics and shown on the dashboard.
- Building needs `libpcap-dev`.
- Very high packet rates may later need AF_PACKET with a memory-mapped ring
  shared across threads, or eBPF. Not needed for a home network.

## Alternatives considered

- **Raw AF_PACKET sockets ourselves**: no libpcap dependency, but more code,
  and some of it `unsafe`.
- **A second thread that wakes the capture**: more moving parts than `poll()`.
- **eBPF/XDP**: very fast, but complex, and not needed at home speeds.
