//! Flagman core: the detection logic, with no network or file I/O.
//!
//! One packet travels through these modules in this order:
//!
//! 1. [`packet`] turns raw bytes into a [`packet::PacketMeta`] (addresses, ports, flags).
//! 2. [`flow`] groups packets into conversations ([`flow::FlowRecord`]).
//! 3. [`detect`] watches new flows and ARP requests for scans, sweeps and brute force.
//! 4. [`incident`] groups the resulting [`alert::Alert`]s per attacker into incidents.
//!
//! [`engine::Engine`] wires the four steps together. Everything here is plain,
//! synchronous Rust, so it can be tested by feeding packets in and checking what comes out.

pub mod alert;
pub mod detect;
pub mod engine;
pub mod flow;
pub mod health;
pub mod ids;
pub mod incident;
pub mod net;
pub mod packet;
pub mod time;
pub mod traffic;

#[cfg(test)]
pub(crate) mod testutil;
