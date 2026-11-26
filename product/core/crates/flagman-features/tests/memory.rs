//! How much memory one flow costs, with and without features, for the
//! router's memory budget (phase 2, item 2.6).
//!
//! A counting allocator measures what the flow table really allocates for
//! 100,000 flows (the default limit), hash table spare room included. This
//! file holds a single test, so no other test allocates at the same time.
//! Print the numbers with:
//! `cargo test -p flagman-features --test memory -- --nocapture`

use flagman_core::flow::{FlowExtra, FlowTable, FlowTableConfig};
use flagman_core::packet::{IpPacket, TcpFlags, Transport};
use flagman_core::time::Timestamp;
use flagman_features::FeatureState;
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The system allocator, plus a running total of the bytes in use.
struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is passed unchanged to the system allocator; only a
// counter is updated next to it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            IN_USE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const FLOWS: u32 = 100_000;

/// Bytes allocated per flow by a table holding `FLOWS` one-packet flows.
fn bytes_per_flow<X: FlowExtra>() -> usize {
    let before = IN_USE.load(Ordering::Relaxed);
    let mut table: FlowTable<X> = FlowTable::with_extra(FlowTableConfig::default());
    let mut ended = Vec::new();
    for i in 0..FLOWS {
        let packet = IpPacket {
            src: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
            dst: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            transport: Transport::Tcp {
                src_port: 40_000,
                dst_port: 22,
                flags: TcpFlags {
                    syn: true,
                    ..TcpFlags::default()
                },
            },
            ttl: 64,
            payload_len: 0,
        };
        table.observe(Timestamp(i64::from(i)), 60, &packet, &mut ended);
    }
    assert_eq!(table.active(), FLOWS as usize);
    assert!(ended.is_empty());
    let used = IN_USE.load(Ordering::Relaxed) - before;
    drop(table);
    used / FLOWS as usize
}

#[test]
fn memory_per_flow_with_and_without_features() {
    let plain = bytes_per_flow::<()>();
    let with_features = bytes_per_flow::<FeatureState>();
    let state = std::mem::size_of::<FeatureState>();
    println!("flow table, sensor as today: {plain} bytes per flow");
    println!("flow table with features:    {with_features} bytes per flow");
    println!("feature state alone:         {state} bytes");
    let megabytes = with_features as f64 * f64::from(FLOWS) / 1_000_000.0;
    println!("{FLOWS} flows with features:  {megabytes:.1} MB");
    // The budget written in the README: features add at most 300 bytes per
    // flow (262 when this was written: 200 for the state, the rest is the
    // hash table's spare room).
    assert!(with_features - plain <= 300, "{with_features} - {plain}");
}
