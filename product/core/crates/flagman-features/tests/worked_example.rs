//! A readable example: the features of the ten-packet conversation in
//! `common/mod.rs`, worked out by hand.
//!
//! | ms    | from   | flags   | data bytes |
//! |-------|--------|---------|------------|
//! | 0     | client | SYN     | 0          |
//! | 12    | server | SYN-ACK | 0          |
//! | 13    | client | ACK     | 0          |
//! | 20    | server | PSH-ACK | 41         |
//! | 25    | client | PSH-ACK | 41         |
//! | 40    | client | PSH-ACK | 1,200      |
//! | 52    | server | PSH-ACK | 600        |
//! | 90    | client | ACK     | 0          |
//! | 3,100 | server | FIN-ACK | 0          |
//! | 3,101 | client | FIN-ACK | 0          |

mod common;

use common::{CONVERSATION, Capture, one_flow};
use flagman_core::flow::{FlowEnd, Protocol, TcpOutcome};
use flagman_features::PortClass;

/// Mean and population standard deviation, the plain two-pass way, to
/// check the running (one-pass) statistics against.
fn mean_std(values: &[f64]) -> (f64, f64) {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
    (mean, var.sqrt())
}

fn close(a: Option<f64>, b: f64) -> bool {
    a.is_some_and(|a| (a - b).abs() < 1e-9)
}

#[test]
fn the_features_of_a_short_conversation() {
    let flow = one_flow(&Capture::default(), &CONVERSATION);
    let f = flow.features;
    assert_eq!(flow.record.end, FlowEnd::Closed);

    assert_eq!(f.protocol, Protocol::Tcp);
    assert_eq!(f.dst_port_class, PortClass::WellKnown);
    assert_eq!(f.tcp_outcome, Some(TcpOutcome::Established));
    assert_eq!(f.duration_ms, 3_101);
    assert_eq!(f.first_response_ms, Some(12));

    // Client: 6 packets at 0, 13, 25, 40, 90 and 3,101 ms.
    assert_eq!((f.fwd.packets, f.fwd.payload_bytes), (6, 1_241));
    assert_eq!(
        (f.fwd.payload_min, f.fwd.payload_max),
        (Some(0), Some(1_200))
    );
    let (mean, std) = mean_std(&[0.0, 0.0, 41.0, 1_200.0, 0.0, 0.0]);
    assert!(close(f.fwd.payload_mean, mean) && close(f.fwd.payload_std, std));
    assert_eq!(
        (f.fwd.gap_min_ms, f.fwd.gap_max_ms),
        (Some(12), Some(3_011))
    );
    let (mean, std) = mean_std(&[13.0, 12.0, 15.0, 50.0, 3_011.0]);
    assert!(close(f.fwd.gap_mean_ms, mean) && close(f.fwd.gap_std_ms, std));
    assert_eq!(
        (f.fwd.syn, f.fwd.fin, f.fwd.rst, f.fwd.empty_packets),
        (1, 1, 0, 4)
    );

    // Server: 4 packets at 12, 20, 52 and 3,100 ms.
    assert_eq!((f.rev.packets, f.rev.payload_bytes), (4, 641));
    assert_eq!((f.rev.payload_min, f.rev.payload_max), (Some(0), Some(600)));
    assert_eq!((f.rev.gap_min_ms, f.rev.gap_max_ms), (Some(8), Some(3_048)));
    assert!(close(f.rev.gap_mean_ms, 3_088.0 / 3.0));
    assert_eq!(
        (f.rev.syn, f.rev.fin, f.rev.rst, f.rev.empty_packets),
        (1, 1, 0, 2)
    );

    assert!((f.packets_share_rev - 0.4).abs() < 1e-12);
    assert!(close(f.payload_share_rev, 641.0 / 1_882.0));
    assert!(!f.fwd.ttl_changed && !f.rev.ttl_changed);
}

#[test]
fn a_probe_that_gets_no_answer() {
    // One SYN and nothing back, like a scan of a filtered port.
    let flow = one_flow(&Capture::default(), &CONVERSATION[..1]);
    let f = flow.features;
    assert_eq!(f.tcp_outcome, Some(TcpOutcome::Unanswered));
    assert_eq!((f.fwd.packets, f.rev.packets), (1, 0));
    assert_eq!(f.first_response_ms, None);
    assert_eq!((f.rev.payload_mean, f.rev.gap_mean_ms), (None, None));
    assert_eq!(f.fwd.gap_mean_ms, None);
    assert_eq!(f.payload_share_rev, None);
    assert_eq!(f.packets_share_rev, 0.0);
}
