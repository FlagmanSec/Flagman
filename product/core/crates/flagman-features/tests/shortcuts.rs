//! The second CS395 lesson, as tests: what a lab leaves in its recordings
//! (addresses, ports, TTL, the capture's link layer, the clock time, the
//! sender's TCP options) must not change a single feature. Each test changes
//! one of them and expects exactly the same feature vector.

mod common;

use common::{Addresses, CONVERSATION, Capture, Link, features_of, one_flow, run};
use flagman_features::FlowFeatures;

fn features(capture: Capture) -> FlowFeatures {
    one_flow(&capture, &CONVERSATION).features
}

fn reference() -> FlowFeatures {
    features(Capture::default())
}

#[test]
fn addresses_do_not_change_the_features() {
    let other_network = Capture {
        addresses: Addresses::V4([10, 9, 8, 7], [172, 16, 5, 4]),
        ..Capture::default()
    };
    assert_eq!(features(other_network), reference());
    let mut client = [0u8; 16];
    let mut server = [0u8; 16];
    client[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    server[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    client[15] = 1;
    server[15] = 2;
    let ipv6 = Capture {
        addresses: Addresses::V6(client, server),
        ..Capture::default()
    };
    assert_eq!(features(ipv6), reference());
}

#[test]
fn exact_ports_do_not_change_the_features() {
    let other_ports = Capture {
        client_port: 51_515,
        server_port: 443,
        ..Capture::default()
    };
    assert_eq!(features(other_ports), reference());
}

#[test]
fn a_steady_ttl_is_invisible_whatever_its_value() {
    // 64 (Linux), 128 (Windows), 254 (the CS395 shortcut), 1 (last hop).
    for (client_ttl, server_ttl) in [(128, 128), (254, 63), (255, 1)] {
        let capture = Capture {
            client_ttl,
            server_ttl,
            ..Capture::default()
        };
        assert_eq!(
            features(capture),
            reference(),
            "TTL {client_ttl}/{server_ttl}"
        );
    }
}

#[test]
fn only_a_ttl_change_inside_the_flow_shows() {
    let before = Capture::default();
    let after = Capture {
        server_ttl: 50,
        ..Capture::default()
    };
    let mut frames = before.frames(&CONVERSATION[..6]);
    frames.extend(after.frames(&CONVERSATION[6..]));
    let changed = run(before.link_type(), frames).remove(0).features;
    let mut expected = reference();
    expected.rev.ttl_changed = true;
    assert_eq!(changed, expected);
}

#[test]
fn the_link_layer_does_not_change_the_features() {
    for link in [Link::EthernetVlan, Link::RawIp, Link::LinuxCooked] {
        let capture = Capture {
            link,
            ..Capture::default()
        };
        assert_eq!(features(capture), reference(), "{link:?}");
    }
}

#[test]
fn the_clock_time_does_not_change_the_features() {
    let later = Capture {
        start_ms: Capture::default().start_ms + 400 * 86_400_000,
        ..Capture::default()
    };
    assert_eq!(features(later), reference());
}

#[test]
fn the_senders_tcp_options_do_not_change_the_features() {
    let linux_like = Capture {
        tcp_timestamps: true,
        ..Capture::default()
    };
    assert_eq!(features(linux_like), reference());
}

#[test]
fn the_record_still_says_who_and_when_for_labelling() {
    let flows = features_of(&Capture::default(), &CONVERSATION);
    let record = flows[0].record;
    assert_eq!(record.initiator.port, 40_000);
    assert_eq!(record.responder.port, 22);
    assert_eq!(record.first_seen.millis(), Capture::default().start_ms);
}
