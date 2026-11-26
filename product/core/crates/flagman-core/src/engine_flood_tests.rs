//! A known limit, pinned by tests: a heavy flood of new connections can end
//! a login attempt early, while it waits for the server's answer. The flow
//! table then reports it as "evicted", and an evicted attempt never counts
//! (only refused or closed connections do). These tests show the mechanism
//! with a small table; phase 2 (pull request 2.6 in `phase-2-plan.md`)
//! measures the rate on real hardware with the default table.
//!
//! Every time comes from the frames' own timestamps, as in a replay; the
//! engine never reads the computer's clock, so the result is the same on
//! every machine.

use super::*;
use crate::alert::AlertKind;
use crate::testutil::{ACK, FIN_ACK, SYN, SYN_ACK, tcp_frame};

/// The quiet pause inside one failed SSH login: the server's delay after a
/// wrong password, 2.89 s in every single-password attempt of
/// `lab-ssh-logins.pcap`.
const PAUSE_MS: i64 = 2_900;
/// A small flow table, so that a small flood fills it.
const TABLE_SIZE: usize = 1_000;
const CLIENT: &str = "192.168.1.66";
const SERVER: &str = "192.168.1.10";

/// The packets of one failed SSH login starting at `start` ms: handshake,
/// password, the server's pause, then its refusal and the close.
fn failed_login(start: i64, port: u16) -> Vec<(i64, Vec<u8>)> {
    vec![
        (start, tcp_frame(CLIENT, port, SERVER, 22, SYN)),
        (start + 1, tcp_frame(SERVER, 22, CLIENT, port, SYN_ACK)),
        (start + 2, tcp_frame(CLIENT, port, SERVER, 22, ACK)),
        (start + 100, tcp_frame(CLIENT, port, SERVER, 22, ACK)),
        (
            start + 100 + PAUSE_MS,
            tcp_frame(SERVER, 22, CLIENT, port, ACK),
        ),
        (
            start + 101 + PAUSE_MS,
            tcp_frame(SERVER, 22, CLIENT, port, FIN_ACK),
        ),
        (
            start + 102 + PAUSE_MS,
            tcp_frame(CLIENT, port, SERVER, 22, FIN_ACK),
        ),
    ]
}

/// Replays 10 failed logins, one every 3.1 s like in the lab recording,
/// while one-packet connections from made-up addresses arrive at
/// `flood_per_sec`. Returns whether a login attempts alert came out, and how
/// many flows the full table had to end early.
fn logins_seen_under_flood(flood_per_sec: i64) -> (bool, u64) {
    let config = EngineConfig {
        flows: FlowTableConfig {
            max_flows: TABLE_SIZE,
            ..FlowTableConfig::default()
        },
        ..EngineConfig::default()
    };
    let mut engine = Engine::new(&config, StartIds::default());
    let mut packets: Vec<(i64, Vec<u8>)> = Vec::new();
    for attempt in 0..10u16 {
        packets.extend(failed_login(i64::from(attempt) * 3_100, 40_000 + attempt));
    }
    let duration_ms = 32_000;
    for i in 0..flood_per_sec * duration_ms / 1_000 {
        let fake = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        let ms = i * 1_000 / flood_per_sec;
        packets.push((ms, tcp_frame(&fake, 40_000, SERVER, 80, SYN)));
    }
    // A stable sort keeps each login's packets in order.
    packets.sort_by_key(|(ms, _)| *ms);

    let mut out = Vec::new();
    for (ms, frame) in packets {
        let length = u32::try_from(frame.len()).expect("small frame");
        engine.process_frame(LinkType::Ethernet, Timestamp(ms), length, &frame, &mut out);
    }
    engine.finish(&mut out);
    let seen = out.iter().any(
        |output| matches!(output, Output::Alert(alert) if alert.kind == AlertKind::BruteForce),
    );
    (seen, engine.counters().flows_evicted)
}

#[test]
fn a_light_flood_does_not_hide_login_attempts() {
    // 200 new connections per second: the table of 1,000 holds the last 5 s
    // of them, longer than the 2.9 s pause, so each attempt is still there
    // when it closes.
    let (seen, evicted) = logins_seen_under_flood(200);
    assert!(evicted > 0, "the table was full");
    assert!(seen);
}

#[test]
fn known_limit_a_heavy_flood_hides_login_attempts() {
    // 1,000 per second: the table only holds the last second, so each
    // attempt is pushed out during its pause and ends as "evicted". A flow
    // is pushed out once it has been quiet for between 0.9 and 1 times
    // (table size / flood rate), so with the default table of 100,000 flows
    // the same happens above about 31,000 new connections per second
    // (0.9 x 100,000 / 2.9 s).
    let (seen, evicted) = logins_seen_under_flood(1_000);
    assert!(evicted > 0, "the table was full");
    assert!(
        !seen,
        "the limit changed: update known limit 8 in docs/changes/phase-1-linux-pro.md, \
         the threat model, and this test"
    );
}

/// Prints, for a few flood rates, whether the logins were still seen. With
/// the table of 1,000 flows and the 2.9 s pause, the last rate that keeps
/// them is 310 per second (0.9 x 1,000 / 2.9), and 320 per second loses
/// them. Run it with:
/// `cargo test -p flagman-core flood_rate -- --ignored --nocapture`
#[test]
#[ignore = "a measurement, not a check; run it by hand"]
fn measure_the_flood_rate_where_logins_are_lost() {
    for rate in [250, 300, 310, 320, 350, 400, 1_000] {
        let (seen, evicted) = logins_seen_under_flood(rate);
        println!("{rate} new connections per second: logins seen {seen}, flows evicted {evicted}");
    }
}
