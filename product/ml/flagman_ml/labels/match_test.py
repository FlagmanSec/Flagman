"""Small hand-made examples of the matching rules (see match.py)."""

import pandas as pd

from flagman_ml.labels.match import best_match, candidate_pairs

T = 1_800_000_000_000  # some moment, in milliseconds since 1970


def flow(src="10.0.0.1", sport=40000, dst="10.0.0.2", dport=22, start=T, end=T + 500,
         protocol="tcp"):
    return {"protocol": protocol, "src_ip": src, "src_port": sport, "dst_ip": dst,
            "dst_port": dport, "flow_start_ms": start, "flow_end_ms": end}


def record(src="10.0.0.1", sport=None, dst="10.0.0.2", dport=22, start=T, end=T + 1000,
           protocol="tcp", label="attack"):
    return {"protocol": protocol, "src_ip": src, "src_port": sport, "dst_ip": dst,
            "dst_port": dport, "start_ms": start, "end_ms": end, "label": label}


def frames(flows, records):
    events = pd.DataFrame(records).astype({"src_port": "Int64", "dst_port": "Int64"})
    return pd.DataFrame(flows), events


def matched(flows, records, offset=0, tolerance=0):
    f, e = frames(flows, records)
    return sorted(set(candidate_pairs(f, e, offset, tolerance)["flow"]))


def test_a_record_matches_its_flow_in_either_direction():
    forward = flow()
    backward = flow(src="10.0.0.2", sport=22, dst="10.0.0.1", dport=40000)
    assert matched([forward, backward], [record()]) == [0, 1]


def test_an_empty_port_matches_any_port_but_a_given_port_must_agree():
    ssh, web = flow(dport=22), flow(dport=80)
    assert matched([ssh, web], [record(dport=22)]) == [0]
    assert matched([ssh, web], [record(dport=None)]) == [0, 1]


def test_records_with_both_ports_need_the_exact_conversation():
    exact = record(sport=40000, dport=22)
    assert matched([flow(sport=40000), flow(sport=40001)], [exact]) == [0]


def test_the_protocol_must_agree_when_the_record_gives_one():
    udp = flow(protocol="udp")
    assert matched([udp], [record(protocol="tcp")]) == []
    assert matched([udp], [record(protocol=None)]) == [0]


def test_times_must_overlap_within_the_tolerance():
    late = flow(start=T + 1500, end=T + 2000)  # starts 500 ms after the record ends
    assert matched([late], [record()]) == []
    assert matched([late], [record()], tolerance=500) == [0]


def test_the_offset_moves_the_record_window():
    one_hour_later = flow(start=T + 3_600_000, end=T + 3_600_500)
    assert matched([one_hour_later], [record()]) == []
    assert matched([one_hour_later], [record()], offset=3_600_000) == [0]


def test_the_most_specific_record_wins_and_disagreement_is_a_conflict():
    f, e = frames([flow(dport=22)], [record(dport=None, label="scan"),
                                     record(dport=22, label="guess")])
    pairs = candidate_pairs(f, e)
    best = best_match(pairs, e["label"].to_numpy(), flows=1)
    assert best.loc[0, "event"] == 1  # the record that names the port
    assert best.loc[0, "candidates"] == 2
    assert best.loc[0, "conflict"]


def test_among_equals_the_longest_overlap_wins():
    f, e = frames([flow(start=T, end=T + 1000)],
                  [record(start=T - 5000, end=T + 100, label="a"),
                   record(start=T + 200, end=T + 5000, label="a")])
    best = best_match(candidate_pairs(f, e), e["label"].to_numpy(), flows=1)
    assert best.loc[0, "event"] == 1  # overlaps 800 ms instead of 100
    assert not best.loc[0, "conflict"]  # both say the same class


def test_a_flow_without_a_record_gets_none():
    f, e = frames([flow(dst="10.0.0.9")], [record()])
    best = best_match(candidate_pairs(f, e), e["label"].to_numpy(), flows=1)
    assert best.loc[0, "event"] == -1 and best.loc[0, "candidates"] == 0
