import numpy as np
import pandas as pd
import pytest

from flagman_ml.suricata.eve import ALERT_COLUMNS
from flagman_ml.suricata.match import counts, match_alerts, per_flow

# Four flows checked by hand: the same two ends used twice over time
# (rows 0 and 1), another source port (row 2), and a ping (row 3).
FLOWS = pd.DataFrame({
    "source": "made-up.parquet", "row": [0, 1, 2, 3],
    "protocol": ["tcp", "tcp", "tcp", "icmp"],
    "src_ip": "10.0.0.1", "src_port": [40000, 40000, 40001, 0],
    "dst_ip": "10.0.0.2", "dst_port": [22, 22, 22, 0],
    "flow_start_ms": [1000, 5000, 1000, 1000], "flow_end_ms": [2000, 6000, 2000, 2000]})


def alerts(*rows):
    """(time in µs, protocol, src, src port, dst, dst port, rule) per alert."""
    frame = pd.DataFrame([(n + 1, t, proto, src, sp, dst, dp, sid, "")
                          for n, (t, proto, src, sp, dst, dp, sid) in enumerate(rows)],
                         columns=ALERT_COLUMNS)
    return frame.astype({"src_port": "Int64", "dst_port": "Int64"})


def test_an_alert_goes_to_the_flow_that_holds_its_packet():
    found = match_alerts(FLOWS, alerts(
        (1_500_123, "tcp", "10.0.0.2", 22, "10.0.0.1", 40000, 1),  # answer side first
        (5_000_999, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 1),  # the later flow
        (2_000_999, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 1),  # 2000.999 ms is cut to 2000
        (1_999_000, "icmp", "10.0.0.1", None, "10.0.0.2", None, 1)))  # no ports
    assert found.tolist() == [0, 1, 0, 3]


def test_an_alert_that_no_flow_holds_is_unmatched():
    found = match_alerts(FLOWS, alerts(
        (3_000_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 1),  # between the two flows
        (1_500_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 23, 1),  # another port
        (1_500_000, "udp", "10.0.0.1", 40000, "10.0.0.2", 22, 1)))  # another protocol
    assert found.tolist() == [-1, -1, -1]


def test_a_tolerance_widens_the_flows_and_the_nearer_flow_wins():
    late = alerts((3_000_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 1))
    assert match_alerts(FLOWS, late, tolerance_ms=999).tolist() == [-1]
    assert match_alerts(FLOWS, late, tolerance_ms=1000).tolist() == [0]  # 1000 ms off
    assert match_alerts(FLOWS, late, tolerance_ms=5000).tolist() == [0]  # flow 1: 2000 ms
    with pytest.raises(ValueError):
        match_alerts(FLOWS, late, tolerance_ms=-1)


def test_each_flow_counts_its_alerts_and_lists_their_rules():
    found_alerts = alerts((1_500_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 5),
                          (1_600_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 3),
                          (1_700_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 5),
                          (9_000_000, "tcp", "10.0.0.1", 40000, "10.0.0.2", 22, 4))
    found = match_alerts(FLOWS, found_alerts)
    table = per_flow(FLOWS, found_alerts, found)
    assert table["suricata_alerts"].tolist() == [3, 0, 0, 0]
    assert table["suricata_signatures"].tolist() == ["3,5", "", "", ""]
    summary = counts(found_alerts, found, table)
    assert (summary["alerts"], summary["matched"], summary["unmatched"]) == (4, 3, 1)
    assert summary["flows_alerted"] == 1 and summary["unmatched_lines"] == [4]
    assert summary["alerts_by_rule"] == {"3": 1, "4": 1, "5": 2}


def test_no_alert_leaves_every_flow_without_one():
    table = per_flow(FLOWS, alerts(), match_alerts(FLOWS, alerts()))
    assert np.array_equal(table["suricata_alerts"], [0, 0, 0, 0])
