import calendar
import gzip
import json

import pandas as pd
import pytest

from flagman_ml.suricata.eve import EveError, read_alerts, time_us
from flagman_ml.testing import fixture

# Hand-written lines, in the format of the EVE files that Suricata 7.0.3
# wrote for the lab captures (fixtures/suricata), for the cases those
# recordings do not have: other event types, alerts without ports, other
# protocols, and broken lines.
HAND_WRITTEN = [
    {"timestamp": "2026-11-26T22:16:19.441084+0000", "event_type": "flow",
     "src_ip": "192.168.77.66"},
    {"timestamp": "2026-11-26T23:16:19.441084+0100", "event_type": "alert",
     "src_ip": "192.168.77.66", "dest_ip": "192.168.77.10", "proto": "ICMP",
     "alert": {"signature_id": 7, "signature": "hand-written"}},
    {"timestamp": "2026-11-26T22:16:19.000001+0000", "event_type": "alert",
     "src_ip": "fe80::1", "dest_ip": "fe80::2", "proto": "IPv6-ICMP",
     "alert": {"signature_id": 8}},
    {"timestamp": "2026-11-26T22:16:19.000002+0000", "event_type": "alert",
     "src_ip": "10.0.0.1", "src_port": 1, "dest_ip": "10.0.0.2", "dest_port": 2,
     "proto": "SCTP", "alert": {"signature_id": 9}},
]


def write(path, records, broken=None):
    lines = [json.dumps(record) for record in records]
    if broken is not None:
        lines.insert(1, broken)
    path.write_text("\n".join(lines) + "\n\n", encoding="utf-8")
    return path


def test_the_alerts_that_suricata_wrote_for_the_lab_ssh_logins():
    alerts = read_alerts(fixture("suricata/lab-ssh-logins/eve.json.gz"))
    assert len(alerts) == 9
    assert set(alerts["signature_id"]) == {1000002}
    assert set(alerts["protocol"]) == {"tcp"} and set(alerts["dst_port"]) == {22}
    assert alerts["time_us"].iloc[0] == time_us("2026-11-26T22:16:19.441084+0000")
    assert alerts["time_us"].is_monotonic_increasing  # one thread: packet order


def test_times_are_microseconds_since_1970_in_utc():
    expected = calendar.timegm((2026, 11, 26, 22, 16, 19)) * 10**6 + 441084
    assert time_us("2026-11-26T22:16:19.441084+0000") == expected
    assert time_us("2026-11-26T23:16:19.441084+0100") == expected  # same moment, other zone


def test_only_alert_lines_are_read_and_protocols_take_flagman_names(tmp_path):
    alerts = read_alerts(write(tmp_path / "eve.json", HAND_WRITTEN))
    assert list(alerts["line"]) == [2, 3, 4]
    assert list(alerts["protocol"]) == ["icmp", "icmp", "other"]
    assert alerts["src_port"].isna().tolist() == [True, True, False]
    assert alerts["time_us"].iloc[0] == time_us("2026-11-26T22:16:19.441084+0000")


def test_a_gzip_file_reads_like_the_plain_one(tmp_path):
    plain = write(tmp_path / "eve.json", HAND_WRITTEN)
    packed = tmp_path / "eve.json.gz"
    packed.write_bytes(gzip.compress(plain.read_bytes()))
    pd.testing.assert_frame_equal(read_alerts(plain), read_alerts(packed))


@pytest.mark.parametrize("broken, message", [
    ("{not json", "line 2 is not JSON"),
    (json.dumps({"event_type": "alert", "timestamp": "2026-11-26T22:16:19.000001+0000",
                 "src_ip": "a", "dest_ip": "b", "proto": "TCP", "alert": {}}),
     "line 2 is not a complete alert"),
    (json.dumps({"event_type": "alert", "timestamp": "yesterday", "src_ip": "a",
                 "dest_ip": "b", "proto": "TCP", "alert": {"signature_id": 1}}),
     "line 2 is not a complete alert"),
    (json.dumps({"event_type": "alert", "timestamp": "2026-11-26T22:16:19.000001+0000",
                 "src_ip": "a", "src_port": 70000, "dest_ip": "b", "proto": "TCP",
                 "alert": {"signature_id": 1}}), "line 2 is not a complete alert"),
])
def test_a_broken_line_stops_the_reading_and_is_named(tmp_path, broken, message):
    with pytest.raises(EveError, match=message):
        read_alerts(write(tmp_path / "eve.json", HAND_WRITTEN, broken))
