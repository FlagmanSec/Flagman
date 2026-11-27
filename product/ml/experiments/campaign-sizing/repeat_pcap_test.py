"""An example: two copies of the lab's normal traffic make one capture of
twice the packets, the second copy 600 s after the first."""

from __future__ import annotations

from pathlib import Path

from repeat_pcap import GAP_US, packets, repeat

LAB = Path(__file__).resolve().parents[3] / "core/testdata/pcap/lab-normal-traffic.pcap"


def test_two_copies_six_hundred_seconds_apart(tmp_path):
    out = tmp_path / "twice.pcap"
    assert repeat([LAB], 2, out) == 1000  # the lab capture holds 500 packets
    times = [moment for moment, _, _ in packets(out)]
    assert times == sorted(times)
    assert times[500] - times[0] == GAP_US
    assert out.stat().st_size == 2 * LAB.stat().st_size - 24  # one file header
