"""Each reader on a small hand-written sample in the dataset's documented
columns. Addresses come from the ranges kept for documentation (RFC 5737)
and every value is made up: these are not records of the real datasets."""

import pandas as pd
import pytest

from flagman_ml.labels.formats import read_ground_truth


def ms(text):
    return pd.Timestamp(text).value // 10**6


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


UNSW = """\
Start time,Last time,Attack category,Attack subcategory,Protocol,Source IP,Source Port,Destination IP,Destination Port,Attack Name,Attack Reference,.
1421927414,1421927416,Reconnaissance,HTTP,tcp,192.0.2.10,13284,198.51.100.16,80,made-up name,-,
1421927420,1421927420, Fuzzers ,FTP,TCP,192.0.2.10,0x000b,198.51.100.16,-,made-up name,-,
1421927421,1421927425,Exploits,Miscellaneous,ospf,192.0.2.10,0,198.51.100.16,0,made-up name,-,
"""


def test_unsw_times_are_seconds_and_cover_the_whole_last_second(tmp_path):
    events = read_ground_truth("unsw_gt", write(tmp_path, "UNSW-NB15_GT.csv", UNSW))
    first = events.iloc[0]
    assert first["start_ms"] == 1421927414000
    assert first["end_ms"] == 1421927416999
    assert (first["src_port"], first["dst_port"], first["label"]) == (13284, 80, "Reconnaissance")
    assert events["record"].tolist() == [1, 2, 3]


def test_unsw_labels_are_trimmed_and_ports_may_be_hexadecimal_or_empty(tmp_path):
    events = read_ground_truth("unsw_gt", write(tmp_path, "gt.csv", UNSW))
    second = events.iloc[1]
    assert second["label"] == "Fuzzers"
    assert second["protocol"] == "tcp"
    assert second["src_port"] == 11  # 0x000b
    assert pd.isna(second["dst_port"])  # "-" means any port


def test_other_protocols_never_compare_ports(tmp_path):
    third = read_ground_truth("unsw_gt", write(tmp_path, "gt.csv", UNSW)).iloc[2]
    assert third["protocol"] == "other"
    assert pd.isna(third["src_port"]) and pd.isna(third["dst_port"])


def test_unsw_times_that_are_not_seconds_ask_for_a_time_format(tmp_path):
    text = UNSW.replace("1421927414,1421927416", "22/01/2015 10:30:14,22/01/2015 10:30:16")
    with pytest.raises(ValueError, match="set time_format"):
        read_ground_truth("unsw_gt", write(tmp_path, "gt.csv", text))


CIC = """\
Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Fwd Packets, Label
192.0.2.10-198.51.100.5-51234-80-6,192.0.2.10,51234,198.51.100.5,80,6,04/07/2017 09:20:01,2500000,3,BENIGN
192.0.2.10-198.51.100.5-51240-21-6,192.0.2.10,51240,198.51.100.5,21,6,04/07/2017 09:20:05,1000,1,FTP-Patator
"""


def test_cic_flows_use_the_mapping_time_format_and_zone(tmp_path):
    events = read_ground_truth("cic_flows", write(tmp_path, "tuesday.csv", CIC),
                               time_zone="America/Halifax", time_format="%d/%m/%Y %H:%M:%S")
    first = events.iloc[0]
    # 09:20:01 in Halifax summer time (UTC-3) is 12:20:01 UTC; the flow lasted 2.5 s.
    assert first["start_ms"] == ms("2017-07-04 12:20:01Z")
    assert first["end_ms"] == ms("2017-07-04 12:20:03.500Z")
    assert (first["protocol"], first["label"]) == ("tcp", "BENIGN")
    assert events.iloc[1]["label"] == "FTP-Patator"


def test_cic_flows_without_a_time_format_are_refused(tmp_path):
    with pytest.raises(ValueError, match="needs time_format"):
        read_ground_truth("cic_flows", write(tmp_path, "tuesday.csv", CIC))


CTU = """\
StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label
2011/08/18 10:19:13.328000,0.002000,udp,192.0.2.20,1025,  <->,198.51.100.53,53,CON,0,0,2,203,64,flow=From-Botnet-V52-1-UDP-DNS
2011/08/18 10:19:14.000500,3.500000,tcp,192.0.2.20,1027,   ->,203.0.113.80,80,SRPA_SPA,0,0,10,1500,600,flow=Background-TCP-Established
2011/08/18 10:19:15.100000,0.000000,icmp,192.0.2.20,0x0008,   ->,203.0.113.1,0x0000,ECO,0,0,1,98,98,flow=From-Botnet-V52-1-ICMP
"""


def test_ctu_binetflow_local_times_durations_and_icmp(tmp_path):
    events = read_ground_truth("ctu_binetflow", write(tmp_path, "c.binetflow", CTU),
                               time_zone="Europe/Prague")
    dns, web, ping = (events.iloc[i] for i in range(3))
    # 10:19:13.328 in Prague summer time (UTC+2) is 08:19:13.328 UTC.
    assert dns["start_ms"] == ms("2011-08-18 08:19:13.328Z")
    assert dns["end_ms"] == ms("2011-08-18 08:19:13.330Z")
    # Starts at .0005 s: the window starts on the millisecond and ends rounded up.
    assert (web["start_ms"], web["end_ms"]) == (ms("2011-08-18 08:19:14Z"),
                                                ms("2011-08-18 08:19:17.501Z"))
    assert ping["protocol"] == "icmp" and pd.isna(ping["src_port"])
    assert dns["label"] == "flow=From-Botnet-V52-1-UDP-DNS"


def test_records_that_end_before_they_start_are_refused(tmp_path):
    text = ("start_utc,end_utc,protocol,src_ip,src_port,dst_ip,dst_port,label,note\n"
            "2026-11-26T18:00:05Z,2026-11-26T18:00:01Z,tcp,192.0.2.1,,192.0.2.2,22,x,\n")
    with pytest.raises(ValueError, match="end before they start: \\[1\\]"):
        read_ground_truth("lab_csv", write(tmp_path, "lab.csv", text))
