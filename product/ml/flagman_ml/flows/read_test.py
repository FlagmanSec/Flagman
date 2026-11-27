import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pytest

from flagman_ml.flows.read import read_flows
from flagman_ml.flows.schema import SchemaError
from flagman_ml.testing import LAB_FILES, fixture, lab_paths, rewrite


def test_one_row_per_flow_named_by_file_and_row():
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    frame = flows.frame
    assert len(frame) == 24  # one per SSH connection
    assert list(frame.columns[:2]) == ["source", "row"]
    assert set(frame["source"]) == {"lab-ssh-logins.parquet"}
    assert frame["row"].tolist() == list(range(24))
    # The first connection: one wrong password, 14 packets to the server.
    first = frame.iloc[0]
    assert first["flow_start_ms"] == pd.Timestamp("2026-11-26 22:16:03.922Z").value // 10**6
    assert first["packets_fwd"] == 14
    assert first["dst_port"] == 22


def test_the_model_inputs_are_only_the_features():
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    inputs = flows.inputs()
    assert inputs.shape == (24, 37)
    assert not set(inputs.columns) & {"src_ip", "dst_ip", "dst_port", "flow_start_ms"}


def test_categories_keep_every_value_of_the_schema_in_order():
    flows = read_flows(fixture("lab-ssh-logins.parquet"))
    protocol = flows.frame["protocol"]
    assert list(protocol.cat.categories) == ["tcp", "udp", "icmp", "other"]
    assert set(protocol) == {"tcp"}  # this capture only has TCP


def test_several_files_are_stacked_and_remember_where_each_row_comes_from():
    flows = read_flows(*lab_paths())
    counts = flows.frame["source"].value_counts().to_dict()
    assert counts == LAB_FILES
    assert [f.capture for f in flows.files] == [
        "lab-attack-chain.pcap", "lab-normal-traffic.pcap", "lab-ssh-logins.pcap",
    ]
    assert all(len(f.sha256) == 64 for f in flows.files)


def test_two_files_with_the_same_name_are_refused(tmp_path):
    for folder in ("day1", "day2"):
        (tmp_path / folder).mkdir()
        rewrite(fixture("lab-ssh-logins.parquet"), tmp_path / folder / "flows.parquet")
    with pytest.raises(ValueError, match="two feature files are named flows.parquet"):
        read_flows(tmp_path / "day1/flows.parquet", tmp_path / "day2/flows.parquet")


def test_files_cut_with_other_flow_table_settings_are_not_mixed(tmp_path):
    def shorter_timeout(footer):
        footer["flagman.flow_table"] = footer["flagman.flow_table"].replace(
            '"tcp_idle_secs":120', '"tcp_idle_secs":60')
        return footer

    other = rewrite(fixture("lab-normal-traffic.parquet"), tmp_path / "other.parquet",
                    footer=shorter_timeout)
    with pytest.raises(SchemaError, match="other flow table settings"):
        read_flows(fixture("lab-ssh-logins.parquet"), other)


def test_a_category_value_outside_the_schema_is_refused(tmp_path):
    def sctp(table):
        index = table.schema.get_field_index("protocol")
        values = pc.replace_substring(table.column("protocol"), "tcp", "sctp")
        return table.set_column(index, pa.field("protocol", pa.string(), nullable=False), values)

    path = rewrite(fixture("lab-ssh-logins.parquet"), tmp_path / "sctp.parquet", table=sctp)
    with pytest.raises(SchemaError, match="values outside the schema: \\['sctp'\\]"):
        read_flows(path)
