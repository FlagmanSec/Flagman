import json

import pytest

from flagman_ml.flows.schema import SchemaError, parse_schema, read_footer
from flagman_ml.testing import fixture, rewrite


def test_the_footer_describes_the_file():
    footer = read_footer(fixture("lab-ssh-logins.parquet"))
    assert footer.schema.version == 1
    assert len(footer.schema.features) == 37
    assert footer.schema.metadata == (
        "flow_start_ms", "flow_end_ms", "src_ip", "src_port",
        "dst_ip", "dst_port", "end_reason",
    )
    assert footer.schema.feature_names[:3] == ["protocol", "dst_port_class", "tcp_outcome"]
    assert footer.schema.categories()["protocol"] == ("tcp", "udp", "icmp", "other")
    assert footer.flow_table["tcp_idle_secs"] == 120
    assert footer.capture == "lab-ssh-logins.pcap"
    assert footer.writer.startswith("flagmand ")


def test_features_that_may_describe_the_lab_say_why():
    watched = read_footer(fixture("lab-ssh-logins.parquet")).schema.watched()
    assert "network" in watched["duration_ms"]
    assert "packets_fwd" not in watched


def test_every_metadata_column_says_why_it_is_never_an_input():
    schema = read_footer(fixture("lab-ssh-logins.parquet")).schema
    reasons = dict(schema.reasons)
    assert set(reasons) == set(schema.metadata)
    assert "clock time" in reasons["flow_start_ms"]


def test_an_unknown_schema_version_is_refused(tmp_path):
    def version_2(footer):
        footer["flagman.schema"]["schema_version"] = 2
        footer["flagman.schema_version"] = "2"
        return footer

    path = rewrite(fixture("lab-ssh-logins.parquet"), tmp_path / "v2.parquet", footer=version_2)
    with pytest.raises(SchemaError, match="version 2 is not supported"):
        read_footer(path)


def test_a_parquet_file_without_the_footer_is_not_a_feature_file(tmp_path):
    path = rewrite(fixture("lab-ssh-logins.parquet"), tmp_path / "plain.parquet",
                   footer=lambda f: {"flagman.schema": f["flagman.schema"]})
    with pytest.raises(SchemaError, match="not a Flagman feature file"):
        read_footer(path)


def test_a_schema_with_an_unknown_kind_is_refused():
    text = json.dumps({
        "schema_version": 1,
        "features": [{"name": "x", "kind": "colour", "unit": "", "categories": None,
                      "watch": None}],
        "metadata": [],
    })
    with pytest.raises(SchemaError, match="unknown kind"):
        parse_schema(text)
