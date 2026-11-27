import dataclasses

from flagman_ml.flows import read_flows
from flagman_ml.labels import label_flows, load_mapping, read_ground_truth
from flagman_ml.testing import DATA, fixture


def lab(tolerance_ms=None):
    mapping = load_mapping(DATA / "labels/lab.toml")
    if tolerance_ms is not None:
        mapping = dataclasses.replace(mapping, time_tolerance_ms=tolerance_ms)
    return mapping, read_ground_truth(mapping.format, fixture("lab-ground-truth.csv"))


def test_the_ssh_capture_gets_one_label_per_connection():
    mapping, events = lab()
    flows = read_flows(fixture("lab-ssh-logins.parquet")).frame
    labels, report = label_flows(flows, events, mapping)
    # Steps 1 and 2: 13 connections guessing passwords. Steps 3 to 5: 11 normal.
    assert labels["label"].tolist() == ["brute_force"] * 13 + ["normal"] * 11
    first = labels.iloc[0]
    assert first["dataset_label"] == "ssh_password_guessing"
    assert first["record"] == "lab-ground-truth.csv:3"  # the third row of the file
    assert report["labels"] == {"brute_force": 13, "normal": 11}
    assert report["conflicts"] == 0
    assert (report["records_in_span"], report["records_used"]) == (5, 5)


def test_the_attack_chain_is_a_port_scan_then_password_guessing():
    mapping, events = lab()
    flows = read_flows(fixture("lab-attack-chain.parquet")).frame
    labels, report = label_flows(flows, events, mapping)
    assert report["labels"] == {"brute_force": 15, "scan": 1000}
    # The scan's SYN to port 22 belongs to the scan, not to the guessing.
    scan_ssh = labels[(flows["dst_port"] == 22) & (flows["tcp_outcome"] == "half_open")]
    assert scan_ssh["label"].tolist() == ["scan"]


def test_flows_that_no_record_describes_get_the_default_label():
    mapping, events = lab()
    flows = read_flows(fixture("lab-normal-traffic.parquet")).frame
    labels, report = label_flows(flows, events, mapping)
    assert set(labels["label"]) == {"normal"}
    assert labels["record"].isna().all()
    assert (report["matched"], report["unmatched"], report["records_in_span"]) == (0, 42, 0)


def test_a_wide_tolerance_shows_conflicts_but_the_longest_overlap_still_wins():
    mapping, events = lab(tolerance_ms=1000)
    flows = read_flows(fixture("lab-ssh-logins.parquet")).frame
    labels, report = label_flows(flows, events, mapping)
    # Steps 2 and 3 are 9 ms apart: with 1 s of tolerance, the connections at
    # the boundary match both steps. They are marked, and keep the right label.
    assert report["conflicts"] == 2
    assert labels["label"].tolist() == ["brute_force"] * 13 + ["normal"] * 11
