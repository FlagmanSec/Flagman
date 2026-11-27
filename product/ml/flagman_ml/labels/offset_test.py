from flagman_ml.flows import read_flows
from flagman_ml.labels import load_mapping, read_ground_truth
from flagman_ml.labels.offset import HOUR_MS, candidate_offsets, offset_scores
from flagman_ml.testing import DATA, fixture, lab_paths


def test_offsets_cover_every_time_zone_in_quarter_hours():
    offsets = candidate_offsets()
    assert offsets[0] == -14 * HOUR_MS and offsets[-1] == 14 * HOUR_MS
    assert 0 in offsets and 5 * HOUR_MS + 45 * 60_000 in offsets  # UTC+5:45
    assert len(offsets) == 14 * 4 * 2 + 1


def test_a_ground_truth_written_three_hours_ahead_is_found():
    mapping = load_mapping(DATA / "labels/lab.toml")
    events = read_ground_truth(mapping.format, fixture("lab-ground-truth.csv"))
    # As if the dataset wrote its times in local time, three hours ahead of UTC.
    ahead = events.assign(start_ms=events["start_ms"] + 3 * HOUR_MS,
                          end_ms=events["end_ms"] + 3 * HOUR_MS)
    flows = read_flows(*lab_paths()).frame
    scores = offset_scores(flows, ahead, candidate_offsets())
    best = scores.iloc[0]
    assert best["offset_ms"] == -3 * HOUR_MS  # move the records back by three hours
    assert best["flows_matched"] == 1015 + 24  # every flow of the two attack captures
    assert scores.iloc[1]["flows_matched"] == 0  # and no other offset comes close
