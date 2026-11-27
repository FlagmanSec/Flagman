"""Find the time offset between a capture and its ground truth.

Some datasets write their ground-truth times in local time without saying
which zone (CTU-13 and CIC-IDS2017 do not state it on their pages), while
captures count time in UTC. A wrong zone shifts every record by whole
hours, and almost nothing matches.

``offset_scores`` tries many offsets and counts, for each one, how many
flows find a matching record. The right offset stands out clearly; write
it into the mapping file as ``time_offset_ms``, with a note on how it was
found. Example: records written in local time three hours ahead of UTC
need ``time_offset_ms = -10800000`` (minus three hours).
"""

from __future__ import annotations

import pandas as pd

from flagman_ml.labels.match import key_pairs

HOUR_MS = 3_600_000


def candidate_offsets(max_hours: int = 14, step_minutes: int = 15) -> list[int]:
    """Offsets from -max_hours to +max_hours, every step_minutes.

    Fourteen hours covers every time zone on Earth; 15 minutes covers
    zones such as UTC+5:45.
    """
    step = step_minutes * 60_000
    count = max_hours * HOUR_MS // step
    return [i * step for i in range(-count, count + 1)]


def offset_scores(
    flows: pd.DataFrame, events: pd.DataFrame, offsets_ms: list[int], tolerance_ms: int = 0
) -> pd.DataFrame:
    """For each offset: flows that find a record, and records that find a flow.

    Sorted best first: most flows matched, then the smallest offset.
    """
    pairs = key_pairs(flows, events, tolerance_ms)
    rows = []
    for offset in offsets_ms:
        hit = pairs[(pairs["lo_ms"] <= offset) & (offset <= pairs["hi_ms"])]
        rows.append((offset, hit["flow"].nunique(), hit["event"].nunique()))
    scores = pd.DataFrame(rows, columns=["offset_ms", "flows_matched", "records_matched"])
    scores["distance"] = scores["offset_ms"].abs()
    scores = scores.sort_values(["flows_matched", "distance"], ascending=[False, True])
    return scores.drop(columns="distance").reset_index(drop=True)
