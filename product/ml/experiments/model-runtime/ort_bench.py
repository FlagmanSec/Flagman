"""ONNX Runtime on its own, in a fresh process, for measure.py.

Usage::

    python ort_bench.py classifier.onnx rows.f64 <columns> probabilities.f64

Loads the converted classifier on one thread, scores every flow one at a
time, then all of them in one batch, and prints JSON: the process memory
after importing ONNX Runtime and after loading the model, the load time,
and the time per flow both ways. Writes the batch's probabilities (as
float64, the format measure.py reads).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np


def rss_kb() -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return -1


def main(model: str, rows_file: str, columns: int, out: str) -> dict:
    rows = np.fromfile(rows_file).reshape(-1, columns).astype(np.float32)
    import onnxruntime

    after_import = rss_kb()
    options = onnxruntime.SessionOptions()
    options.intra_op_num_threads = options.inter_op_num_threads = 1
    start = time.perf_counter()
    session = onnxruntime.InferenceSession(model, options, providers=["CPUExecutionProvider"])
    load = time.perf_counter() - start
    after_load = rss_kb()
    name, wanted = session.get_inputs()[0].name, ["probabilities"]
    start = time.perf_counter()
    for row in rows:
        session.run(wanted, {name: row[None, :]})
    one = (time.perf_counter() - start) / len(rows) * 1e6
    start = time.perf_counter()
    probabilities = session.run(wanted, {name: rows})[0]
    batch = (time.perf_counter() - start) / len(rows) * 1e6
    probabilities.astype(np.float64).tofile(out)
    return {"rows": len(rows), "load_seconds": load, "rss_kb_after_import": after_import,
            "rss_kb_after_load": after_load, "microseconds_per_flow": one,
            "microseconds_per_flow_in_one_batch": batch}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4])))
