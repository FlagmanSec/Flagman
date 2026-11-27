"""Peak memory and time of training both models on N made-up flows.

Usage, from product/ml (one process for each N, so that each peak is its
own)::

    python experiments/campaign-sizing/train_memory.py 100000

Trains as ``python -m flagman_ml.models train`` does, with the default
settings (LightGBM on 2 threads): the classifier on N flows, its
temperature on N/4 calibration flows, the Isolation Forest on the normal
training flows, then the anomaly scores of the normal calibration flows.
80% of the made-up flows are normal. Prints JSON.
"""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # product/ml, for flagman_ml

from flagman_ml.models.anomaly import anomaly_scores, fit_anomaly  # noqa: E402
from flagman_ml.models.classifier import fit_classifier  # noqa: E402
from flagman_ml.models.data import anomaly_matrix  # noqa: E402
from flagman_ml.synthetic import synthetic_flows  # noqa: E402

SHARE = {"normal": 0.8, "scan": 0.08, "brute_force": 0.08, "dos": 0.04}


def main(flows: int) -> dict:
    start = time.perf_counter()
    train, schema = synthetic_flows({k: int(flows * v) for k, v in SHARE.items()}, seed=0)
    calibration, _ = synthetic_flows({k: int(flows * v / 4) for k, v in SHARE.items()}, seed=1)
    made = time.perf_counter()
    names = schema.feature_names
    model = fit_classifier(train[names], train["label"], calibration[names], calibration["label"])
    forest = fit_anomaly(anomaly_matrix(train.loc[train["label"] == "normal", names], schema))
    normal = calibration.loc[calibration["label"] == "normal", names]
    anomaly_scores(forest, anomaly_matrix(normal, schema))
    assert model.temperature > 0
    return {"train_flows": len(train), "calibration_flows": len(calibration),
            "seconds_to_make_flows": made - start, "seconds_to_train": time.perf_counter() - made,
            "peak_rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}


if __name__ == "__main__":
    print(json.dumps(main(int(sys.argv[1]))))
