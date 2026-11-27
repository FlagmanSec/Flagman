"""Use a trained bundle on feature files: one decision per flow.

The bundle refuses flows extracted with another feature schema or other
flow table settings: a model only sees flows cut the way it was trained.

Example::

    models, metadata = load_bundle("results/models/lab")
    predictions = predict(models, metadata, read_flows("day3.parquet"))
    predictions["decision"].value_counts()
"""

from __future__ import annotations

import pandas as pd

from flagman_ml.flows import Flows
from flagman_ml.models.anomaly import anomaly_scores
from flagman_ml.models.bundle import schema_record
from flagman_ml.models.classifier import probabilities
from flagman_ml.models.data import anomaly_matrix
from flagman_ml.models.openset import decide

KEY = "flagman.predictions"  # the provenance key in a predictions file's footer


class IncompatibleFlows(ValueError):
    """Flows that the bundle was not trained for."""


def check_compatible(flows: Flows, metadata: dict) -> None:
    if schema_record(flows.schema) != metadata["schema"]:
        raise IncompatibleFlows("the feature schema differs from the one the model was trained on")
    if flows.flow_table != metadata["flow_table"]:
        raise IncompatibleFlows("the flows were cut with other flow table settings than the "
                                f"training flows ({flows.flow_table} != {metadata['flow_table']})")


def predict(models: dict, metadata: dict, flows: Flows) -> pd.DataFrame:
    """source, row, the decision, and the calibrated probability of each class."""
    check_compatible(flows, metadata)
    inputs = flows.inputs()
    proba = probabilities(models["classifier"], inputs)
    anomaly = anomaly_scores(models["forest"], anomaly_matrix(inputs, flows.schema))
    decisions = decide(proba, anomaly, models["thresholds"]).drop(columns="p_normal")
    per_class = proba.add_prefix("p_")  # p_normal is among them
    return pd.concat([flows.frame[["source", "row"]], decisions, per_class], axis=1)
