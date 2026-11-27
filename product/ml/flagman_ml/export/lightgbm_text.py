"""The classifier in LightGBM's own text format, for a runtime outside Python.

``export_classifier(models, metadata, out)`` writes two files:

- ``classifier.txt``: LightGBM's text model (``Booster.save_model``). Any
  program that links LightGBM's C library can load it; ADR 0015 (draft)
  compares the ways to run it.
- ``export.json``: everything a runtime needs besides the trees: the 37
  inputs in order, the integer code of each category value, the class
  order, how raw scores become probabilities (the temperature), the two
  thresholds and the confidence the decision uses, the library versions,
  and the checksums.

**The inputs a runtime gives the trees** (``input_matrix``): one row per
flow, the schema's features in order, as numbers. A category is given as
its position in the schema's list of values (for ``protocol``: tcp 0,
udp 1, icmp 2, other 3); an empty value is NaN. That is the code pandas
gives the same value, so the trees see the same numbers in Python and in
the runtime: ``check_export`` loads ``classifier.txt`` again, feeds it the
matrix, and returns the largest difference from the bundle's raw scores.

The Isolation Forest is not exported: scikit-learn's forests have no
LightGBM text form. ADR 0015 (draft) weighs the options.

Example::

    models, metadata = load_bundle("results/models/lab")
    export_classifier(models, metadata, Path("results/export/lab"))
    check_export(Path("results/export/lab"), inputs, schema, models)   # 0.0
"""

from __future__ import annotations

import json
from pathlib import Path

import lightgbm
import numpy as np
import pandas as pd

from flagman_ml.files import sha256_of
from flagman_ml.flows import Schema
from flagman_ml.models.classifier import raw_scores

MODEL = "classifier.txt"
RECORD = "export.json"


def input_matrix(inputs: pd.DataFrame, schema: Schema) -> np.ndarray:
    """The features as a float matrix: categories as their codes, empty as NaN."""
    columns = []
    for feature in schema.features:
        values = inputs[feature.name]
        if feature.kind == "category":
            codes = pd.Categorical(values, categories=list(feature.categories)).codes
            columns.append(np.where(codes < 0, np.nan, codes).astype(float))
        else:
            columns.append(values.astype(float).to_numpy())
    return np.column_stack(columns) if columns else np.empty((len(inputs), 0))


def export_classifier(models: dict, metadata: dict, out: Path) -> dict:
    """Write classifier.txt and export.json into ``out``; returns the record."""
    classifier = models["classifier"]
    out.mkdir(parents=True, exist_ok=True)
    booster = classifier.booster.booster_
    booster.save_model(str(out / MODEL))
    classes = [str(name) for name in classifier.classes_]
    schema = metadata["schema"]
    record = {
        "format": "LightGBM text model",
        "file": {"name": MODEL, "sha256": sha256_of(out / MODEL)},
        "inputs": [{"name": f["name"], "kind": f["kind"],
                    **({"codes": {v: i for i, v in enumerate(f["categories"])}}
                       if f["kind"] == "category" else {})} for f in schema["features"]],
        "empty_value": "NaN",
        "classes": classes,
        "raw_scores": ("one per class" if len(classes) > 2 else
                       "one, for the second class; the first class scores 0"),
        "probabilities": "softmax(raw scores / temperature)",
        "temperature": float(classifier.temperature),
        "decision": {"thresholds": metadata["report"]["thresholds"],
                     "min_confidence": metadata["report"]["settings"]["min_confidence"],
                     "rule": "flagman_ml/models/openset.py"},
        "not_exported": ["the Isolation Forest (scikit-learn): no LightGBM text form"],
        "bundle": {"model_sha256": metadata.get("model_sha256"),
                   "schema_version": schema["version"]},
        "libraries": {"lightgbm": lightgbm.__version__},
    }
    (out / RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    return record


def check_export(out: Path, inputs: pd.DataFrame, schema: Schema, models: dict) -> float:
    """Largest difference between the exported model's raw scores, fed the
    input matrix, and the bundle's own raw scores on the same flows."""
    loaded = lightgbm.Booster(model_file=str(out / MODEL))
    exported = np.asarray(loaded.predict(input_matrix(inputs, schema), raw_score=True))
    if exported.ndim == 1:
        exported = np.column_stack([np.zeros(len(exported)), exported])
    own = raw_scores(models["classifier"].booster, inputs[schema.feature_names])
    return float(np.max(np.abs(exported - own))) if len(own) else 0.0
