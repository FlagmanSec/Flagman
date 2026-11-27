"""A trained model bundle: the models, and what is needed to use them right.

A bundle is a folder:

- ``model.joblib``: the classifier, the Isolation Forest, the thresholds
  and the drift monitor's reference flows;
- ``bundle.json``: what a person (and a report) needs to know: classes,
  thresholds, settings, the feature schema and flow table it was trained
  with, the checksums of its training data, the library versions, and the
  checksum of ``model.joblib``.

Loading a joblib file runs code stored in it, so only load bundles this
project made. ``load_bundle`` checks the checksum in ``bundle.json``
first, so a changed or swapped model file is refused. A bundle saved with
other library versions still loads, with a warning: its numbers may
differ slightly, so install requirements.txt or train again.
"""

from __future__ import annotations

import json
import os
import platform
import warnings
from pathlib import Path

import joblib
import lightgbm
import numpy
import pandas
import scipy
import sklearn

from flagman_ml.files import replace_atomically, sha256_of
from flagman_ml.flows import Schema

MODEL = "model.joblib"
METADATA = "bundle.json"


class BundleError(ValueError):
    """A bundle that is incomplete or does not match its metadata."""


def schema_record(schema: Schema) -> dict:
    """The parts of the feature schema a model depends on."""
    return {"version": schema.version,
            "features": [{"name": f.name, "kind": f.kind, "categories": list(f.categories)}
                         for f in schema.features]}


def library_versions() -> dict[str, str]:
    return {"python": platform.python_version(), "lightgbm": lightgbm.__version__,
            "scikit-learn": sklearn.__version__, "numpy": numpy.__version__,
            "pandas": pandas.__version__, "scipy": scipy.__version__,
            "joblib": joblib.__version__}


def save_bundle(folder: str | os.PathLike, models: dict, metadata: dict) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / (MODEL + ".part")
    joblib.dump(models, tmp)
    replace_atomically(tmp, folder / MODEL)
    record = {**metadata, "libraries": library_versions(),
              "model_sha256": sha256_of(folder / MODEL)}
    (folder / METADATA).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")


def read_metadata(folder: str | os.PathLike) -> dict:
    path = Path(folder) / METADATA
    if not path.exists():
        raise BundleError(f"{folder}: no {METADATA}: not a model bundle")
    return json.loads(path.read_text(encoding="utf-8"))


def load_bundle(folder: str | os.PathLike) -> tuple[dict, dict]:
    """(models, metadata), after checking the model file's checksum."""
    metadata = read_metadata(folder)
    model = Path(folder) / MODEL
    if not model.exists() or sha256_of(model) != metadata.get("model_sha256"):
        raise BundleError(f"{model}: missing or changed since it was saved: not loaded")
    recorded, running = metadata.get("libraries", {}), library_versions()
    differ = sorted(k for k in running if k != "python" and recorded.get(k) != running[k])
    if differ:
        warnings.warn(f"{folder} was saved with other versions of {', '.join(differ)}: "
                      "install requirements.txt or train again", stacklevel=2)
    return joblib.load(model), metadata
