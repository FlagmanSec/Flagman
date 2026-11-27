import json

import pytest

from flagman_ml.models.bundle import (
    MODEL,
    BundleError,
    library_versions,
    load_bundle,
    save_bundle,
    schema_record,
)
from flagman_ml.synthetic import lab_schema


def test_a_bundle_loads_back_with_its_metadata(tmp_path):
    save_bundle(tmp_path / "b", {"answer": 42}, {"classes": ["normal", "scan"]})
    models, metadata = load_bundle(tmp_path / "b")
    assert models == {"answer": 42}
    assert metadata["classes"] == ["normal", "scan"]
    assert metadata["libraries"] == library_versions()
    assert len(metadata["model_sha256"]) == 64


def test_a_changed_model_file_is_refused(tmp_path):
    save_bundle(tmp_path / "b", {"answer": 42}, {})
    (tmp_path / "b" / MODEL).write_bytes(b"something else")
    with pytest.raises(BundleError, match="changed"):
        load_bundle(tmp_path / "b")


def test_a_folder_without_metadata_is_not_a_bundle(tmp_path):
    with pytest.raises(BundleError, match="not a model bundle"):
        load_bundle(tmp_path)


def test_other_library_versions_load_with_a_warning(tmp_path):
    save_bundle(tmp_path / "b", {"answer": 42}, {})
    path = tmp_path / "b" / "bundle.json"
    metadata = json.loads(path.read_text())
    metadata["libraries"]["lightgbm"] = "0.1"
    path.write_text(json.dumps(metadata))
    with pytest.warns(UserWarning, match="lightgbm"):
        load_bundle(tmp_path / "b")


def test_the_schema_record_keeps_what_a_model_depends_on():
    record = schema_record(lab_schema())
    assert record["version"] == 1
    assert len(record["features"]) == 37
    assert record["features"][0]["name"] == "protocol"
    assert "tcp" in record["features"][0]["categories"]
