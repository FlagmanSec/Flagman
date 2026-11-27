"""The generated C code and the LightGBM C API program give exactly
LightGBM's own raw scores (needs a C compiler: skipped without one).

The example: a model with 10 trees per class trained on made-up flows,
scored on 300 made-up flows. Some of them get an empty number or an empty
category (NaN), so the rules for missing values are used too.
"""

from __future__ import annotations

import shutil

import lightgbm
import numpy as np
import pytest
from codegen import generate
from measure import compile_c, run_bench

from flagman_ml.export.lightgbm_text import MODEL, export_classifier, input_matrix
from flagman_ml.models.bundle import schema_record
from flagman_ml.models.classifier import ClassifierSettings, fit_classifier
from flagman_ml.synthetic import synthetic_flows

pytestmark = pytest.mark.skipif(shutil.which("cc") is None, reason="needs a C compiler (cc)")


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    out = tmp_path_factory.mktemp("runtime")
    train, schema = synthetic_flows({"normal": 600, "scan": 150, "brute_force": 150}, seed=0)
    test, _ = synthetic_flows({"normal": 200, "scan": 50, "brute_force": 50}, seed=1)
    names = schema.feature_names
    model = fit_classifier(train[names], train["label"], train[names], train["label"],
                           ClassifierSettings(trees=10, min_flows_per_leaf=5))
    export_classifier({"classifier": model}, {"schema": schema_record(schema), "report": {
        "thresholds": {}, "settings": {"min_confidence": 0.5}}}, out)
    rows = np.ascontiguousarray(input_matrix(test[names], schema), dtype=np.float64)
    rows[::7, 1] = np.nan  # an empty number
    rows[::11, names.index("protocol")] = np.nan  # an empty category
    rows.tofile(out / "rows.f64")
    expected = lightgbm.Booster(model_file=str(out / MODEL)).predict(rows, raw_score=True)
    return out, rows, expected, model.booster.booster_.dump_model()


def test_generated_code_gives_lightgbms_raw_scores_exactly(exported):
    out, rows, expected, dump = exported
    (out / "flagman_model.c").write_text(generate(dump), encoding="utf-8")
    compile_c(out, ["codegen_bench.c", str(out / "flagman_model.c")], "codegen_bench", ["-lm"])
    found, scores = run_bench(
        [str(out / "codegen_bench"), str(out / "rows.f64"), "37", "3", str(out / "codegen.f64")],
        out / "codegen.f64", 3, 300)
    assert found["rows"] == 300 and np.isnan(rows).any()
    assert np.array_equal(scores, expected)


def test_c_api_program_gives_lightgbms_raw_scores_exactly(exported):
    out, _, expected, _ = exported
    library = lightgbm.__file__.rsplit("/", 1)[0] + "/lib"
    compile_c(out, ["capi_bench.c"], "capi_bench",
              [f"-L{library}", "-l_lightgbm", f"-Wl,-rpath,{library}"])
    found, scores = run_bench(
        [str(out / "capi_bench"), str(out / MODEL), str(out / "rows.f64"), "37", "3",
         str(out / "capi.f64")], out / "capi.f64", 3, 300)
    assert found["iterations"] == 10  # boosting rounds: 10 trees per class
    assert np.array_equal(scores, expected)
