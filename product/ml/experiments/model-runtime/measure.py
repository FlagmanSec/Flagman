"""Small measurements for ADR 0015 (draft): three ways to run the classifier.

A pipeline check, not a result: the model is trained on made-up flows
(synthetic.py) with the default settings, on one machine. The numbers
compare the runtimes with each other; they say nothing about detection.

Run from product/ml, in a Python with requirements.txt and this folder's
requirements.txt, with a C compiler::

    python experiments/model-runtime/measure.py results/model-runtime

It writes ``measurements.json`` there (and the files it measured): sizes,
load times, time per flow one at a time, memory, and the largest
difference from LightGBM's own scores for each way:

- the LightGBM C API, from C (``capi_bench.c``);
- generated C code (``codegen.py``, ``codegen_bench.c``);
- ONNX (onnxmltools for LightGBM, skl2onnx for the Isolation Forest), run
  by ONNX Runtime from Python in a fresh process (``ort_bench.py``);
- LightGBM's Python package, for reference.

Everything scores one flow at a time on one thread, as the sensor would
when a flow ends. Each timing is repeated (``REPEATS``): the file keeps
every run and their median.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from importlib import metadata as dist
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # product/ml, for flagman_ml

import lightgbm  # noqa: E402
from codegen import generate  # noqa: E402 (this folder)

from flagman_ml.export.lightgbm_text import MODEL, export_classifier, input_matrix  # noqa: E402
from flagman_ml.models.anomaly import anomaly_scores, fit_anomaly  # noqa: E402
from flagman_ml.models.bundle import schema_record  # noqa: E402
from flagman_ml.models.classifier import fit_classifier, raw_scores  # noqa: E402
from flagman_ml.models.data import anomaly_matrix  # noqa: E402
from flagman_ml.synthetic import synthetic_flows  # noqa: E402

TRAIN = {"normal": 20_000, "scan": 4_000, "brute_force": 4_000, "dos": 2_000}
TEST = {"normal": 1_400, "scan": 250, "brute_force": 250, "dos": 100}
ONE_AT_A_TIME = 500  # flows scored one by one from Python
REPEATS = 5


def rss_kb() -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return -1


def timed(action):
    start = time.perf_counter()
    result = action()
    return result, time.perf_counter() - start


def per_flow_us(score_one, rows: np.ndarray) -> float:
    start = time.perf_counter()
    for row in rows[:ONE_AT_A_TIME]:
        score_one(row[None, :])
    return (time.perf_counter() - start) / min(len(rows), ONE_AT_A_TIME) * 1e6


def compile_c(out: Path, sources: list[str], target: str, extra: list[str]) -> float:
    command = ["cc", "-O2", *sources, "-o", str(out / target), *extra]
    _, seconds = timed(lambda: subprocess.run(command, check=True, cwd=HERE))
    return seconds


def run_bench(command: list[str], scores: Path, classes: int, rows: int) -> tuple[dict, np.ndarray]:
    done = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(done.stdout), np.fromfile(scores).reshape(rows, classes)


def versions() -> dict:
    names = ["lightgbm", "scikit-learn", "numpy", "onnx", "onnxruntime", "onnxmltools", "skl2onnx"]
    found = {}
    for name in names:
        try:
            found[name] = dist.version(name)
        except dist.PackageNotFoundError:
            found[name] = None
    cc = subprocess.run(["cc", "--version"], capture_output=True, text=True).stdout.splitlines()
    return {"python": platform.python_version(), "cc": cc[0] if cc else None, **found}


def machine() -> dict:
    cpu = [line.split(":", 1)[1].strip() for line in
           Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")]
    return {"cpu": cpu[0] if cpu else None, "cpus": os.cpu_count(), "system": platform.platform()}


def main(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    train, schema = synthetic_flows(TRAIN, seed=0)
    calibration, _ = synthetic_flows(TRAIN, seed=2)
    test, _ = synthetic_flows(TEST, seed=1)
    names = schema.feature_names
    model, train_seconds = timed(lambda: fit_classifier(
        train[names], train["label"], calibration[names], calibration["label"]))
    forest = fit_anomaly(anomaly_matrix(train.loc[train["label"] == "normal", names], schema))
    metadata = {"schema": schema_record(schema),
                "report": {"thresholds": {}, "settings": {"min_confidence": 0.5}}}
    export_classifier({"classifier": model}, metadata, out)
    rows = np.ascontiguousarray(input_matrix(test[names], schema), dtype=np.float64)
    rows.tofile(out / "rows.f64")
    reference = raw_scores(model.booster, test[names])
    dump = model.booster.booster_.dump_model()
    result = {
        "note": "a pipeline check on made-up flows, not a result",
        "machine": machine(), "versions": versions(), "repeats": REPEATS,
        "model": {"classes": reference.shape[1], "trees": len(dump["tree_info"]),
                  "leaves": sum(t["num_leaves"] for t in dump["tree_info"]),
                  "inputs": len(names), "train_seconds": train_seconds,
                  "text_bytes": (out / MODEL).stat().st_size},
        "test_flows": len(rows),
        "python_lightgbm": measure_python(out / MODEL, rows),
        "c_api": measure_capi(out, rows, reference),
        "codegen": measure_codegen(out, dump, rows, reference),
        "onnx": measure_onnx(out, model, forest, test, schema, rows),
    }
    (out / "measurements.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                           encoding="utf-8")
    return result


def median_of(measure) -> dict:
    runs = [measure() for _ in range(REPEATS)]
    return {"median": float(np.median(runs)), "runs": runs}


def bench(command: list[str], scores: Path, classes: int, rows: int) -> tuple[dict, np.ndarray]:
    """A benchmark program run REPEATS times: its last output, with every
    run's times per flow and their median."""
    outputs = [run_bench(command, scores, classes, rows) for _ in range(REPEATS)]
    found, values = outputs[-1]
    for key in [key for key in found if key.startswith("microseconds")]:
        runs = [output[key] for output, _ in outputs]
        found[key] = {"median": float(np.median(runs)), "runs": runs}
    return found, values


def largest(found: np.ndarray, expected: np.ndarray) -> float:
    return float(np.max(np.abs(found - expected)))


def measure_python(model: Path, rows: np.ndarray) -> dict:
    """LightGBM's Python package (for reference: the sensor has no Python)."""
    booster, load = timed(lambda: lightgbm.Booster(model_file=str(model)))

    def batch() -> float:
        _, seconds = timed(lambda: booster.predict(rows, raw_score=True, num_threads=1))
        return seconds / len(rows) * 1e6

    return {"load_seconds": load,
            "microseconds_per_flow": median_of(lambda: per_flow_us(
                lambda row: booster.predict(row, raw_score=True, num_threads=1), rows)),
            "microseconds_per_flow_in_one_batch": median_of(batch)}


def measure_capi(out: Path, rows: np.ndarray, reference: np.ndarray) -> dict:
    """LightGBM's C library, from C (capi_bench.c)."""
    library = Path(lightgbm.__file__).parent / "lib"
    compile_c(out, ["capi_bench.c"], "capi_bench",
              [f"-L{library}", "-l_lightgbm", f"-Wl,-rpath,{library}"])
    found, scores = bench([str(out / "capi_bench"), str(out / MODEL), str(out / "rows.f64"),
                           str(rows.shape[1]), str(reference.shape[1]), str(out / "capi.f64")],
                          out / "capi.f64", reference.shape[1], len(rows))
    return {**found, "library_bytes": (library / "lib_lightgbm.so").stat().st_size,
            "largest_difference": largest(scores, reference)}


def measure_codegen(out: Path, dump: dict, rows: np.ndarray, reference: np.ndarray) -> dict:
    """The trees as generated C code (codegen.py), compiled into codegen_bench.c."""
    source = out / "flagman_model.c"
    source.write_text(generate(dump), encoding="utf-8")
    seconds = compile_c(out, ["codegen_bench.c", str(source)], "codegen_bench", ["-lm"])
    found, scores = bench([str(out / "codegen_bench"), str(out / "rows.f64"),
                           str(rows.shape[1]), str(reference.shape[1]), str(out / "codegen.f64")],
                          out / "codegen.f64", reference.shape[1], len(rows))
    return {**found, "compile_seconds": seconds, "source_bytes": source.stat().st_size,
            "program_bytes": (out / "codegen_bench").stat().st_size,
            "largest_difference": largest(scores, reference)}


def measure_onnx(out: Path, model, forest, test, schema, rows: np.ndarray) -> dict:
    """Both models converted to ONNX and run by ONNX Runtime; the error if a step fails."""
    try:
        import onnxmltools
        import onnxruntime
        from onnxmltools.convert.common.data_types import FloatTensorType
        from skl2onnx import to_onnx
    except ImportError as error:
        return {"error": f"not installed: {error}"}
    found = {}
    try:
        converted = onnxmltools.convert_lightgbm(
            model.booster, initial_types=[("input", FloatTensorType([None, rows.shape[1]]))],
            zipmap=False)
        path = out / "classifier.onnx"
        path.write_bytes(converted.SerializeToString())
        own = model.booster.predict_proba(test[schema.feature_names])
        result, probabilities = bench(
            [sys.executable, str(HERE / "ort_bench.py"), str(path), str(out / "rows.f64"),
             str(rows.shape[1]), str(out / "onnx.f64")], out / "onnx.f64", own.shape[1], len(rows))
        found["classifier"] = {
            **result, "bytes": path.stat().st_size,
            "largest_probability_difference": largest(probabilities, own),
            "same_top_class": float(np.mean(probabilities.argmax(1) == own.argmax(1)))}
    except Exception as error:  # the attempt is the result: record why it failed
        found["classifier"] = {"error": f"{type(error).__name__}: {error}"}
    try:
        matrix = anomaly_matrix(test[schema.feature_names], schema).to_numpy(np.float32)
        converted = to_onnx(forest, matrix[:1], target_opset={"": 17, "ai.onnx.ml": 3})
        path = out / "forest.onnx"
        path.write_bytes(converted.SerializeToString())
        session = onnxruntime.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        scores = session.run(["scores"], {session.get_inputs()[0].name: matrix})[0].ravel()
        mine = -(scores + forest.offset_)  # scores = decision_function = score_samples - offset_
        own = anomaly_scores(forest, anomaly_matrix(test[schema.feature_names], schema))
        found["forest"] = {"bytes": path.stat().st_size,
                           "largest_score_difference": largest(mine, own)}
    except Exception as error:
        found["forest"] = {"error": f"{type(error).__name__}: {error}"}
    libraries = Path(onnxruntime.__file__).parent / "capi"
    found["library_bytes"] = {p.name: p.stat().st_size for p in sorted(libraries.glob("*.so*"))}
    return found


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1])), indent=2, sort_keys=True))
