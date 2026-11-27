import pytest

from flagman_ml.evaluation.plan import PlanError, load_plan

PLAN = """
name = "two-days"
alpha = 0.05
seeds = [0, 1]

[datasets.a]
labels = "labels.parquet"
flows = ["flows/day1.parquet", "flows/day2.parquet", "flows/day3.parquet"]

[[folds]]
name = "test-day3"
train = ["day1.parquet"]
calibration = ["day2.parquet"]
test = ["day3.parquet"]
"""


def write(tmp_path, text):
    path = tmp_path / "plan.toml"
    path.write_text(text)
    return path


def test_a_plan_names_files_and_finds_their_dataset(tmp_path):
    plan = load_plan(write(tmp_path, PLAN))
    assert plan.seeds == (0, 1) and not plan.leave_one_attack_out
    dataset, path = plan.locate("day2.parquet")
    assert dataset.name == "a" and str(path) == "flows/day2.parquet"


@pytest.mark.parametrize("change, message", [
    (('test = ["day3.parquet"]', 'test = ["day2.parquet"]'), "two roles"),
    (('test = ["day3.parquet"]', 'test = ["day9.parquet"]'), "day9.parquet"),
    (("alpha = 0.05", "alpha = 5"), "alpha"),
    (("seeds = [0, 1]", "seeds = []"), "seed"),
    (('test = ["day3.parquet"]', "test = []"), "all need files"),
    (('name = "two-days"', ""), "missing"),
    (("[[folds]]", "[model]\ndepth = 3\n\n[[folds]]"), "unknown model settings"),
])
def test_mistakes_in_a_plan_are_refused(tmp_path, change, message):
    with pytest.raises(PlanError, match=message):
        load_plan(write(tmp_path, PLAN.replace(*change)))


def test_the_example_plan_in_the_repository_loads():
    from flagman_ml.testing import ML_ROOT

    plan = load_plan(ML_ROOT / "plans" / "example.toml")
    assert [fold.name for fold in plan.folds] == ["test-day4", "test-second-dataset"]
    assert plan.locate("capture-a.parquet")[0].name == "second"
