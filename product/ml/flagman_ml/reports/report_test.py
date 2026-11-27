import json

import pytest

from flagman_ml.reports.cli import main
from flagman_ml.reports.numbers import fmt, json_numbers, numbers_in


def test_every_number_of_the_report_is_a_value_of_its_source_files(evaluated, tmp_path):
    _, _, results = evaluated
    out = tmp_path / "report.md"
    assert main(["--evaluation", str(results), "--out", str(out)]) == 0
    report = out.read_text()
    allowed = set()
    for path in [results / "summary.json", *sorted((results / "runs").glob("*.json"))]:
        allowed |= json_numbers(json.loads(path.read_text()))
    found = numbers_in(report)
    assert found  # the report does hold numbers
    assert [n for n in found if n not in allowed] == []


def test_a_changed_run_file_is_refused(evaluated, tmp_path):
    _, _, results = evaluated
    copy = tmp_path / "copy"
    (copy / "runs").mkdir(parents=True)
    (copy / "summary.json").write_text((results / "summary.json").read_text())
    for path in (results / "runs").glob("*.json"):
        (copy / "runs" / path.name).write_text(path.read_text() + " ")
    with pytest.raises(ValueError, match="changed since the summary"):
        main(["--evaluation", str(copy), "--out", str(tmp_path / "r.md")])


def test_numbers_are_printed_one_way():
    assert [fmt(v) for v in (None, True, 3, 0.0443751, 151.2481)] == ["–", "yes", "3", "0.04438",
                                                                     "151.2"]
    assert numbers_in("a 0.5 and `day3.parquet` and 2e-05") == ["0.5", "2e-05"]
