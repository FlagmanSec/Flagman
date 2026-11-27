import pandas as pd
import pytest

from flagman_ml.labels.mapping import MappingError, UnmappedLabels, load_mapping
from flagman_ml.testing import DATA

HEAD = """\
dataset = "test"
source = "https://example.org"
format = "ctu_binetflow"
ground_truth = ["x.binetflow"]
default_label = "unlabelled"
"""


def write(tmp_path, text):
    path = tmp_path / "test.toml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("path", sorted((DATA / "labels").glob("*.toml")), ids=lambda p: p.name)
def test_every_mapping_file_in_the_repository_loads(path):
    mapping = load_mapping(path)
    assert mapping.source.startswith("https://")
    assert len(mapping.sha256) == 64


def test_the_lab_mapping_turns_lab_steps_into_classes():
    mapping = load_mapping(DATA / "labels/lab.toml")
    assert mapping.class_of("port_scan") == "scan"
    assert mapping.class_of("ssh_password_guessing") == "brute_force"
    assert mapping.class_of("ssh_key_login") == "normal"
    assert mapping.default_label == "normal"


def test_patterns_are_tried_in_order_after_exact_labels(tmp_path):
    mapping = load_mapping(write(tmp_path, HEAD + """
[classes]
"flow=From-Botnet-special" = "scan"
[patterns]
"^flow=From-Botnet" = "botnet"
"^flow=Background" = "background"
"^flow=" = "normal"
"""))
    assert mapping.class_of("flow=From-Botnet-special") == "scan"
    assert mapping.class_of("flow=From-Botnet-V52-1-UDP-DNS") == "botnet"
    assert mapping.class_of("flow=Background-TCP-Established") == "background"
    assert mapping.class_of("flow=To-Normal-V52-UDP") == "normal"
    assert mapping.class_of("something else") is None


def test_every_unknown_label_is_listed_before_anything_is_labelled(tmp_path):
    mapping = load_mapping(write(tmp_path, HEAD + '[classes]\nknown = "normal"\n'))
    with pytest.raises(UnmappedLabels) as error:
        mapping.classes_of(pd.Series(["known", "new-b", "new-a", "new-b"]))
    assert error.value.labels == ["new-a", "new-b"]


@pytest.mark.parametrize("extra, message", [
    ('[classes]\nx = "hacking"\n', "not a Flagman class"),
    ('colour = "red"\n[classes]\nx = "normal"\n', "unknown keys \\['colour'\\]"),
    ('time_zone = "Mars/Olympus"\n[classes]\nx = "normal"\n', "unknown time zone"),
    ('[patterns]\n"(" = "normal"\n', "bad regular expression"),
    ("", "give \\[classes\\] or \\[patterns\\]"),
])
def test_mistakes_in_a_mapping_file_are_explained(tmp_path, extra, message):
    with pytest.raises(MappingError, match=message):
        load_mapping(write(tmp_path, HEAD + extra))
