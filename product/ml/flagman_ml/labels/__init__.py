"""Labelling: join flows to each dataset's ground truth by addresses, ports
and time, through a mapping file per dataset. Start with README.md."""

from flagman_ml.labels.classes import ATTACKS, CLASSES, NOT_SCORED
from flagman_ml.labels.formats import read_ground_truth
from flagman_ml.labels.label import label_flows
from flagman_ml.labels.mapping import Mapping, MappingError, UnmappedLabels, load_mapping
from flagman_ml.labels.store import LabelsMismatch, attach_labels, read_labels, write_labels

__all__ = [
    "ATTACKS",
    "CLASSES",
    "LabelsMismatch",
    "Mapping",
    "MappingError",
    "NOT_SCORED",
    "UnmappedLabels",
    "attach_labels",
    "label_flows",
    "load_mapping",
    "read_ground_truth",
    "read_labels",
    "write_labels",
]
