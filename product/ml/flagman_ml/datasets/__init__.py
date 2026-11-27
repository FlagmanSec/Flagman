"""Dataset downloads with size and SHA-256 checks. Start with README.md."""

from flagman_ml.datasets.download import DownloadError, check_budget, get
from flagman_ml.datasets.manifest import Entry, Manifest, ManifestError, load_manifest

__all__ = ["DownloadError", "Entry", "Manifest", "ManifestError", "check_budget", "get",
           "load_manifest"]
