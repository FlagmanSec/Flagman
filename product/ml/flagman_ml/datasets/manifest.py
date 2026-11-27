"""Dataset manifests: the files to download, with their size and checksum.

A manifest is a TOML file in ``product/ml/data/manifests/``::

    dataset = "ctu-13"
    page = "https://www.stratosphereips.org/datasets-ctu13"

    [[files]]
    name = "ctu-52/capture20110818-2.binetflow"   # where it goes under --dest
    url = "https://mcfp.felk.cvut.cz/..."         # empty: download it by hand
    listed_size = "14M"                           # as the source page shows it
    bytes = 0                                     # exact size, 0 until recorded
    sha256 = ""                                   # checksum, empty until recorded
    kind = "labels"                               # pcap, labels or ground_truth

None of the datasets publishes checksums for these files, so the first
download records them (``--record``) and later downloads check them.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

KINDS = ("pcap", "labels", "ground_truth")
UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
# Never download a program: some dataset folders hold the malware samples
# they recorded. A manifest that names one is refused.
EXECUTABLE = re.compile(r"\.exe(\.|$)|only-exes", re.IGNORECASE)
SHA256 = re.compile(r"[0-9a-f]{64}")


class ManifestError(ValueError):
    """A manifest that is incomplete, unsafe or inconsistent."""


@dataclass(frozen=True)
class Entry:
    name: str  # relative path under the destination folder
    url: str  # empty when the file must be downloaded by hand
    listed_size: str  # the size as the source page shows it, such as "1.9G"
    bytes: int  # exact size in bytes, 0 when not recorded yet
    sha256: str  # empty when not recorded yet
    kind: str

    def estimated_bytes(self) -> int:
        """The exact size if recorded, otherwise the listed size, roughly."""
        return self.bytes or parse_size(self.listed_size)


@dataclass(frozen=True)
class Manifest:
    dataset: str
    page: str
    files: tuple[Entry, ...]

    def select(self, only: list[str] | None = None, skip: list[str] | None = None) -> list[Entry]:
        """The entries named in ``only`` (all when empty), minus those in ``skip``."""
        known = {entry.name: entry for entry in self.files}
        unknown = [name for name in [*(only or []), *(skip or [])] if name not in known]
        if unknown:
            raise ManifestError(f"{self.dataset}: no file named {unknown}")
        chosen = [known[name] for name in only] if only else list(self.files)
        return [entry for entry in chosen if entry.name not in (skip or [])]


def parse_size(text: str) -> int:
    """'56M' -> 58720256. An empty or unknown size counts as 0."""
    match = re.fullmatch(r"\s*([0-9.]+)\s*([KMGT]?)i?B?\s*", text or "", re.IGNORECASE)
    if not match:
        return 0
    return int(float(match.group(1)) * UNITS[match.group(2).upper()])


def load_manifest(path: str | os.PathLike) -> Manifest:
    path = Path(path)
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    for key in ("dataset", "page"):
        if key not in raw:
            raise ManifestError(f"{path.name}: missing {key}")
    entries = tuple(_entry(item, path.name) for item in raw.get("files", []))
    names = [entry.name for entry in entries]
    if len(set(names)) != len(names):
        raise ManifestError(f"{path.name}: a file name appears twice")
    return Manifest(dataset=raw["dataset"], page=raw["page"], files=entries)


def _entry(item: dict, where: str) -> Entry:
    entry = Entry(
        name=item.get("name", ""),
        url=item.get("url", ""),
        listed_size=item.get("listed_size", ""),
        bytes=int(item.get("bytes", 0)),
        sha256=item.get("sha256", "").lower(),
        kind=item.get("kind", ""),
    )
    name = PurePosixPath(entry.name)
    if not entry.name or name.is_absolute() or ".." in name.parts:
        raise ManifestError(f"{where}: {entry.name!r} must be a plain relative path")
    if EXECUTABLE.search(entry.name) or EXECUTABLE.search(entry.url):
        raise ManifestError(f"{where}: {entry.name} looks like a program: never download one")
    if entry.url and not entry.url.startswith(("https://", "http://")):
        raise ManifestError(f"{where}: {entry.name}: the url must start with https:// or http://")
    if entry.sha256 and not SHA256.fullmatch(entry.sha256):
        raise ManifestError(f"{where}: {entry.name}: sha256 must be 64 hexadecimal characters")
    if entry.kind not in KINDS:
        raise ManifestError(f"{where}: {entry.name}: kind must be one of {KINDS}")
    return entry
