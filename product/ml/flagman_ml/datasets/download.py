"""Download dataset files, resuming broken transfers and checking every byte.

For each file of a manifest:

1. a file already in place is checked (size and SHA-256) and kept;
2. otherwise it is downloaded to ``name.part``; a broken transfer resumes
   where it stopped when the server allows it (HTTP range requests);
3. the size and the SHA-256 are checked before the file gets its final
   name, so a final name always means a complete, checked file;
4. a file whose checksum is not in the manifest yet is downloaded only with
   ``record=True``: its size and checksum are then printed, ready to paste
   into the manifest, so later downloads are checked against them.

Big downloads need a clear yes: a selection of 20 GB or more is refused
unless ``allow_large`` is set (the team's rule: ask before datasets over
20 GB). The free disk space is checked too.
"""

from __future__ import annotations

import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from flagman_ml.datasets.manifest import Entry
from flagman_ml.files import replace_atomically, sha256_of

LARGE_BYTES = 20 * 1000**3  # 20 GB
SPARE_BYTES = 1000**3  # keep 1 GB of disk free after the downloads
CHUNK = 1 << 20
USER_AGENT = "flagman-ml-download/0.1"  # no personal details in requests


class DownloadError(RuntimeError):
    """A file that could not be downloaded or did not pass its checks."""


@dataclass(frozen=True)
class Outcome:
    name: str
    status: str  # "kept", "downloaded", "recorded", "by hand", "missing"
    bytes: int = 0
    sha256: str = ""


def check_budget(entries: list[Entry], dest: Path, allow_large: bool) -> int:
    """Refuse a selection of 20 GB or more without allow_large, or one that
    does not fit on the disk. Returns the estimated number of bytes."""
    todo = [e for e in entries if e.url and not (dest / e.name).exists()]
    total = sum(e.estimated_bytes() for e in todo)
    if total >= LARGE_BYTES and not allow_large:
        raise DownloadError(
            f"about {total / 1000**3:.1f} GB to download: that needs the team's yes, "
            "then --allow-large (or pick fewer files with --only)"
        )
    dest.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(dest).free
    if total + SPARE_BYTES > free:
        raise DownloadError(
            f"about {total / 1000**3:.1f} GB to download but only {free / 1000**3:.1f} GB free"
        )
    return total


def get(entry: Entry, dest: Path, record: bool = False, retries: int = 3,
        timeout: float = 60.0) -> Outcome:
    """Make sure one file is in place and checked; download it if needed."""
    target = dest / entry.name
    if target.exists():
        size, digest = check(entry, target)
        return Outcome(entry.name, "kept" if entry.sha256 else "recorded", size, digest)
    if not entry.url:
        return Outcome(entry.name, "by hand")
    if not entry.sha256 and not record:
        raise DownloadError(
            f"{entry.name}: no checksum in the manifest yet. Run again with --record to "
            "download it and print its checksum for the manifest"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")
    fetch(entry.url, part, retries, timeout)
    try:
        size, digest = check(entry, part)
    except DownloadError:
        part.replace(target.with_name(target.name + ".bad"))
        raise
    replace_atomically(part, target)
    return Outcome(entry.name, "downloaded" if entry.sha256 else "recorded", size, digest)


def check(entry: Entry, path: Path) -> tuple[int, str]:
    """Compare a file with the manifest; returns its size and checksum."""
    size = path.stat().st_size
    if entry.bytes and size != entry.bytes:
        raise DownloadError(f"{entry.name}: {size} bytes instead of {entry.bytes}")
    digest = sha256_of(path)
    if entry.sha256 and digest != entry.sha256:
        raise DownloadError(f"{entry.name}: the SHA-256 differs from the manifest")
    return size, digest


def fetch(url: str, part: Path, retries: int, timeout: float) -> None:
    """Download ``url`` into ``part``, resuming what is already there."""
    for attempt in range(retries + 1):
        have = part.stat().st_size if part.exists() else 0
        headers = {"User-Agent": USER_AGENT}
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                        timeout=timeout) as response:
                resumed = have > 0 and response.status == 206
                with open(part, "ab" if resumed else "wb") as out:
                    shutil.copyfileobj(response, out, CHUNK)
            return
        except urllib.error.HTTPError as error:
            if error.code == 416 and have:  # nothing left to send: already complete
                return
            if error.code < 500 or attempt == retries:
                raise DownloadError(f"{url}: HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            if attempt == retries:
                raise DownloadError(f"{url}: {error}") from None
        time.sleep(2**attempt)
