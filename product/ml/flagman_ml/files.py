"""Small helpers about files, shared by every part of the pipeline."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def sha256_of(path: str | os.PathLike) -> str:
    """The SHA-256 checksum of a file, as 64 hexadecimal characters.

    A checksum names the exact bytes of a file: labels record the
    checksum of the feature files they describe, and downloads check
    theirs against the dataset manifest.
    """
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def replace_atomically(tmp: Path, final: Path) -> None:
    """Move a finished temporary file to its final name in one step.

    A reader never sees a half-written file: either the old file or the
    complete new one.
    """
    os.replace(tmp, final)
