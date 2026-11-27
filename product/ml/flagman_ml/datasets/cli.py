"""Command line: ``python -m flagman_ml.datasets`` (run from product/ml).

    python -m flagman_ml.datasets list --manifest data/manifests/ctu-13.toml
    python -m flagman_ml.datasets download --manifest data/manifests/ctu-13.toml \\
        --dest data/downloads/ctu-13 --only ctu-52/capture20110818-2.binetflow --record
    python -m flagman_ml.datasets verify --manifest data/manifests/ctu-13.toml \\
        --dest data/downloads/ctu-13

``--record`` downloads files whose checksum is not in the manifest yet and
prints the lines to paste into it. Read data/README.md first: licences,
sizes and what is never downloaded.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flagman_ml.datasets.download import DownloadError, check, check_budget, get
from flagman_ml.datasets.manifest import Manifest, load_manifest


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    manifest = load_manifest(args.manifest)
    entries = manifest.select(args.only, args.skip)
    if args.command == "list":
        return show(manifest, entries)
    if args.command == "verify":
        return verify(manifest, entries, args.dest)
    return download(manifest, entries, args)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m flagman_ml.datasets",
                                  description="Download and check dataset files.")
    commands = top.add_subparsers(dest="command", required=True)
    for name, text in (("list", "show the files of a manifest"),
                       ("download", "download missing files and check them"),
                       ("verify", "check files already downloaded (by hand or not)")):
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("--manifest", required=True, type=Path)
        command.add_argument("--only", action="append", help="one file name (repeat for more)")
        command.add_argument("--skip", action="append", help="leave out one file (repeat)")
        if name != "list":
            command.add_argument("--dest", required=True, type=Path, help="download folder")
    get_command = commands.choices["download"]
    get_command.add_argument("--record", action="store_true",
                             help="accept files without a checksum and print it")
    get_command.add_argument("--allow-large", action="store_true",
                             help="allow 20 GB or more (ask the team first)")
    return top


def show(manifest: Manifest, entries: list) -> int:
    print(f"{manifest.dataset}: {manifest.page}")
    for entry in entries:
        how = "by hand" if not entry.url else "download"
        known = "checksum known" if entry.sha256 else "no checksum yet"
        print(f"  {entry.name}  [{entry.kind}, {entry.listed_size or 'size not stated'}, "
              f"{how}, {known}]")
    return 0


def download(manifest: Manifest, entries: list, args: argparse.Namespace) -> int:
    try:
        total = check_budget(entries, args.dest, args.allow_large)
        print(f"about {total / 1000**3:.2f} GB to download into {args.dest}")
        failed = False
        for entry in entries:
            try:
                outcome = get(entry, args.dest, record=args.record)
            except DownloadError as error:
                print(f"FAILED {error}", file=sys.stderr)
                failed = True
                continue
            report(manifest, entry, outcome.status, outcome.bytes, outcome.sha256)
    except DownloadError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2
    return 1 if failed else 0


def verify(manifest: Manifest, entries: list, dest: Path) -> int:
    bad = False
    for entry in entries:
        path = dest / entry.name
        if not path.exists():
            print(f"missing  {entry.name}" + ("" if entry.url else f" (by hand: {manifest.page})"))
            bad = True
            continue
        try:
            size, digest = check(entry, path)
        except DownloadError as error:
            print(f"BAD      {error}")
            bad = True
            continue
        report(manifest, entry, "checked" if entry.sha256 else "recorded", size, digest)
    return 1 if bad else 0


def report(manifest: Manifest, entry, status: str, size: int, digest: str) -> None:
    if status == "by hand":
        print(f"by hand  {entry.name}: download it from {manifest.page}, then run verify")
    elif status == "recorded":
        print(f"recorded {entry.name}: paste into the manifest: bytes = {size}, "
              f'sha256 = "{digest}"')
    else:
        print(f"{status:<8} {entry.name} ({size} bytes, SHA-256 checked)")
