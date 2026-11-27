"""One long capture made of the lab captures, repeated, for timing.

Usage, from product/ml::

    python experiments/campaign-sizing/repeat_pcap.py OUT COPIES PCAP...

Each copy of each capture starts 600 s after the start of the one before
it, which is longer than every flow timeout of the flow table (300 s at
most), so copies never join into one flow. The packets themselves are
unchanged. Reads and writes classic little-endian pcap files with
microsecond times (the format of the lab captures).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

MAGIC = b"\xd4\xc3\xb2\xa1"  # little-endian, microseconds
GAP_US = 600 * 1_000_000
START_US = 1_767_225_600 * 1_000_000  # 2026-01-01 00:00:00 UTC


def packets(path: Path) -> list[tuple[int, int, bytes]]:
    """(microseconds since the capture's first packet, original length, bytes)."""
    data = path.read_bytes()
    if data[:4] != MAGIC:
        raise ValueError(f"{path}: not a little-endian microsecond pcap file")
    found, offset = [], 24
    while offset < len(data):
        seconds, micros, kept, original = struct.unpack("<IIII", data[offset:offset + 16])
        found.append((seconds * 1_000_000 + micros, original, data[offset + 16:offset + 16 + kept]))
        offset += 16 + kept
    first = found[0][0] if found else 0
    return [(moment - first, original, body) for moment, original, body in found]


def repeat(sources: list[Path], copies: int, out: Path) -> int:
    """Writes ``out``; returns the number of packets written."""
    captures = [packets(path) for path in sources]
    written, slot = 0, 0
    with out.open("wb") as file:
        file.write(sources[0].read_bytes()[:24])  # the first capture's file header
        for _ in range(copies):
            for capture in captures:
                for moment, original, body in capture:
                    at = START_US + slot * GAP_US + moment
                    file.write(struct.pack("<IIII", at // 1_000_000, at % 1_000_000, len(body),
                                           original))
                    file.write(body)
                    written += 1
                slot += 1
    return written


if __name__ == "__main__":
    count = repeat([Path(p) for p in sys.argv[3:]], int(sys.argv[2]), Path(sys.argv[1]))
    print(f"wrote {count} packets to {sys.argv[1]}")
