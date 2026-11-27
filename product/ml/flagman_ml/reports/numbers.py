"""Every number of a report goes through ``fmt``, from a JSON value.

Reports never compute or type a number: they format values read from
results/*.json files. ``numbers_in`` and ``json_numbers`` let a test
check that each number of a report is one of its source files' values.
"""

from __future__ import annotations

import re

NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?:e[-+]?\d+)?")
CODE = re.compile(r"`[^`]*`")


def fmt(value) -> str:
    """A value as the report prints it: 4 significant digits for real numbers."""
    if value is None:
        return "–"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def json_numbers(node) -> set[str]:
    """Every number of a JSON value, as fmt prints it, and the numbers in its keys."""
    found: set[str] = set()
    if isinstance(node, dict):
        for key, item in node.items():
            found |= set(NUMBER.findall(str(key)))
            found |= json_numbers(item)
    elif isinstance(node, list):
        for item in node:
            found |= json_numbers(item)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        found.add(fmt(node))
    return found


def numbers_in(markdown: str) -> list[str]:
    """The numbers of a Markdown text, outside `code` spans (names and checksums)."""
    return NUMBER.findall(CODE.sub("", markdown))


def table(headers: list[str], rows: list[list]) -> str:
    """A Markdown table; every cell goes through fmt."""
    lines = ["| " + " | ".join(headers) + " |", "|" + " --- |" * len(headers)]
    lines += ["| " + " | ".join(fmt(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)
