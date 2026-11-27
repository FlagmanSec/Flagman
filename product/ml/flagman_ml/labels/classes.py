"""Flagman's classes: the names that every dataset's own labels map to.

A mapping file (``product/ml/data/labels/*.toml``) says which dataset label
goes to which class. The UNSW-NB15 categories that have no clear match in
the other datasets keep a class of their own, named after the category:
merging them is a research choice, made later in one visible place.

Two classes never train or score a model: ``background`` and
``unlabelled``. They stay in the labels file, and are counted, so the
reports can say how much traffic was left out.
"""

from __future__ import annotations

CLASSES: dict[str, str] = {
    "normal": "ordinary traffic",
    "scan": "port scans and host sweeps: looking for machines and open ports",
    "brute_force": "password guessing against a login service (SSH, FTP, web forms)",
    "dos": "denial of service from one machine",
    "ddos": "denial of service from many machines",
    "web_attack": "attacks on web applications, such as SQL injection or cross-site scripting",
    "botnet": "an infected machine talking with its controller, or sending what it is told to",
    "infiltration": "an attacker working from inside the network after a first break-in",
    "exploit": "use of a software flaw",
    "fuzzers": "the UNSW-NB15 category Fuzzers",
    "backdoor": "the UNSW-NB15 category Backdoor",
    "shellcode": "the UNSW-NB15 category Shellcode",
    "worm": "the UNSW-NB15 category Worms",
    "generic": "the UNSW-NB15 category Generic",
    "analysis": "the UNSW-NB15 category Analysis",
    "background": "traffic of unknown nature, such as CTU-13 Background: never trains or scores",
    "unlabelled": "no ground-truth record describes the flow, in a dataset that lists every"
    " flow: never trains or scores",
}

NOT_SCORED = frozenset({"background", "unlabelled"})
ATTACKS = frozenset(CLASSES) - NOT_SCORED - {"normal"}


def check_class(name: str, where: str) -> str:
    """Return ``name`` if it is one of Flagman's classes, or fail clearly."""
    if name not in CLASSES:
        raise ValueError(f"{where}: {name!r} is not a Flagman class (see labels/classes.py)")
    return name
