"""Count what the entry list of a password zip shows (phageo, 2026-10-15, fiftieth message).

A measurement, not a rule: per zip whose members are encrypted (what ``ARC-001`` stands for),
how many of its entries are programs, scripts, archives or other - by the ending of the entry's
name in the zip's own list, which stays readable when the members are encrypted. Numbers only:
no name, no path, no content is printed.

    python tools/encrypted_count.py <folder of one clean sample> [...]

Real samples: ``tools/positive_benchmark.py <folders> --encrypted-count``.
"""
from __future__ import annotations

import io
import os
import sys
import zipfile
from typing import Callable, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gamescan.handlers.documents import (ENCRYPTED_ARCHIVES as ARCHIVES, ENCRYPTED_PROGRAMS as PROGRAMS,  # the rule's lists
                                         ENCRYPTED_SCRIPTS as SCRIPTS)
COLUMNS = ("password zips", "entries", "programs", "scripts", "archives", "other")


def kind(name: str) -> str:
    ext = os.path.splitext(name.replace("\\", "/").rsplit("/", 1)[-1])[1].lower()
    return ("programs" if ext in PROGRAMS else "scripts" if ext in SCRIPTS
            else "archives" if ext in ARCHIVES else "other")


def entries(data: bytes) -> Dict[str, int]:
    """The numbers of ``COLUMNS`` for one file (all 0 when it is no zip with an encrypted member)."""
    out = {column: 0 for column in COLUMNS}
    if data[:4] != b"PK\x03\x04":
        return out
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return out
    if not any(info.flag_bits & 1 for info in infos):
        return out
    out["password zips"] = 1
    for info in infos:
        if info.is_dir():
            continue
        out["entries"] += 1
        out[kind(info.filename)] += 1
    return out


def count(scanner, scan: Callable[[], object]) -> Dict[str, int]:
    """Run ``scan()`` (which must scan with ``scanner``) and add up ``entries`` of every file it reads."""
    out = {column: 0 for column in COLUMNS}
    real_scan = scanner._scan_one

    def watched(ctx, depth: int = 0):
        for column, number in entries(ctx.data).items():
            out[column] += number
        return real_scan(ctx, depth)

    scanner._scan_one = watched
    try:
        scan()
    finally:
        del scanner._scan_one
    return out


def line(numbers: Dict[str, int]) -> str:
    return "; ".join("%s: %d" % (column, numbers[column]) for column in COLUMNS)


def main(argv: List[str]) -> int:
    from gamescan import neutral_scanner
    if not argv:
        print(__doc__)
        return 2
    for folder in argv:
        if not os.path.isdir(folder):
            print("not a folder: %s" % folder)
            return 2
        scanner = neutral_scanner()
        print("%s | %s" % (os.path.basename(os.path.normpath(folder)), line(count(scanner, lambda: scanner.scan(folder)))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
