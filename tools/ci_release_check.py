"""The release checklist on a build machine that has only the repository (the workflow).

    python tools/ci_release_check.py <package zip> --installer <setup.exe> [--names <mapping file>]

(Source release, phageo 2026-10-25.) Runs the lines of ``tools/release_check.py`` unchanged. Three
of them need files that are never part of the repository, and on a machine without them they say
SKIPPED instead of failing:

- ``dev content`` needs ``engine_archives`` (the official archives) beside ``tests/``;
- ``samples`` needs the clean benchmark games;
- ``game names`` needs the code -> real name mapping file (private; ``--names``).

Each of them still runs, and must pass, where its files are present - on the developer's PC the
full ``tools/release_check.py`` is the release checklist. Every other line must pass here.
Exit code 0 only when no line fails.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import release_check as R                                  # noqa: E402

LOCAL_ONLY = ("dev content", "samples", "game names")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("zip")
    ap.add_argument("--installer")
    ap.add_argument("--names", help="the mapping file, if this machine has it")
    ap.add_argument("--samples", action="append", default=[], help="a clean sample folder, if present")
    args = ap.parse_args(argv)
    have = {"dev content": os.path.isdir(R.B.ENGINE_ARCHIVES),
            "samples": bool(args.samples) and all(os.path.isdir(s) for s in args.samples),
            "game names": bool(args.names) and os.path.isfile(args.names)}
    top, files = R.read(args.zip)
    with tempfile.TemporaryDirectory() as tmp:
        mapping = args.names if have["game names"] else os.path.join(tmp, "no-mapping.txt")
        if not have["game names"]:
            open(mapping, "w").close()
        lines = R.checks(top, files, mapping, args.samples)
    if args.installer:
        lines.append(R.installer_check(args.installer, files))
    failed = 0
    for i, (name, passed, detail) in enumerate(lines, 1):
        if name in LOCAL_ONLY and not have[name]:
            print("%2d. SKIP %-11s needs files that are not part of the repository" % (i, name))
            continue
        failed += not passed
        print("%2d. %-4s %-11s %s" % (i, "PASS" if passed else "FAIL", name, detail))
    print("release checklist (build machine): %s" % ("no line fails" if not failed else "%d line(s) fail" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
