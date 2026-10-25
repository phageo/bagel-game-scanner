"""The held-out check (finish criterion 3; phageo, 2026-10-17): samples never used for tuning.

One command scans both held-out sets and writes **one baseline CSV, once**:

    python tools/heldout.py --malicious "<malicious held-out folder>" --clean <folder of clean games>
        --out docs/benchmark/heldout_baseline.csv

* **Malicious held-out samples** lie in password zips under ``<malicious>\\renpy`` and
  ``<malicious>\\electron`` (the label of a row is its sub-folder, as in the tuning set). They
  are read only by ``tools/positive_benchmark.py`` - in memory, its guard on (CLAUDE.md, rule
  19); this tool never lists, opens or copies them, it only hands the two folder paths on.
* **Clean held-out games** lie in a folder of their own, one sub-folder per game named by a
  code (rule 11), scanned by ``tools/fp_benchmark.py`` like the clean tuning set.

The baseline is written once: an existing ``--out`` is refused (a later run writes another
file). No rule may change in the session of the first held-out run (phageo) - this tool cannot
know that; CLAUDE.md records it.

Columns: ``set`` (clean / malicious), ``folder``, ``sample`` (a clean game's code, or a
malicious sample's SHA-256), ``verdict``, ``profile`` (the malicious sample's rules column; for
a clean game its counts - engine, files, CRITICAL, HIGH, MEDIUM, LOW, suppressed), ``notes``,
``same_build``: the tuning-set sample with an identical profile, if any - the same build seen
under another name, which proves nothing new about the rules.

The report says, per finish criterion: **1** (clean - no clean game SUSPICIOUS or worse) and
**2** (malicious - at least SUSPICIOUS, how many DANGEROUS), the second both with and without
the same-build samples. A held-out malicious sample that could not be read (MISSING / NOT
READ) counts as missed.
"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TUNING_POSITIVE = os.path.join(ROOT, "docs", "benchmark", "positive_after_sideload_names.csv")
TUNING_CLEAN = os.path.join(ROOT, "docs", "benchmark", "after_sideload_names.csv")
LABELS = ("renpy", "electron")
COLUMNS = ["set", "folder", "sample", "verdict", "profile", "notes", "same_build"]
ORDER = {"CLEAN": 0, "LIKELY SAFE": 1, "REVIEW": 2, "SUSPICIOUS": 3, "DANGEROUS": 4}
_CLEAN_PROFILE = ("engine", "files", "critical", "high", "medium", "low", "suppressed")


def _read(path: str) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def clean_profile(row: Dict[str, str]) -> str:
    return " ".join("%s=%s" % (key, row.get(key, "")) for key in _CLEAN_PROFILE)


def summary(row: Dict[str, str]) -> bool:
    """A "TOTAL (n games)" row of ``fp_benchmark.py`` (per engine, and all engines): no game.
    (``heldout_baseline.csv``, the round-1 baseline written once, still holds five of them -
    phageo, 2026-10-17: it is not rewritten.)"""
    return row.get("game", "").startswith("TOTAL (") and not row.get("verdict")


def same_build(profile: str, tuning: Dict[str, str]) -> str:
    """The tuning sample with exactly this profile ("" = none, or the profile is empty)."""
    return tuning.get(profile, "") if profile.strip() else ""


def merge(malicious: List[Dict[str, str]], clean: List[Dict[str, str]],
          tuning_positive: List[Dict[str, str]], tuning_clean: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """The rows of the baseline (see the module's text)."""
    known_bad = {}
    for row in tuning_positive:
        known_bad.setdefault(row.get("rules", ""), row.get("sha256", "")[:16])
    known_clean = {}
    for row in tuning_clean:
        if not summary(row):
            known_clean.setdefault(clean_profile(row), row.get("game", ""))
    out = []
    for row in clean:
        if summary(row):
            continue
        profile = clean_profile(row)
        out.append({"set": "clean", "folder": "", "sample": row.get("game", ""), "verdict": row.get("verdict", ""),
                    "profile": profile, "notes": "launcher: %s" % row.get("launcher", ""),
                    "same_build": same_build(profile, known_clean)})
    for row in malicious:
        profile = row.get("rules", "")
        out.append({"set": "malicious", "folder": row.get("folder", ""), "sample": row.get("sha256", ""),
                    "verdict": row.get("verdict", ""), "profile": profile, "notes": row.get("notes", ""),
                    "same_build": same_build(profile, known_bad)})
    return out


def report(rows: List[Dict[str, str]]) -> List[str]:
    """Lines per finish criterion: 1 for the clean set, 2 for the malicious set (with and
    without the same-build samples)."""
    lines = []
    clean = [r for r in rows if r["set"] == "clean"]
    alarmed = [r["sample"] for r in clean if ORDER.get(r["verdict"], -1) >= ORDER["SUSPICIOUS"]]
    lines.append("criterion 1 (clean held-out, %d games): %s" % (
        len(clean), "met - none SUSPICIOUS or worse" if not alarmed else
        "NOT met - SUSPICIOUS or worse: %s" % ", ".join(alarmed)))
    bad = [r for r in rows if r["set"] == "malicious"]
    for label, chosen in (("all", bad), ("without same-build samples", [r for r in bad if not r["same_build"]])):
        caught = sum(ORDER.get(r["verdict"], -1) >= ORDER["SUSPICIOUS"] for r in chosen)
        dangerous = sum(r["verdict"] == "DANGEROUS" for r in chosen)
        missed = len(chosen) - caught
        lines.append("criterion 2 (malicious held-out, %s, %d samples): %d at least SUSPICIOUS, %d DANGEROUS, "
                     "%d missed%s" % (label, len(chosen), caught, dangerous, missed,
                                      " - met" if chosen and not missed else ""))
    same = sum(1 for r in rows if r["same_build"])
    lines.append("same build as a tuning sample: %d of %d rows" % (same, len(rows)))
    return lines


def _run(command: List[str]) -> int:
    print("> " + " ".join('"%s"' % part if " " in part else part for part in command))
    return subprocess.call(command, cwd=ROOT)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--malicious", required=True, help='the held-out folder of password zips, with "renpy" '
                                                           'and "electron" in it')
    parser.add_argument("--clean", required=True, help="the folder of clean held-out games (one code per sub-folder)")
    parser.add_argument("--out", required=True, help="the baseline CSV (written once: an existing file is refused)")
    parser.add_argument("--tuning-positive", default=TUNING_POSITIVE)
    parser.add_argument("--tuning-clean", default=TUNING_CLEAN)
    args = parser.parse_args(argv)
    out = os.path.abspath(args.out)
    malicious, clean = os.path.abspath(args.malicious), os.path.abspath(args.clean)
    if os.path.lexists(out):
        parser.error("the baseline is written once - %s exists" % out)
    folders = [os.path.join(malicious, label) for label in LABELS]
    for folder in folders + [clean]:
        if not os.path.isdir(folder):
            parser.error("not a folder: %s" % folder)
    for folder in (malicious, clean):
        try:
            if os.path.commonpath([out, folder]) == folder:
                parser.error("the baseline may not be written into a sample folder")
        except ValueError:
            pass
    tuning = [os.path.abspath(p) for p in (args.tuning_positive, args.tuning_clean)]
    for path in tuning:
        if not os.path.isfile(path):
            parser.error("no tuning result: %s" % path)
    work = tempfile.mkdtemp(prefix="gss-heldout-")
    positive_csv, clean_csv = os.path.join(work, "malicious.csv"), os.path.join(work, "clean.csv")
    try:
        # (the clean games first: the positive runner's guard is in its own process anyway)
        code = _run([sys.executable, os.path.join(HERE, "fp_benchmark.py"), clean, "--out", clean_csv])
        if not os.path.isfile(clean_csv):
            print("STOPPED: the clean held-out scan wrote no result (exit code %d)" % code)
            return 1
        code = _run([sys.executable, os.path.join(HERE, "positive_benchmark.py")] + folders + ["--out", positive_csv])
        if not os.path.isfile(positive_csv):
            print("STOPPED: the malicious held-out scan wrote no result (exit code %d)" % code)
            return 1
        rows = merge(_read(positive_csv), _read(clean_csv), _read(tuning[0]), _read(tuning[1]))
    finally:
        for path in (positive_csv, clean_csv):
            if os.path.exists(path):
                os.remove(path)
        os.rmdir(work)
    with open(out, "x", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print("%d rows -> %s" % (len(rows), out))
    for line in report(rows):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
