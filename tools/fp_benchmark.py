"""False-positive benchmark.

Point it at a folder whose sub-folders are games you know to be clean. Every
sub-folder is scanned and the result is written to a CSV: one row per game
(detected engine, findings per severity and what the secure launcher would do
with it), then one total row per engine and a grand total. Run it before and
after changing a rule and compare the two files - on known-clean games every
finding is a false alarm, so lower is better.

Every game is scanned twice: once for the benchmark and once the way the
secure launcher scans it (its temporary folder, the Windows antimalware
engine switched on). The two lists of findings must be the same; every
difference is printed, counted in the ``launcher_diff`` column, and makes the
exit code 1.

    python tools/fp_benchmark.py D:\\CleanGames --out before.csv
    (change a rule)
    python tools/fp_benchmark.py D:\\CleanGames --out after.csv --rules after_rules.csv

Three games are scanned at once (``--workers``), each in a process of its own
with a temporary folder of its own; the rows are written in the order of the
games' names. The result files hold no times, so the same games always give
the same files, byte for byte - whatever ``--workers`` is and however busy the
PC. (``--times FILE`` writes the seconds per game.)

``--rules`` additionally writes how often each rule fired, which shows *which*
rule is responsible for a change. Nothing is executed, quarantined, uploaded
or remembered: the scan uses the built-in rules only. Nothing of the user's
profile is read either - no memory center (scan history, feedback), no allow
list - so the result does not depend on what was scanned or marked before.

The cache of unpacked and parsed files (``gamescan/cache.py``) is not used
unless ``--cache`` asks for it - then for the benchmark's own scan only; the
scan the launcher's way never uses it. With or without, the result files must
be the same, byte for byte: ``--cache`` is there to measure the time it saves
(``--cache-dir`` names its folder, ``--times`` writes the seconds).
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import csv
import multiprocessing
import os
import shutil
import sys
import tempfile
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gamescan import Scanner, Severity, cache, launcher, neutral_scanner  # noqa: E402

LEVELS = [s.name for s in reversed(Severity)]            # CRITICAL .. LOW
# (no "seconds" column since 2026-10-12: the same games give the same file, byte for byte,
# however many are scanned at once; the times are printed, and written with --times)
COLUMNS = ["game", "engine", "verdict", "files"] + [n.lower() for n in LEVELS] + \
    ["suppressed", "errors", "launcher", "launcher_diff"]
WORKERS = 3                 # games scanned at once (measured 2026-10-12: a third of the time)
# the launcher shows extracted content to the Windows antimalware engine unless told not to
LAUNCHER_AMSI = True


def new_scanner(strict: bool = False) -> Scanner:
    """A scanner that knows nothing about this PC's user: no memory center and
    no allow list. It is the scanner the secure launcher uses."""
    return neutral_scanner(strict=strict)


def launcher_scan(path: str, strict: bool = False):
    """The report of the scan the secure launcher makes of a game folder: the
    same scanner function, its own temporary folder, the Windows antimalware
    engine on. (Not the user's hash list or YARA rules: the benchmark reads
    nothing of the profile.)"""
    return launcher.scan_folder(neutral_scanner(strict=strict, amsi=LAUNCHER_AMSI), path)


def differences(benchmark, launched) -> List[str]:
    """What the two reports do not have in common, one line per finding."""
    def keys(report):
        return collections.Counter(
            (f.severity.name, f.rule_id, f.file, "suppressed" if f.suppressed else "active")
            for f in report.findings)
    ours, theirs = keys(benchmark), keys(launched)
    out = ["only in the launcher's scan:  %-8s %s  %s  (%s)" % key
           for key in sorted((theirs - ours).elements())]
    out += ["only in the benchmark's scan: %-8s %s  %s  (%s)" % key
            for key in sorted((ours - theirs).elements())]
    if len(benchmark.errors) != len(launched.errors):
        out.append("files that could not be read: %d in the benchmark's scan, %d in the launcher's"
                   % (len(benchmark.errors), len(launched.errors)))
    return out


def scan_game(name: str, path: str, strict: bool = False) -> tuple:
    """One game: ``(row, rule_counts, launcher_differences, seconds)``."""
    started = time.time()
    report = new_scanner(strict).scan(path)
    seconds = round(time.time() - started, 1)
    launched = launcher_scan(path, strict)
    lines = differences(report, launched)
    counts = report.counts()
    row = {"game": name, "engine": " + ".join(report.engines) or "unknown",
           "verdict": str(report.verdict), "files": report.files_scanned,
           "suppressed": len(report.suppressed), "errors": len(report.errors),
           # what the secure launcher does with its own scan of the game:
           # start, ask (one confirmation), ask-word (type "launch"), block
           "launcher": launcher.decide(launched).action,
           # findings its scan and the benchmark's do not share (0 = the same)
           "launcher_diff": len(lines)}
    row.update({level.lower(): counts[level] for level in LEVELS})
    rules: Dict[tuple, int] = collections.OrderedDict()
    for finding in report.active:
        key = (finding.rule_id, finding.severity.name)
        rules[key] = rules.get(key, 0) + 1
    return row, rules, lines, seconds


def _work(job: tuple) -> tuple:
    """One game in a process of its own, with a temporary folder of its own (so that two
    scans at once never see each other's temporary files): what :func:`scan_game` gives,
    and how many files the scan left behind in that folder."""
    global LAUNCHER_AMSI
    name, path, strict, amsi, scratch, kept = job
    os.makedirs(scratch, exist_ok=True)
    os.environ["TEMP"] = os.environ["TMP"] = scratch
    tempfile.tempdir = scratch
    LAUNCHER_AMSI = amsi
    cache.configure(kept, enabled=bool(kept))
    row, rules, lines, seconds = scan_game(name, path, strict)
    left = sum(len(files) for _base, _folders, files in os.walk(scratch))
    return name, row, list(rules.items()), lines, seconds, left


def _worker():
    """:func:`_work` as the processes of the pool can find it by name."""
    if __name__ == "__main__":
        return _work
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import fp_benchmark
    return fp_benchmark._work


def scan_games(root: str, strict: bool = False, workers: int = 1, times: Optional[dict] = None) -> tuple:
    """``(rows, rule_counts, launcher_differences)`` for every sub-folder of
    ``root``; the last maps a game to the lines of :func:`differences`.
    ``workers``: how many games are scanned at once, each in its own process
    with its own temporary folder (1: one after the other, in this process).
    The result is put together in the order of the games' names, so it does
    not depend on ``workers``. ``times``: filled with game -> seconds."""
    games = [(name, os.path.join(root, name)) for name in sorted(os.listdir(root))
             if os.path.isdir(os.path.join(root, name))]
    done = {}
    if workers <= 1 or len(games) <= 1:
        for name, path in games:
            row, rules, lines, seconds = scan_game(name, path, strict)
            done[name] = (row, list(rules.items()), lines, seconds)
    else:
        work = _worker()                    # (before the processes start: they need its place)
        scratch = tempfile.mkdtemp(prefix="gss-bench-")
        # a new process for every game where Python can do that (3.11 and later): nothing one
        # scan keeps in memory reaches the next. A process that dies ends the run with an error.
        fresh = {"max_tasks_per_child": 1} if sys.version_info >= (3, 11) else {}
        try:
            jobs = [(name, path, strict, LAUNCHER_AMSI, os.path.join(scratch, "%03d" % index), cache.directory())
                    for index, (name, path) in enumerate(games)]
            with concurrent.futures.ProcessPoolExecutor(
                    min(workers, len(games)), mp_context=multiprocessing.get_context("spawn"), **fresh) as pool:
                for future in concurrent.futures.as_completed([pool.submit(work, job) for job in jobs]):
                    name, row, rules, lines, seconds, left = future.result()
                    done[name] = (row, rules, lines, seconds)
                    print("  %-12s %6.1f s%s" % (name, seconds, "" if not left else
                                                 "   LEFT %d temporary file(s) behind" % left), flush=True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    rows: List[Dict[str, object]] = []
    counted: Dict[tuple, int] = collections.OrderedDict()
    differing: Dict[str, List[str]] = collections.OrderedDict()
    for name, _path in games:
        row, rules, lines, seconds = done[name]
        rows.append(row)
        for key, count in rules:
            counted[tuple(key)] = counted.get(tuple(key), 0) + count
        if lines:
            differing[name] = lines
        if times is not None:
            times[name] = seconds
    return rows, counted, differing


def totals(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """One "TOTAL" row per engine, then a grand total."""
    numeric = ["files"] + [n.lower() for n in LEVELS] + ["suppressed", "errors", "launcher_diff"]
    groups: Dict[str, List[Dict[str, object]]] = collections.OrderedDict()
    for row in rows:
        groups.setdefault(str(row["engine"]), []).append(row)
    out = []
    for engine, members in list(groups.items()) + [("all engines", rows)]:
        total = {"game": "TOTAL (%d games)" % len(members), "engine": engine, "verdict": ""}
        for column in numeric:
            total[column] = sum(int(m[column]) for m in members)
        out.append(total)
    return out


def write_csv(path: str, rows: List[Dict[str, object]], columns: List[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:      # opens cleanly in Excel
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folder", help="folder that contains one sub-folder per clean game")
    parser.add_argument("--out", default="fp_benchmark.csv", help="result CSV (default: %(default)s)")
    parser.add_argument("--rules", metavar="FILE", help="also write per-rule counts to FILE")
    parser.add_argument("--strict", action="store_true", help="scan in strict mode")
    parser.add_argument("--workers", type=int, default=WORKERS, metavar="N",
                        help="games scanned at once, each in its own process with its own temporary "
                             "folder (default: %(default)s; 1: one after the other). The result "
                             "files do not depend on it.")
    parser.add_argument("--times", metavar="FILE", help="also write the seconds per game to FILE")
    parser.add_argument("--cache", action="store_true",
                        help="use the cache of unpacked and parsed files for the benchmark's own scan "
                             "(never for the launcher's): the result files must not differ - only the time")
    parser.add_argument("--cache-dir", metavar="FOLDER",
                        help="with --cache: the cache's folder (default: the user's own cache)")
    args = parser.parse_args(argv)
    cache.configure(os.path.abspath(args.cache_dir) if args.cache_dir else cache.default_directory(),
                    enabled=args.cache)
    if not os.path.isdir(args.folder):
        parser.error("not a folder: %s" % args.folder)
    if not 1 <= args.workers <= 16:
        parser.error("--workers: 1 to 16")
    times: Dict[str, float] = {}
    started = time.time()
    rows, rules, differing = scan_games(args.folder, args.strict, args.workers, times)
    if not rows:
        parser.error("no sub-folders (games) found in %s" % args.folder)
    summary = totals(rows)
    write_csv(args.out, rows + summary, COLUMNS)
    if args.times:
        write_csv(args.times, [{"game": game, "seconds": seconds} for game, seconds in times.items()],
                  ["game", "seconds"])
    print("%.0f s in all (%d at once); the scans alone: %.0f s%s"
          % (time.time() - started, args.workers, sum(times.values()),
             "; cache: %s" % cache.directory() if cache.directory() else ""))
    if args.rules:
        write_csv(args.rules, [{"rule": rule, "severity": level, "count": count}
                               for (rule, level), count in sorted(rules.items(), key=lambda kv: -kv[1])],
                  ["rule", "severity", "count"])
    grand = summary[-1]
    print("%d games scanned -> %s" % (len(rows), os.path.abspath(args.out)))
    print("false alarms: " + ", ".join("%s %d" % (level.lower(), grand[level.lower()])
                                       for level in LEVELS))
    decisions = collections.Counter(str(row["launcher"]) for row in rows)
    print("launcher: " + ", ".join("%s %d" % item for item in sorted(decisions.items())))
    if not differing:
        print("launcher check: OK - the launcher's scan found the same as the benchmark's "
              "in all %d games" % len(rows))
        return 0
    print("")
    print("LAUNCHER CHECK FAILED: the launcher's scan differs from the benchmark's in %d of %d "
          "games" % (len(differing), len(rows)))
    for game, lines in differing.items():
        print("  %s: %d difference(s)" % (game, len(lines)))
        for line in lines[:20]:
            print("      " + line)
        if len(lines) > 20:
            print("      ... and %d more" % (len(lines) - 20))
    return 1


if __name__ == "__main__":
    sys.exit(main())
