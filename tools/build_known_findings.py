"""Build ``gamescan/known_findings.json.gz``: what the readers find in the larger files of the
official npm and Electron tables, kept so that a scan does not read them again (phageo,
2026-10-14, forty-third message; ``gamescan/known_findings.py`` says how it is used).

    python tools/build_known_findings.py --archives <engine_archives> [--workers 3]

Offline: it reads the archives already kept in ``<engine_archives>`` (the Electron release zips
of ``build_electron_tables.SOURCES``, the npm package archives of ``tools/manifest_npm.json`` in
``<engine_archives>/npm``) and contacts no server. Only a member that is, by its SHA-256, a file
of ``gamescan/npm_hashes.py`` or ``gamescan/electron_official.py`` and at least
``known_findings.MIN_SIZE`` bytes is read - in memory, by the scanner itself, twice under two
unrelated paths; it is kept only when both readings give the same. Nothing is written but the
one data file; nothing of an archive is run.

Run it after every change of the package's code (the data is tied to the code's fingerprint, and
a test says when it is out of date) - and after the npm or Electron table was built again.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import itertools
import json
import os
import sys
import tarfile
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Iterator, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import build_electron_tables as E          # noqa: E402
import build_npm_hashes as N               # noqa: E402
from gamescan import electron_official, known_findings, npm_hashes   # noqa: E402

_A = "resources/app.asar!node_modules/%s"      # where such a file usually lies
_B = "elsewhere/k/%s"                           # ... and somewhere else (only its name kept)



def _npm(archives: str) -> Iterator[Tuple[str, bytes]]:
    with open(N.MANIFEST, encoding="utf-8") as fh:
        rows = json.load(fh)["files"]
    for row in rows:
        path = os.path.join(archives, N.FOLDER, row["file"])
        if not os.path.isfile(path) or os.path.getsize(path) > N.MAX_ARCHIVE:
            continue
        with open(path, "rb") as fh:
            raw = fh.read()
        package = row["file"].rsplit(".", 1)[0]
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for count, member in enumerate(archive):
                if count > N.MAX_MEMBERS:
                    break
                if not member.isreg() or member.size < known_findings.MIN_SIZE or member.size > N.MAX_MEMBER:
                    continue
                name = member.name.replace("\\", "/")
                name = name.split("/", 1)[1] if "/" in name else name
                if os.path.splitext(name)[1].lower() not in N.KEPT or name.lower() == "package.json":
                    continue
                yield "%s/%s" % (package, name), archive.extractfile(member).read()


def _electron(archives: str) -> Iterator[Tuple[str, bytes]]:
    for version, build in E.SOURCES:
        path = os.path.join(archives, E.file_name(version, build))
        if not os.path.isfile(path):
            continue
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir() or info.file_size < known_findings.MIN_SIZE or info.file_size > E.MAX_MEMBER:
                    continue
                name = info.filename.replace("\\", "/")
                if name == E.PROGRAM:
                    continue                       # (the program of an app is never this file)
                yield "electron-%s/%s" % (version, name), archive.read(info)


def files(archives: str) -> Iterator[Tuple[str, str, bytes]]:
    """``(sha256, where it was found, bytes)`` of every table file to read, each once."""
    seen = set()
    for where, data in itertools.chain(_electron(archives), _npm(archives)):
        digest = hashlib.sha256(data).hexdigest()
        if digest not in seen and (npm_hashes.verified(digest) or electron_official.verified(digest)):
            seen.add(digest)
            yield digest, where, data


def read_one(job: Tuple[str, str, bytes]) -> Tuple[str, Optional[dict], str]:
    """``(sha256, the kept reading or None, why not)`` - the file read twice."""
    digest, where, data = job
    from gamescan.scanner import neutral_scanner
    name = where.split("/", 1)[1]
    rows = []
    for path in (_A % name, _B % name.rsplit("/", 1)[-1]):
        scanner = neutral_scanner()
        scanner.known_record = {}
        scanner.scan_bytes(path, data)
        found = scanner.known_record.get(digest) or [{"unstorable": "not read"}]
        rows.append(found[0])
    if "unstorable" in rows[0]:
        return digest, None, rows[0]["unstorable"]
    if "unstorable" in rows[1] or json.dumps(rows[0], sort_keys=True) != json.dumps(rows[1], sort_keys=True):
        return digest, None, "the two readings differ"
    if rows[0]["ext"] != os.path.splitext(name)[1].lower():
        return digest, None, "another ending"
    return digest, rows[0], ""


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args(argv)
    started = time.time()
    kept: Dict[str, dict] = {}
    skipped: Dict[str, int] = {}

    def take(future) -> None:
        digest, row, why = future.result()
        if row is None:
            skipped[why] = skipped.get(why, 0) + 1
        else:
            kept[digest] = row
    with ProcessPoolExecutor(max_workers=max(1, args.workers)) as pool:
        running = []
        for job in files(args.archives):          # (a few files in memory at a time)
            running.append(pool.submit(read_one, job))
            if len(running) >= 2 * args.workers:
                done, running = running[0], running[1:]
                take(done)
        for future in running:
            take(future)
    print("%d table files of %d KB or more read" % (len(kept) + sum(skipped.values()), known_findings.MIN_SIZE >> 10))
    data = {"format": known_findings.FORMAT, "code": known_findings.fingerprint(),
            "min_size": known_findings.MIN_SIZE, "files": dict(sorted(kept.items()))}
    raw = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    with open(known_findings.DATA, "wb") as fh:          # (mtime 0: the same input, the same file)
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0, compresslevel=9) as z:
            z.write(raw)
    print("kept %d, not kept %s; %.1f MB of data (%.1f MB packed); %.0f s" % (
        len(kept), skipped or 0, len(raw) / 1e6, os.path.getsize(known_findings.DATA) / 1e6, time.time() - started))
    places, words, longest = _place_counts(kept)
    print("texts of the files kept as places: %d; words between them: %d characters, the longest %d "
          "(pieces of a file under %d characters stay words)" % (places, words, longest, known_findings.MIN_PIECE))
    return 0


def _place_counts(kept: Dict[str, dict]) -> Tuple[int, int, int]:
    """``(texts kept as places, characters of words between places, the longest such word)``."""
    counts = [0, 0, 0]

    def walk(value) -> None:
        if isinstance(value, dict):
            if set(value) == {"r", "h"}:
                counts[0] += 1
                for part in value["r"]:
                    if isinstance(part, str):
                        counts[1] += len(part)
                        counts[2] = max(counts[2], len(part))
                return
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
    walk(kept)
    return counts[0], counts[1], counts[2]


if __name__ == "__main__":
    sys.exit(main())
