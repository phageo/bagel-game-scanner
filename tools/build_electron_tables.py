"""Build ``gamescan/electron_official.py``: the files of the official Electron releases.

An Electron game is the Electron runtime - a whole browser engine, published
unsigned by the Electron project - plus the game's own code. The runtime's
libraries (``ffmpeg.dll``, ``libEGL.dll`` ...) are in a game byte for byte;
its program, ``electron.exe``, is in a game under the game's name and with
the game's icon, version text and manifest in its resource section. This tool
writes the table the scanner compares with (phageo, 2026-10-13):

* the SHA-256 of **every file** of an official release zip, and
* for ``electron.exe`` the key of everything but its resources
  (``gamescan.pe.resource_frame_key`` with ``signature=True``: the resource
  section, the checksum field and the place of a signature are left out),
  its entry point and the kinds of resources the official program holds.

The same rule as the other tables: official files only, never a scanned
sample. The source is the Windows zip of a release (``SOURCES``) from the
Electron project's releases on GitHub. This tool has no download of its own:
a missing zip comes through ``tools/fetch.py``, which fetches only a row of
``tools/manifest.json``, and a zip - downloaded or already there - whose
SHA-256 is not that row's is refused (the rows hold the SHA-256 of the
project's own ``SHASUMS256.txt``). The zip is never unpacked to disk and
nothing of it is run: its members are read in memory and only hashed.

    python tools/build_electron_tables.py --archives C:\\somewhere\\engine_archives
    python tools/build_electron_tables.py --archives ... --offline     (never downloads)

Which versions: the one of a clean benchmark sample and those the programs of
the Electron samples of the positive benchmark state (their version text
only). To cover another version, add its row to the manifest and the version
to ``SOURCES`` (at the end: the table holds row numbers), and run again.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import zipfile
from typing import Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "gamescan", "electron_official.py")
_BASE = "https://github.com/electron/electron/releases/download/v%s/"

# (version, build) - the zip is electron-v<version>-<build>.zip of that release
SOURCES: List[Tuple[str, str]] = [
    ("41.4.0", "win32-x64"),
    ("40.1.0", "win32-x64"),
    ("29.4.6", "win32-x64"),
    ("29.1.0", "win32-x64"),
    ("27.3.11", "win32-x64"),
    ("21.4.1", "win32-x64"),
    ("18.3.15", "win32-x64"),
    # the versions of the clean samples ELE-02 to ELE-04 (2026-10-13); one of them is 32-bit
    ("37.3.1", "win32-x64"),
    ("21.3.1", "win32-ia32"),
    ("43.1.1", "win32-x64"),
]
PROGRAM = "electron.exe"
# what a zip must hold to be taken for an Electron release
MARKS = (PROGRAM, "version", "resources.pak", "LICENSE")

MAX_MEMBERS = 5_000                      # entries in one zip
MAX_MEMBER = 512 * 1024 * 1024           # one file of it (the program is over 200 MB)
MAX_UNPACKED = 1024 * 1024 * 1024        # all of them
MAX_SECONDS = 900                        # reading one zip
_CHUNK = 1 << 20


class BuildError(Exception):
    pass


def file_name(version: str, build: str) -> str:
    return "electron-v%s-%s.zip" % (version, build)


def address(version: str, build: str) -> str:
    return _BASE % version + file_name(version, build)


def listing(version: str) -> str:
    """The address of the project's own checksum list of a release."""
    return _BASE % version + "SHASUMS256.txt"


def obtain(url: str, path: str, offline: bool, say=print) -> str:
    """The SHA-256 of the listed zip with the address ``url``, which then lies
    at ``path`` (``tools/fetch.py``: only a row of the manifest; any other
    file is refused)."""
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    try:
        return fetch.obtain(url, path, offline=offline, say=say)["sha256"]
    except fetch.FetchError as exc:
        raise BuildError(str(exc))


def files_of(path) -> Tuple[Dict[str, str], bytes]:
    """``({path in the release: sha256}, the program's bytes)`` of a release
    zip. Empty files are left out (every empty file is the same file).
    Members are read in pieces and hashed; nothing is written or run."""
    out: Dict[str, str] = {}
    program = b""
    deadline = time.monotonic() + MAX_SECONDS
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in %s" % (path,))
        for info in members:
            name = info.filename.replace("\\", "/")
            if info.file_size > MAX_MEMBER:
                raise BuildError("member too large: " + name)
            digest, size, kept = hashlib.sha256(), 0, []
            with archive.open(info) as member:
                for block in iter(lambda: member.read(_CHUNK), b""):
                    size += len(block)
                    total += len(block)
                    if size > MAX_MEMBER or total > MAX_UNPACKED:
                        raise BuildError("unpacked data exceeds the limit in %s" % (path,))
                    if time.monotonic() > deadline:
                        raise BuildError("reading took too long: %s" % (path,))
                    digest.update(block)
                    if name == PROGRAM:
                        kept.append(block)
            if size:
                out[name] = digest.hexdigest()
            if name == PROGRAM:
                program = b"".join(kept)
    return out, program


def program_entry(data: bytes) -> Tuple[str, int, Tuple[int, ...]]:
    """``(frame key, entry point, resource kinds)`` of an official program."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from gamescan import pe
    info = pe.parse_pe(data)
    if info is None:
        raise BuildError("the program is not a readable Windows program")
    key = pe.resource_frame_key(data, info, signature=True)
    kinds = pe.resource_kinds(data, info)
    if key is None or kinds is None or -1 in kinds:
        raise BuildError("the program's layout is not the plain one (no key, or resources that cannot be read)")
    if info.overlay_size or info.has_signature:
        raise BuildError("the official program has appended data or a signature: the table's rule would not fit")
    return key, info.entry_point, tuple(kinds)


def build(folder: str, offline: bool = False, say=print):
    """Returns ``(archives, files, programs)``: the rows of ``ARCHIVES``,
    ``{sha256: (path in the release, indexes of the zips that hold it)}`` and
    ``{frame key: (name, index, entry point, resource kinds)}`` - of the zips of
    ``SOURCES`` (every file), then of the releases the state file holds
    (code files only; :func:`download_all`)."""
    archives, files, programs = [], {}, {}
    for version, build_name in SOURCES:
        name, url = file_name(version, build_name), address(version, build_name)
        path = os.path.join(folder, name)
        say("Electron %s (%s): %s" % (version, build_name, name))
        digest = obtain(url, path, offline, say)
        inside, program = files_of(path)
        missing = [mark for mark in MARKS if mark not in inside]
        if missing:
            raise BuildError("%s is not an Electron release (no %s)" % (name, ", ".join(missing)))
        with zipfile.ZipFile(path) as archive:
            stated = archive.read("version").decode("ascii", "replace").strip().lstrip("v")
        if stated != version:
            raise BuildError("%s says it is version %r" % (name, stated))
        key, entry, kinds = program_entry(program)
        _add(archives, files, programs, (version, build_name, url, digest), inside, (key, entry, kinds))
        say("  %d files; the program: %d bytes, resource kinds %s" % (len(inside), len(program), list(kinds)))
    added = 0
    order = {}
    if os.path.isfile(ELECTRON_MANIFEST):
        order = {name: at for at, name in enumerate(_fetcher().load(ELECTRON_MANIFEST))}
    # (in the order of the manifest, whatever order the runs took them in; only what it lists)
    once = {d["file"]: d for d in read_state(state_path(folder)) if d["file"] in order}
    for done in sorted(once.values(), key=lambda d: order[d["file"]]):
        program = done["program"]
        _add(archives, files, programs, (done["version"], done["build"], done["url"], done["sha256"]),
             done["files"], (program[0], program[1], tuple(program[2])) if program else None)
        added += 1
    if added:
        say("%d release zip(s) of the state file (code files only)" % added)
    return archives, files, programs


def _add(archives, files, programs, row, inside: Dict[str, str], program) -> None:
    archives.append(tuple(row))
    index = len(archives) - 1
    for member in sorted(inside, key=lambda n: (n.lower(), n)):
        known = files.get(inside[member])
        if known is None:
            files[inside[member]] = (member, (index,))
        elif known[1][-1] != index:
            files[inside[member]] = (known[0], known[1] + (index,))
    if program is not None:
        key, entry, kinds = program
        # (the first zip that holds a program names it; until 2026-10-19 a second one stopped the
        # build - with every release, the 32- and 64-bit programs of one version stay apart anyway)
        programs.setdefault(key, (PROGRAM, index, entry, tuple(kinds)))


# -- every stable release from 5.0 on (phageo, 2026-10-19) ------------------------------------------
# Its rows are in tools/manifest_electron.json (written by --register: the SHA-256 of each zip is the
# one of that release's own SHASUMS256.txt, its size the one GitHub states). The zips are fetched one
# at a time, compared, hashed - code files only - and deleted (--download-all); what was found is kept
# in a state file beside the archives, so that a stopped run goes on where it stopped.
ELECTRON_MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest_electron.json")
STATE = "electron-code-hashes.jsonl"
CODE = (".exe", ".dll", ".node", ".asar")             # what is taken of these releases (no locales)
FIRST_MAJOR = 5
BUILDS = ("win32-x64", "win32-ia32")
MAX_PLANNED = 150 * 1000 ** 3                          # bytes: above it, 64-bit only (phageo)
SPARE = 2 * 1024 ** 3                                  # free disk kept besides the zip being fetched
LICENCE = ("Electron: MIT licence; it bundles Chromium and Node.js with their own open-source licences "
           "(LICENSES.chromium.html in the archive lists them).")
_STABLE = re.compile(r"\Av(\d+)\.(\d+)\.(\d+)\Z")


def state_path(folder: str) -> str:
    return os.path.join(folder, STATE)


def read_state(path: str) -> List[dict]:
    """The releases already hashed (a last line cut short by a stop is left out)."""
    out: List[dict] = []
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and {"file", "version", "build", "url", "sha256", "files"} <= set(item):
                out.append(item)
    return out


def _fetcher():
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    return fetch


def register(say=print, opener=None) -> Tuple[int, int]:
    """Write ``tools/manifest_electron.json``: a row for the Windows zip of every stable release
    from 5.0 on (64- and 32-bit; 64-bit only when all of them would be more than
    :data:`MAX_PLANNED`), except the zips of ``SOURCES``, which ``tools/manifest.json`` lists.
    Reads GitHub's list of releases and each release's SHASUMS256.txt; downloads no zip.
    Returns ``(rows, bytes)`` written."""
    fetch = _fetcher()
    releases = []
    for page in range(1, 11):                     # (GitHub hands out the newest 1000 releases only)
        batch = fetch.read_release_list("electron/electron", page, opener=opener)
        releases += batch
        if len(batch) < 100:
            break
    stable = []
    for release in releases:
        found = _STABLE.match(release.get("tag_name", ""))
        if found and not release.get("prerelease") and not release.get("draft") and int(found.group(1)) >= FIRST_MAJOR:
            stable.append((tuple(int(x) for x in found.groups()), release))
    lists: Dict[str, str] = {}
    stable += _older(stable, lists, fetch, say, opener)
    stable.sort(key=lambda item: item[0])
    kept = {(version, build_name) for version, build_name in SOURCES}
    planned = []
    for numbers, release in stable:
        version = "%d.%d.%d" % numbers
        sizes = {asset.get("name"): asset.get("size") for asset in release.get("assets", ())}
        for build_name in BUILDS:
            name = file_name(version, build_name)
            if (version, build_name) in kept:
                continue
            if not isinstance(sizes.get(name), int):
                say("  %s: not in the release" % name)
                continue
            planned.append((version, build_name, name, sizes[name]))
    total = sum(size for *_rest, size in planned)
    say("%d stable releases from %d.0 on; %d zips, %.1f GB" % (len(stable), FIRST_MAJOR, len(planned), total / 1000 ** 3))
    if total > MAX_PLANNED:
        planned = [item for item in planned if item[1] == "win32-x64"]
        total = sum(size for *_rest, size in planned)
        say("more than %d GB: 64-bit only - %d zips, %.1f GB" % (MAX_PLANNED // 1000 ** 3, len(planned), total / 1000 ** 3))
    rows = []
    for version, build_name, name, size in planned:
        listing_url = listing(version)
        if listing_url not in lists:
            try:
                lists[listing_url] = fetch.read_listing(listing_url, manifest={"x": {"listing": listing_url}},
                                                        opener=opener)
            except fetch.FetchError as exc:
                lists[listing_url] = ""
                say("  %s: its SHASUMS256.txt could not be read (%s)" % (version, exc))
        digest = None
        for line in lists[listing_url].splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == name and re.match(r"\A[0-9a-fA-F]{64}\Z", parts[0]):
                digest = parts[0].lower()
        if digest is None:
            say("  %s: left out (the release's SHASUMS256.txt does not name it)" % name)
            continue
        rows.append({"file": name, "what": "Electron %s (%s)" % (version, build_name), "url": address(version, build_name),
                     "sha256": digest, "size": size, "licence": LICENCE, "groups": ["archives"],
                     "used_by": "tools/build_electron_tables.py -> gamescan/electron_official.py (code files only)",
                     "listing": listing_url})
    for row in rows:
        problem = fetch._entry_problem(row)
        if problem:
            raise BuildError("a row would not be valid: " + problem)
    data = {"about": "The Electron release zips gamescan/electron_official.py takes the code files of (every stable "
                     "release from 5.0 on; tools/build_electron_tables.py --register). Each SHA-256 is the one of the "
                     "release's own SHASUMS256.txt. Fetched one at a time and deleted after hashing (--download-all).",
            "licence_notes": "Licence notes are short reminders, not legal texts.", "files": rows}
    with open(ELECTRON_MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, indent=1) + "\n")
    return len(rows), sum(row["size"] for row in rows)


def _older(stable, lists: Dict[str, str], fetch, say, opener) -> list:
    """The stable releases GitHub's list no longer reaches (it gives the newest 1000 only): each
    version of the majors from 5 on that the list does not hold is asked for by its own
    SHASUMS256.txt on github.com - a release that has one exists. Patch numbers are tried until
    three in a row have none, minor numbers until one has neither x.y.0, x.y.1 nor x.y.2. The
    zips' sizes are asked of the server. Returns entries like those of the list."""
    known = {numbers for numbers, _release in stable}
    newest = max((numbers[0] for numbers in known), default=FIRST_MAJOR)
    found = []
    for major in range(FIRST_MAJOR, newest + 1):
        minor = 0
        while minor < 50:
            misses, patch, any_patch = 0, 0, False
            while misses < 3 and patch < 200:
                numbers = (major, minor, patch)
                version = "%d.%d.%d" % numbers
                if numbers in known:
                    any_patch, misses = True, 0
                else:
                    try:
                        lists[listing(version)] = fetch.read_listing(
                            listing(version), manifest={"x": {"listing": listing(version)}}, opener=opener)
                        assets = []
                        for build_name in BUILDS:
                            try:
                                assets.append({"name": file_name(version, build_name),
                                               "size": fetch.remote_size(address(version, build_name), opener=opener)})
                            except fetch.FetchError:
                                pass                                  # (that build is not in the release)
                        found.append((numbers, {"tag_name": "v" + version, "assets": assets}))
                        any_patch, misses = True, 0
                        say("  %s: found by its SHASUMS256.txt" % version)
                    except fetch.FetchError:
                        misses += 1
                patch += 1
            if not any_patch:
                break
            minor += 1
    return found


def code_files_of(path: str) -> Tuple[Dict[str, str], bytes, str]:
    """``({path: sha256} of the code files, the program's bytes, the version the zip states)``.
    Read in memory, in pieces; nothing written or run."""
    inside, program = files_of(path)
    missing = [mark for mark in MARKS if mark not in inside]
    if missing:
        raise BuildError("%s is not an Electron release (no %s)" % (os.path.basename(path), ", ".join(missing)))
    with zipfile.ZipFile(path) as archive:
        stated = archive.read("version").decode("ascii", "replace").strip().lstrip("v")
    return {name: digest for name, digest in inside.items() if name.lower().endswith(CODE)}, program, stated


def download_all(folder: str, say=print, limit: int = 0) -> Tuple[int, int, int]:
    """Fetch, compare, hash and delete each zip of ``tools/manifest_electron.json`` that the state
    file does not hold yet, one at a time (``limit``: at most so many in this run; 0 = all).
    Returns ``(done in this run, already done, bytes downloaded in this run)``."""
    import shutil
    fetch = _fetcher()
    rows = fetch.load(ELECTRON_MANIFEST)
    path = state_path(folder)
    done = {item["file"] for item in read_state(path)}
    work = os.path.join(folder, "electron-work")
    os.makedirs(work, exist_ok=True)
    count = fetched = 0
    failed: List[str] = []
    for name, row in rows.items():
        if name in done:
            continue
        if limit and count >= limit:
            break
        if len(failed) >= 10:
            raise BuildError("stopped after 10 zips that could not be taken: %s" % ", ".join(failed))
        free = shutil.disk_usage(folder).free
        if free < row["size"] + SPARE:
            raise BuildError("stopped: %.1f GB free, %s needs %.1f GB and %d GB are kept spare"
                             % (free / 1024 ** 3, name, row["size"] / 1024 ** 3, SPARE // 1024 ** 3))
        target = os.path.join(work, name)
        try:
            try:
                fetch.fetch(row, target, say=lambda *_: None)      # compared with the listed SHA-256
            except fetch.FetchError as exc:
                # (nothing is kept of it, and the state file does not hold it: a later run tries again)
                failed.append(name)
                say("%s: NOT TAKEN - %s" % (name, exc))
                continue
            fetched += row["size"]
            code, program, stated = code_files_of(target)
            version, build_name = row["what"].split(" ")[1], row["what"].split("(")[1].rstrip(")")
            if stated != version:
                raise BuildError("%s says it is version %r" % (name, stated))
            try:
                key, entry, kinds = program_entry(program)
                found_program = [key, entry, list(kinds)]
            except BuildError as exc:
                found_program = None
                say("  %s: its program is not taken (%s)" % (name, exc))
        finally:
            if os.path.lexists(target):
                os.remove(target)                                   # deleted: hashed, never kept
        with open(path, "a+b") as fh:                       # (a line a stop cut short stays on its own)
            fh.seek(0, os.SEEK_END)
            if fh.tell():
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    fh.write(b"\n")
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"file": name, "version": version, "build": build_name, "url": row["url"],
                                 "sha256": row["sha256"], "files": code, "program": found_program}) + "\n")
        count += 1
        say("%s: %d code files%s" % (name, len(code), "" if found_program else " (no program)"))
    if failed:
        say("NOT TAKEN in this run (a later run tries again): %s" % ", ".join(failed))
    return count, len(done), fetched


def tables(files, programs) -> Dict[str, dict]:
    """The dictionaries of the table, in the order the module text gives them."""
    return {"FILES": {k: (v[0], tuple(v[1])) for k, v in sorted(files.items(), key=lambda kv: (kv[1][1], kv[1][0].lower(), kv[0]))},
            "PROGRAMS": {k: tuple(v) for k, v in sorted(programs.items(), key=lambda kv: kv[1][1])}}


def render(archives, files, programs, binary: Optional[str] = None) -> str:
    """The text of ``gamescan/electron_official.py``. ``binary``: the name of the table file
    beside it that holds ``FILES`` and ``PROGRAMS`` (``gamescan.bintable``; phageo, 2026-10-19:
    hashes stored binary); without it they are written out (tests)."""
    found = tables(files, programs)
    lines = [
        '"""Files of the official Electron releases, recognised by their exact content.',
        "",
        "GENERATED by tools/build_electron_tables.py - do not edit by hand.",
        "",
        "Electron - the browser engine many desktop games and apps are built on - is",
        "published unsigned. A file whose SHA-256 is in ``FILES`` *is*, byte for byte, a",
        "file of an official Electron release: it was read out of the official zip named",
        "in ``ARCHIVES`` (address and SHA-256 - the one of the project's own checksum",
        "list; a zip with another SHA-256 is refused when the table is built). Nothing",
        "here was taken from a scanned sample. Of the zips of the benchmark's versions",
        "every file is in it; of every other stable release from 5.0 on (since",
        "2026-10-19) the code files - programs, libraries, add-ons, app archives.",
        "",
        "The program of a game is ``electron.exe`` under the game's name with the game's",
        "icon, version text and manifest: ``PROGRAMS`` holds, for each official program,",
        "the key of everything but its resource section, its checksum field and the place",
        "of a signature (``gamescan.pe.resource_frame_key`` with ``signature=True``).",
        "",
        "Genuine does not mean harmless in every use: the runtime runs whatever code the",
        "app brings (``resources/app``, ``app.asar``), and that is scanned on its own.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Optional, Tuple",
        "",
        "# version, build, address of the official zip, its SHA-256",
        "ARCHIVES = (",
    ]
    lines += ["    %r," % (row,) for row in archives]
    lines += [")", ""]
    if binary:
        lines += ["# the dictionaries below are kept in %s beside this module, every SHA-256 as its 32" % binary,
                  "# bytes (gamescan.bintable)",
                  "from . import bintable as _bintable  # noqa: E402", "",
                  "_TABLES = _bintable.beside(__file__, %r)" % binary, ""]
    lines += ["# SHA-256 of the file -> (its path in the release, indexes into ARCHIVES of every zip",
              "# that holds it). Every file of the releases; the scanner asks it for programs and",
              "# libraries, and for the \"not read\" notes."]
    if binary:
        lines += ["FILES = _TABLES['FILES']"]
    else:
        lines += ["FILES = {"] + ["    %r: %r," % (digest, entry) for digest, entry in found["FILES"].items()] + ["}"]
    lines += ["",
              "# the program without its resources: frame key -> (name, index into ARCHIVES, entry point,",
              "# the kinds of resources the official program holds)"]
    if binary:
        lines += ["PROGRAMS = _TABLES['PROGRAMS']"]
    else:
        lines += ["PROGRAMS = {"] + ["    %r: %r," % (key, entry) for key, entry in found["PROGRAMS"].items()] + ["}"]
    lines += ["",
              'PROGRAM_VERIFIED = "official Electron program with other resources, code verified by SHA-256"',
              "ENTRY_POINTS = frozenset(entry[2] for entry in PROGRAMS.values())",
              "# what a game's maker puts into the program: icon, icon group, version, manifest",
              "BRANDING_KINDS = frozenset({3, 14, 16, 24})",
              "# a file in more releases than this is named with the first ones and a count",
              "NAMED = 10",
              "", "",
              "def _named(entry) -> str:",
              "    shown = [\"%s (%s)\" % ARCHIVES[index][:2] for index in entry[1][:NAMED]]",
              "    more = len(entry[1]) - NAMED",
              "    return \"%s - Electron %s%s\" % (entry[0], \", \".join(shown),",
              "                                   \" and %d more releases\" % more if more > 0 else \"\")",
              "", "",
              "def verified(sha256: str) -> Optional[str]:",
              '    """What official Electron file has this SHA-256 (None: not in the table): its path',
              '    in the release and the versions that hold it."""',
              '    entry = FILES.get((sha256 or "").lower())',
              "    return None if entry is None else _named(entry)",
              "", "",
              "def verified_program(frame_key: Optional[str]) -> Optional[Tuple[str, frozenset]]:",
              '    """Which official Electron program this is apart from its resources, and the kinds',
              "    of resources it may then hold - the official program's own and the branding kinds",
              '    (None: not in the table)."""',
              '    entry = PROGRAMS.get(frame_key or "")',
              "    if entry is None:",
              "        return None",
              "    return _named((entry[0], (entry[1],))), BRANDING_KINDS | frozenset(entry[3])",
              "", "",
              "def versions() -> tuple:",
              '    """The Electron versions in the table."""',
              "    return tuple(row[0] for row in ARCHIVES)",
              ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True, help="folder the official archives are kept in")
    parser.add_argument("--offline", action="store_true", help="never download; fail when a zip is missing")
    parser.add_argument("--out", default=OUT, help="the table to write (default: %(default)s)")
    parser.add_argument("--register", action="store_true",
                        help="only write tools/manifest_electron.json (reads GitHub's release list and each "
                             "release's SHASUMS256.txt; downloads no zip)")
    parser.add_argument("--download-all", action="store_true",
                        help="only fetch, compare, hash and delete the zips of tools/manifest_electron.json "
                             "that the state file does not hold yet, one at a time")
    parser.add_argument("--limit", type=int, default=0, help="with --download-all: at most so many zips")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.archives):
        parser.error("not a folder: %s" % args.archives)
    try:
        if args.register:
            count, size = register()
            print("%d zips, %d bytes -> %s" % (count, size, ELECTRON_MANIFEST))
            return 0
        if args.download_all:
            count, before, size = download_all(args.archives, limit=args.limit)
            print("%d zips hashed in this run (%d before), %d bytes downloaded" % (count, before, size))
            return 0
        archives, files, programs = build(args.archives, args.offline)
    except (BuildError, OSError, zipfile.BadZipFile) as exc:
        print("STOPPED: %s" % exc)
        return 1
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from gamescan import bintable
    binary = os.path.splitext(os.path.basename(args.out))[0] + ".bin"
    size = bintable.write(os.path.join(os.path.dirname(args.out), binary), tables(files, programs))
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(archives, files, programs, binary=binary))
    print("%d zips, %d files, %d programs -> %s (+ %s, %d bytes)" % (len(archives), len(files), len(programs),
                                                                    args.out, binary, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())