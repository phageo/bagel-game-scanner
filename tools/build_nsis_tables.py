"""Build ``gamescan/nsis_official.py``: the files of the official NSIS distribution.

NSIS - the installer maker - consists of programs nobody signs: the compiler
and its window, the installer stubs every NSIS installer is built on
(``Stubs/lzma-x86-unicode`` ...: programs without a file ending), the plug-in
libraries an installer unpacks while it runs (``System.dll``,
``nsDialogs.dll``), small tools. A setup package of NSIS itself carries all
of them, and none of that is the work of whoever is scanned. This tool
writes the table the scanner compares with: the SHA-256 of **every file** of
the official distribution (phageo, 2026-10-12; as for Inno Setup and NW.js).

The same rule as the other tables: official files only, never a scanned
sample. The source is the official zip of a release (``SOURCES``), from the
NSIS project's own download place on SourceForge. It is kept in the folder of
official archives. This tool has no download of its own: a missing zip comes
through ``tools/fetch.py``, which fetches only a row of
``tools/manifest.json``, and a zip - downloaded or already there - whose
SHA-256 is not that row's is refused. The zip is never unpacked to disk and
nothing of it is run: its members are read in memory and only hashed.

    python tools/build_nsis_tables.py --archives C:\\somewhere\\engine_archives
    python tools/build_nsis_tables.py --archives ... --offline     (never downloads)

To cover another version, add its row to the manifest and the version to
``SOURCES`` (at the end: the table holds row numbers), and run again.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import zipfile
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "gamescan", "nsis_official.py")
_ZIP = "https://downloads.sourceforge.net/project/nsis/NSIS%%203/%s/nsis-%s.zip"

# (version, address, file name in the archives folder)
SOURCES: List[Tuple[str, str, str]] = [
    ("3.13", _ZIP % ("3.13", "3.13"), "nsis-3.13.zip"),
]
# what a zip must hold to be taken for the NSIS distribution
MARKS = ("makensis.exe", "Stubs/zlib-x86-unicode", "Include/MUI2.nsh")

MAX_MEMBERS = 20_000                     # entries in one zip
MAX_MEMBER = 64 * 1024 * 1024            # one file of it
MAX_UNPACKED = 512 * 1024 * 1024         # all of them
MAX_SECONDS = 600                        # reading one zip
_CHUNK = 1 << 20


class BuildError(Exception):
    pass


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


def files_of(path) -> Dict[str, str]:
    """``{path in the distribution: sha256}`` of every file of the zip, without
    the one folder the zip wraps everything in. Empty files are left out
    (every empty file is the same file). Members are read in pieces and
    hashed; nothing is written or run."""
    out: Dict[str, str] = {}
    deadline = time.monotonic() + MAX_SECONDS
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in %s" % (path,))
        tops = {info.filename.replace("\\", "/").split("/", 1)[0] for info in members}
        if len(tops) != 1 or any("/" not in info.filename.replace("\\", "/") for info in members):
            raise BuildError("%s: not one folder at the top" % (path,))
        for info in members:
            name = info.filename.replace("\\", "/").split("/", 1)[1]
            if info.file_size > MAX_MEMBER:
                raise BuildError("member too large: " + name)
            digest, size = hashlib.sha256(), 0
            with archive.open(info) as member:
                for block in iter(lambda: member.read(_CHUNK), b""):
                    size += len(block)
                    total += len(block)
                    if size > MAX_MEMBER or total > MAX_UNPACKED:
                        raise BuildError("unpacked data exceeds the limit in %s" % (path,))
                    if time.monotonic() > deadline:
                        raise BuildError("reading took too long: %s" % (path,))
                    digest.update(block)
            if size:
                out[name] = digest.hexdigest()
    return out


def build(folder: str, offline: bool = False, say=print):
    """Returns ``(archives, files)``: the rows of ``ARCHIVES`` and
    ``{sha256: (path in the distribution, indexes of the zips that hold it)}``."""
    archives, files = [], {}
    for version, url, file_name in SOURCES:
        path = os.path.join(folder, file_name)
        say("NSIS %s: %s" % (version, file_name))
        digest = obtain(url, path, offline, say)
        inside = files_of(path)
        missing = [mark for mark in MARKS if mark not in inside]
        if missing:
            raise BuildError("%s is not the NSIS distribution (no %s)" % (file_name, ", ".join(missing)))
        archives.append((version, url, digest))
        for name in sorted(inside, key=lambda n: (n.lower(), n)):
            known = files.get(inside[name])
            if known is None:
                files[inside[name]] = (name, (len(archives) - 1,))
            elif known[1][-1] != len(archives) - 1:
                files[inside[name]] = (known[0], known[1] + (len(archives) - 1,))
        say("  %d files" % len(inside))
    return archives, files


def render(archives, files) -> str:
    lines = [
        '"""Files of the official NSIS distribution, recognised by their exact content.',
        "",
        "GENERATED by tools/build_nsis_tables.py - do not edit by hand.",
        "",
        "NSIS, the installer maker, is signed by nobody. Its setup package carries the",
        "compiler, the installer stubs (programs without a file ending), the plug-in",
        "libraries and small tools; an installer made with NSIS unpacks some of those",
        "plug-in libraries while it runs. A file whose SHA-256 is in ``FILES`` *is*,",
        "byte for byte, a file of an official NSIS release: it was read out of the",
        "official zip named in ``ARCHIVES`` (address and SHA-256; a zip with another",
        "SHA-256 is refused when the table is built). Nothing here was taken from a",
        "scanned sample.",
        "",
        "Genuine does not mean harmless in every use: what an installer does with",
        "these parts - its instructions, its files - is scanned on its own.",
        '"""',
        "from __future__ import annotations",
        "",
        "from typing import Optional",
        "",
        "# version, address of the official zip, its SHA-256",
        "ARCHIVES = (",
    ]
    lines += ["    %r," % (row,) for row in archives]
    lines += [")", "",
              "# SHA-256 of the file -> (its path in the distribution, indexes into ARCHIVES of every",
              "# zip that holds it). The table is the official distribution - every file of it, on",
              "# purpose (phageo, 2026-10-12); the scanner asks it for programs only.",
              "FILES = {"]
    lines += ["    %r: %r," % (digest, entry)
              for digest, entry in sorted(files.items(), key=lambda kv: (kv[1][1], kv[1][0].lower(), kv[0]))]
    lines += ["}", "", "",
              "def verified(sha256: str) -> Optional[str]:",
              '    """What official NSIS file has this SHA-256 (None: not in the table): its path',
              '    in the distribution and the versions that hold it."""',
              '    entry = FILES.get((sha256 or "").lower())',
              "    if entry is None:",
              "        return None",
              '    return "%s - NSIS %s" % (entry[0], ", ".join(ARCHIVES[index][0] for index in entry[1]))',
              ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True, help="folder the official archives are kept in")
    parser.add_argument("--offline", action="store_true", help="never download; fail when a zip is missing")
    parser.add_argument("--out", default=OUT, help="the table to write (default: %(default)s)")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.archives):
        parser.error("not a folder: %s" % args.archives)
    try:
        archives, files = build(args.archives, args.offline)
    except (BuildError, OSError, zipfile.BadZipFile) as exc:
        print("STOPPED: %s" % exc)
        return 1
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(archives, files))
    print("%d files -> %s" % (len(files), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
