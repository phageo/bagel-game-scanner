"""Privacy check of the source release and of the built files (source release, phageo 2026-10-25).

    python tools/privacy_check.py <folder | zip | setup.exe | file> ... [--names <mapping file>]
                                  [--word <word> ...]

Searches every file - in a folder (``.git`` left out), every member of a zip (a zip inside a zip
too), every file an Inno Setup installer installs (read in memory by the scanner's own reader,
``build_inno_tables.files_of``; nothing is unpacked or run) and the installer itself - in any case,
as UTF-8 and as UTF-16LE text, for:

 1. words      each private word (``--word``, or the variable ``BAGEL_PRIVACY_WORDS``: words split
               by commas or new lines - a secret in the workflow) as a whole word
 2. user name  the Windows user name of the PC running the check (``USERNAME``, the last part of
               ``USERPROFILE``) as a whole word
 3. users path ``<drive>:\\Users\\<name>`` (also with ``/`` or doubled ``\\``), except the made-up
               names of the tests (``TEST_USERS``) and Windows' own ``Public``
 4. abs paths  any other absolute path - ``<drive>:\\<folder>``, ``/home/<name>``, ``/Users/<name>`` -
               except a standard Windows folder (``SYSTEM_FOLDERS``: what the scanner looks for),
               and a made-up folder of the tests and examples (``MADE_UP``)
 5. game names every real game name of the mapping file (``--names``, outside the repository;
               ``build_package.real_names``), whole words, ``_`` / ``-`` / spaces alike. Never
               printed: a hit names the file only
 6. png chunks every PNG (alone, inside an ``.ico`` or a program) holds only IHDR, PLTE, tRNS,
               IDAT and IEND - no text, time, EXIF, colour profile or other metadata chunk

Compressed bytes are not searched as text (their noise looks like anything): a zip's member
names and members, a gzip file's content and the texts of the project's binary tables
(``gamescan/*.bin``) are; of a PNG only its chunk list (check 6), of a program only its own
sections - what an installer appends behind them is read as the files it installs. The files of
python.org's Python inside the package (``python/``) and the installer's own setup program (Inno
Setup's) are counted apart for checks 4 and 6: their build paths and icons are their makers'.

The words themselves are never printed and never written into this file. One line per check:
the count of files with a hit and their names; what an allowlist let through is counted on a
line of its own. Exit code 0 only when every check is 0; a check with nothing to search with
(no word, no mapping file) says SKIPPED and does not fail.
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import struct
import sys
import zipfile
from typing import Dict, Iterator, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

CHECKS = ("words", "user name", "users path", "abs paths", "game names", "png chunks")
# standard Windows folders: the scanner's rules, tests and texts name them on purpose
SYSTEM_FOLDERS = frozenset({"windows", "program files", "program files (x86)", "programdata",
                            "progra~1", "progra~2", "$recycle.bin", "system volume information"})
# made-up user names of the tests (C:\Users\<name>), and Windows' own shared profile
TEST_USERS = frozenset({"public", "x", "somebody", "dev"})
# made-up first folders of the tests and of the examples in the texts - they exist on no PC of ours
MADE_UP = frozenset({"cleangames", "samples", "documents", "sdk", "tools", "old place", "old", "a", "b",
                     "a b", 'a"b', "p y", "100%1", "50%", "nope", "g", "dev", "secretdir", "ö", "a.zip",
                     "work", "games", "game", "temp", "bagelapp", "x", "somewhere"})
MADE_UP_POSIX = frozenset({"tom", "someone"})
TABLE_MAGIC = b"GSS-TABLES 1\n"          # gamescan/bintable.py
PNG = b"\x89PNG\r\n\x1a\n"
PNG_PLAIN = frozenset({b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"})
MAX_DEPTH = 3                    # a zip inside a zip inside a zip
MAX_MEMBER = 512 * 1024 * 1024   # one member read in memory
_SEP = r"(?:\\\\|\\|/)+"
# a drive letter standing alone, a separator, then a name - not a text escape (``class A:\n``,
# ``o:\x16``) and not a separator followed by a space
_DRIVE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]:%s(?![nrtfvab0](?![A-Za-z0-9])|x[0-9a-fA-F]{2}|"
                    r"u[0-9a-fA-F]{4}|\s|[\\/])[^\"'<>|*?\r\n\t\x00`]{1,120})" % _SEP)
_POSIX = re.compile(r"(?<![A-Za-z0-9.~:\\/])/(?:home|Users)/([A-Za-z0-9._-]{1,40})")
_USERS = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:%susers%s([^\\/\"'<>|*?\r\n\t\x00]{1,40})" % (_SEP, _SEP),
                    re.IGNORECASE)


def _image_end(data: bytes) -> int:
    """Where a Windows program's sections end (the start of appended data), or its length."""
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            return len(data)
        sections, optional = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        table, end = pe + 24 + optional, 0
        for n in range(sections):
            raw_size, raw = struct.unpack_from("<II", data, table + 40 * n + 16)
            end = max(end, raw + raw_size)
        return min(max(end, table + 40 * sections), len(data))
    except struct.error:
        return len(data)


def readable(data: bytes) -> bytes:
    """What of ``data`` can hold a word: a zip's member names (its members are read one by one),
    a gzip file's content, the texts of one of the project's binary tables - not compressed or
    hashed bytes."""
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return "\n".join(z.namelist()).encode("utf-8")
        except zipfile.BadZipFile:
            return data
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
                return fh.read(MAX_MEMBER)
        except (OSError, EOFError):
            return data
    if data.startswith(PNG):
        # the picture data (IDAT) is compressed; the other chunks are check 6's
        return b""
    if data[:2] == b"MZ":
        # a program: its own sections, not what is appended behind them (an installer's
        # compressed files - each of them is read on its own)
        return data[:_image_end(data)]
    if data.startswith(TABLE_MAGIC):
        try:
            at, texts = len(TABLE_MAGIC) + 4, []
            for _ in range(struct.unpack_from("<I", data, len(TABLE_MAGIC))[0]):
                size = struct.unpack_from("<I", data, at)[0]
                texts.append(data[at + 4:at + 4 + size])
                at += 4 + size
            return b"\n".join(texts)
        except struct.error:
            return data
    return data


def _texts(data: bytes) -> List[str]:
    """The bytes as UTF-8 text and as UTF-16LE text (both byte alignments)."""
    out = [data.decode("utf-8", "replace")]
    if b"\x00" in data:
        out += [data.decode("utf-16-le", "replace"), data[1:].decode("utf-16-le", "replace")]
    return out


def _whole(words: List[str]) -> Optional["re.Pattern"]:
    """One pattern for whole words, any case; ``_`` / ``-`` / spaces between the parts alike."""
    parts = []
    for word in words:
        bits = [re.escape(b) for b in re.split(r"[\s_-]+", word.strip()) if b]
        if bits:
            parts.append(r"[\s_-]*".join(bits))
    if not parts:
        return None
    return re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(sorted(parts, key=len, reverse=True)),
                      re.IGNORECASE)


def user_names(env: Optional[Dict[str, str]] = None) -> List[str]:
    env = os.environ if env is None else env
    out = []
    for name in (env.get("USERNAME", ""), os.path.basename(env.get("USERPROFILE", "").rstrip("\\/"))):
        if len(name) >= 3 and name.lower() not in [n.lower() for n in out]:
            out.append(name)
    return out


def users_paths(text: str) -> Tuple[int, int]:
    """``(hits, allowed)`` of ``<drive>:\\Users\\<name>`` in ``text``."""
    hits = allowed = 0
    for m in _USERS.finditer(text):
        name = re.split(r"[\\/]", m.group(1))[0].strip().lower()
        if name in TEST_USERS:
            allowed += 1
        else:
            hits += 1
    return hits, allowed


def abs_paths(text: str) -> Tuple[int, int]:
    """``(hits, allowed)``: the absolute paths of ``text`` other than ``<drive>:\\Users\\`` (check 3)."""
    hits = allowed = 0
    for m in _DRIVE.finditer(text):
        path = m.group(1)
        rest = re.sub(r"^[A-Za-z]:" + _SEP, "", path)
        first = re.split(r"[\\/]|\s{2,}| --|\" ", rest)[0].strip().rstrip(".,;:)").lower()
        if first == "users":
            continue
        # a drive alone ("C:\") or a placeholder ("D:\...\") names no folder of a PC
        if not re.match(r"[a-z0-9_%$]", first.strip(". ")) or first in SYSTEM_FOLDERS \
                or first in MADE_UP or first.startswith("%"):
            allowed += 1
        else:
            hits += 1
    for m in _POSIX.finditer(text):
        if m.group(1).lower() in MADE_UP_POSIX:
            allowed += 1
        else:
            hits += 1
    return hits, allowed


def png_extra(data: bytes) -> List[str]:
    """The chunk types other than ``PNG_PLAIN`` of every PNG inside ``data``."""
    extra = []
    at = data.find(PNG)
    while at >= 0:
        pos = at + 8
        while pos + 8 <= len(data):
            length, kind = struct.unpack_from(">I4s", data, pos)
            if not kind.isalpha() or length > len(data):
                break
            if kind not in PNG_PLAIN:
                extra.append(kind.decode("ascii"))
            pos += 12 + length
            if kind == b"IEND":
                break
        at = data.find(PNG, at + 8)
    return extra


# -- what is read ---------------------------------------------------------------------------------
def _zip_members(label: str, data: bytes, depth: int = 0) -> Iterator[Tuple[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size > MAX_MEMBER:
                continue
            inner = z.read(info)
            name = label + "!" + info.filename
            yield name, inner
            if inner[:4] == b"PK\x03\x04" and depth < MAX_DEPTH:
                try:
                    yield from _zip_members(name, inner, depth + 1)
                except zipfile.BadZipFile:
                    pass


def tracked(folder: str) -> List[str]:
    """The files git tracks in ``folder`` (relative, ``/``): what a commit of it holds."""
    import subprocess
    done = subprocess.run(["git", "-C", folder, "ls-files", "-z"], capture_output=True, check=True)
    return sorted(n for n in done.stdout.decode("utf-8").split("\0") if n)


def units(path: str, only_tracked: bool = False) -> Iterator[Tuple[str, bytes]]:
    """``(name, bytes)`` of everything ``path`` holds (of a folder: only what git tracks, when
    ``only_tracked``)."""
    if os.path.isdir(path):
        wanted = set(tracked(path)) if only_tracked else None
        for base, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d != ".git")
            for name in sorted(files):
                full = os.path.join(base, name)
                if wanted is not None and os.path.relpath(full, path).replace("\\", "/") not in wanted:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                rel = os.path.relpath(full, path).replace("\\", "/")
                yield rel, data
                if data[:4] == b"PK\x03\x04":
                    try:
                        yield from _zip_members(rel, data, 1)
                    except zipfile.BadZipFile:
                        pass
        return
    label = os.path.basename(path)
    with open(path, "rb") as fh:
        data = fh.read()
    yield label, data
    if data[:4] == b"PK\x03\x04":
        yield from _zip_members(label, data)
    elif data[:2] == b"MZ" and label.lower().endswith("-setup.exe"):
        import build_inno_tables
        for name, inner in sorted(build_inno_tables.files_of(path).items()):
            yield label + "!" + name, inner
            if inner[:4] == b"PK\x03\x04":
                try:
                    yield from _zip_members(label + "!" + name, inner, 1)
                except zipfile.BadZipFile:
                    pass


def third_party(name: str) -> bool:
    """A file of python.org's Python inside the package (``python/...``), or the installer's own
    setup program (Inno Setup's, compiled by its makers; what it installs is read apart)."""
    inner = re.split(r"!", name)
    if len(inner) == 1 and name.lower().endswith("-setup.exe"):
        return True
    return any(re.match(r"^(Bagel-[^/]+/)?python/", part) for part in inner[1:])


# -- the check ------------------------------------------------------------------------------------
def run(paths: List[str], words: List[str], mapping: Optional[str] = None,
        env: Optional[Dict[str, str]] = None, only_tracked: bool = False) -> Dict[str, dict]:
    """``{check: {"files": [names with a hit], "skipped": why or "", "searched": n, "allowed": n}}``,
    and the python.org lines ``"third-party abs paths"`` / ``"third-party png chunks"`` (counted,
    never failing)."""
    word_re = _whole(words)
    user_re = _whole(user_names(env))
    names: Dict[str, List[str]] = {}
    if mapping:
        import build_package
        names = build_package.real_names(mapping)
    name_re = _whole([n for found in names.values() for n in found])
    lines = CHECKS + ("third-party abs paths", "third-party png chunks")
    result = {c: {"files": [], "skipped": "", "searched": 0, "allowed": 0} for c in lines}
    result["words"]["skipped"] = "" if word_re else "no private word given (--word / BAGEL_PRIVACY_WORDS)"
    result["user name"]["skipped"] = "" if user_re else "no Windows user name in the environment"
    result["game names"]["skipped"] = "" if name_re else "no mapping file given (--names)"
    total = 0
    for path in paths:
        for name, data in units(path, only_tracked):
            total += 1
            outside = third_party(name)
            hit = {c: False for c in lines}
            for text in _texts(readable(data)):
                hit["words"] |= bool(word_re and word_re.search(text))
                hit["user name"] |= bool(user_re and user_re.search(text))
                found, allowed = users_paths(text)
                hit["users path"] |= bool(found)
                result["users path"]["allowed"] += allowed
                found, allowed = abs_paths(text)
                hit["third-party abs paths" if outside else "abs paths"] |= bool(found)
                result["abs paths"]["allowed"] += allowed
                hit["game names"] |= bool(name_re and name_re.search(text))
            hit["third-party png chunks" if outside else "png chunks"] = bool(png_extra(data))
            for check in lines:
                if hit[check] and not result[check]["skipped"] and name not in result[check]["files"]:
                    result[check]["files"].append(name)
    for check in lines:
        result[check]["searched"] = total
    return result


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+", help="folders, zips, the installer, programs")
    ap.add_argument("--names", help="the code -> real name mapping file (outside the repository)")
    ap.add_argument("--word", action="append", default=[], help="a private word (repeatable; never printed)")
    ap.add_argument("--tracked", action="store_true", help="of a folder, only the files git tracks")
    args = ap.parse_args(argv)
    words = list(args.word) + [w.strip() for w in re.split(r"[,\r\n]+", os.environ.get("BAGEL_PRIVACY_WORDS", ""))
                               if w.strip()]
    result = run(args.paths, words, args.names, only_tracked=args.tracked)
    failed = 0
    for check, entry in result.items():
        if entry["skipped"]:
            print("%-22s SKIPPED (%s)" % (check, entry["skipped"]))
            continue
        files = entry["files"]
        counted = check.startswith("third-party")
        failed += bool(files) and not counted
        print("%-22s %s %d of %d files%s%s" % (
            check, "info" if counted else ("FAIL" if files else "PASS"), len(files), entry["searched"],
            "" if not entry["allowed"] else " (allowlisted places: %d)" % entry["allowed"],
            (": " + ", ".join(files[:12]) + (" ..." if len(files) > 12 else "")) if files and not counted else ""))
    print("privacy check: %s" % ("all checks 0" if not failed else "%d check(s) with hits" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
