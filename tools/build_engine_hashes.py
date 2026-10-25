"""Build ``gamescan/engine_hashes.py``: SHA-256 of official engine builds.

NW.js (as shipped with RPG Maker MV / MZ) and the Python runtime Ren'Py
bundles are not signed by anybody, so a signature cannot prove such a file
genuine. Its exact content can: this tool downloads the *official* release
archives, hashes every program and library inside them, and writes the table
the scanner compares files with.

    python tools/build_engine_hashes.py --archives C:\\somewhere\\engine_archives

Sources are the publishers' own download servers only (``dl.nwjs.io``, which
hands the files out through the project's ``dl.node-webkit.org``, and
``www.renpy.org``) - never a game. Each archive is checked against the
SHA-256 the publisher lists for it where there is such a list; its own
SHA-256 is written into the table either way, so a later run can tell
whether the archive changed. Nothing is run and nothing is unpacked to disk:
members are read from the zip in memory, in pieces, and only hashed.

Archives already in the folder are not downloaded again (``--offline`` never
downloads). This tool has no download of its own (phageo, 2026-10-12): every
archive comes through ``tools/fetch.py``, which fetches only a row of
``tools/manifest.json`` and refuses a file - downloaded or already there -
whose SHA-256 is not the row's; the publishers' checksum lists are read
through it too. To cover another version, add its row to the manifest and
the version to ``SOURCES``, and run again.

From the Ren'Py SDKs the engine's own scripts are taken as well (``.py``,
``.rpy``, ``.rpym`` and the compiled ``.rpyc`` / ``.rpymc`` under ``renpy/``
and ``lib/``): by the SHA-256 of the file, and - compiled scripts - also by
what they contain (``gamescan.unpack.rpyc.content_key``), because a compiled
script carries the folder of whoever compiled it and is therefore never the
same file twice. The compiled scripts are read with the scanner's own
reader, which rebuilds them from inert stand-in objects; nothing is run.
The SDK's shell launcher (``renpy.sh``, beside those two folders) goes into
the table of files by its SHA-256.

``--hosts`` limits which servers may be contacted in this run; an archive of
another server is then used as it is in the folder, and whether its SHA-256
was confirmed against the publisher's list is taken from the existing table.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import zipfile
from typing import Dict, List, Optional, Tuple

# the servers of this tool's sources (for --hosts; the asking itself is tools/fetch.py's,
# which also knows where dl.nwjs.io hands a download on to)
HOSTS = frozenset({"dl.nwjs.io", "www.renpy.org", "download.unity3d.com"})
NWJS = "https://dl.nwjs.io/v{v}/{flavor}-v{v}-win-{arch}.zip"
RENPY = "https://www.renpy.org/dl/{v}/renpy-{v}-sdk.zip"
# Unity: the Windows player files (Mono) as Unity publishes them for its macOS editor - the
# smallest official package that holds them (105 MB; the Windows editor installer is 1.5 GB).
# {c} is the release's changeset. Unity lists an MD5 for each package in the release's
# .ini file and publishes no SHA-256.
UNITY = ("https://download.unity3d.com/download_unity/{c}/MacEditorTargetInstaller/"
         "UnitySetup-Windows-Mono-Support-for-Editor-{v}.pkg")
UNITY_LISTING = "https://download.unity3d.com/download_unity/{c}/unity-{v}-osx.ini"
# archive file name -> the MD5 its publisher lists (read from the listing on 2026-10-07;
# 2019.2.6f1 on 2026-10-11).
# The package is compared with it before it is read, online or not; online the listing
# has to say the same.
MD5 = {
    "UnitySetup-Windows-Mono-Support-for-Editor-2019.3.6f1.pkg": "50fd9e65e091f925a5afa024349dc734",
    "UnitySetup-Windows-Mono-Support-for-Editor-2019.2.6f1.pkg": "922bbb85e179cfa6f771f5bb91b05b45",
}

ADDED_RENPY = (
    "6.99.12", "6.99.12.1", "6.99.12.2", "6.99.12.3", "6.99.13", "6.99.14",
    "6.99.14.1", "6.99.14.2", "6.99.14.3", "7.0.0", "7.1.0", "7.1.1", "7.1.2", "7.1.3", "7.2.0", "7.2.1",
    "7.2.2", "7.3.0", "7.3.1", "7.3.2", "7.3.3", "7.3.4", "7.4.0", "7.4.1", "7.4.2", "7.4.3", "7.4.4",
    "7.4.5", "7.4.6", "7.4.7", "7.4.8", "7.4.9", "7.4.10", "7.5.0", "7.5.1", "7.5.2", "7.6.0", "7.6.1",
    "7.6.2", "7.7.0", "7.7.1", "7.7.2", "7.8.0", "7.8.1", "7.8.2", "7.8.3", "7.8.4", "7.8.5", "7.8.6",
    "8.0.0", "8.0.1", "8.0.2", "8.1.0", "8.1.1", "8.1.2", "8.2.0", "8.2.1", "8.2.2", "8.3.0", "8.3.1",
    "8.3.2", "8.3.3", "8.3.4", "8.3.5", "8.3.6", "8.4.0", "8.5.0", "8.5.1", "8.5.2")

# (engine, version, build, archive URL, URL of the publisher's checksum list)
SOURCES: List[Tuple[str, str, str, str, str]] = [
    ("NW.js", v, "%s, win-%s" % ("sdk" if flavor.endswith("sdk") else "normal", arch),
     NWJS.format(v=v, flavor=flavor, arch=arch), "https://dl.nwjs.io/v%s/SHASUMS256.txt" % v)
    for v in ("0.29.0", "0.48.4") for flavor in ("nwjs", "nwjs-sdk") for arch in ("ia32", "x64")
] + [
    ("Ren'Py", v, "SDK", RENPY.format(v=v), "https://www.renpy.org/dl/%s/checksums.txt" % v)
    # the two versions of the benchmark samples, then the last release of the 7.4 - 7.6
    # and 8.0 - 8.4 series (chosen 2026-10-05), then the last release of the 7.7, 7.8 and
    # 8.5 series as of 2026-10-06 (new ones go at the end: the tables hold row numbers).
    # 8.6.0 is left out: renpy.org publishes no checksum list for it (yet), and a Ren'Py
    # archive only enters the table when its SHA-256 matches the published one
    for v in ("6.99.12.4", "7.3.5", "7.4.11", "7.5.3", "7.6.3", "8.0.3", "8.1.3", "8.2.3",
              "8.3.7", "8.4.1", "7.7.3", "7.8.7", "8.5.3")
] + [
    # the version of benchmark sample UNI-02, whose 32-bit player files Unity did not sign;
    # then the version of UNI-01 (phageo, 2026-10-11: a version is added when a real sample
    # needs one; the changeset is the one UNI-01's own UnityPlayer.dll names). New ones go
    # at the end: the tables hold row numbers
    ("Unity", v, "Windows Mono player support", UNITY.format(c=c, v=v), UNITY_LISTING.format(c=c, v=v))
    for v, c in (("2019.3.6f1", "5c3fb0a11183"), ("2019.2.6f1", "fe82a0e88406"))
] + [
    # the Ren'Py SDKs that were missing (phageo, 2026-10-19): every release older than 8.6.0 whose
    # checksum list on renpy.org names its SDK zip - from 6.99.12 on; none of 6.x before 6.99.10, of
    # 7.0.1 or of 8.6.0 has a list, the lists of 6.99.10 / 6.99.11 name no zip, and 7.1.4's names
    # the 7.2.0 files - none of these is taken. (69 SDKs, 8.9 GB.)
    ("Ren'Py", v, "SDK", RENPY.format(v=v), "https://www.renpy.org/dl/%s/checksums.txt" % v)
    for v in ADDED_RENPY
]

PROGRAMS = (".exe", ".dll", ".pyd")
SCRIPTS = (".py", ".rpy", ".rpym", ".rpyc", ".rpymc")     # engine scripts of a Ren'Py SDK
COMPILED = (".rpyc", ".rpymc")
SCRIPT_FOLDERS = ("renpy", "lib")                         # second path component in the SDK
MAX_SCRIPT = 16 * 1024 * 1024            # one engine script
MAX_ARCHIVE = 512 * 1024 * 1024          # one downloaded archive
MAX_CHECKSUMS = 4 * 1024 * 1024          # one checksum list
MAX_MEMBERS = 50_000                     # entries in one archive
MAX_MEMBER = 512 * 1024 * 1024           # one unpacked program
MAX_UNPACKED = 4 * 1024 * 1024 * 1024    # all programs of one archive
MAX_SECONDS = 1800                       # per download / per archive
_CHUNK = 1 << 20


class BuildError(Exception):
    pass


def _fetcher():
    """``tools/fetch.py``: the one place of this project that contacts a server.
    This tool has no download of its own (phageo, 2026-10-12): an archive comes
    through ``fetch.obtain`` - only a row of ``tools/manifest.json``, compared
    with its SHA-256 -, a publisher's checksum list through ``fetch.read_listing``."""
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    return fetch


def _host(url: str) -> str:
    return url.split("/")[2] if url.count("/") >= 2 else ""


def _listing(listing_url: str) -> Optional[str]:
    """The text of a publisher's checksum list (None: it could not be read)."""
    fetch = _fetcher()
    try:
        return fetch.read_listing(listing_url)
    except fetch.FetchError:
        return None


def published_sha256(listing_url: str, file_name: str) -> Optional[str]:
    """The SHA-256 the publisher lists for ``file_name`` (None: no list, or
    the file is not on it - old NW.js releases have an empty list)."""
    text = _listing(listing_url)
    if text is None:
        return None
    for line in text.splitlines():
        parts = line.split()
        if (len(parts) == 2 and parts[1].lstrip("*") == file_name and len(parts[0]) == 64
                and all(c in "0123456789abcdefABCDEF" for c in parts[0])):
            return parts[0].lower()
    return None


RENPY_LICENCE = ("Ren'Py: MIT licence for the engine; it bundles libraries under other licences, some LGPL "
                 "(the LICENSE.txt in the archive lists them).")


def register(manifest_path: str, say=print, opener=None) -> List[str]:
    """Add the manifest row of every Ren'Py archive of ``SOURCES`` that has none yet: its
    SHA-256 from the publisher's own checksum list (never computed here), its size as the
    server states it. An archive whose list does not name it is left out and said. Contacts
    renpy.org for the lists and the sizes; downloads nothing. Returns the files added."""
    import json
    fetch = _fetcher()
    with open(manifest_path, "r", encoding="utf-8") as fh:
        original = fh.read()
    data = json.loads(original)
    if json.dumps(data, indent=1) + "\n" != original:
        raise BuildError("the manifest is not in the form this tool writes; nothing was changed")
    listed = {row["url"] for row in data["files"]}
    added: List[str] = []
    for engine, version, build_name, url, listing in SOURCES:
        if engine != "Ren'Py" or url in listed:
            continue
        name = url.rsplit("/", 1)[-1]
        try:
            text = fetch.read_listing(listing, manifest={name: {"listing": listing}}, opener=opener)
            size = fetch.remote_size(url, opener=opener)
        except fetch.FetchError as exc:
            say("  %s: left out (%s)" % (name, exc))
            continue
        digest = None
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == name and len(parts[0]) == 64:
                digest = parts[0].lower()
        if digest is None or size is None:
            say("  %s: left out (%s)" % (name, "its checksum list does not name it" if digest is None
                                       else "the server states no size"))
            continue
        data["files"].append({
            "file": name, "what": "Ren'Py %s (SDK)" % version, "url": url, "sha256": digest, "size": size,
            "licence": RENPY_LICENCE, "groups": ["archives"],
            "used_by": "tools/build_engine_hashes.py -> gamescan/engine_hashes.py, gamescan/compiled_hashes.py",
            "listing": listing})
        added.append(name)
        say("  %s: %d bytes, SHA-256 %s (renpy.org's list)" % (name, size, digest))
    for row in data["files"]:
        problem = fetch._entry_problem(row)
        if problem:
            raise BuildError("a row would not be valid: " + problem)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, indent=1) + "\n")
    return added


def published_md5(listing_url: str, file_name: str) -> Optional[str]:
    """The MD5 a Unity release listing (an .ini file) gives for the package
    ``file_name`` (None: no listing, or the package is not in it)."""
    text = _listing(listing_url)
    if text is None:
        return None
    for section in text.split("\n["):
        fields = dict(line.strip().split("=", 1) for line in section.splitlines() if "=" in line)
        value = fields.get("md5", "").strip().lower()
        if fields.get("url", "").rsplit("/", 1)[-1] == file_name and len(value) == 32 \
                and all(c in "0123456789abcdef" for c in value):
            return value
    return None


def md5_of(path: str) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def check_md5(path: str, listing_url: str, online: bool) -> None:
    """Refuses a package that is not the one its publisher lists: its MD5 has
    to be the one written down in ``MD5`` and - when the server may be asked -
    the one in the publisher's listing today. MD5 is a weak checksum; it is
    the only one Unity publishes, and the download itself is HTTPS."""
    name = os.path.basename(path)
    pinned = MD5.get(name)
    if pinned is None:
        raise BuildError("no MD5 is written down for " + name)
    if online:
        listed = published_md5(listing_url, name)
        if listed != pinned:
            raise BuildError("the publisher's listing gives %s for %s, not %s" % (listed, name, pinned))
    found = md5_of(path)
    if found != pinned:
        raise BuildError("%s has the MD5 %s; its publisher lists %s" % (path, found, pinned))


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_archive(path: str, everything: bool = False) -> Dict[str, str]:
    """``{sha256: file name}`` of every program and library in a zip archive.
    ``everything``: of every file in it (the table is then the official
    distribution - NW.js; phageo, 2026-10-12, the same decision as for Inno
    Setup). A program is named by its file name, as before; any other file by
    its path inside the archive without the archive's own top folder
    (``locales/tr.pak``). Empty files are left out (every empty file is the
    same file). Members are read in pieces and hashed; nothing is written or run."""
    out: Dict[str, str] = {}
    deadline = time.monotonic() + MAX_SECONDS
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            name = info.filename.replace("\\", "/")
            program = name.lower().endswith(PROGRAMS)
            if info.is_dir() or not (program or everything) or (everything and not info.file_size):
                continue
            if info.file_size > MAX_MEMBER:
                raise BuildError("member too large: " + name)
            digest = hashlib.sha256()
            size, head = 0, b""
            with archive.open(info) as member:
                for block in iter(lambda: member.read(_CHUNK), b""):
                    head = head or block[:2]
                    size += len(block)
                    total += len(block)
                    if size > MAX_MEMBER or total > MAX_UNPACKED:
                        raise BuildError("unpacked data exceeds the limit in " + path)
                    if time.monotonic() > deadline:
                        raise BuildError("hashing took too long: " + path)
                    digest.update(block)
            if head == b"MZ" and program:                      # a Windows program, by content
                out.setdefault(digest.hexdigest(), name.rsplit("/", 1)[-1])
            elif everything and size:
                out.setdefault(digest.hexdigest(), name.split("/", 1)[-1])
    return out


SHELL_LAUNCHERS = (".sh",)               # beside renpy/ and lib/ in a Ren'Py SDK: renpy.sh


def hash_shell_launchers(path: str) -> Dict[str, str]:
    """``{sha256: file name}`` of the shell launchers of a Ren'Py SDK archive:
    every ``.sh`` file that lies at the top of the SDK, beside ``renpy/`` and
    ``lib/`` (``renpy.sh`` - a game is shipped with a copy of it under the
    game's name; phageo, 2026-10-12). They go into the table of files, like the
    files of the NW.js archives that are no programs. Nothing is written or run."""
    out: Dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            parts = info.filename.replace("\\", "/").split("/")
            if info.is_dir() or len(parts) != 2 or not parts[1].lower().endswith(SHELL_LAUNCHERS):
                continue
            if info.file_size > MAX_SCRIPT:
                raise BuildError("script too large: " + info.filename)
            data = archive.read(info)
            if data:
                out.setdefault(hashlib.sha256(data).hexdigest(), parts[1])
    return out


LAUNCHER = "nw.exe"                      # the NW.js program RPG Maker ships with another icon
MAX_LAUNCHER = 64 * 1024 * 1024


def hash_launchers(path: str) -> Dict[str, Tuple[str, int]]:
    """``{frame key: (file name, entry point)}`` of the NW.js launcher in an
    archive: the program without its resource section
    (``gamescan.pe.resource_frame_key``). RPG Maker MV / MZ replace the icon in
    ``nw.exe``, so the file itself is never in the first table; everything but
    its resources can still be compared. Nothing is written or run."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan import pe
    out: Dict[str, Tuple[str, int]] = {}
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            name = info.filename.replace("\\", "/")
            if info.is_dir() or name.rsplit("/", 1)[-1].lower() != LAUNCHER:
                continue
            if info.file_size > MAX_LAUNCHER:
                raise BuildError("launcher too large: " + name)
            data = archive.read(info)
            parsed = pe.parse_pe(data)
            key = pe.resource_frame_key(data, parsed) if parsed is not None else None
            if key is not None:
                out.setdefault(key, (LAUNCHER, parsed.entry_point))
    return out


def hash_renpy_programs(path: str) -> Dict[str, Tuple[str, int]]:
    """``{frame key: (file name, entry point)}`` of every Windows program (``.exe``) of a
    Ren'Py SDK archive, without its resource section (``gamescan.pe.resource_frame_key``).
    A game built with Ren'Py ships the SDK's start program renamed, with the game's icon
    (phageo, 2026-10-18, sixty-second message: accepted for ENGINE-008 like a renamed
    ``nw.exe``). Nothing is written or run."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan import pe
    out: Dict[str, Tuple[str, int]] = {}
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            name = info.filename.replace("\\", "/")
            if info.is_dir() or not name.lower().endswith(".exe"):
                continue
            if info.file_size > MAX_LAUNCHER:
                raise BuildError("program too large: " + name)
            data = archive.read(info)
            parsed = pe.parse_pe(data) if data[:2] == b"MZ" else None
            key = pe.resource_frame_key(data, parsed) if parsed is not None else None
            if key is not None:
                out.setdefault(key, (name.rsplit("/", 1)[-1], parsed.entry_point))
    return out


def hash_scripts(path: str) -> Tuple[Dict[str, str], Dict[str, str], int]:
    """``({sha256: name}, {content key: name}, unread)`` of the engine scripts
    in a Ren'Py SDK archive: every script under ``renpy/`` and ``lib/`` by the
    SHA-256 of the file; compiled scripts also by what they contain. ``unread``
    counts the compiled scripts the reader could not rebuild (they are then in
    the first table only). Nothing is written or run."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan.unpack import rpyc
    scripts: Dict[str, str] = {}
    content: Dict[str, str] = {}
    unread, total = 0, 0
    deadline = time.monotonic() + MAX_SECONDS
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            parts = info.filename.replace("\\", "/").split("/")
            if (info.is_dir() or len(parts) < 3 or parts[1] not in SCRIPT_FOLDERS
                    or not parts[-1].lower().endswith(SCRIPTS)):
                continue
            if info.file_size > MAX_SCRIPT:
                raise BuildError("script too large: " + info.filename)
            total += info.file_size
            if total > MAX_UNPACKED or time.monotonic() > deadline:
                raise BuildError("the scripts exceed the limits in " + path)
            data = archive.read(info)
            name = "/".join(parts[1:])
            scripts.setdefault(hashlib.sha256(data).hexdigest(), name)
            if name.lower().endswith(COMPILED):
                key = rpyc.content_key(data)
                if key is None:
                    unread += 1
                else:
                    content.setdefault(key, name)
    return scripts, content, unread


BYTECODE = (".pyo", ".pyc")              # compiled Python of a Ren'Py SDK


def hash_compiled(path):
    """``({sha256: name}, {content key: name}, {token key: {line-free keys}},
    unread)`` of the compiled Python files under ``renpy/`` and ``lib/`` of a
    Ren'Py SDK archive. A Python 2.7 file the scanner's reader can read goes
    into the second table only, by what it contains
    (``gamescan.unpack.pyo.content_key`` - the same file compiled on another
    PC has other bytes); every other file (Python 3, or not compiled Python
    at all) goes into the first, by the SHA-256 of the file.

    The third table ties a source to what it compiles to: for every ``.py``
    that has such a Python 2.7 file beside it, the source without comments
    and spacing (``gamescan.unpack.pytokens.token_key``) -> the compiled file
    without its line numbers. ``unread`` counts the sources of that kind the
    tokenizer of this Python could not read (they are in no table).

    The readers walk bytes and text as data; nothing is unmarshalled,
    compiled, written or run."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan.unpack import pyo, pytokens
    by_file: Dict[str, str] = {}
    by_content: Dict[str, str] = {}
    without_lines: Dict[str, str] = {}       # path of the source -> line-free key of its compiled file
    sources: Dict[str, set] = {}
    total = unread = 0
    deadline = time.monotonic() + MAX_SECONDS
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in %s" % (path,))
        wanted = []
        for info in members:
            parts = info.filename.replace("\\", "/").split("/")
            if (info.is_dir() or len(parts) < 3 or parts[1] not in SCRIPT_FOLDERS
                    or not parts[-1].lower().endswith(BYTECODE + (".py",))):
                continue
            if info.file_size > MAX_SCRIPT:
                raise BuildError("file too large: " + info.filename)
            total += info.file_size
            if total > MAX_UNPACKED:
                raise BuildError("the compiled files exceed the limits in %s" % (path,))
            wanted.append((info, "/".join(parts[1:])))
        for info, name in wanted:
            if name.lower().endswith(".py"):
                continue
            if time.monotonic() > deadline:
                raise BuildError("reading took too long: %s" % (path,))
            data = archive.read(info)
            key = pyo.content_key(data)
            if key is None:
                by_file.setdefault(hashlib.sha256(data).hexdigest(), name)
            else:
                by_content.setdefault(key, name)
                without_lines[name[:-1]] = pyo.content_key(data, lines=False)
        for info, name in wanted:
            if name not in without_lines:
                continue
            if time.monotonic() > deadline:
                raise BuildError("reading took too long: %s" % (path,))
            key = pytokens.token_key(archive.read(info))
            if key is None:
                unread += 1
            else:
                sources.setdefault(key, set()).add(without_lines[name])
    return by_file, by_content, sources, unread


def build_compiled(folder: str, archives, say=print):
    """``({sha256: (name, indexes)}, {content key: (name, indexes)}, {token
    key: line-free keys})`` for the compiled Python of every Ren'Py archive in
    ``archives`` (the rows of the engine table); ``indexes``: every archive
    that holds the file, so that a file of another version can be told from
    one all versions share. Contacts no server: each archive has to be in
    ``folder`` and has to have the SHA-256 its row gives."""
    files: Dict[str, Tuple[str, List[int]]] = {}
    content: Dict[str, Tuple[str, List[int]]] = {}
    sources: Dict[str, set] = {}
    for index, row in enumerate(archives):
        if row[0] != "Ren'Py":
            continue
        path = os.path.join(folder, row[3].rsplit("/", 1)[-1])
        if not os.path.isfile(path):
            raise BuildError("missing: " + path)
        if sha256_of(path) != row[4]:
            raise BuildError("%s is not the archive the engine table was built from" % path)
        by_file, by_content, by_source, unread = hash_compiled(path)
        say("Ren'Py %s: %d compiled Python files by content, %d by the file; %d sources by their "
            "tokens, %d sources not readable as tokens"
            % (row[1], len(by_content), len(by_file), len(by_source), unread))
        for table, found in ((files, by_file), (content, by_content)):
            for key, name in found.items():
                table.setdefault(key, (name, []))[1].append(index)
        for key, compiled in by_source.items():
            sources.setdefault(key, set()).update(compiled)
    return files, content, sources


COMPILED_HEADER = '''"""Compiled Python of the official Ren'Py SDKs, recognised by its content.

GENERATED by tools/build_engine_hashes.py - do not edit by hand.

Ren'Py ships its engine and its Python library as compiled files (``.pyo`` up
to Ren'Py 7, ``.pyc`` in Ren'Py 8), and Python runs the compiled file, not the
source beside it, when the time stamp inside fits. Every entry below was
computed from an archive downloaded from renpy.org (the ``ARCHIVES`` rows of
:mod:`gamescan.engine_hashes`, whose SHA-256 the builder compares again); none
was taken from a game.

A table of its own, loaded only when a scan meets such a file.
"""
from __future__ import annotations

from typing import Optional, Tuple

from .engine_hashes import ARCHIVES

VERIFIED = "Official Ren'Py compiled file, verified against the SDK"
'''

COMPILED_FOOTER = '''

def _entry(sha256: str, content_key: Optional[str]):
    entry = CONTENT.get(content_key) if content_key else None
    return entry if entry is not None else FILES.get((sha256 or "").lower())


def verified(sha256: str, content_key: Optional[str] = None) -> Optional[str]:
    """Which official compiled file this is (None: not in the tables): by what
    it contains (``gamescan.unpack.pyo.content_key``) or by the SHA-256 of the
    file."""
    entry = _entry(sha256, content_key)
    if entry is None:
        return None
    engine, version, build = ARCHIVES[entry[1][0]][:3]
    return "%s - %s %s (%s)" % (entry[0], engine, version, build)


def versions(sha256: str, content_key: Optional[str] = None) -> Tuple[str, ...]:
    """Every listed Ren'Py version whose SDK holds this compiled file."""
    entry = _entry(sha256, content_key)
    return () if entry is None else tuple(ARCHIVES[index][1] for index in entry[1])


def compiled_from(token_key: Optional[str]) -> Optional[Tuple[str, ...]]:
    """What an official source compiles to: the line-free keys
    (``pyo.content_key(data, lines=False)``) of the compiled files that lie
    beside a source with these tokens (``gamescan.unpack.pytokens.token_key``)
    in the SDKs. None: no official source has these tokens."""
    return SOURCES.get(token_key or "")
'''


def compiled_tables(files, content, sources=None) -> Dict[str, dict]:
    """The dictionaries of the compiled-Python table, in the order the module text gives them."""
    by_archive = lambda kv: (kv[1][1][0], kv[1][0].lower(), kv[0])
    return {"CONTENT": {k: (v[0], tuple(v[1])) for k, v in sorted(content.items(), key=by_archive)},
            "FILES": {k: (v[0], tuple(v[1])) for k, v in sorted(files.items(), key=by_archive)},
            "SOURCES": {k: tuple(sorted(v)) for k, v in sorted((sources or {}).items())}}


def render_compiled(files, content, sources=None, binary: Optional[str] = None) -> str:
    """The text of ``gamescan/compiled_hashes.py`` (``binary``: as for :func:`render`)."""
    found = compiled_tables(files, content, sources)
    out = [COMPILED_HEADER]
    if binary:
        out.append("\n# the dictionaries below are kept in %s beside this module, every SHA-256 as its 32\n"
                   "# bytes (gamescan.bintable)\nfrom . import bintable as _bintable  # noqa: E402\n\n"
                   "_TABLES = _bintable.beside(__file__, %r)\n" % (binary, binary))
    for title, what in (
            ("CONTENT",
             "# Python 2.7 (.pyo): gamescan.unpack.pyo.content_key -> (path in the SDK, indexes into\n"
             "# ARCHIVES of every archive that contains it). The key leaves out the time stamp and\n"
             "# the folder of whoever compiled the file, so a file compiled elsewhere still matches.\n"),
            ("FILES",
             "# every other file named .pyc / .pyo (Python 3 - no reader yet -, or not compiled Python\n"
             "# at all): SHA-256 of the file -> (path in the SDK, indexes into ARCHIVES)\n")):
        out.append("\n" + what)
        _section(out, title, found[title], binary, lambda key, v: "    %r: (%r, %r),\n" % (key, v[0], v[1]))
    out.append("\n# a Python 2.7 source without comments and spacing (gamescan.unpack.pytokens.token_key)\n"
               "# -> the compiled files beside it in the SDKs, without their line numbers\n"
               "# (pyo.content_key(data, lines=False)). Keys made by the tokenizer of the Python that\n"
               "# ran the builder (%d.%d).\n" % sys.version_info[:2])
    _section(out, "SOURCES", found["SOURCES"], binary, lambda key, v: "    %r: %r,\n" % (key, v))
    out.append(COMPILED_FOOTER)
    return "".join(out)

def _confirmed_before() -> Dict[str, bool]:
    """Archive SHA-256 -> "was confirmed against the publisher's list", from
    the table as it is now."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        from gamescan import engine_hashes
        return {row[4]: bool(row[5]) for row in engine_hashes.ARCHIVES}
    except Exception:
        return {}


def build(folder: str, offline: bool = False, say=print, hosts: Optional[frozenset] = None):
    """``(archives, files, scripts, content, launchers, programs)``: one row per archive;
    ``{sha256: (file name, index of the first archive it is in)}`` for the
    programs; the same for the Ren'Py engine scripts, by file and by content;
    ``{frame key: (file name, index, entry point)}`` for the NW.js launchers, and the same
    for the programs of the Ren'Py SDKs (``programs``).
    ``hosts``: the only servers contacted in this run (None: all of HOSTS)."""
    os.makedirs(folder, exist_ok=True)
    archives, files, scripts, content, launchers, programs = [], {}, {}, {}, {}, {}
    before = _confirmed_before()
    for engine, version, build_name, url, listing in SOURCES:
        name = url.rsplit("/", 1)[-1]
        path = os.path.join(folder, name)
        say("%s %s (%s)" % (engine, version, build_name))
        quiet = offline or (hosts is not None and _host(url) not in hosts)
        if not os.path.isfile(path) and quiet:
            raise BuildError("missing (and its server is not to be contacted): " + path)
        # through tools/fetch.py: only the row of the manifest with this address; a file that
        # is there is compared with the row's SHA-256, a missing one is downloaded and compared
        fetch = _fetcher()
        try:
            digest = fetch.obtain(url, path, offline=quiet, say=say)["sha256"]
        except fetch.FetchError as exc:
            raise BuildError(str(exc))
        if engine == "Unity":
            check_md5(path, listing, online=not quiet)         # before anything of it is read
            say("  MD5 %s (matches the publisher's listing)" % MD5[name])
        expected = None if quiet or engine == "Unity" else published_sha256(listing, name)
        if expected is not None and expected != digest:
            raise BuildError("%s does not match the SHA-256 its publisher lists (%s)" % (path, expected))
        confirmed = bool(expected) or (quiet and before.get(digest, False))
        checked = ("matches the publisher's list" if expected else
                   "confirmed in an earlier run" if confirmed else "publisher lists no SHA-256")
        if engine == "Unity":
            tools = os.path.dirname(os.path.abspath(__file__))
            if tools not in sys.path:
                sys.path.insert(0, tools)
            import xar_reader
            try:
                found = xar_reader.hash_programs(path)
            except xar_reader.FormatError as exc:
                raise BuildError("%s: %s" % (name, exc))
        else:
            found = hash_archive(path, everything=engine == "NW.js")
        if not found:
            raise BuildError("no programs found in " + path)
        say("  archive SHA-256 %s (%s); %d %s" % (digest, checked, len(found),
                                                  "files" if engine == "NW.js" else "programs"))
        index = len(archives)
        archives.append((engine, version, build_name, url, digest, confirmed))
        for sha, file_name in found.items():
            files.setdefault(sha, (file_name, index))
        if engine == "NW.js":
            found_launchers = hash_launchers(path)
            say("  %d launcher(s) by everything but the resources" % len(found_launchers))
            for key, (file_name, entry) in found_launchers.items():
                launchers.setdefault(key, (file_name, index, entry))
        if engine == "Ren'Py":
            shell = hash_shell_launchers(path)
            say("  %d shell launcher(s)" % len(shell))
            for sha, file_name in shell.items():
                files.setdefault(sha, (file_name, index))
            found_programs = hash_renpy_programs(path)
            say("  %d program(s) by everything but the resources" % len(found_programs))
            for key, (file_name, entry) in found_programs.items():
                programs.setdefault(key, (file_name, index, entry))
            by_file, by_content, unread = hash_scripts(path)
            say("  %d engine scripts; %d compiled ones by content, %d compiled ones could not "
                "be rebuilt" % (len(by_file), len(by_content), unread))
            for sha, file_name in by_file.items():
                scripts.setdefault(sha, (file_name, index))
            for key, file_name in by_content.items():
                content.setdefault(key, (file_name, index))
    return archives, files, scripts, content, launchers, programs


HEADER = '''"""Official engine builds, recognised by their exact content.

GENERATED by tools/build_engine_hashes.py - do not edit by hand.

NW.js (RPG Maker MV / MZ) and the Python runtime Ren'Py bundles are not
signed by anybody, and Unity did not sign the 32-bit Windows player files of
some versions, so no signature can prove such a file genuine. A file
whose SHA-256 is in this table *is*, byte for byte, a file of an official
release archive - whatever it is called (RPG Maker renames ``nw.exe`` to
``Game.exe``). Every hash below was computed from an archive downloaded from
the publisher's own server (``ARCHIVES``); none was taken from a game.

Genuine does not mean harmless: these are a browser engine and a language
runtime, and they run whatever script the game gives them. The scripts are
scanned on their own.
"""
from __future__ import annotations

from typing import Optional

VERIFIED = "official engine build, verified by SHA-256"
# added to an attack chain found inside such a file, which is shown as a LOW note
CHAIN_NOTE = (" It was found inside a verified official build of a browser or runtime engine, "
              "where such combinations of functions are expected, so it is shown as a LOW note.")

# engine, version, build, source URL, SHA-256 of the archive, whether that
# SHA-256 was also confirmed against the publisher's own checksum list
# (a Unity package: no - Unity lists an MD5 only; the package matched it, see ARCHIVE_MD5)
ARCHIVES = (
'''

FOOTER = '''

def verified(sha256: str) -> Optional[str]:
    """What official file has this SHA-256 (None: not in the table)."""
    entry = KNOWN.get((sha256 or "").lower())
    if entry is None:
        return None
    engine, version, build = ARCHIVES[entry[1]][:3]
    return "%s - %s %s (%s)" % (entry[0], engine, version, build)


def source(sha256: str) -> Optional[str]:
    """URL of the official archive the file with this SHA-256 comes from."""
    entry = KNOWN.get((sha256 or "").lower())
    return None if entry is None else ARCHIVES[entry[1]][3]


def verified_shell_launcher(sha256: str) -> Optional[str]:
    """Which official Ren'Py shell launcher (``renpy.sh`` of an SDK) has this
    SHA-256 (None: none) - a game ships a copy of it under the game's name."""
    entry = KNOWN.get((sha256 or "").lower())
    if entry is None or entry[0] != "renpy.sh" or ARCHIVES[entry[1]][0] != "Ren'Py":
        return None
    return verified(sha256)


def verified_script(sha256: str, content_key: Optional[str] = None) -> Optional[str]:
    """Which official Ren'Py engine script this is (None: not in the tables):
    by the SHA-256 of the file, or - a compiled script - by what it contains
    (``gamescan.unpack.rpyc.content_key``)."""
    entry = SCRIPTS.get((sha256 or "").lower())
    if entry is None and content_key:
        entry = SCRIPT_CONTENT.get(content_key)
    if entry is None:
        return None
    engine, version, build = ARCHIVES[entry[1]][:3]
    return "%s - %s %s (%s)" % (entry[0], engine, version, build)


def renpy_versions() -> tuple:
    """The Ren'Py versions whose engine scripts are in the tables."""
    return tuple(row[1] for row in ARCHIVES if row[0] == "Ren'Py")


LAUNCHER_VERIFIED = "official NW.js launcher with other resources, code verified by SHA-256"
LAUNCHER_ENTRY_POINTS = frozenset(entry[2] for entry in LAUNCHERS.values())


def verified_launcher(frame_key: Optional[str]) -> Optional[str]:
    """Which official NW.js launcher this program is apart from its resource
    section (``gamescan.pe.resource_frame_key``; None: not in the table)."""
    entry = LAUNCHERS.get(frame_key or "")
    if entry is None:
        return None
    engine, version, build = ARCHIVES[entry[1]][:3]
    return "%s - %s %s (%s)" % (entry[0], engine, version, build)


# A Ren'Py SDK program apart from its resource section (phageo, 2026-10-18, sixty-second
# message): accepted for ENGINE-008 only when the resources hold these kinds and nothing else
# (gamescan.pe.RESOURCE_KINDS: icon, icon group, version, manifest)
RENPY_PROGRAM_KINDS = frozenset({3, 14, 16, 24})
RENPY_PROGRAM_ENTRY_POINTS = frozenset(entry[2] for entry in RENPY_PROGRAMS.values())


def verified_renpy_program(frame_key: Optional[str]) -> Optional[str]:
    """Which official Ren'Py SDK program this one is apart from its resource section
    (``gamescan.pe.resource_frame_key``; None: not in the table)."""
    entry = RENPY_PROGRAMS.get(frame_key or "")
    if entry is None:
        return None
    engine, version, build = ARCHIVES[entry[1]][:3]
    return "%s - %s %s (%s)" % (entry[0], engine, version, build)
'''


def tables(files, scripts=None, content=None, launchers=None, programs=None) -> Dict[str, dict]:
    """The dictionaries of the engine table, in the order the module text gives them."""
    def ordered(table, key):
        return {k: tuple(v) for k, v in sorted((table or {}).items(), key=key)}
    by_archive = lambda kv: (kv[1][1], kv[1][0].lower(), kv[0])
    return {"KNOWN": ordered(files, by_archive), "SCRIPTS": ordered(scripts, by_archive),
            "SCRIPT_CONTENT": ordered(content, by_archive),
            "LAUNCHERS": ordered(launchers, lambda kv: (kv[1][1], kv[0])),
            "RENPY_PROGRAMS": ordered(programs, by_archive)}


def _section(out: List[str], title: str, table: dict, binary: Optional[str], line) -> None:
    """One dictionary of a generated module: written out, or (``binary``) taken from the table
    file beside the module (``gamescan.bintable``; phageo, 2026-10-19: hashes stored binary)."""
    if binary:
        out.append("%s = _TABLES[%r]\n" % (title, title))
        return
    out.append(title + " = {\n")
    for key, value in table.items():
        out.append(line(key, value))
    out.append("}\n")


def render(archives, files, scripts=None, content=None, launchers=None, programs=None,
           binary: Optional[str] = None) -> str:
    """The text of ``gamescan/engine_hashes.py``. ``binary``: the name of the table file
    (:func:`tables`, written by the caller) the module loads its dictionaries from; without
    it they are written out in the text (as before 2026-10-19 - kept for the tests)."""
    found = tables(files, scripts, content, launchers, programs)
    out = [HEADER]
    for row in archives:
        out.append("    %r,\n" % (tuple(row),))
    out.append(")\n\n# index into ARCHIVES -> the MD5 its publisher lists for the archive, which it matched\n"
               "# when the table was built (HTTPS + MD5: a weak checksum, like no checksum at all for\n"
               "# NW.js 0.29.0)\nARCHIVE_MD5 = {\n")
    for index, row in enumerate(archives):
        name = row[3].rsplit("/", 1)[-1]
        if name in MD5:
            out.append("    %d: %r,\n" % (index, MD5[name]))
    out.append("}\n")
    if binary:
        out.append("\n# the dictionaries below are kept in %s beside this module, every SHA-256 as its 32\n"
                   "# bytes (gamescan.bintable)\nfrom . import bintable as _bintable  # noqa: E402\n\n"
                   "_TABLES = _bintable.beside(__file__, %r)\n" % (binary, binary))
    out.append("\n# SHA-256 of the file -> (its name in the archive, index into ARCHIVES of the first\n"
               "# archive that contains it). Programs and libraries; of the NW.js archives every\n"
               "# file (the table is the official distribution - a program by its file name, any\n"
               "# other file by its path in the archive); of the Ren'Py SDKs also the shell launcher\n"
               "# (renpy.sh). The scanner asks the table for programs and for that launcher, and\n"
               "# for the note SCRIPT-LIMIT-001.\n")
    _section(out, "KNOWN", found["KNOWN"], binary, lambda sha, v: "    %r: (%r, %d),   # %s %s (%s); %s\n" % (
        (sha, v[0], v[1]) + tuple(archives[v[1]][:4])))
    for title, what in (
            ("SCRIPTS",
             "# Ren'Py engine scripts (renpy/ and lib/ of an SDK): SHA-256 of the file ->\n"
             "# (its path in the SDK, index into ARCHIVES of the first archive that contains it)\n"),
            ("SCRIPT_CONTENT",
             "# compiled Ren'Py engine scripts by what they contain: a compiled script carries the\n"
             "# folder of whoever compiled it, so the file itself is never the same twice.\n"
             "# gamescan.unpack.rpyc.content_key -> (path in the SDK, index into ARCHIVES)\n")):
        out.append("\n" + what)
        _section(out, title, found[title], binary, lambda key, v: "    %r: (%r, %d),\n" % (key, v[0], v[1]))
    out.append("\n# the NW.js launcher without its resource section (RPG Maker MV / MZ put the game's icon\n"
               "# into nw.exe): gamescan.pe.resource_frame_key -> (name, index into ARCHIVES, entry point)\n")
    _section(out, "LAUNCHERS", found["LAUNCHERS"], binary, lambda key, v: "    %r: (%r, %d, %d),\n" % ((key,) + v))
    out.append("\n# the programs (.exe) of the Ren'Py SDKs without their resource section (a game ships the\n"
               "# start program renamed, with its own icon): gamescan.pe.resource_frame_key -> (name, index\n"
               "# into ARCHIVES of the first archive that holds it, entry point)\n")
    _section(out, "RENPY_PROGRAMS", found["RENPY_PROGRAMS"], binary,
             lambda key, v: "    %r: (%r, %d, %d),\n" % ((key,) + v))
    out.append(FOOTER)
    return "".join(out)


def main(argv=None) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archives", required=True,
                    help="folder that keeps the downloaded archives (outside the project)")
    ap.add_argument("--out", default=os.path.join(here, "gamescan", "engine_hashes.py"))
    ap.add_argument("--offline", action="store_true",
                    help="use only archives already in the folder; contact no server")
    ap.add_argument("--hosts", metavar="HOST[,HOST]",
                    help="contact only these of the official servers in this run (%s)"
                         % ", ".join(sorted(HOSTS)))
    ap.add_argument("--compiled-out", default=os.path.join(here, "gamescan", "compiled_hashes.py"),
                    help="where the table of the SDKs' compiled Python goes")
    ap.add_argument("--compiled-only", action="store_true",
                    help="write only the table of compiled Python, from the archives the engine "
                         "table as it is was built from; contacts no server")
    ap.add_argument("--register", action="store_true",
                    help="only add the manifest rows of the Ren'Py archives of SOURCES that have none "
                         "(SHA-256 from renpy.org's lists, size from the server); downloads nothing")
    args = ap.parse_args(argv)
    if args.register:
        try:
            added = register(os.path.join(here, "tools", "manifest.json"))
        except BuildError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        print("%d row(s) added to the manifest" % len(added))
        return 0
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan import bintable
    hosts = None
    if args.hosts:
        hosts = frozenset(h.strip() for h in args.hosts.split(",") if h.strip())
        if not hosts <= HOSTS:
            ap.error("not an official server: %s" % ", ".join(sorted(hosts - HOSTS)))
    try:
        if args.compiled_only:
            if here not in sys.path:
                sys.path.insert(0, here)
            from gamescan import engine_hashes
            archives = engine_hashes.ARCHIVES
        else:
            archives, files, scripts, content, launchers, programs = build(args.archives, args.offline, hosts=hosts)
        compiled_files, compiled_content, compiled_sources = build_compiled(args.archives, archives)
    except (BuildError, OSError, zipfile.BadZipFile) as exc:      # (a package in an unknown form is a BuildError)
        print("error: %s" % exc, file=sys.stderr)
        return 1
    # the dictionaries go into a table file beside each module (gamescan.bintable; phageo,
    # 2026-10-19: hashes stored binary), the module text keeps the rows and the functions
    if not args.compiled_only:
        binary = os.path.splitext(os.path.basename(args.out))[0] + ".bin"
        size = bintable.write(os.path.join(os.path.dirname(args.out), binary),
                              tables(files, scripts, content, launchers, programs))
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(archives, files, scripts, content, launchers, programs, binary=binary))
        print("%d files (programs; of NW.js every file; Ren'Py's shell launchers), %d engine scripts (%d compiled ones by content), %d launchers and %d Ren'Py programs without their "
              "resources from %d archives -> %s (+ %s, %d bytes)"
              % (len(files), len(scripts), len(content), len(launchers), len(programs), len(archives), args.out,
                 binary, size))
    binary = os.path.splitext(os.path.basename(args.compiled_out))[0] + ".bin"
    size = bintable.write(os.path.join(os.path.dirname(args.compiled_out), binary),
                          compiled_tables(compiled_files, compiled_content, compiled_sources))
    with open(args.compiled_out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_compiled(compiled_files, compiled_content, compiled_sources, binary=binary))
    print("%d compiled Python files by content, %d by the file, %d sources by their tokens -> %s (+ %s, %d bytes)"
          % (len(compiled_content), len(compiled_files), len(compiled_sources), args.compiled_out, binary, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
