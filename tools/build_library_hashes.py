"""Build ``gamescan/library_hashes.py``: SHA-256 of official library releases.

Games bundle script libraries that nobody signs (the Steam wrapper Greenworks,
the effects library Effekseer). The folder and name such a file has can be
imitated; its exact content cannot. This tool downloads the *official*
release archives, hashes the named library files inside them, and writes the
table the scanner compares files with - the same rule as
``tools/build_engine_hashes.py``: official releases only, never a game.

    python tools/build_library_hashes.py --archives C:\\somewhere\\engine_archives

Sources are the projects' own repositories on ``github.com`` (a release
asset, or the source archive of a release tag), which hands the files out
through GitHub's download servers. Neither project publishes checksums, so
an archive rests on the HTTPS download alone; its SHA-256 is written into the
table so that a later run can tell whether the archive changed. Nothing is
run and nothing is unpacked to disk: members are read from the zip in memory
and only hashed.

Archives already in the folder are not downloaded again (``--offline`` never
downloads). This tool has no download of its own (phageo, 2026-10-12): every
archive comes through ``tools/fetch.py`` - only a row of
``tools/manifest.json``, and only with the SHA-256 that row gives. To cover
another library or version, add its row to the manifest and the version to
``SOURCES`` (at the end: the table holds row numbers), and run again.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import zipfile
from typing import Dict, List, Optional, Tuple

GREENWORKS = "https://github.com/greenheartgames/greenworks/archive/refs/tags/v{v}.zip"


class BuildError(Exception):
    pass


# (library, version, archive URL, file name in the archives folder, library files taken)
SOURCES: List[Tuple[str, str, str, str, Tuple[str, ...]]] = [
    ("Effekseer for WebGL", "1.70b",
     "https://github.com/effekseer/EffekseerForWebGL/releases/download/170b/EffekseerForWebGL170b.zip",
     "EffekseerForWebGL170b.zip",
     ("effekseer.js", "effekseer.min.js", "effekseer.wasm", "effekseer_asmjs.js", "effekseer_asmjs.min.js")),
] + [
    # greenworks.js is the same file in every release from 0.15.0 to 0.22.0
    ("Greenworks", v, GREENWORKS.format(v=v), "greenworks-%s-source.zip" % v, ("greenworks.js",))
    for v in ("0.15.0", "0.16.0", "0.17.0", "0.18.0", "0.19.0", "0.20.0", "0.21.0", "0.22.0")
]

# Since 2026-10-19 (phageo): jQuery, SDL2 and OpenAL Soft - only files whose publisher states a
# SHA-256: jQuery's own release list (``code.jquery.com/jquery/``, a SHA-256 per file), GitHub's
# stated SHA-256 of a release file (newer releases only; older ones are left out and said). Their
# rows are in a manifest of their own, ``tools/manifest_libraries.json`` (written by
# ``--register``), and they come after the sources above, in the order of that file.
LIBRARY_MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest_libraries.json")
JQUERY_LIST = "https://code.jquery.com/jquery/"
EVERY_PROGRAM = ("*",)                   # names: every .dll / .exe of the archive, by its path
THE_FILE = ()                            # names: the downloaded file is the library itself
_NAMED = (
    # (library, pattern of the file name -> version, what of it is taken)
    ("jQuery", re.compile(r"\Ajquery-(\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.module)?(?:\.min|\.pack)?\.js\Z"), THE_FILE),
    ("SDL2", re.compile(r"\ASDL2-(\d+\.\d+\.\d+)-win32-(?:x64|x86)\.zip\Z"), EVERY_PROGRAM),
    ("OpenAL Soft", re.compile(r"\Aopenal-soft-(\d+\.\d+\.\d+)-bin\.zip\Z"), EVERY_PROGRAM),
)
_RELEASES = (("SDL2", "libsdl-org/SDL", re.compile(r"\ASDL2-\d+\.\d+\.\d+-win32-(?:x64|x86)\.zip\Z")),
             ("OpenAL Soft", "kcat/openal-soft", re.compile(r"\Aopenal-soft-\d+\.\d+\.\d+-bin\.zip\Z")))
LICENCES = {
    "jQuery": "jQuery: MIT licence (OpenJS Foundation).",
    "SDL2": "SDL: zlib licence.",
    "OpenAL Soft": "OpenAL Soft: LGPL 2.0 or later (the library); the archive's COPYING file has the text.",
}


def _added_sources() -> List[Tuple[str, str, str, str, Tuple[str, ...]]]:
    """The sources of ``tools/manifest_libraries.json``, in its order (none when it is missing)."""
    if not os.path.isfile(LIBRARY_MANIFEST):
        return []
    import json
    with open(LIBRARY_MANIFEST, "r", encoding="utf-8") as fh:
        rows = json.load(fh)["files"]
    out = []
    for row in rows:
        for library, pattern, names in _NAMED:
            found = pattern.match(row["file"])
            if found:
                out.append((library, found.group(1), row["url"], row["file"], names))
                break
        else:
            raise BuildError("a row of %s is of no known library: %s" % (LIBRARY_MANIFEST, row["file"]))
    return out


SOURCES = SOURCES + _added_sources()

MAX_MEMBERS = 20_000                     # entries in one archive
MAX_MEMBER = 32 * 1024 * 1024            # one library file
ADDED_FOLDER = "libraries"               # (the added sources' files: a folder of their own)


def _fetch():
    tools = os.path.dirname(os.path.abspath(__file__))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import fetch
    return fetch


def _manifest(fetch) -> dict:
    """The rows this tool may fetch: ``tools/manifest.json`` and the libraries' own manifest."""
    rows = dict(fetch.load())
    if os.path.isfile(LIBRARY_MANIFEST):
        rows.update(fetch.load(LIBRARY_MANIFEST))
    return rows


def path_of(folder: str, source) -> str:
    """Where the file of a source lies in the archives folder."""
    added = source[4] in (THE_FILE, EVERY_PROGRAM)
    return os.path.join(folder, ADDED_FOLDER, source[3]) if added else os.path.join(folder, source[3])


def obtain(url: str, path: str, offline: bool, say=print) -> str:
    """The SHA-256 of the listed archive with the address ``url``, which then
    lies at ``path``. Through ``tools/fetch.py`` - this tool has no download
    of its own (phageo, 2026-10-12): only a row of ``tools/manifest.json`` (or,
    since 2026-10-19, of ``tools/manifest_libraries.json``) is fetched, and a
    file whose SHA-256 is not the row's is refused, whether it was just
    downloaded or was already there."""
    fetch = _fetch()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return fetch.obtain(url, path, offline=offline, manifest=_manifest(fetch), say=say)["sha256"]
    except fetch.FetchError as exc:
        raise BuildError(str(exc))


def hash_source(path: str, names: Tuple[str, ...]) -> Dict[str, str]:
    """``{sha256: name}`` of what a source gives: the named files of a zip (:func:`hash_members`),
    every program of a zip by its path (``EVERY_PROGRAM``), or the file itself (``THE_FILE``)."""
    if names == THE_FILE:
        size = os.path.getsize(path)
        if not 0 < size <= MAX_MEMBER:
            raise BuildError("not a library file of a plausible size: " + path)
        with open(path, "rb") as fh:
            return {hashlib.sha256(fh.read()).hexdigest(): os.path.basename(path)}
    if names == EVERY_PROGRAM:
        out: Dict[str, str] = {}
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_MEMBERS:
                raise BuildError("too many members in " + path)
            for info in members:
                name = info.filename.replace("\\", "/")
                if info.is_dir() or not name.lower().endswith((".dll", ".exe")):
                    continue
                if info.file_size > MAX_MEMBER:
                    raise BuildError("member too large: " + name)
                with archive.open(info) as member:
                    data = member.read(MAX_MEMBER + 1)
                if len(data) > MAX_MEMBER:
                    raise BuildError("member too large: " + name)
                out.setdefault(hashlib.sha256(data).hexdigest(), name)
        if not out:
            raise BuildError("no program or library in " + path)
        return out
    return hash_members(path, names)


def hash_members(path: str, names: Tuple[str, ...]) -> Dict[str, str]:
    """``{sha256: file name}`` of the named library files of a zip archive: at
    its top, or inside the one folder a source archive wraps everything in.
    Every name must be there exactly once."""
    out: Dict[str, str] = {}
    seen: Dict[str, int] = {}
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise BuildError("too many members in " + path)
        for info in members:
            parts = info.filename.replace("\\", "/").split("/")
            if info.is_dir() or len(parts) > 2 or parts[-1] not in names:
                continue
            if info.file_size > MAX_MEMBER:
                raise BuildError("member too large: " + info.filename)
            with archive.open(info) as member:
                data = member.read(MAX_MEMBER + 1)
            if len(data) > MAX_MEMBER:
                raise BuildError("member too large: " + info.filename)
            seen[parts[-1]] = seen.get(parts[-1], 0) + 1
            out[hashlib.sha256(data).hexdigest()] = parts[-1]
    for name in names:
        if seen.get(name, 0) != 1:
            raise BuildError("%s: expected one %s, found %d" % (os.path.basename(path), name, seen.get(name, 0)))
    return out


def build(folder: str, offline: bool = False, say=print):
    """Returns ``(archives, files)``: the rows of ``ARCHIVES`` and
    ``{sha256: (file name, index of the first archive that has it)}``."""
    archives, files = [], {}
    for source in SOURCES:
        library, version, url, file_name, names = source
        path = path_of(folder, source)
        say("%s %s: %s" % (library, version, file_name))
        digest = obtain(url, path, offline, say)
        found = hash_source(path, names)
        archives.append((library, version, url, digest))
        for digest, name in sorted(found.items(), key=lambda item: item[1]):
            files.setdefault(digest, (name, len(archives) - 1))
        say("  %d library file(s)" % len(found))
    return archives, files


HEADER = '''"""Official releases of libraries that games bundle, recognised by their exact content.

GENERATED by tools/build_library_hashes.py - do not edit by hand.

A library a game ships (the Steam wrapper Greenworks, the effects library
Effekseer, jQuery, SDL2, OpenAL Soft) is often signed by nobody, and the folder
and name it has can be imitated. A file whose SHA-256 is in this table *is*,
byte for byte, a file of an official release of that library. Every hash below
was computed from a file downloaded from the project's own release source
(``ARCHIVES``); none was taken from a game. Greenworks and Effekseer publish no
checksums (their archives rest on the HTTPS download alone); the files of jQuery,
SDL2 and OpenAL Soft (since 2026-10-19) were taken only with the SHA-256 their
publisher - jQuery's release list, GitHub for a release file - states for them.

Genuine does not mean harmless in every use: what the game's own scripts do
with the library is scanned on its own.
"""
from __future__ import annotations

from typing import Optional

VERIFIED = "official library release, verified by SHA-256"

# library, version, source URL, SHA-256 of the archive as it was downloaded
ARCHIVES = (
'''

FOOTER = '''

def verified(sha256: str) -> Optional[str]:
    """What official library file has this SHA-256 (None: not in the table): its name, the
    library and the versions from the first to the last that hold it."""
    digest = (sha256 or "").lower()
    entry = KNOWN.get(digest)
    if entry is None:
        return None
    first = ARCHIVES[entry[1]]
    versions = [ARCHIVES[index][1] for index in HOLDERS.get(digest, ())
                if index >= entry[1] and ARCHIVES[index][0] == first[0]]
    last = versions[-1] if versions else first[1]
    span = first[1] if last == first[1] else "%s to %s" % (first[1], last)
    return "%s - %s %s" % (entry[0], first[0], span)


def source(sha256: str) -> Optional[str]:
    """URL of the official archive the file with this SHA-256 comes from."""
    entry = KNOWN.get((sha256 or "").lower())
    return None if entry is None else ARCHIVES[entry[1]][2]
'''


def tables(files, also) -> Dict[str, dict]:
    """The dictionaries of the table: ``KNOWN`` and ``HOLDERS`` (SHA-256 -> the indexes into
    ARCHIVES of every archive that holds the file, in order)."""
    holders: Dict[str, List[int]] = {}
    for index in sorted(also):
        for digest in sorted(also[index]):
            holders.setdefault(digest, []).append(index)
    return {"KNOWN": {k: tuple(v) for k, v in sorted(files.items(), key=lambda item: (item[1][1], item[1][0], item[0]))},
            "HOLDERS": {k: tuple(v) for k, v in sorted(holders.items())}}


def render(archives, files, also, binary: Optional[str] = None) -> str:
    """The text of ``gamescan/library_hashes.py``. ``binary``: the name of the table file
    beside it that holds the dictionaries (``gamescan.bintable``; phageo, 2026-10-19: hashes
    stored binary); without it they are written out (tests)."""
    found = tables(files, also)
    out = [HEADER]
    for row in archives:
        out.append("    %r,\n" % (tuple(row),))
    out.append(")\n")
    if binary:
        out.append("\n# the dictionaries below are kept in %s beside this module, every SHA-256 as its 32\n"
                   "# bytes (gamescan.bintable)\nfrom . import bintable as _bintable  # noqa: E402\n\n"
                   "_TABLES = _bintable.beside(__file__, %r)\n" % (binary, binary))
    for title, what in (("KNOWN", "# SHA-256 of the file -> (its name in the archive, index into ARCHIVES of the first\n"
                                  "# archive that contains it)\n"),
                        ("HOLDERS", "# SHA-256 of the file -> the indexes into ARCHIVES of every archive that holds it\n")):
        out.append("\n" + what)
        if binary:
            out.append("%s = _TABLES[%r]\n" % (title, title))
            continue
        out.append(title + " = {\n")
        for key, value in found[title].items():
            out.append("    %r: %r,\n" % (key, value))
        out.append("}\n")
    out.append(FOOTER)
    return "".join(out)


def register(say=print, opener=None) -> List[str]:
    """Write ``tools/manifest_libraries.json``: a row for every jQuery file of jQuery's own
    release list (with the SHA-256 the list states), and for every SDL2 / OpenAL Soft Windows
    file of a GitHub release that is no pre-release and for which GitHub states a SHA-256.
    Rows already there keep their place; new ones go at the end. Contacts code.jquery.com and
    GitHub's list of releases; downloads nothing. Returns the files added."""
    import base64
    import json
    fetch = _fetch()
    data = {"about": "The official files gamescan/library_hashes.py is built from besides those of tools/manifest.json "
                     "(tools/build_library_hashes.py --register): jQuery from its own CDN, SDL2 and OpenAL Soft from "
                     "their GitHub releases - each only with the SHA-256 its publisher states. Used with: "
                     "python tools/fetch.py --manifest tools/manifest_libraries.json",
            "licence_notes": "Licence notes are short reminders, not legal texts.", "files": []}
    if os.path.isfile(LIBRARY_MANIFEST):
        with open(LIBRARY_MANIFEST, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    known = {row["file"] for row in data["files"]}
    found: List[dict] = []
    text = fetch.read_listing(JQUERY_LIST, manifest={"list": {"listing": JQUERY_LIST}}, opener=opener)
    for name, stated in re.findall(r"href='https://code\.jquery\.com/(jquery-[^'/]+\.js)'\s+data-hash='sha256-([A-Za-z0-9+/=]{44})'",
                                   text):
        if not _NAMED[0][1].match(name):
            say("  %s: left out (not a file name this tool knows)" % name)
            continue
        found.append({"file": name, "url": "https://code.jquery.com/" + name,
                      "sha256": base64.b64decode(stated).hex(), "size": None, "library": "jQuery",
                      "listing": JQUERY_LIST})
    for library, repo, pattern in _RELEASES:
        releases = []
        for page in range(1, 11):
            batch = fetch.read_release_list(repo, page, opener=opener)
            releases += batch
            if len(batch) < 100:
                break
        for release in reversed(releases):                      # oldest first
            if release.get("prerelease") or release.get("draft"):
                continue
            for asset in release.get("assets", ()):
                name, digest = asset.get("name", ""), asset.get("digest") or ""
                if not pattern.match(name):
                    continue
                if not digest.startswith("sha256:"):
                    say("  %s: left out (GitHub states no SHA-256 for it)" % name)
                    continue
                found.append({"file": name, "url": asset.get("browser_download_url", ""), "sha256": digest[7:].lower(),
                              "size": asset.get("size"), "library": library,
                              "listing": "https://api.github.com/repos/%s/releases" % repo})
    added: List[str] = []
    for item in found:
        if item["file"] in known:
            continue
        size = item["size"] if item["size"] is not None else fetch.remote_size(item["url"], opener=opener)
        row = {"file": item["file"], "what": "%s (%s)" % (item["library"], item["file"]), "url": item["url"],
               "sha256": item["sha256"], "size": size, "licence": LICENCES[item["library"]], "groups": ["archives"],
               "used_by": "tools/build_library_hashes.py -> gamescan/library_hashes.py", "listing": item["listing"]}
        problem = fetch._entry_problem(row)
        if problem:
            say("  %s: left out (%s)" % (item["file"], problem))
            continue
        data["files"].append(row)
        known.add(item["file"])
        added.append(item["file"])
    with open(LIBRARY_MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(data, indent=1) + "\n")
    return added


def main(argv=None) -> int:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--archives", required=True,
                    help="folder the official archives are kept in (downloaded when missing)")
    ap.add_argument("--out", default=os.path.join(here, "gamescan", "library_hashes.py"))
    ap.add_argument("--offline", action="store_true", help="never download; fail when an archive is missing")
    ap.add_argument("--register", action="store_true",
                    help="only write the rows of tools/manifest_libraries.json (reads the publishers' lists; "
                         "downloads nothing)")
    args = ap.parse_args(argv)
    if args.register:
        try:
            added = register()
        except (BuildError, OSError, ValueError) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 1
        print("%d row(s) added to %s" % (len(added), LIBRARY_MANIFEST))
        return 0
    if here not in sys.path:
        sys.path.insert(0, here)
    from gamescan import bintable
    os.makedirs(args.archives, exist_ok=True)
    try:
        archives, files = build(args.archives, args.offline)
        also: Dict[int, set] = {}
        for index, source in enumerate(SOURCES):
            also[index] = set(hash_source(path_of(args.archives, source), source[4])) & set(files)
    except (BuildError, OSError, zipfile.BadZipFile) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    binary = os.path.splitext(os.path.basename(args.out))[0] + ".bin"
    size = bintable.write(os.path.join(os.path.dirname(args.out), binary), tables(files, also))
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render(archives, files, also, binary=binary))
    print("%d archive(s), %d library file(s) -> %s (+ %s, %d bytes)" % (len(archives), len(files), args.out,
                                                                        binary, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())