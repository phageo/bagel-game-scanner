"""Build ``gamescan/npm_hashes.py``: the files of published npm packages, by SHA-256.

An Electron app carries its libraries with it: ``node_modules`` inside
``app.asar``. They are published packages - ``systeminformation``,
``electron-updater`` - whose scripts start programs and ask Windows about the
PC, and in a clean app nearly every HIGH finding stands in one of them. The
folder and name of such a file can be imitated; its exact content cannot.
This tool writes the table the scanner compares with (phageo, 2026-10-14):

* **Which packages:** the names and versions in ``tools/npm_packages.txt``
  (one ``name@version`` per line). They were read from the ``package.json``
  files of the clean benchmark samples and of the real samples - names and
  versions only. Nothing else of a sample is used: **no hash in the table
  comes from a sample.**
* **Where the files come from:** the package's archive on
  ``registry.npmjs.org``, through ``tools/fetch.py`` (only a row of
  ``tools/manifest_npm.json``).
* **What vouches for an archive:** the registry states the SHA-512 of every
  version's archive (``dist.integrity``). ``--register`` reads that value
  (through ``fetch.read_listing``), downloads the archive once, refuses it
  when its SHA-512 is another one, and writes the row - with the registry's
  value and the SHA-256 of that same file. Afterwards ``fetch.py`` checks
  both on every use.
* **What is hashed:** every file of the archive with an ending of code or of
  something a script loads (``KEPT``), read from the ``.tgz`` in memory -
  nothing is unpacked to disk, nothing is run, no install script is looked at.

    python tools/build_npm_hashes.py --archives <folder> --register     (contacts the registry)
    python tools/build_npm_hashes.py --archives <folder>                (builds; never downloads)

A package the registry does not have (a private one, one fetched from
somewhere else) is skipped and said. Verified does not mean harmless in every
use: what the app's own scripts do with a library is scanned on its own, and
a CRITICAL chain inside a verified file is still shown (CLAUDE.md, rule 13).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "gamescan", "npm_hashes.py")
LIST = os.path.join(HERE, "npm_packages.txt")
MANIFEST = os.path.join(HERE, "manifest_npm.json")
REGISTRY = "https://registry.npmjs.org/"
FOLDER = "npm"                           # sub-folder of --archives the archives are kept in

KEPT = frozenset({".js", ".cjs", ".mjs", ".node", ".json", ".html", ".htm", ".wasm", ".exe", ".dll", ".ps1",
                  ".bat", ".cmd", ".sh", ".vbs", ".py"})
MIN_SIZE = 24                            # smaller files say nothing (an empty index.js is everybody's)
MAX_ARCHIVE = 256 * 1024 * 1024          # one package archive
MAX_MEMBERS = 50_000                     # entries in one archive
MAX_MEMBER = 128 * 1024 * 1024           # one file of it
MAX_UNPACKED = 1024 * 1024 * 1024        # all files of one archive
_SPEC = re.compile(r"\A((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)\Z")
_CHUNK = 1 << 20


class BuildError(Exception):
    pass


def _fetch():
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import fetch
    return fetch


def wanted(path: str = LIST) -> List[Tuple[str, str]]:
    """``(name, version)`` of every line of the list; anything that is not a plain
    ``name@version`` is refused."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = _SPEC.match(line)
            if not m:
                raise BuildError("not a name@version: %r" % line)
            out.append((m.group(1), m.group(2)))
    return sorted(set(out))


def file_name(name: str, version: str) -> str:
    """The archive's name in the archives folder (``@scope/name`` -> ``scope__name``)."""
    return "%s-%s.tgz" % (name.lstrip("@").replace("/", "__"), version)


def metadata_address(name: str, version: str) -> str:
    return REGISTRY + name.replace("/", "%2F") + "/" + version


def load_manifest(path: str = MANIFEST) -> dict:
    if not os.path.exists(path):
        return {"about": "The npm package archives gamescan/npm_hashes.py is built from (tools/build_npm_hashes.py). "
                         "Each row holds what the registry states about the archive (integrity: its SHA-512) and the "
                         "SHA-256 of the same file. Used with: python tools/fetch.py --manifest tools/manifest_npm.json",
                "licence_notes": "Each package has its own open-source licence (the licence field of its "
                                 "package.json); the archives are only read and hashed, never passed on.",
                "files": []}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def register(archives: str, say=print) -> Tuple[int, List[str]]:
    """Make a manifest row for every listed package that has none: read what the registry
    states about that version, download the archive once, refuse it when its SHA-512 is not
    the stated one. Returns ``(rows added, packages skipped with the reason)``."""
    fetch = _fetch()
    manifest = load_manifest()
    have = {row["file"] for row in manifest["files"]}
    folder = os.path.join(archives, FOLDER)
    os.makedirs(folder, exist_ok=True)
    added, skipped = 0, []
    for name, version in wanted():
        target = file_name(name, version)
        if target in have:
            continue
        listing = metadata_address(name, version)
        try:
            stated = json.loads(fetch.read_listing(listing, manifest={"x": {"listing": listing}}))
            address, integrity = stated["dist"]["tarball"], stated["dist"].get("integrity", "")
            if stated.get("name") != name or stated.get("version") != version:
                raise ValueError("the registry answered for another package")
        except (fetch.FetchError, ValueError, KeyError, TypeError) as exc:
            skipped.append("%s@%s: %s" % (name, version, str(exc)[:80] or type(exc).__name__))
            continue
        if not integrity.startswith("sha512-") or not fetch._official(address):
            skipped.append("%s@%s: the registry states no SHA-512, or another server" % (name, version))
            continue
        path = os.path.join(folder, target)
        try:
            if not os.path.exists(path):
                size, _sha = fetch._once({"file": target, "url": address}, path + ".part", MAX_ARCHIVE, fetch._open)
                if fetch.integrity_of(path + ".part") != integrity:
                    os.remove(path + ".part")
                    skipped.append("%s@%s: the download's SHA-512 is not the registry's - refused" % (name, version))
                    continue
                os.replace(path + ".part", path)
            elif fetch.integrity_of(path) != integrity:
                skipped.append("%s@%s: the file that is there has another SHA-512 - left alone" % (name, version))
                continue
        except (fetch.FetchError, fetch._NoConnection, OSError) as exc:
            if os.path.exists(path + ".part"):
                os.remove(path + ".part")
            skipped.append("%s@%s: %s" % (name, version, str(exc)[:80]))
            continue
        manifest["files"].append({
            "file": target, "what": "npm package %s %s" % (name, version), "url": address,
            "sha256": fetch.sha256_of(path), "size": os.path.getsize(path), "integrity": integrity,
            "listing": listing, "licence": "the package's own (licence field of its package.json)",
            "groups": ["archives"], "used_by": "tools/build_npm_hashes.py -> gamescan/npm_hashes.py"})
        have.add(target)
        added += 1
        if added % 25 == 0:
            say("  %d registered" % added)
            _write_manifest(manifest)
    _write_manifest(manifest)
    return added, skipped


def _write_manifest(manifest: dict) -> None:
    with open(MANIFEST, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


def files_of(path: str) -> Dict[str, str]:
    """``{path in the package: sha256}`` of the kept files of a package archive. Read in
    memory, member by member; nothing is written, nothing is run."""
    out: Dict[str, str] = {}
    total = 0
    with open(path, "rb") as fh:
        raw = fh.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise BuildError("archive too large: " + path)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for count, member in enumerate(archive):
                if count > MAX_MEMBERS:
                    raise BuildError("too many members in " + path)
                if not member.isreg():
                    continue                         # (links and folders are never followed)
                name = member.name.replace("\\", "/")
                name = name.split("/", 1)[1] if "/" in name else name      # (the leading "package/")
                if member.size > MAX_MEMBER:
                    raise BuildError("member too large: " + name)
                total += member.size
                if total > MAX_UNPACKED:
                    raise BuildError("unpacked data exceeds the limit in " + path)
                if os.path.splitext(name)[1].lower() not in KEPT or member.size < MIN_SIZE \
                        or name.lower() == "package.json":
                    continue                         # (npm rewrites package.json when it installs)
                handle = archive.extractfile(member)
                digest = hashlib.sha256()
                for block in iter(lambda: handle.read(_CHUNK), b""):
                    digest.update(block)
                out[name] = digest.hexdigest()
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise BuildError("%s: %s" % (path, exc))
    return out


def build(archives: str, offline: bool = True, say=print) -> Tuple[List[str], Dict[str, int]]:
    """``(packages, {sha256: index into packages})`` from every row of the npm manifest
    whose archive is at hand (checked by ``fetch.py``: SHA-256 and the registry's SHA-512)."""
    fetch = _fetch()
    rows = fetch.load(MANIFEST)
    packages: List[str] = []
    files: Dict[str, int] = {}
    for row in rows.values():
        path = os.path.join(archives, FOLDER, row["file"])
        try:
            fetch.obtain(row["url"], path, offline=offline, manifest=rows, say=lambda *_a: None)
        except fetch.FetchError as exc:
            raise BuildError(str(exc))
        index = len(packages)
        packages.append(row["what"].replace("npm package ", ""))
        for digest in files_of(path).values():
            files.setdefault(digest, index)
    say("%d packages, %d files" % (len(packages), len(files)))
    return packages, files


def render(packages: List[str], files: Dict[str, int]) -> str:
    lines = [
        '"""Files of published npm packages, recognised by their exact content.',
        "",
        "GENERATED by tools/build_npm_hashes.py - do not edit by hand.",
        "",
        "An Electron app carries its libraries in ``node_modules``. A file whose SHA-256",
        "is in ``FILES`` *is*, byte for byte, a file of the named version of a package as",
        "the npm registry hands it out: it was read from the package's archive, and that",
        "archive has the SHA-512 the registry states for it (``tools/manifest_npm.json``).",
        "Which packages: the names and versions found in the ``package.json`` files of",
        "the benchmark's samples - names only; no hash here was taken from a sample.",
        "",
        "Genuine does not mean harmless in every use: what the app's own scripts do with",
        "a library is scanned on its own, and a CRITICAL chain inside a verified file is",
        'still shown."""',
        "from __future__ import annotations",
        "",
        "from typing import Optional",
        "",
        "# name and version of each package",
        "PACKAGES = (",
    ]
    lines += ["    %r," % name for name in packages]
    lines += [")", "", "# SHA-256 of a file -> index into PACKAGES of the first package that holds it", "FILES = {"]
    lines += ["    %r: %d," % (digest, index) for digest, index in sorted(files.items())]
    lines += ["}", "", "",
              "def verified(sha256: str) -> Optional[str]:",
              '    """``"npm package <name> <version>"`` when the file is one of a listed package."""',
              "    index = FILES.get((sha256 or \"\").lower())",
              "    return None if index is None else \"npm package \" + PACKAGES[index]",
              ""]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--archives", required=True, help="the folder the archives are kept in (outside the project)")
    parser.add_argument("--register", action="store_true",
                        help="contact the registry: make manifest rows for listed packages that have none")
    args = parser.parse_args(argv)
    try:
        if args.register:
            added, skipped = register(args.archives)
            print("%d row(s) added; %d package(s) skipped" % (added, len(skipped)))
            for line in skipped:
                print("  skipped " + line)
            return 0
        packages, files = build(args.archives)
        with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(packages, files))
        print("-> " + OUT)
        return 0
    except BuildError as exc:
        print("refused: %s" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
