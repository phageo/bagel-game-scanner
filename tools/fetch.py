"""Fetch the outside files this project needs - the ones listed, and nothing else.

``tools/manifest.json`` lists every file the project takes from outside: the
official engine and library archives the hash tables are built from, and the
compilers the installer tests use. One row per file: its name, the official
address, its SHA-256, its size and a note about its licence. None of these
files is part of the project or of what is shipped (CLAUDE.md, open item 19).

    python tools/fetch.py --list
    python tools/fetch.py --check --to C:\\somewhere\\engine_archives
    python tools/fetch.py --fetch --group archives --to C:\\somewhere\\engine_archives
    python tools/fetch.py --fetch nsis-3.13.zip --to C:\\somewhere

What this tool does, and does not:

- It downloads **only what is listed**: a file is asked for by its name in the
  manifest; an address is never taken from the command line.
- Only over https, only from the servers in ``HOSTS``; a redirect is followed
  only to https and only to the servers in ``REDIRECTS``.
- It **refuses any mismatch**: a download whose SHA-256 (or size) is not the
  listed one is deleted and reported; nothing of it is kept. A file that is
  already there under the name and is not the listed file is reported too and
  left as it is - never overwritten.
- It tries **up to three times** when a server cannot be reached or the
  connection breaks (a short wait in between) - never after a mismatch: a file
  that came and is not the listed one is refused at once.
- **A first download** (phageo, 2026-10-17): a publisher that states no SHA-256
  (Microsoft's DirectX package) is listed once with ``"sha256": null`` and a
  ``"first"`` note. Such a row is downloaded **once**, its SHA-256 is printed,
  and from then on it is refused - by ``--check``, by the table builders, by a
  second ``--fetch`` - until that SHA-256 is written into the manifest and the
  ``"first"`` note is taken out. Whoever writes it in checks the file first
  (for DirectX: Microsoft's signature on it).
  **Since 2026-10-17 (phageo) such a row names its publisher** (``"publisher"``,
  as the signing certificate states it - ``"Microsoft Corporation"``), and the
  first download is **kept only with a valid Authenticode signature of exactly
  that publisher** (Windows' ``WinVerifyTrust`` through ctypes,
  :func:`publisher_of`); anything else is deleted and refused. Windows only.
- It **never runs, unpacks or opens** what it fetched. It writes the bytes and
  hashes them. (Whoever uses a file afterwards decides what happens to it;
  ``tests/build_installers.py`` runs the compilers.)

``--check`` contacts no server: it compares the files in a folder with the
manifest. Downloading needs phageo's word first (CLAUDE.md, rule 14).

The tools that build the hash tables (``build_engine_hashes.py``,
``build_library_hashes.py``, ``build_inno_tables.py``, ``build_nsis_tables.py``)
have no download of their own: they get their archives through
:func:`obtain` and a publisher's checksum list through :func:`read_listing`
(only a list that a row names as its ``listing``).
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(HERE, "manifest.json")
# the only servers ever asked (the publishers' own download servers)
HOSTS = frozenset({"dl.nwjs.io", "www.renpy.org", "download.unity3d.com", "github.com",
                   "files.jrsoftware.org", "downloads.sourceforge.net",
                   "www.python.org",         # (since 2026-10-12: the Python that is to be bundled)
                   "tetr.io",                # (since 2026-10-13: a clean benchmark sample, from its own site)
                   "registry.npmjs.org",     # (since 2026-10-14: packages for the npm library table)
                   "download.microsoft.com",   # (since 2026-10-17: the DirectX June 2010 package)
                   # (since 2026-10-19, phageo: jQuery from its own CDN; the lists of GitHub releases -
                   # Electron, SDL2, OpenAL Soft - with the SHA-256 GitHub states for each file)
                   "code.jquery.com", "api.github.com"})
# ... and the servers those hand a download on to; a redirect to anywhere else is refused
REDIRECTS = HOSTS | frozenset({"dl.node-webkit.org", "codeload.github.com",
                               "objects.githubusercontent.com",
                               "release-assets.githubusercontent.com",
                               "releases.jquery.com"})   # (code.jquery.com's own list of releases)
REDIRECT_SUFFIXES = (".dl.sourceforge.net",)      # SourceForge's mirrors
# samples: clean games for the false-positive benchmark; package: the python.org files the user
# package is built from (since 2026-10-24, tools/manifest_package.json)
GROUPS = ("archives", "test-tools", "samples", "package")
FIELDS = frozenset({"file", "url", "sha256", "size", "licence", "groups", "what", "used_by", "md5", "note",
                    "listing", "integrity", "first", "publisher"})
REQUIRED = ("file", "url", "sha256", "size", "licence", "groups")
MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 5000                         # (1000 until 2026-10-14: the npm manifest has a row per package)
MAX_SIZE = 512 * 1024 * 1024             # one file, also when its size is not listed
MAX_LISTING = 4 * 1024 * 1024            # one checksum list of a publisher
MAX_SECONDS = 1800                       # per download
TRIES = 3                                # when the server cannot be reached or the connection breaks
RETRY_WAIT = 5                           # seconds between two tries
_CHUNK = 1 << 20
_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._ +-]{0,150}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_MD5 = re.compile(r"\A[0-9a-f]{32}\Z")
# what a publisher states about the file in the form the npm registry uses: SHA-512, base64
_INTEGRITY = re.compile(r"\Asha512-[A-Za-z0-9+/]{86}==\Z")


class FetchError(Exception):
    pass


# -- the manifest ---------------------------------------------------------------------------
def _official(url: object) -> bool:
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    return urllib.parse.urlsplit(url).hostname in HOSTS


def _entry_problem(entry: object) -> str:
    """What is wrong with one row of the manifest ("": nothing)."""
    if not isinstance(entry, dict):
        return "a row is not an object"
    name = entry.get("file")
    if not isinstance(name, str) or not _NAME.match(name) or ".." in name:
        return "not a plain file name: %r" % (name,)
    for field in REQUIRED:
        if field not in entry:
            return "%s: no %r" % (name, field)
    unknown = sorted(set(entry) - FIELDS)
    if unknown:
        return "%s: unknown field %s" % (name, ", ".join(unknown))
    if not _official(entry["url"]):
        return "%s: not an https address of an official server: %r" % (name, entry["url"])
    if entry["sha256"] is None:
        if not isinstance(entry.get("first"), str) or not entry["first"].strip():
            return "%s: no SHA-256 (null only for a first download, with a \"first\" note)" % name
        if not isinstance(entry.get("publisher"), str) or not entry["publisher"].strip():
            return "%s: a first download names its publisher (\"publisher\", as its signature states it)" % name
    elif not isinstance(entry["sha256"], str) or not _SHA256.match(entry["sha256"]):
        return "%s: not a SHA-256 (64 lower-case hex digits)" % name
    elif "first" in entry:
        return "%s: a SHA-256 is listed - take the \"first\" note out" % name
    size = entry["size"]
    if size is not None and (type(size) is not int or not 0 < size <= MAX_SIZE):
        return "%s: not a size (a whole number of bytes up to %d MB, or null)" % (name, MAX_SIZE >> 20)
    if not isinstance(entry["licence"], str) or not entry["licence"].strip():
        return "%s: no licence note" % name
    groups = entry["groups"]
    if not isinstance(groups, list) or not groups or any(g not in GROUPS for g in groups):
        return "%s: groups must be of %s" % (name, ", ".join(GROUPS))
    if "md5" in entry and (not isinstance(entry["md5"], str) or not _MD5.match(entry["md5"])):
        return "%s: not an MD5" % name
    if "integrity" in entry and (not isinstance(entry["integrity"], str) or not _INTEGRITY.match(entry["integrity"])):
        return "%s: not an integrity value (sha512-<base64>)" % name
    if "listing" in entry and not _official(entry["listing"]):
        return "%s: the checksum list is not an https address of an official server" % name
    for field in ("what", "used_by", "note", "publisher"):
        if field in entry and not isinstance(entry[field], str):
            return "%s: %s is not a text" % (name, field)
    return ""


def load(path: str = MANIFEST) -> Dict[str, dict]:
    """``{file name: row}`` of the manifest, in its order. Refuses a manifest
    with any row that is not complete and well-formed - nothing is fetched by
    half a list."""
    try:
        if os.path.getsize(path) > MAX_MANIFEST:
            raise FetchError("the manifest is too large: " + path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise FetchError("the manifest cannot be read: %s" % exc)
    rows = data.get("files") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) > MAX_FILES:
        raise FetchError("the manifest has no list of files (or more than %d)" % MAX_FILES)
    out: Dict[str, dict] = {}
    for row in rows:
        problem = _entry_problem(row)
        if problem:
            raise FetchError("manifest: " + problem)
        if row["file"].lower() in (name.lower() for name in out):
            raise FetchError("manifest: listed twice: " + row["file"])
        out[row["file"]] = row
    return out


def listed(url: str, sha256: str, manifest: Optional[Dict[str, dict]] = None) -> dict:
    """The row with this address and this SHA-256. Refuses an address that is
    not listed, and one that is listed with another SHA-256."""
    for entry in (load() if manifest is None else manifest).values():
        if entry["url"] == url:
            if entry["sha256"] != (sha256 or "").lower():
                raise FetchError("%s is listed with another SHA-256 than the one asked for" % entry["file"])
            return entry
    raise FetchError("not listed in the manifest: " + str(url))


def row_for(url: str, manifest: Optional[Dict[str, dict]] = None) -> dict:
    """The row with this address (refuses an address that is not listed)."""
    for entry in (load() if manifest is None else manifest).values():
        if entry["url"] == url:
            return entry
    raise FetchError("not listed in the manifest: " + str(url))


def obtain(url: str, path: str, offline: bool = False, manifest: Optional[Dict[str, dict]] = None,
           opener=None, say=print) -> dict:
    """For the tools that build the hash tables: make sure the listed file with
    the address ``url`` lies at ``path``, and return its row. A file that is
    there is compared with the row (size and SHA-256); one that is missing is
    downloaded - never when ``offline``. Every refusal of :func:`fetch` applies."""
    entry = row_for(url, manifest)
    if offline and not os.path.lexists(path):
        raise FetchError("missing (offline): " + path)
    fetch(entry, path, opener, say)
    return entry


def read_listing(url: str, manifest: Optional[Dict[str, dict]] = None, opener=None) -> str:
    """The text of a publisher's checksum list - only one that a row of the
    manifest names as its ``listing``. It is read (at most ``MAX_LISTING``
    bytes) and returned; nothing is kept."""
    rows = load() if manifest is None else manifest
    if not any(row.get("listing") == url for row in rows.values()):
        raise FetchError("not a checksum list of the manifest: " + str(url))
    try:
        with (opener or _open)(url) as reply:
            return reply.read(MAX_LISTING).decode("utf-8", "replace")
    except (OSError, urllib.error.URLError) as exc:
        raise FetchError("%s: %s" % (url, exc))


def remote_size(url: str, opener=None) -> Optional[int]:
    """The size an official server states for the file at ``url`` (its ``Content-Length``;
    None: it states none). Nothing of the file is read - for the builders that write a row
    of a manifest, and for the size of a planned download (phageo, 2026-10-19)."""
    try:
        with (opener or _open)(url) as reply:
            stated = reply.headers.get("Content-Length")
    except (OSError, urllib.error.URLError) as exc:
        raise FetchError("%s: %s" % (url, exc))
    return int(stated) if stated and stated.isdigit() else None


def read_release_list(repo: str, page: int, opener=None) -> list:
    """One page (100 releases) of GitHub's list of the releases of ``repo`` - only for the
    projects whose releases a table is built from (``RELEASE_LISTS``). Each release with its
    tag, whether it is a pre-release or a draft, and its files with the size and the SHA-256
    GitHub states (``"digest": "sha256:..."``; older files have none). Nothing is kept."""
    if repo not in RELEASE_LISTS or type(page) is not int or not 1 <= page <= 100:
        raise FetchError("not a release list of the projects this project builds tables from: %r" % (repo,))
    url = "https://api.github.com/repos/%s/releases?per_page=100&page=%d" % (repo, page)
    try:
        with (opener or _open)(url) as reply:
            data = json.JSONDecoder().decode(reply.read(MAX_LISTING * 4).decode("utf-8"))
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise FetchError("%s: %s" % (url, exc))
    if not isinstance(data, list):
        raise FetchError("%s: not a list of releases" % url)
    return data


# the GitHub projects whose release lists are read (phageo, 2026-10-19)
RELEASE_LISTS = frozenset({"electron/electron", "libsdl-org/SDL", "kcat/openal-soft"})


# -- comparing ------------------------------------------------------------------------------
def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def difference(entry: dict, path: str) -> str:
    """How the file at ``path`` differs from its row ("": it is the listed
    file). The file is read and hashed, nothing else."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return "missing"
    if entry["sha256"] is None:
        return "no SHA-256 listed yet (a first download): SHA-256 of the file %s" % sha256_of(path)
    if entry["size"] is not None and size != entry["size"]:
        return "size %d, listed %d" % (size, entry["size"])
    found = sha256_of(path)
    if found != entry["sha256"]:
        return "SHA-256 %s, listed %s" % (found, entry["sha256"])
    if "integrity" in entry and integrity_of(path) != entry["integrity"]:
        return "SHA-512 is not the listed integrity value"
    return ""


def integrity_of(path: str) -> str:
    """``sha512-<base64>`` of a file: the form in which the npm registry states it."""
    import base64
    digest = hashlib.sha512()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(block)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


# -- downloading ----------------------------------------------------------------------------
def _redirect_allowed(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    return parts.scheme == "https" and (host in REDIRECTS or host.endswith(REDIRECT_SUFFIXES))


class _OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _redirect_allowed(newurl):
            raise FetchError("redirected away from the official servers: " + newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(url: str):
    """The reply of an official server to a request for ``url``."""
    if not _official(url):
        raise FetchError("not an https address of an official server: " + str(url))
    # (SourceForge sends anything that looks like a browser to an HTML page instead)
    agent = "curl/8.0" if urllib.parse.urlsplit(url).hostname == "downloads.sourceforge.net" \
        else "gamescan-fetch"
    opener = urllib.request.build_opener(_OfficialRedirects)
    reply = opener.open(urllib.request.Request(url, headers={"User-Agent": agent}), timeout=60)
    if not _redirect_allowed(reply.geturl()):
        reply.close()
        raise FetchError("answered from another server: " + reply.geturl())
    return reply


def fetch(entry: dict, target: str, opener=None, say=print) -> str:
    """Bring the listed file ``entry`` to the path ``target`` and return what
    happened: ``"already there"`` or ``"downloaded"``. A file that is already
    at ``target`` and is not the listed one is refused and left alone. The
    download goes to ``target + ".part"``, is hashed while it is written, and
    is deleted when its size or SHA-256 is not the listed one. ``opener``:
    what answers an address (default: the official servers, :func:`_open`).
    Nothing of the file is run, unpacked or read as anything but bytes."""
    problem = _entry_problem(entry)
    if problem:
        raise FetchError("not a row of the manifest: " + problem)
    if entry["sha256"] is None and os.path.lexists(target):
        raise FetchError("%s: the first download is done (SHA-256 %s); write it into the manifest and take "
                         "the \"first\" note out" % (entry["file"], sha256_of(target)))
    if os.path.lexists(target):
        wrong = difference(entry, target)
        if wrong:
            raise FetchError("%s is there but is not the listed file (%s); it was left as it is"
                             % (target, wrong))
        return "already there"
    limit = entry["size"] if entry["size"] is not None else MAX_SIZE
    part = target + ".part"
    try:
        for attempt in range(1, TRIES + 1):
            try:
                size, found = _once(entry, part, limit, opener or _open)
                break
            except _NoConnection as exc:
                # only this is tried again: the server could not be reached, or the connection
                # broke. A file that came and is not the listed one is refused at once.
                if os.path.lexists(part):
                    os.remove(part)
                if attempt == TRIES:
                    raise FetchError("%s: %s (%d tries)" % (entry["file"], exc, TRIES))
                say("  %s: no connection (%s); try %d of %d in %d seconds"
                    % (entry["file"], exc, attempt + 1, TRIES, RETRY_WAIT))
                time.sleep(RETRY_WAIT)
        if entry["size"] is not None and size != entry["size"]:
            raise FetchError("%s: %d bytes, listed %d" % (entry["file"], size, entry["size"]))
        if entry["sha256"] is None:
            # (no SHA-256 to compare with: the publisher's own signature is the proof - phageo, 2026-10-17)
            who = publisher_of(part)
            if who != entry["publisher"]:
                raise FetchError("%s: a first download is kept only with a valid signature of %r - %s; deleted"
                                 % (entry["file"], entry["publisher"],
                                    "signed by %r" % who if who else "no valid signature"))
            os.replace(part, target)
            say("  downloaded %s (%d bytes) - a FIRST download, validly signed by %s: SHA-256 %s; write the "
                "value into the manifest" % (entry["file"], size, who, found))
            return "downloaded (first download)"
        if found != entry["sha256"]:
            raise FetchError("%s: SHA-256 %s does not match the listed %s"
                             % (entry["file"], found, entry["sha256"]))
        if "integrity" in entry and integrity_of(part) != entry["integrity"]:
            raise FetchError("%s: its SHA-512 is not the listed integrity value" % entry["file"])
        os.replace(part, target)
    except OSError as exc:
        raise FetchError("%s: %s" % (entry["file"], exc))
    finally:
        if os.path.lexists(part):
            os.remove(part)
    say("  downloaded %s (%d bytes, SHA-256 as listed)" % (entry["file"], size))
    return "downloaded"


def publisher_of(path: str) -> str:
    """The publisher on the valid Authenticode signature embedded in the file at ``path``
    ("": none, or not valid, or not Windows). Windows' own check (``WinVerifyTrust``, through
    ctypes - ``gamescan/trust.py``), asked afresh: no answer kept from before. The file is
    read by Windows, never run. A developer's check: the scanner does not use this."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from gamescan import trust
    if sys.platform != "win32":
        return ""
    try:
        # (trust.signer_name keeps answers by path, time and size; a .part file is new every time)
        if not trust._verify(path):
            return ""
        return trust._subject(path)
    except Exception:                            # missing API, odd file, ...
        return ""


class _NoConnection(Exception):
    """The server could not be reached, or the connection broke: worth another try."""


def _once(entry: dict, part: str, limit: int, opener) -> tuple:
    """One try to download ``entry`` into ``part``: ``(size, SHA-256)`` of what came.
    :class:`_NoConnection` when the server was not reached or the connection broke; an
    answer of the server that is an error (404 ...) is no connection problem."""
    digest, size = hashlib.sha256(), 0
    deadline = time.monotonic() + MAX_SECONDS
    try:
        reply = opener(entry["url"])
    except urllib.error.HTTPError as exc:
        raise FetchError("%s: %s" % (entry["file"], exc))
    except (OSError, urllib.error.URLError) as exc:
        raise _NoConnection(str(exc))
    with reply, open(part, "wb") as out:
        while True:
            try:
                block = reply.read(_CHUNK)
            except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
                raise _NoConnection(str(exc) or type(exc).__name__)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise FetchError("%s: more than the %d bytes that are listed" % (entry["file"], limit))
            if time.monotonic() > deadline:
                raise FetchError("%s: the download took too long" % entry["file"])
            digest.update(block)
            out.write(block)
    return size, digest.hexdigest()


# -- command line ---------------------------------------------------------------------------
def _chosen(manifest: Dict[str, dict], names: List[str], group: Optional[str]) -> List[dict]:
    for name in names:
        if name not in manifest:
            raise FetchError("not listed in the manifest: " + name)
    rows = [manifest[name] for name in names] if names else list(manifest.values())
    return [row for row in rows if group is None or group in row["groups"]]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("names", nargs="*", help="file names from the manifest (default: all)")
    ap.add_argument("--manifest", default=MANIFEST)
    ap.add_argument("--group", choices=GROUPS, help="only the files of this group")
    ap.add_argument("--to", metavar="FOLDER", help="the folder the files are kept in (outside the project)")
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument("--list", action="store_true", help="show what is listed; contacts no server")
    what.add_argument("--check", action="store_true",
                      help="compare the files in --to with the manifest; contacts no server")
    what.add_argument("--fetch", action="store_true",
                      help="download what is missing in --to, and compare everything")
    args = ap.parse_args(argv)
    try:
        rows = _chosen(load(args.manifest), args.names, args.group)
        if args.list:
            for row in rows:
                size = "%11d" % row["size"] if row["size"] is not None else "    unknown"
                print("%-58s %s  %s  %s" % (row["file"], size, (row["sha256"] or "(first download)")[:16],
                                            ",".join(row["groups"])))
            print("%d files, %.1f MB listed" % (len(rows), sum(r["size"] or 0 for r in rows) / 1048576))
            return 0
        if not args.to:
            ap.error("--to FOLDER is needed")
        if args.fetch:
            os.makedirs(args.to, exist_ok=True)
        bad = 0
        for row in rows:
            target = os.path.join(args.to, row["file"])
            try:
                result = fetch(row, target) if args.fetch else (difference(row, target) or "as listed")
            except FetchError as exc:
                result = "REFUSED: %s" % exc
            bad += result not in ("as listed", "already there", "downloaded", "downloaded (first download)")
            print("%-58s %s" % (row["file"], result))
        return 1 if bad else 0
    except FetchError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
