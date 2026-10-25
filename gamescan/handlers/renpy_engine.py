"""Is a file of the Ren'Py engine really a file of the Ren'Py engine?

Ren'Py's own scripts sit in ``renpy/`` (and its Python library in ``lib/``),
and they do things a game script has no business doing - the updater downloads
files and starts programs. Being in that folder proves nothing: a repack can
put anything there. What proves it is the content:

``VERIFIED``  the file is, by its SHA-256, a script of an official SDK
              (:mod:`gamescan.engine_hashes`) - or, a compiled script, it
              contains exactly what the official one contains
``MISMATCH``  the engine in this folder says it is a version whose scripts are
              in the tables, and this file is not one of them: it was changed
``UNKNOWN``   the engine is a version that is not in the tables (or says so),
              so nothing can be compared

``""`` means the file is no engine file at all. The version is read from the
engine's own ``vc_version.py`` / ``__init__.py`` - which a repack can rewrite,
so ``UNKNOWN`` is weaker than it sounds: it is what an altered engine that
claims an unlisted version gets, too.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Dict, Optional

from .. import engine_hashes
from ..models import FileContext
from ..unpack import pycalls, pyo, pytokens, rpyc

VERIFIED, MISMATCH, UNKNOWN = "verified", "changed", "unknown version"
# why a chain inside a verified engine script is kept among the suppressed findings
VERIFIED_SCRIPT = "Official Ren'Py engine script, verified against the SDK"
UNVERIFIED_NOTE = (" The engine file could not be verified: this copy of Ren'Py is a version "
                   "whose official files are not in the scanner's table, so the file is trusted "
                   "for its folder only and the finding is shown as HIGH instead of CRITICAL.")
_ENGINE_PATH = re.compile(r"(?:^|/)(?:renpy|lib/(?:python|py)[^/]*)/")
_ENGINE_PLACE = re.compile(r"(?:^|[/!])(?:renpy|lib/(?:python|py)[^/]*)/")     # ... also inside an archive
_COMPILED = (".rpyc", ".rpymc")
_MAX_VERSION_FILE = 1 << 20
_NEW_STYLE = re.compile(r"""^version\s*=\s*u?['"](\d+(?:\.\d+){1,5})['"]""", re.M)
_TUPLE = re.compile(r"^version_tuple\s*=\s*\(\s*(\d+(?:\s*,\s*\d+){1,4})\s*,\s*vc_version\s*\)", re.M)
_VC = re.compile(r"^vc_version\s*=\s*(\d+)", re.M)
_versions: Dict[str, Optional[str]] = {}          # engine folder -> version it claims
_MAX_CACHED = 256


def is_engine_path(key: str) -> bool:
    """Named like a file of the engine (``key``: lower-case path, forward slashes)."""
    return "!" not in key and bool(_ENGINE_PATH.search(key))


def _read(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(_MAX_VERSION_FILE).decode("utf-8", "replace")
    except OSError:
        return ""


def claimed_version(engine_folder: str) -> Optional[str]:
    """The version the Ren'Py in ``engine_folder`` (its ``renpy`` directory)
    says it is, e.g. ``"7.3.5.606"`` (None: it does not say)."""
    if engine_folder not in _versions:
        if len(_versions) >= _MAX_CACHED:
            _versions.clear()
        vc = _read(os.path.join(engine_folder, "vc_version.py"))
        _versions[engine_folder] = version_from(vc, lambda: _read(os.path.join(engine_folder, "__init__.py")))
    return _versions[engine_folder]


def version_from(vc: str, init) -> Optional[str]:
    """The version ``renpy/vc_version.py`` (text ``vc``) and ``renpy/__init__.py`` (``init``: its
    text, or a function that gives it - read only when needed) say."""
    found = _NEW_STYLE.search(vc or "")
    if found:
        return found.group(1)
    found = _TUPLE.search((init() if callable(init) else init) or "")
    if not found:
        return None
    version = ".".join(part.strip() for part in found.group(1).split(","))
    build = _VC.search(vc or "")
    return version + "." + build.group(1) if build else version


# -- programs in the engine's place (ENGINE-008; phageo, 2026-10-18, decision 2) ------------------
# Where a game built with Ren'Py keeps the engine's programs and libraries: lib/ (and renpy/). The
# folder that holds them is the engine's root, with renpy/vc_version.py and renpy/__init__.py.
_PROGRAM_PLACE = re.compile(r"(?:^|[/!])(renpy|lib)/")
VERSION_FILES = ("renpy/vc_version.py", "renpy/__init__.py")
_sdk_names: Optional[frozenset] = None


def engine_root(key: str) -> Optional[str]:
    """The engine's root a file of ``lib/`` / ``renpy/`` belongs to - the part of its path before
    that folder (``"game-1.0-pc/"``, ``"x.zip!game/"``, ``""``); None: no such file."""
    found = _PROGRAM_PLACE.search(key)
    return key[:found.start(1)] if found else None


def version_file(key: str) -> Optional[tuple]:
    """``(engine root, which file)`` for ``renpy/vc_version.py`` / ``renpy/__init__.py`` (None: other)."""
    for name in VERSION_FILES:
        if key.endswith(name):
            root = key[:-len(name)]
            if not root or root.endswith(("/", "!")):
                return root, name
    return None


def sdk_program(name: str) -> bool:
    """Does any listed Ren'Py SDK hold a program of this file name?"""
    global _sdk_names
    if _sdk_names is None:
        renpy = {at for at, row in enumerate(engine_hashes.ARCHIVES) if row[0] == "Ren'Py"}
        _sdk_names = frozenset(entry[0].rsplit("/", 1)[-1].lower() for entry in engine_hashes.KNOWN.values()
                               if entry[1] in renpy)
    return name.lower() in _sdk_names


def version_listed(version: Optional[str]) -> bool:
    """Are the official scripts of this version in the tables?"""
    return bool(version) and any(version == known or version.startswith(known + ".")
                                 for known in engine_hashes.renpy_versions())


def _engine_folder(path: str) -> Optional[str]:
    """The ``renpy`` directory the file on disk belongs to."""
    parts = os.path.abspath(path).split(os.sep)
    for index in range(len(parts) - 2, 0, -1):
        if parts[index].lower() == "renpy":
            return os.sep.join(parts[:index + 1])
        if parts[index].lower() == "lib":                      # the engine sits beside lib/
            return os.sep.join(parts[:index] + ["renpy"])
    return None


BYTECODE = (".pyo", ".pyc")
# what lies beside a compiled file that is not the official one (compiled_status)
SOURCE_OFFICIAL, SOURCE_CHANGED, SOURCE_MISSING = "official source", "changed source", "no source"
SOURCE_COMMENTS = "source changed in comments only"       # ... and the compiled file is not its
SOURCE_UNREAD = "changed source, not readable as tokens"  # so that question could not be asked
LEFTOVER = "another version"       # an official compiled file, of another listed version
# added to the LOW note when the changed source could not be cut into tokens
UNREAD_SOURCE_NOTE = (" (the source could not be read token by token, so it was not checked "
                      "whether more than comments were changed)")
# compiled Python is looked at in all of lib/, not only where the scripts' rule looks: the
# Python library the game's program loads first sits in lib/<platform>/Lib
_COMPILED_PLACE = re.compile(r"(?:^|[/!])(?:renpy|lib)/")
_MAX_SOURCE = 16 * 1024 * 1024


def _home(path: str) -> Optional[str]:
    """The ``renpy`` directory a compiled file belongs to: the nearest
    ``renpy`` folder above it, or beside a ``lib`` folder above it, that says
    which version it is (``lib/<platform>/lib/python2.7/renpy`` is a folder of
    the Python library, not the engine)."""
    parts = os.path.abspath(path).split(os.sep)
    for index in range(len(parts) - 2, 0, -1):
        if parts[index].lower() in ("renpy", "lib"):
            folder = os.sep.join(parts[:index] + ["renpy"])
            if claimed_version(folder) is not None:
                return folder
    return None


def _source_beside(path: str, compiled: bytes) -> str:
    """What lies beside a compiled file that is not the official one: the
    official ``.py``, none, or a changed one - and then, was it changed in its
    code? The changed source is cut into tokens (:mod:`gamescan.unpack.pytokens`:
    text only, nothing is compiled or run). If it is an official source apart
    from comments and spacing, it explains nothing: the compiled file then
    has to be what that official source compiles to, apart from the line
    numbers the comments moved."""
    from .. import compiled_hashes
    source = os.path.splitext(path)[0] + ".py"
    try:
        if os.path.getsize(source) > _MAX_SOURCE:
            return SOURCE_UNREAD
        with open(source, "rb") as fh:
            text = fh.read(_MAX_SOURCE)
    except OSError:
        return SOURCE_MISSING
    if engine_hashes.verified_script(hashlib.sha256(text).hexdigest()):
        return SOURCE_OFFICIAL
    tokens = pytokens.token_key(text)
    if tokens is None:
        return SOURCE_UNREAD
    official = compiled_hashes.compiled_from(tokens)
    if official is None or pyo.content_key(compiled, lines=False) in official:
        return SOURCE_CHANGED
    return SOURCE_COMMENTS


_MANGLED = re.compile(r"_[A-Za-z0-9_]*?(__\w+)\Z")       # self.__x in class C is stored as _C__x


def calls_not_in_source(path: str, called) -> Optional[list]:
    """The names a compiled file calls (``pycalls.Listing.called``) that the
    ``.py`` beside it never writes - a compiled file is made from its source,
    so there should be none. Left out: the names the compiler adds by itself.
    None: the source is missing or cannot be read as tokens."""
    source = os.path.splitext(path)[0] + ".py"
    try:
        if os.path.getsize(source) > _MAX_SOURCE:
            return None
        with open(source, "rb") as fh:
            written = pytokens.names(fh.read(_MAX_SOURCE))
    except OSError:
        return None
    return None if written is None else names_not_written(called, written)


def names_not_written(called, written) -> list:
    """The called names that are not among the names a source writes."""
    missing = []
    for name in sorted(called):
        private = _MANGLED.match(name)
        if (name not in written and name not in pycalls.COMPILER_NAMES
                and not (private and private.group(1) in written)):
            missing.append(name)
    return missing


def _same_version(version: str, known) -> bool:
    return any(version == one or version.startswith(one + ".") for one in known)


def compiled_status(ctx: FileContext) -> str:
    """The same question for compiled Python (``.pyo`` / ``.pyc``) of the
    engine: ``VERIFIED`` - it contains exactly what a compiled file of an
    official SDK contains (:mod:`gamescan.compiled_hashes`); ``LEFTOVER`` -
    official, but of other listed versions than the one this copy of Ren'Py
    says it is (``ctx.cache["compiled_versions"]``); ``MISMATCH`` - a listed
    version, compiled Python 2.7, and not an official file
    (``ctx.cache["compiled_source"]`` then says what lies beside it);
    ``UNKNOWN`` - a version that is not listed; ``""`` - no engine file, or
    nothing can be said: Python 3 files are only known by their exact bytes
    so far, and one that differs is not judged.

    The file is read as data (:mod:`gamescan.unpack.pyo`); the source path
    stored in it is never taken out of it.

    Inside an archive or an installer only ``VERIFIED`` can be said (by content, as for the
    scripts - phageo, 2026-10-17, fifty-ninth message): there is no engine folder to ask."""
    if not ctx.key.endswith(BYTECODE) or not _COMPILED_PLACE.search(ctx.key):
        return ""
    if "!" in ctx.key:
        if "compiled_file" not in ctx.cache:
            from .. import compiled_hashes
            key = pyo.content_key(ctx.data) if pyo.is_python2(ctx.data) and not ctx.truncated else None
            ctx.cache["compiled_file"] = VERIFIED if compiled_hashes.versions(ctx.sha256, key) else ""
        return ctx.cache["compiled_file"]
    if "compiled_file" not in ctx.cache:
        from .. import compiled_hashes                 # a large table: only when needed
        python2 = pyo.is_python2(ctx.data)
        key = pyo.content_key(ctx.data) if python2 and not ctx.truncated else None
        known = compiled_hashes.versions(ctx.sha256, key)
        folder = _home(ctx.path) if ctx.path and (known or python2) else None
        version = claimed_version(folder) if folder is not None else None
        listed = version_listed(version)
        ctx.cache["engine_version"] = version or ""
        if known:
            result = VERIFIED
            if listed and not _same_version(version, known):
                result = LEFTOVER
                ctx.cache["compiled_versions"] = known
        elif not python2:
            result = ""
        else:
            result = MISMATCH if listed else UNKNOWN
            if result == MISMATCH:
                ctx.cache["compiled_source"] = _source_beside(ctx.path, ctx.data)
        ctx.cache["compiled_file"] = result
    return ctx.cache["compiled_file"]

def status(ctx: FileContext) -> str:
    """``VERIFIED``, ``MISMATCH`` or ``UNKNOWN`` for a file named like an
    engine file; ``""`` for any other file.

    A member of an archive or an installer is checked by its content wherever it sits in it
    (phageo, 2026-10-17, fifty-ninth message): ``VERIFIED`` needs no engine folder. ``MISMATCH``
    / ``UNKNOWN`` do - the folder is asked which version it is -, so a member that is not an
    official script is no engine file (``""``), as before; a loose file is an engine file by
    its folder, as before."""
    if "!" not in ctx.key and not is_engine_path(ctx.key):
        return ""
    if "engine_script" not in ctx.cache:
        # (a compiled script is compared by what it contains only where the engine's are -
        # inside an archive too: the content key costs a decompression)
        key = rpyc.content_key(ctx.data) if ctx.key.endswith(_COMPILED) and not ctx.truncated \
            and _ENGINE_PLACE.search(ctx.key) else None
        official = engine_hashes.verified_script(ctx.sha256, key)
        if official:
            result = VERIFIED
            ctx.cache["engine_script_name"] = official
        elif not is_engine_path(ctx.key):
            return ""                   # (no engine file: nothing is kept about it, as before)
        else:
            folder = _engine_folder(ctx.path) if ctx.path else None
            version = claimed_version(folder) if folder is not None else None
            listed = version_listed(version)
            result = MISMATCH if listed else UNKNOWN
            ctx.cache["engine_version"] = version or ""
        ctx.cache["engine_script"] = result
    return ctx.cache["engine_script"]
