"""Where a finding stands: its origin tag (phageo, 2026-11-02, origin-tag session).

Every finding gets one of five kinds, decided only from what the scan already knows about the file it
is filed on - the official tables, the npm / library hashes, the installer readers, the engines' own
places inside the game root - never from a guess on the content:

- ``ENGINE_OFFICIAL``: the file matched an official table (an engine build, an Electron / NW.js /
  Ren'Py / Unity / RPG Maker runtime, an Inno Setup or NSIS stub, DirectX), by SHA-256 or by the
  frame key those tables use.
- ``BUNDLED_LIBRARY``: a third-party library the game ships. *Verified* when the file is byte for byte
  a file of a published npm package or of an official library release (name and version from that
  table); *unverified* when only its place says so (``node_modules/<package>/``, RPG Maker's
  ``js/libs/``) or its file name is one a library of the table ships (``SDL2.dll``) - name only.
- ``INSTALLER``: the setup engine or the installer's script - the installer file itself (Inno Setup,
  NSIS, Windows Installer) and what its reader makes of its instructions (``[installer script]``,
  ``[custom action]``, ``[Binary]``). The files an installer carries are judged by their own place.
- ``GAME_CODE``: the places where an engine keeps the game's own code: Ren'Py's ``game/`` scripts,
  RPG Maker's plugins and ``Scripts`` data, Unity's ``Assembly-CSharp`` / ``GameAssembly`` and
  metadata, an Electron app's own files outside ``node_modules``, a Godot pack.
- ``UNKNOWN``: everything else - an unverified program or library no table and no place explains.
  A valid trusted signature tells who made a file, not what it is: it stays UNKNOWN (the signer is
  named in the detail).

**Information only (phageo, 2026-11-02): an origin changes no level, no verdict and no suppression.**
It is stamped after every level is final (``Scanner.scan`` / ``scan_bytes``), and the tests check that
a scan gives the same levels with the stamping on and off (``STAMP``). A chain filed on a file gets
that file's origin, also when its other parts stand elsewhere.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, Optional, Tuple

GAME_CODE = "GAME_CODE"
BUNDLED_LIBRARY = "BUNDLED_LIBRARY"
ENGINE_OFFICIAL = "ENGINE_OFFICIAL"
INSTALLER = "INSTALLER"
UNKNOWN = "UNKNOWN"
KINDS = (GAME_CODE, BUNDLED_LIBRARY, ENGINE_OFFICIAL, INSTALLER, UNKNOWN)

# False: findings get no origin (the tests compare a scan with and without; nothing else switches it)
STAMP = True

# the names the installer readers give what they read out of an installer's instructions
_INSTALLER_PARTS = ("[installer script]", "[custom action", "[binary]")
_INSTALLER_KINDS = frozenset({"inno", "nsis"})
# the endings of a library's program file a table's name may be matched on (an index.js is no name)
_PROGRAM_ENDINGS = (".dll", ".node", ".so", ".dylib")
_RENPY_CODE = (".rpy", ".rpyc", ".rpym", ".rpymc", ".py", ".pyc", ".pyo", ".rpa", ".rpyb")
_RGSS_SCRIPTS = ("scripts.rxdata", "scripts.rvdata", "scripts.rvdata2")
_UNITY_CODE = ("assembly-csharp", "assembly-unityscript", "assembly-boo")

_LIBRARY_NAMES: Optional[Dict[str, str]] = None


class Origin(tuple):
    """``(kind, detail, verified)``: ``detail`` names a library (and version), an official file or a
    signer; ``verified`` is True when a table proves it (BUNDLED_LIBRARY, ENGINE_OFFICIAL)."""

    def __new__(cls, kind: str, detail: str = "", verified: bool = False):
        return tuple.__new__(cls, (kind, detail, verified))

    kind = property(lambda self: self[0])
    detail = property(lambda self: self[1])
    verified = property(lambda self: self[2])


def token(kind: str, verified: bool) -> str:
    """The form of the result files: the kind, and for a library whether a table proves it
    (``BUNDLED_LIBRARY:verified`` / ``BUNDLED_LIBRARY:unverified``). No names: a package name read
    from a path could be the game's own (CLAUDE.md rule 11)."""
    if kind == BUNDLED_LIBRARY:
        return "%s:%s" % (kind, "verified" if verified else "unverified")
    return kind or UNKNOWN


def of_finding(f) -> str:
    """:func:`token` of a finding (UNKNOWN when it has none: a report from before the tag)."""
    return token(getattr(f, "origin", "") or UNKNOWN, bool(getattr(f, "origin_verified", False)))


def _library_names() -> Dict[str, str]:
    """File name (lower case) of a program file an official library release ships -> that name as the
    table spells it, without its ending (``library_hashes``). The name, not the release: a release can
    ship other libraries' files too (OpenAL Soft's archive holds Qt and the MinGW runtime)."""
    global _LIBRARY_NAMES
    if _LIBRARY_NAMES is None:
        from . import library_hashes
        names: Dict[str, str] = {}
        for name, _index in library_hashes.KNOWN.values():
            leaf = str(name).replace("\\", "/").rsplit("/", 1)[-1]
            if leaf.lower().endswith(_PROGRAM_ENDINGS):
                names[leaf.lower()] = os.path.splitext(leaf)[0]
        _LIBRARY_NAMES = names
    return _LIBRARY_NAMES


def _parts(relpath: str) -> list:
    return [p for p in relpath.replace("\\", "/").replace("!", "/").lower().split("/") if p]


def by_place(relpath: str) -> Origin:
    """The origin a path inside the game root gives (no table, no content)."""
    parts = _parts(relpath)
    if not parts:
        return Origin(UNKNOWN)
    leaf = parts[-1]
    if any(p.startswith(_INSTALLER_PARTS) for p in parts):
        return Origin(INSTALLER)
    if "node_modules" in parts:
        at = len(parts) - 1 - parts[::-1].index("node_modules")
        rest = parts[at + 1:]
        if len(rest) >= 2:
            name = "/".join(rest[:2]) if rest[0].startswith("@") and len(rest) >= 3 else rest[0]
            return Origin(BUNDLED_LIBRARY, name)
    for i in range(len(parts) - 2):
        if parts[i] == "js" and parts[i + 1] == "libs":
            return Origin(BUNDLED_LIBRARY, os.path.splitext(parts[i + 2])[0])
    library = _library_names().get(leaf)
    if library:
        return Origin(BUNDLED_LIBRARY, library)
    # the places the engines keep the game's own code in
    if "game" in parts[:-1] and leaf.endswith(_RENPY_CODE) and not {"renpy", "lib"} & set(parts[:parts.index("game")]):
        return Origin(GAME_CODE, "Ren'Py game scripts")
    if leaf in _RGSS_SCRIPTS and len(parts) >= 2 and parts[-2] == "data":
        return Origin(GAME_CODE, "RPG Maker scripts")
    for i in range(len(parts) - 1):
        if parts[i] == "js" and (parts[i + 1] == "plugins" or (parts[i + 1] == "plugins.js" and i + 1 == len(parts) - 1)):
            return Origin(GAME_CODE, "RPG Maker plugins")
    if leaf.startswith(_UNITY_CODE) and leaf.endswith(".dll") and "managed" in parts:
        return Origin(GAME_CODE, "Unity game code")
    if leaf == "gameassembly.dll" or (leaf == "global-metadata.dat" and "metadata" in parts):
        return Origin(GAME_CODE, "Unity game code (IL2CPP)")
    for i in range(len(parts) - 1):
        if parts[i] == "resources" and parts[i + 1] in ("app", "app.asar"):
            return Origin(GAME_CODE, "the app's own files")
    if leaf.endswith(".pck"):
        return Origin(GAME_CODE, "Godot pack")
    return Origin(UNKNOWN)


def of_file(ctx, signed_prefix: str = "") -> Origin:
    """The origin of a file the scan read, from the tables and what the readers recorded on ``ctx``
    (its ``baseline``, its containers), else from its place (:func:`by_place`)."""
    from . import electron_official, engine_hashes, library_hashes, npm_hashes, official
    sha, base = ctx.sha256, ctx.baseline or ""
    library = library_hashes.verified(sha) or npm_hashes.verified(sha)
    if library:
        if library.startswith("npm package "):
            library = library[len("npm package "):]
        return Origin(BUNDLED_LIBRARY, library, True)
    if base.startswith(engine_hashes.VERIFIED) or electron_official.PROGRAM_VERIFIED in base:
        return Origin(ENGINE_OFFICIAL, base.split(": ", 1)[-1], True)
    exact = official.exact(sha)
    if exact:
        return Origin(ENGINE_OFFICIAL, exact, True)
    kinds = {kind for kind, _at, _size in (ctx.cache.get("containers") or ())}
    if kinds & _INSTALLER_KINDS or ctx.ext == ".msi":
        return Origin(INSTALLER, "/".join(sorted(kinds & _INSTALLER_KINDS)) or "msi")
    place = by_place(ctx.relpath)
    if place.kind == UNKNOWN and signed_prefix and base.startswith(signed_prefix):
        return Origin(UNKNOWN, base.split(": ", 1)[-1])      # (the signer)
    return place


def stamp(findings: Iterable, files: Dict[str, Origin]) -> None:
    """Give every finding without one the origin of the file it is filed on (``files``: relpath ->
    :class:`Origin` of every file the scan read); a file the scan did not read (a note on a folder)
    by its place. Changes nothing else of a finding."""
    if not STAMP:
        return
    for f in findings:
        if getattr(f, "origin", ""):
            continue
        found = files.get(f.file) or by_place(f.file)
        f.origin, f.origin_detail, f.origin_verified = found.kind, found.detail, found.verified


def summary(findings: Iterable) -> Tuple[Tuple[str, str, bool, int], ...]:
    """``((kind, detail, verified, count), ...)`` of ``findings``, most first."""
    counted: Dict[Tuple[str, str, bool], int] = {}
    for f in findings:
        key = (getattr(f, "origin", "") or UNKNOWN, getattr(f, "origin_detail", ""),
               bool(getattr(f, "origin_verified", False)))
        counted[key] = counted.get(key, 0) + 1
    return tuple((k, d, v, n) for (k, d, v), n in sorted(counted.items(), key=lambda kv: (-kv[1], kv[0])))
