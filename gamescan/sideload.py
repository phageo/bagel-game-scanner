"""DLL side-loading: SIDELOAD-001 (phageo, 2026-10-17).

Windows looks for a library first in the folder of the program that asks for it. A
library that is named like a part of Windows or like a Microsoft redistributable
(``d3dx9_43.dll``, ``msvcp140.dll``, ``version.dll`` ...) and lies beside a program that
imports it - or loads it by name - is therefore what that program runs, whatever the
genuine library is. The names are fixed lists in the repository (``windows_dlls.NAMES`` and
``windows_dlls.REDISTRIBUTABLE``, with the patterns below); the scanning PC's own folders
are never read for them, so the answer does not depend on the PC (phageo, 2026-10-17).
Such a library is reported, HIGH, unless it is validly signed by
Microsoft or is, by its SHA-256, a file of an official hash table (an engine, Electron,
Inno Setup, NSIS, a known library). Its name proves nothing.

Judged after the whole scan (``Scanner._join_sideload``): the scanner keeps, for every
program, the libraries of these names it imports or names beside a ``LoadLibrary`` import,
and for every library of these names what proves where it comes from - for loose files and
for the members of archives and installers alike ("beside": the same folder, inside the same
archive). What is kept is names and a few marks, never content.

Limits: "loads it by name" is the name written in the program next to a ``LoadLibrary``
import (a name put together at run time is not seen); a program that is itself a library
(``.dll``) is not looked at as the one that loads; a memory-only scan cannot check a
signature (Windows checks signatures on files) - there only the official tables can clear a
library.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .windows_dlls import NAMES as WINDOWS_NAMES, REDISTRIBUTABLE as REDISTRIBUTABLE_NAMES

RULE = "SIDELOAD-001"
TITLE = "Library named like a part of Windows beside a program that loads it"
REASON = (
    "Windows looks for a library first in the folder of the program that asks for it. This library "
    "is named like a part of Windows or of a Microsoft runtime package, and the program beside it "
    "imports it or loads it by name - so the program runs this file instead of the genuine one. That "
    "is how malware gets a trusted program to run its code (\"DLL side-loading\"). The genuine library "
    "is signed by Microsoft; this file is not validly signed by Microsoft and is not, byte for byte, "
    "a file of an official release the scanner knows. Games do ship such libraries, but signed ones.")
# the Microsoft redistributables games ship (DirectX, the Visual C++ runtime, XNA / XAudio ...)
REDISTRIBUTABLE = re.compile(
    r"(?:d3dx9_\d+|d3dx10(?:_\d+)?|d3dx11_\d+|d3dcompiler_\d+|d3dcsx_\d+|d3d12core|d3d12sdklayers|dxcompiler"
    r"|dxil|xinput\d_\d|xinput9_1_0|xaudio2_\d+|x3daudio1_\d+|xapofx1_\d+|xactengine\d_\d+"
    r"|msvc[pr]\d+d?(?:_\w+)?|msvcrt\d*|vcruntime\d+(?:_\w+)?|ucrtbased?|api-ms-win-[\w-]+|ext-ms-win-[\w-]+"
    r"|concrt\d+|vcomp\d+d?|vcamp\d+|vccorlib\d+|mfc\d+[a-z]*|mfcm\d+u?|atl\d+|msvcirt|dbghelp|dbgcore"
    r"|webview2loader)\.dll\Z")
LOAD_FUNCTIONS = frozenset({"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrloaddll"})
MICROSOFT = ("Microsoft",)
_NAME_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
MAX_PROGRAMS = 20000                # programs kept per scan
MAX_LIBRARIES = 20000               # libraries of these names kept per scan
MAX_LOADED = 256                    # names one program loads, as kept


def kind_of(name: str) -> str:
    """What a library's file name is named like: "a part of Windows", "a Microsoft
    redistributable" ("" when neither)."""
    name = name.lower()
    if not name.endswith(".dll"):
        return ""
    if name in REDISTRIBUTABLE_NAMES or REDISTRIBUTABLE.match(name):
        return "a Microsoft redistributable"
    return "a part of Windows" if name in WINDOWS_NAMES else ""


def folder_of(relpath: str) -> str:
    """The folder a file lies in, inside the archive or installer it is a member of."""
    path = relpath.replace("\\", "/")
    cut = max(path.rfind("/"), path.rfind("!"))
    return path[:cut].lower() if cut >= 0 else ""


def leaf_of(relpath: str) -> str:
    path = relpath.replace("\\", "/")
    return path[max(path.rfind("/"), path.rfind("!")) + 1:].lower()


def loaded_names(data, imports: Dict[str, List[str]]) -> Set[str]:
    """The libraries of these names a program names in its content, when it imports a
    ``LoadLibrary`` function (written as text, either in single bytes or in UTF-16)."""
    if not any(name.lower() in LOAD_FUNCTIONS for names in imports.values() for name in names):
        return set()
    out: Set[str] = set()
    # (every ".dll" is found by a plain search and the name read backwards from it: a pattern
    # tried at every place of a 150 MB program takes seconds)
    for needle, width in ((b".dll", 1), (b".DLL", 1), (b".Dll", 1), (b".\0d\0l\0l\0", 2),
                          (b".\0D\0L\0L\0", 2), (b".\0D\0l\0l\0", 2)):
        at, seen = data.find(needle), 0
        while at >= 0 and seen < 100000:
            seen += 1
            start = at
            while at - start < 64 * width and start >= width and data[start - width] in _NAME_BYTES \
                    and (width == 1 or data[start - 1] == 0):
                start -= width
            text = bytes(data[start:at + len(needle)])
            name = (text.decode("utf-16-le", "replace") if width == 2 else text.decode("latin-1")).lower()
            if kind_of(name):
                out.add(name)
                if len(out) >= MAX_LOADED:
                    return out
            at = data.find(needle, at + len(needle))
    return out


class Program:
    __slots__ = ("file", "imports", "loads")

    def __init__(self, file: str, imports: Iterable[str], loads: Iterable[str]) -> None:
        self.file = file
        self.imports = frozenset(name for name in imports if kind_of(name))
        self.loads = frozenset(loads)


class Library:
    """A library of such a name: ``proof`` - why it is cleared ("" = nothing clears it);
    ``why`` - what was found about its signature."""
    __slots__ = ("file", "name", "proof", "why", "tag")

    def __init__(self, file: str, proof: str, why: str, tag: dict) -> None:
        self.file, self.name, self.proof, self.why, self.tag = file, leaf_of(file), proof, why, tag


def pairs(programs: List[Program], libraries: List[Library]) -> List[Tuple[Library, Program, str]]:
    """``(library, program, "imports it" / "loads it by name")`` for every library of such a name
    beside a program that asks for it - one program per library (the first by name)."""
    by_folder: Dict[str, List[Program]] = {}
    for program in programs:
        by_folder.setdefault(folder_of(program.file), []).append(program)
    out: List[Tuple[Library, Program, str]] = []
    for library in libraries:
        found: Optional[Tuple[Program, str]] = None
        for program in sorted(by_folder.get(folder_of(library.file), ()), key=lambda p: p.file.lower()):
            if library.name in program.imports:
                found = (program, "imports it")
                break
            if library.name in program.loads and found is None:
                found = (program, "loads it by name")
        if found is not None:
            out.append((library, found[0], found[1]))
    return out
