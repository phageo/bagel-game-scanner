"""Download-and-run across two files: one file stores a download under a name
it shares with other files, another runs what that name holds.

Each Python / Ren'Py script of a folder leaves a short summary
(:func:`gamescan.dataflow.remote_py.study`): the shared names it *fills* from
a download and the shared names it *runs*. After the folder was scanned the
summaries are joined here - one pass, one hop (A fills, B runs; never A to B
to C). Two kinds of names are shared:

``store``   Ren'Py's store: a top-level name of a ``.rpy`` / ``.rpyc`` script,
            and ``store.x`` / ``renpy.store.x`` in any file
``module``  a top-level name (or what a top-level function returns) of a
            ``.py`` file, used elsewhere through an import of that file's
            name: ``import net`` ... ``net.payload``, ``from net import get``

A field of Ren'Py's ``persistent`` is a name of the store (``store:persistent.x``).

The same pass joins a dropper across two files: one file writes a download to
a file on disk (its ``drops``), another starts that file (its ``starts``).
The two are tied by the file's name where both write it out
(``file:<name>``), or by a shared name that holds the path. A module that is
written to the game's folder (``import:<name>``) is started by every script
that imports it with a plain ``import``: the caller hands those in
(``importers``), because a script that only imports leaves no summary.

Nothing is read or parsed here: the summaries are plain texts and numbers.
Limits: number of files, links per file and in all, wall-clock time. What
is cut off by a limit is said to the caller (``complete``).
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from .values import SAFETY_SECONDS

MAX_FILES = 2000                # summaries that are joined
# The counts bound the join (files, names per file - remote_py._MAX_SHARED and its kin -, links).
# The clock is a far safety cap only (values.SAFETY_SECONDS, like every other one since
# 2026-10-13; it was five seconds, and one second before 2026-10-12); when it fires the
# scan's note says so, as before.
MAX_SECONDS = SAFETY_SECONDS    # (a far safety cap since 2026-10-13: ten minutes)
MAX_LINKS = 200                 # chains across files in one folder
_MAX_PER_FILE = 8               # ... and ending in one file
_COMPILED = (".rpyc", ".rpymc", ".pyc", ".pyo")


class Entry:
    """What one script shares. ``store``: its top-level names are names of
    Ren'Py's store. ``tag``: whatever the caller wants back with a link.
    ``drops`` / ``starts``: the files it writes a download to / starts."""

    __slots__ = ("file", "store", "fills", "runs", "tag", "drops", "starts")

    def __init__(self, file: str, store: bool, fills: Dict[str, tuple], runs: Dict[str, tuple],
                 tag: Any = None, drops: Optional[Dict[str, tuple]] = None,
                 starts: Optional[Dict[str, tuple]] = None) -> None:
        self.file, self.store, self.fills, self.runs, self.tag = file, store, fills, runs, tag
        self.drops, self.starts = drops or {}, starts or {}


NAME, FILE, PATH, MODULE = "name", "file", "path", "module"   # what ties the two files of a link


class Link:
    """``filler`` stores a download under ``shown``; ``runner`` runs it.
    ``fill``: ``(request, line, kind, address)``; ``run``: ``(how, sink, line, detail)``.
    ``kind``: ``NAME`` - a shared name holds the download; ``FILE`` - the filler
    wrote it to the file ``shown`` and the runner starts that file; ``PATH`` - the
    same, and the shared name ``shown`` holds the file's path; ``MODULE`` - the
    filler wrote the module ``shown`` and the runner imports it."""

    __slots__ = ("filler", "runner", "shown", "fill", "run", "kind")

    def __init__(self, filler: Entry, runner: Entry, shown: str, fill: tuple, run: tuple,
                 kind: str = NAME) -> None:
        self.filler, self.runner, self.shown, self.fill, self.run = filler, runner, shown, fill, run
        self.kind = kind


def _script(file: str) -> str:
    """The script a file is, whether as source or compiled (``a.rpyc`` is ``a.rpy``)."""
    low = file.lower()
    return low[:-1] if low.endswith(_COMPILED) else low


def _module_path(file: str) -> List[str]:
    """``game/tools/net.py`` -> ``["game", "tools", "net"]`` (inside an archive: its name there)."""
    inner = file.rsplit("!", 1)[-1].lower()
    return inner.rsplit(".", 1)[0].split("/")


class _Index:
    """Who fills what (``which``: ``fills`` or ``drops``), by the kind of name."""

    def __init__(self, entries: List[Entry], which: str) -> None:
        self.which = which
        self.in_store: Dict[str, List[Tuple[Entry, tuple]]] = {}
        self.modules: Dict[str, List[Entry]] = {}
        self.files: Dict[str, List[Tuple[Entry, tuple]]] = {}
        for entry in entries:
            own = False
            for name, fill in getattr(entry, which).items():
                if name.startswith("import:"):
                    continue                      # joined with the importers (join)
                if name.startswith("file:"):
                    self.files.setdefault(name[5:], []).append((entry, fill))
                elif name.startswith("store:"):
                    self.in_store.setdefault(name[6:], []).append((entry, fill))
                elif entry.store:
                    self.in_store.setdefault(name[7:], []).append((entry, fill))
                else:
                    own = True
            if own:
                self.modules.setdefault(_module_path(entry.file)[-1], []).append(entry)

    def fillers(self, name: str):
        """``(entry, fill, name as shown)`` for everything that fills ``name``."""
        if name.startswith("file:"):
            for entry, fill in self.files.get(name[5:], ()):
                yield entry, fill, name[5:]
            return
        if name.startswith("store:"):
            inner = name[6:]
            for entry, fill in self.in_store.get(inner, ()):
                # (rb: / sh: - names all scripts of that language share: shown as they are written)
                yield entry, fill, inner[3:] if inner.startswith(("rb:", "sh:")) else \
                    inner if inner.startswith("persistent.") else "store." + inner
            return
        dotted = name[7:]
        call = dotted.endswith("()")
        parts = (dotted[:-2] if call else dotted).lower().split(".")
        for cut in range(len(parts) - 1, 0, -1):          # the longest module name first
            module, member = parts[:cut], parts[cut]
            if call and cut == len(parts) - 1:
                member += "()"
            for entry in self.modules.get(module[-1], ()):
                if _module_path(entry.file)[-len(module):] != module:
                    continue
                for own, fill in getattr(entry, self.which).items():
                    if own.startswith("global:") and own[7:].lower() == member:
                        yield entry, fill, "%s.%s" % (".".join(module), own[7:])

    def first(self, name: str, runner: Entry) -> Optional[Tuple[Entry, tuple, str]]:
        """... the first of them in another file than ``runner``."""
        for entry, fill, shown in self.fillers(name):
            # (a script and its own compiled form are one file, and one file is the
            # business of the tracer that reads it)
            if entry is not runner and _script(entry.file) != _script(runner.file):
                return entry, fill, shown
        return None


def join(entries: List[Entry], importers: Optional[Dict[str, list]] = None) -> Tuple[List[Link], bool]:
    """The chains across two of these files, and whether every file and name
    was looked at (False: a limit cut the join short). ``importers``: module
    name -> ``[(file, line, tag)]``, the scripts that import it."""
    complete = len(entries) <= MAX_FILES
    entries = sorted(entries[:MAX_FILES], key=lambda e: e.file)
    deadline = time.monotonic() + MAX_SECONDS
    fills, drops = _Index(entries, "fills"), _Index(entries, "drops")
    links: List[Link] = []
    for runner in entries:
        made = 0
        started = set()                 # one call that starts a file is one chain, however it is tied
        todo = [(name, run, fills) for name, run in runner.runs.items()]
        todo += [(name, start, drops) for name, start in runner.starts.items()]
        for name, run, index in todo:
            if time.monotonic() > deadline or len(links) >= MAX_LINKS:
                return links, False
            if made >= _MAX_PER_FILE:
                complete = False
                break
            found = index.first(name, runner)
            if found is None:
                continue
            entry, fill, shown = found
            if index is fills:
                links.append(Link(entry, runner, shown, fill, run))
            elif (entry.file, run[1]) in started:
                continue
            else:
                started.add((entry.file, run[1]))
                links.append(Link(entry, runner, shown, fill[:4], ("dropper", run[0], run[1], fill[4]),
                                  FILE if name.startswith("file:") else PATH))
            made += 1
    for filler in entries if importers else ():
        for name, drop in filler.drops.items():
            if not name.startswith("import:"):
                continue
            made = 0
            for file, line, tag in importers.get(name[7:], ()):
                if time.monotonic() > deadline or len(links) >= MAX_LINKS:
                    return links, False
                if _script(file) == _script(filler.file):
                    continue
                if made >= _MAX_PER_FILE:
                    complete = False
                    break
                links.append(Link(filler, Entry(file, False, {}, {}, tag), name[7:], drop[:4],
                                  ("dropper", "import " + name[7:], line, drop[4]), MODULE))
                made += 1
    return links, complete