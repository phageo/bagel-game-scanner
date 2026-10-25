"""One signal for every limit of the format readers (phageo, 2026-10-12).

Every reader in this package has limits - how many entries it walks, how large
a table or a member may be, how deep it nests. Some stop the reader with its
own error, some cut a list short and go on. Before this module nothing made
sure that a limit which was reached also reached the user: each reader's
callers had to remember it, one by one.

Now every limit says so in the same way, at the place where it is applied::

    if count > _MAX_FILES:
        raise SevenZipError(limits.hit("7z", "more than %d files" % _MAX_FILES))
    ...
    for entry in entries[:_MAX_KEPT]:           # cut short and go on
        ...
    if len(entries) > _MAX_KEPT:
        limits.hit("nsis", "more than %d instructions: the rest was not read" % _MAX_KEPT)

:func:`hit` records the limit for the file that is being scanned and gives the
text back (for the reader's own error). The scanner opens a :func:`watch`
around each file; when the file is done, every recorded limit for which the
file has no "not read" note yet becomes one (``Scanner._limit_notes`` - the
note of the reader's family, see ``RULES``). So a reached limit cannot be
silent, whatever the reader's caller does with the error.

:func:`quiet` is for a caller that only *asks* whether some bytes are of a
format (a probe that is allowed to fail): what the reader says while probing
is not about the file.

A test (``FormatReaderLimitTests``) holds the list of limits: every limit
constant of this package is either named at a :func:`hit`, or listed with the
reason why reaching it loses nothing.

This module imports nothing of the package (``lz4block`` runs as a script of
its own and does not use it; its limits are said by ``unity``).
"""
from __future__ import annotations

import contextlib
import threading
from typing import Iterator, List, Tuple

# reader -> (rule id of its "not read" note, title of that note)
RULES = {
    "cab": ("ARC-002", "Archive could not be fully inspected"),
    "rar": ("ARC-002", "Archive could not be fully inspected"),
    "7z": ("ARC-002", "Archive could not be fully inspected"),
    "nsis": ("ARC-002", "Archive could not be fully inspected"),
    "inno": ("ARC-002", "Archive could not be fully inspected"),
    "media": ("ARC-002", "Archive could not be fully inspected"),
    "asar": ("ARC-002", "Archive could not be fully inspected"),
    "cfb": ("ARC-002", "Archive could not be fully inspected"),
    "msi": ("ARC-002", "Archive could not be fully inspected"),
    "unity": ("UNITY-FMT-001", "Unity bundle could not be fully unpacked"),
    "rgss": ("RGSS-FMT-002", "Unreadable RPG Maker archive"),
    "rgss-scripts": ("RGSS-FMT-001", "Unreadable RPG Maker script table"),
    "rpyc": ("RPY-FMT-001", "Unreadable compiled script"),
    "pyo": ("PYO-FMT-001", "Unreadable compiled Python"),
    "ifps": ("INNO-CODE-001", "Installer's own instructions could not be fully read"),
    "dotnet": ("DN-META-001", "Assembly metadata could not be read"),
    "dotnet-il": ("DN-IL-001", ".NET library's code could not be fully read"),
    "il2cpp": ("IL2CPP-META-001", "IL2CPP metadata could not be read"),
    "screnc": ("ENC-SCRIPT-001", "Encoded script could not be decoded"),
}
REASON = ("The reader for this kind of file stopped at one of its limits - more entries, a larger "
          "table or deeper nesting than it reads - so part of the file was not inspected. A file "
          "whose content was not read is never reported as clean.")
MAX_KEPT = 64                       # limits remembered for one file

_state = threading.local()


def _stack() -> list:
    try:
        return _state.stack
    except AttributeError:
        _state.stack = []
        return _state.stack


def hit(reader: str, what: str) -> str:
    """The reader ``reader`` (a key of ``RULES``) stopped at, or cut something
    short at, the limit described by ``what``. Returns ``what``."""
    assert reader in RULES, reader
    stack = _stack()
    if stack and stack[-1] is not None and len(stack[-1]) < MAX_KEPT:
        if (reader, what) not in stack[-1]:
            stack[-1].append((reader, what))
    return what


@contextlib.contextmanager
def watch() -> Iterator[List[Tuple[str, str]]]:
    """The limits reached inside the block, in order: ``[(reader, what)]``."""
    seen: List[Tuple[str, str]] = []
    stack = _stack()
    stack.append(seen)
    try:
        yield seen
    finally:
        stack.pop()


@contextlib.contextmanager
def quiet() -> Iterator[None]:
    """Inside the block nothing is recorded: a probe ("is this such a file at
    all?") that may fail without that saying anything about the file."""
    stack = _stack()
    stack.append(None)
    try:
        yield
    finally:
        stack.pop()
