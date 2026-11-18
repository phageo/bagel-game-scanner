"""What the members of a Windows Installer package add up to (phageo, 2026-10-31).

**Mechanism A, ``CHAIN-MSI-LOAD`` (HIGH).** Every link must be there, each read from the package
itself: the package is not signed; a sequence table starts one of its own programs by itself
(``msi.Contents.auto_started``: no dialog, no user asks for it); that program's import table names a
library of the package; the library has no signature block, has no name of a Windows file
(``sideload.kind_of``) and is no file of an official table; its texts name another member; and that
member is unread (no reader understood it) and near-random - at least ``MIN_ENTROPY`` bits per byte
over at most its first ``ENTROPY_BYTES``. Together: a program the package starts by itself leads to
a part of the package nobody could read.

``ON = False`` switches A off, and nothing else (phageo: if A changes a verdict in a clean set it is
switched off and reported).

**Mechanism B, ``MSI-PROG-001`` (MEDIUM).** A member with a program's ending that holds no program
(no Windows, Linux or macOS program header). Empty members are left out: they hold nothing to hide.
A note in every package, signed or not, and also a way a member counts as "unread" for A.

Only names, tables and a bounded part of each member are read, and nothing is run. Limits:
``MAX_PROGRAM`` per program or library, ``MAX_KEPT`` characters of library texts per package; what
goes over them is said (``limits.hit``), and that member takes no part in A.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Tuple

from . import entropy, official, pe, sideload
from .models import Category, FileContext, Finding, Severity
from .unpack import limits, spool

ON = True                       # mechanism A (phageo, 2026-10-31)
RULE_A = "CHAIN-MSI-LOAD"
RULE_B = "MSI-PROG-001"
MIN_ENTROPY = 7.8               # bits per byte
ENTROPY_BYTES = 4 << 20         # at most this much of a member is measured
MIN_SIZE = 4096                 # a shorter member can hardly reach MIN_ENTROPY: nothing to measure
MAX_PROGRAM = 64 << 20          # a program or library read for its imports and texts
MAX_KEPT = 64 << 20             # characters of library texts kept per package
MAX_NOTES = 8                   # MSI-PROG-001 findings per package

TITLE_A = "Unsigned installer starts its own program, which leads to an unreadable part"
REASON_A = (
    "This Windows Installer package has no valid signature. Its own tables start one of its programs "
    "by themselves during installation; that program loads a library of the package which has no "
    "signature either; and the library names a file of the package that looks like random data and "
    "that no reader could understand. Malware is built this way: an ordinary-looking program, a small "
    "library, and the real code kept encrypted in a file with a harmless name. Each part alone is "
    "ordinary - it is the whole chain that counts, and what the unreadable part does cannot be seen.")
TITLE_B = "File named like a program holds no program"
REASON_B = (
    "The name of this member of the package ends like a program or library, but what it holds is "
    "no program for any system the scanner knows. A file is sometimes named this way to look ordinary "
    "while it carries other data; what it really holds was not read.")

# endings of programs and libraries (.com is left out: such a program has no header at all)
PROGRAM_ENDINGS = (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".pyd", ".node", ".so", ".dylib")
_HEADERS = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe")


def _leaf(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _first(data, count: int) -> bytes:
    """At most the first ``count`` bytes of a member, wherever it is kept."""
    if isinstance(data, spool.Blob) and data.path is not None:
        with open(data.path, "rb") as fh:
            return fh.read(count)
    return spool.head_of(data)[:count]


def not_a_program(name: str, data) -> bool:
    """Mechanism B: a program's ending, something in it, and no program's header."""
    return (_leaf(name).endswith(PROGRAM_ENDINGS) and spool.size_of(data) > 0
            and not _first(data, 8).startswith(_HEADERS))


class Watch:
    """The facts mechanism A and B need, gathered while the package's members go by.

    ``started``: the members the package starts by itself, when A looks at this package at all
    (empty: the package is signed, starts nothing, or A is off - then only B is watched)."""

    def __init__(self, started: Iterable[str] = ()) -> None:
        self.started = {name.lower() for name in started} if ON else set()
        self.imports: Dict[str, List[str]] = {}          # started program -> libraries it imports
        self.libraries: Dict[str, str] = {}              # library's leaf -> its texts, in small letters
        self.hidden: Dict[str, Tuple[str, float]] = {}   # leaf of an unread near-random member -> name, bits
        self.notes: List[str] = []                       # members of mechanism B
        self.kept = 0

    def note(self, name: str, data, unread: bool) -> None:
        """One member. ``unread``: the container's policy left it out as "not clearly harmless"."""
        empty = not_a_program(name, data)
        if empty:
            self.notes.append(name)
        if not self.started:
            return
        if (unread or empty) and spool.size_of(data) >= MIN_SIZE:
            bits = entropy.shannon(_first(data, ENTROPY_BYTES))
            if bits >= MIN_ENTROPY:
                self.hidden.setdefault(_leaf(name), (name, bits))
        elif not unread and not empty and _first(data, 2) == b"MZ":
            self._program(name, data)

    def _program(self, name: str, data) -> None:
        size = spool.size_of(data)
        if size > MAX_PROGRAM:
            limits.hit("msi", "a program of %d bytes was not read for the package's chain of programs" % size)
            return
        raw = data.read() if isinstance(data, spool.Blob) else bytes(data)
        info = pe.parse_pe(raw)
        if info is None:
            return
        if name.lower() in self.started:
            self.imports[name] = [library.lower() for library in info.imports]
        leaf = _leaf(name)
        sha = data.sha256 if isinstance(data, spool.Blob) else hashlib.sha256(raw).hexdigest()
        if not info.has_signature and not sideload.kind_of(leaf) and not official.exact(sha):
            text = "\n".join(pe.extract_strings(raw, 4)).lower()
            if self.kept + len(text) > MAX_KEPT:
                limits.hit("msi", "the texts of more libraries than %d MB: the rest took no part in the "
                                  "package's chain of programs" % (MAX_KEPT >> 20))
                return
            self.kept += len(text)
            self.libraries[leaf] = text

    def chain(self) -> Optional[Tuple[str, str, str, float]]:
        """``(program, library, unread member, bits)`` of the first whole chain (None: no chain).
        The members may come in any order: this looks only when all of them went by."""
        for program in sorted(self.imports):
            for library in self.imports[program]:
                text = self.libraries.get(library)
                if text is None:
                    continue
                for leaf in sorted(self.hidden):
                    if leaf != library and leaf in text:
                        name, bits = self.hidden[leaf]
                        return program, library, name, bits
        return None


def findings(watch: Watch, ctx: FileContext, make) -> List[Finding]:
    """The findings of a package once its members went by. ``make``: ``BaseHandler.make``."""
    out: List[Finding] = []
    chain = watch.chain()
    if chain is not None:
        out.append(make(ctx, RULE_A, TITLE_A, Category.CHAIN, Severity.HIGH, REASON_A,
                        "%s starts by itself -> imports %s -> names %s (%.2f bits per byte)" % chain, 0.8))
    for name in watch.notes[:MAX_NOTES]:
        note = make(ctx, RULE_B, TITLE_B, Category.EVASION, Severity.MEDIUM, REASON_B, name, 0.5)
        note.chainable = False
        out.append(note)
    return out
