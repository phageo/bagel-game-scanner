"""Text that no other handler takes: read by what it is, not by how it is named.

The scanner routes files by their ending. A game of an engine it does not know
keeps its scripts under endings it has never heard of (``.tjs``, ``.ks``,
``.lua``, ``.gd`` ...), and until 2026-10-12 none of them was opened at all.
This handler is asked last, by the scanner itself (it claims no ending): when a
file that no reader takes is text, it is read -

* with the language-neutral rules (the ones that read the texts of a program:
  command lines of system tools, known bad addresses ...) - a plain address by
  itself is left out, licence files and read-me texts are full of them;
* and, when its content looks like a script of a kind the scanner does read
  (:mod:`gamescan.unpack.sniff`: batch, PowerShell, VBScript, JavaScript), as
  that script: it is handed on as a member ``<file>!content<.ending>`` and the
  reader of that kind takes it, with everything that reader does.

Nothing is run. A file that is not text is left to the coverage figure of the
scan (``SCAN-COVERAGE-001``).
"""
from __future__ import annotations

import hashlib
import os
from typing import Iterable, List

from .. import localdrop, trust
from ..models import FileContext, Finding
from ..rules import RuleEngine
from ..unpack import sniff
from .base import BaseHandler

MAX_TEXT = 8 * 1024 * 1024              # a larger file is not taken (it is counted as unread)
_SAMPLE = 65536
_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\r\n"
_SCRIPTS = frozenset({".bat", ".ps1", ".vbs", ".js"})
_LEFT_OUT = frozenset({"URL-001"})      # an address by itself, in a text file
# what an MSI member is handed (UnreadFormatHandler.expand; read in Scanner._scan_one)
PACKAGE_SIGNER = "package_signer"       # who validly signed the package or cabinet it came from
OWN_STARTS = "msi_own_starts"           # (the package's signer, lines that start its own files, lines)


def is_text(data: bytes) -> bool:
    """Is ``data`` text - nearly all printable ASCII, or UTF-8 / UTF-16 with a
    mark, without control characters?"""
    sample = data[:_SAMPLE]
    if not sample:
        return False
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = sample[2:len(sample) & ~1].decode("utf-16-le" if sample[:2] == b"\xff\xfe" else "utf-16-be")
        except UnicodeDecodeError:
            return False
    elif b"\0" in sample:
        return False
    elif len(sample.translate(None, _PRINTABLE)) * 20 <= len(sample):
        return True
    else:
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.start < len(sample) - 4:         # (not just a character cut at the end)
                return False
            text = sample[:exc.start].decode("utf-8", "replace")
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\r\n")
    return bool(text) and control * 50 <= len(text)


def not_script(ctx: FileContext) -> bool:
    """Text that describes code and is not run (phageo, 2026-10-12): a TypeScript
    declaration file (``.d.ts`` - types only, no instructions) and a source map
    (``.map`` - a table from packed code back to its sources). Read as script
    they are full of words that mean nothing there ("keylog" is an option of
    TLS, "powershell" a language a code editor colours). They are not read by
    the rules and form no chain; they count as read.

    A source map is taken for one only if it *is* one - JSON with the fields
    of a source map; anything else under that ending is text like any other.
    A declaration file goes by its name: see the limit in the README."""
    name = ctx.name.lower()
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return True
    if name.endswith(".map"):
        head = ctx.data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
        return head.startswith(b"{") and b'"mappings"' in ctx.data and b'"version"' in ctx.data[:65536] \
            or (head.startswith(b"{") and b'"sources"' in head and b'"version"' in head)
    return False


class TextHandler(BaseHandler):
    name = "text"
    engine = ""

    def can_handle(self, ctx: FileContext) -> bool:
        return False                    # asked by the scanner, after every other handler

    def takes(self, ctx: FileContext) -> bool:
        return not ctx.truncated and 0 < len(ctx.data) <= MAX_TEXT and not ctx.is_pe and is_text(ctx.data)

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if not_script(ctx):
            return []
        found = rules.scan(ctx.text(), "strings", ctx, self.name)
        return [f for f in found if f.rule_id not in _LEFT_OUT]

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        if not_script(ctx):
            return
        ending = sniff.extension(ctx.data)
        if ending in _SCRIPTS:
            yield FileContext(path=ctx.path, relpath="%s!content%s" % (ctx.relpath, ending), data=ctx.data,
                              size=len(ctx.data), sha256=hashlib.sha256(ctx.data).hexdigest())


# -- programs of a kind the scanner has no reader for ------------------------------------------
UNREAD_PROGRAM = "EXEC-FMT-001"
_JAVA = b"\xca\xfe\xba\xbe"


def java_class(data: bytes) -> bool:
    """A Java class file by its first bytes. (A program for several kinds of Mac begins with
    the same four bytes; there the next number is small - a count -, here it is the version
    of the class format, 45 or more.)"""
    return data[:4] == _JAVA and len(data) >= 8 and 45 <= int.from_bytes(data[6:8], "big") <= 99


class UnreadProgramHandler(BaseHandler):
    """A program for a runtime the scanner cannot read - today: Java class files. It is not
    read, and that is said (CLAUDE.md, rule 15): a note that is never hidden, and a scan
    with such a file is never CLEAN (phageo, 2026-10-12)."""

    name = "unread-program"
    engine = ""
    extensions = frozenset({".class"})
    magics = (_JAVA,)

    def can_handle(self, ctx: FileContext) -> bool:
        return ctx.ext in self.extensions or java_class(ctx.data)

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        from ..models import Category, Severity
        note = self.make(
            ctx, UNREAD_PROGRAM, "Program of a kind the scanner does not read", Category.EVASION, Severity.LOW,
            "This file is a program for a runtime the scanner has no reader for (a Java class file: "
            "instructions for the Java runtime). It was not read, so what it does was not inspected.",
            "%s: %s, %d bytes - not read" % (ctx.name, "Java class file" if java_class(ctx.data) else
                                             "named like a Java class file", ctx.size), 0.3)
        note.chainable = False
        return [note]


# -- files of a format the scanner has no reader for ------------------------------------------
class UnreadFormatHandler(BaseHandler):
    """A Windows Installer package, a disk image, a single compressed file ...
    (``sniff.unread_kind``): no reader takes it, and until 2026-10-17 it came out with no
    finding and no note - a malicious MSI package was CLEAN. It gets the "could not be read"
    note now (``ARC-002``, never hidden; phageo, 2026-10-17, fifty-eighth message), so a scan
    holding one is at least REVIEW and the launcher asks. Inside an archive the archive says
    it (``containers.Policy``)."""

    name = "unread-format"
    engine = ""
    extensions = frozenset(sniff.UNREAD_ENDINGS)
    # (by its first bytes it is taken in Scanner._load, which looks at sniff.UNREAD_HEAD of them)

    def can_handle(self, ctx: FileContext) -> bool:
        return not ctx.is_pe and bool(sniff.unread_kind(ctx.data, ctx.ext))

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        kind = sniff.unread_kind(ctx.data, ctx.ext)
        said = "the scanner has no reader for this format, so its content was not inspected"
        if kind.startswith("Windows Installer"):
            said = self._installer(ctx)
            if not said:                          # read: what it carries is scanned through expand()
                return []
        return [self._note(ctx, kind, said)]

    def _note(self, ctx: FileContext, kind: str, said: str) -> Finding:
        from ..models import NOT_INSPECTED, Category, Severity
        note = self.make(
            ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION, Severity.LOW, NOT_INSPECTED,
            "%s: a %s, %d bytes - %s" % (ctx.name, kind, ctx.size, said), 0.3)
        note.chainable = False
        return note

    @staticmethod
    def _source(ctx: FileContext):
        """The whole package: its bytes, or (a large file only partly loaded) the file on disk."""
        from ..unpack import msi
        if ctx.truncated:
            if not ctx.on_disk:
                raise msi.MsiError("only the beginning of it was loaded")
            return open(ctx.path, "rb")
        return None

    @classmethod
    def _installer(cls, ctx: FileContext) -> str:
        """Read the database of a Windows Installer package (``unpack/msi.py``; phageo,
        2026-10-17: part 1 of 2) - what it holds goes to ``ctx.cache["msi_inventory"]``
        (names and sizes; the positive runner's inventory prints it). "" when it was read: a
        package's cabinets, ``Binary`` streams, custom actions and command lines are handed on
        by :meth:`expand` (part 2, 2026-10-19) and what of them could not be read is said by
        :meth:`after_expand`. A transform or a patch changes another package: what it changes
        is not read, and the note says so."""
        from ..unpack import limits, msi
        source = None
        with limits.watch() as reached:
            try:
                source = cls._source(ctx)
                package = msi.package(source if source is not None else ctx.data, ctx.size if source else None)
            except (msi.MsiError, OSError) as exc:
                package, failed = None, str(exc)
            finally:
                if source is not None:
                    source.close()
        for reader, what in reached:            # (said for the file as well, as every limit is)
            limits.hit(reader, what)
        cut = "; a limit of the reader was reached: %s" % "; ".join(what for _r, what in reached) if reached else ""
        if package is None:
            ctx.cache["msi_inventory"] = ["could not be read: %s" % failed]
            return "its database could not be read (%s)%s, so its content was not inspected" % (failed, cut)
        ctx.cache["msi_inventory"] = msi.inventory(package) + (["could not be read: " + cut[2:]] if cut else [])
        if package.kind in (msi.TRANSFORM, "Windows Installer patch"):
            ctx.cache["msi_read"] = True          # (its other streams are still handed on)
            return ("its database was read (%s)%s; it changes another package, and what it changes was not "
                    "inspected" % (msi.summary(package), cut))
        ctx.cache["msi_read"] = True
        if package.problem or cut:
            return ("its database was read (%s)%s%s; what it carries was handed on to be scanned" % (
                msi.summary(package), "; part of it could not be read (%s)" % package.problem if package.problem
                else "", cut))
        return ""

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        """What a Windows Installer package carries (``msi.Contents``; phageo, 2026-10-19, part 2
        of 2): the files of its cabinets under the names it installs them as, its ``Binary``
        programs and scripts, the scripts and command lines of its custom actions - each a
        member, scanned like a member of an archive; every one held in memory. A cabinet that
        lies beside the package is read when the package is a file of the scanned folder."""
        if not ctx.cache.get("msi_read"):
            return
        from ..unpack import msi, spool
        from . import containers, engine_files
        policy = containers.Policy()
        problems: List[str] = ctx.cache.setdefault("msi_problems", [])
        source = None
        try:
            source = self._source(ctx)
            db = msi.Database(source if source is not None else ctx.data, ctx.size if source else None)
            contents = msi.Contents(db, self._beside(ctx) if "!" not in ctx.relpath and ctx.on_disk else None)
            # the package's own signature (Windows' check, as for a program): the files of its
            # embedded cabinets share it, as the members of a signed installer do; a cabinet
            # beside it is judged by its own (phageo, 2026-10-19)
            signer = engine_files.package_signer(ctx) if msi.SIGNATURE in db.streams else None
            beside: dict = {}
            for name, data in contents.members(policy.want):
                if ctx.cancelled:
                    break
                if policy.settle(name, data):
                    member = containers.child(ctx, name, data)
                    where, path = contents.origin
                    shared = signer if where == msi.EMBEDDED else None
                    if where == msi.BESIDE and path:
                        if path not in beside:
                            beside[path] = trust.signer_name(path)
                        shared = beside[path]
                    if shared:
                        member.cache[PACKAGE_SIGNER] = shared
                    if name == msi.COMMANDS:
                        # the command lines that start a file of the package and fetch or decode
                        # nothing (Scanner._scan_one: MEDIUM in a package whose signature is trusted)
                        member.cache[OWN_STARTS] = (signer, contents.own_lines,
                                                    data.count(b"\n") + 1)
                    yield member
                elif isinstance(data, spool.Blob):
                    data.release()
                else:
                    # not scanned - but perhaps the file a script decodes (CHAIN-LOCAL-DROP)
                    localdrop.offer("%s!%s" % (ctx.relpath, name), data)
            problems.extend(contents.problems)
            ctx.cache.setdefault("msi_inventory", []).extend(contents.read)
        except (msi.MsiError, OSError) as exc:
            problems.append("what it carries could not be read (%s)" % exc)
        finally:
            if source is not None:
                source.close()
        problems.extend(policy.problems())

    @staticmethod
    def _beside(ctx: FileContext):
        """Opens a cabinet that lies in the package's own folder (the name as the package
        writes it, matched without regard to case) - None when there is none."""
        folder = os.path.dirname(ctx.path)

        def opener(name: str):
            leaf = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
            try:
                for entry in os.listdir(folder)[:20000]:
                    if entry.lower() == leaf and os.path.isfile(os.path.join(folder, entry)):
                        return open(os.path.join(folder, entry), "rb")
            except OSError:
                return None
            return None
        return opener

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        """The "could not be read" notes of a package: a cabinet compressed with LZX or
        Quantum, one that is missing, a member over the memory limit, a storage inside it ..."""
        problems = ctx.cache.pop("msi_problems", [])
        return [self._note(ctx, "Windows Installer package", problem[:300]) for problem in
                list(dict.fromkeys(problems))[:8]]
