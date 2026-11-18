"""Archives and Office documents: ZIP-family containers, cabinets, 7z, RAR and VBA macros."""
from __future__ import annotations

import io
import re
import zipfile
from typing import Iterable, List, Optional

from .. import localdrop
from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..pe import extract_strings
from ..rules import RuleEngine
from ..unpack import cab, limits, rar, sevenzip, sniff, spool
from . import containers
from .base import BaseHandler
from .containers import (ARCHIVE_EXTS, ENCRYPTED_ARCHIVES, ENCRYPTED_PROGRAMS, ENCRYPTED_RUNNABLE,  # noqa: F401
                         ENCRYPTED_RUNNABLE_REASON, ENCRYPTED_RUNNABLE_TITLE, ENCRYPTED_SCRIPTS, MEMBER_EXTS,
                         OLE_EXTS, ZIP_EXTS, Policy, ext_of, runnable_counts)

_AUTO_EXEC = re.compile(r"Auto_?Open|AutoExec|Auto_?Close|Document_Open|Workbook_Open"
                        r"|Document_Close|Workbook_Activate", re.I)
_MACRO_ACTION = re.compile(r"\bShell\b|CreateObject|URLDownloadToFile|powershell|WScript\.Shell"
                           r"|MSXML2|ADODB\.Stream|\bEnviron\b|cmd(?:\.exe)? /c", re.I)
_MAX_MEMBER = containers.MAX_MEMBER   # (tests lower it)
# ARC-ENC-EXEC-001 (phageo, 2026-10-15, fiftieth / fifty-first message): a password zip whose own list of
# entries - readable although the members are encrypted - names a program, a script or an archive. By the
# ending only. The lists live in containers.py since 2026-11-09 (C4 gives the same rule for 7z / RAR).
# (phase D, session R2b-1, S02 - phageo 2026-11-17; a silent escape) a file named or marked as an archive that cannot
# be opened as one - a zip whose list of members is damaged, cut off or in another part, a ".zip" that does not begin
# like one, a ".cab" that is no Microsoft cabinet, a ".7z" / ".rar" without its mark at the start, a password-protected
# Office file under a zip ending - gets ARC-002 (at least REVIEW); so do bytes that stand in front of the first member
# a zip's own list names (two zips written one after the other: another unpacker may read the first). Notes only:
# nothing more is opened or read (phageo's principle for the session). Off: nothing is said, as before.
UNOPENED_ARCHIVE_NOTE = True
_ARCHIVE_MARKS = (b"PK\x03\x04", cab.MAGIC, sevenzip.MAGIC[:4], rar.MAGIC[:4], b"idsk")
NOT_AN_ARCHIVE = "it does not begin like an archive of its kind"


class DocumentHandler(BaseHandler):
    name = "archive"
    engine = "Archive / document"
    extensions = ZIP_EXTS | OLE_EXTS | ARCHIVE_EXTS
    magics = (b"PK\x03\x04", b"\xd0\xcf\x11\xe0", cab.MAGIC, sevenzip.MAGIC[:4], rar.MAGIC[:4],
              b"idsk")

    def can_handle(self, ctx: FileContext) -> bool:
        return (ctx.ext in self.extensions or ctx.data[:4] in self.magics) and not ctx.is_pe

    def _open(self, ctx: FileContext, problem: Optional[List[str]] = None):
        """The zip, or None - then ``problem`` (when given) gets why, as a type name or a fixed text (S02)."""
        if ctx.data[:2] != b"PK":
            if problem is not None:
                problem.append(NOT_AN_ARCHIVE)
            return None
        try:
            return zipfile.ZipFile(ctx.path if ctx.truncated else io.BytesIO(ctx.data))
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            if problem is not None:
                problem.append(type(exc).__name__)
            return None

    def _unopened(self, ctx: FileContext, problem: List[str]) -> List[Finding]:
        """(S02) ``ARC-002`` for a file named or marked as an archive that could not be opened as one. Not for an
        empty file, nor for an Office file of the old kind under its own ending (no archive: its macros are read)."""
        if not UNOPENED_ARCHIVE_NOTE or ctx.size <= 0 or not (
                ctx.ext in ZIP_EXTS or ctx.ext in ARCHIVE_EXTS or bytes(ctx.data[:8]).startswith(_ARCHIVE_MARKS)):
            return []
        note = self.make(
            ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION, Severity.LOW, NOT_INSPECTED,
            "%s: named or marked as an archive, but it could not be opened as one (%s) - its content was not "
            "inspected" % (ctx.name, (problem or [NOT_AN_ARCHIVE])[0]), 0.3)
        note.chainable = False
        return [limits.mark(note)]

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        out: List[Finding] = []
        macro_text = None
        if containers.detect(ctx):
            # members are scanned through expand(); Inno Setup data is read here
            return containers.scan_inno(self, ctx, rules)
        problem: List[str] = []
        archive = self._open(ctx, problem)
        if archive is None:
            out += self._unopened(ctx, problem)
        if archive is not None:
            with archive:
                infos = archive.infolist()
                if any(i.flag_bits & 1 for i in infos):
                    out.append(self.make(
                        ctx, "ARC-001", "Password-protected archive", Category.EVASION,
                        Severity.LOW, "The archive is encrypted, so its contents cannot be "
                        "inspected. Malware is often delivered this way to get past scanners.",
                        "%d encrypted member(s)" % sum(i.flag_bits & 1 for i in infos), 0.4))
                    files = [i for i in infos if not i.is_dir()]
                    programs, scripts, archives = runnable_counts(i.filename for i in files)
                    if programs or scripts or archives:
                        out.append(self.make(
                            ctx, ENCRYPTED_RUNNABLE, ENCRYPTED_RUNNABLE_TITLE, Category.EVASION, Severity.HIGH,
                            ENCRYPTED_RUNNABLE_REASON,
                            "%d program(s), %d script(s), %d archive(s) among %d entries"
                            % (programs, scripts, archives, len(files)), 0.6))
                for info in infos:
                    if info.filename.lower().endswith("vbaproject.bin") and \
                            info.file_size <= _MAX_MEMBER and not info.flag_bits & 1:
                        try:
                            macro_text = "\n".join(extract_strings(archive.read(info), 4))
                        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                            macro_text = ""
        elif ctx.data[:4] == b"\xd0\xcf\x11\xe0" and (
                b"_VBA_PROJECT" in ctx.data or "_VBA_PROJECT".encode("utf-16-le") in ctx.data):
            macro_text = "\n".join(extract_strings(ctx.data, 4))
        if macro_text is not None:
            auto, action = _AUTO_EXEC.search(macro_text), _MACRO_ACTION.search(macro_text)
            if auto and action:
                out.append(self.make(
                    ctx, "DOC-002", "Office macro that runs automatically and launches code",
                    Category.EXECUTION, Severity.HIGH, "The document contains a macro that "
                    "starts by itself when opened and can run programs or download files.",
                    "%s + %s" % (auto.group(0), action.group(0)), 0.75))
            else:
                out.append(self.make(
                    ctx, "DOC-001", "Office document contains macros", Category.EXECUTION,
                    Severity.MEDIUM, "Macros are programs inside a document. Most documents "
                    "do not need them, and they are a common way to deliver malware.",
                    "VBA project present", 0.5))
            out += rules.scan(macro_text, "strings", ctx, self.name, numbered=False)
        return out

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        if containers.detect(ctx):
            yield from containers.expand(ctx)
            return
        archive = self._open(ctx)
        if archive is None:
            return
        policy = Policy()
        with archive:
            listed = archive.infolist()
            front = min((i.header_offset for i in listed), default=0) if UNOPENED_ARCHIVE_NOTE else 0
            if front == 4 and bytes(ctx.data[:4]) in (b"PK00", b"PK\x07\x08"):
                front = 0                       # (the mark a one-part "split" zip begins with: no content)
            if front > 0:
                # (S02) said before the first member is handed out: the scanner may let this reading go early
                ctx.cache.setdefault("container_notes", []).append(limits.said(
                    "%d byte(s) stand in front of the first member the zip's own list names: they were not "
                    "inspected" % front))
            infos = [i for i in listed if not i.is_dir() and not i.flag_bits & 1]
            slices = containers.ZipSlices(archive, infos)      # (B3) an Inno installer's setup-N.bin beside it
            total = sum(i.compress_size for i in infos) or 1
            done = 0
            for info in infos:
                if ctx.cancelled:
                    break
                done += info.compress_size
                ctx.tick(done / total)
                name = info.filename
                if ext_of(name) in containers.UNREAD_PROGRAMS:
                    policy.unread_programs.append(name)         # (said in the archive's note)
                    continue
                if policy.unread_format(name, info.file_size):  # (... so is a format nobody reads)
                    continue
                known = containers.member_ext(ext_of(name)) or ext_of(name) in sniff.UNREAD_ENDINGS
                limit = min(policy.limit(name), _MAX_MEMBER)
                if info.file_size > limit:
                    policy.skipped.append(name)             # (also without a telling ending, since 2026-10-23)
                    continue
                try:
                    with archive.open(info) as member:
                        head = member.read(16)

                        def pieces(member=member, head=head, left=limit + 1):
                            yield head                      # zip-bomb guard: never more than
                            while left > 0:                 # the member claims, plus one byte
                                piece = member.read(min(left, 1 << 20))
                                if not piece:
                                    return
                                left -= len(piece)
                                yield piece
                        data = spool.collect(pieces())
                except spool.SpoolError as exc:
                    policy.skipped.append("%s (%s)" % (name, exc))
                    continue
                except MemoryError:
                    raise
                except Exception as exc:                    # (S01) said; the members after it are read
                    if not policy.member_failed(name, exc):
                        raise
                    continue
                if spool.size_of(data) > limit:
                    if isinstance(data, spool.Blob):
                        data.release()
                    policy.skipped.append(name)
                    continue
                if not known and not policy.settle(name, data):
                    if isinstance(data, spool.Blob):
                        data.release()
                    elif localdrop.wanted(name, len(data)):
                        # not scanned - but perhaps the file a script of the game decodes
                        # (CHAIN-LOCAL-DROP: kept in memory, bounded, for Scanner._join_local)
                        localdrop.offer("%s!%s" % (ctx.relpath, name), data[:localdrop.MAX_KEPT_FILE + 1])
                    continue
                member = containers.child(ctx, name, data)
                beside = slices.opener(name)
                if beside is not None:
                    member.cache[containers.SLICES] = beside   # (read while this zip is open: the member is
                yield member                                   #  scanned before the next one is taken)
        ctx.cache.setdefault("container_notes", []).extend(policy.problems())

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        return containers.findings(self, ctx)
