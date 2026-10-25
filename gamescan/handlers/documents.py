"""Archives and Office documents: ZIP-family containers, cabinets, 7z, RAR and VBA macros."""
from __future__ import annotations

import io
import re
import zipfile
from typing import Iterable, List

from .. import localdrop
from ..models import Category, FileContext, Finding, Severity
from ..pe import extract_strings
from ..rules import RuleEngine
from ..unpack import cab, rar, sevenzip, sniff, spool
from . import containers
from .base import BaseHandler
from .containers import ARCHIVE_EXTS, MEMBER_EXTS, OLE_EXTS, ZIP_EXTS, Policy, ext_of

_AUTO_EXEC = re.compile(r"Auto_?Open|AutoExec|Auto_?Close|Document_Open|Workbook_Open"
                        r"|Document_Close|Workbook_Activate", re.I)
_MACRO_ACTION = re.compile(r"\bShell\b|CreateObject|URLDownloadToFile|powershell|WScript\.Shell"
                           r"|MSXML2|ADODB\.Stream|\bEnviron\b|cmd(?:\.exe)? /c", re.I)
_MAX_MEMBER = containers.MAX_MEMBER   # (tests lower it)
# ARC-ENC-EXEC-001 (phageo, 2026-10-15, fiftieth message): a password zip whose own list of entries -
# readable although the members are encrypted - names a program or a script. By the ending only.
ENCRYPTED_PROGRAMS = frozenset({".exe", ".dll", ".scr", ".com", ".msi", ".node", ".sys", ".cpl", ".ocx", ".pif",
                                ".jar"})
ENCRYPTED_SCRIPTS = frozenset({".js", ".jse", ".mjs", ".cjs", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1",
                               ".bat", ".cmd", ".py", ".pyw", ".pyc", ".pyo", ".rpy", ".rpyc", ".rb", ".lnk",
                               ".html", ".htm"})
# ... or an archive (phageo, 2026-10-15, fifty-first message: it hides its content twice). A password zip
# of pictures, sound or documents only (bonus content of a visual novel) stays ARC-001 alone - REVIEW.
ENCRYPTED_ARCHIVES = frozenset({".zip", ".7z", ".rar", ".asar", ".rpa", ".cab", ".gz", ".tgz", ".bz2", ".xz",
                                ".tar", ".iso", ".img", ".rgssad", ".rgss2a", ".rgss3a"})
ENCRYPTED_RUNNABLE = "ARC-ENC-EXEC-001"


def _ending(name: str) -> str:
    leaf = name.replace("\\", "/").rsplit("/", 1)[-1]
    return leaf[leaf.rfind("."):].lower() if "." in leaf else ""


class DocumentHandler(BaseHandler):
    name = "archive"
    engine = "Archive / document"
    extensions = ZIP_EXTS | OLE_EXTS | ARCHIVE_EXTS
    magics = (b"PK\x03\x04", b"\xd0\xcf\x11\xe0", cab.MAGIC, sevenzip.MAGIC[:4], rar.MAGIC[:4],
              b"idsk")

    def can_handle(self, ctx: FileContext) -> bool:
        return (ctx.ext in self.extensions or ctx.data[:4] in self.magics) and not ctx.is_pe

    def _open(self, ctx: FileContext):
        if ctx.data[:2] != b"PK":
            return None
        try:
            return zipfile.ZipFile(ctx.path if ctx.truncated else io.BytesIO(ctx.data))
        except (zipfile.BadZipFile, OSError, ValueError):
            return None

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        out: List[Finding] = []
        macro_text = None
        if containers.detect(ctx):
            # members are scanned through expand(); Inno Setup data is read here
            return containers.scan_inno(self, ctx, rules)
        archive = self._open(ctx)
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
                    programs = sum(_ending(i.filename) in ENCRYPTED_PROGRAMS for i in files)
                    scripts = sum(_ending(i.filename) in ENCRYPTED_SCRIPTS for i in files)
                    archives = sum(_ending(i.filename) in ENCRYPTED_ARCHIVES for i in files)
                    if programs or scripts or archives:
                        out.append(self.make(
                            ctx, ENCRYPTED_RUNNABLE, "Password-protected archive holding programs, scripts "
                            "or archives", Category.EVASION, Severity.HIGH,
                            "The archive is encrypted, so its contents cannot be inspected - and its list of "
                            "entries, which stays readable, names programs, scripts or further archives. "
                            "Malware is delivered this way so that scanners cannot look at what will run.",
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
            infos = [i for i in archive.infolist() if not i.is_dir() and not i.flag_bits & 1]
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
                known = ext_of(name) in MEMBER_EXTS or ext_of(name) in sniff.UNREAD_ENDINGS
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
                except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
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
                yield containers.child(ctx, name, data)
        ctx.cache.setdefault("container_notes", []).extend(policy.problems())

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        return containers.findings(self, ctx)
