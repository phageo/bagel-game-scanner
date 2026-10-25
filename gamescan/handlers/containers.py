"""Archives and installers: find them, open them, hand their members on.

One place decides, for every container format the scanner knows -
cabinets, 7z, RAR, NSIS and Inno Setup installers, on their own or behind a
self-extracting program, and a zip appended to a program (how NW.js carries a
whole game: ``copy /b nw.exe+package.nw Game.exe``):

* *where* it is in a file (:func:`detect`),
* *how* it is read: by the project's own readers only - what they cannot
  decode goes to no program (no tar.exe, no 7-Zip, no Windows library; phageo,
  2026-10-20) but gives a finding that says the content was not inspected,
* *what* is worth keeping (:class:`Policy`).

Members are produced one at a time (:func:`expand`) and scanned like files
in a folder; nothing is written to disk and nothing is executed.
"""
from __future__ import annotations

import hashlib
import io
import mmap
import os
import re
import struct
import tempfile
import zipfile
from typing import Iterator, List, Optional, Tuple

from .. import localdrop
from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..pe import extract_strings
from ..unpack import cab, inno, media, nsis, rar, rgss, sevenzip, sniff, spool, unity

ZIP_EXTS = frozenset({".zip", ".jar", ".apk", ".nupkg", ".whl", ".docx", ".docm", ".dotm", ".xlsx",
                      ".xlsm", ".xlsb", ".xltm", ".pptx", ".pptm", ".ppsm"})
OLE_EXTS = frozenset({".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".msi"})
ARCHIVE_EXTS = frozenset({".cab", ".7z", ".rar"})
MEMBER_EXTS = frozenset({
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".lnk", ".py", ".rpy", ".rpyc", ".rpa", ".sh", ".cs", ".rb", ".json",
    # compiled Python, read as on disk (since 2026-10-23: until then left out of archives unread)
    ".pyc", ".pyo",
    ".rgssad", ".rgss2a", ".rgss3a", ".rxdata", ".rvdata", ".rvdata2", ".assets", ".bundle",
    ".unity3d",
    # Electron: the archive of the game's own code, compiled JavaScript, native add-ons
    ".asar", ".jsc", ".node", ".mjs", ".cjs",
    # media: read by structure (handlers/media.py)
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ogg", ".oga", ".wav", ".mp3", ".m4a",
    ".mp4", ".mov", ".avi", ".webm", ".ogv", ".mid", ".midi"}) | ZIP_EXTS | OLE_EXTS | ARCHIVE_EXTS
# programs for a runtime the scanner has no reader for. (Linux and macOS programs and
# WebAssembly are not in this list: every Ren'Py game ships the first two for its other
# platforms, an RPG Maker MZ game the third - see docs/CHANGELOG.md, thirty-second message.)
UNREAD_PROGRAMS = frozenset({".class"})
UNREAD_PROGRAMS_WHAT = "Java class files"
GAME_ARCHIVES = (".rgssad", ".rgss2a", ".rgss3a", ".rpa")   # one file holds the whole game
CONTAINER_MAGICS = (b"MZ", b"PK\x03\x04", b"RGSSAD\0", cab.MAGIC, b"UnityFS\0", sevenzip.MAGIC,
                    rar.MAGIC)
MAX_MEMBERS = 100_000                # members of one container that are looked at
# A member larger than spool.MEMORY (32 MB) is unpacked into a temporary file and
# scanned from there like a large file on disk, so these are limits on *work*,
# not on memory:
MAX_MEMBER = 8 << 30
MAX_GAME_ARCHIVE = 8 << 30
MAX_UNNAMED = 16 * 1024 * 1024       # only kept if the content turns out to be a program / container
MAX_COMPARED = MAX_UNNAMED           # a member of a format nobody reads, unpacked to be compared (Policy)
MAX_PAYLOAD = 4 << 30                # unpacked Inno Setup data that is searched
_WINDOW = 8 * 1024 * 1024
_SLICE = (b"idska32\x1a", b"idska16\x1a")   # Inno Setup data in a separate setup-N.bin file
# (no container goes to a program: what the own reader cannot decode is said. Cabinets since
# 2026-10-19, 7z since 2026-10-20, RAR and NSIS bzip2 since 2026-10-20, seventy-third message -
# phageo: "no external program may extract scanned files"; until then Windows' tar.exe or 7-Zip
# got them, and gamescan/unpack/external.py is gone)
# a zip behind a program is an application package (NW.js): its pages are code too
_PACKAGE_EXTS = frozenset({".html", ".htm", ".mjs", ".cjs"})
_ZIP_END = b"PK\x05\x06"


def ext_of(name: str) -> str:
    leaf = name.replace("\\", "/").rsplit("/", 1)[-1]
    return "." + leaf.rsplit(".", 1)[-1].lower() if "." in leaf else ""


_FONTS = (b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf", b"wOFF", b"wOF2")
_PNM = re.compile(rb"P[1-6][ \t\r\n]+\d+[ \t\r\n]+\d+[ \t\r\n]")     # PBM / PGM / PPM pictures


def _icon(head: bytes) -> bool:
    """A Windows icon or cursor that is all pictures: each entry inside the file, and nothing
    behind the last one."""
    if len(head) < 6 or head[:4] not in (b"\0\0\x01\0", b"\0\0\x02\0"):
        return False
    count = int.from_bytes(head[4:6], "little")
    if not 0 < count <= 256 or len(head) < 6 + 16 * count:
        return False
    end = 6 + 16 * count
    for at in range(6, 6 + 16 * count, 16):
        size, offset = struct.unpack_from("<II", head, at + 8)
        if offset < 6 + 16 * count or offset + size > len(head):
            return False
        end = max(end, offset + size)
    return media.blank(head[end:])


def harmless(data) -> bool:
    """Clearly harmless data, by content (a name proves nothing): nothing but padding; text (a
    member whose ending Windows runs - ``.bat``, ``.ps1``, ``.js`` ... - is in ``MEMBER_EXTS``
    and read; any other text runs only through something that reads it, which is scanned on
    its own - measured 2026-10-23: telling scripts apart by content flagged read-me texts,
    translations and sources, and reading every text member cost four clean games
    SUSPICIOUS); a picture or sound that is all media by its own structure, an icon or cursor,
    a PBM / PGM / PPM picture; a font; or a file
    that is, byte for byte, a file of an official table (:mod:`gamescan.official`)."""
    from .text import is_text
    head = spool.head_of(data)
    if is_text(head):
        return True
    if spool.size_of(data) == len(head):
        if media.blank(head):
            return True
        info = media.parse(head)
        if info is not None and not info.problem and media.blank(head[info.end:]):
            return True
        if head.startswith(_FONTS) or _icon(head) or _PNM.match(head):
            return True
    sha = data.sha256 if isinstance(data, spool.Blob) else hashlib.sha256(head).hexdigest()
    from .. import official
    return bool(official.exact(sha))


def _member_kind(head: bytes) -> str:
    """What a member that is left out seems to be, for the note."""
    if head.startswith(b"\x7fELF"):
        return "Linux program or library"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macOS program or library"
    magic = int.from_bytes(head[:2], "little") if len(head) > 16 else 0
    if head[2:4] == b"\r\n" and (3000 <= magic < 4000 or 62000 <= magic < 63000):    # Python 3 / 2
        return "compiled Python"
    return "data of an unknown kind"


class Policy:
    """Which members of a container are extracted, and how large they may be."""

    def __init__(self) -> None:
        self.count = 0
        self.skipped: List[str] = []
        self.unread_programs: List[str] = []      # members that are programs of a kind nobody reads
        self.unread_formats: List[Tuple[str, str]] = []   # (member, format) of a format nobody reads
        self.unread_members: List[Tuple[str, str]] = []   # (member, kind) left out, not clearly harmless

    @staticmethod
    def limit(name: str) -> int:
        ext = ext_of(name)
        return (MAX_GAME_ARCHIVE if ext in GAME_ARCHIVES else
                MAX_MEMBER if ext in MEMBER_EXTS else MAX_UNNAMED)

    def unread_format(self, name: str, size: Optional[int] = None) -> bool:
        """A member named like a format the scanner has no reader for (``sniff.UNREAD_ENDINGS``;
        an MSI package is unpacked and said by its own handler): not unpacked, and said -
        until 2026-10-17 it vanished without a word (phageo, fifty-eighth message). Up to
        ``MAX_COMPARED`` it is unpacked after all, to be compared with the official tables: a
        file that is one of their files is known content (``UnreadFormatHandler``; phageo,
        fifty-ninth message) - any other gets its own note there."""
        ext = ext_of(name)
        if ext in sniff.UNREAD_ENDINGS and ext not in MEMBER_EXTS:
            if size is not None and size <= MAX_COMPARED:
                return False
            self.unread_formats.append((name, sniff.UNREAD_ENDINGS[ext]))
            return True
        return False

    def want(self, name: str, size: int) -> bool:
        """Called once per member, before it is unpacked where the format allows."""
        if ext_of(name) in UNREAD_PROGRAMS:
            # a program for a runtime the scanner has no reader for (Java): not unpacked,
            # and said - until 2026-10-12 such a member vanished without a word
            self.unread_programs.append(name)
            return False
        if self.unread_format(name, size):
            return False
        known = ext_of(name) in MEMBER_EXTS or ext_of(name) in sniff.UNREAD_ENDINGS
        if size > self.limit(name):
            # (a member without a telling ending, too large to be looked at, was left out without
            # a word until 2026-10-23: what it is cannot be told, so it is said too)
            self.skipped.append(name)
            return False
        if known:
            self.count += 1
            if self.count > MAX_MEMBERS:
                self.skipped.append(name)
                return False
        return True

    @staticmethod
    def keep(name: str, data: bytes) -> bool:
        """Members with no telling extension are only kept for what they contain (a container,
        or a format the scanner has no reader for - which its handler then says)."""
        return (ext_of(name) in MEMBER_EXTS or ext_of(name) in sniff.UNREAD_ENDINGS
                or data.startswith(CONTAINER_MAGICS) or bool(sniff.unread_kind(data)))

    def settle(self, name: str, data) -> bool:
        """Is this member scanned (:meth:`keep`)? Anything else is left out - and said, unless
        it is clearly harmless data (:func:`harmless`; phageo, 2026-10-23: until then such a
        member vanished without a word, as the two Linux libraries of an MSI did)."""
        head = spool.head_of(data)
        if self.keep(name, head):
            return True
        if not harmless(data):
            self.unread_members.append((name, _member_kind(head)))
        return False

    def problems(self) -> List[str]:
        out = []
        if self.unread_members:
            kinds = ", ".join(dict.fromkeys(kind for _name, kind in self.unread_members))
            out.append("%d member(s) of a kind the scanner does not read (%s) were not inspected: %s"
                       % (len(self.unread_members), kinds, ", ".join(name for name, _kind in self.unread_members[:5])))
        if self.unread_programs:
            out.append("%d program file(s) of a kind the scanner does not read (%s) were not inspected: %s"
                       % (len(self.unread_programs), UNREAD_PROGRAMS_WHAT, ", ".join(self.unread_programs[:5])))
        if self.unread_formats:
            kinds = ", ".join(dict.fromkeys(what for _name, what in self.unread_formats))
            out.append("%d file(s) of a format the scanner has no reader for (%s) were not inspected: %s"
                       % (len(self.unread_formats), kinds, ", ".join(name for name, _what in self.unread_formats[:5])))
        if self.skipped:
            out.append("%d member(s) over the size or count limit were not inspected: %s"
                       % (len(self.skipped), ", ".join(self.skipped[:5])))
        return out


# -- detection ---------------------------------------------------------------------------
def _on_disk(ctx: FileContext) -> bool:
    return ctx.on_disk


def _search_file(path: str, needles: Tuple[bytes, ...], start: int) -> List[Tuple[bytes, int]]:
    """All occurrences of ``needles`` in a file from ``start`` on (bounded)."""
    out: List[Tuple[bytes, int]] = []
    overlap = max(map(len, needles)) - 1
    with open(path, "rb") as fh:
        fh.seek(start)
        base, tail = start, b""
        while len(out) < 8192:
            block = fh.read(4 << 20)
            if not block:
                break
            buffer = tail + block
            for needle in needles:
                pos = buffer.find(needle)
                while pos >= 0:
                    out.append((needle, base - len(tail) + pos))
                    pos = buffer.find(needle, pos + 1)
            base += len(block)
            tail = buffer[-overlap:]
    return sorted(set(out), key=lambda hit: hit[1])


def detect(ctx: FileContext) -> List[Tuple[str, int, int]]:
    """``(kind, offset, size)`` of every container in the file (cached)."""
    if "containers" in ctx.cache:
        return ctx.cache["containers"]
    data, total = ctx.data, ctx.size or len(ctx.data)
    found: List[Tuple[str, int, int]] = []
    if not ctx.is_pe:
        if data.startswith(cab.MAGIC):
            found = [("cab", offset, size) for offset, size in cab.find(data, total, 1)] \
                or [("cab", 0, total)]
        elif sevenzip.valid_at(data, 0):
            found = [("7z", 0, total)]
        elif data.startswith(rar.MAGIC):
            found = [("rar", 0, total)]
        elif data.startswith(_SLICE):
            found = [("inno", -1, total)]
    elif ctx.pe is not None:
        found = [("cab", offset, size) for offset, size in cab.find(data, total)]
        start = ctx.pe.overlay_offset
        unsure = False
        # (a program with nothing behind it has no "behind": all of it is the program)
        inside = nsis.first_header(data, start if start > 0 else len(data)) if not found else -1
        if inside >= 0:
            # a first header inside the program: NSIS reads its file from the start and
            # takes the first one it meets, so that is the installer that would run
            found = [("nsis", inside, total - inside)]
            if ctx.pe.overlay_size > 64:
                ctx.cache.setdefault("container_notes", []).append(
                    "an NSIS installer header stands inside the program itself; NSIS uses that one, "
                    "so it was read - the data behind the program was not read as an installer of its own")
        if ctx.pe.overlay_size > 64 and not found:
            # what a self-extractor carries starts right behind its program
            near = data[start:start + (1 << 20)]
            seven = near.find(sevenzip.MAGIC)
            while seven >= 0 and not sevenzip.valid_at(near, seven):
                seven = near.find(sevenzip.MAGIC, seven + 1)
            if seven >= 0:
                found = [("7z", start + seven, total - start - seven)]
            elif rar.MAGIC in near:
                at = start + near.find(rar.MAGIC)
                found = [("rar", at, total - at)]
            elif nsis.find(near) >= 0:
                # the header NSIS would take (512-byte steps); one that stands off those
                # steps is no installer NSIS would run, but it is read all the same
                at = nsis.first_header(data, start + len(near))
                at = at if at >= 0 else start + nsis.find(near)
                found = [("nsis", at, total - at)]
            else:
                at = _inno_header(ctx, start, total)
                if at >= 0:
                    found = [("inno", at, total)]
                unsure = at == inno.AMBIGUOUS
        if not found and _zip_behind(ctx):
            # last, so that the installers keep their own readers
            found = [("zip", start, ctx.pe.overlay_size)]
        if not found and ctx.pe.overlay_size > _NSIS_NEAR:
            # NSIS itself searches its whole file; the reader stops one megabyte behind the
            # program. A first header further back is not read - and that is said (rule 15)
            far = _nsis_beyond(ctx, start + _NSIS_NEAR)
            if far >= 0:
                ctx.cache.setdefault("container_notes", []).append(
                    "an NSIS installer header stands %.1f MB behind the program, further back than "
                    "installers are looked for (1 MB) - the installer was not read"
                    % ((far - start) / 1048576))
        if not found and unsure:
            ctx.cache.setdefault("container_notes", []).append(
                "Inno Setup: the text that marks the setup header stands more than once behind the "
                "program, and the program has no readable table that says which one it uses - "
                "the installer was not read")
    ctx.cache["containers"] = found
    return found


_NSIS_NEAR = 1 << 20                # how far behind the program an NSIS header is looked for and read


def _marks(ctx: FileContext, start: int) -> List[Tuple[bytes, int]]:
    """Every place behind ``start`` where the mark of an Inno Setup header or of an NSIS
    first header stands (one pass over the file, kept for the second caller)."""
    key = ("overlay_marks", start)
    if key not in ctx.cache:
        needles = (inno.SIGNATURE, nsis.SIGNATURE)
        if ctx.truncated and _on_disk(ctx):
            try:
                ctx.cache[key] = _search_file(ctx.path, needles, start)
            except OSError:
                ctx.cache[key] = []
        else:
            out: List[Tuple[bytes, int]] = []
            for needle in needles:
                at = ctx.data.find(needle, start)
                while at >= 0 and len(out) < 8192:
                    out.append((needle, at))
                    at = ctx.data.find(needle, at + 1)
            ctx.cache[key] = sorted(out, key=lambda hit: hit[1])
    return ctx.cache[key]


def _nsis_beyond(ctx: FileContext, limit: int) -> int:
    """Where a first header NSIS would take stands at or behind ``limit`` (-1: nowhere)."""
    for needle, at in _marks(ctx, ctx.pe.overlay_offset):
        place = at - 4
        if needle != nsis.SIGNATURE or place < limit or place % 512:
            continue
        if place + 4 <= len(ctx.data):
            flags = ctx.data[place:place + 4]
        elif not (ctx.truncated and _on_disk(ctx)):
            continue
        else:
            try:
                with open(ctx.path, "rb") as fh:
                    fh.seek(place)
                    flags = fh.read(4)
            except OSError:
                continue
        if len(flags) == 4 and not int.from_bytes(flags, "little") & ~15:
            return place
    return -1


def _inno_header(ctx: FileContext, start: int, total: int) -> int:
    """Where the setup header of an Inno Setup installer is (-1: this is none;
    ``inno.AMBIGUOUS``: no table and more than one candidate, so none is taken):
    the place its loader's own table names (:func:`inno.header`), not the first
    place where the header's text stands."""
    data, on_disk = ctx.data, ctx.truncated and _on_disk(ctx)

    def read(offset: int, count: int) -> bytes:
        if offset + count <= len(data) or not on_disk:
            return data[offset:offset + count]
        try:
            with open(ctx.path, "rb") as fh:
                fh.seek(offset)
                return fh.read(count)
        except OSError:
            return b""

    def markers() -> List[int]:
        return [at for needle, at in _marks(ctx, start) if needle == inno.SIGNATURE]

    return inno.header(data[:start], start, total, read, markers)


def _zip_behind(ctx: FileContext) -> bool:
    """Is the data behind the program a zip archive (its directory is at the end)?"""
    start, size = ctx.pe.overlay_offset, ctx.pe.overlay_size
    if size < 22:
        return False
    tail = min(size, 66 * 1024)                       # end record + the longest comment
    at = start + size - tail
    if at + tail <= len(ctx.data):
        end = ctx.data[at:at + tail]
    elif _on_disk(ctx):
        try:
            with open(ctx.path, "rb") as fh:
                fh.seek(at)
                end = fh.read(tail)
        except OSError:
            return False
    else:
        return False
    return _ZIP_END in end


def covers_overlay(ctx: FileContext) -> bool:
    """Is the data behind the program a container that is being opened?"""
    pe = ctx.pe
    return pe is not None and any(
        kind == "inno" or (offset <= pe.overlay_offset + (1 << 20)
                           and offset + size >= pe.overlay_offset + 0.9 * pe.overlay_size)
        for kind, offset, size in detect(ctx))


# -- reading -----------------------------------------------------------------------------
def child(ctx: FileContext, name: str, data) -> FileContext:
    """Context for a member of ``ctx``: ``data`` is its content, or the
    :class:`spool.Blob` it was unpacked into. A spooled member is a file on
    disk for everything that follows (read in a stream, never as a whole);
    the scanner deletes the temporary file once the member has been scanned."""
    relpath = "%s!%s" % (ctx.relpath, name.lstrip("/"))
    if isinstance(data, spool.Blob):
        if data.path is None:
            data = data.data
        else:
            member = FileContext(path=data.path, relpath=relpath, data=data.data, size=data.size,
                                 sha256=data.sha256, truncated=data.size > len(data.data))
            member.cache["spooled"] = data.path
            return member
    return FileContext(path=ctx.path, relpath=relpath, data=data, size=len(data),
                       sha256=hashlib.sha256(data).hexdigest())


_child = child


def release(member: FileContext) -> None:
    """Delete the temporary file behind a spooled member (no-op otherwise)."""
    path = member.cache.pop("spooled", None)
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass


def _source(ctx: FileContext, offset: int, size: int):
    # a large file is only partly in memory: read it from disk instead
    base = open(ctx.path, "rb") if ctx.truncated and _on_disk(ctx) else io.BytesIO(ctx.data)
    return cab.Window(base, max(offset, 0), size)


def _native(ctx: FileContext, kind: str, offset: int, size: int, policy: Policy,
            notes: List[str]) -> Iterator[Tuple[str, bytes]]:
    """Members read with the standard library. Raises the format's NeedTool
    (a ValueError) when that is not enough."""
    with _source(ctx, offset, size) as stream:
        if kind == "cab":
            # the project's own reader only - since 2026-10-19 no Windows program (cabinet.dll,
            # tar.exe) reads a scanned file's cabinet (phageo); Quantum stays a note
            yield from cab.members(stream, policy.want, notes=notes)
        elif kind == "7z":
            yield from sevenzip.Archive(stream).members(policy.want, ctx.tick)
        elif kind == "rar":
            entries = rar.entries(stream)
            wanted = [e for e in entries if policy.want(e.name, e.size)]
            blocked = next((e for e in wanted if e.encrypted or not e.stored), None)
            if blocked is not None:
                raise rar.NeedTool("a password" if blocked.encrypted else "RAR decompression")
            for entry in wanted:
                yield entry.name, rar.read(stream, entry, policy.limit(entry.name))
        elif kind == "nsis":
            yield from nsis.members(stream, policy, ctx.tick)
        elif kind == "zip":
            yield from _zip_members(stream, policy, ctx, notes)


def _zip_members(stream, policy: Policy, ctx: FileContext,
                 notes: List[str]) -> Iterator[Tuple[str, bytes]]:
    """Members of a zip that is appended to a program."""
    with zipfile.ZipFile(stream) as archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        locked = sum(1 for i in infos if i.flag_bits & 1)
        if locked:
            notes.append("zip behind the program: %d password-protected member(s) were not "
                         "inspected" % locked)
        total, done = sum(i.compress_size for i in infos) or 1, 0
        for info in infos:
            if ctx.cancelled:
                return
            done += info.compress_size
            ctx.tick(done / total)
            name = info.filename
            if info.flag_bits & 1 or not policy.want(name, info.file_size):
                continue
            limit = policy.limit(name)
            try:
                with archive.open(info) as member:
                    def pieces(member=member, left=limit + 1):
                        while left > 0:                 # zip-bomb guard: never more than
                            piece = member.read(min(left, 1 << 20))     # the limit, plus one byte
                            if not piece:
                                return
                            left -= len(piece)
                            yield piece
                    data = spool.collect(pieces())
            except spool.SpoolError as exc:
                policy.skipped.append("%s (%s)" % (name, exc))
                continue
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
                policy.skipped.append(name)
                continue
            if spool.size_of(data) > limit:
                if isinstance(data, spool.Blob):
                    data.release()
                policy.skipped.append(name)
                continue
            yield name, data


def _members(ctx: FileContext, kind: str, offset: int, size: int,
             notes: List[str], policy: Policy) -> Iterator[Tuple[str, bytes]]:
    """(``policy`` is the caller's: what it settles while the members come is said with the rest)"""
    try:
        for name, data in _native(ctx, kind, offset, size, policy, notes):
            yield name, data
        notes.extend(policy.problems())
        return
    except (cab.NeedTool, sevenzip.NeedTool, rar.NeedTool, nsis.NeedTool) as exc:
        need = str(exc)
    except spool.SpoolError as exc:
        notes.append(str(exc))
        notes.extend(policy.problems())
        return
    except (ValueError, OSError, EOFError, zipfile.BadZipFile, NotImplementedError,
            RuntimeError) as exc:                           # damaged, or not what it seemed
        notes.append("%s data could not be read: %s" % (kind, exc))
        notes.extend(policy.problems())
        return
    # the own reader cannot decode this one, and no program is asked to (phageo): it is said
    if "password" in need or "split into parts" in need:
        notes.append("needs %s" % need)
        return
    notes.append("needs %s, which the scanner does not decode" % need)
    notes.extend(policy.problems())


def expand(ctx: FileContext) -> Iterator[FileContext]:
    """The members of the file's containers, one at a time. What could not be
    read is collected for :func:`findings` (call it after this is exhausted)."""
    notes: List[str] = ctx.cache.setdefault("container_notes", [])
    for kind, offset, size in detect(ctx):
        if kind == "inno":
            yield from ctx.cache.get("inno_children", ())
            installer = ctx.cache.get("inno_installer")
            if installer is not None:                       # exact: names and real bytes
                policy = Policy()
                try:
                    for name, data in installer.members(policy.want, ctx.cancel, ctx.tick, notes):
                        if policy.settle(name, data):
                            yield child(ctx, name, data)
                        elif isinstance(data, spool.Blob):
                            data.release()
                        else:
                            localdrop.offer("%s!%s" % (ctx.relpath, name), data)
                except spool.SpoolError as exc:
                    notes.append(str(exc))
                notes.extend(policy.problems())
            continue
        policy = Policy()
        for name, data in _members(ctx, kind, offset, size, notes, policy):
            if ctx.cancelled:
                return
            if (kind == "zip" and ext_of(name) in _PACKAGE_EXTS) or policy.settle(name, data):
                yield child(ctx, name, data)
            elif isinstance(data, spool.Blob):
                data.release()
            else:
                # not scanned - but perhaps the file a script of the game decodes (CHAIN-LOCAL-DROP:
                # kept in memory, bounded, for Scanner._join_local)
                localdrop.offer("%s!%s" % (ctx.relpath, name), data)


def findings(handler, ctx: FileContext) -> List[Finding]:
    """Say so when a container (or part of one) could not be looked into."""
    notes = ctx.cache.pop("container_notes", [])
    return [handler.make(
        ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION, Severity.LOW,
        NOT_INSPECTED,
        note[:300], 0.3) for note in dict.fromkeys(notes)]


# -- Inno Setup: content is found, not listed --------------------------------------------------
class _Spool:
    """Unpacked data: in memory while small, in an unnamed temporary file
    (gone when closed) once it is large. ``view()`` gives random access."""

    def __init__(self, memory: int = 64 * 1024 * 1024) -> None:
        self.memory, self.size = memory, 0
        self.buffer: Optional[io.BytesIO] = io.BytesIO()
        self.file = None
        self.map = None

    def write(self, data: bytes) -> None:
        if self.buffer is not None and self.size + len(data) > self.memory:
            self.file = tempfile.TemporaryFile()
            self.file.write(self.buffer.getvalue())
            self.buffer = None
        (self.buffer or self.file).write(data)
        self.size += len(data)

    def view(self):
        if self.buffer is not None:
            return self.buffer.getvalue()
        self.file.flush()
        self.map = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        return self.map

    def close(self) -> None:
        for item in (self.map, self.file):
            if item is not None:
                item.close()


def scan_inno(handler, ctx: FileContext, rules) -> List[Finding]:
    """Read an Inno Setup installer.

    Its setup script becomes a text member. Its data is unpacked into one
    stream in which the installed files lie back to back, unnamed: programs,
    RPG Maker archives and script tables are found by their content and
    become members; everything is also read as text, like an asset file."""
    hit = next((c for c in detect(ctx) if c[0] == "inno"), None)
    if hit is None or "inno_children" in ctx.cache:
        return []
    _kind, signature, total = hit
    notes: List[str] = ctx.cache.setdefault("container_notes", [])
    children: List[FileContext] = []
    out: List[Finding] = []
    seen = set()
    on_disk = ctx.truncated and _on_disk(ctx)
    if signature >= 0 and ctx.pe is not None:
        # first choice: rebuild every installed file exactly, under its own name
        try:
            def whole():
                return open(ctx.path, "rb") if on_disk else io.BytesIO(ctx.data)

            def part(number: int):
                stem = os.path.splitext(ctx.path)[0]
                path = "%s-%d.bin" % (stem, number)
                return open(path, "rb") if _on_disk(ctx) and os.path.isfile(path) else None

            first = ctx.pe.overlay_offset
            offsets = [at for _n, at in _search_file(ctx.path, (inno.CHUNK_MAGIC,), first)] \
                if on_disk else inno.chunks(ctx.data, first)
            installer = inno.Installer(whole, signature, first, offsets, part)
            text = "\n".join(extract_strings(installer.script, 4))
            ctx.cache["inno_children"] = [_child(ctx, nsis.SCRIPT_NAME, installer.script_member(
                text.encode("utf-8", "replace")))]
            ctx.cache["inno_installer"] = installer
            return out
        except (inno.InnoError, OSError) as exc:
            notes.append("Inno Setup: file table not read (%s); the content was searched "
                         "instead, without names" % exc)
    spool = _Spool()
    try:
        with (open(ctx.path, "rb") if on_disk else io.BytesIO(ctx.data)) as stream:
            if signature >= 0:
                try:
                    parts = inno.blocks(stream, signature)
                    text = "\n".join(extract_strings(b"\0".join(parts[:2]), 4))
                    # (no file table: the [Code] is still read; the [Run] rows are not found)
                    member = inno.Script(text.encode("utf-8", "replace"))
                    member.block = parts[0]
                    children.append(_child(ctx, nsis.SCRIPT_NAME, member))
                except inno.InnoError as exc:
                    notes.append("Inno Setup script: %s" % exc)
            first = ctx.pe.overlay_offset if ctx.pe is not None else 0
            if on_disk:
                offsets = [at for _needle, at in _search_file(ctx.path, (inno.CHUNK_MAGIC,), first)]
            else:
                offsets = inno.chunks(ctx.data, first)
            if signature >= 0:
                before = [at for at in offsets if at < signature]
                offsets = before or offsets
                total = signature if before else total
            if not offsets:
                notes.append("Inno Setup data not found (it may be in separate setup-*.bin files "
                             "- scan those too)")
            carver = unity.Carver(limit=64)

            def pieces():
                try:
                    for piece in inno.payload(stream, offsets, total, ctx.cancel, ctx.tick):
                        if spool.size + len(piece) > MAX_PAYLOAD:
                            notes.append("Inno Setup data over %d GB: the rest was not inspected"
                                         % (MAX_PAYLOAD >> 30))
                            return
                        spool.write(piece)
                        yield piece
                except inno.InnoError as exc:
                    notes.append("Inno Setup data needs %s" % exc if isinstance(
                        exc, inno.NeedTool) else "Inno Setup data: %s" % exc)

            for _offset, window in carver.windows(pieces()):
                text = "\n".join(extract_strings(window))
                for f in rules.scan(text, "strings", ctx, handler.name, numbered=False):
                    key = (f.rule_id, f.context.get("match") or f.evidence)
                    if key not in seen and len(out) < 2000:
                        seen.add(key)
                        out.append(f)
        for offset, image, is_dll in carver.images:
            children.append(_child(ctx, "installed_0x%x.%s" % (offset, "dll" if is_dll else "exe"),
                                   image))
        children += _carve_rgss(ctx, spool.view())
    finally:
        spool.close()
    ctx.cache["inno_children"] = children
    return out


def _carve_rgss(ctx: FileContext, view) -> List[FileContext]:
    """RPG Maker archives and script tables inside unpacked installer data."""
    out: List[FileContext] = []
    pos = view.find(rgss.MAGIC)
    while pos >= 0 and len(out) < 16:
        end = pos + len(rgss.MAGIC)
        try:
            limit = min(len(view) - pos, MAX_GAME_ARCHIVE)
            data = bytes(view[pos:pos + limit])
            entries = rgss.list_archive(io.BytesIO(data), lenient=True)
            if entries:
                end = pos + max(e.offset + e.size for e in entries)
                data = data[:end - pos]
                out.append(_child(ctx, "installed_0x%x%s" % (pos, sniff.extension(data)), data))
        except rgss.RgssError:
            pass
        pos = view.find(rgss.MAGIC, end)
    pos = view.find(b"\x04\x08[")
    tables = 0
    while pos >= 0 and tables < 8:
        end = pos + 3
        try:
            data = bytes(view[pos:pos + rgss.MAX_SCRIPTS_TOTAL])
            used = rgss.scripts_extent(data)
            name = "Scripts" + sniff.extension(data[:used])
            out.append(_child(ctx, "installed_0x%x/Data/%s" % (pos, name), data[:used]))
            end = pos + used
            tables += 1
        except rgss.RgssError:
            pass
        pos = view.find(b"\x04\x08[", end)
    return out
