"""Data in, or behind, a program's signature block.

A signed program ends with its certificate table. Windows leaves that table
out when it checks the signature, so bytes placed *inside* it, beyond the
signature itself, change nothing: the signature stays valid, and whatever is
put there travels under the signer's name without the signer ever having seen
it. Bytes placed *after* the table are the opposite case: Windows then no
longer accepts the signature at all.

Neither area belongs to the program or to its overlay, so nothing else in the
scanner reads it. This module finds both, says so with a finding that no
signature (or other baseline) can hide, and hands the content on to be scanned
like a file of its own - without the trust the signature gives the rest of
the file. How serious the finding is depends on what the data is.
"""
from __future__ import annotations

import hashlib
import struct
from typing import List, Optional, Tuple

from .entropy import shannon
from .models import Category, FileContext, Finding, Severity
from .unpack import sniff

MAX_READ = 64 * 1024 * 1024     # of each area; what lies beyond is reported as not inspected
# A readable text up to this size is a tag (LOW); a longer one is not (MEDIUM). The tags
# installers keep here - which download, which campaign - are a line or two, a few hundred
# bytes; 16 KB leaves two orders of magnitude of room for them and is still far too small
# to be worth hiding a document or a packed program in.
SMALL = 16 * 1024
INSIDE, AFTER = "SIG-DATA-001", "SIG-DATA-002"
_MAGICS = (b"MZ", b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"MSCF", b"RGSSAD\0")
_TEXT = bytes(range(0x20, 0x7F)) + b"\t\r\n\0"
_KINDS = {".exe": "a program", ".dll": "a program library", ".zip": "a zip archive",
          ".cab": "a cabinet archive", ".7z": "a 7z archive", ".rar": "a RAR archive",
          ".rgssad": "an RPG Maker archive", ".rgss3a": "an RPG Maker archive",
          ".ps1": "a PowerShell script", ".vbs": "a VBScript", ".bat": "a batch script",
          ".js": "a JavaScript file"}
_REASON = {
    INSIDE: "This program carries data inside its signature block, beyond the signature itself. "
            "Windows leaves this area out when it checks a signature, so the signature stays "
            "valid whatever is put there - and the signer vouches for none of it. Some "
            "installers keep a short download tag here; anything more has no business being "
            "there. The data was scanned on its own, without the trust the signature gives the "
            "rest of the file.",
    AFTER: "Data follows this program's signature block. Windows does not accept the signature "
           "of a file that was changed this way, so the file is treated as unsigned here too: "
           "no publisher trust applies to it or to anything inside it. The data was scanned on "
           "its own.",
}
_TITLE = {INSIDE: "Data hidden inside the signature block", AFTER: "Data after the signature block"}


def _der_length(blob: bytes) -> Optional[int]:
    """Length of the DER object that starts ``blob`` (None: it is not one)."""
    if len(blob) < 2 or blob[0] != 0x30:
        return None
    first = blob[1]
    if first < 0x80:
        return 2 + first
    count = first & 0x7F
    if not 1 <= count <= 4 or len(blob) < 2 + count:
        return None
    return 2 + count + int.from_bytes(blob[2:2 + count], "big")


def _read(ctx: FileContext, offset: int, size: int) -> bytes:
    if offset + size <= len(ctx.data):
        return bytes(ctx.data[offset:offset + size])
    if not ctx.on_disk:
        return b""
    try:
        with open(ctx.path, "rb") as fh:
            fh.seek(offset)
            return fh.read(size)
    except OSError:
        return b""


def _layout(ctx: FileContext) -> Tuple[List[Tuple[int, int]], Tuple[int, int]]:
    """``(gaps inside the table, (offset, size) of what follows it)`` - file offsets."""
    if "sigblock" in ctx.cache:
        return ctx.cache["sigblock"]
    out: Tuple[List[Tuple[int, int]], Tuple[int, int]] = ([], (0, 0))
    pe = ctx.pe
    total = ctx.size or len(ctx.data)
    if pe is not None and pe.has_signature and len(pe.data_dirs) > 4:
        offset, size = pe.data_dirs[4]
        # a table that does not lie inside the file: a piece cut out of unpacked installer
        # data, or a damaged header - there is no signature area to speak of
        if offset > 0 and size >= 8 and offset + size <= total:
            table = _read(ctx, offset, min(size, MAX_READ))
            if len(table) == min(size, MAX_READ):
                out = (_gaps(table, offset, size), (offset + size, total - offset - size))
    ctx.cache["sigblock"] = out
    return out


def _gaps(table: bytes, offset: int, size: int) -> List[Tuple[int, int]]:
    """Parts of the certificate table that are not a signature (and not zero padding)."""
    found: List[Tuple[int, int]] = []
    pos = 0
    while pos + 8 <= len(table) and len(found) < 64:
        length = struct.unpack_from("<I", table, pos)[0]
        if length < 8 or pos + length > size:
            break                                    # not an entry: the rest is not a signature
        der = _der_length(table[pos + 8:pos + 16])
        end = pos + 8 + der if der is not None and 8 + der <= length else pos + length
        if end < pos + length:
            found.append((end, pos + length - end))
        pos = (pos + length + 7) & ~7
    if pos < size:
        found.append((pos, size - pos))
    return [(offset + at, count) for at, count in found
            if table[at:at + count].strip(b"\0") or at + count > len(table)]


def data_after(ctx: FileContext) -> int:
    """Bytes behind the certificate table. Windows rejects the signature of such a
    file; the scanner therefore treats it as unsigned (see ``engine_files.signer``)."""
    return _layout(ctx)[1][1]


def _areas(ctx: FileContext) -> List[Tuple[str, int, int, bytes]]:
    """``(rule, offset, size, content read)`` for each area that holds data."""
    if "sigblock_areas" in ctx.cache:
        return ctx.cache["sigblock_areas"]
    gaps, (after_at, after_size) = _layout(ctx)
    out: List[Tuple[str, int, int, bytes]] = []
    if gaps:
        left, pieces = MAX_READ, []
        for at, count in gaps:
            pieces.append(_read(ctx, at, min(count, left)))
            left -= len(pieces[-1])
        out.append((INSIDE, gaps[0][0], sum(count for _at, count in gaps), b"".join(pieces)))
    if after_size > 0:
        out.append((AFTER, after_at, after_size, _read(ctx, after_at, min(after_size, MAX_READ))))
    ctx.cache["sigblock_areas"] = out
    return out


def _classify(data: bytes, size: int) -> Tuple[Severity, str, str, int]:
    """``(severity, what it is, extension to scan it under, where that starts)``."""
    start = len(data) - len(data.lstrip(b"\0"))          # zero padding in front says nothing
    ext = sniff.extension(data[start:])
    if not ext:
        # a program or an archive behind a few bytes of something else
        hits = [at for at in (data.find(magic, start + 1, 1 << 20) for magic in _MAGICS) if at > 0]
        for at in sorted(hits):
            inner = sniff.extension(data[at:])
            if inner and (inner not in (".exe", ".dll") or _is_program(data, at)):
                start, ext = at, inner
                break
    if ext in (".exe", ".dll") and not _is_program(data, start):
        ext = ""
    if ext:
        return Severity.HIGH, _KINDS.get(ext, "a file the scanner knows (%s)" % ext), ext, start
    body = data.strip(b"\0")
    if body and len(body.translate(None, _TEXT)) * 20 <= len(body):
        # (scanned under the name of a script, so that the command rules read it)
        if size <= SMALL:
            return Severity.LOW, "readable text, short enough to be a download tag", ".bat", start
        return Severity.MEDIUM, "readable text, too long for a download tag", ".bat", start
    return (Severity.MEDIUM, "data that could not be recognised (entropy %.1f of 8 bits per byte)"
            % shannon(data[:1 << 20]), "", 0)


def _is_program(data: bytes, at: int) -> bool:
    try:
        header = struct.unpack_from("<I", data, at + 0x3C)[0]
    except struct.error:
        return False
    return 0 < header < 0x1000 and data[at + header:at + header + 4] == b"PE\0\0"


def findings(ctx: FileContext) -> List[Finding]:
    """The notes about data in / behind the signature block (never hidden by a baseline)."""
    out: List[Finding] = []
    for rule, offset, size, data in _areas(ctx):
        severity, what, _ext, _start = _classify(data, size)
        evidence = "%d bytes at offset %d: %s" % (size, offset, what)
        if size > len(data):
            evidence += "; only the first %d MB were inspected" % (len(data) >> 20)
            severity = max(severity, Severity.MEDIUM)
        out.append(Finding(
            rule_id=rule, title=_TITLE[rule], category=Category.EVASION, severity=severity,
            file=ctx.relpath, line=None, snippet="", evidence=evidence, confidence=0.6,
            reason=_REASON[rule], sha256=ctx.sha256, path=ctx.path, chainable=False))
    return out


def children(ctx: FileContext) -> List[FileContext]:
    """The content of both areas as members, to be scanned like any file - and not
    as part of what the signature covers."""
    out: List[FileContext] = []
    for rule, _offset, size, data in _areas(ctx):
        _severity, _what, ext, start = _classify(data, size)
        if not ext:
            continue
        content = data[start:]
        name = "[data inside the signature block]" if rule == INSIDE else "[data after the signature block]"
        member = FileContext(path=ctx.path, relpath="%s!%s%s" % (ctx.relpath, name, ext), data=content,
                             size=len(content), sha256=hashlib.sha256(content).hexdigest())
        member.cache["outside_signature"] = True
        out.append(member)
    return out
