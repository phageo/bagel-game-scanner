"""RAR archive reader (standard library only): versions 4 and 5.

RAR's compression is proprietary and not in the standard library, so this
module does what can be done without it: it reads the file table (names,
sizes, flags) and returns members that were *stored* without compression.
For compressed members it raises :class:`NeedTool`; the caller then reports
that the archive could not be looked into (since 2026-10-20 no installed
extractor - Windows' ``tar``, 7-Zip - is asked: phageo).
"""
from __future__ import annotations

import struct
from typing import BinaryIO, List, NamedTuple

from . import limits, spool

MAGIC = b"Rar!\x1a\x07"
MAGIC4 = MAGIC + b"\x00"
MAGIC5 = MAGIC + b"\x01\x00"
_MAX_ENTRIES = 200_000
_MAX_HEADER = 2 * 1024 * 1024


class RarError(ValueError):
    """The archive is damaged or not a RAR archive."""


class NeedTool(RarError):
    """Valid archive, but reading it needs what this reader does not do."""


class Entry(NamedTuple):
    name: str
    size: int          # unpacked
    offset: int        # of its data, from the start of the archive
    packed: int
    stored: bool
    encrypted: bool


def _vint(data: bytes, pos: int):
    value = shift = 0
    while True:
        if pos >= len(data) or shift > 63:
            raise RarError("truncated header")
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7


def _entries5(stream: BinaryIO, pos: int, end: int) -> List[Entry]:
    out: List[Entry] = []
    while pos < end and len(out) < _MAX_ENTRIES:
        stream.seek(pos)
        head = stream.read(4 + 10)
        if len(head) < 7:
            break
        size, at = _vint(head, 4)
        if size > _MAX_HEADER:
            raise RarError(limits.hit("rar", "a header larger than %d MB" % (_MAX_HEADER >> 20)))
        if size <= 0:
            raise RarError("implausible header size")
        stream.seek(pos + at)
        body = stream.read(size)
        if len(body) != size:
            raise RarError("truncated header")
        kind, p = _vint(body, 0)
        flags, p = _vint(body, p)
        extra = data = 0
        if flags & 0x01:
            extra, p = _vint(body, p)
        if flags & 0x02:
            data, p = _vint(body, p)
        data_at = pos + at + size
        if kind == 4:
            raise NeedTool("a password (the archive's file table is encrypted)")
        if kind == 5:
            break
        if kind == 2:
            file_flags, p = _vint(body, p)
            unpacked, p = _vint(body, p)
            _attributes, p = _vint(body, p)
            if file_flags & 0x02:
                p += 4
            if file_flags & 0x04:
                p += 4
            info, p = _vint(body, p)
            _host, p = _vint(body, p)
            length, p = _vint(body, p)
            name = body[p:p + length].decode("utf-8", "replace").replace("\\", "/")
            encrypted, q = False, size - extra
            while extra and q < size:                       # extra records: [size][type]...
                record, after = _vint(body, q)
                encrypted |= _vint(body, after)[0] == 0x01
                q = after + record
            if flags & 0x18:
                raise NeedTool("the other volumes (the archive is split into parts)")
            if not file_flags & 0x01:                       # not a directory
                out.append(Entry(name, unpacked, data_at, data,
                                 (info >> 7) & 7 == 0, encrypted))
        pos = data_at + data
    if len(out) >= _MAX_ENTRIES:
        limits.hit("rar", "more than %d entries: the rest was not read" % _MAX_ENTRIES)
    return out


def _entries4(stream: BinaryIO, pos: int, end: int) -> List[Entry]:
    out: List[Entry] = []
    while pos + 7 <= end and len(out) < _MAX_ENTRIES:
        stream.seek(pos)
        head = stream.read(7)
        if len(head) < 7:
            break
        _crc, kind, flags, size = struct.unpack("<HBHH", head)
        if size < 7:
            raise RarError("implausible header size")
        body = head + stream.read(size - 7)
        add = 0
        if kind == 0x73 and flags & 0x0080:
            raise NeedTool("a password (the archive's file table is encrypted)")
        if kind == 0x7B:
            break
        if kind == 0x74:
            if len(body) < 32:
                raise RarError("truncated header")
            packed, unpacked, _os, _crc32, _time, _ver, method, name_len, _attr = \
                struct.unpack_from("<IIBIIBBHI", body, 7)
            p = 32
            if flags & 0x100:
                high_packed, high_unpacked = struct.unpack_from("<II", body, p)
                packed |= high_packed << 32
                unpacked |= high_unpacked << 32
                p += 8
            raw = body[p:p + name_len]
            if flags & 0x200:                               # "name\0<packed unicode>"
                raw = raw.split(b"\0", 1)[0]
            if flags & 0x03:
                raise NeedTool("the other volumes (the archive is split into parts)")
            if flags & 0xE0 != 0xE0:                        # not a directory
                out.append(Entry(raw.decode("utf-8", "replace").replace("\\", "/"), unpacked,
                                 pos + size, packed, method == 0x30, bool(flags & 0x04)))
            add = packed
        elif flags & 0x8000:
            if len(body) < 11:
                raise RarError("truncated header")
            add = struct.unpack_from("<I", body, 7)[0]
        pos += size + add
    if len(out) >= _MAX_ENTRIES:
        limits.hit("rar", "more than %d entries: the rest was not read" % _MAX_ENTRIES)
    return out


def entries(stream: BinaryIO) -> List[Entry]:
    """The file table. ``stream`` must start at the RAR signature."""
    end = stream.seek(0, 2)
    stream.seek(0)
    head = stream.read(8)
    try:
        if head == MAGIC5:
            return _entries5(stream, 8, end)
        if head[:7] == MAGIC4:
            return _entries4(stream, 7, end)
    except struct.error:
        raise RarError("truncated header") from None
    raise RarError("not a RAR archive")


def read(stream: BinaryIO, entry: Entry, limit: int):
    """Content of a stored member (``bytes``, or a :class:`spool.Blob` if large)."""
    if entry.encrypted:
        raise NeedTool("a password (the member is encrypted)")
    if not entry.stored:
        raise NeedTool("RAR decompression")
    if entry.size > limit:
        raise RarError(limits.hit("rar", "a member larger than the limit for its kind (%d MB)" % (limit >> 20)))
    if entry.packed != entry.size:
        raise RarError("member size is inconsistent or over the limit")
    stream.seek(entry.offset)

    def pieces():
        left = entry.size
        while left > 0:
            piece = stream.read(min(left, 1 << 20))
            if not piece:
                raise RarError("member is cut short")
            left -= len(piece)
            yield piece
    return spool.collect(pieces())
