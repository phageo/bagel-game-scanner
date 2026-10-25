"""RPG Maker XP / VX / VX Ace (RGSS) unpacker.

Two things live here, both read-only and bounded:

* The encrypted game archives - ``Game.rgssad`` (XP), ``Game.rgss2a`` (VX) and
  ``Game.rgss3a`` (VX Ace). They use simple, publicly documented XOR schemes
  with a rolling 32-bit key; nothing is brute-forced.
* ``Data/Scripts.rxdata`` / ``.rvdata`` / ``.rvdata2`` - a Ruby ``Marshal``
  dump of ``[[id, name, zlib-deflated source], ...]``. The Marshal reader below
  understands exactly the handful of value types that file needs and rejects
  everything else; it never creates Ruby objects, classes or code.
"""
from __future__ import annotations

import struct
from typing import BinaryIO, List, NamedTuple, Tuple

from . import limits
from .rpyc import inflate

MAGIC = b"RGSSAD\0"
MAX_ENTRIES = 50_000
MAX_NAME = 1024
MAX_SCRIPTS = 20_000
MAX_SCRIPT = 16 * 1024 * 1024          # one inflated script
MAX_SCRIPTS_TOTAL = 64 * 1024 * 1024   # all inflated scripts of one file
_MASK = 0xFFFFFFFF


class RgssError(ValueError):
    """The archive / scripts file is damaged, unsupported or over a limit."""


class Entry(NamedTuple):
    name: str          # path inside the archive, forward slashes
    offset: int
    size: int
    key: int           # XOR key the file's data starts with


# -- archives -------------------------------------------------------------------------
def _u32(stream: BinaryIO) -> int:
    raw = stream.read(4)
    if len(raw) != 4:
        raise RgssError("unexpected end of archive")
    return struct.unpack("<I", raw)[0]


def _size_of(stream: BinaryIO) -> int:
    here = stream.tell()
    stream.seek(0, 2)
    end = stream.tell()
    stream.seek(here)
    return end


def list_archive(stream: BinaryIO, lenient: bool = False) -> List[Entry]:
    """Table of contents of an RGSSAD archive (versions 1 and 3).

    A version 1 archive has no index and no end mark - it simply ends with
    the file. ``lenient`` is for an archive found *inside* other data (an
    installer's payload): the first entry that makes no sense is taken as
    the end, as long as at least one entry was read before it."""
    stream.seek(0)
    header = stream.read(8)
    if header[:7] != MAGIC:
        raise RgssError("not an RGSSAD archive")
    total = _size_of(stream)
    version, entries = header[7], []
    if version == 1:                               # XP (.rgssad) and VX (.rgss2a)
        key = 0xDEADCAFE
        while stream.tell() < total and len(entries) < MAX_ENTRIES:
            try:
                length = _u32(stream) ^ key
                key = (key * 7 + 3) & _MASK
                if length > MAX_NAME:
                    # (behind an archive that lies inside another file this is simply its end)
                    raise RgssError("file name too long" if lenient and entries else limits.hit(
                        "rgss", "file name too long (more than %d bytes)" % MAX_NAME))
                raw = bytearray(stream.read(length))
                if len(raw) != length:
                    raise RgssError("unexpected end of archive")
                for i in range(length):
                    raw[i] ^= key & 0xFF
                    key = (key * 7 + 3) & _MASK
                size = _u32(stream) ^ key
                key = (key * 7 + 3) & _MASK
                offset = stream.tell()
                if offset + size > total:
                    raise RgssError("entry runs past the end of the archive")
                if lenient and (not raw or any(b < 0x20 for b in raw)):
                    raise RgssError("not a file name")
            except RgssError:
                if lenient and entries:
                    break
                raise
            entries.append(Entry(raw.decode("utf-8", "replace").replace("\\", "/"),
                                 offset, size, key))
            stream.seek(offset + size)
    elif version == 3:                             # VX Ace (.rgss3a)
        key = (_u32(stream) * 9 + 3) & _MASK
        while len(entries) < MAX_ENTRIES:
            offset, size, file_key, length = (_u32(stream) ^ key for _ in range(4))
            if offset == 0:
                break
            if length > MAX_NAME:
                limits.hit("rgss", "a file name longer than %d bytes" % MAX_NAME)
            if length > MAX_NAME or offset + size > total:
                raise RgssError("damaged archive index")
            raw = bytearray(stream.read(length))
            if len(raw) != length:
                raise RgssError("unexpected end of archive")
            for i in range(length):
                raw[i] ^= (key >> (8 * (i % 4))) & 0xFF
            entries.append(Entry(raw.decode("utf-8", "replace").replace("\\", "/"),
                                 offset, size, file_key))
    else:
        raise RgssError("unsupported RGSSAD version %d" % version)
    if len(entries) >= MAX_ENTRIES:
        limits.hit("rgss", "more than %d entries: the rest was not read" % MAX_ENTRIES)
    return entries


def _xor_next(data: bytes, key: int) -> Tuple[bytes, int]:
    """``data`` XOR the rolling key (one key value per 4-byte word), and the
    key for what follows."""
    n = len(data)
    stream = bytearray((n + 3) // 4 * 4)
    for i in range(0, len(stream), 4):
        struct.pack_into("<I", stream, i, key)
        key = (key * 7 + 3) & _MASK
    out = (int.from_bytes(data, "little")
           ^ int.from_bytes(stream[:n], "little")).to_bytes(n, "little") if n else b""
    return out, key


def _xor(data: bytes, key: int) -> bytes:
    return _xor_next(data, key)[0]


def read_entry(stream: BinaryIO, entry: Entry, limit: int) -> bytes:
    """Decrypted content of one archive member (RgssError if over ``limit``)."""
    if entry.size > limit:
        raise RgssError("member larger than the %d MB limit" % (limit >> 20))
    stream.seek(entry.offset)
    data = stream.read(entry.size)
    if len(data) != entry.size:
        raise RgssError("unexpected end of archive")
    return _xor(data, entry.key)


def entry_pieces(stream: BinaryIO, entry: Entry, chunk: int = 4 * 1024 * 1024):
    """Decrypted content of one archive member, piece by piece (any size).
    The key advances once per 4-byte word, so pieces are cut on word bounds."""
    stream.seek(entry.offset)
    key, left = entry.key, entry.size
    while left > 0:
        raw = stream.read(min(left, chunk))
        if not raw:
            raise RgssError("unexpected end of archive")
        left -= len(raw)
        piece, key = _xor_next(raw, key)
        yield piece


def encrypt_for_tests(data: bytes, key: int) -> bytes:
    """The cipher is its own inverse; exposed so tests can build archives."""
    return _xor(data, key)


# -- Ruby Marshal (the subset a scripts file uses) ----------------------------------------
class _Marshal:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0
        self.objects: list = []           # for "@" object links
        self.symbols: List[bytes] = []
        self.budget = 400_000             # values read, in total

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise RgssError("truncated Marshal data")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def integer(self) -> int:
        c = struct.unpack("b", self.take(1))[0]
        if c == 0:
            return 0
        if 0 < c < 5:
            return int.from_bytes(self.take(c), "little")
        if -5 < c < 0:
            return int.from_bytes(self.take(-c), "little") - (1 << (8 * -c))
        return c - 5 if c > 0 else c + 5

    def symbol(self) -> bytes:
        kind = self.take(1)
        if kind == b":":
            name = self.take(self.integer())
            self.symbols.append(name)
            return name
        if kind == b";":
            index = self.integer()
            if not 0 <= index < len(self.symbols):
                raise RgssError("bad symbol link")
            return self.symbols[index]
        raise RgssError("expected a symbol")

    def value(self, depth: int = 0):
        self.budget -= 1
        if depth > 4 or self.budget < 0:
            raise RgssError("Marshal data is nested too deeply or too large")
        kind = self.take(1)
        if kind == b"0":
            return None
        if kind in (b"T", b"F"):
            return kind == b"T"
        if kind == b"i":
            return self.integer()
        if kind == b"l":                                   # bignum (large script ids)
            sign = self.take(1)
            number = int.from_bytes(self.take(2 * self.integer()), "little")
            self.objects.append(number)
            return -number if sign == b"-" else number
        if kind == b'"':
            text = self.take(self.integer())
            self.objects.append(text)
            return text
        if kind == b"I":                                   # a string with its encoding
            inner = self.value(depth + 1)
            count = self.integer()
            if not isinstance(inner, bytes) or not 0 <= count <= 8:
                raise RgssError("unsupported instance variables")
            for _ in range(count):
                self.symbol()
                self.value(depth + 1)
            return inner
        if kind == b"[":
            count = self.integer()
            if count > MAX_SCRIPTS:
                raise RgssError(limits.hit("rgss-scripts", "a list of more than %d items" % MAX_SCRIPTS))
            if count < 0:
                raise RgssError("array too large")
            items: list = []
            self.objects.append(items)
            for _ in range(count):
                items.append(self.value(depth + 1))
            return items
        if kind == b"@":
            index = self.integer()
            if not 0 <= index < len(self.objects):
                raise RgssError("bad object link")
            return self.objects[index]
        if kind == b":" or kind == b";":
            self.pos -= 1
            return self.symbol()
        raise RgssError("unsupported Marshal type %r" % kind)   # objects, classes, floats...


def marshal_strings(data: bytes, limit: int = 50_000) -> List[str]:
    """The text strings of a Ruby Marshal data file (a map, the common
    events), exactly as they are stored and in the order of the file - the
    lines of an event's "Script" command follow each other. They are found by
    their type byte and length prefix; no object is rebuilt, nothing is run.
    (The printable-string search used otherwise glues the length byte and
    whatever follows onto each line.) A stray quote byte in binary data can
    yield a wrong string or hide a real one, so callers that lower a severity
    on what they read here must check it against the raw data."""
    out: List[str] = []
    i, n = 0, len(data)
    while len(out) < limit:
        j = data.find(b'"', i)
        if j < 0 or j + 2 > n:
            break
        i = j + 1
        c = data[j + 1]
        if c == 0 or c >= 0x80:
            continue                                        # empty, or a negative length
        if c < 5:
            length, start = int.from_bytes(data[j + 2:j + 2 + c], "little"), j + 2 + c
        else:
            length, start = c - 5, j + 2
        if not 1 <= length <= 65536 or start + length > n:
            continue
        try:
            text = data[start:start + length].decode("utf-8")
        except UnicodeDecodeError:
            continue
        if any(ch < " " and ch not in "\t\r\n" for ch in text):
            continue
        out.append(text)
        i = start + length
    return out


def load_scripts(data: bytes) -> List[Tuple[str, str]]:
    """``[(script name, Ruby source)]`` from a Scripts data file.

    Raises :class:`RgssError` for anything that is not the expected shape.
    Each script's source is inflated with a hard size limit.
    """
    return _scripts(data)[0]


def scripts_extent(data: bytes) -> int:
    """Number of bytes at the start of ``data`` that form a script table
    (:class:`RgssError` if there is none). For finding a ``Scripts`` file
    inside other data."""
    return _scripts(data)[1]


def _scripts(data: bytes) -> Tuple[List[Tuple[str, str]], int]:
    if data[:2] != b"\x04\x08":
        raise RgssError("not Ruby Marshal 4.8 data")
    reader = _Marshal(data)
    reader.pos = 2
    table = reader.value()
    if not isinstance(table, list):
        raise RgssError("not a script table")
    out: List[Tuple[str, str]] = []
    total = 0
    for row in table:
        if not (isinstance(row, list) and len(row) >= 3 and isinstance(row[1], bytes)
                and isinstance(row[2], bytes)):
            raise RgssError("not a script table")
        source = inflate(row[2], MAX_SCRIPT)
        if source is None:
            raise RgssError(limits.hit("rgss-scripts", "a script could not be decompressed within the size limit (%d MB)" % (MAX_SCRIPT >> 20)))
        total += len(source)
        if total > MAX_SCRIPTS_TOTAL:
            raise RgssError(limits.hit("rgss-scripts", "scripts exceed the total size limit (%d MB)" % (MAX_SCRIPTS_TOTAL >> 20)))
        out.append((row[1].decode("utf-8", "replace"), source.decode("utf-8", "replace")))
    return out, reader.pos
