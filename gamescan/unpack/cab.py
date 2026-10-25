"""Microsoft Cabinet (``MSCF``) reader, including self-extracting executables.

Many RPG Maker XP / VX games are distributed as one ``.exe`` that is a small
extractor stub with a cabinet behind it; the game (``Game.rgssad``, the RGSS
DLL, ...) only appears on disk once that program has been *run*. This module
reads the cabinet in place so the game can be inspected first.

One reader, :func:`members`, pure Python: cabinets that are stored,
MSZIP-compressed (deflate is in the standard library) or LZX-compressed (the
project's own decoder, :mod:`.lzx`); Quantum raises :class:`NeedTool`. Until
2026-10-19 Windows' own ``cabinet.dll`` (FDI) read every cabinet on Windows; no
Windows program reads a scanned file's cabinet any more (phageo, 2026-10-19).
"""
from __future__ import annotations

import io
import re
import struct
import zlib
from typing import BinaryIO, Callable, Dict, Iterator, List, Optional, Tuple

from . import limits, lzx, spool

MAGIC = b"MSCF"
_HEADER = struct.Struct("<4sIIIIIBBHHHHH")       # CFHEADER without the optional parts
_MSCF = re.compile(re.escape(MAGIC))
_COPY_FILE, _CLOSE_FILE_INFO, _NEXT_CABINET = 2, 3, 4
_NAME_IS_UTF = 0x80


class CabError(ValueError):
    """The cabinet is damaged, unsupported or cannot be read on this system."""


class NeedTool(CabError):
    """Valid cabinet, but its compression is not in the standard library."""


def cabinet_size(header: bytes) -> int:
    """Total size a cabinet header declares, or 0 if it is not a plausible header."""
    if len(header) < _HEADER.size:
        return 0
    (magic, res1, size, res2, files_at, res3, minor, major, folders, files,
     _flags, _set, _index) = _HEADER.unpack_from(header)
    if (magic != MAGIC or res1 or res2 or res3 or (major, minor) != (1, 3)
            or not folders or not files or not _HEADER.size <= files_at < size):
        return 0
    return size


def find(data: bytes, total: Optional[int] = None, limit: int = 4) -> List[Tuple[int, int]]:
    """``(offset, size)`` of each cabinet embedded in ``data``.

    ``total`` is the real size of the file when ``data`` is only its beginning.
    """
    total = len(data) if total is None else total
    out: List[Tuple[int, int]] = []
    end = 0
    for m in _MSCF.finditer(data):
        pos = m.start()
        if pos < end:                              # inside the cabinet found before
            continue
        size = cabinet_size(data[pos:pos + _HEADER.size])
        if size and pos + size <= total:
            out.append((pos, size))
            end = pos + size
            if len(out) >= limit:
                break
    return out


class Window(io.RawIOBase):
    """Read-only view of ``size`` bytes of ``base`` starting at ``start``."""

    def __init__(self, base: BinaryIO, start: int, size: int) -> None:
        super().__init__()
        self.base, self.start, self.size, self.pos = base, start, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        left = max(0, self.size - self.pos)
        n = left if n is None or n < 0 else min(n, left)
        self.base.seek(self.start + self.pos)
        data = self.base.read(n)
        self.pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = max(0, offset + (0, self.pos, self.size)[whence])
        return self.pos

    def tell(self) -> int:
        return self.pos

    def close(self) -> None:
        if not self.closed:
            self.base.close()
        super().close()


# -- pure Python (stored / MSZIP / LZX) ---------------------------------------------------
_METHODS = {2: "Quantum", 3: "LZX"}
_MAX_FILES = 65535
MAX_LZX_OUT = 1 << 30                  # decoded from one LZX folder (pure Python: 5-8 MB/s measured, 2026-10-19)
CHECKSUM_NOTE = ("an LZX data block does not match its checksum (block %d of %d; the cabinet may be damaged "
                 "or altered): it was decoded and scanned all the same")


def _need(stream: BinaryIO, count: int) -> bytes:
    data = stream.read(count)
    if len(data) != count:
        raise CabError("cabinet is cut short")
    return data


def _name(stream: BinaryIO) -> bytes:
    out = bytearray()
    while len(out) < 512:
        b = _need(stream, 1)
        if b == b"\0":
            return bytes(out)
        out += b
    raise CabError("unterminated name")


def methods(stream: BinaryIO) -> List[str]:
    """The compression of each folder of the cabinet ("stored", "MSZIP", "Quantum", "LZX" or
    "method N"), from its header - nothing is decompressed. ``stream`` starts at ``MSCF``."""
    stream.seek(0)
    (magic, _r1, _size, _r2, _files_at, _r3, _minor, _major, folder_count, _file_count,
     flags, _set, _index) = _HEADER.unpack(_need(stream, _HEADER.size))
    if magic != MAGIC:
        raise CabError("not a cabinet")
    folder_extra = 0
    if flags & 0x04:
        header_extra, folder_extra, _data_extra = struct.unpack("<HBB", _need(stream, 4))
        _need(stream, header_extra)
    if flags & 0x03:
        raise NeedTool("the other cabinet files (the archive is split into parts)")
    out = []
    for _ in range(folder_count):
        _start, _blocks, method = struct.unpack("<IHH", _need(stream, 8))
        _need(stream, folder_extra)
        method &= 0x0F
        out.append({0: "stored", 1: "MSZIP"}.get(method) or _METHODS.get(method, "method %d" % method))
    return out


def members(stream: BinaryIO, want: Callable[[str, int], bool],
            memory: Optional[int] = None,
            notes: Optional[List[str]] = None) -> Iterator[Tuple[str, bytes]]:
    """``(name, data)`` of the members ``want(name, size)`` accepts.
    ``stream`` must start at the ``MSCF`` header. ``memory``: members are kept in memory
    up to this size (``spool.MEMORY`` by default; a larger one continues in a temporary
    file) - a caller that wants nothing written refuses larger members in ``want``.
    ``notes`` receives what the caller must say although the members were read (an LZX
    data block that does not match its checksum - decoded anyway, phageo 2026-10-19)."""
    stream.seek(0)
    (magic, _r1, _size, _r2, files_at, _r3, _minor, _major, folder_count, file_count,
     flags, _set, _index) = _HEADER.unpack(_need(stream, _HEADER.size))
    if magic != MAGIC:
        raise CabError("not a cabinet")
    header_extra = folder_extra = data_extra = 0
    if flags & 0x04:
        header_extra, folder_extra, data_extra = struct.unpack("<HBB", _need(stream, 4))
        _need(stream, header_extra)
    if flags & 0x03:
        raise NeedTool("the other cabinet files (the archive is split into parts)")
    folders = []
    for _ in range(folder_count):
        start, blocks, method = struct.unpack("<IHH", _need(stream, 8))
        _need(stream, folder_extra)
        folders.append((start, blocks, method))
    stream.seek(files_at)
    files: Dict[int, List[Tuple[int, int, str]]] = {}
    if file_count > _MAX_FILES:
        limits.hit("cab", "more than %d files: the rest was not read" % _MAX_FILES)
    for _ in range(min(file_count, _MAX_FILES)):
        size, offset, folder, _date, _time, attribs = struct.unpack("<IIHHHH", _need(stream, 16))
        raw = _name(stream)
        name = raw.decode("utf-8" if attribs & _NAME_IS_UTF else "cp1252", "replace")
        if folder < len(folders) and want(name.replace("\\", "/"), size):
            files.setdefault(folder, []).append((offset, size, name.replace("\\", "/")))
    for index, wanted in sorted(files.items()):
        start, blocks, method = folders[index]
        if method & 0x0F not in (0, 1, 3):
            raise NeedTool("%s decompression" % _METHODS.get(method & 0x0F, "an unknown method's"))
        wanted.sort()
        parts = [spool.Collector(memory) for _ in wanted]
        stream.seek(start)
        at, first = 0, 0
        frames = _lzx_frames(stream, blocks, data_extra, method, notes) if method & 0x0F == 3 \
            else _frames(stream, blocks, data_extra, method & 0x0F)
        for raw in frames:
            if first >= len(wanted):
                break
            end = at + len(raw)
            for i in range(first, len(wanted)):
                offset, size, _name_ = wanted[i]
                if offset >= end:
                    break
                lo, hi = max(offset, at), min(offset + size, end)
                if hi > lo:
                    parts[i].write(raw[lo - at:hi - at])
            while first < len(wanted) and wanted[first][0] + wanted[first][1] <= end:
                offset, size, name = wanted[first]
                if parts[first].size != size:
                    raise CabError("member is cut short")
                done, parts[first] = parts[first].result(), None    # (not held while the rest is read)
                yield name, done
                first += 1
            at = end
        if first < len(wanted):
            raise CabError("member is cut short")


def _frames(stream: BinaryIO, blocks: int, data_extra: int, method: int) -> Iterator[bytes]:
    """The output of each data block of a stored (0) or MSZIP (1) folder."""
    previous = b""
    for _ in range(blocks):
        _checksum, packed, unpacked = struct.unpack("<IHH", _need(stream, 8))
        _need(stream, data_extra)
        raw = _need(stream, packed)
        if method == 1:                                 # MSZIP: "CK" + deflate, shared window
            if raw[:2] != b"CK":
                raise CabError("damaged MSZIP block")
            try:
                inflater = zlib.decompressobj(-15, zdict=previous) if previous \
                    else zlib.decompressobj(-15)
                raw = inflater.decompress(raw[2:], 32768)
            except zlib.error as exc:
                raise CabError("damaged MSZIP block (%s)" % exc)
            previous = raw
        if len(raw) != unpacked:
            raise CabError("block size does not match")
        yield raw


def _checksum(data: bytes, seed: int = 0) -> int:
    """The cabinet checksum: the 32-bit little-endian words XORed together, the last one to
    three bytes taken first byte highest (as cabinet.dll computes it); 0 in a block = none."""
    whole = len(data) & ~3
    value, width = int.from_bytes(data[:whole], "little"), whole * 8
    while width > 32:                                   # fold the halves onto each other
        half = (width // 64 + (width % 64 != 0)) * 32
        value = (value & ((1 << half) - 1)) ^ (value >> half)
        width = half
    tail = 0
    for byte in data[whole:]:
        tail = tail << 8 | byte
    return seed ^ value ^ tail


def _lzx_frames(stream: BinaryIO, blocks: int, data_extra: int, method: int,
                notes: Optional[List[str]] = None) -> Iterator[bytes]:
    """The output of each data block of an LZX folder (``lzx.Decoder``; the window size is in
    bits 8-12 of the method). Each block's checksum is checked: a block that does not match
    is decoded all the same - never skipped - and said once per folder in ``notes`` (phageo,
    2026-10-19; without ``notes``, as a reader's limit). At most :data:`MAX_LZX_OUT` bytes of
    one folder are decoded, whatever the checksums say."""
    sizes: List[int] = []
    wrong: List[int] = []

    def chunks() -> Iterator[bytes]:
        for number in range(blocks):
            head = _need(stream, 8)
            stated, packed, unpacked = struct.unpack("<IHH", head)
            _need(stream, data_extra)
            sizes.append(unpacked)
            data = _need(stream, packed)
            # a damaged (or altered) block decodes to other bytes in silence: its checksum says so
            if stated and _checksum(head[4:], _checksum(data)) != stated:
                if not wrong:
                    text = CHECKSUM_NOTE % (number + 1, blocks)
                    if notes is None:
                        limits.hit("cab", text)
                    else:
                        notes.append(text)
                wrong.append(number)
            yield data

    try:
        decoder = lzx.Decoder((method >> 8) & 0x1F, chunks())
        total = 0
        for index in range(blocks):
            while len(sizes) <= index:
                if not decoder.pull():
                    raise CabError("cabinet is cut short")
            total += sizes[index]
            if total > MAX_LZX_OUT:
                raise CabError(limits.hit("cab", "an LZX folder of more than %d MB: the rest was not decoded"
                                          % (MAX_LZX_OUT >> 20)))
            yield decoder.frame(sizes[index])
    except lzx.LzxError as exc:
        raise CabError("damaged LZX data (%s)" % exc)
