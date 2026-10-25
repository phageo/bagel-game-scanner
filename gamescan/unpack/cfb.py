"""Compound files (OLE / CFB): sectors, the FAT and mini FAT, the directory, streams.

A Windows Installer package (MSI, and its patches, transforms and merge modules) is a
compound file: a small file system inside one file. Its sectors are linked into chains by
a table (the FAT); streams under 4 KB live in a second, smaller sector size (the mini
stream, linked by the mini FAT); a directory of 128-byte entries names every stream and
storage (a folder of streams) in a tree. ``msi.py`` reads the installer database out of it
(phageo, 2026-10-17: build it - part 1 of 2).

Data only, standard library only: nothing is run, nothing is written to disk. The whole
file may be ``bytes`` in memory or a seekable file (a large file of the scan on disk).
Every chain and every walk is bounded - by the number of sectors the file really has, a
seen set (a chain or a tree that loops), and the named limits below. A damaged file raises
:class:`CfbError`; a limit is said with ``limits.hit`` as well, so that it reaches the
"could not be read" note (``ARC-002``).
"""
from __future__ import annotations

import array
import io
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Dict, List, Optional, Tuple, Union

from . import limits

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_HEADER = struct.Struct("<8s16sHHHHH6sIIIIIIIII")
_ENTRY = struct.Struct("<64sHBBIII16sIQQIQ")
END, FREE = 0xFFFFFFFE, 0xFFFFFFFF
_LAST_REGULAR = 0xFFFFFFFA                 # a sector number above it is a mark, not a sector
_NO_ENTRY = 0xFFFFFFFF
STORAGE, STREAM, ROOT = 1, 2, 5
_MINI_SHIFT, _MINI_CUTOFF = 6, 4096        # the only values the format allows
_HEADER_DIFAT = 109                        # FAT sector numbers in the header itself

_MAX_SECTORS = 1 << 23                     # sectors the FAT may describe (4 GiB of 512 bytes)
_MAX_ENTRIES = 1 << 16                     # directory entries
_MAX_DEPTH = 32                            # storages inside storages
MAX_STREAM = 1 << 30                       # the largest stream :meth:`CompoundFile.stream` gives


class CfbError(ValueError):
    """Not a compound file, or one that is damaged."""


@dataclass
class Entry:
    """One stream or storage of the directory."""

    index: int
    name: str                              # as stored (an MSI name is still encoded)
    kind: int                              # STORAGE, STREAM or ROOT
    start: int                             # first sector (of the mini stream, for a small stream)
    size: int
    clsid: bytes
    parent: int = -1                       # index of the storage it lies in (-1: the root itself)
    depth: int = 0
    children: List[int] = field(default_factory=list)
    links: Tuple[int, int, int] = (_NO_ENTRY, _NO_ENTRY, _NO_ENTRY)   # left, right, child in the tree


class _Source:
    """``read(offset, count)`` over bytes in memory or a seekable file."""

    def __init__(self, data: Union[bytes, bytearray, memoryview, BinaryIO], size: Optional[int] = None) -> None:
        if isinstance(data, (bytes, bytearray, memoryview)):
            self.data, self.stream = memoryview(data), None
            self.size = len(data)
        else:
            self.data, self.stream = None, data
            if size is None:
                data.seek(0, 2)
                size = data.tell()
            self.size = size

    def read(self, offset: int, count: int) -> bytes:
        if self.data is not None:
            return bytes(self.data[offset:offset + count])
        self.stream.seek(offset)
        return self.stream.read(count)


class CompoundFile:
    """The directory of a compound file and its streams, read on demand.

    ``entries`` holds the entries reachable from the root, the root first, then depth
    first; ``children`` of an entry are in the order of the stored tree."""

    def __init__(self, data: Union[bytes, bytearray, memoryview, BinaryIO], size: Optional[int] = None) -> None:
        self._src = _Source(data, size)
        head = self._src.read(0, 512)
        if len(head) < 512 or head[:8] != MAGIC:
            raise CfbError("not a compound file")
        (_magic, _clsid, _minor, self.version, order, shift, mini_shift, _reserved, _dir_sectors,
         fat_sectors, first_dir, _transaction, cutoff, first_mini, mini_sectors, first_difat,
         difat_sectors) = _HEADER.unpack_from(head)
        if order != 0xFFFE or (self.version, shift) not in ((3, 9), (4, 12)) \
                or mini_shift != _MINI_SHIFT or cutoff != _MINI_CUTOFF:
            raise CfbError("a compound file of a form that is not known (version %d, sector shift %d)"
                           % (self.version, shift))
        self.sector = 1 << shift
        # sectors that lie in the file (a last sector cut short counts: it is read as it is)
        self.sectors = max(0, (self._src.size + self.sector - 1) // self.sector - 1)
        per = self.sector // 4
        if fat_sectors > self.sectors or mini_sectors > self.sectors:
            raise CfbError("the file says it has more table sectors than it holds")
        if fat_sectors * per > _MAX_SECTORS:
            raise CfbError(limits.hit("cfb", "a table of more than %d sectors" % _MAX_SECTORS))
        # the FAT: its sectors are named by the header, then by the DIFAT chain
        fat_at = list(struct.unpack_from("<109I", head, 0x4C))
        seen = set()
        difat = first_difat
        while len(fat_at) < fat_sectors + _HEADER_DIFAT and difat not in (END, FREE):
            if difat >= self.sectors or difat in seen or len(seen) >= difat_sectors:
                raise CfbError("the list of table sectors is damaged or loops")
            seen.add(difat)
            numbers = struct.unpack("<%dI" % per, self._sector(difat))
            fat_at.extend(numbers[:-1])
            difat = numbers[-1]
        fat_at = [s for s in fat_at[:fat_sectors + _HEADER_DIFAT] if s != FREE][:fat_sectors]
        if len(fat_at) != fat_sectors:
            raise CfbError("the file names fewer table sectors than it says it has")
        self.fat = array.array("I")
        for sector in fat_at:
            if sector >= self.sectors:
                raise CfbError("a table sector lies outside the file")
            self.fat.frombytes(self._sector(sector))
        if self.fat.itemsize != 4:                                  # (array "I" is 4 bytes here)
            raise CfbError("unsupported platform")
        if struct.pack("=I", 1) != struct.pack("<I", 1):
            self.fat.byteswap()
        # the directory, then the tree from the root
        chain = self._chain(first_dir, self.fat, self.sectors, "directory", _MAX_ENTRIES * 128 // self.sector)
        raw = b"".join(self._sector(s) for s in chain)
        self._raw: Dict[int, Entry] = {}
        for index in range(len(raw) // 128):
            entry = self._entry(raw, index)
            if entry is not None:
                self._raw[index] = entry
        root = self._raw.get(0)
        if root is None or root.kind != ROOT:
            raise CfbError("the directory has no root")
        self.root = root
        self.entries: List[Entry] = []
        self._walk()
        # the mini stream (in the root's chain) and its table
        self.minifat = array.array("I")
        if mini_sectors:
            if mini_sectors * per > _MAX_SECTORS:
                raise CfbError(limits.hit("cfb", "a small-sector table of more than %d sectors" % _MAX_SECTORS))
            for sector in self._chain(first_mini, self.fat, self.sectors, "small-sector table", mini_sectors):
                self.minifat.frombytes(self._sector(sector))
            if struct.pack("=I", 1) != struct.pack("<I", 1):
                self.minifat.byteswap()
        self._mini_chain: Optional[List[int]] = None

    # -- sectors and chains -------------------------------------------------------------
    def _sector(self, number: int) -> bytes:
        data = self._src.read((number + 1) * self.sector, self.sector)
        return data + bytes(self.sector - len(data)) if len(data) < self.sector else data

    @staticmethod
    def _chain(first: int, table: "array.array", sectors: int, what: str, most: int) -> List[int]:
        """The sector numbers of a chain, at most ``most`` of them (a longer chain is cut
        there: the caller asks for no more than it needs)."""
        out: List[int] = []
        seen = set()
        sector = first
        while sector != END and len(out) < most:
            if sector >= sectors or sector >= len(table) or sector > _LAST_REGULAR:
                raise CfbError("the %s's chain points outside the file" % what)
            if sector in seen:
                raise CfbError("the %s's chain loops" % what)
            seen.add(sector)
            out.append(sector)
            sector = table[sector]
        if sector != END and len(out) >= most and what == "directory":
            limits.hit("cfb", "a directory of more than %d entries: the rest was not read" % _MAX_ENTRIES)
        return out

    # -- the directory --------------------------------------------------------------------
    def _entry(self, raw: bytes, index: int) -> Optional[Entry]:
        (name, length, kind, _color, left, right, child, clsid, _state, _made, _changed, start,
         size) = _ENTRY.unpack_from(raw, index * 128)
        if kind not in (STORAGE, STREAM, ROOT):
            return None
        if self.version == 3:
            size &= 0xFFFFFFFF                 # (the upper half of a version-3 size is not used)
        length = min(max(length, 2), 64)
        return Entry(index, name[:length - 2].decode("utf-16-le", "replace").rstrip("\0"), kind, start, size,
                     bytes(clsid), links=(left, right, child))

    def _walk(self) -> None:
        """Every entry reachable from the root, each once (a tree that reaches an entry a
        second time is damaged), depth first; storages deeper than ``_MAX_DEPTH`` are said."""
        seen = {0}
        self.entries.append(self.root)
        todo: List[Tuple[Entry, int]] = [(self.root, 0)]
        while todo:
            storage, depth = todo.pop()
            if depth >= _MAX_DEPTH:
                limits.hit("cfb", "storages nested more than %d deep: the deeper ones were not read" % _MAX_DEPTH)
                continue
            members: List[Entry] = []
            stack = [storage.links[2]]
            while stack:                         # the members of one storage: a binary tree
                index = stack.pop()
                if index == _NO_ENTRY:
                    continue
                entry = self._raw.get(index)
                if entry is None or entry.kind == ROOT:
                    raise CfbError("the directory names an entry that does not exist")
                if index in seen:
                    raise CfbError("the directory loops")
                seen.add(index)
                left, right, _child = entry.links
                stack.extend((right, left))
                members.append(entry)
            members.sort(key=lambda e: (len(e.name), e.name.upper()))   # (the format's own order)
            for entry in members:
                entry.parent, entry.depth = storage.index, depth
                storage.children.append(entry.index)
                self.entries.append(entry)
            for entry in reversed(members):
                if entry.kind == STORAGE:
                    todo.append((entry, depth + 1))

    def entry(self, index: int) -> Entry:
        return self._raw[index]

    def children(self, storage: Optional[Entry] = None) -> List[Entry]:
        return [self._raw[i] for i in (storage or self.root).children]

    def path(self, entry: Entry) -> str:
        """The entry's names from the root down, joined with "/" (the root itself: "")."""
        names = []
        while entry.kind != ROOT:
            names.append(entry.name)
            entry = self._raw[entry.parent]
        return "/".join(reversed(names))

    # -- streams --------------------------------------------------------------------------
    def stream(self, entry: Entry, most: Optional[int] = None) -> bytes:
        """The content of a stream. Raises :class:`CfbError` when its chain is damaged, or
        when it is larger than ``most`` / ``MAX_STREAM`` (said as a limit)."""
        if entry.kind != STREAM:
            raise CfbError("not a stream")
        most = MAX_STREAM if most is None else min(most, MAX_STREAM)
        if entry.size > most:
            raise CfbError(limits.hit("cfb", "a stream of more than %d bytes: not read" % most))
        if entry.size == 0:
            return b""
        if entry.size < _MINI_CUTOFF:
            return self._mini(entry)
        return self._big(entry.start, entry.size, "stream")

    def open(self, entry: Entry, most: Optional[int] = None) -> "io.RawIOBase":
        """A stream as a seekable file, read from the compound file on demand - an embedded
        cabinet of a hundred megabytes is never held whole (phageo, 2026-10-19: part 2). The
        same checks as :meth:`stream`: its chain is followed before anything is read."""
        if entry.kind != STREAM:
            raise CfbError("not a stream")
        most = MAX_STREAM if most is None else min(most, MAX_STREAM)
        if entry.size > most:
            raise CfbError(limits.hit("cfb", "a stream of more than %d bytes: not read" % most))
        if entry.size < _MINI_CUTOFF:
            return io.BytesIO(self.stream(entry))
        if entry.size > (self.sectors + 1) * self.sector:
            raise CfbError("a stream larger than the file")
        need = (entry.size + self.sector - 1) // self.sector
        chain = self._chain(entry.start, self.fat, self.sectors, "stream", need)
        if len(chain) < need:
            raise CfbError("a stream ends before its size")
        return _ChainReader(self, chain, entry.size)

    def _big(self, first: int, size: int, what: str) -> bytes:
        if size > (self.sectors + 1) * self.sector:
            raise CfbError("a %s larger than the file" % what)
        need = (size + self.sector - 1) // self.sector
        chain = self._chain(first, self.fat, self.sectors, what, need)
        if len(chain) < need:
            raise CfbError("a %s ends before its size" % what)
        out = []
        run_start, run = chain[0], 1
        for sector in chain[1:] + [None]:          # neighbouring sectors are read at once
            if sector is not None and sector == run_start + run:
                run += 1
                continue
            out.append(self._src.read((run_start + 1) * self.sector, run * self.sector))
            if sector is not None:
                run_start, run = sector, 1
        data = b"".join(out)[:size]
        if len(data) < size:
            raise CfbError("a %s ends before its size" % what)
        return data

    def _mini(self, entry: Entry) -> bytes:
        if self._mini_chain is None:
            root = self.root
            if root.size > (self.sectors + 1) * self.sector:
                raise CfbError("the small-sector stream is larger than the file")
            need = (root.size + self.sector - 1) // self.sector
            self._mini_chain = self._chain(root.start, self.fat, self.sectors, "small-sector stream", need)
            if len(self._mini_chain) < need:
                raise CfbError("the small-sector stream ends before its size")
        small = 1 << _MINI_SHIFT
        count = (self.root.size + small - 1) // small
        need = (entry.size + small - 1) // small
        chain = self._chain(entry.start, self.minifat, count, "small stream", need)
        if len(chain) < need:
            raise CfbError("a small stream ends before its size")
        per = self.sector // small
        out = []
        for mini in chain:
            big = self._mini_chain[mini // per]
            out.append(self._src.read((big + 1) * self.sector + (mini % per) * small, small))
        data = b"".join(out)[:entry.size]
        if len(data) < entry.size:
            raise CfbError("a small stream ends before its size")
        return data


class _ChainReader(io.RawIOBase):
    """A big stream of a compound file, read sector by sector where it is asked for."""

    def __init__(self, owner: CompoundFile, chain: List[int], size: int) -> None:
        super().__init__()
        self.owner, self.chain, self.size, self.pos = owner, chain, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        left = max(0, self.size - self.pos)
        n = left if n is None or n < 0 else min(n, left)
        out, sector = [], self.owner.sector
        while n > 0:
            index, inside = divmod(self.pos, sector)
            start, run = self.chain[index], 1
            while run * sector - inside < n and index + run < len(self.chain) \
                    and self.chain[index + run] == start + run:      # neighbouring sectors: read at once
                run += 1
            count = min(n, run * sector - inside)
            data = self.owner._src.read((start + 1) * sector + inside, count)
            if len(data) < count:
                raise CfbError("a stream ends before its size")
            out.append(data)
            self.pos += count
            n -= count
        return b"".join(out)

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = max(0, offset + (0, self.pos, self.size)[whence])
        return self.pos

    def tell(self) -> int:
        return self.pos
