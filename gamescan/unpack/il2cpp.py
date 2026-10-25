"""Unity IL2CPP: reader for ``global-metadata.dat`` (standard library only).

An IL2CPP game has no managed assemblies to inspect: the C# code was turned
into native code (``GameAssembly.dll``). What remains readable is this
metadata file, which the runtime needs to name things: every string literal
the code uses, and the names of all assemblies, types and methods.

The file is a header of table locations followed by the tables. Two header
styles exist - ``(offset, size)`` pairs up to Unity 2022, ``(offset, size,
count)`` triples in Unity 6 - and the records of most tables changed size
from version to version (Unity 6 packs indexes into fewer bytes). So only
what is stable is relied on:

* the string-literal table and its data, the identifier heap (NUL-terminated
  UTF-8), and the *position* of the method, type and image tables in the
  header;
* a record starts with the index of its name in the identifier heap.

Everything else is *found and checked*: record sizes are the ones for which
every record's name index really points at the start of a string; the
fields that tie images to their types and types to their methods are the
ones that tile the whole table without a gap. A file that does not pass
these checks (a newer layout, or an obfuscated / encrypted metadata file) is
reported as such instead of being half-read.
"""
from __future__ import annotations

import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

from . import limits

MAGIC = b"\xaf\x1b\xb1\xfa"
_METHODS, _TYPES, _IMAGES_FROM = 5, 19, 20
_MAX_LITERALS = 2_000_000
_MAX_LITERAL = 64 * 1024
_PINVOKE = 0x2000                    # MethodAttributes.PinvokeImpl


class Il2CppError(ValueError):
    """Not IL2CPP metadata, or a layout this reader does not recognise."""


class Image(NamedTuple):
    name: str                        # "Assembly-CSharp.dll"
    types: List[str]                 # "Namespace.Type"
    methods: List[str]               # "Namespace.Type::Method"
    pinvoke: List[str]               # methods implemented by a native library


class Metadata(NamedTuple):
    version: int
    literals: List[str]
    images: List[Image]
    identifiers: int                 # strings in the identifier heap
    notes: List[str]                 # what could not be related (names are still listed)


def _columns(records: List[bytes], total: int, widths=(4, 2)) -> Optional[Tuple[int, int, int, int]]:
    """Find the (start, count) pair of fields whose ranges tile ``0 .. total``
    exactly - no gap, no overlap, in whatever order the records come:
    ``(start offset, start width, count offset, count width)``. Records with a
    count of 0 may hold anything in their start field."""
    if not records:
        return None
    size = len(records[0])
    sample = records[:48]

    def ranges(rows, a, wa, b, wb):
        out = []
        for row in rows:
            count = int.from_bytes(row[b:b + wb], "little")
            if count:
                out.append((int.from_bytes(row[a:a + wa], "little"), count))
        return out

    for wa in widths:
        for a in range(0, size - wa + 1):
            for wb in widths:
                for b in range(0, size - wb + 1):
                    if a <= b < a + wa or b <= a < b + wb:
                        continue
                    # cheap look at a few records first: inside the table, no overlap
                    at, fits = -1, True
                    for start, count in sorted(ranges(sample, a, wa, b, wb)):
                        if start < at or start + count > total:
                            fits = False
                            break
                        at = start + count
                    if not fits or at < 0:
                        continue
                    at = 0
                    for start, count in sorted(ranges(records, a, wa, b, wb)):
                        if start != at:
                            at = -1
                            break
                        at += count
                    if at == total:
                        return a, wa, b, wb
    return None


class _File:
    def __init__(self, data: bytes) -> None:
        if data[:4] != MAGIC or len(data) < 264:
            raise Il2CppError("not IL2CPP metadata")
        self.data = data
        self.version = struct.unpack_from("<i", data, 4)[0]
        first = struct.unpack_from("<3I", data, 8)
        triples = first[1] == 4 * first[2] and first[0] >= 100     # Unity 6 header
        step = 3 if triples else 2
        end = first[0]
        if not 8 + 4 * step * 20 <= end <= min(len(data), 4096):
            raise Il2CppError("implausible header")
        words = struct.unpack_from("<%dI" % ((end - 8) // 4), data, 8)
        self.tables: List[Tuple[int, int, int]] = []
        for i in range(0, len(words) - step + 1, step):
            offset, size = words[i], words[i + 1]
            if offset + size > len(data):
                raise Il2CppError("a table lies outside the file")
            self.tables.append((offset, size, words[i + 2] if triples else 0))
        self.triples = triples
        offset, size, _count = self.tables[2]
        self.strings = data[offset:offset + size]

    def name(self, index: int) -> str:
        end = self.strings.find(b"\0", index)
        return self.strings[index:end if end >= 0 else len(self.strings)].decode("utf-8", "replace")

    def starts_string(self, index: int) -> bool:
        return 0 <= index < len(self.strings) and (index == 0 or self.strings[index - 1] == 0)

    def literals(self) -> List[str]:
        offset, size, _count = self.tables[0]
        base, data_size, _ = self.tables[1]
        blob = self.data[base:base + data_size]
        out: List[str] = []
        if self.triples:                                    # offsets; a literal ends at the next
            marks = struct.unpack_from("<%dI" % (size // 4), self.data, offset)
            spans = zip(marks, marks[1:])
        else:                                               # (length, offset)
            pairs = struct.unpack_from("<%dI" % (size // 4), self.data, offset)
            spans = ((at, at + length) for length, at in zip(pairs[0::2], pairs[1::2]))
        for start, stop in spans:
            if len(out) >= _MAX_LITERALS:
                limits.hit("il2cpp", "more than %d texts: the rest was not read" % _MAX_LITERALS)
                break
            if 0 <= start < stop <= len(blob):
                if stop - start > _MAX_LITERAL:
                    limits.hit("il2cpp", "a text longer than %d KB: only its start was read" % (_MAX_LITERAL >> 10))
                out.append(blob[start:min(stop, start + _MAX_LITERAL)].decode("utf-8", "replace"))
        return out

    def records(self, table: int, sizes) -> List[bytes]:
        """The table cut into records whose first field is a valid name index."""
        offset, size, count = self.tables[table]
        if count:
            sizes = [size // count] if size % count == 0 else []
        for record in sizes:
            if record < 8 or size % record or not size:
                continue
            rows = [self.data[offset + i:offset + i + record] for i in range(0, size, record)]
            if all(self.starts_string(struct.unpack_from("<I", row)[0]) for row in rows):
                return rows
        return []


def parse(data: bytes) -> Metadata:
    """Everything readable in a ``global-metadata.dat``."""
    try:
        return _parse(data)
    except (struct.error, IndexError) as exc:
        raise Il2CppError("damaged metadata (%s)" % exc)


def _parse(data: bytes) -> Metadata:
    f = _File(data)
    if len(f.tables) <= _IMAGES_FROM:
        raise Il2CppError("too few tables")
    notes: List[str] = []
    literals = f.literals()
    types = f.records(_TYPES, range(60, 160, 4))
    methods = f.records(_METHODS, (32, 36, 40, 44, 48, 52, 56, 28, 30))
    if types and not all(f.starts_string(struct.unpack_from("<I", row, 4)[0]) for row in types):
        types = []
    type_names = []
    for row in types:
        name, namespace = struct.unpack_from("<II", row)
        type_names.append((f.name(namespace) + "." if f.name(namespace) else "") + f.name(name))
    method_names = [f.name(struct.unpack_from("<I", row)[0]) for row in methods]
    if not types:
        notes.append("type table not recognised")
    if not methods:
        notes.append("method table not recognised")
    # which methods belong to which type: the (first method, method count) fields
    owner: List[int] = [-1] * len(methods)
    span = _columns(types, len(methods)) if types and methods else None
    if span:
        a, wa, b, wb = span
        for index, row in enumerate(types):
            count = int.from_bytes(row[b:b + wb], "little")
            if count:
                start = int.from_bytes(row[a:a + wa], "little")
                owner[start:start + count] = [index] * count
    elif types and methods:
        notes.append("methods could not be related to their types")
    # methods that are implemented by a native library (P/Invoke)
    native = set()
    if methods:
        at = len(methods[0]) - 8                            # flags, iflags, slot, parameter count
        flags = [struct.unpack_from("<H", row, at)[0] for row in methods]
        if all(flag & 7 <= 6 for flag in flags) and sum(1 for flag in flags if flag & _PINVOKE) \
                <= len(flags) // 4:
            native = {i for i, flag in enumerate(flags) if flag & _PINVOKE}
        else:
            notes.append("method flags not recognised (P/Invoke methods are not marked)")
    # images (assemblies): the table whose names end in .dll and whose type ranges tile the types
    images: List[Image] = []
    for table in range(_IMAGES_FROM, min(len(f.tables), _IMAGES_FROM + 8)):
        rows = f.records(table, (40, 32, 24, 28, 36, 44, 48))
        named = sum(1 for row in rows if f.name(struct.unpack_from("<I", row)[0]).lower().endswith(
            (".dll", ".exe", ".winmd")))
        if not rows or named * 5 < len(rows) * 4:           # (newer builds add "__Generated")
            continue
        span = _columns(rows, len(types), (4, 2)) if types else None
        for row in rows:
            name = f.name(struct.unpack_from("<I", row)[0])
            members: List[int] = []
            if span:
                a, wa, b, wb = span
                start = int.from_bytes(row[a:a + wa], "little")
                members = list(range(start, start + int.from_bytes(row[b:b + wb], "little")))
            wanted = set(members)
            mine = [i for i, t in enumerate(owner) if t in wanted] if wanted else []
            images.append(Image(
                name, [type_names[i] for i in members],
                ["%s::%s" % (type_names[owner[i]], method_names[i]) for i in mine],
                ["%s::%s" % (type_names[owner[i]], method_names[i]) for i in mine if i in native]))
        if not span and types:
            notes.append("types could not be related to their assemblies")
        break
    if not images:
        notes.append("assembly table not recognised")
        images = [Image("", type_names,
                        ["%s::%s" % (type_names[t] if t >= 0 else "?", n)
                         for t, n in zip(owner, method_names)],
                        ["%s::%s" % (type_names[owner[i]] if owner[i] >= 0 else "?", method_names[i])
                         for i in sorted(native)])]
    return Metadata(f.version, literals, images, f.strings.count(b"\0"), notes)
