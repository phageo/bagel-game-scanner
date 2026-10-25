"""The project's own binary form for the large generated hash tables (phageo, 2026-10-19).

The tables of official files (``engine_hashes``, ``compiled_hashes``, ``library_hashes``,
``electron_official``) were Python text, every SHA-256 as 64 hex characters. With the
added Ren'Py SDKs, libraries and Electron releases they would be many megabytes of text,
so their dictionaries are kept in a file beside the module instead: a SHA-256 as its 32
bytes, every text once. The modules keep their names and their dictionaries keep their
shapes - ``{key: (name, index, ...)}`` -, so nothing that reads them changes.

The format, little-endian throughout::

    MAGIC
    u32 number of texts, then each: u32 length, UTF-8 bytes
    u32 number of tables, then each:
        u32 index of its name (a text), u8 key kind, u32 number of entries,
        then each entry: its key, its value
    key kind 0: 32 raw bytes (a SHA-256, given back as 64 lower-case hex characters)
    key kind 1: u32 index of a text
    value: one tag byte, then N (None) | I i64 | S u32 text index | H 32 raw bytes
           (a SHA-256 given back as hex) | T u32 count and that many values (a tuple)

It is read with ``struct`` only - nothing is unpickled, unmarshalled or run - and every
count is checked against what is left of the file (CLAUDE.md, rules 2 and 3). Written by
the table builders in ``tools/`` (developer's tools); read by the modules that load them.
"""
from __future__ import annotations

import os
import re
import struct
from typing import Dict, List, Tuple

MAGIC = b"GSS-TABLES 1\n"
MAX_FILE = 256 * 1024 * 1024         # one table file
MAX_DEPTH = 8                        # tuples inside tuples
_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_U32 = struct.Struct("<I")
_I64 = struct.Struct("<q")


class TableError(ValueError):
    """The table file is damaged or is not one."""


# -- writing ----------------------------------------------------------------------------------
class _Writer:
    def __init__(self) -> None:
        self.texts: Dict[str, int] = {}

    def text(self, value: str) -> int:
        if value not in self.texts:
            self.texts[value] = len(self.texts)
        return self.texts[value]

    def value(self, value, out: List[bytes], depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise TableError("values nested too deep")
        if value is None:
            out.append(b"N")
        elif isinstance(value, bool):
            raise TableError("a truth value is not a table value")
        elif isinstance(value, int):
            out.append(b"I" + _I64.pack(value))
        elif isinstance(value, str):
            if _HEX.match(value):
                out.append(b"H" + bytes.fromhex(value))
            else:
                out.append(b"S" + _U32.pack(self.text(value)))
        elif isinstance(value, (tuple, list)):
            out.append(b"T" + _U32.pack(len(value)))
            for item in value:
                self.value(item, out, depth + 1)
        else:
            raise TableError("not a table value: %r" % (type(value).__name__,))


def dump(tables: Dict[str, dict]) -> bytes:
    """The bytes of a table file holding ``tables`` (``{name: {key: value}}``), entries in
    the order of each dictionary. Keys are texts; a key that is a SHA-256 in lower-case hex
    in every entry of a table is kept as its 32 bytes."""
    writer = _Writer()
    body: List[bytes] = [_U32.pack(len(tables))]
    for name, table in tables.items():
        hexed = bool(table) and all(isinstance(k, str) and _HEX.match(k) for k in table)
        if not hexed and not all(isinstance(k, str) for k in table):
            raise TableError("table %s: a key is not a text" % name)
        body.append(_U32.pack(writer.text(name)) + bytes((0 if hexed else 1,)) + _U32.pack(len(table)))
        for key, value in table.items():
            body.append(bytes.fromhex(key) if hexed else _U32.pack(writer.text(key)))
            writer.value(value, body)
    head: List[bytes] = [MAGIC, _U32.pack(len(writer.texts))]
    for text in writer.texts:                         # (in the order of their indexes)
        raw = text.encode("utf-8")
        head.append(_U32.pack(len(raw)) + raw)
    return b"".join(head + body)


def write(path: str, tables: Dict[str, dict]) -> int:
    """Write ``tables`` to ``path``; returns its size in bytes."""
    data = dump(tables)
    with open(path, "wb") as fh:
        fh.write(data)
    return len(data)


# -- reading ----------------------------------------------------------------------------------
class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > len(self.data):
            raise TableError("the table file is cut short")
        piece = self.data[self.at:self.at + count]
        self.at += count
        return piece

    def u32(self) -> int:
        return _U32.unpack(self.take(4))[0]

    def count(self, smallest: int) -> int:
        """A count of items of at least ``smallest`` bytes each - never more than fit."""
        number = self.u32()
        if number * smallest > len(self.data) - self.at:
            raise TableError("a count larger than the file")
        return number

    def value(self, texts: List[str], depth: int = 0):
        if depth > MAX_DEPTH:
            raise TableError("values nested too deep")
        tag = self.take(1)
        if tag == b"N":
            return None
        if tag == b"I":
            return _I64.unpack(self.take(8))[0]
        if tag == b"S":
            return self.text(texts)
        if tag == b"H":
            return self.take(32).hex()
        if tag == b"T":
            return tuple(self.value(texts, depth + 1) for _ in range(self.count(1)))
        raise TableError("unknown value kind %r" % tag)

    def text(self, texts: List[str]) -> str:
        index = self.u32()
        if index >= len(texts):
            raise TableError("a text that is not in the file")
        return texts[index]


def loads(data: bytes) -> Dict[str, dict]:
    """``{name: {key: value}}`` of the bytes of a table file."""
    if len(data) > MAX_FILE or not data.startswith(MAGIC):
        raise TableError("not a table file of this project")
    reader = _Reader(data)
    reader.take(len(MAGIC))
    texts = []
    for _ in range(reader.count(4)):
        try:
            texts.append(reader.take(reader.u32()).decode("utf-8"))
        except UnicodeDecodeError:
            raise TableError("a text is not UTF-8")
    tables: Dict[str, dict] = {}
    for _ in range(reader.count(9)):
        name = reader.text(texts)
        kind = reader.take(1)[0]
        if kind not in (0, 1):
            raise TableError("unknown key kind %d" % kind)
        table: dict = {}
        for _ in range(reader.count(5)):
            key = reader.take(32).hex() if kind == 0 else reader.text(texts)
            table[key] = reader.value(texts)
        tables[name] = table
    if reader.at != len(data):
        raise TableError("the table file goes on behind its last table")
    return tables


def load(path: str) -> Dict[str, dict]:
    """The tables of the file at ``path``."""
    if os.path.getsize(path) > MAX_FILE:
        raise TableError("the table file is too large: " + path)
    with open(path, "rb") as fh:
        return loads(fh.read(MAX_FILE + 1))


def beside(module_file: str, name: str) -> Dict[str, dict]:
    """The tables of the file ``name`` in the folder of the module ``module_file``."""
    return load(os.path.join(os.path.dirname(os.path.abspath(module_file)), name))


def size_of(tables: Dict[str, dict]) -> Tuple[int, int]:
    """``(entries, bytes)`` the tables take in this form (for the builders' reports)."""
    return sum(len(t) for t in tables.values()), len(dump(tables))
