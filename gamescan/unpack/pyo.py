"""Compiled Python 2.7 (``.pyo`` / ``.pyc``), read as data.

Ren'Py 6 and 7 ship their engine as compiled files beside the sources, and
Python runs the compiled file when its time stamp fits the source. The file is
a four-byte format mark, a time stamp and one "marshalled" code object: a tree
of numbers, texts, tuples and further code objects.

This reader walks that tree byte by byte with ``struct`` - it never calls
``marshal`` or ``pickle``, builds no code object and runs nothing. It answers
two questions. "What does this file contain", as one SHA-256
(:func:`content_key`, which keeps nothing of the tree), so that a file
compiled on a developer's PC can be compared with the one in the official
SDK. And "what is in it", as plain records of bytes, texts and numbers
(:func:`load`, :class:`Code`), for the walk over the instructions in
:mod:`gamescan.unpack.pycalls`. For the key, four things are left out,
because they differ from one compilation to the next and change nothing about
what the code does:

* the time stamp in the header,
* the path of the source file stored in every code object (the folder on the
  PC that compiled it - it is skipped unread and never leaves this module),
* how a whole number is stored: a 32-bit Python writes a number above 32 bits
  as a "long", a 64-bit one as an "int"; they are compared by value,
* how a text is stored: in place, or as a reference to an earlier, identical
  one (which of the two a compiler writes for a short text differs from one
  compilation to the next); texts are compared by value.

Everything else goes into the key exactly as stored: the instructions, every
constant, every name, the line table, the order of everything.

Limits: file size, nesting depth, number of objects, digits of one number.
One pass over the bytes; the object limit bounds the time.
"""
from __future__ import annotations

import hashlib
import struct
from typing import List, Optional

from . import limits

MAGIC = b"\x03\xf3\r\n"                  # Python 2.7 (Ren'Py 6.99 - 7.x)
_HEADER = 8                              # format mark + time stamp
_MAX_SIZE = 16 * 1024 * 1024             # one compiled file
_MAX_DEPTH = 100                         # code in code, tuples in tuples
_MAX_OBJECTS = 1_000_000
_MAX_DIGITS = 4096                       # 15-bit digits of one whole number
_SINGLE = b"NFTS."                       # None, False, True, StopIteration, Ellipsis
_SEQUENCE = b"([<>"                      # tuple, list, set, frozenset
_TEXT = (b"s", b"t", b"R", b"u")         # what a stored source path can be


class _Unreadable(Exception):
    pass


def is_python2(data: bytes) -> bool:
    """Does the file start like compiled Python 2.7?"""
    return data[:4] == MAGIC


class _Walk:
    """One pass over the marshalled data; what is not left out is fed to ``put``."""

    def __init__(self, data: bytes, put, lines: bool = True) -> None:
        self.data, self.pos, self.put, self.lines = data, _HEADER, put, lines
        self.interned: List[bytes] = []  # texts stored for reference so far
        self.left = _MAX_OBJECTS

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise _Unreadable("ends early")
        self.pos += count
        return self.data[self.pos - count:self.pos]

    def int32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def number(self, value: int, keep: bool) -> None:
        if keep:
            text = ("%x" % value).encode("ascii")           # (hex: no limit on its length)
            self.put(b"i" + struct.pack("<I", len(text)) + text)

    def text(self, body: bytes, keep: bool) -> None:
        """A byte text, however it is stored: in place, in place and remembered,
        or as a reference to a remembered one."""
        if keep:
            self.put(b"s" + struct.pack("<I", len(body)) + body)

    def sized(self, tag: bytes, keep: bool, width: int = 4) -> None:
        length = self.int32() if width == 4 else self.take(1)[0]
        body = self.take(length)
        if keep:
            self.put(tag + struct.pack("<I", length) + body)

    def obj(self, depth: int, keep: bool = True) -> None:
        self.left -= 1
        if depth > _MAX_DEPTH or self.left < 0:
            raise _Unreadable(limits.hit("pyo", "nested deeper than %d or more than %d objects" % (_MAX_DEPTH, _MAX_OBJECTS)))
        tag = self.take(1)
        if tag in _SINGLE:
            if keep:
                self.put(tag)
        elif tag == b"i":
            self.number(self.int32(), keep)
        elif tag == b"I":
            self.number(struct.unpack("<q", self.take(8))[0], keep)
        elif tag == b"l":
            count = self.int32()
            if abs(count) > _MAX_DIGITS:
                raise _Unreadable(limits.hit("pyo", "a whole number of more than %d digits" % _MAX_DIGITS))
            value = 0
            for digit in reversed(struct.unpack("<%dH" % abs(count), self.take(2 * abs(count)))):
                if digit > 0x7FFF:
                    raise _Unreadable("bad digit")
                value = (value << 15) | digit
            self.number(-value if count < 0 else value, keep)
        elif tag == b"f":
            self.sized(tag, keep, 1)
        elif tag == b"g" or tag == b"y":
            body = self.take(8 if tag == b"g" else 16)
            if keep:
                self.put(tag + body)
        elif tag == b"x":
            self.sized(tag, keep, 1)
            self.sized(b"", keep, 1)
        elif tag == b"u":
            self.sized(tag, keep)
        elif tag == b"s" or tag == b"t":
            body = self.take(self.int32())
            if tag == b"t":
                self.interned.append(body)
            self.text(body, keep)
        elif tag == b"R":
            index = self.int32()
            if not 0 <= index < len(self.interned):
                raise _Unreadable("reference to nothing")
            self.text(self.interned[index], keep)
        elif tag in _SEQUENCE:
            count = self.int32()
            if count < 0 or count > len(self.data) - self.pos:      # each member is a byte at least
                raise _Unreadable("bad count")
            if keep:
                self.put(tag + struct.pack("<I", count))
            for _ in range(count):
                self.obj(depth + 1, keep)
        elif tag == b"{":
            if keep:
                self.put(tag)
            while self.data[self.pos:self.pos + 1] != b"0":
                self.obj(depth + 1, keep)                           # key
                self.obj(depth + 1, keep)                           # value
            self.take(1)
            if keep:
                self.put(b"0")
        elif tag == b"c":
            self.code(depth, keep)
        else:                                                       # "0", "?" or no type at all
            raise _Unreadable("unknown type")

    def code(self, depth: int, keep: bool) -> None:
        head = self.take(16)                 # arguments, locals, stack size, flags
        if keep:
            self.put(b"c" + head)
        for _ in range(6):                   # instructions, constants, names, three name lists
            self.obj(depth + 1, keep)
        if self.data[self.pos:self.pos + 1] not in _TEXT:
            raise _Unreadable("the source path is not a text")      # (Python would not load it)
        self.obj(depth + 1, keep=False)      # the source path: walked over, never kept
        self.obj(depth + 1, keep)            # the code object's name
        line = self.take(4)                  # first line
        if keep and self.lines:
            self.put(line)
        self.obj(depth + 1, keep and self.lines)        # line table


def content_key(data: bytes, lines: bool = True) -> Optional[str]:
    """SHA-256 over what a compiled Python 2.7 file contains, without the time
    stamp and the stored source paths, whole numbers by value (see the module
    text). Bytes behind the code object are part of the key. None: not such a
    file, or it could not be read within the limits - nothing is said about
    it then.

    ``lines=False`` also leaves out every code object's first line and line
    table - another key, for one question only: is this what the official
    source compiles to once nothing but comments and blank lines were changed
    in it (which moves the lines and nothing else)?"""
    if is_python2(data) and len(data) > _MAX_SIZE:
        limits.hit("pyo", "a compiled file larger than %d MB" % (_MAX_SIZE >> 20))
    if not is_python2(data) or len(data) > _MAX_SIZE or data[_HEADER:_HEADER + 1] != b"c":
        return None
    digest = hashlib.sha256((b"pyo-1\0" if lines else b"pyo-1-no-lines\0") + MAGIC)
    walk = _Walk(data, digest.update, lines)
    try:
        walk.obj(0)
    except (_Unreadable, struct.error, RecursionError):
        return None
    digest.update(b"\0end" + data[walk.pos:])
    return digest.hexdigest()


class Code:
    """What a code object of a compiled file holds, as plain data - this is a
    record of bytes, texts and numbers, not a code object, and nothing can run
    it. The stored source path is not among its fields."""

    __slots__ = ("name", "first_line", "instructions", "constants", "names", "local_names",
                 "free_names", "cell_names", "line_table", "arg_count", "flags")

    def __init__(self, name, first_line, instructions, constants, names, local_names,
                 free_names, cell_names, line_table, arg_count=0, flags=0) -> None:
        self.name, self.first_line, self.instructions = name, first_line, instructions
        self.constants, self.names, self.local_names = constants, names, local_names
        self.free_names, self.cell_names, self.line_table = free_names, cell_names, line_table
        # how many of the local names are the function's parameters, and its flags
        # (4: one more for *args, 8: one more for **kwargs)
        self.arg_count, self.flags = arg_count, flags


class Unknown:
    """A constant this reader does not turn into a value (a complex number,
    ``StopIteration``)."""

    def __init__(self, text: str) -> None:
        self.text = text


class _Tree(_Walk):
    """The same pass, returning what it reads instead of hashing it: ``None``,
    ``True`` / ``False``, ``Ellipsis``, whole numbers, floats, byte texts,
    Unicode texts, tuples (for every kind of collection) and :class:`Code`."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data, lambda _piece: None)

    def value(self, depth: int):
        self.left -= 1
        if depth > _MAX_DEPTH or self.left < 0:
            raise _Unreadable(limits.hit("pyo", "nested deeper than %d or more than %d objects" % (_MAX_DEPTH, _MAX_OBJECTS)))
        tag = self.take(1)
        if tag == b"N":
            return None
        if tag == b"F" or tag == b"T":
            return tag == b"T"
        if tag == b".":
            return Ellipsis
        if tag == b"S":
            return Unknown("StopIteration")
        if tag == b"i":
            return self.int32()
        if tag == b"I":
            return struct.unpack("<q", self.take(8))[0]
        if tag == b"l":
            count = self.int32()
            if abs(count) > _MAX_DIGITS:
                raise _Unreadable(limits.hit("pyo", "a whole number of more than %d digits" % _MAX_DIGITS))
            value = 0
            for digit in reversed(struct.unpack("<%dH" % abs(count), self.take(2 * abs(count)))):
                if digit > 0x7FFF:
                    raise _Unreadable("bad digit")
                value = (value << 15) | digit
            return -value if count < 0 else value
        if tag == b"f":
            text = self.take(self.take(1)[0])
            try:
                return float(text.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                raise _Unreadable("bad float")
        if tag == b"g":
            return struct.unpack("<d", self.take(8))[0]
        if tag == b"y":
            self.take(16)
            return Unknown("complex")
        if tag == b"x":
            self.take(self.take(1)[0])
            self.take(self.take(1)[0])
            return Unknown("complex")
        if tag == b"u":
            return self.take(self.int32()).decode("utf-8", "replace")
        if tag == b"s" or tag == b"t":
            body = self.take(self.int32())
            if tag == b"t":
                self.interned.append(body)
            return body
        if tag == b"R":
            index = self.int32()
            if not 0 <= index < len(self.interned):
                raise _Unreadable("reference to nothing")
            return self.interned[index]
        if tag in _SEQUENCE:
            count = self.int32()
            if count < 0 or count > len(self.data) - self.pos:
                raise _Unreadable("bad count")
            return tuple(self.value(depth + 1) for _ in range(count))
        if tag == b"{":
            pairs = []
            while self.data[self.pos:self.pos + 1] != b"0":
                pairs.append((self.value(depth + 1), self.value(depth + 1)))
            self.take(1)
            return tuple(pairs)
        if tag == b"c":
            arg_count, _locals, _stack, flags = struct.unpack("<iiii", self.take(16))
            instructions, constants, names, local_names, free_names, cell_names = (
                self.value(depth + 1) for _ in range(6))
            if self.data[self.pos:self.pos + 1] not in _TEXT:
                raise _Unreadable("the source path is not a text")
            self.obj(depth + 1, keep=False)  # the source path: walked over, never kept
            name = self.value(depth + 1)
            first_line = self.int32()
            line_table = self.value(depth + 1)
            if not (isinstance(instructions, bytes) and isinstance(line_table, bytes)
                    and isinstance(name, bytes) and isinstance(constants, tuple)
                    and all(isinstance(group, tuple) and all(isinstance(one, bytes) for one in group)
                            for group in (names, local_names, free_names, cell_names))):
                raise _Unreadable("a code object with parts of the wrong kind")
            return Code(name, first_line, instructions, constants, names, local_names, free_names,
                        cell_names, line_table, arg_count, flags)
        raise _Unreadable("unknown type")


def load(data: bytes) -> Optional[Code]:
    """The code object of a compiled Python 2.7 file as plain data
    (:class:`Code`; code objects among its constants likewise). None: not such
    a file, or not readable within the limits."""
    if is_python2(data) and len(data) > _MAX_SIZE:
        limits.hit("pyo", "a compiled file larger than %d MB" % (_MAX_SIZE >> 20))
    if not is_python2(data) or len(data) > _MAX_SIZE or data[_HEADER:_HEADER + 1] != b"c":
        return None
    try:
        return _Tree(data).value(0)
    except (_Unreadable, struct.error, RecursionError):
        return None