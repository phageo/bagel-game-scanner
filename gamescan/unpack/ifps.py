"""Compiled Pascal Script: the ``[Code]`` of an Inno Setup installer, read as data.

Inno Setup compiles ``[Code]`` with RemObjects Pascal Script and stores the
result in the setup script as one text that starts with ``IFPS``: a header,
the types, the procedures, the variables and then the instructions of every
procedure of the script itself. A procedure the script only *uses* - a
support function of Inno Setup (``Exec``, ``DownloadTemporaryFile``), a method
of one of its classes, a function of a library - is in the table by its name.

:func:`load` gives all of that as plain records (standard library only:
``struct``). Nothing is compiled, interpreted or run; an instruction is an
instruction number and its operands, as they are stored. Everything is
bounded (size, counts, text lengths); a file that does not fit raises
:class:`IfpsError`.
"""
from __future__ import annotations

import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

from . import limits

MAGIC = b"IFPS"
_MAX_SIZE = 16 * 1024 * 1024
_MAX_TYPES = 50_000
_MAX_PROCS = 50_000
_MAX_VARIABLES = 100_000
_MAX_FIELDS = 4096                  # fields of one record type
_MAX_ATTRIBUTES = 256               # attributes of one type or procedure, and values of one
_MAX_NAME = 4096
_MAX_INSTRUCTIONS = 2_000_000       # in the whole file
_MAX_TEXT = 4096                    # characters kept of one text constant
_MAX_TRIED = 64                     # places in a setup script where the mark is looked at
_LOWEST_BUILD, _HIGHEST_BUILD = 12, 40
_ATTRIBUTES_SINCE = 21

# base types (uPSUtils.pas)
U8, S8, U16, S16, U32, S32, SINGLE, DOUBLE, EXTENDED, STRING, RECORD, ARRAY, POINTER, PCHAR = range(1, 15)
RESOURCE_POINTER, VARIANT, S64, CHAR, WIDE_STRING, WIDE_CHAR, PROC_POINTER, STATIC_ARRAY = range(15, 23)
SET, CURRENCY, CLASS, INTERFACE, NOTIFICATION_VARIANT, UNICODE_STRING = range(23, 29)
_PLAIN = frozenset({U8, S8, U16, S16, U32, S32, SINGLE, DOUBLE, EXTENDED, STRING, POINTER, PCHAR, VARIANT,
                    S64, CHAR, WIDE_STRING, WIDE_CHAR, CURRENCY, UNICODE_STRING, RESOURCE_POINTER,
                    NOTIFICATION_VARIANT})
_SIZES = {U8: 1, S8: 1, CHAR: 1, U16: 2, S16: 2, WIDE_CHAR: 2, U32: 4, S32: 4, SINGLE: 4, PROC_POINTER: 4,
          S64: 8, DOUBLE: 8, CURRENCY: 8, EXTENDED: 10}
_NUMBERS = {U8: "<B", S8: "<b", CHAR: "<B", U16: "<H", S16: "<h", WIDE_CHAR: "<H", U32: "<I", S32: "<i",
            PROC_POINTER: "<I", S64: "<q"}
TEXTS = frozenset({STRING, PCHAR, WIDE_STRING, UNICODE_STRING})

# instructions (uPSUtils.pas)
ASSIGN, CALCULATE, PUSH, PUSH_VAR, POP, CALL, GOTO, GOTO_IF, GOTO_IF_NOT, RETURN = range(10)
SET_STACK_TYPE, PUSH_TYPE, COMPARE, CALL_VAR, SET_POINTER, NOT, NEGATE, SET_FLAG, GOTO_FLAG = range(10, 19)
PUSH_HANDLER, POP_HANDLER, INTEGER_NOT, SET_COPY_POINTER, INCREMENT, DECREMENT, POP_GOTO, POP2_GOTO = range(19, 27)
NOP = 255
# what follows the instruction number: v = an operand, b = a byte, j = a jump distance,
# c = a number
_LAYOUT = {ASSIGN: "vv", CALCULATE: "bvv", PUSH: "v", PUSH_VAR: "v", POP: "", CALL: "c", GOTO: "j",
           GOTO_IF: "jv", GOTO_IF_NOT: "jv", RETURN: "", SET_STACK_TYPE: "cc", PUSH_TYPE: "c",
           COMPARE: "bvvv", CALL_VAR: "v", SET_POINTER: "vv", NOT: "v", NEGATE: "v", SET_FLAG: "vb",
           GOTO_FLAG: "j", PUSH_HANDLER: "cccc", POP_HANDLER: "b", INTEGER_NOT: "v",
           SET_COPY_POINTER: "vv", INCREMENT: "v", DECREMENT: "v", POP_GOTO: "j", POP2_GOTO: "j", NOP: ""}
JUMPS = frozenset({GOTO, GOTO_IF, GOTO_IF_NOT, GOTO_FLAG, POP_GOTO, POP2_GOTO})

# kinds of operand
VARIABLE, CONSTANT, ELEMENT, ELEMENT_BY_VARIABLE = 0, 1, 2, 3
# where a variable number points (uPSRuntime.pas): below GLOBALS_END a variable of the
# script, from LOCALS on a place on the stack counted from the procedure's own base, and
# between the two a parameter (below that base)
GLOBALS_END, LOCALS = 0x40000000, 0x60000000


class IfpsError(ValueError):
    """Not compiled Pascal Script, damaged, or over a limit."""


class Operand(NamedTuple):
    kind: int                   # VARIABLE, CONSTANT, ELEMENT, ELEMENT_BY_VARIABLE
    number: int                 # the variable (CONSTANT: the base type of the value)
    value: object = None        # CONSTANT: a text (str), a whole number (int) or None
    index: int = 0              # ELEMENT: the element; ELEMENT_BY_VARIABLE: the variable that holds it


class Instruction(NamedTuple):
    offset: int                 # inside the procedure
    code: int
    operands: Tuple[Operand, ...] = ()
    number: int = 0             # CALL: the procedure; PUSH_TYPE: the type; a jump: its target offset
    extra: int = 0              # CALCULATE / COMPARE: which one


class Procedure(NamedTuple):
    index: int
    name: str                   # as written in the file (support functions in capitals)
    external: bool              # not part of the script: a support function, a method, a library
    library: str = ""           # a function of a library: the library ...
    function: str = ""          # ... and the name it has there
    owner: str = ""             # a method: its class
    code: Tuple[Instruction, ...] = ()
    cut: bool = False           # its instructions were not read to their end


class Script(NamedTuple):
    build: int
    types: Tuple[int, ...]              # the base type of every type
    procedures: Tuple[Procedure, ...]
    variables: int                      # how many variables the script has
    cut: bool                           # an instruction limit was reached somewhere


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > len(self.data):
            raise IfpsError("cut short")
        self.at += count
        return self.data[self.at - count:self.at]

    def byte(self) -> int:
        return self.take(1)[0]

    def number(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def name(self, length: int) -> str:
        if length > _MAX_NAME:
            raise IfpsError(limits.hit("ifps", "a name longer than %d bytes" % _MAX_NAME))
        return self.take(length).decode("latin-1")


def _attributes(r: _Reader, types: List[int], sets: Dict[int, int]) -> None:
    """Skip the attributes of a type or a procedure (since build 21)."""
    count = r.number()
    if count > _MAX_ATTRIBUTES:
        raise IfpsError(limits.hit("ifps", "more than %d attributes" % _MAX_ATTRIBUTES))
    for _ in range(count):
        r.name(r.number())
        fields = r.number()
        if fields > _MAX_ATTRIBUTES:
            raise IfpsError(limits.hit("ifps", "more than %d attribute values" % _MAX_ATTRIBUTES))
        for _field in range(fields):
            _value(r, r.number(), types, sets)


def _value(r: _Reader, number: int, types: List[int], sets: Dict[int, int]):
    """``(base type, value)`` of the constant of type ``number`` at the reader's place."""
    if number >= len(types):
        raise IfpsError("a constant of a type that does not exist")
    base = types[number]
    if base in TEXTS:
        length = r.number()
        wide = base in (WIDE_STRING, UNICODE_STRING)
        if length > len(r.data):
            raise IfpsError("cut short")
        raw = r.take(2 * length if wide else length)
        if length > _MAX_TEXT:
            limits.hit("ifps", "a text longer than %d characters: only its start was read" % _MAX_TEXT)
        kept = raw[:2 * _MAX_TEXT if wide else _MAX_TEXT]
        return base, kept.decode("utf-16-le", "replace") if wide else kept.decode("latin-1")
    if base == SET:
        r.take(sets[number])
        return base, None
    size = _SIZES.get(base)
    if size is None:
        raise IfpsError("a constant of a type that has no constants")
    raw = r.take(size)
    return base, struct.unpack(_NUMBERS[base], raw)[0] if base in _NUMBERS else None


def _types(r: _Reader, count: int, build: int, offsets: bool) -> Tuple[List[int], Dict[int, int]]:
    types: List[int] = []
    sets: Dict[int, int] = {}               # set type -> its size in bytes
    for _ in range(count):
        base = r.byte()
        exported, base = bool(base & 0x80), base & 0x7F
        if base in _PLAIN:
            pass
        elif base in (CLASS, PROC_POINTER):
            length = r.number()
            if length > 255:
                raise IfpsError("a class name is too long")
            r.take(length)
        elif base == INTERFACE:
            r.take(16)
        elif base == SET:
            bits = r.number()
            if bits > 256:
                raise IfpsError("a set is too large")
            sets[len(types)] = (bits + 7) // 8
        elif base == STATIC_ARRAY:
            if r.number() >= len(types):
                raise IfpsError("an array of a type that does not exist")
            r.number()
            if offsets:
                r.number()
        elif base == ARRAY:
            if r.number() >= len(types):
                raise IfpsError("an array of a type that does not exist")
        elif base == RECORD:
            fields = r.number()
            if fields > _MAX_FIELDS:
                limits.hit("ifps", "a record with more than %d fields" % _MAX_FIELDS)
            if not 0 < fields <= _MAX_FIELDS:
                raise IfpsError("a record with too many fields")
            for _field in range(fields):
                if r.number() >= len(types):
                    raise IfpsError("a field of a type that does not exist")
        else:
            raise IfpsError("an unknown kind of type (%d)" % base)
        if exported:
            r.name(r.number())
        types.append(base)
        if build >= _ATTRIBUTES_SINCE:
            _attributes(r, types, sets)
    return types, sets


def _instructions(data: bytes, start: int, length: int, types: List[int], sets: Dict[int, int],
                  budget: List[int]) -> Tuple[Tuple[Instruction, ...], bool]:
    """The instructions in ``data[start:start + length]``; ``(instructions, cut short)``.
    An unknown instruction or an operand that does not fit ends the reading there."""
    r = _Reader(data[start:start + length])
    out: List[Instruction] = []

    def operand() -> Operand:
        kind = r.byte()
        if kind == VARIABLE:
            return Operand(kind, r.number())
        if kind == CONSTANT:
            base, value = _value(r, r.number(), types, sets)
            return Operand(kind, base, value)
        if kind in (ELEMENT, ELEMENT_BY_VARIABLE):
            return Operand(kind, r.number(), None, r.number())
        raise IfpsError("an unknown kind of operand")

    try:
        while r.at < len(r.data):
            if budget[0] <= 0:
                limits.hit("ifps", "more than %d instructions: the rest was not read" % _MAX_INSTRUCTIONS)
                return tuple(out), True
            budget[0] -= 1
            offset, code = r.at, r.byte()
            layout = _LAYOUT.get(code)
            if layout is None:
                return tuple(out), True
            operands: List[Operand] = []
            numbers: List[int] = []
            extra = 0
            for part in layout:
                if part == "v":
                    operands.append(operand())
                elif part == "b":
                    extra = r.byte()
                else:
                    numbers.append(r.number())
            number = numbers[0] if numbers else 0
            if code in JUMPS:
                # the distance is counted from behind the distance itself (GOTO_IF / GOTO_IF_NOT:
                # from behind the whole instruction)
                distance = number - (1 << 32) if number & 0x80000000 else number
                number = r.at + distance
            out.append(Instruction(offset, code, tuple(operands), number, extra))
    except IfpsError:
        return tuple(out), True
    return tuple(out), False


def _external(name: str, declaration: bytes) -> Tuple[str, str, str]:
    """``(library, function, class)`` from the declaration of an external procedure."""
    if declaration.startswith(b"dll:"):
        parts = declaration[4:].split(b"\0")
        if len(parts) >= 2:
            return parts[0].decode("latin-1")[:_MAX_NAME], parts[1].decode("latin-1")[:_MAX_NAME], ""
    if declaration.startswith(b"class:"):
        parts = declaration[6:].split(b"|")
        if len(parts) >= 2:
            return "", parts[1].decode("latin-1")[:_MAX_NAME], parts[0].decode("latin-1")[:_MAX_NAME]
    return "", "", ""


def _load(data: bytes, offsets: bool) -> Script:
    r = _Reader(data)
    if r.take(4) != MAGIC:
        raise IfpsError("not compiled Pascal Script")
    build, type_count, proc_count, var_count, _main, _imports = struct.unpack("<6I", r.take(24))
    if not _LOWEST_BUILD <= build <= _HIGHEST_BUILD:
        raise IfpsError("build %d is not known" % build)
    if type_count > _MAX_TYPES or proc_count > _MAX_PROCS or var_count > _MAX_VARIABLES:
        raise IfpsError(limits.hit("ifps", "too many types, procedures or variables (more than %d / %d / %d)"
                                   % (_MAX_TYPES, _MAX_PROCS, _MAX_VARIABLES)))
    types, sets = _types(r, type_count, build, offsets)
    rows = []
    for index in range(proc_count):
        flags = r.byte()
        if flags & 1:
            name = r.name(r.byte())
            declaration = r.take(_checked(r, r.number())) if flags & 2 else b""
            rows.append((index, name, True, _external(name, declaration), 0, 0))
        else:
            start, length = r.number(), r.number()
            if not 0 < start <= len(data) or length > len(data) - start:
                raise IfpsError("a procedure outside the file")
            name = ""
            if flags & 2:
                name = r.name(r.number())
                r.take(_checked(r, r.number()))
            rows.append((index, name, False, ("", "", ""), start, length))
        if flags & 4:
            _attributes(r, types, sets)
    for _ in range(var_count):
        if r.number() >= type_count:
            raise IfpsError("a variable of a type that does not exist")
        if r.byte() & 1:
            r.name(r.number())
    end = r.at
    budget = [_MAX_INSTRUCTIONS]
    procedures: List[Procedure] = []
    cut = False
    for index, name, external, (library, function, owner), start, length in rows:
        code: Tuple[Instruction, ...] = ()
        short = False
        if not external:
            if start < end:
                raise IfpsError("a procedure inside the tables")
            code, short = _instructions(data, start, length, types, sets, budget)
            cut = cut or short
        procedures.append(Procedure(index, name, external, library, function, owner, code, short))
    return Script(build, tuple(types), tuple(procedures), var_count, cut)


def _checked(r: _Reader, length: int) -> int:
    if length > len(r.data) - r.at:
        raise IfpsError("cut short")
    return length


def load(data: bytes) -> Script:
    """The compiled script in ``data`` (it starts with ``IFPS``). Raises
    :class:`IfpsError` when it cannot be read."""
    if len(data) > _MAX_SIZE:
        raise IfpsError(limits.hit("ifps", "larger than %d MB" % (_MAX_SIZE >> 20)))
    try:
        try:
            return _load(data, True)
        except IfpsError:
            # older builds store a fixed-size array without its first index
            return _load(data, False)
    except (struct.error, IndexError, UnicodeError) as exc:
        raise IfpsError("damaged (%s)" % exc)


def locate(block: bytes) -> Optional[Tuple[int, int]]:
    """``(offset, length)`` of the compiled ``[Code]`` inside the setup script
    ``block`` of an Inno Setup installer: the text that starts with ``IFPS``
    and whose length stands in front of it (None = the installer has no
    ``[Code]``, or it is not found)."""
    at = block.find(MAGIC)
    tried = 0
    while at >= 0 and tried < _MAX_TRIED:
        tried += 1
        if at >= 4:
            length = struct.unpack_from("<I", block, at - 4)[0]
            if 28 <= length <= _MAX_SIZE and at + length <= len(block):
                build = struct.unpack_from("<I", block, at + 4)[0]
                if _LOWEST_BUILD <= build <= _HIGHEST_BUILD:
                    return at, length
        at = block.find(MAGIC, at + 1)
    if at >= 0:
        limits.hit("ifps", "the mark of the compiled [Code] stands at more than %d places: not all were looked at" % _MAX_TRIED)
    return None


def find(block: bytes) -> Optional[bytes]:
    """The compiled ``[Code]`` inside the setup script ``block`` (see :func:`locate`)."""
    where = locate(block)
    return None if where is None else block[where[0]:where[0] + where[1]]


def named(block: bytes) -> bool:
    """Does ``block`` hold the mark of compiled code at all (found or not)?"""
    return MAGIC in block
