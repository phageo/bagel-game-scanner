""".NET method bodies, read as data (ECMA-335, standard library only).

:mod:`gamescan.unpack.dotnet_meta` reads what a managed program *names*
(types, members, strings). This module reads what its methods *do*: where
each method's body is, the body's header, and the instructions (IL) in it,
with the names of the methods and fields they refer to.

Nothing is loaded, compiled or run: bytes are walked with a written-out
table of the instruction set. Everything has a limit; a program that cannot
be read to the end raises :class:`IlError`, and the caller says so (a "could
not be read" note - CLAUDE.md, rule 15).
"""
from __future__ import annotations

import struct
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from . import dotnet_meta, limits

MAX_METHODS = 400_000               # method rows of one program
MAX_TYPES = 200_000
MAX_BODY = 1 << 20                  # instruction bytes of one method (the largest seen: 34 KB)
MAX_SWITCH = 65_536                 # targets of one switch
_ERRORS = (struct.error, IndexError, ValueError, TypeError, KeyError)
_MAX_SHAPE_PARAMS = 255             # parameters / type arguments of one signature that are named
_MAX_SHAPE_DEPTH = 16               # types inside types (arrays of generic types ...)
_SHAPE_NAMES = {0x01: "Void", 0x02: "Boolean", 0x03: "Char", 0x04: "SByte", 0x05: "Byte", 0x06: "Int16",
                0x07: "UInt16", 0x08: "Int32", 0x09: "UInt32", 0x0A: "Int64", 0x0B: "UInt64", 0x0C: "Single",
                0x0D: "Double", 0x0E: "String", 0x16: "TypedReference", 0x18: "IntPtr", 0x19: "UIntPtr",
                0x1C: "Object"}


class IlError(ValueError):
    """The program's methods cannot be read (damaged, protected, or over a limit)."""


# -- the instruction set -------------------------------------------------------------------
# opcode -> (bytes that follow, values taken from the stack, values put on it); -1: depends
# on what is called. Two-byte opcodes (0xFE xx) are written 0xFExx.
CALL, CALLI, CALLVIRT, NEWOBJ, JMP, RET, SWITCH = 0x28, 0x29, 0x6F, 0x73, 0x27, 0x2A, 0x45
LDSTR, LDFTN, LDVIRTFTN, LDTOKEN = 0x72, 0xFE06, 0xFE07, 0xD0
OPCODES: Dict[int, Tuple[int, int, int]] = {}


def _ops(codes, size: int, pops: int, pushes: int) -> None:
    for code in codes:
        OPCODES[code] = (size, pops, pushes)


_ops((0x00, 0x01, 0xDC), 0, 0, 0)                                   # nop, break, endfinally
_ops(range(0x02, 0x0A), 0, 0, 1)                                    # ldarg.0-3, ldloc.0-3
_ops(range(0x0A, 0x0E), 0, 1, 0)                                    # stloc.0-3
_ops((0x0E, 0x0F, 0x11, 0x12, 0x1F), 1, 0, 1)                       # ldarg.s ldarga.s ldloc.s ldloca.s ldc.i4.s
_ops((0x10, 0x13), 1, 1, 0)                                         # starg.s, stloc.s
_ops(range(0x14, 0x1F), 0, 0, 1)                                    # ldnull, ldc.i4.m1 - ldc.i4.8
_ops((0x20, 0x22, LDSTR, LDTOKEN, 0x7E, 0x7F), 4, 0, 1)             # ldc.i4 ldc.r4 ldstr ldtoken ldsfld ldsflda
_ops((0x21, 0x23), 8, 0, 1)                                         # ldc.i8, ldc.r8
_ops((0x25,), 0, 1, 2)                                              # dup
_ops((0x26, 0x7A), 0, 1, 0)                                         # pop, throw
_ops((JMP,), 4, 0, 0)
_ops((CALL, CALLI, CALLVIRT, NEWOBJ), 4, -1, -1)
_ops((RET,), 0, -1, 0)
_ops((0x2B, 0xDE), 1, 0, 0)                                         # br.s, leave.s
_ops((0x2C, 0x2D), 1, 1, 0)                                         # brfalse.s, brtrue.s
_ops(range(0x2E, 0x38), 1, 2, 0)                                    # beq.s - blt.un.s
_ops((0x38, 0xDD), 4, 0, 0)                                         # br, leave
_ops((0x39, 0x3A), 4, 1, 0)                                         # brfalse, brtrue
_ops(range(0x3B, 0x45), 4, 2, 0)                                    # beq - blt.un
_ops((SWITCH,), -1, 1, 0)
_ops(range(0x46, 0x51), 0, 1, 1)                                    # ldind.*
_ops(list(range(0x51, 0x58)) + [0xDF], 0, 2, 0)                     # stind.*
_ops(list(range(0x58, 0x65)) + list(range(0xD6, 0xDC)), 0, 2, 1)    # add ... shr.un, the .ovf forms
_ops(list(range(0x65, 0x6F)) + [0x76, 0x8E, 0xC3] + list(range(0x82, 0x8C)) + list(range(0xB3, 0xBB))
     + list(range(0xD1, 0xD6)) + [0xE0], 0, 1, 1)                   # neg, not, conv.*, ldlen, ckfinite
_ops((0x70, 0x81), 4, 2, 0)                                         # cpobj, stobj
_ops((0x71, 0x74, 0x75, 0x79, 0x7B, 0x7C, 0x8C, 0x8D, 0xA5, 0xC2, 0xC6), 4, 1, 1)
#     ldobj castclass isinst unbox ldfld ldflda box newarr unbox.any refanyval mkrefany
_ops((0x7D,), 4, 2, 0)                                              # stfld
_ops((0x80,), 4, 1, 0)                                              # stsfld
_ops((0x8F, 0xA3), 4, 2, 1)                                         # ldelema, ldelem
_ops(range(0x90, 0x9B), 0, 2, 1)                                    # ldelem.*
_ops(range(0x9B, 0xA3), 0, 3, 0)                                    # stelem.*
_ops((0xA4,), 4, 3, 0)                                              # stelem
_ops((0xFE00,), 0, 0, 1)                                            # arglist
_ops(range(0xFE01, 0xFE06), 0, 2, 1)                                # ceq - clt.un
_ops((LDFTN, 0xFE1C), 4, 0, 1)                                      # ldftn, sizeof
_ops((LDVIRTFTN,), 4, 1, 1)
_ops((0xFE09, 0xFE0A, 0xFE0C, 0xFE0D), 2, 0, 1)                     # ldarg ldarga ldloc ldloca
_ops((0xFE0B, 0xFE0E), 2, 1, 0)                                     # starg, stloc
_ops((0xFE0F, 0xFE1D), 0, 1, 1)                                     # localloc, refanytype
_ops((0xFE11,), 0, 1, 0)                                            # endfilter
_ops((0xFE12, 0xFE19), 1, 0, 0)                                     # unaligned., no.
_ops((0xFE13, 0xFE14, 0xFE1A, 0xFE1E), 0, 0, 0)                     # volatile. tail. rethrow readonly.
_ops((0xFE15,), 4, 1, 0)                                            # initobj
_ops((0xFE16,), 4, 0, 0)                                            # constrained.
_ops((0xFE17, 0xFE18), 0, 3, 0)                                     # cpblk, initblk

# after these the next instruction is not reached from the one before it
ENDS = frozenset({0x2B, 0x38, 0xDD, 0xDE, RET, 0x7A, JMP, 0xDC, 0xFE1A})
BRANCH_SHORT = frozenset(range(0x2B, 0x38)) | {0xDE}
BRANCH_LONG = frozenset(range(0x38, 0x45)) | {0xDD}
LOAD_LOCAL = {0x06: 0, 0x07: 1, 0x08: 2, 0x09: 3}
STORE_LOCAL = {0x0A: 0, 0x0B: 1, 0x0C: 2, 0x0D: 3}
LOAD_ARG = {0x02: 0, 0x03: 1, 0x04: 2, 0x05: 3}


class Instruction(NamedTuple):
    offset: int
    code: int
    operand: int            # the number that follows the opcode (0: none; a switch: its count)
    size: int               # bytes of the whole instruction


def instructions(code: bytes) -> List[Instruction]:
    """The instructions of one method body, in order. Raises :class:`IlError`
    at an opcode that is not in the table or a body that ends inside one."""
    out: List[Instruction] = []
    at, end = 0, len(code)
    while at < end:
        start, op = at, code[at]
        at += 1
        if op == 0xFE:
            if at >= end:
                raise IlError("a method body ends inside an instruction")
            op = 0xFE00 | code[at]
            at += 1
        entry = OPCODES.get(op)
        if entry is None:
            raise IlError("unknown instruction 0x%X" % op)
        size = entry[0]
        if size < 0:                                    # switch: a count, then that many targets
            if at + 4 > end:
                raise IlError("a method body ends inside an instruction")
            operand = struct.unpack_from("<I", code, at)[0]
            if operand > MAX_SWITCH:
                raise IlError(limits.hit("dotnet-il", "a switch with more than %d targets" % MAX_SWITCH))
            size = 4 + 4 * operand
        elif size == 0:
            operand = 0
        else:
            if at + size > end:
                raise IlError("a method body ends inside an instruction")
            operand = int.from_bytes(code[at:at + size], "little")
        if at + size > end:
            raise IlError("a method body ends inside an instruction")
        at += size
        out.append(Instruction(start, op, operand, at - start))
    return out


def target(instruction: Instruction) -> Optional[int]:
    """Where a branch goes (an offset in the body); None: not a branch."""
    code, size = instruction.code, instruction.size
    if code in BRANCH_SHORT:
        jump = instruction.operand - 256 if instruction.operand > 127 else instruction.operand
    elif code in BRANCH_LONG:
        jump = instruction.operand - (1 << 32) if instruction.operand >> 31 else instruction.operand
    else:
        return None
    return instruction.offset + size + jump


# -- what is called ------------------------------------------------------------------------
VOID, PLAIN, OTHER = "void", "plain", "other"       # what a call gives back: nothing, a number / flag, anything else
_PLAIN_TYPES = frozenset(range(0x02, 0x0E)) | {0x18, 0x19}


class Callee(NamedTuple):
    name: str               # "System.Net.WebClient::DownloadData"; own methods under their type's full name
    params: int
    has_this: bool
    returns: str            # VOID, PLAIN or OTHER
    own: int = 0            # row of the method when it is one of this program's (0: another program's)
    scope: str = ""         # the assembly a method of another program is referred to in ("": not known)
    shape: str = ""         # its parameter types (Module.shape; "": not known) - tells overloads apart


class Method(NamedTuple):
    row: int
    name: str
    type_row: int           # the type that declares it
    rva: int                # 0: no body (abstract, external, supplied by the runtime)


def _number(blob: bytes, at: int) -> Tuple[int, int]:
    """A compressed number of a signature: ``(value, next position)``."""
    first = blob[at]
    if first & 0x80 == 0:
        return first, at + 1
    if first & 0xC0 == 0x80:
        return (first & 0x3F) << 8 | blob[at + 1], at + 2
    return (first & 0x1F) << 24 | blob[at + 1] << 16 | blob[at + 2] << 8 | blob[at + 3], at + 4


class Module:
    """One managed program: its methods, and the names its instructions refer to."""

    def __init__(self, data: bytes, pe) -> None:
        try:
            md = self.md = dotnet_meta._Metadata(data, pe)
        except _ERRORS as exc:
            raise IlError("the tables cannot be read (%s)" % type(exc).__name__)
        self.data, self.pe = data, pe
        if "#~" not in md.streams:
            raise IlError("the tables are stored in an unusual form (#-)")
        if any(table in md.rows for table in (3, 5, 7)):
            raise IlError("the tables are reached through pointer tables")
        types, methods = md.rows.get(2, 0), md.rows.get(6, 0)
        if types > MAX_TYPES or methods > MAX_METHODS:
            raise IlError(limits.hit("dotnet-il", "more types or methods than are read (%d / %d)" % (MAX_TYPES, MAX_METHODS)))
        if methods and (6 not in md.fmt or 2 not in md.fmt):
            raise IlError("the method table cannot be reached")
        if any(table not in md.fmt for table in md.rows if table <= 44):
            raise IlError("a table of an unknown kind stands before the ones that are needed")
        try:
            rows = [md.row(2, i) for i in range(1, types + 1)]
            self._type_names = [md.type_name(2, i) for i in range(1, types + 1)]
            self._first_method = [row[5] for row in rows] + [methods + 1]
            self._first_field = [row[4] for row in rows] + [md.rows.get(4, 0) + 1]
            self.enclosing: Dict[int, int] = {}
            for i in range(1, md.rows.get(41, 0) + 1):
                nested, outer = md.row(41, i)
                self.enclosing[nested] = outer
            self._imports: Dict[int, str] = {}
            for i in range(1, md.rows.get(28, 0) + 1):
                _flags, member, name, _scope = md.row(28, i)
                if member & 1:                              # MemberForwarded: a method
                    self._imports[member >> 1] = md.string(name)
        except _ERRORS as exc:
            raise IlError("the tables cannot be read (%s)" % type(exc).__name__)
        self._owner_of_method: Dict[int, int] = {}
        self._callees: Dict[int, Callee] = {}
        self._fields: Dict[int, Tuple[int, str]] = {}

    # -- types -----------------------------------------------------------------------------
    def type_name(self, row: int) -> str:
        return self._type_names[row - 1] if 1 <= row <= len(self._type_names) else "?"

    def family(self, row: int) -> int:
        """The outermost type ``row`` is nested in (itself when it is not nested):
        a class and the small classes the compiler generates inside it - for a
        coroutine, an ``async`` method, a lambda - are one family."""
        hops = 0
        while row in self.enclosing and hops < 16:
            row, hops = self.enclosing[row], hops + 1
        return row

    def _owner(self, first: List[int], row: int) -> int:
        low, high = 0, len(first) - 1                   # the last type whose list starts at or before row
        while low < high:
            middle = (low + high + 1) // 2
            if first[middle] <= row:
                low = middle
            else:
                high = middle - 1
        return low + 1

    # -- methods ---------------------------------------------------------------------------
    def methods(self) -> Iterator[Method]:
        md = self.md
        for row in range(1, md.rows.get(6, 0) + 1):
            try:
                rva, _impl, _flags, name, _sig, _params = md.row(6, row)
                yield Method(row, md.string(name), self._owner(self._first_method, row), rva)
            except _ERRORS as exc:
                raise IlError("the method table cannot be read (%s)" % type(exc).__name__)

    def body(self, rva: int) -> bytes:
        """The instruction bytes of the method body at ``rva``."""
        data = self.data
        try:
            at = self.pe.offset(rva)
        except _ERRORS:
            at = None
        if at is None or not 0 < at < len(data):
            raise IlError("a method body lies outside the file")
        first = data[at]
        if first & 3 == 2:                              # tiny header: one byte
            start, size = at + 1, first >> 2
        elif first & 3 == 3:                            # fat header
            if at + 12 > len(data):
                raise IlError("a method body lies outside the file")
            flags, _stack, size, _locals = struct.unpack_from("<HHII", data, at)
            start = at + (flags >> 12) * 4
            if flags >> 12 < 3:
                raise IlError("a method header of an unknown form")
        else:
            raise IlError("a method header of an unknown form")
        if size > MAX_BODY:
            raise IlError(limits.hit("dotnet-il", "a method body larger than %d KB" % (MAX_BODY >> 10)))
        if start + size > len(data):
            raise IlError("a method body lies outside the file")
        return data[start:start + size]

    # -- names -----------------------------------------------------------------------------
    def _blob(self, offset: int) -> bytes:
        heap = self.md.streams.get("#Blob", b"")
        if not 0 <= offset < len(heap):
            return b""
        size, at = _number(heap, offset)
        return heap[at:at + size]

    def _signature(self, blob: bytes) -> Tuple[int, bool, str]:
        """``(parameters, has this, what it gives back)`` of a method signature."""
        try:
            convention, at = blob[0], 1
            if convention & 0x10:                       # generic: the number of type parameters
                _count, at = _number(blob, at)
            params, at = _number(blob, at)
            while blob[at] in (0x1F, 0x20):             # custom modifiers
                _token, at = _number(blob, at + 1)
            kind = blob[at]
            returns = VOID if kind == 0x01 else PLAIN if kind in _PLAIN_TYPES else OTHER
            return params, bool(convention & 0x20) and not convention & 0x40, returns
        except IndexError:
            return 0, False, OTHER

    def shape(self, blob: bytes) -> str:
        """The parameter types of a method signature by their short names (``"(Type,Object[])"``,
        ``"()"`` for none),
        so that two overloads of one name - ``Activator.CreateInstance(Type, object[])`` and
        ``(string, string)`` - are told apart across programs; "" when it cannot be read.
        Short names, because one program names a type by a reference and the other by its
        definition (phageo, 2026-10-24: HO2-06 / HO2-07)."""
        try:
            convention, at = blob[0], 1
            if convention & 0x10:                       # generic: the number of type parameters
                _count, at = _number(blob, at)
            params, at = _number(blob, at)
            if params > _MAX_SHAPE_PARAMS:
                return ""
            _returned, at = self._shape_type(blob, at, 0)
            out = []
            for _ in range(params):
                text, at = self._shape_type(blob, at, 0)
                out.append(text)
            return "(%s)" % ",".join(out)
        except _ERRORS:
            return ""

    def _shape_type(self, blob: bytes, at: int, depth: int) -> Tuple[str, int]:
        """One type of a signature at ``at``: ``(short name, next position)``; raises
        ValueError on a form that is not read (a function pointer, a vararg sentinel)."""
        if depth > _MAX_SHAPE_DEPTH:
            raise ValueError("a type nested too deep")
        kind, at = blob[at], at + 1
        if kind in _SHAPE_NAMES:
            return _SHAPE_NAMES[kind], at
        if kind in (0x1F, 0x20):                        # custom modifier, then the type
            _token, at = _number(blob, at)
            return self._shape_type(blob, at, depth + 1)
        if kind in (0x0F, 0x10, 0x45, 0x1D):            # pointer, by reference, pinned, array
            inner, at = self._shape_type(blob, at, depth + 1)
            return inner + {0x0F: "*", 0x10: "&", 0x45: "", 0x1D: "[]"}[kind], at
        if kind in (0x11, 0x12):                        # value type / class: a type token
            coded, at = _number(blob, at)
            return self._short_type(coded), at
        if kind in (0x13, 0x1E):                        # type parameter of the class / the method
            number, at = _number(blob, at)
            return "%s%d" % ("!" if kind == 0x13 else "!!", number), at
        if kind == 0x14:                                # array with a rank
            inner, at = self._shape_type(blob, at, depth + 1)
            rank, at = _number(blob, at)
            sizes, at = _number(blob, at)
            for _ in range(sizes):
                _size, at = _number(blob, at)
            bounds, at = _number(blob, at)
            for _ in range(bounds):
                _bound, at = _number(blob, at)
            return "%s[%s]" % (inner, "," * max(rank - 1, 0)), at
        if kind == 0x15:                                # generic instance: its type, then the arguments
            base, at = self._shape_type(blob, at, depth + 1)
            count, at = _number(blob, at)
            if count > _MAX_SHAPE_PARAMS:
                raise ValueError("too many type arguments")
            parts = []
            for _ in range(count):
                part, at = self._shape_type(blob, at, depth + 1)
                parts.append(part)
            return "%s<%s>" % (base, ",".join(parts)), at
        raise ValueError("a signature form that is not read")

    def _short_type(self, coded: int) -> str:
        """The short name (no namespace, no outer type) of a TypeDefOrRef token."""
        tag, index = coded & 3, coded >> 2
        if tag == 0:
            name = self.type_name(index)
        elif tag == 1:
            name = self.md.type_name(1, index)
        else:
            raise ValueError("a type written as a signature")
        if not name or name == "?":
            raise ValueError("a type without a name")
        return name.replace("/", ".").replace("+", ".").rsplit(".", 1)[-1]

    def method_shape(self, row: int) -> str:
        """:meth:`shape` of this program's own method ``row``."""
        try:
            entry = self.md.row(6, row)
            return self.shape(self._blob(entry[4])) if entry is not None else ""
        except _ERRORS:
            return ""

    def _spec_type(self, row: int) -> Tuple[int, str]:
        """``(row of the own type or 0, name)`` of a type written as a signature
        (a generic class with its type arguments)."""
        md = self.md
        entry = md.row(27, row)
        blob = self._blob(entry[0]) if entry else b""
        try:
            if blob[0] == 0x15:                         # generic instance: class / value type + its type
                coded, _at = _number(blob, 2)
                tag, index = coded & 3, coded >> 2
                if tag == 0:
                    return index, self.type_name(index)
                if tag == 1:
                    return 0, md.type_name(1, index)
        except IndexError:
            pass
        return 0, "?"

    def _parent(self, coded: int) -> Tuple[int, str]:
        """``(row of the own type or 0, name)`` of the type a member reference names."""
        md, tag, index = self.md, coded & 7, coded >> 3
        if tag == 0:
            return index, self.type_name(index)
        if tag == 1:
            return 0, md.type_name(1, index)
        if tag == 4:
            return self._spec_type(index)
        if tag == 3:                                    # a method of this program (a vararg call)
            owner = self._owner(self._first_method, index)
            return owner, self.type_name(owner)
        return 0, "?"

    def _type_scope(self, row: int) -> str:
        """The assembly a referred type (a TypeRef row) is said to be in ("": the reference
        does not name one - a module of this program, something unreadable)."""
        md = self.md
        for _ in range(8):                              # a nested type is referred to through its outer type
            entry = md.row(1, row)
            if entry is None:
                return ""
            tag, index = entry[0] & 3, entry[0] >> 2
            if tag == 2:                                # an assembly reference
                reference = md.row(35, index)
                return md.string(reference[6]) if reference else ""
            if tag != 3:
                return ""
            row = index
        return ""

    def _scope(self, coded: int) -> str:
        """The assembly the type of a member reference is referred to in ("": not known)."""
        tag, index = coded & 7, coded >> 3
        try:
            if tag == 1:
                return self._type_scope(index)
            if tag == 4:                                # a generic class with its type arguments
                entry = self.md.row(27, index)
                blob = self._blob(entry[0]) if entry else b""
                if blob[:1] == b"\x15":
                    coded_type, _at = _number(blob, 2)
                    if coded_type & 3 == 1:
                        return self._type_scope(coded_type >> 2)
        except _ERRORS:
            pass
        return ""

    def assembly_name(self) -> str:
        """The name this program gives itself (its Assembly table; "": none)."""
        try:
            row = self.md.row(32, 1)
            return self.md.string(row[7]) if row else ""
        except _ERRORS:
            return ""

    def forwarded(self) -> frozenset:
        """The types this program only passes on to another assembly (type forwarders)."""
        md, out = self.md, set()
        try:
            for i in range(1, min(md.rows.get(39, 0), 20_000) + 1):
                _flags, _hint, name, namespace, implementation = md.row(39, i)
                if implementation & 3 == 1:             # implemented in another assembly
                    out.add("%s.%s" % (md.string(namespace), md.string(name)) if md.string(namespace) else md.string(name))
        except _ERRORS:
            pass
        return frozenset(out)

    def references(self) -> List[str]:
        """Every member of another program this one refers to (``Namespace.Type::Member``)
        and every Windows function it imports - what its own reference tables name."""
        md = self.md
        out = list(self._imports.values())
        try:
            for i in range(1, min(md.rows.get(10, 0), dotnet_meta._MAX_ROWS) + 1):
                row = md.row(10, i)
                if row[0] & 7 in (1, 4):                # a type of another program (or a generic form of one)
                    own, owner = self._parent(row[0])
                    if not own:
                        out.append("%s::%s" % (owner, md.string(row[1])))
        except _ERRORS as exc:
            raise IlError("the tables cannot be read (%s)" % type(exc).__name__)
        return out

    def defined(self, wanted) -> Iterator[str]:
        """``Namespace.Type::Method`` of every method this program defines itself in a
        type whose full name ``wanted`` accepts."""
        md = self.md
        try:
            for index, name in enumerate(self._type_names):
                if wanted(name):
                    for row in range(self._first_method[index], self._first_method[index + 1]):
                        entry = md.row(6, row)
                        if entry is not None:
                            yield "%s::%s" % (name, md.string(entry[3]))
        except _ERRORS as exc:
            raise IlError("the tables cannot be read (%s)" % type(exc).__name__)

    def callee(self, token: int) -> Callee:
        """What a call / newobj / ldftn token names."""
        known = self._callees.get(token)
        if known is not None:
            return known
        md, table, index = self.md, token >> 24, token & 0xFFFFFF
        out = Callee("?", 0, False, OTHER)
        try:
            if table == 0x2B:                           # a generic method with its type arguments
                row = md.row(43, index)
                if row is not None:
                    table, index = (0x06, 0x0A)[row[0] & 1], row[0] >> 1
            if table == 0x0A:
                row = md.row(10, index)
                if row is not None:
                    _own, owner = self._parent(row[0])
                    out = Callee("%s::%s" % (owner, md.string(row[1])), *self._signature(self._blob(row[2])),
                                 scope=self._scope(row[0]), shape=self.shape(self._blob(row[2])))
            elif table == 0x06:
                row = md.row(6, index)
                if row is not None:
                    owner = self.type_name(self._owner(self._first_method, index))
                    name = "%s::%s" % (owner, md.string(row[3]))
                    out = Callee(name, *self._signature(self._blob(row[4])), own=index,
                                 shape=self.shape(self._blob(row[4])))
            elif table == 0x11:                         # calli: a signature by itself
                row = md.row(17, index)
                if row is not None:
                    out = Callee("?", *self._signature(self._blob(row[0])))
        except _ERRORS:
            out = Callee("?", 0, False, OTHER)
        self._callees[token] = out
        return out

    def imported(self, method_row: int) -> str:
        """The name of the Windows function an own method stands for (P/Invoke; "" = none)."""
        return self._imports.get(method_row, "")

    def field(self, token: int) -> Tuple[int, str]:
        """``(row of the own type that declares it or 0, name)`` of a field token."""
        known = self._fields.get(token)
        if known is not None:
            return known
        md, table, index = self.md, token >> 24, token & 0xFFFFFF
        out = (0, "?")
        try:
            if table == 0x04:
                row = md.row(4, index)
                if row is not None:
                    out = (self._owner(self._first_field, index), md.string(row[1]))
            elif table == 0x0A:
                row = md.row(10, index)
                if row is not None:
                    out = (self._parent(row[0])[0], md.string(row[1]))
        except _ERRORS:
            out = (0, "?")
        self._fields[token] = out
        return out

    def string(self, token: int) -> str:
        """The text an ``ldstr`` token names ("" when it cannot be read)."""
        heap, at = self.md.streams.get("#US", b""), token & 0xFFFFFF
        try:
            size, at = _number(heap, at)
            return heap[at:at + max(size - 1, 0)].decode("utf-16-le", "replace")[:400]
        except IndexError:
            return ""

    def names(self) -> frozenset:
        """Every type this program defines or refers to, by full name."""
        md = self.md
        try:
            return frozenset(self._type_names) | frozenset(
                md.type_name(1, i) for i in range(1, min(md.rows.get(1, 0), dotnet_meta._MAX_ROWS) + 1))
        except _ERRORS as exc:
            raise IlError("the tables cannot be read (%s)" % type(exc).__name__)
