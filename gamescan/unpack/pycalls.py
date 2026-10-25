"""The calls a compiled Python 2.7 file makes, rebuilt from its instructions.

The instructions of every code object (:func:`gamescan.unpack.pyo.load`) are
walked once, in the order they are stored, with a small model of Python's
value stack that holds *texts*, not values: loading the name ``os`` puts the
text ``os`` on it, loading an attribute turns it into ``os.system``, and a
call turns the callee and its arguments into ``os.system('...')``. Whatever
leaves the stack with a call or a text constant in it is written down as one
line of Python-like text at the line number the file's line table gives for
it - imports, assignments, calls. That text is what the ordinary Python rules
read.

Nothing is run and no value is computed. The instruction numbers of Python
2.7 are written out below (the ``dis`` / ``opcode`` modules of the Python that
runs the scanner describe Python 3 and are not used).

This is a sweep, not a decompiler: jumps are not followed, so the text holds
every call the file contains, but not which branch it is in, and a value
that depends on a branch (``a if x else b``) is put together approximately.
A name imported with ``from m import n`` is written ``m.n`` where it is used.

Limits: number of instructions per file, entries on the modelled stack,
length of one text, highest line number, size of the rebuilt text. An
instruction number that Python 2.7 does not have, an argument that points
at nothing, or a file beyond the limits gives no result at all - the caller
reports the file as not read.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/unpack/pycalls.py")

import re
import struct
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from . import limits, pyo

_MAX_INSTRUCTIONS = 2_000_000            # all code objects of one file together
_MAX_STACK = 256                         # entries of the modelled stack
_MAX_TEXT = 4000                         # characters of one rebuilt expression
_MAX_LINE = 1_000_000                    # highest line number
_MAX_OUTPUT = 8 * 1024 * 1024            # characters of the rebuilt text
_MAX_CODES = 100_000                     # code objects in one file

# Python 2.7 instruction numbers (Include/opcode.h of CPython 2.7)
HAVE_ARGUMENT = 90
EXTENDED_ARG = 145
_NAMES = {
    0: "STOP_CODE", 1: "POP_TOP", 2: "ROT_TWO", 3: "ROT_THREE", 4: "DUP_TOP", 5: "ROT_FOUR", 9: "NOP",
    10: "UNARY_POSITIVE", 11: "UNARY_NEGATIVE", 12: "UNARY_NOT", 13: "UNARY_CONVERT", 15: "UNARY_INVERT",
    19: "BINARY_POWER", 20: "BINARY_MULTIPLY", 21: "BINARY_DIVIDE", 22: "BINARY_MODULO", 23: "BINARY_ADD",
    24: "BINARY_SUBTRACT", 25: "BINARY_SUBSCR", 26: "BINARY_FLOOR_DIVIDE", 27: "BINARY_TRUE_DIVIDE",
    28: "INPLACE_FLOOR_DIVIDE", 29: "INPLACE_TRUE_DIVIDE", 30: "SLICE+0", 31: "SLICE+1", 32: "SLICE+2",
    33: "SLICE+3", 40: "STORE_SLICE+0", 41: "STORE_SLICE+1", 42: "STORE_SLICE+2", 43: "STORE_SLICE+3",
    50: "DELETE_SLICE+0", 51: "DELETE_SLICE+1", 52: "DELETE_SLICE+2", 53: "DELETE_SLICE+3",
    54: "STORE_MAP", 55: "INPLACE_ADD", 56: "INPLACE_SUBTRACT", 57: "INPLACE_MULTIPLY",
    58: "INPLACE_DIVIDE", 59: "INPLACE_MODULO", 60: "STORE_SUBSCR", 61: "DELETE_SUBSCR",
    62: "BINARY_LSHIFT", 63: "BINARY_RSHIFT", 64: "BINARY_AND", 65: "BINARY_XOR", 66: "BINARY_OR",
    67: "INPLACE_POWER", 68: "GET_ITER", 70: "PRINT_EXPR", 71: "PRINT_ITEM", 72: "PRINT_NEWLINE",
    73: "PRINT_ITEM_TO", 74: "PRINT_NEWLINE_TO", 75: "INPLACE_LSHIFT", 76: "INPLACE_RSHIFT",
    77: "INPLACE_AND", 78: "INPLACE_XOR", 79: "INPLACE_OR", 80: "BREAK_LOOP", 81: "WITH_CLEANUP",
    82: "LOAD_LOCALS", 83: "RETURN_VALUE", 84: "IMPORT_STAR", 85: "EXEC_STMT", 86: "YIELD_VALUE",
    87: "POP_BLOCK", 88: "END_FINALLY", 89: "BUILD_CLASS",
    90: "STORE_NAME", 91: "DELETE_NAME", 92: "UNPACK_SEQUENCE", 93: "FOR_ITER", 94: "LIST_APPEND",
    95: "STORE_ATTR", 96: "DELETE_ATTR", 97: "STORE_GLOBAL", 98: "DELETE_GLOBAL", 99: "DUP_TOPX",
    100: "LOAD_CONST", 101: "LOAD_NAME", 102: "BUILD_TUPLE", 103: "BUILD_LIST", 104: "BUILD_SET",
    105: "BUILD_MAP", 106: "LOAD_ATTR", 107: "COMPARE_OP", 108: "IMPORT_NAME", 109: "IMPORT_FROM",
    110: "JUMP_FORWARD", 111: "JUMP_IF_FALSE_OR_POP", 112: "JUMP_IF_TRUE_OR_POP", 113: "JUMP_ABSOLUTE",
    114: "POP_JUMP_IF_FALSE", 115: "POP_JUMP_IF_TRUE", 116: "LOAD_GLOBAL", 119: "CONTINUE_LOOP",
    120: "SETUP_LOOP", 121: "SETUP_EXCEPT", 122: "SETUP_FINALLY", 124: "LOAD_FAST", 125: "STORE_FAST",
    126: "DELETE_FAST", 130: "RAISE_VARARGS", 131: "CALL_FUNCTION", 132: "MAKE_FUNCTION",
    133: "BUILD_SLICE", 134: "MAKE_CLOSURE", 135: "LOAD_CLOSURE", 136: "LOAD_DEREF", 137: "STORE_DEREF",
    140: "CALL_FUNCTION_VAR", 141: "CALL_FUNCTION_KW", 142: "CALL_FUNCTION_VAR_KW", 143: "SETUP_WITH",
    145: "EXTENDED_ARG", 146: "SET_ADD", 147: "MAP_ADD",
}
_UNARY = {"UNARY_POSITIVE": "+", "UNARY_NEGATIVE": "-", "UNARY_NOT": "not ", "UNARY_INVERT": "~"}
_BINARY = {"POWER": "**", "MULTIPLY": "*", "DIVIDE": "/", "MODULO": "%", "ADD": "+", "SUBTRACT": "-",
           "FLOOR_DIVIDE": "//", "TRUE_DIVIDE": "/", "LSHIFT": "<<", "RSHIFT": ">>", "AND": "&",
           "XOR": "^", "OR": "|"}
_COMPARE = ("<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "==", "==")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_NOT_WORD = re.compile(r"[^A-Za-z0-9_]")
# names the compiler puts into a call by itself: the two halves of a "with" statement
COMPILER_NAMES = frozenset({"__enter__", "__exit__"})
_HOLE = "_"                              # a value the sweep does not know


class Unreadable(Exception):
    pass


class Function:
    """One code object of the file kept apart from the others (the second
    output of the sweep, for the tracer that follows data: in the flat text a
    ``data`` of one function is the ``data`` of every function). ``args``: its
    parameters. ``is_class``: it is the body of a class. ``lines``: ``(line,
    text)`` - what the flat text holds for this code object, and besides it
    the plain assignments (``a = b``) and ``return x``. ``inner``: the code
    objects defined inside it."""

    __slots__ = ("name", "first_line", "args", "is_class", "lines", "inner")

    def __init__(self, name: str, first_line: int, args: Tuple[str, ...]) -> None:
        self.name, self.first_line, self.args = name, first_line, args
        self.is_class = False
        self.lines: List[Tuple[int, str]] = []
        self.inner: List["Function"] = []


class Listing:
    """``text``: the rebuilt lines, each at its line number. ``called``: every
    name that is part of what a call calls (``os`` and ``system`` for
    ``os.system(...)``), as it stands in the file. ``calls``: how many calls.
    ``root``: the same per function (:class:`Function`; the module's own code
    is the root) - None when that second output grew beyond the size limit."""

    def __init__(self, text: str, called: FrozenSet[str], calls: int,
                 root: Optional[Function] = None) -> None:
        self.text, self.called, self.calls, self.root = text, called, calls, root


class _Item:
    """One entry of the modelled stack: a text, whether a call or a text
    constant is inside it (then it is worth writing down), and the names it
    was put together from (asked when it is called)."""

    __slots__ = ("text", "worth", "names", "module")

    def __init__(self, text: str, worth: bool = False, names: FrozenSet[str] = frozenset(),
                 module: bool = False) -> None:
        if len(text) > _MAX_TEXT:
            limits.hit("pyo", "a text or expression longer than %d characters: only its start was read" % _MAX_TEXT)
        self.text = text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT - 3] + "..."
        self.worth, self.names = worth, names
        self.module = module             # a module, or a name taken out of one, by an import


def _name(raw: bytes) -> str:
    """A name out of the file as an identifier (a name is any bytes there)."""
    text = raw.decode("latin-1")
    if _IDENTIFIER.match(text):
        return text
    return "_" + _NOT_WORD.sub("_", text)[:80]


def _dotted(raw: bytes) -> str:
    return ".".join(_name(part.encode("latin-1")) for part in raw.decode("latin-1").split(".")[:20])


def _constant(value) -> Tuple[str, bool]:
    """``(text, is it a text constant)`` for a constant of the file."""
    if isinstance(value, bytes):
        try:
            return repr(value.decode("utf-8")), True
        except UnicodeDecodeError:
            return repr(value.decode("latin-1")), True
    if isinstance(value, str):
        return repr(value), True
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value), False
    if value is Ellipsis:
        return "Ellipsis", False
    if isinstance(value, pyo.Code):
        return "_code_" + _NOT_WORD.sub("_", value.name.decode("latin-1"))[:60], False
    if isinstance(value, tuple):
        parts = [_constant(one) for one in value[:50]]
        return "(%s,)" % ", ".join(text for text, _ in parts), any(worth for _, worth in parts)
    return _HOLE, False


class _Sweep:
    def __init__(self) -> None:
        self.lines: Dict[int, List[str]] = {}
        self.size = 0
        self.called: Set[str] = set()
        self.calls = 0
        self.left = _MAX_INSTRUCTIONS
        self.codes = 0
        self.imported: Dict[str, str] = {}       # name in the file -> module.name it was imported as
        self.own: Optional[List[Tuple[int, str]]] = None    # the lines of the code object being read
        self.own_size = 0
        self.overflow = False                    # the per-function output was given up (too large)

    # -- what is written down ---------------------------------------------------
    def write(self, line: int, text: str, flat: bool = True, own: bool = True) -> None:
        """``flat``: into the text of the whole file. ``own``: into the lines of
        the code object that is being read."""
        line = min(max(line, 1), _MAX_LINE)
        if flat:
            self.size += len(text) + 2
            if self.size > _MAX_OUTPUT:
                raise Unreadable(limits.hit("pyo", "more than %d MB of rebuilt calls" % (_MAX_OUTPUT >> 20)))
            self.lines.setdefault(line, []).append(text)
        if own and self.own is not None and not self.overflow:
            self.own_size += len(text) + 2
            if self.own_size > _MAX_OUTPUT:
                limits.hit("pyo", "more than %d MB of rebuilt calls in the functions: they were not read one by one" % (_MAX_OUTPUT >> 20))
                self.overflow = True             # the flat text stays; only this output is dropped
            else:
                self.own.append((line, text))

    def keep(self, line: int, item: Optional[_Item], form: str = "%s") -> None:
        """An entry leaves the stack: written down if a call or a text is in it."""
        if item is not None and item.worth:
            self.write(line, form % item.text)

    # -- one code object ----------------------------------------------------------
    def code(self, code: pyo.Code, depth: int = 0) -> Function:
        self.codes += 1
        if self.codes > _MAX_CODES:
            raise Unreadable(limits.hit("pyo", "more than %d code objects" % _MAX_CODES))
        if code.first_line > _MAX_LINE:
            limits.hit("pyo", "a line number above %d" % _MAX_LINE)
        if not 0 <= code.first_line <= _MAX_LINE or len(code.line_table) % 2:
            raise Unreadable("bad line table")
        count = max(code.arg_count, 0) + bool(code.flags & 4) + bool(code.flags & 8)
        record = Function(_name(code.name), code.first_line,
                            tuple(_name(one) for one in code.local_names[:min(count, 255)]))
        for constant in code.constants:          # (the reader bounds the nesting)
            if isinstance(constant, pyo.Code):
                record.inner.append(self.code(constant, depth + 1))
        outer, self.own = self.own, record.lines
        data, constants, names = code.instructions, code.constants, code.names
        local, cells = code.local_names, code.cell_names + code.free_names
        # where each line starts: (offset, line), from the line table
        starts, offset, line = [], 0, code.first_line
        for index in range(0, len(code.line_table), 2):
            step, lines = code.line_table[index], code.line_table[index + 1]
            if step:
                starts.append((offset, line))
            offset += step
            line += lines
        starts.append((offset, line))
        starts.reverse()                         # popped as the sweep passes them
        line = code.first_line
        stack: List[_Item] = []
        merge: Dict[int, List[Tuple[str, object]]] = {}    # jump target -> what to do there

        def pop() -> _Item:
            return stack.pop() if stack else _Item(_HOLE)

        def push(item: _Item) -> None:
            if len(stack) >= _MAX_STACK:
                self.keep(line, stack.pop(0))
            stack.append(item)

        def drop(count: int) -> None:
            for _ in range(count):
                self.keep(line, pop())

        def named(table, index: int) -> str:
            if not 0 <= index < len(table):
                raise Unreadable("a name that is not there")
            return _name(table[index])

        position, extended = 0, 0
        while position < len(data):
            self.left -= 1
            if self.left < 0:
                raise Unreadable(limits.hit("pyo", "more than %d instructions" % _MAX_INSTRUCTIONS))
            while starts and starts[-1][0] <= position:
                line = starts.pop()[1]
            for kind, what in merge.pop(position, ()):
                if kind == "depth":              # the end of a loop: its iterator is gone
                    while len(stack) > what:
                        self.keep(line, stack.pop())
                elif kind == "either":           # two branches left a value each
                    if len(stack) > what >= 1:
                        top = stack.pop()
                        while len(stack) >= what:
                            other = stack.pop()
                            top = _Item("(%s or %s)" % (other.text, top.text), other.worth or top.worth,
                                        other.names | top.names)
                        stack.append(top)
                else:                            # "x and y" / "x or y"
                    right = pop()
                    push(_Item("(%s %s %s)" % (what.text, kind, right.text), what.worth or right.worth,
                               what.names | right.names))
            number = data[position]
            op = _NAMES.get(number)
            if op is None:
                raise Unreadable("not an instruction of Python 2.7")
            position += 1
            arg = 0
            if number >= HAVE_ARGUMENT:
                if position + 2 > len(data):
                    raise Unreadable("the instructions end inside an instruction")
                arg = struct.unpack_from("<H", data, position)[0] | extended
                position += 2
                extended = 0
                if op == "EXTENDED_ARG":
                    extended = arg << 16
                    continue

            if op == "LOAD_CONST":
                if arg >= len(constants):
                    raise Unreadable("a constant that is not there")
                text, worth = _constant(constants[arg])
                push(_Item(text, worth))
            elif op in ("LOAD_NAME", "LOAD_GLOBAL"):
                name = named(names, arg)
                push(_Item(self.imported.get(name, name), False, frozenset({name})))
            elif op == "LOAD_FAST":
                name = named(local, arg)
                push(_Item(self.imported.get(name, name), False, frozenset({name})))
            elif op in ("LOAD_DEREF", "LOAD_CLOSURE"):
                name = named(cells, arg)
                push(_Item(name, False, frozenset({name})))
            elif op == "LOAD_ATTR":
                name, value = named(names, arg), pop()
                push(_Item("%s.%s" % (value.text, name), value.worth, value.names | {name}, value.module))
            elif op == "IMPORT_NAME":
                if arg >= len(names):
                    raise Unreadable("a name that is not there")
                module = _dotted(names[arg])
                wanted = pop()                   # the names to take out of it (None: the module)
                pop()                            # the level
                self.write(line, "import %s" % module)
                if wanted.text == "None":        # "import a.b" gives a; ".b" follows as an attribute
                    module = module.split(".")[0]
                push(_Item(module, False, frozenset(module.split(".")), True))
            elif op == "IMPORT_FROM":
                name, module = named(names, arg), stack[-1].text if stack else _HOLE
                if _DOTTED.match(module):
                    self.write(line, "from %s import %s" % (module, name))
                    push(_Item("%s.%s" % (module, name), False, frozenset({name}), True))
                else:
                    push(_Item(name, False, frozenset({name})))
            elif op == "IMPORT_STAR":
                module = pop().text
                if _DOTTED.match(module):
                    self.write(line, "from %s import *" % module)
            elif op in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF"):
                name = named(local if op == "STORE_FAST" else cells if op == "STORE_DEREF" else names, arg)
                value = pop()
                if value.module and _DOTTED.match(value.text) and value.text != name:
                    self.imported[name] = value.text      # import m as name / from m import n
                elif not value.module:
                    self.imported.pop(name, None)
                if value.text != name:
                    self.keep(line, value, name + " = %s")
                    # a = b: per function only (not "f = <its code>": the function is there)
                    if not value.worth and value.text != _HOLE and not value.text.startswith("_code_"):
                        self.write(line, "%s = %s" % (name, value.text), flat=False)
            elif op == "STORE_ATTR":
                target, value = pop(), pop()
                self.keep(line, target)
                self.keep(line, value, "%s.%s = %%s" % (target.text.replace("%", "%%"), named(names, arg)))
                if not value.worth and value.text != _HOLE:
                    self.write(line, "%s.%s = %s" % (target.text, named(names, arg), value.text), flat=False)
            elif op in ("CALL_FUNCTION", "CALL_FUNCTION_VAR", "CALL_FUNCTION_KW", "CALL_FUNCTION_VAR_KW"):
                extra = []
                if op in ("CALL_FUNCTION_KW", "CALL_FUNCTION_VAR_KW"):
                    extra.append(("**", pop()))
                if op in ("CALL_FUNCTION_VAR", "CALL_FUNCTION_VAR_KW"):
                    extra.append(("*", pop()))
                keywords = []
                for _ in range((arg >> 8) & 0xFF):
                    value, key = pop(), pop()
                    word = key.text[1:-1] if key.text[:1] in "'\"" and _IDENTIFIER.match(key.text[1:-1]) else _HOLE
                    keywords.append(("%s=" % word, value))
                plain = [("", pop()) for _ in range(arg & 0xFF)]
                callee = pop()
                parts = plain[::-1] + keywords[::-1] + extra[::-1]
                self.calls += 1
                self.called.update(callee.names)
                push(_Item("%s(%s)" % (callee.text, ", ".join(mark + one.text for mark, one in parts)),
                           True, callee.names))
            elif op == "POP_TOP":
                self.keep(line, pop())
            elif op == "RETURN_VALUE":
                value = pop()
                if value.worth:                              # the flat text: as before
                    self.write(line, value.text, own=False)
                if value.text not in ("None", _HOLE):        # per function: what it returns
                    self.write(line, "return " + value.text, flat=False)
            elif op in ("YIELD_VALUE", "PRINT_EXPR", "PRINT_ITEM", "LIST_APPEND", "SET_ADD",
                        "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE", "DELETE_ATTR", "PRINT_NEWLINE_TO"):
                self.keep(line, pop())
                if op == "YIELD_VALUE":
                    push(_Item(_HOLE))
            elif op in ("PRINT_ITEM_TO", "DELETE_SUBSCR", "MAP_ADD", "DELETE_SLICE+1", "DELETE_SLICE+2"):
                drop(2)
            elif op in ("STORE_SUBSCR", "DELETE_SLICE+3", "STORE_SLICE+1", "STORE_SLICE+2"):
                drop(3)
            elif op == "STORE_SLICE+0":
                drop(2)
            elif op == "STORE_SLICE+3":
                drop(4)
            elif op == "DELETE_SLICE+0":
                drop(1)
            elif op == "EXEC_STMT":
                pop(), pop()
                value = pop()
                self.write(line, _IND[0] % value.text)
            elif op == "RAISE_VARARGS":
                drop(arg & 0xFF)
            elif op in _UNARY:
                value = pop()
                push(_Item("(%s%s)" % (_UNARY[op], value.text), value.worth, value.names))
            elif op == "UNARY_CONVERT":
                value = pop()
                push(_Item("repr(%s)" % value.text, value.worth, value.names))
            elif op == "BINARY_SUBSCR":
                index, value = pop(), pop()
                push(_Item("%s[%s]" % (value.text, index.text), value.worth or index.worth,
                           value.names | index.names))
            elif op.startswith(("BINARY_", "INPLACE_")):
                right, left = pop(), pop()
                push(_Item("(%s %s %s)" % (left.text, _BINARY[op.split("_", 1)[1]], right.text),
                           left.worth or right.worth, left.names | right.names))
            elif op == "COMPARE_OP":
                right, left = pop(), pop()
                push(_Item("(%s %s %s)" % (left.text, _COMPARE[arg] if arg < len(_COMPARE) else "==",
                                           right.text), left.worth or right.worth, left.names | right.names))
            elif op.startswith("SLICE+"):
                parts = [pop() for _ in range((1, 2, 2, 3)[number - 30])][::-1]
                push(_Item("%s[%s]" % (parts[0].text, ":".join(one.text for one in parts[1:]) or ":"),
                           any(one.worth for one in parts), parts[0].names))
            elif op == "BUILD_SLICE":
                parts = [pop() for _ in range(arg if arg in (2, 3) else 2)][::-1]
                push(_Item("slice(%s)" % ", ".join(one.text for one in parts), any(one.worth for one in parts)))
            elif op in ("BUILD_TUPLE", "BUILD_LIST", "BUILD_SET"):
                if arg > _MAX_STACK:
                    raise Unreadable(limits.hit("pyo", "more than %d members in one list" % _MAX_STACK))
                parts = [pop() for _ in range(arg)][::-1]
                used = frozenset().union(*(one.names for one in parts)) if parts else frozenset()
                push(_Item("[%s]" % ", ".join(one.text for one in parts), any(one.worth for one in parts), used))
            elif op == "BUILD_MAP":
                push(_Item("{}"))
            elif op == "STORE_MAP":
                key, value = pop(), pop()
                target = pop()
                inside = target.text[1:-1] if target.text[:1] == "{" and target.text[-1:] == "}" else ""
                push(_Item("{%s%s: %s}" % (inside + ", " if inside else "", key.text, value.text),
                           target.worth or key.worth or value.worth, target.names))
            elif op == "DUP_TOP":
                top = pop()
                push(top)
                push(_Item(top.text, False, top.names))      # written down once, not twice
            elif op == "DUP_TOPX":
                if not 1 <= arg <= 5:
                    raise Unreadable("bad copy count")
                tops = [pop() for _ in range(arg)][::-1]
                for one in tops:
                    push(one)
                for one in tops:
                    push(_Item(one.text, False, one.names))
            elif op in ("ROT_TWO", "ROT_THREE", "ROT_FOUR"):
                count = {"ROT_TWO": 2, "ROT_THREE": 3, "ROT_FOUR": 4}[op]
                tops = [pop() for _ in range(count)]         # top first
                for one in [tops[0]] + tops[:0:-1]:
                    push(one)
            elif op == "UNPACK_SEQUENCE":
                if arg > _MAX_STACK:
                    raise Unreadable(limits.hit("pyo", "more than %d members in one list" % _MAX_STACK))
                self.keep(line, pop())
                for _ in range(arg):
                    push(_Item(_HOLE))
            elif op == "GET_ITER":
                pass                                         # the same entry, as an iterator
            elif op == "FOR_ITER":
                merge.setdefault(position + arg, []).append(("depth", max(len(stack) - 1, 0)))
                push(_Item(_HOLE))
            elif op in ("JUMP_IF_FALSE_OR_POP", "JUMP_IF_TRUE_OR_POP"):
                merge.setdefault(arg, []).append(("and" if op == "JUMP_IF_FALSE_OR_POP" else "or", pop()))
            elif op == "JUMP_FORWARD":
                if stack:
                    merge.setdefault(position + arg, []).append(("either", len(stack)))
            elif op in ("MAKE_FUNCTION", "MAKE_CLOSURE"):
                function = pop()
                if op == "MAKE_CLOSURE":
                    pop()
                drop(arg & 0xFFFF)                           # default values
                push(_Item(function.text))
            elif op == "BUILD_CLASS":
                self.keep(line, pop())
                bases, name = pop(), pop()
                self.keep(line, bases)
                push(_Item(_HOLE))
            elif op == "LOAD_LOCALS":
                record.is_class = True                     # only the body of a class does this
                push(_Item(_HOLE))
            elif op == "SETUP_WITH":
                manager = pop()
                self.called.update(manager.names)
                push(_Item(_HOLE))
                push(_Item(manager.text, manager.worth, manager.names))
            elif op in ("STOP_CODE", "NOP", "PRINT_NEWLINE", "BREAK_LOOP", "WITH_CLEANUP", "POP_BLOCK",
                        "END_FINALLY", "DELETE_NAME", "DELETE_GLOBAL", "DELETE_FAST", "JUMP_ABSOLUTE",
                        "CONTINUE_LOOP", "SETUP_LOOP", "SETUP_EXCEPT", "SETUP_FINALLY"):
                pass
            else:                                            # in the table and not handled: a mistake here
                raise Unreadable("instruction without a rule: " + op)
        for item in stack:
            self.keep(line, item)
        self.own = outer
        return record


def rebuild(data: bytes) -> Optional[Listing]:
    """The calls, imports and assignments of a compiled Python 2.7 file as
    Python-like text, each line at its line number (None: the file could not
    be read to its end within the limits)."""
    code = pyo.load(data)
    if code is None:
        return None
    sweep = _Sweep()
    try:
        root = sweep.code(code)
    except (Unreadable, struct.error, RecursionError, IndexError, MemoryError):
        return None
    if sweep.overflow:
        root = None
    if not sweep.lines:
        return Listing("", frozenset(), 0, root)
    last = max(sweep.lines)
    text = "\n".join("; ".join(sweep.lines.get(number, ())) for number in range(1, last + 1))
    return Listing(text, frozenset(sweep.called), sweep.calls, root)
