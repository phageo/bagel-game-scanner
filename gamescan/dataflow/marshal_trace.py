"""``exec`` / ``eval`` of ``marshal.loads(x)``: where does ``x`` come from? (phageo, 2026-10-31)

Compiled code that a script turns back into code and runs is the classic loader when a decoding
step stands before it - and it is also what old Ren'Py does with its own compiled scripts
(``renpy/python.py``). ``PY-OBF-001`` (CRITICAL) used to look at one line and could not tell the two
apart. This reading follows ``x`` inside the file:

- it reaches a decode, a decompression, a decryption or a network source -> ``PY-OBF-001`` stands;
- the trace is not complete -> ``PY-OBF-001`` stands;
- the trace is complete and reaches none of these -> ``PY-OBF-003``, HIGH (precedent: 2026-10-05,
  option B - a Ren'Py version that cannot be verified is HIGH).

**Complete** means every value ``x`` can have in this file was followed to one of these ends: text
written in the file, or a file that is read. A parameter of a module-level function is followed into
each caller in the file; when no code of this file calls the function, it is the file's edge. Either
way other files can call that function too.

**Across files (phageo, 2026-10-31, second and third sessions).** A finding whose trace went through
such a parameter is kept with the function and the parameter, and once the whole scan was seen
(:func:`join`, ``Scanner._join_stored_code``) the callers in the other scripts of the same game are
looked for, one hop, by the module names of ``dataflow/shared.py``: an import of that file's name, or
Ren'Py's store. Callers in the function's own file and in other files all count:

- a caller's argument reaches a decode, a decompression, a decryption or a network source ->
  ``PY-OBF-001`` CRITICAL, as if both stood in one file;
- an argument that cannot be followed (an attribute, say: ``self.d``, or a parameter nothing calls)
  counts as not reaching only if the caller's function - with the functions around and inside it -
  and the module-level code of its file make no decoding, decompressing, decrypting or network call;
  otherwise ``PY-OBF-001`` CRITICAL (:meth:`Reading.handed`);
- callers found, none reaches one -> ``PY-OBF-003`` stands;
- no caller found -> ``PY-OBF-003`` stands (a documented limit, ``docs/memory/limits.md``);
- a limit stopped the search -> not complete: ``PY-OBF-001`` CRITICAL.

The callers are read by this same line tracer: Python 2 files defeat ``ast``, and so the reading of
``remote_py.study``. The scripts' texts are kept for that, packed (:class:`Kept`, ``MAX_KEPT``).

**Not complete** is everything else, and then the CRITICAL stands: an attribute, a call of a function
the file does not define, a name nothing binds, a name bound by ``global``, ``import``, ``for``, a tuple
or in place, a method's or an inner function's parameter, a function handed on as a value, a
statement over several lines, an ``exec`` that names ``x`` in a text, writing through ``globals()``.

It is a tracer over lines, not a parser: Python 2 files (``exec x in y``, ``print x``) must be read, and
``ast`` cannot read them. Strings and comments are blanked first; nothing of the file is run.
Bounded: ``MAX_TEXT`` characters, ``MAX_LINE`` per line, ``MAX_HANDOVERS`` calls, ``MAX_CHAIN`` names,
``MAX_STEPS`` steps - past any of them the trace is not complete.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/marshal_trace.py")

import re
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Finding, Severity
from .shared import _module_path, _script

SPLIT_FROM = "PY-OBF-001"
RULE = "PY-OBF-003"
TITLE = "Runs stored compiled code that no decoding step leads to"
REASON = (
    "This script turns stored compiled code back into code and runs it. The value was followed through "
    "the file, and no decoding, unpacking, decryption or download leads to it. Old game engines run "
    "their own compiled scripts this way; a loader can do the same with code kept in another file. "
    "What it runs depends on what is handed to it, and that could not be proven harmless.")
MAX_TEXT = 4 << 20
MAX_LINE = 4000
MAX_HANDOVERS = 4
MAX_STEPS = 20_000
MAX_CHAIN = 64                  # names followed one through another (each is a nested call here)
MAX_KEPT = 64 << 20             # packed script texts kept per scan, for the callers in other files
MAX_SCRIPTS = 20_000            # ... and scripts
MAX_CALLS = 256                 # calls of one function looked at in the other files of a game

TEXT = "marshal_text"           # ctx.cache: the text of a script, for the scanner to keep
EDGES = "marshal_edges"         # Finding.context: (function, position, parameter, called in its file)
WAS = "marshal_was"             # Finding.context: the title and reason of the finding before the split

# NEAR: an argument that cannot be followed, beside a decoding call (Reading.handed); _value never says it
CLEAN, OPEN, NEAR, DIRTY = 0, 1, 2, 3

# what ends the question: a decode, a decompression, a decryption, a network source
_REACHED = re.compile(
    _IND[0],
    re.I)
_LITERAL = re.compile(r"[A-Za-z]{0,2}\"\"\Z")
_NAME = re.compile(r"([A-Za-z_]\w*)(\[[^\[\]]*\])?\Z")
_FILE_READ = re.compile(r"(?:(?:io|codecs)\.)?(?:open|file)\(.*\)\.read\(.*\)\Z"
                        r"|renpy\.(?:exports\.)?(?:file|open_file)\(.*\)\.read\(.*\)\Z"
                        r"|renpy\.loader\.load\(.*\)\.read\(.*\)\Z")
_OPENS = re.compile(r"(?:(?:io|codecs)\.)?(?:open|file)\(|renpy\.(?:exports\.)?(?:file|open_file)\(|renpy\.loader\.load\(")
_NAME_READ = re.compile(r"([A-Za-z_]\w*)\.read\(.*\)\Z")
_CALL = re.compile(r"([A-Za-z_]\w*)\((.*)\)\Z")
_DEF = re.compile(r"[ \t]*def[ \t]+([A-Za-z_]\w*)[ \t]*\(")
_CLASS = re.compile(r"[ \t]*class[ \t]+[A-Za-z_]\w*")
_RETURN = re.compile(r"[ \t]*return\b(.*)\Z")
_SINK = re.compile(r"(?<![\w.])(?:exec|eval)[ \t]*(\()[ \t]*marshal\.loads[ \t]*\(|(?<![\w.])exec[ \t]+marshal\.loads[ \t]*\(")
_WRITES_NAMES = re.compile(r"(?:globals|locals|vars)\(\s*\)\s*\[")
_RUNS_TEXT = re.compile(r"\b(?:exec|eval|execfile|setattr)\b")
_IMPORTS = re.compile(r"[ \t]*(?:from[ \t]+([\w.]+)[ \t]+)?import[ \t]+(.+)\Z")
_NO_CALLS = re.compile(r"[ \t]*(?:import|from|def|class)\b")
_CALLED = re.compile(r"[\w.]*[ \t]*\(")
_OPENERS, _CLOSERS = "([{", ")]}"


class _Spent(Exception):
    pass


def _blanked(text: str) -> List[str]:
    """The file's lines, its strings written as ``""`` and without comments; line numbers stay."""
    out: List[str] = []
    current: List[str] = []
    at, size = 0, len(text)
    while at < size:
        char = text[at]
        if char == "\n":
            out.append("".join(current))
            current = []
            at += 1
        elif char == "#":
            end = text.find("\n", at)
            at = size if end < 0 else end
        elif char in "\"'":
            quote = text[at:at + 3] if text[at:at + 3] in ('"""', "'''") else char
            end = at + len(quote)
            while end < size and not text.startswith(quote, end):
                if len(quote) == 1 and text[end] == "\n":
                    break
                end += 2 if text[end] == "\\" else 1
            stop = min(size, end + (len(quote) if text.startswith(quote, end) else 0))
            current.append('""')
            for _ in range(text.count("\n", at, stop)):       # (lines inside a long string)
                out.append("".join(current))
                current = []
            at = stop
        else:
            current.append(char)
            at += 1
    out.append("".join(current))
    return [re.sub(r"\A([ \t]*)\$[ \t]", r"\1  ", line) for line in out]      # (a Ren'Py "$" line)


def _closed(text: str) -> bool:
    depth = 0
    for char in text:
        depth += (char in _OPENERS) - (char in _CLOSERS)
        if depth < 0:
            return False
    return depth == 0 and not text.rstrip().endswith("\\")


def _pieces(text: str, mark: str) -> List[str]:
    """``text`` cut at the ``mark`` characters outside brackets."""
    out, depth, start = [], 0, 0
    for at, char in enumerate(text):
        depth += (char in _OPENERS) - (char in _CLOSERS)
        if char == mark and depth == 0:
            out.append(text[start:at])
            start = at + 1
    out.append(text[start:])
    return out


def _inside(text: str, opening: int) -> Optional[Tuple[str, int]]:
    """What stands between the bracket at ``opening`` and its partner, and the place after it."""
    depth = 0
    for at in range(opening, len(text)):
        depth += (text[at] in _OPENERS) - (text[at] in _CLOSERS)
        if depth == 0:
            return text[opening + 1:at], at + 1
    return None


def _indent(line: str) -> int:
    return len(line.expandtabs(8)) - len(line.expandtabs(8).lstrip())


def _decoding_call(line: str) -> bool:
    """A line that calls a decode, a decompression, a decryption or a network source: ``import zlib``
    or ``self.decoder = 1`` name one and call nothing."""
    return not _NO_CALLS.match(line) and any(
        "(" in found.group() or _CALLED.match(line, found.end()) for found in _REACHED.finditer(line))


def _within(scope: Optional["_Function"], outer: "_Function") -> bool:
    while scope is not None:
        if scope is outer:
            return True
        scope = scope.parent
    return False


@dataclass(eq=False)
class _Function:
    name: str
    line: int
    indent: int
    parent: Optional["_Function"]
    method: bool
    params: Optional[List[str]] = None           # None: its head could not be read
    lines: List[int] = field(default_factory=list)


class Reading:
    """One file's text, read once, for any number of ``marshal.loads`` lines."""

    def __init__(self, text: str) -> None:
        self.raw = text.split("\n")
        self.code = _blanked(text)
        self.owner: List[Optional[_Function]] = [None] * len(self.code)
        self.functions: Dict[str, List[_Function]] = {}
        self.module: List[int] = []
        self.steps = 0
        self.active: Set[Tuple[str, int]] = set()
        self.sinks: Set[int] = {i for i, line in enumerate(self.code) if _SINK.search(line)}
        self.edges: List[Tuple[str, int, str, bool]] = []    # the parameters the last trace went through
        self._names: Optional[Tuple[Dict[str, str], List[str]]] = None
        self._decoding: Optional[List[int]] = None
        self._scopes()

    def _scopes(self) -> None:
        stack: List[Tuple[int, Optional[_Function]]] = []        # (indent, a function, or None: a class)
        for number, line in enumerate(self.code):
            if not line.strip():
                continue
            indent = _indent(line)
            while stack and indent <= stack[-1][0]:
                stack.pop()
            function = next((item for _i, item in reversed(stack) if item is not None), None)
            self.owner[number] = function
            (function.lines if function is not None else self.module).append(number)
            found = _DEF.match(line)
            if found:
                made = _Function(found.group(1), number, indent, function, bool(stack) and stack[-1][1] is None,
                                 self._head(number, found.end() - 1))
                self.functions.setdefault(made.name, []).append(made)
                stack.append((indent, made))
            elif _CLASS.match(line):
                stack.append((indent, None))

    def _head(self, number: int, opening: int) -> Optional[List[str]]:
        text = self.code[number]
        for more in range(1, 20):
            found = _inside(text, opening)
            if found is not None:
                return [part.strip() for part in _pieces(found[0], ",") if part.strip()]
            if number + more >= len(self.code):
                break
            text += " " + self.code[number + more]
        return None

    def _tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS or len(self.active) > MAX_CHAIN:
            raise _Spent

    # -- the question -----------------------------------------------------------------------------
    def complete_without_decoding(self, number: int) -> bool:
        """Line ``number`` (from 1) runs ``marshal.loads(x)`` and the trace of ``x`` inside the
        file is complete and reaches no decode, decompression, decryption or network source.
        ``edges`` then holds the parameters of module-level functions it went through, each with
        whether code of this file calls that function: other files may call them too."""
        index = number - 1
        self.edges = []
        if not 0 <= index < len(self.code) or len(self.code[index]) > MAX_LINE or len(self.code) > MAX_TEXT:
            return False
        line = self.code[index]
        sinks = list(_SINK.finditer(line))
        if not sinks or _REACHED.search(line):
            return False
        self.steps = 0
        try:
            for sink in sinks:
                found = _inside(line, sink.end() - 1)
                if found is None:
                    return False
                value, after = found
                rest = line[after:].lstrip()
                if sink.group(1):                     # exec(marshal.loads(x)), eval(marshal.loads(x), names)
                    if not rest.startswith((")", ",")):
                        return False
                elif rest and not re.match(r"(?:in\b|;)", rest):     # exec marshal.loads(x) in names
                    return False
                if self._value(value, index, 0) != CLEAN:
                    return False
        except _Spent:
            return False
        return True

    def _value(self, text: str, line: int, depth: int) -> int:
        """What an expression at ``line`` can be: CLEAN, OPEN or DIRTY."""
        self._tick()
        text = text.strip()
        while text.startswith("(") and (_inside(text, 0) or ("", 0))[1] == len(text):
            text = text[1:-1].strip()
        if not text:
            return OPEN
        if _REACHED.search(text):
            return DIRTY
        parts = _pieces(text, "+")
        if len(parts) > 1:
            return max(self._value(part, line, depth) for part in parts)
        if _LITERAL.match(text) or text == "None":
            return CLEAN
        name = _NAME.match(text)
        if name:
            return self._name(name.group(1), line, depth)
        if _FILE_READ.match(text):
            return CLEAN
        read = _NAME_READ.match(text)
        if read:
            return CLEAN if self._is_file(read.group(1), line) else OPEN
        call = _CALL.match(text)
        if call:
            return self._returns(call.group(1), depth)
        return OPEN

    def _name(self, name: str, line: int, depth: int) -> int:
        declared = re.compile(r"[ \t]*(?:global|nonlocal)\b.*(?<![\w.])%s\b" % re.escape(name))
        if any(declared.match(text) for text in self.code):
            return OPEN                               # (any function of the file can bind it)
        scope = self.owner[line]
        while True:
            key = (name, id(scope))
            if key in self.active:
                return CLEAN                          # (a loop: it brings nothing new)
            self.active.add(key)
            try:
                found = self._in_scope(name, scope, depth)
            finally:
                self.active.discard(key)
            if found is not None:
                return found
            if scope is None:
                return OPEN                           # a name nothing here binds
            scope = scope.parent

    def _scope_lines(self, scope: Optional[_Function]) -> List[int]:
        return scope.lines if scope is not None else self.module

    def _in_scope(self, name: str, scope: Optional[_Function], depth: int) -> Optional[int]:
        """What ``name`` can be by what ``scope`` itself does with it (None: it does nothing)."""
        word = re.compile(r"(?<![\w.])%s\b" % re.escape(name))
        escaped = re.escape(name)
        worst: Optional[int] = None
        lines = self._scope_lines(scope)
        for number in lines:
            line = self.code[number]
            if _WRITES_NAMES.search(line):
                return OPEN
            if number not in self.sinks and number < len(self.raw) and _RUNS_TEXT.search(self.raw[number]) \
                    and word.search(self.raw[number]):
                return OPEN                           # (exec("x = ...") binds it unseen)
            if not word.search(line):
                continue
            self._tick()
            if scope is not None and number == scope.line:
                continue                              # (its own head: the parameters, below)
            found = self._binding(name, escaped, line, number, depth)
            if found is not None:
                worst = found if worst is None else max(worst, found)
        if scope is not None and any(self._parameter_name(part) == name for part in scope.params or ()):
            found = self._parameter(scope, name, depth)
            worst = found if worst is None else max(worst, found)
        elif scope is not None and scope.params is None:
            return OPEN
        return worst

    @staticmethod
    def _parameter_name(part: str) -> str:
        return part.split("=", 1)[0].strip().lstrip("*").strip()

    def _binding(self, name: str, escaped: str, line: str, number: int, depth: int) -> Optional[int]:
        """What this line does to ``name``: None (it only reads it), or what the name can be."""
        simple = re.match(r"[ \t]*%s[ \t]*(\+?=)(?!=)(.*)\Z" % escaped, line)
        if simple:
            value = simple.group(2)
            return self._value(value, number, depth) if _closed(value) else OPEN
        if re.search(r"(?<![\w.])%s\[[^\]]*\][ \t]*\^=" % escaped, line) or re.match(r"[ \t]*%s[ \t]*\^=" % escaped, line):
            return DIRTY
        if re.match(r"[ \t]*(?:import|from|global|nonlocal|del|class|def)\b", line) \
                or re.search(r"\bas[ \t]+%s\b" % escaped, line) \
                or re.match(r"[ \t]*for\b[^:]*(?<![\w.])%s\b[^:]*\bin\b" % escaped, line) \
                or re.search(r"(?<![\w.])%s[ \t]*:=" % escaped, line) \
                or re.search(r"(?<![\w.])%s(?:\[[^\]]*\])?[ \t]*(?:[-+*/%%&|]|//|\*\*|<<|>>)?=(?!=)" % escaped,
                             line.split("(", 1)[0]) \
                or re.search(r"(?<![\w.])%s\.(?:extend|append|insert|write|update|frombytes|fromhex)\(" % escaped, line) \
                or re.match(r"[ \t]*[\w.,\s()\[\]*]*,[\w.,\s()\[\]*]*=(?!=)", line) and \
                re.search(r"(?<![\w.])%s\b" % escaped, line.split("=", 1)[0]):
            return OPEN
        return None

    def _parameter(self, function: _Function, name: str, depth: int) -> int:
        """A parameter: the values the file's own calls hand in; the other files' calls are looked
        at afterwards (``edges``, see the module's text)."""
        params = function.params or []
        if function.method or function.parent is not None or len(self.functions.get(function.name, ())) != 1:
            return OPEN
        position = -1
        worst = CLEAN
        for at, part in enumerate(params):
            if part.startswith("*"):
                if self._parameter_name(part) == name:
                    return OPEN
                continue
            if self._parameter_name(part) == name:
                position = at
                if "=" in part:
                    worst = self._value(part.split("=", 1)[1], function.line, depth)
        if position < 0:
            return OPEN
        word = re.compile(r"(?<!\w)%s\b" % re.escape(function.name))
        called = False
        for number, line in enumerate(self.code):
            for found in word.finditer(line):
                if number == function.line and found.start() == _DEF.match(line).start(1):
                    continue                      # (the function's own head)
                self._tick()
                opening = found.end() + len(line[found.end():]) - len(line[found.end():].lstrip())
                if line[opening:opening + 1] != "(":
                    return OPEN                   # handed on as a value
                inside = _inside(line, opening)
                if inside is None or depth + 1 > MAX_HANDOVERS:
                    return OPEN
                called = True
                handed = self._argument(inside[0], position, name)
                if handed is _MANY:
                    return OPEN
                if handed is not None:
                    worst = max(worst, self._value(handed, number, depth + 1))
        self.edges.append((function.name, position, name, called))
        return worst

    @staticmethod
    def _argument(arguments: str, position: int, name: str):
        parts = [part.strip() for part in _pieces(arguments, ",") if part.strip()]
        if any(part.startswith("*") for part in parts):
            return _MANY
        for part in parts:
            if re.match(r"%s[ \t]*=(?!=)" % re.escape(name), part):
                return part.split("=", 1)[1]
        plain = [part for part in parts if not re.match(r"[A-Za-z_]\w*[ \t]*=(?!=)", part)]
        return plain[position] if position < len(plain) else None

    def _is_file(self, name: str, line: int) -> bool:
        """Every binding of ``name`` in its scope opens a file."""
        found = False
        for number in self._scope_lines(self.owner[line]):
            text = self.code[number]
            with_as = re.search(r"\bas[ \t]+%s\b" % re.escape(name), text)
            assigned = re.match(r"[ \t]*%s[ \t]*=(?!=)(.*)\Z" % re.escape(name), text)
            if with_as or assigned:
                if not _OPENS.search(text):
                    return False
                found = True
        return found

    def _returns(self, name: str, depth: int) -> int:
        """A call of a function of this file: what it returns."""
        functions = self.functions.get(name, ())
        if len(functions) != 1 or depth + 1 > MAX_HANDOVERS:
            return OPEN
        function = functions[0]
        worst: Optional[int] = None
        key = ("return " + name, id(function))
        if key in self.active:
            return CLEAN
        self.active.add(key)
        try:
            for number in function.lines:
                self._tick()
                line = self.code[number]
                if re.search(r"\byield\b", line):
                    return OPEN
                found = _RETURN.match(line)
                if found:
                    if not _closed(found.group(1)):
                        return OPEN
                    value = self._value(found.group(1), number, depth + 1) if found.group(1).strip() else CLEAN
                    worst = value if worst is None else max(worst, value)
        finally:
            self.active.discard(key)
        return OPEN if worst is None else worst

    # -- this file as a caller of a function of another file ---------------------------------------
    def imports(self) -> Tuple[Dict[str, str], List[str]]:
        """What the file imports: local name -> dotted name, and the modules of ``import *``."""
        if self._names is not None:
            return self._names
        names: Dict[str, str] = {}
        stars: List[str] = []
        for number, line in enumerate(self.code):
            found = _IMPORTS.match(line)
            if not found:
                continue
            text = found.group(2)
            for more in range(1, 20):
                if _closed(text) or number + more >= len(self.code):
                    break
                text = text.rstrip().rstrip("\\") + " " + self.code[number + more]
            base = (found.group(1) or "").strip(".")
            for part in _pieces(text.strip().strip("()"), ","):
                words = part.split()
                local = words[2] if len(words) == 3 and words[1] == "as" else None
                if not words:
                    continue
                if found.group(1) is None:                # import a.b / import a.b as c
                    names[local or words[0].split(".")[0]] = words[0] if local else words[0].split(".")[0]
                elif words[0] == "*":
                    stars.append(base)
                else:                                     # from a import b / from a import b as c
                    names[local or words[0]] = "%s.%s" % (base, words[0]) if base else words[0]
        self._names = (names, stars)
        return self._names

    def _means(self, dotted: str, name: str, module: List[str], store: bool, own_store: bool) -> bool:
        """Does ``dotted``, written in this file, name the function ``name`` of the file at ``module``?
        ``store``: that file's top-level names are names of Ren'Py's store; ``own_store``: this file's."""
        names, stars = self.imports()
        parts = dotted.split(".")
        if parts[0] in names:
            target = ".".join([names[parts[0]]] + parts[1:])
        elif len(parts) > 1:
            target = dotted if parts[0] == "store" or dotted.startswith("renpy.store.") or (
                own_store and parts[0] == "renpy") else ""
        elif name in self.functions:
            return False                                  # (its own function of that name)
        else:
            inner = [base.lower().split(".") for base in stars if base]
            return (store and own_store) or any(module[-len(each):] == each for each in inner)
        wanted = target.lower().split(".")
        if not target or wanted[-1] != name.lower():
            return False
        inner = wanted[:-1]
        inner = inner[1:] if inner[:2] == ["renpy", "store"] else inner
        if inner == ["store"]:
            return store
        return bool(inner) and module[-len(inner):] == inner

    def calls_of(self, name: str, module: List[str], store: bool, own_store: bool) -> List[Tuple[int, str]]:
        """The calls in this file of that function: (line index, what stands between the brackets)."""
        names = self.imports()[0]
        words = {name} | {local for local, target in names.items() if target.rsplit(".", 1)[-1] == name}
        call = re.compile(r"(?<![\w.])((?:[A-Za-z_]\w*\.)*(?:%s))[ \t]*\(" % "|".join(sorted(map(re.escape, words))))
        out: List[Tuple[int, str]] = []
        for number, line in enumerate(self.code):
            for found in call.finditer(line):
                if line[:found.start()].rstrip().endswith("def") or not self._means(
                        found.group(1), name, module, store, own_store):
                    continue
                arguments = self._arguments(number, found.end() - 1)
                if arguments is None:
                    raise _Spent
                out.append((number, arguments))
        return out

    def _arguments(self, number: int, opening: int) -> Optional[str]:
        text = self.code[number]
        for more in range(1, 40):
            found = _inside(text, opening)
            if found is not None:
                return found[0]
            if number + more >= len(self.code):
                break
            text += " " + self.code[number + more]
        return None

    def handed(self, arguments: str, position: int, parameter: str, line: int) -> int:
        """What this call hands in for the parameter: CLEAN, OPEN, NEAR or DIRTY. An argument that
        cannot be followed - an open value, or a parameter nothing in this file calls - is NEAR when
        a decoding call stands beside the call (:meth:`_decoding_beside`), else OPEN or CLEAN."""
        self.steps = 0
        self.edges = []
        chosen = self._argument(arguments, position, parameter)
        if chosen is _MANY:                       # (a list of arguments: any of them can be the one)
            parts = [part.strip().lstrip("*") for part in _pieces(arguments, ",") if part.strip()]
            value = max(self._value(part, line, 0) for part in parts)
        else:
            value = CLEAN if chosen is None else self._value(chosen, line, 0)
        unfollowed = value == OPEN or (value == CLEAN and not all(edge[3] for edge in self.edges))
        return NEAR if unfollowed and self._decoding_beside(line) else value

    def _decoding_beside(self, line: int) -> bool:
        """A decoding call in the function of ``line`` (the functions around it and inside it
        included) or in the module-level code of this file."""
        if self._decoding is None:
            self._decoding = [number for number, text in enumerate(self.code) if _decoding_call(text)]
        scope = self.owner[line]
        for number in self._decoding:
            owner = self.owner[number]
            if owner is None or (scope is not None and (_within(owner, scope) or _within(scope, owner))):
                return True
        return False


_MANY = object()                          # (a call that hands on a list of arguments: not followed)


def split(findings: List[Finding], text: str) -> List[Finding]:
    """``PY-OBF-001`` findings of the script ``text`` whose ``marshal.loads`` trace is complete and
    reaches no decoding step become ``PY-OBF-003`` (HIGH); every other finding stays as it is. One that
    ended at the file's edge keeps where (:data:`EDGES`), for :func:`join`."""
    reading: Optional[Reading] = None
    for f in findings:
        if f.rule_id != SPLIT_FROM or f.suppressed or not f.line or len(text) > MAX_TEXT or "marshal" not in text:
            continue
        if reading is None:
            reading = Reading(text)
        if reading.complete_without_decoding(f.line):
            if reading.edges:
                f.context[EDGES], f.context[WAS] = sorted(set(reading.edges)), (f.title, f.reason)
            f.rule_id, f.title, f.severity, f.reason = RULE, TITLE, Severity.HIGH, REASON
    return findings


class Kept:
    """The scan's Python / Ren'Py scripts, packed: which function a parameter belongs to is known only
    when the file that runs it was read, and its callers may have been read before it. Bounded:
    ``MAX_KEPT`` bytes and ``MAX_SCRIPTS`` scripts - past them ``cut`` says that some were not kept."""

    def __init__(self) -> None:
        self.files: Dict[str, Tuple[bytes, bool]] = {}
        self.size = 0
        self.cut = False

    def add(self, file: str, text: str, store: bool) -> None:
        packed = zlib.compress(text.encode("utf-8", "surrogatepass"), 1)
        if len(self.files) >= MAX_SCRIPTS or self.size + len(packed) > MAX_KEPT:
            self.cut = True
            return
        self.files[file] = (packed, store)
        self.size += len(packed)


def _callers(file: str, edges: Iterable[Tuple[str, int, str, bool]], store: bool,
             scripts: Dict[str, Tuple[bytes, bool]]):
    """Who calls these functions of ``file`` from the other ``scripts``: ``(worst value, its file, its
    line, calls)``, or None when a limit stopped the search."""
    module = _module_path(file)
    worst, where, count = CLEAN, ("", 0), 0
    for other in sorted(scripts):
        if _script(other) == _script(file):
            continue
        text = zlib.decompress(scripts[other][0]).decode("utf-8", "surrogatepass")
        wanted = [edge for edge in edges if edge[0] in text]
        if not wanted:
            continue
        if len(text) > MAX_TEXT:
            return None
        reading = Reading(text)
        for name, position, parameter, _called in wanted:
            try:
                for number, arguments in reading.calls_of(name, module, store, scripts[other][1]):
                    count += 1
                    if count > MAX_CALLS:
                        return None
                    value = reading.handed(arguments, position, parameter, number)
                    if not where[0] or value > worst:
                        worst, where = value, (other, number + 1)
            except _Spent:
                return None
    return worst, where[0], where[1], count


def join(findings: List[Finding], kept: "Kept", files: Iterable[str]) -> None:
    """The ``PY-OBF-003`` findings of one game whose trace went through a parameter, against the callers
    in the game's other scripts (``files``, of ``kept``): see the module's text."""
    scripts = {file: kept.files[file] for file in files if file in kept.files}
    for f in findings:
        edges, was = f.context.pop(EDGES, None), f.context.pop(WAS, None)
        if not edges or f.suppressed or f.rule_id != RULE:
            continue
        own = scripts.get(f.file)
        found = None if kept.cut else _callers(f.file, edges, bool(own and own[1]), scripts)
        if found is None:
            f.rule_id, f.severity, (f.title, f.reason) = SPLIT_FROM, Severity.CRITICAL, was
            f.evidence += "; its callers in other files could not all be read (a limit): not complete"
            continue
        worst, other, line, count = found
        if worst == DIRTY:
            f.rule_id, f.severity, (f.title, f.reason) = SPLIT_FROM, Severity.CRITICAL, was
            f.evidence += "; %s line %d hands it decoded, unpacked, decrypted or downloaded data  " \
                          "[across two files]" % (other, line)
        elif worst == NEAR:
            f.rule_id, f.severity, (f.title, f.reason) = SPLIT_FROM, Severity.CRITICAL, was
            f.evidence += "; %s line %d hands it a value that cannot be followed, beside code that decodes, " \
                          "unpacks, decrypts or downloads  [across two files]" % (other, line)
        elif count:
            f.evidence += "; called from other files (%d call(s), first %s line %d): none hands it decoded, " \
                          "unpacked, decrypted or downloaded data" % (count, other, line)
        elif all(edge[3] for edge in edges):
            f.evidence += "; no caller in the other scanned files"
        else:
            f.evidence += "; no caller found in the scanned files"
