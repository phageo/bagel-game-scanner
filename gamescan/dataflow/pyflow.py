"""Python payload resolution: an abstract interpreter over the syntax tree.

The source is parsed with ``ast`` (which never runs it) and then *modelled*:
assignments are followed, string building is carried out on the scanner's own
values, user functions are stepped through with the arguments of their call
sites, and every call that executes code, starts a program, opens a network
address or deletes a file is recorded together with the value that really
reaches it. Whatever cannot be known statically (input, environment, files)
becomes a ‹named hole› in the result instead of stopping the analysis.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/pyflow.py")

import ast
import ntpath
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple

from . import values as V
from .values import Budget, Clock, Ref, Resolved, Sym, cap, hole, is_plain, show

MAX_SOURCE = 2 * 1024 * 1024
_LOOP = 5000                       # iterations of one loop that are modelled
_SEQ = 20000                       # longest sequence that is iterated

# cheap test: is there anything in this text the resolver could say something about?
_WORTH = re.compile(
    _IND[0])
_TOO_DEEP = re.compile(r"[(\[{]{80,}|(?:[-+~]\s*){80,}|(?:\bnot\s+){80,}")

_PY2 = (
    (re.compile(r"^(\s*)print\s*>>.*$"), r"\1pass"),
    (re.compile(r"^(\s*)print\s+(?![=(.\[,])(.*?),?\s*$"), r"\1print(\2)"),
    (re.compile(r"^(\s*)exec\s+(?![=(.])(.+?)(?:\s+in\s+.+)?\s*$"), _IND[1]),
    (re.compile(r"^(\s*except\s+[\w.]+(?:\s*\([^)]*\))?)\s*,\s*(\w+)\s*:"), r"\1 as \2:"),
    (re.compile(r"^(\s*raise\s+[\w.]+)\s*,.*$"), r"\1"),
)
_RENPY_BLOCK = re.compile(r"^(\s*)(?:init\s+(?:-?\d+\s+)?)?python\b[^:#\"']*:\s*(?:#.*)?$")
_RENPY_LINE = re.compile(r"^\s*\$\s*(.+)$")
_RENPY_DEFINE = re.compile(r"^\s*(?:define|default)\s+(?:-?\d+\s+)?([A-Za-z_][\w.]*\s*=(?!=).+)$")

_BUILTINS = frozenset("""exec eval compile open getattr __import__ chr unichr ord str unicode int
float bool len bytes bytearray hex bin oct repr range xrange reversed list tuple set sorted map zip
enumerate sum min max abs print input raw_input dict globals locals vars isinstance type
__builtins__ execfile""".split())
_MODULES = frozenset(_IND[2].split())

_CONTROL = (TypeError, ValueError, IndexError, KeyError, AttributeError, OverflowError,
            ZeroDivisionError, UnicodeError, StopIteration)


# -- source preparation ----------------------------------------------------------
def renpy_python(text: str) -> str:
    """The Python inside a Ren'Py script, every statement kept on its own line."""
    lines = text.split("\n")
    out = [""] * len(lines)
    i = 0
    while i < len(lines):
        line = lines[i]
        block = _RENPY_BLOCK.match(line)
        if block:
            outer, indent, j = len(block.group(1).expandtabs(4)), None, i + 1
            while j < len(lines):
                body = lines[j]
                if body.strip():
                    width = len(body.expandtabs(4)) - len(body.expandtabs(4).lstrip())
                    if width <= outer:
                        break
                    if indent is None:
                        indent = width
                    out[j] = body.expandtabs(4)[indent:] if width >= indent else body.lstrip()
                j += 1
            i = j
            continue
        single = _RENPY_LINE.match(line) or _RENPY_DEFINE.match(line)
        if single:
            out[i] = single.group(1)
        i += 1
    return "\n".join(out)


def _nesting(text: str) -> int:
    depth = deepest = 0
    for m in re.finditer(r"[(\[{]|[)\]}]", text):
        depth = depth + 1 if m.group(0) in "([{" else max(0, depth - 1)
        deepest = max(deepest, depth)
    return deepest


def _ast(text: str) -> ast.Module:
    with warnings.catch_warnings():          # the scanned file's own syntax warnings are not ours
        warnings.simplefilter("ignore")
        return ast.parse(text)


def _try_parse(text: str) -> Optional[ast.Module]:
    try:
        return _ast(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def unread(text: str) -> str:
    """Why :func:`parse` does not look at this text at all - its size, its
    nesting - or "" (it does look; a text that simply is not Python gives ""
    too). The caller says so (SCRIPT-LIMIT-001): until 2026-10-12 a Python
    file over 2 MB was skipped without a word."""
    if len(text) > MAX_SOURCE:
        return "larger than %d MB" % (MAX_SOURCE >> 20)
    if "\0" not in text and (_TOO_DEEP.search(text) or _nesting(text) > 150):
        return "nested too deeply"
    return ""


def parse(text: str) -> Optional[ast.Module]:
    """Syntax tree of Python 3 - or lightly repaired Python 2 - source, or None.
    Parsing never executes anything."""
    if len(text) > MAX_SOURCE or "\0" in text or _TOO_DEEP.search(text) or _nesting(text) > 150:
        return None
    tree = _try_parse(text)
    if tree is not None:
        return tree
    lines = text.split("\n")
    for i, line in enumerate(lines):                      # the usual Python 2 leftovers
        for rx, repl in _PY2:
            fixed = rx.sub(repl, line)
            if fixed != line:
                lines[i] = fixed
                break
    patched = set()
    for _ in range(25):                                   # blank out what still fails
        try:
            return _ast("\n".join(lines))
        except SyntaxError as exc:
            n = (exc.lineno or 0) - 1
            if not 0 <= n < len(lines) or n in patched:
                break
            patched.add(n)
            lines[n] = lines[n][:len(lines[n]) - len(lines[n].lstrip())] + "pass"
        except (ValueError, RecursionError, MemoryError):
            return None
    # last resort: keep every top-level statement that parses on its own
    starts = [i for i, line in enumerate(lines)
              if line[:1] not in ("", " ", "\t", "#", ")", "]", "}")
              and not re.match(r"(?:else|elif|except|finally)\b", line)]
    body: List[ast.stmt] = []
    for a, b in list(zip(starts, starts[1:] + [len(lines)]))[:400]:
        part = _try_parse("\n" * a + "\n".join(lines[a:b]))
        if part is not None:
            body.extend(part.body)
    if not body:
        return None
    module = ast.Module(body=body, type_ignores=[])
    return module


# -- interpreter objects ---------------------------------------------------------
class _Return(Exception):
    def __init__(self, value: Any) -> None:
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class Func:
    __slots__ = ("node", "name", "method", "called", "_shape")

    def __init__(self, node, name: str, method: bool) -> None:
        self.node, self.name, self.method, self.called = node, name, method, False
        self._shape: Any = False                 # not looked at yet

    def shape(self) -> Optional[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]]:
        """None when the function is not *pure* as written; else what its result
        can depend on besides its arguments: ``(names it reads, dotted attributes
        it reads, attribute names it uses)``.

        Pure (phageo, 2026-10-12): nothing in its body writes outside its own
        variables - no ``global`` / ``nonlocal``, no assignment to or deletion of
        an attribute or an item, no ``del``, no function, class or lambda defined
        inside it (defining one adds to what the whole reading knows). Only the
        result of such a function is kept; every other one is read again at every
        call, as before."""
        if self._shape is False:
            self._shape = self._look()
        return self._shape

    def _look(self):
        node = self.node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None                          # a lambda: cheap, and it closes over its scope
        names, dotted, attributes = set(), set(), set()
        for inner in ast.walk(node):
            if inner is node:
                continue
            if isinstance(inner, (ast.Global, ast.Nonlocal, ast.Delete, ast.FunctionDef,
                                  ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                return None
            if isinstance(inner, (ast.Attribute, ast.Subscript)) and not isinstance(inner.ctx, ast.Load):
                return None
            if isinstance(inner, ast.Name):
                names.add(inner.id)
            elif isinstance(inner, ast.Attribute):
                attributes.add(inner.attr)
                key = _dotted(inner)
                if key:
                    dotted.add(key)
        if len(names) + len(dotted) + len(attributes) > 400:
            return None                          # (comparing that much costs more than it saves)
        return tuple(sorted(names)), tuple(sorted(dotted)), tuple(sorted(attributes))


class Klass:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class Bound:
    """A method of a modelled value (``"".join``), not yet called."""
    __slots__ = ("obj", "name")

    def __init__(self, obj: Any, name: str) -> None:
        self.obj, self.name = obj, name


class Scope:
    __slots__ = ("vars", "parent", "declared", "returned", "klass")

    def __init__(self, vars: Dict[str, Any], parent: "Optional[Scope]" = None,
                 klass: str = "") -> None:
        self.vars, self.parent, self.klass = vars, parent, klass
        self.declared: set = set()
        self.returned: List[Any] = []


def _dotted(node: ast.AST) -> Optional[str]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and len(parts) <= 4:
        return ".".join([node.id] + parts[::-1])
    return None


def _literal(node: Optional[ast.AST]) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(isinstance(e, ast.Constant) for e in node.elts)
    return False


def _canon(name: str) -> str:
    name = name.replace("()", "")
    for prefix in ("builtins.", "__builtin__.", "__builtins__.", "six.moves."):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


# sinks: canonical name -> (kind, argument index, keyword, deletes)
_SINKS: Dict[str, Tuple[str, int, str, bool]] = {}


def _sink(kind: str, names: str, index: int = 0, keyword: str = "", delete: bool = False) -> None:
    for name in names.split():
        _SINKS[name] = (kind, index, keyword, delete)


_sink("exec", "exec eval compile renpy.python.py_exec renpy.python.py_eval", keyword="source")
_sink("command", _IND[3], keyword="args")
_sink("url", _IND[4], keyword="url")
_sink("url", "requests.request requests.Session.request", index=1, keyword="url")
_sink("path", "os.remove os.unlink os.rmdir os.removedirs shutil.rmtree", delete=True)
_sink("path", "shutil.copy shutil.copy2 shutil.copyfile shutil.move os.rename os.replace",
      index=1, keyword="dst")
_OPENERS = frozenset({"open", "io.open", "codecs.open"})
_HOST_SINKS = {"HTTPConnection": "http://", "HTTPSConnection": "https://", "FTP": "ftp://"}
# modules and builtins where a call picked by an assembled name is worth reporting
_SENSITIVE = re.compile(
    _IND[5])
_CONNECT = frozenset({"connect", "connect_ex"})

_STR_SAFE = frozenset("""strip lstrip rstrip lower upper split rsplit splitlines startswith endswith
find rfind index count title capitalize swapcase partition rpartition casefold isdigit isalpha
isalnum isupper islower isspace translate removeprefix removesuffix hex""".split())
_PAD = frozenset({"zfill", "ljust", "rjust", "center"})
_SYM_KEEP = frozenset("""strip lstrip rstrip lower upper encode decode title capitalize casefold
removeprefix removesuffix read""".split())


class Interp:
    """One layer of code being modelled (the file, or a decoded payload)."""

    def __init__(self, clock: Clock, layer: int = 0, line: Optional[int] = None,
                 hidden: Optional[set] = None) -> None:
        self.clock, self.layer, self.fixed_line = clock, layer, line
        self.globals: Dict[str, Any] = {}
        self.attrs: Dict[str, Any] = {}
        self.methods: Dict[str, Func] = {}
        self.inits: Dict[str, Func] = {}
        self.funcs: List[Func] = []
        self.hits: List[Resolved] = []
        self.payloads: List[Tuple[int, str]] = []
        self.hidden: set = set() if hidden is None else hidden
        self.assigned: Dict[str, int] = {}
        self.reads: List[List[str]] = []
        self.stack: List[Func] = []
        self.kept: Dict[Any, Tuple[Any, int]] = {}      # what pure functions gave (invoke)
        self.seen: set = set()
        self.line = 1
        self.swallowed = 0

    # -- driver ----------------------------------------------------------------
    def run(self, tree: ast.Module) -> None:
        scope = Scope(self.globals)
        try:
            self._maybe(tree.body, scope)
            for _ in range(3):                       # functions nobody called: unknown arguments
                pending = [f for f in self.funcs if not f.called]
                if not pending:
                    break
                for func in pending:
                    self.invoke(func, None, {})
        except (Budget, RecursionError) as exc:
            self.clock.ended(exc)                    # (the clock keeps which limit it was)

    # -- hidden-value bookkeeping ------------------------------------------------
    def _hide(self, value: Any) -> Any:
        key = value.text if isinstance(value, Sym) else value
        if isinstance(key, (str, bytes)) and 0 < len(key) <= 65536 and len(self.hidden) < 4000:
            self.hidden.add(key)
        return value

    def _is_hidden(self, value: Any) -> bool:
        if isinstance(value, Sym):
            return value.text in self.hidden
        if isinstance(value, (str, bytes)):
            return value in self.hidden
        if isinstance(value, (list, tuple)):
            return any(self._is_hidden(v) for v in value[:64])
        return False

    def _mark(self, result: Any, *sources: Any) -> Any:
        if any(self._is_hidden(s) for s in sources):
            self._hide(result)
        return result

    # -- statements ----------------------------------------------------------------
    def block(self, stmts: List[ast.stmt], scope: Scope) -> None:
        for node in stmts:
            self.clock.tick()
            self.line = getattr(node, "lineno", self.line)
            handler = getattr(self, "s_" + type(node).__name__, None)
            try:
                if handler is not None:
                    handler(node, scope)
                else:
                    self._generic(node, scope)
            except _CONTROL:
                continue                         # a statement the model cannot follow

    def _maybe(self, stmts: List[ast.stmt], scope: Scope) -> None:
        """Run a block that may or may not execute: its ``return`` / ``break``
        must not stop the analysis of what follows."""
        try:
            self.block(stmts, scope)
        except _Return as ret:
            self.swallowed += 1
            scope.returned.append(ret.value)
        except (_Break, _Continue):
            self.swallowed += 1

    def _generic(self, node: ast.AST, scope: Scope) -> None:
        for _name, field in ast.iter_fields(node):
            items = field if isinstance(field, list) else [field]
            stmts = [i for i in items if isinstance(i, ast.stmt)]
            if stmts:
                self._maybe(stmts, scope)
            for item in items:
                if isinstance(item, ast.expr):
                    self.eval(item, scope)
                elif isinstance(item, ast.AST) and not isinstance(item, ast.stmt):
                    self._generic(item, scope)

    def s_Expr(self, node, scope):
        self.eval(node.value, scope)

    def s_Pass(self, node, scope):
        pass

    def s_Global(self, node, scope):
        scope.declared.update(node.names)

    s_Nonlocal = s_Global

    def s_Assign(self, node, scope):
        value = self.eval(node.value, scope)
        for target in node.targets:
            self.assign(target, value, scope)

    def s_AnnAssign(self, node, scope):
        if node.value is not None:
            self.assign(node.target, self.eval(node.value, scope), scope)

    def s_AugAssign(self, node, scope):
        current = self.eval(node.target, scope) if isinstance(
            node.target, (ast.Name, ast.Attribute, ast.Subscript)) else hole("?")
        self.assign(node.target, self.binop(node.op, current, self.eval(node.value, scope)), scope)

    def s_Return(self, node, scope):
        raise _Return(self.eval(node.value, scope) if node.value is not None else None)

    def s_Break(self, node, scope):
        raise _Break()

    def s_Continue(self, node, scope):
        raise _Continue()

    def s_If(self, node, scope):
        known = self.truth(self.eval(node.test, scope))
        if known is True:
            self.block(node.body, scope)
        elif known is False:
            self.block(node.orelse, scope)
        else:                                   # unknown: both, the "if" side last so it wins
            self._maybe(node.orelse, scope)
            self._maybe(node.body, scope)

    def s_For(self, node, scope):
        items = self._iterable(self.eval(node.iter, scope))
        if items is None or len(items) > _LOOP:
            self._bind_unknown(node.target, scope)
            self._maybe(node.body, scope)
        else:
            for item in items:
                self.clock.tick()
                self.assign(node.target, item, scope)
                try:
                    self.block(node.body, scope)
                except _Break:
                    break
                except _Continue:
                    continue
        self._maybe(node.orelse, scope)

    s_AsyncFor = s_For

    def s_While(self, node, scope):
        last = None
        for turn in range(_LOOP):
            known = self.truth(self.eval(node.test, scope))
            if known is None:
                self._maybe(node.body, scope)
                break
            if not known:
                break
            before = self.swallowed
            try:
                self.block(node.body, scope)
            except _Break:
                break
            except _Continue:
                pass
            else:
                if self.swallowed != before:    # a conditional exit may have been taken
                    break
            # A full turn that left everything this reading knows as the turn before left it
            # will be followed by 4,998 turns that do the same: stop (phageo, 2026-10-12). What
            # is compared: the globals, the attributes of modules and objects, the variables
            # of this function and of those around it, and what was found so far.
            now = self._state(scope)
            if now is not None and now == last:
                break
            last = now
        self._maybe(node.orelse, scope)

    _STATE_PARTS = 6000                 # values looked at for one comparison; more: not compared

    def _state(self, scope: Scope) -> Any:
        """Everything the next turn of a loop can depend on, as one value that can be
        compared - or None when it is too much to compare (then the loop goes on)."""
        left = [self._STATE_PARTS]

        def fixed(value: Any, depth: int = 0) -> Any:
            left[0] -= 1
            if left[0] < 0 or depth > 8:
                raise OverflowError
            if value is None or isinstance(value, (bool, int, float, str, bytes)):
                return (type(value).__name__, value)
            if isinstance(value, Sym):
                return ("sym", value.text)
            if isinstance(value, Ref):
                return ("ref", value.name, value.dynamic)
            if isinstance(value, (list, tuple)):
                return (type(value).__name__,) + tuple(fixed(v, depth + 1) for v in value)
            if isinstance(value, dict):
                return ("dict",) + tuple(sorted(((type(k).__name__, repr(k)), fixed(v, depth + 1))
                                                for k, v in value.items()))
            if isinstance(value, Bound):
                return ("bound", fixed(value.obj, depth + 1), value.name)
            if isinstance(value, Klass):
                return ("class", value.name)
            return ("object", id(value))                    # a function of the file, a scope ...

        try:
            scopes = []
            where: Optional[Scope] = scope
            while where is not None:
                if where.vars is not self.globals:
                    scopes.append((fixed(where.vars), tuple(sorted(where.declared)), len(where.returned)))
                where = where.parent
            return (fixed(self.globals), fixed(self.attrs), tuple(scopes), len(self.hidden),
                    len(self.hits), len(self.payloads), len(self.funcs), len(self.methods), len(self.inits))
        except (OverflowError, RecursionError, TypeError):
            return None

    def s_Try(self, node, scope):
        leaving = None
        try:
            self.block(node.body, scope)
        except (_Return, _Break, _Continue) as exc:
            leaving = exc                        # the handlers are still worth reading
        for handler in node.handlers:
            if handler.name:
                scope.vars[handler.name] = hole(handler.name)
            self._maybe(handler.body, scope)
        if leaving is None:
            self._maybe(node.orelse, scope)
        self._maybe(node.finalbody, scope)
        if leaving is not None:
            raise leaving

    s_TryStar = s_Try

    def s_With(self, node, scope):
        for item in node.items:
            value = self.eval(item.context_expr, scope)
            if item.optional_vars is not None:
                self.assign(item.optional_vars, value, scope)
        self.block(node.body, scope)

    s_AsyncWith = s_With

    def s_Import(self, node, scope):
        for alias in node.names:
            if alias.asname:
                scope.vars[alias.asname] = Ref(alias.name)
            else:
                top = alias.name.split(".")[0]
                scope.vars[top] = Ref(top)

    def s_ImportFrom(self, node, scope):
        for alias in node.names:
            if alias.name != "*":
                scope.vars[alias.asname or alias.name] = Ref(
                    (node.module + "." if node.module else "") + alias.name)

    def s_FunctionDef(self, node, scope):
        for decorator in node.decorator_list:
            self.eval(decorator, scope)
        func = Func(node, node.name, bool(scope.klass))
        self.funcs.append(func)
        if scope.klass:
            self.methods[node.name] = func
            if node.name == "__init__":
                self.inits[scope.klass] = func
        else:
            scope.vars[node.name] = func

    s_AsyncFunctionDef = s_FunctionDef

    def s_ClassDef(self, node, scope):
        inner = Scope({}, scope, klass=node.name)
        self._maybe(node.body, inner)
        for name, value in inner.vars.items():
            self.attrs["self." + name] = self.attrs[node.name + "." + name] = value
        scope.vars[node.name] = Klass(node.name)

    # -- assignment ----------------------------------------------------------------
    def _bind_unknown(self, target: ast.AST, scope: Scope) -> None:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                self._set(node.id, hole(node.id), scope, node)

    def _set(self, name: str, value: Any, scope: Scope, node: ast.AST) -> None:
        if name in scope.declared:
            self.globals[name] = value
        else:
            scope.vars[name] = value
        self.assigned[name] = getattr(node, "lineno", self.line)

    def assign(self, target: ast.AST, value: Any, scope: Scope) -> None:
        if isinstance(target, ast.Name):
            self._set(target.id, value, scope, target)
        elif isinstance(target, (ast.Tuple, ast.List)):
            plain = not any(isinstance(e, ast.Starred) for e in target.elts)
            if plain and isinstance(value, (list, tuple)) and len(value) == len(target.elts):
                for element, item in zip(target.elts, value):
                    self.assign(element, item, scope)
            else:
                self._bind_unknown(target, scope)
        elif isinstance(target, ast.Attribute):
            key = _dotted(target)
            if key:
                head, _, tail = key.partition(".")
                if head in ("self", "cls"):
                    key = "self." + tail
                self.attrs[key] = value
                self.assigned[key] = getattr(target, "lineno", self.line)
        elif isinstance(target, ast.Subscript):
            box, index = self.eval(target.value, scope), self.eval(self._index(target), scope)
            try:
                if isinstance(box, list) and isinstance(index, int):
                    box[index] = value
                elif isinstance(box, dict) and is_plain(index) and not isinstance(
                        index, (list, dict)) and len(box) < V.MAX_ITEMS:
                    box[index] = value
            except _CONTROL:
                pass
        elif isinstance(target, ast.Starred):
            self._bind_unknown(target, scope)

    @staticmethod
    def _index(node: ast.Subscript) -> ast.AST:
        inner = node.slice
        return getattr(inner, "value", inner) if type(inner).__name__ == "Index" else inner

    # -- expressions -----------------------------------------------------------------
    def eval(self, node: Optional[ast.AST], scope: Scope) -> Any:
        if node is None:
            return None
        self.clock.tick()
        handler = getattr(self, "e_" + type(node).__name__, None)
        if handler is None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.eval(child, scope)
            return hole("expr")
        try:
            return cap(handler(node, scope))
        except _CONTROL:
            return hole("expr")

    @staticmethod
    def truth(value: Any) -> Optional[bool]:
        if isinstance(value, (Sym, Ref, Func, Bound, Klass)):
            return None
        try:
            return bool(value)
        except Exception:
            return None

    def lookup(self, name: str, scope: Optional[Scope]) -> Any:
        where = scope
        while where is not None:
            if name in where.vars and (where is scope or not where.klass):
                break
            where = where.parent
        if where is not None:
            value = where.vars[name]
        elif name in self.globals:
            value = self.globals[name]
        elif name in _BUILTINS or name in _MODULES:
            return Ref(name)
        else:
            return hole(name)
        if self.reads:
            self.reads[-1].append(name)
        return value

    def e_Constant(self, node, scope):
        value = node.value
        return value if is_plain(value) else hole("const")

    def e_Name(self, node, scope):
        return self.lookup(node.id, scope)

    def e_JoinedStr(self, node, scope):
        parts, partial, sources = [], False, []
        for piece in node.values:
            if isinstance(piece, ast.FormattedValue):
                value = self.eval(piece.value, scope)
                partial = partial or isinstance(value, (Sym, Ref, Func, Bound, Klass))
                sources.append(value)
                parts.append(show(value))
            else:
                parts.append(show(self.eval(piece, scope)))
        text = "".join(parts)
        return self._mark(Sym(text) if partial else text, *sources)

    def e_FormattedValue(self, node, scope):
        return self.eval(node.value, scope)

    def e_List(self, node, scope):
        out: List[Any] = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                items = self._iterable(self.eval(element.value, scope))
                out.extend(items if items is not None else [hole("*")])
            else:
                out.append(self.eval(element, scope))
        return out

    def e_Tuple(self, node, scope):
        return tuple(self.e_List(node, scope))

    e_Set = e_List

    def e_Dict(self, node, scope):
        out = {}
        for key, value in zip(node.keys, node.values):
            v = self.eval(value, scope)
            k = self.eval(key, scope) if key is not None else None
            if isinstance(k, (str, bytes, int, float, bool)):
                out[k] = v
        return out

    def e_Starred(self, node, scope):
        return self.eval(node.value, scope)

    def e_NamedExpr(self, node, scope):
        value = self.eval(node.value, scope)
        self.assign(node.target, value, scope)
        return value

    def e_Lambda(self, node, scope):
        func = Func(node, "lambda", False)
        func.called = True                       # only analysed where it is applied
        return func

    def e_IfExp(self, node, scope):
        known = self.truth(self.eval(node.test, scope))
        if known is True:
            return self.eval(node.body, scope)
        if known is False:
            return self.eval(node.orelse, scope)
        self.eval(node.orelse, scope)
        return self.eval(node.body, scope)

    def e_Await(self, node, scope):
        return self.eval(node.value, scope)

    def e_UnaryOp(self, node, scope):
        value = self.eval(node.operand, scope)
        if isinstance(node.op, ast.Not):
            known = self.truth(value)
            return hole("cond") if known is None else not known
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return value
            if isinstance(node.op, ast.Invert) and isinstance(value, int):
                return ~value
        return hole("expr")

    def e_BoolOp(self, node, scope):
        want = isinstance(node.op, ast.Or)
        first_unknown, value = None, None
        for operand in node.values:
            value = self.eval(operand, scope)
            known = self.truth(value)
            if known is None:
                first_unknown = value if first_unknown is None else first_unknown
            elif known is want and first_unknown is None:
                return value
        return first_unknown if first_unknown is not None else value

    def e_Compare(self, node, scope):
        left = self.eval(node.left, scope)
        result: Any = True
        for op, right_node in zip(node.ops, node.comparators):
            right = self.eval(right_node, scope)
            if not (is_plain(left) and is_plain(right)):
                result = hole("cond")
            elif result is True:
                kind = type(op)
                if kind is ast.Eq:
                    result = left == right
                elif kind is ast.NotEq:
                    result = left != right
                elif kind is ast.In:
                    result = left in right
                elif kind is ast.NotIn:
                    result = left not in right
                elif kind is ast.Is:
                    result = left is right or left == right
                elif kind is ast.IsNot:
                    result = not (left is right or left == right)
                elif kind is ast.Lt:
                    result = left < right
                elif kind is ast.LtE:
                    result = left <= right
                elif kind is ast.Gt:
                    result = left > right
                elif kind is ast.GtE:
                    result = left >= right
            left = right
        return result

    def e_BinOp(self, node, scope):
        return self.binop(node.op, self.eval(node.left, scope), self.eval(node.right, scope))

    def binop(self, op: ast.operator, a: Any, b: Any) -> Any:
        kind = type(op)
        number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
        if kind is ast.Add:
            if number(a) and number(b):
                return self._num(a + b)
            if isinstance(a, (list, tuple)) and type(a) is type(b):
                return cap(a + b)
            joined = V.concat(a, b)
            if joined is not None:
                return self._mark(joined, a, b)
        elif kind is ast.Mult:
            seq, count = (a, b) if isinstance(b, int) else (b, a)
            if isinstance(count, int) and isinstance(seq, (str, bytes, list, tuple)):
                if len(seq) * max(count, 0) > V.MAX_TEXT:
                    raise Budget()
                return self._mark(seq * count, seq)
            if number(a) and number(b):
                return self._num(a * b)
        elif kind is ast.Mod:
            if isinstance(a, (str, Sym)):
                extra = b if isinstance(b, tuple) else (b,)
                return self._mark(V.percent(a, b), a, *extra)
            if number(a) and number(b):
                return a % b
        elif number(a) and number(b):
            if kind is ast.Sub:
                return self._num(a - b)
            if kind is ast.Div:
                return a / b
            if kind is ast.FloorDiv:
                return a // b
            if isinstance(a, int) and isinstance(b, int):
                if kind is ast.BitXor:
                    return a ^ b
                if kind is ast.BitAnd:
                    return a & b
                if kind is ast.BitOr:
                    return a | b
                if kind is ast.LShift and 0 <= b <= 64:
                    return self._num(a << b)
                if kind is ast.RShift and 0 <= b <= 4096:
                    return a >> b
                if kind is ast.Pow and 0 <= b <= 64 and abs(a) <= 1 << 16:
                    return self._num(a ** b)
        return hole("expr")

    @staticmethod
    def _num(value: Any) -> Any:
        if isinstance(value, int) and abs(value) >= 1 << 256:
            return hole("number")
        return value

    def e_Subscript(self, node, scope):
        base = self.eval(node.value, scope)
        inner = self._index(node)
        if isinstance(inner, ast.Slice):
            lo, hi, step = (self.eval(part, scope) for part in (inner.lower, inner.upper, inner.step))
            if isinstance(base, (str, bytes, list, tuple)) and all(
                    part is None or isinstance(part, int) for part in (lo, hi, step)) and step != 0:
                result = base[lo:hi:step]
                if step is not None and step < 0 and isinstance(result, (str, bytes)):
                    return self._hide(result)             # reversed text
                return self._mark(result, base)
            return base if isinstance(base, Sym) else hole("slice")
        index = self.eval(inner, scope)
        if isinstance(base, Ref):
            name = _canon(base.name)
            if isinstance(index, str):
                if name == "os.environ":
                    return Sym("%" + index + "%")
                if name == "sys.modules":
                    return Ref(index, base.dynamic or not _literal(inner))
                if name in ("globals", "locals", "vars"):
                    found = self.lookup(index, scope)
                    if isinstance(found, Ref) and not _literal(inner):
                        found = Ref(found.name, True)
                    return found
                if name.endswith(".__dict__") or name == "__builtins__":
                    owner = name[:-len(".__dict__")] if name.endswith(".__dict__") else ""
                    owner = "" if owner in ("__builtins__", "builtins", "__builtin__") else owner
                    return Ref((owner + "." if owner else "") + index, not _literal(inner))
            return hole(base.name + "[]")
        if isinstance(base, (str, bytes, list, tuple)) and isinstance(index, int):
            return self._mark(base[index], base)
        if isinstance(base, dict) and isinstance(index, (str, bytes, int, float, bool)):
            return base[index]
        return hole("item")

    def e_Attribute(self, node, scope):
        key = _dotted(node)
        if key:
            found = self._attr(key)
            if found is not None:
                return found
        base = self.eval(node.value, scope)
        if isinstance(base, Ref):
            name = _canon(base.name)
            if name == "os" and node.attr in ("sep", "linesep"):
                return "\\" if node.attr == "sep" else "\r\n"
            return Ref(base.name + "." + node.attr, base.dynamic)
        if isinstance(base, Sym):
            if node.attr in self.methods:
                return self.methods[node.attr]
            return hole(key or "?." + node.attr)
        if isinstance(base, (str, bytes, list, dict)):
            return Bound(base, node.attr)
        return hole(key or "?." + node.attr)

    def _attr(self, key: str) -> Any:
        head, _, tail = key.partition(".")
        for name in ((key, "self." + tail) if head in ("self", "cls") else (key,)):
            if name in self.attrs:
                if self.reads:
                    self.reads[-1].append(name)
                return self.attrs[name]
        return None

    # -- comprehensions ----------------------------------------------------------------
    def _iterable(self, value: Any) -> Optional[List[Any]]:
        if isinstance(value, (list, tuple)):
            return list(value) if len(value) <= _SEQ else None
        if isinstance(value, (str, bytes)) and len(value) <= _SEQ:
            return list(value)
        if isinstance(value, dict) and len(value) <= _SEQ:
            return list(value)
        return None

    def _comprehend(self, node, scope, emit) -> bool:
        local = Scope({}, scope)
        exact = [True]

        def level(i: int) -> None:
            if i == len(node.generators):
                emit(local)
                return
            gen = node.generators[i]
            items = self._iterable(self.eval(gen.iter, local))
            if items is None:
                exact[0] = False
                self._bind_unknown(gen.target, local)
                for cond in gen.ifs:
                    self.eval(cond, local)
                level(i + 1)
                return
            for item in items:
                self.clock.tick()
                self.assign(gen.target, item, local)
                if all(self.truth(self.eval(cond, local)) is not False for cond in gen.ifs):
                    level(i + 1)

        level(0)
        return exact[0]

    def e_ListComp(self, node, scope):
        out: List[Any] = []
        exact = self._comprehend(node, scope, lambda s: out.append(self.eval(node.elt, s)))
        return cap(out) if exact else hole("items")

    e_GeneratorExp = e_SetComp = e_ListComp

    def e_DictComp(self, node, scope):
        out: Dict[Any, Any] = {}

        def emit(s: Scope) -> None:
            key, value = self.eval(node.key, s), self.eval(node.value, s)
            if isinstance(key, (str, bytes, int, float, bool)) and len(out) < V.MAX_ITEMS:
                out[key] = value

        return out if self._comprehend(node, scope, emit) else hole("items")

    # -- calls -------------------------------------------------------------------------
    def e_Call(self, node, scope):
        self.reads.append([])
        try:
            func = self._callee(node.func, scope)
            args: List[Any] = []
            for arg in node.args:
                if isinstance(arg, ast.Starred):
                    items = self._iterable(self.eval(arg.value, scope))
                    args.extend(items if items is not None else [hole("*")])
                else:
                    args.append(self.eval(arg, scope))
            kwargs = {kw.arg: self.eval(kw.value, scope) for kw in node.keywords if kw.arg}
            for kw in node.keywords:
                if not kw.arg:
                    self.eval(kw.value, scope)
            return self.call(func, args, kwargs, node, scope)
        finally:
            reads = self.reads.pop()
            if self.reads:
                self.reads[-1].extend(reads[:32])

    def _callee(self, node: ast.AST, scope: Scope) -> Any:
        if not isinstance(node, ast.Attribute):
            return self.eval(node, scope)
        key = _dotted(node)
        if key:
            found = self._attr(key)
            if found is not None:
                return found
        base = self.eval(node.value, scope)
        if isinstance(base, Ref):
            return Ref(base.name + "." + node.attr, base.dynamic)
        return Bound(base, node.attr)

    def call(self, func: Any, args: List[Any], kwargs: Dict[str, Any],
             node: Optional[ast.Call], scope: Optional[Scope]) -> Any:
        if isinstance(func, Ref):
            return self._call_ref(func, args, kwargs, node, scope)
        if isinstance(func, Func):
            return self.invoke(func, args, kwargs)
        if isinstance(func, Bound):
            return self._method(func.obj, func.name, args, kwargs, node)
        if isinstance(func, Klass):
            init = self.inits.get(func.name)
            if init is not None:
                self.invoke(init, args, kwargs)
            return hole(func.name)
        return hole("call")

    # -- what a pure function gave is kept ---------------------------------------------
    def _fixed(self, value: Any, depth: int = 0) -> Any:
        """``value`` as something that can be compared and that nobody can change
        afterwards (raises TypeError for anything else: a list, a dict, a function)."""
        if value is None or isinstance(value, (bool, int, float)):
            return (type(value).__name__, value)
        if isinstance(value, (str, bytes)):
            if len(value) > 4096:
                raise TypeError
            return (type(value).__name__, value, value in self.hidden)
        if isinstance(value, Sym):
            if len(value.text) > 4096:
                raise TypeError
            return ("sym", value.text, value.text in self.hidden)
        if isinstance(value, Ref):
            return ("ref", value.name, value.dynamic)
        if isinstance(value, tuple) and depth < 3 and len(value) <= 16:
            return ("tuple",) + tuple(self._fixed(v, depth + 1) for v in value)
        raise TypeError

    def _kept_key(self, func: Func, args: Optional[List[Any]], kwargs: Dict[str, Any],
                  depth: int = 0) -> Any:
        """What decides the result of the pure function ``func`` here: its
        arguments, the present value of every name and attribute it reads, and
        how deep in calls it stands. Raises TypeError when it cannot be told -
        the function is not pure, it reads something that can change under it,
        or it calls a function of the file that is not pure itself."""
        shape = func.shape()
        if shape is None or depth > 6:
            raise TypeError
        names, dotted, attributes = shape
        seen = []
        for name in names:
            value = self.globals.get(name, self)             # (self: the name is not set)
            if isinstance(value, Func):                      # a function of the file it may call
                seen.append(("func", id(value), self._kept_key(value, None, {}, depth + 1)[3:])
                            if value is not func else ("func", "itself"))
            elif value is not self:
                seen.append(self._fixed(value))
            else:
                seen.append(None)
        for key in dotted:
            head, _, tail = key.partition(".")
            for known in ((key, "self." + tail) if head in ("self", "cls") else (key,)):
                value = self.attrs.get(known, self)
                if isinstance(value, Func):
                    raise TypeError
                seen.append(None if value is self else self._fixed(value))
        for name in attributes:                              # x.name(...) may be a method of the file
            method = self.methods.get(name)
            if method is not None:
                seen.append(("func", id(method), self._kept_key(method, None, {}, depth + 1)[3:])
                            if method is not func else ("func", "itself"))
        given = None if args is None else tuple(self._fixed(a) for a in args)
        named = tuple(sorted((k, self._fixed(v)) for k, v in kwargs.items()))
        return (id(func), given, named, len(self.stack), tuple(seen))

    def invoke(self, func: Func, args: Optional[List[Any]], kwargs: Dict[str, Any]) -> Any:
        if len(self.stack) >= 12 or self.stack.count(func) >= 2:
            return hole(func.name + "()")
        # A pure function called again with the same arguments, while everything it reads
        # is as it was, gives what it gave before: that is kept, not read again (phageo,
        # 2026-10-12). Any other function is read again at every call, as before.
        try:
            key = self._kept_key(func, args, kwargs)
        except (TypeError, RecursionError):
            key = None
        if key is not None:
            kept = self.kept.get(key)
            if kept is not None and (kept[2] is not None or not self.reads):
                self.clock.tick()
                func.called = True
                self.swallowed += kept[1]
                if self.reads:                               # the names it read, for a later trace
                    self.reads[-1].extend(kept[2])
                return kept[0]
            swallowed = self.swallowed
            mark = len(self.reads[-1]) if self.reads else None
            result = self._invoke(func, args, kwargs)
            try:
                self._fixed(result)                          # (a list could be changed by whoever got it)
            except TypeError:
                return result
            if len(self.kept) < 20_000:
                self.kept[key] = (result, self.swallowed - swallowed,
                                  None if mark is None else tuple(self.reads[-1][mark:mark + 64]))
            return result
        return self._invoke(func, args, kwargs)

    def _invoke(self, func: Func, args: Optional[List[Any]], kwargs: Dict[str, Any]) -> Any:
        func.called = True
        spec = func.node.args
        params = [p.arg for p in list(getattr(spec, "posonlyargs", [])) + list(spec.args)]
        local: Dict[str, Any] = {}
        if func.method and params and params[0] in ("self", "cls"):
            local[params[0]] = hole(params[0])
            params = params[1:]
            defaults_from = len(spec.args) + len(getattr(spec, "posonlyargs", [])) - 1
        else:
            defaults_from = len(params)
        defaults_from -= len(spec.defaults)
        outer = Scope(self.globals)
        for i, name in enumerate(params):
            if args is not None and i < len(args):
                local[name] = args[i]
            elif name in kwargs:
                local[name] = kwargs[name]
            elif i >= defaults_from:
                local[name] = self.eval(spec.defaults[i - defaults_from], outer)
            else:
                local[name] = hole(name)
        for param, default in zip(spec.kwonlyargs, spec.kw_defaults):
            local[param.arg] = kwargs[param.arg] if param.arg in kwargs else (
                self.eval(default, outer) if default is not None else hole(param.arg))
        if spec.vararg:
            local[spec.vararg.arg] = list(args[len(params):]) if args is not None else hole("args")
        if spec.kwarg:
            local[spec.kwarg.arg] = hole(spec.kwarg.arg)
        scope = Scope(local, outer)
        self.stack.append(func)
        saved = self.line
        try:
            if isinstance(func.node, ast.Lambda):
                return self.eval(func.node.body, scope)
            try:
                self.block(func.node.body, scope)
            except _Return as ret:
                return ret.value
            except (_Break, _Continue):
                pass
            return next((v for v in scope.returned if v is not None), None)
        finally:
            self.stack.pop()
            self.line = saved

    # -- methods of modelled values ----------------------------------------------------
    def _method(self, obj: Any, name: str, args: List[Any], kwargs: Dict[str, Any],
                node: Optional[ast.Call]) -> Any:
        if name in _CONNECT and args and isinstance(args[0], (tuple, list)) and len(args[0]) == 2:
            host, port = args[0]
            if isinstance(host, (str, Sym)):
                self.record(node, "url", "socket.connect", Sym("tcp://%s:%s" % (show(host), show(port)))
                            if isinstance(host, Sym) or not isinstance(port, int)
                            else self._mark("tcp://%s:%d" % (host, port), host), False, False)
        if isinstance(obj, (Sym, Ref, Klass)) or obj is None:
            method = self.methods.get(name)
            if method is not None:
                return self.invoke(method, args, kwargs)
            if isinstance(obj, Sym):
                if name == "format":
                    return V.brace_format(obj, args, kwargs)
                if name == "join":
                    return self._join(obj, args)
                if name in _SYM_KEEP:
                    return obj
                return hole(V.known_part(obj.text) and "text" or obj.text[1:-1] + "." + name + "()")
            return hole(name + "()")
        if isinstance(obj, (str, bytes)):
            if name == "join":
                return self._join(obj, args)
            if name == "format" and isinstance(obj, str):
                return self._mark(V.brace_format(obj, args, kwargs), obj, *args)
            if name in ("decode", "encode"):
                codec = args[0] if args else kwargs.get("encoding", "utf-8")
                result, hidden = (V.decode if name == "decode" else V.encode)(obj, codec)
                return self._hide(result) if hidden else self._mark(result, obj)
            if not all(is_plain(a) for a in args) or kwargs:
                return hole(name + "()")
            if name == "replace" and len(args) >= 2:
                if len(obj) * (len(args[1]) + 1) > 4 * V.MAX_TEXT:
                    raise Budget()
                return self._mark(obj.replace(*args[:3]), obj, *args)
            if name in _PAD and args and isinstance(args[0], int) and args[0] <= 4096:
                return self._mark(getattr(obj, name)(*args), obj)
            if name in _STR_SAFE and hasattr(obj, name):
                result = getattr(obj, name)(*args)
                return self._hide(result) if name == "translate" else self._mark(result, obj)
            return hole(name + "()")
        if isinstance(obj, list):
            if name == "append" and args and len(obj) < V.MAX_ITEMS:
                obj.append(args[0])
                return None
            if name == "extend" and args:
                items = self._iterable(args[0])
                if items is not None and len(obj) + len(items) <= V.MAX_ITEMS:
                    obj.extend(items)
                return None
            if name == "insert" and len(args) == 2 and isinstance(args[0], int) and len(obj) < V.MAX_ITEMS:
                obj.insert(args[0], args[1])
                return None
            if name == "pop":
                return obj.pop(*[a for a in args[:1] if isinstance(a, int)])
            if name == "reverse":
                obj.reverse()
                return None
            if name == "sort" and is_plain(obj) and not kwargs:
                obj.sort()
                return None
            if name in ("index", "count") and args and is_plain(obj) and is_plain(args[0]):
                return getattr(obj, name)(args[0])
            if name == "copy":
                return list(obj)
            return hole(name + "()")
        if isinstance(obj, dict):
            key = args[0] if args else None
            hashable = isinstance(key, (str, bytes, int, float, bool))
            if name == "get" and hashable:
                return obj.get(key, args[1] if len(args) > 1 else None)
            if name in ("keys", "values"):
                return list(getattr(obj, name)())
            if name == "items":
                return [tuple(pair) for pair in obj.items()]
            if name == "copy":
                return dict(obj)
            if name == "update" and args and isinstance(args[0], dict):
                obj.update(args[0])
                return None
            if name == "pop" and hashable:
                return obj.pop(key, args[1] if len(args) > 1 else None)
            if name == "setdefault" and hashable and len(args) > 1:
                return obj.setdefault(key, args[1])
        return hole(name + "()")

    def _join(self, sep: Any, args: List[Any]) -> Any:
        items = self._iterable(args[0]) if args else None
        if items is None:
            return hole("joined")
        if isinstance(sep, bytes) and all(isinstance(i, bytes) for i in items):
            if sum(len(i) for i in items) + len(sep) * len(items) > V.MAX_TEXT:
                raise Budget()
            return self._mark(sep.join(items), sep, *items[:256])
        if all(isinstance(i, str) for i in items) and isinstance(sep, str):
            if sum(len(i) for i in items) + len(sep) * len(items) > V.MAX_TEXT:
                raise Budget()
            return self._mark(sep.join(items), sep, *items[:256])
        if all(isinstance(i, (str, bytes, Sym, Ref)) for i in items):
            return self._mark(Sym(show(sep).join(show(i) for i in items[:4096])), *items[:256])
        return hole("joined")

    # -- known functions ------------------------------------------------------------------
    def _call_ref(self, ref: Ref, args: List[Any], kwargs: Dict[str, Any],
                  node: Optional[ast.Call], scope: Optional[Scope]) -> Any:
        name = _canon(ref.name)
        self._sinks(name, ref, args, kwargs, node)
        pure = _PURE.get(name)
        if pure is not None:
            try:
                return cap(pure(self, args, kwargs, node, scope))
            except _CONTROL:
                return hole(name + "()")
        return Ref(ref.name + "()", ref.dynamic)

    def _sinks(self, name: str, ref: Ref, args: List[Any], kwargs: Dict[str, Any],
               node: Optional[ast.Call]) -> None:
        arg_nodes = node.args if node is not None else []

        def pick(index: int, keyword: str):
            if index < len(args):
                # positions shift when *args was expanded: then nothing is "literal"
                plain = len(arg_nodes) == len(args) and _literal(arg_nodes[index])
                return args[index], plain
            if keyword in kwargs:
                kw = next((k.value for k in node.keywords if k.arg == keyword), None) if node else None
                return kwargs[keyword], _literal(kw)
            return None, False

        if name.startswith(("os.exec", "os.spawn")) and name not in _SINKS:
            rest = args[1:] if name.startswith("os.spawn") else args
            flat: List[Any] = []
            for item in rest:
                flat.extend(item if isinstance(item, (list, tuple)) else [item])
            if flat:
                self.record(node, "command", name, flat, False, ref.dynamic)
            return
        if name in _OPENERS:
            mode, _ = pick(1, "mode")
            target, plain = pick(0, "file")
            if target is not None and isinstance(mode, str) and set(mode) & set("wax+"):
                self.record(node, "path", name, target, plain, ref.dynamic)
            return
        spec = _SINKS.get(name)
        if spec is None:
            if name.rsplit(".", 1)[-1] in _CONNECT and args and isinstance(
                    args[0], (tuple, list)) and len(args[0]) == 2:
                self.record(node, "url", "socket.connect",
                            Sym("tcp://%s:%s" % (show(args[0][0]), show(args[0][1]))), False,
                            ref.dynamic)
            return
        kind, index, keyword, delete = spec
        value, plain = pick(index, keyword)
        if value is None:
            return
        if kind == "url" and isinstance(value, (tuple, list)) and len(value) == 2:
            value = Sym("tcp://%s:%s" % (show(value[0]), show(value[1])))
        scheme = _HOST_SINKS.get(name.rsplit(".", 1)[-1]) if kind == "url" else None
        if scheme and isinstance(value, (str, Sym)) and "://" not in show(value):
            value = self._mark(V.concat(scheme, value), value)      # these take a host name
        self.record(node, kind, name, value, plain, ref.dynamic, delete)

    def record(self, node: Optional[ast.AST], kind: str, sink: str, value: Any, literal: bool,
               dynamic: bool, delete: bool = False) -> None:
        if isinstance(value, (Ref, Func, Bound, Klass)) or value is None:
            return
        text = show(value).strip()
        if len(V.known_part(text).strip()) < 3:
            return
        hidden = self._is_hidden(value)
        if kind == "url" and "://" not in V.known_part(text) and not hidden:
            return                               # no address was recovered, only a fragment
        if kind == "call" and not _SENSITIVE.match(text):
            return                               # getattr(style, name): ordinary dynamic lookup
        line = self.fixed_line or getattr(node, "lineno", self.line)
        if (kind, line, text) in self.seen or len(self.hits) >= 200:
            return
        self.seen.add((kind, line, text))
        trace: List[str] = []
        if self.layer == 0 and self.reads:
            for name in self.reads[-1]:
                step = "%s <- line %d" % (name, self.assigned[name]) if name in self.assigned else ""
                if step and step not in trace and len(trace) < 5:
                    trace.append(step)
        partial = V.is_partial(text)
        self.hits.append(Resolved(
            kind=kind, line=line, sink=sink, value=text[:4000], hidden=hidden, partial=partial,
            delete=delete, dynamic=dynamic, trivial=literal and not dynamic and self.layer == 0,
            layer=self.layer, trace=tuple(trace)))
        if kind == "exec" and not partial and self.layer < V.MAX_DEPTH:
            self._nested(text, line, literal and not dynamic and self.layer == 0)

    def _nested(self, code: str, line: int, trivial: bool) -> None:
        """Model the code that an exec()/eval() call was given."""
        tree = parse(code)
        if tree is None:
            return
        inner = Interp(self.clock, self.layer + 1, line, self.hidden)
        inner.globals.update((k, v) for k, v in self.globals.items() if isinstance(v, Ref))
        inner.run(tree)
        self.hits.extend(inner.hits[:200 - len(self.hits)])
        if not trivial:
            self.payloads.append((line, code))
        self.payloads.extend(inner.payloads)


# -- models of library functions ---------------------------------------------------------
# Each takes (interp, args, kwargs, call node, scope) and works on the scanner's
# own values only. Anything unsupported raises and becomes a ‹hole›.
def _first(args, kwargs, key=""):
    if args:
        return args[0]
    return kwargs[key]


def _decoder(kind):
    def run(interp, args, kwargs, node, scope):
        return interp._hide(V.b_decode(kind, _first(args, kwargs, "s")))
    return run


def _decompress(kind):
    def run(interp, args, kwargs, node, scope):
        return interp._hide(V.decompress(kind, _first(args, kwargs, "data")))
    return run


def _unhex(interp, args, kwargs, node, scope):
    return interp._hide(V.unhex(args[0]))


def _chr(interp, args, kwargs, node, scope):
    return interp._hide(chr(args[0]))


def _ord(interp, args, kwargs, node, scope):
    value = args[0]
    if isinstance(value, (str, bytes)) and len(value) == 1:
        return ord(value)
    raise ValueError


def _str(interp, args, kwargs, node, scope):
    if not args:
        return ""
    value = args[0]
    if isinstance(value, (Sym, str)):
        return value
    if isinstance(value, bytes):
        result, hidden = V.decode(value, args[1] if len(args) > 1 else "utf-8")
        return interp._hide(result) if hidden else interp._mark(result, value)
    if isinstance(value, Ref):
        return hole(value.name)
    if is_plain(value):
        return str(value)[:V.MAX_TEXT]
    raise ValueError


def _int(interp, args, kwargs, node, scope):
    value = args[0]
    if isinstance(value, (str, bytes)) and len(value) <= 80:
        return int(value, *[a for a in args[1:2] if isinstance(a, int)])
    if isinstance(value, (int, float)):
        return int(value)
    raise ValueError


def _bytes(interp, args, kwargs, node, scope):
    if not args:
        return b""
    value = args[0]
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return V.encode(value, args[1] if len(args) > 1 else "utf-8")[0]
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value <= 65536:
            return bytes(value)
        raise ValueError
    items = interp._iterable(value)
    if items is not None and all(isinstance(i, int) and 0 <= i < 256 for i in items):
        return interp._hide(bytes(items))
    raise ValueError


def _range(interp, args, kwargs, node, scope):
    if not all(isinstance(a, int) for a in args) or not 1 <= len(args) <= 3:
        raise ValueError
    span = range(*args)
    if len(span) > _SEQ:
        raise ValueError
    return list(span)


def _seq(build):
    def run(interp, args, kwargs, node, scope):
        if not args:
            return build([])
        items = interp._iterable(args[0])
        if items is None:
            raise ValueError
        return build(items)
    return run


def _sorted(interp, args, kwargs, node, scope):
    items = interp._iterable(args[0])
    if items is None or not is_plain(items) or "key" in kwargs:
        raise ValueError
    return sorted(items, reverse=bool(kwargs.get("reverse", False)))


def _len(interp, args, kwargs, node, scope):
    if isinstance(args[0], (str, bytes, list, tuple, dict)):
        return len(args[0])
    raise ValueError


def _map(interp, args, kwargs, node, scope):
    columns = [interp._iterable(a) for a in args[1:]]
    if not columns or any(c is None for c in columns):
        for column in args[1:]:                       # still let a sink see what it can
            interp.call(args[0], [hole("item")], {}, node, scope)
            break
        raise ValueError
    out = []
    for row in zip(*columns):
        interp.clock.tick()
        out.append(interp.call(args[0], list(row), {}, node, scope))
    return out


def _zip(interp, args, kwargs, node, scope):
    columns = [interp._iterable(a) for a in args]
    if any(c is None for c in columns):
        raise ValueError
    return [tuple(row) for row in zip(*columns)]


def _enumerate(interp, args, kwargs, node, scope):
    items = interp._iterable(args[0])
    if items is None:
        raise ValueError
    start = args[1] if len(args) > 1 and isinstance(args[1], int) else 0
    return [tuple(pair) for pair in enumerate(items, start)]


def _numbers(fn):
    def run(interp, args, kwargs, node, scope):
        items = interp._iterable(args[0]) if len(args) == 1 else list(args)
        if not items or not all(isinstance(i, (int, float)) for i in items):
            raise ValueError
        return fn(items)
    return run


def _getattr(interp, args, kwargs, node, scope):
    obj, name = args[0], args[1]
    if not isinstance(name, str):
        raise ValueError
    literal = node is not None and len(node.args) > 1 and _literal(node.args[1])
    if isinstance(obj, Ref):
        found = Ref(obj.name + "." + name, obj.dynamic or not literal)
        if not literal:
            interp.record(node, "call", "getattr", _canon(found.name), False, True)
        return found
    if isinstance(obj, (str, bytes, list, dict)):
        return Bound(obj, name)
    if name in interp.methods:
        return interp.methods[name]
    raise ValueError


def _import(interp, args, kwargs, node, scope):
    name = _first(args, kwargs, "name")
    if not isinstance(name, str) or not re.fullmatch(r"[\w.]{1,80}", name):
        raise ValueError
    literal = node is not None and bool(node.args) and _literal(node.args[0])
    if not literal:
        interp.record(node, "call", "__import__", name, False, True)
    return Ref(name, not literal)


def _compile(interp, args, kwargs, node, scope):
    return _first(args, kwargs, "source")              # so that exec(compile(...)) is followed


def _env(interp, args, kwargs, node, scope):
    name = args[0]
    if isinstance(name, str) and re.fullmatch(r"[\w()]{1,60}", name):
        return Sym("%" + name + "%")
    raise ValueError


def _codec(direction):
    def run(interp, args, kwargs, node, scope):
        codec = args[1] if len(args) > 1 else kwargs.get("encoding", "utf-8")
        result, hidden = direction(args[0], codec)
        return interp._hide(result) if hidden else interp._mark(result, args[0])
    return run


def _unquote(plus):
    def run(interp, args, kwargs, node, scope):
        if isinstance(args[0], Sym):
            return args[0]
        result = V.url_unquote(args[0], plus)
        return interp._hide(result) if result != show(args[0]) else result
    return run


def _path_join(interp, args, kwargs, node, scope):
    if not args or not all(isinstance(a, (str, bytes, Sym, Ref)) for a in args):
        raise ValueError
    return interp._mark(V.join_path(args), *args)


def _expanduser(interp, args, kwargs, node, scope):
    text = show(args[0])
    return Sym("%USERPROFILE%" + text[1:]) if text.startswith("~") else args[0]


def _same(interp, args, kwargs, node, scope):
    if isinstance(args[0], (str, bytes, Sym)):
        return args[0]
    raise ValueError


def _path_part(fn):
    def run(interp, args, kwargs, node, scope):
        if not isinstance(args[0], (str, Sym)):
            raise ValueError
        text = fn(show(args[0]))
        return Sym(text) if isinstance(args[0], Sym) else text
    return run


def _maketrans(interp, args, kwargs, node, scope):
    if len(args) == 2 and all(isinstance(a, str) for a in args):
        return str.maketrans(args[0], args[1])
    if len(args) == 2 and all(isinstance(a, bytes) for a in args):
        return bytes.maketrans(args[0], args[1])
    raise ValueError


def _zlib(interp, args, kwargs, node, scope):
    data = V._raw(args[0])
    wbits = args[1] if len(args) > 1 else kwargs.get("wbits")
    if isinstance(wbits, int) and (-15 <= wbits <= -8 or 8 <= wbits <= 47):
        return interp._hide(V.inflate(data, wbits))
    return interp._hide(V.decompress("zlib", data))


def _const(value):
    return lambda interp, args, kwargs, node, scope: value


def _never(label):
    # deliberately not modelled: these formats can only be understood by running them
    return lambda interp, args, kwargs, node, scope: hole(label)


def _scope_ref(name):
    return lambda interp, args, kwargs, node, scope: Ref(name)


_PURE = {
    "chr": _chr, "unichr": _chr, "ord": _ord, "str": _str, "unicode": _str, "int": _int,
    "float": lambda i, a, k, n, s: float(a[0]) if isinstance(a[0], (int, float)) or (
        isinstance(a[0], str) and len(a[0]) <= 80) else hole("float"),
    "bool": lambda i, a, k, n, s: bool(a[0]) if is_plain(a[0]) else hole("bool"),
    "abs": lambda i, a, k, n, s: abs(a[0]) if isinstance(a[0], (int, float)) else hole("abs"),
    "len": _len, "bytes": _bytes, "bytearray": _bytes,
    "hex": lambda i, a, k, n, s: hex(a[0]) if isinstance(a[0], int) else hole("hex"),
    "bin": lambda i, a, k, n, s: bin(a[0]) if isinstance(a[0], int) else hole("bin"),
    "oct": lambda i, a, k, n, s: oct(a[0]) if isinstance(a[0], int) else hole("oct"),
    "repr": lambda i, a, k, n, s: repr(a[0])[:V.MAX_TEXT] if is_plain(a[0]) else hole("repr"),
    "range": _range, "xrange": _range,
    "list": _seq(list), "tuple": _seq(tuple), "set": _seq(lambda items: list(dict.fromkeys(
        i for i in items if isinstance(i, (str, bytes, int, float))))),
    "reversed": _seq(lambda items: items[::-1]), "sorted": _sorted,
    "map": _map, "zip": _zip, "enumerate": _enumerate,
    "sum": _numbers(sum), "min": _numbers(min), "max": _numbers(max),
    "dict": lambda i, a, k, n, s: dict(k) if not a else (
        dict(a[0]) if isinstance(a[0], dict) else hole("dict")),
    "print": _const(None), "input": _never("input"), "raw_input": _never("input"),
    "getattr": _getattr, "__import__": _import, "importlib.import_module": _import,
    "compile": _compile,
    "globals": _scope_ref("globals"), "locals": _scope_ref("locals"), "vars": _scope_ref("vars"),
    _IND[6]: _decoder("b64"), "base64.standard_b64decode": _decoder("b64"),
    "base64.decodebytes": _decoder("b64"), "base64.decodestring": _decoder("b64"),
    "base64.urlsafe_b64decode": _decoder("urlsafe"), "base64.b32decode": _decoder("b32"),
    "base64.b16decode": _decoder("b16"), "base64.b85decode": _decoder("b85"),
    "base64.a85decode": _decoder("a85"), "binascii.a2b_base64": _decoder("b64"),
    "binascii.unhexlify": _unhex, "binascii.a2b_hex": _unhex,
    "bytes.fromhex": _unhex, "bytearray.fromhex": _unhex,
    "codecs.decode": _codec(V.decode), "codecs.encode": _codec(V.encode),
    "zlib.decompress": _zlib, "gzip.decompress": _decompress("gzip"),
    "bz2.decompress": _decompress("bz2"), "lzma.decompress": _decompress("lzma"),
    "urllib.parse.unquote": _unquote(False), "urllib.parse.unquote_plus": _unquote(True),
    "urllib.unquote": _unquote(False), "urllib.unquote_plus": _unquote(True),
    "urllib2.unquote": _unquote(False),
    "os.path.join": _path_join, "os.path.expanduser": _expanduser,
    "os.path.expandvars": _same, "os.path.abspath": _same, "os.path.normpath": _same,
    "os.path.realpath": _same, "os.path.normcase": _same,
    "os.path.dirname": _path_part(ntpath.dirname), "os.path.basename": _path_part(ntpath.basename),
    "os.getenv": _env, "os.environ.get": _env,
    "os.getcwd": _never("cwd"), "os.getcwdu": _never("cwd"),
    "tempfile.gettempdir": _const(Sym("%TEMP%")),
    "tempfile.mktemp": _const(Sym("%TEMP%\\" + V.OPEN + "tmp" + V.CLOSE)),
    "str.maketrans": _maketrans, "bytes.maketrans": _maketrans, "string.maketrans": _maketrans,
    _IND[7]: _never("marshal"), "pickle.loads": _never("pickle"),
}


def worth(text: str) -> bool:
    return _WORTH.search(text) is not None


def analyse(text: str, renpy: bool = False, clock: Optional[Clock] = None):
    """``(hits, payloads)`` for Python source; payloads are ``(line, code)``."""
    if not worth(text):
        return [], []
    tree = parse(renpy_python(text) if renpy else text)
    if tree is None and renpy:
        tree = parse(text)
    if tree is None:
        if clock is not None:               # too large or too deep to be read at all: said
            clock.stopped = clock.stopped or unread(text)
        return [], []
    interp = Interp(clock or Clock())
    interp.run(tree)
    return interp.hits, interp.payloads
