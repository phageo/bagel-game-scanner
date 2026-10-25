"""What the main process of an Electron app does with the messages its pages send.

A preload script that hands the page a message channel of its choice
(``send: (channel, data) => ipcRenderer.send(channel, data)``) lets a page's
script - also one it loads from somewhere else - send any message to the main
process. Whether that reaches the PC depends on what the main process does with
a message (phageo, 2026-10-15, forty-eighth message): the window still counts as
shut in when **no** ``ipcMain.on`` / ``once`` / ``handle`` handler of the app
passes the message's data to

* a process start (``child_process``, ``execa`` ...),
* a code load (``eval``, ``new Function``, ``vm``, ``require`` / ``import()`` of a
  name that is not written out, ``process.dlopen``, a ``Worker``),
* the shell's open (``shell.openPath`` / ``openItem`` / ``openExternal`` - an
  address written out as http(s) is a browser open), or
* a file write whose path is then started.

The reading follows a message's data (the handler's parameters after the event)
through assignments, taken-apart objects, ``for ... of``, the functions of the
same script (also one wrapped like ``debounce(async (a, b) => ...)``), the
functions of the app's own modules (``require("./storage")``), a promise
(``resolve(data)``: what the function around the promise gives back) and the
fields of objects (``window.gameInfo = {...arg}``: every ``.gameInfo`` read in
the app's main scripts carries it). A function of a published package is no
place it follows; a package's function named like one of the sinks above is the
sink. Whatever it cannot follow - data handed to a function it does not find, a
handler it does not find, a limit - is **not known**, and the window is then not
shut in.

Everything here reads text; nothing is run. It is a reading by names, not a
parser: two variables of one name in one function are one variable to it (that
only adds data, never loses it). Known misses: a function handed on as a value
and called elsewhere (``const f = obj.method; f(data)``), getters and setters,
``Reflect`` / ``Proxy``, ``eval``'s own scope, a field read through a computed key
(``obj[name]``), main-process code of the app that is not among its scripts (a
bundled main script whose modules call each other through the bundler's own
``require`` - their calls are "not known").
"""
from __future__ import annotations

import bisect
import posixpath
import re
from typing import Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Set, Tuple

from ..rules import _MASKS, mask_comments

MAX_SCRIPT = 1024 * 1024            # characters of one main-process script that are read
MAX_TOTAL = 16 * 1024 * 1024        # characters of all of them, per app
MAX_HANDLERS = 200                  # handlers of one app that are followed
MAX_WORK = 20_000                   # (function, parameters) readings for one handler
MAX_DEPTH = 8                       # hand-overs from the handler
MAX_ROUNDS = 4                      # rounds through the fields and promises a handler fills

NOTHING = "nothing"
PROCESS = "starts a program"
CODE = "loads code"
SHELL = "opens a file with the shell"
WRITE = "writes a file that is then started"
NOT_KNOWN = "not known"

_ID = r"[A-Za-z_$][\w$]*"
_WORD = re.compile(r"(?:(?<![\w$.])|(?<=\.\.\.))" + _ID)          # (also ...name: a spread)
_FIELD = re.compile(r"(?:\?\.|\.)\s*(%s)" % _ID)
_HANDLER = re.compile(r"(?<![\w$.])ipcMain\s*\.\s*(on|once|handle|handleOnce)\s*\(")
_KEYWORDS = frozenset("""if for while switch catch function return typeof with do else new await yield delete
void in of async super class const let var instanceof throw case default try finally import export""".split())
_CALL = re.compile(r"(?<![\w$.])(new\s+)?((?:%s\s*(?:\?\.|\.)\s*)*%s)\s*(?:\?\.\s*)?\(" % (_ID, _ID))
_CHAINED = re.compile(r"\)\s*(?:\?\.|\.)\s*(%s)\s*\(" % _ID)       # require("x").name(
_ASSIGN = re.compile(r"(?<![\w$.])(?:(?:const|let|var)\s+)?(\{[^{}=;]{0,400}\}|\[[^\[\]=;]{0,400}\]|%s"
                     r"(?:\s*(?:\?\.|\.)\s*%s)*)\s*(?:[+\-*/%%&|^]|\?\?|\|\||&&)?=(?![=>])" % (_ID, _ID))
_FOR = re.compile(r"(?<![\w$.])for\s*(?:await\s*)?\(\s*(?:const|let|var)?\s*(\{[^{}]{0,400}\}|\[[^\[\]]{0,400}\]|%s)"
                  r"\s+(?:of|in)\b" % _ID)
_RETURN = re.compile(r"(?<![\w$.])return\b")
_REQUIRE = re.compile(r"""(?<![\w$.])(?:const|let|var)\s+(\{[^{}]{0,400}\}|%s)\s*=\s*require\s*\(\s*(["'])([^"'\n]{1,200})\2\s*\)"""
                      r"""(\s*\.\s*%s)?""" % (_ID, _ID))
_IMPORT = re.compile(r"""(?<![\w$.])import\s+(?:(%s)\s*,?\s*)?(?:\*\s+as\s+(%s)\s*)?(\{[^{}]{0,400}\})?\s*from\s*(["'])([^"'\n]{1,200})\4"""
                     % (_ID, _ID))
_EXPORTS = re.compile(r"(?<![\w$.])(?:module\s*\.\s*)?exports\s*\.\s*(%s)\s*=\s*(%s)\s*[;,\n)]" % (_ID, _ID))
_EXPORT_OBJECT = re.compile(r"(?<![\w$.])module\s*\.\s*exports\s*=\s*\{")
_EXPORT_DEFAULT = re.compile(r"(?<![\w$.])module\s*\.\s*exports\s*=\s*(%s)\s*[;\n]" % _ID)
_INLINE_CP = re.compile(r"""require\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*(%s)\s*\(""" % _ID)
_HTTP = re.compile(r"""\s*["'`]https?://""", re.I)
_NAMED_AT = re.compile(r"(?:(?<![\w$.])(?:const|let|var)\s+)?((?:%s\s*\.\s*)*%s)\s*(?:=|:)\s*(?:async\s*)?\Z" % (_ID, _ID))
_WRAPPED_AT = re.compile(r"(?:(?<![\w$.])(?:const|let|var)\s+)?((?:%s\s*\.\s*)*%s)\s*=\s*(?:%s\s*\.\s*)*%s\s*\(\s*(?:async\s*)?\Z"
                         % (_ID, _ID, _ID, _ID))

# the sinks, by the name that is called
_PROCESS_NAMES = frozenset({"execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork", "execa",
                            "execaSync", "execaCommand", "execaCommandSync", "execaNode"})
_PROCESS_PACKAGES = frozenset({"child_process", "execa", "cross-spawn", "shelljs", "node-pty", "sudo-prompt",
                               "@vscode/sudo-prompt", "open", "opn"})
_SHELL_NAMES = frozenset({"openPath", "openItem", "openExternal"})
_CODE_NAMES = frozenset({"eval", "Function", "runInThisContext", "runInNewContext", "runInContext",
                         "compileFunction", "dlopen", "Worker", "Script", "require", "import", "importScripts"})
_WRITE_PATH = {"writeFile": 0, "writeFileSync": 0, "appendFile": 0, "appendFileSync": 0, "createWriteStream": 0,
               "outputFile": 0, "outputFileSync": 0, "writeJson": 0, "writeJsonSync": 0, "copyFile": 1,
               "copyFileSync": 1, "rename": 1, "renameSync": 1, "cp": 1, "cpSync": 1, "move": 1, "moveSync": 1}
# what a call to one of these does is known and reaches none of the sinks
_BUILTINS = frozenset("""console JSON Object Array Math String Number Boolean Promise Date RegExp Error TypeError
parseInt parseFloat isNaN isFinite encodeURIComponent decodeURIComponent encodeURI decodeURI setTimeout setInterval
clearTimeout clearInterval setImmediate Buffer Symbol Map Set WeakMap WeakSet structuredClone BigInt queueMicrotask
Uint8Array Int8Array Uint16Array Int16Array Uint32Array Int32Array Float32Array Float64Array ArrayBuffer DataView
TextEncoder TextDecoder URL URLSearchParams atob btoa""".split())
# names in a written file's path that tell nothing about which file it is
_COMMON = frozenset("""path join resolve normalize app getPath getAppPath __dirname __filename process env os tmpdir
homedir fs promises require await this window electron dirname basename extname sep String toString""".split())


class Handler(NamedTuple):
    """One ``ipcMain`` handler and what the message's data reaches."""
    file: str
    line: int
    kind: str                       # on / once / handle / handleOnce
    channel: str                    # "*": not written out
    reach: Tuple[str, ...]          # PROCESS, CODE, SHELL, WRITE, NOT_KNOWN (empty: nothing)
    why: str                        # where (file and line of the first sink), or why it is not known


class Reading(NamedTuple):
    handlers: Tuple[Handler, ...]
    complete: bool                  # every main-process script of the app was read
    why: str                        # ... and if not, why

    @property
    def contained(self) -> bool:
        """No handler passes a message's data to a sink, and nothing was left unread."""
        return self.complete and not any(h.reach for h in self.handlers)

    def first(self) -> Optional[Handler]:
        return next((h for h in self.handlers if h.reach), None)


def _bare(text: str) -> str:
    """``text`` with comments, the inside of strings and the text parts of templates blanked
    (same length); what stands in a template's ``${...}`` stays, in brackets of its own."""
    def blank(m: "re.Match[str]") -> str:
        token = m.group(0)
        if token[:2] in ("//", "/*"):
            return re.sub(r"[^\n]", " ", token)
        if token[:1] in "\"'" and len(token) > 1:
            return token[0] + re.sub(r"[^\n]", " ", token[1:-1]) + token[-1]
        if token[:1] == "`":
            out, i, depth = ["`"], 1, 0
            while i < len(token):
                ch = token[i]
                if depth:
                    depth += {"{": 1, "}": -1}.get(ch, 0)
                    out.append(ch if depth else ")")
                elif token.startswith("${", i):
                    out.append(" (")                     # ${x} -> " (x)": parts that stand apart
                    depth, i = 1, i + 2
                    continue
                elif ch == "`" and i == len(token) - 1:
                    out.append("`")
                else:
                    out.append("\n" if ch == "\n" else " ")
                i += 1
            return "".join(out)
        return re.sub(r"[^\n]", " ", token)                 # a regular expression
    return _MASKS["c"].sub(blank, text)


def keeps(name: str, text: str) -> bool:
    """Is ``text`` (the script ``name`` of an Electron app) one this reading needs: the app's own
    scripts, and any script - also of a package - that handles messages."""
    low = name.replace("\\", "/").lower()
    return "ipcMain" in text or ("/node_modules/" not in low and "!node_modules/" not in low)


class _Function(NamedTuple):
    file: str
    head: int
    name: str
    params: Tuple[Tuple[str, ...], ...]     # the names each parameter binds
    rest: int                               # index of a ...rest parameter (-1: none)
    a: int                                  # the body
    b: int


class _Call(NamedTuple):
    pos: int
    callee: str                             # "a.b.c" (blanks and ?. taken out)
    new: bool
    args: Tuple[Tuple[int, int], ...]


class _Script:
    """What one text says, found once: its functions, calls, assignments, modules."""

    def __init__(self, name: str, text: str) -> None:
        self.name = name
        self.code = mask_comments(text, "c")        # comments blanked
        self.bare = _bare(text)                     # ... and the inside of strings
        self.match = _brackets(self.bare)
        self.functions: List[_Function] = []
        self.by_name: Dict[str, List[_Function]] = {}
        self._functions()
        self.parent = _parents(self.functions)          # (also puts them in the order of their bodies)
        self.heads = [f.a for f in self.functions]      # where each body begins, ascending
        self.index = {(f.head, f.a): i for i, f in enumerate(self.functions)}
        self.whole = _Function(name, -2, "", (), -1, 0, len(self.bare))     # the text itself (Run.handler)
        self.calls = list(self._calls())
        self.call_pos = [c.pos for c in self.calls]
        self.assigns = list(self._assigns())
        self.assign_pos = [a[0] for a in self.assigns]
        self.returns = [m.end() for m in _RETURN.finditer(self.bare)]
        self.bindings: Dict[str, Tuple[str, Optional[str]]] = {}     # name -> (module, member)
        self.exports: Dict[str, str] = {}                             # exported name -> name in the script
        self.default = ""
        self._modules()

    # -- reading the text once ----------------------------------------------------------------
    def _functions(self) -> None:
        bare, match = self.bare, self.match
        for m in re.finditer(r"(?<![\w$.])function\b\s*\*?\s*(%s)?\s*\(|\(|(?<![\w$.])(%s)\s*=>" % (_ID, _ID), bare):
            if m.group(0).startswith("function"):
                opener = m.end() - 1
                close = match.get(opener, -1)
                brace = _skip(bare, close + 1) if close > 0 else -1
                if brace < 0 or bare[brace:brace + 1] != "{":
                    continue
                self._add(m.start(), m.group(1) or self._named(m.start()), bare[opener + 1:close], brace + 1,
                          match.get(brace, len(bare)))
            elif m.group(2):                                        # x => ...
                self._arrow(m.start(), m.group(2), m.end())
            else:                                                   # ( ... ) => ... or name( ... ) {
                close = match.get(m.start(), -1)
                if close < 0:
                    continue
                after = _skip(bare, close + 1)
                if bare.startswith("=>", after):
                    start = m.start()
                    k = _back(bare, start - 1)
                    if bare[max(0, k - 4):k + 1] == "async":
                        start = k - 4
                    self._arrow(start, bare[m.start() + 1:close], after + 2)
                elif bare[after:after + 1] == "{":
                    k = _back(bare, m.start() - 1)
                    word = re.search(r"(%s)\Z" % _ID, bare[max(0, k - 80):k + 1]) if k >= 0 else None
                    if word is None or word.group(1) in _KEYWORDS:
                        continue
                    begin = k - len(word.group(1)) + 1
                    if begin > 0 and bare[begin - 1] in ".$" or re.search(r"function\s*\*?\s*\Z", bare[max(0, begin - 12):begin]):
                        continue
                    self._add(begin, word.group(1), bare[m.start() + 1:close], after + 1, match.get(after, len(bare)))

    def _arrow(self, start: int, params: str, after: int) -> None:
        bare = self.bare
        body = _skip(bare, after)
        if bare[body:body + 1] == "{":
            a, b = body + 1, self.match.get(body, len(bare))
        else:
            a, b = body, _expr_end(bare, body, self.match)
        self._add(start, self._named(start), params, a, b)

    def _named(self, start: int) -> str:
        before = self.bare[max(0, start - 200):start]
        m = _NAMED_AT.search(before) or _WRAPPED_AT.search(before)
        return re.sub(r"\s+", "", m.group(1)).rsplit(".", 1)[-1] if m else ""

    def _add(self, head: int, name: str, params: str, a: int, b: int) -> None:
        names, rest = [], -1
        for i, part in enumerate(_split(params)):
            part = part.strip()
            if part.startswith("..."):
                rest, part = i, part[3:]
            part = re.split(r"(?<![=!<>])=(?![=>])", part, maxsplit=1)[0]            # a default value
            names.append(tuple(_names(part)))
        f = _Function(self.name, head, name, tuple(names), rest, a, b)
        self.functions.append(f)
        if name:
            self.by_name.setdefault(name, []).append(f)

    def _calls(self) -> Iterable[_Call]:
        bare, match = self.bare, self.match
        found = []
        for m in _CALL.finditer(bare):
            callee = re.sub(r"\s+|\?", "", m.group(2))
            if callee in _KEYWORDS or callee.split(".")[0] in ("function",):
                continue
            opener = m.end() - 1
            close = match.get(opener, -1)
            if close < 0:
                continue
            if not m.group(1) and "." not in callee and bare[_skip(bare, close + 1):_skip(bare, close + 1) + 1] == "{":
                continue                                # name(params) { ... }: a method written, not a call
            found.append(_Call(m.start(), callee, bool(m.group(1)), tuple(_spans(bare, opener, close))))
        for m in _CHAINED.finditer(bare):                         # f(...).name(...): what f gave back
            opener = m.end() - 1
            close = match.get(opener, -1)
            if close > 0:
                found.append(_Call(m.start() + 1, "?." + m.group(1), False, tuple(_spans(bare, opener, close))))
        for m in re.finditer(r"\]\s*(?:\?\.\s*)?\(", bare):         # table[key](...): which function, not known
            opener = m.end() - 1
            close = match.get(opener, -1)
            if close > 0:
                found.append(_Call(m.start(), "[]", False, tuple(_spans(bare, opener, close))))
        found.sort(key=lambda c: c.pos)
        return found

    def _assigns(self) -> Iterable[Tuple[int, int, int, str]]:
        """(where, start of the value, its end, what is given it) - also ``for (x of value)``."""
        bare, match = self.bare, self.match
        for m in _ASSIGN.finditer(bare):
            target = re.sub(r"\s+|\?", "", m.group(1))
            yield m.start(), m.end(), _expr_end(bare, m.end(), match), target
        for m in _FOR.finditer(bare):
            close = match.get(bare.find("(", m.start()), -1)
            if close > 0:
                yield m.start(), m.end(), close, re.sub(r"\s+", "", m.group(1))

    def _modules(self) -> None:
        code = self.code
        for m in _REQUIRE.finditer(code):
            spec = m.group(3)
            member = re.sub(r"[\s.]", "", m.group(4)) if m.group(4) else None
            target = m.group(1)
            if target.startswith("{"):
                for key, name in _pairs(target):
                    self.bindings[name] = (spec, key)
            else:
                self.bindings[target] = (spec, member)
        for m in _IMPORT.finditer(code):
            spec = m.group(5)
            if m.group(1):
                self.bindings[m.group(1)] = (spec, "default")
            if m.group(2):
                self.bindings[m.group(2)] = (spec, None)
            if m.group(3):
                for key, name in _pairs(m.group(3).replace(" as ", ":")):
                    self.bindings[name] = (spec, key)
        for m in _EXPORTS.finditer(code):
            self.exports[m.group(1)] = m.group(2)
        for m in _EXPORT_OBJECT.finditer(self.bare):
            close = self.match.get(m.end() - 1, -1)
            if close > 0:
                for key, name in _pairs(self.bare[m.end() - 1:close + 1]):
                    self.exports.setdefault(key, name)
        m = _EXPORT_DEFAULT.search(code)
        if m:
            self.default = m.group(1)

    # -- places ----------------------------------------------------------------------------------
    def inner(self, pos: int) -> int:
        """The innermost function around ``pos`` (index into ``functions``; -1: none)."""
        i = bisect.bisect_right(self.heads, pos) - 1
        while i >= 0 and not (self.functions[i].a <= pos < self.functions[i].b):
            i = self.parent[i]
        return i

    def line_of(self, pos: int) -> int:
        return self.code.count("\n", 0, pos) + 1


def _brackets(bare: str) -> Dict[int, int]:
    out: Dict[int, int] = {}
    stack: List[int] = []
    for m in re.finditer(r"[()\[\]{}]", bare):
        if m.group(0) in "([{":
            stack.append(m.start())
        elif stack:
            out[stack.pop()] = m.start()
    return out


def _parents(functions: List[_Function]) -> List[int]:
    """For each function (in the order of their bodies), the one its body stands in (-1: none)."""
    order = sorted(range(len(functions)), key=lambda i: (functions[i].a, -functions[i].b))
    ranked = [functions[i] for i in order]
    functions[:] = ranked
    parent, around = [-1] * len(ranked), []
    for i, f in enumerate(ranked):
        while around and ranked[around[-1]].b <= f.a:
            around.pop()
        parent[i] = around[-1] if around else -1
        around.append(i)
    return parent


def _skip(text: str, pos: int) -> int:
    while 0 <= pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    return pos


def _back(text: str, pos: int) -> int:
    while pos >= 0 and text[pos] in " \t\r\n":
        pos -= 1
    return pos


def _expr_end(bare: str, pos: int, match: Dict[int, int], reach: int = 200_000) -> int:
    """Where the expression that begins at ``pos`` ends: a ``;``, a ``,`` or a closing bracket of
    the level it began at, or a line end the expression does not go on behind."""
    i, n = pos, min(len(bare), pos + reach)
    while i < n:
        ch = bare[i]
        if ch in "([{":
            close = match.get(i, -1)
            if close < 0:
                return n
            i = close + 1
            continue
        if ch in ")]};,":
            return i
        if ch == "\n":
            j, k = _skip(bare, i), _back(bare, i - 1)
            if j >= len(bare) or (bare[j] not in ".?:+-*/%&|^=<>,([" and (k < pos or bare[k] not in ".?:+-*/%&|^=<>,(!~")):
                return i
        i += 1
    return n


def _split(text: str) -> List[str]:
    """``text`` cut at the commas outside brackets."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
    if text[start:].strip():
        out.append(text[start:])
    return out


def _spans(bare: str, opener: int, close: int) -> Iterable[Tuple[int, int]]:
    depth, start = 0, opener + 1
    for i in range(opener + 1, close):
        ch = bare[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            yield start, i
            start = i + 1
    if bare[start:close].strip():
        yield start, close


def _names(target: str) -> List[str]:
    """The names a target binds: ``x``, ``{ a, b: c, ...d }`` (a, c, d), ``[x, y]``."""
    target = target.strip()
    if not target or target[0] not in "{[":
        m = re.match(_ID, target)
        return [m.group(0)] if m and m.group(0) not in _KEYWORDS else []
    out = []
    for part in _split(target[1:-1] if target[-1:] in "}]" else target[1:]):
        part = re.split(r"(?<![=!<>])=(?![=>])", part, maxsplit=1)[0].strip()
        if part.startswith("..."):
            part = part[3:]
        if ":" in part and part[:1] not in "{[":
            part = part.split(":", 1)[1]
        out += _names(part)
    return out


def _pairs(obj: str) -> List[Tuple[str, str]]:
    """``{ a, b: c, d() {...} }`` -> [(a, a), (b, c), (d, d)] (key, the name it stands for)."""
    out = []
    inner = obj.strip()[1:-1]
    for part in _split(inner):
        part = part.strip()
        m = re.match(r"""["']?(%s)["']?\s*(?::\s*(%s)\s*$|\(|$)""" % (_ID, _ID), part)
        if m:
            out.append((m.group(1), m.group(2) or m.group(1)))
    return out


class _Run:
    """One handler followed: what its message's data reaches."""

    def __init__(self, app: "_App") -> None:
        self.app = app
        self.fields: Set[str] = set()                # object fields that hold the message's data
        self.always: Set[Tuple[str, int]] = set()    # functions whose result is (a promise of) it
        self.reach: Dict[str, str] = {}              # what is reached -> where
        self.unknown = ""
        self.work = 0
        self.seen: Set[tuple] = set()
        self.returning: Dict[tuple, bool] = {}
        self.writes: List[Tuple[_Script, int, int]] = []    # (script, start, end) of written paths

    def found(self, what: str, script: _Script, pos: int) -> None:
        self.reach.setdefault(what, "%s, line %d" % (script.name.replace("\\", "/").rsplit("/", 1)[-1].rsplit("!", 1)[-1],
                                                     script.line_of(pos)))

    def lost(self, why: str) -> None:
        self.unknown = self.unknown or why

    # -- the data in a stretch of text -----------------------------------------------------------
    def tainted(self, script: _Script, a: int, b: int, names: Set[str], depth: int) -> bool:
        if not names and not self.fields and not self.always:
            return False
        bare = script.bare
        if names:
            for m in _WORD.finditer(bare, a, b):
                if m.group(0) in names:
                    return True
        if self.fields:
            for m in _FIELD.finditer(bare, a, b):
                if m.group(1) in self.fields:
                    return True
        i = bisect.bisect_left(script.call_pos, a)
        while i < len(script.calls) and script.calls[i].pos < b:
            call = script.calls[i]
            i += 1
            kind, targets = self.resolve(script, call)
            if kind != "functions":
                continue
            for f in targets:
                key = (f.file, f.head)
                if key in self.always:
                    return True
                marked = frozenset(k for k, (x, y) in enumerate(call.args) if self.tainted(script, x, y, names, depth + 1)) \
                    if depth < MAX_DEPTH else frozenset()
                if self.returns(f, marked, depth + 1):
                    return True
        return False

    def returns(self, f: _Function, marked: FrozenSet[int], depth: int) -> bool:
        """Does ``f``, given the data in its parameters ``marked``, give it back?"""
        if not marked and not self.fields and not self.always:
            return False
        key = (f.file, f.head, marked, frozenset(self.fields), len(self.always))
        if key in self.returning:
            return self.returning[key]
        if depth > 3 * MAX_DEPTH:
            self.lost("the reading stopped at its limit (%d calls inside each other)" % (3 * MAX_DEPTH))
            return False
        self.returning[key] = False                  # (while it is being read)
        script = self.app.scripts[f.file]
        names = self.names(script, f, marked, depth)
        out = False
        if script.bare[f.a - 1:f.a] != "{":          # x => expression
            out = self.tainted(script, f.a, f.b, names, depth)
        else:
            index = script.index.get((f.head, f.a), -1) if depth <= MAX_DEPTH else -1
            for at in script.returns[bisect.bisect_left(script.returns, f.a):bisect.bisect_left(script.returns, f.b)]:
                if index >= 0 and script.inner(at) == index and \
                        self.tainted(script, at, _expr_end(script.bare, at, script.match), names, depth):
                    out = True
                    break
        self.returning[key] = out
        return out

    def names(self, script: _Script, f: _Function, marked: FrozenSet[int], depth: int) -> Set[str]:
        """The names in ``f`` that hold the data: the ``marked`` parameters, what is given them."""
        names: Set[str] = set()
        for k in marked:
            if k < len(f.params):
                names.update(f.params[k])
            elif f.rest >= 0:
                names.update(f.params[f.rest])
        lo, hi = bisect.bisect_left(script.assign_pos, f.a), bisect.bisect_left(script.assign_pos, f.b)
        for _ in range(8):
            before = len(names)
            for _at, x, y, target in script.assigns[lo:hi]:
                if target.split(".")[0] in names and "." not in target:
                    continue
                if self.tainted(script, x, y, names, depth):
                    if "." in target and not target.startswith(("{", "[")):
                        root = target.split(".")[0]
                        if self.local(script, f, root):
                            names.add(root)          # a field of an object of the function: the object has it
                        continue                     # (any other field: Run.follow)
                    names.update(_names(target))
            if len(names) == before:
                break
        return names

    @staticmethod
    def local(script: _Script, f: _Function, name: str) -> bool:
        """Is ``name`` a parameter of ``f`` or declared in its body?"""
        if f.head < 0:
            return False
        if any(name in bound for bound in f.params):
            return True
        return re.search(r"(?<![\w$.])(?:const|let|var)\s+%s(?![\w$])" % re.escape(name), script.bare[f.a:f.b]) is not None

    # -- following -------------------------------------------------------------------------------
    def follow(self, f: _Function, marked: FrozenSet[int], depth: int = 0) -> None:
        key = (f.file, f.head, marked, frozenset(self.fields), len(self.always))
        if key in self.seen:
            return
        self.seen.add(key)
        self.work += 1
        if self.work > MAX_WORK or depth > MAX_DEPTH:
            self.lost("the reading stopped at its limit (%s)" % ("%d readings" % MAX_WORK if self.work > MAX_WORK
                                                                 else "%d hand-overs" % MAX_DEPTH))
            return
        script = self.app.scripts[f.file]
        names = self.names(script, f, marked, depth)
        bare = script.bare
        # fields given the data: every read of them carries it (Run.tainted)
        lo, hi = bisect.bisect_left(script.assign_pos, f.a), bisect.bisect_left(script.assign_pos, f.b)
        for _at, x, y, target in script.assigns[lo:hi]:
            if "." in target and not target.startswith(("{", "[")) and not self.local(script, f, target.split(".")[0]) \
                    and self.tainted(script, x, y, names, depth):
                self.fields.add(target.rsplit(".", 1)[-1])
        i = bisect.bisect_left(script.call_pos, f.a)
        while i < len(script.calls) and script.calls[i].pos < f.b:
            call = script.calls[i]
            i += 1
            marked_args = frozenset(k for k, (x, y) in enumerate(call.args) if self.tainted(script, x, y, names, depth))
            root = call.callee.split(".")[0]
            receiver = "." in call.callee and root in names
            if not marked_args and not receiver:
                continue
            if self.sink(script, call, marked_args):
                continue
            kind, targets = self.resolve(script, call)
            if kind == "promise":
                for g in targets:
                    self.always.add((g.file, g.head))
                continue
            for k, (x, y) in enumerate(call.args):         # functions written as arguments get the data
                if k in marked_args or receiver or marked_args:
                    for g in self._written_in(script, x, y):
                        self.follow(g, frozenset(range(len(g.params) + 1)), depth + 1)
                    name = bare[x:y].strip()
                    if re.match(_ID + r"\Z", name):
                        for g in script.by_name.get(name, ()):
                            self.follow(g, frozenset(range(len(g.params) + 1)), depth + 1)
            if kind == "functions":
                for g in targets:
                    self.follow(g, marked_args, depth + 1)
            elif kind == "unknown" and marked_args:
                self.lost("the message's data is handed to %s (%s), which the reading does not find"
                          % (call.callee, "%s, line %d" % (script.name.rsplit("/", 1)[-1].rsplit("!", 1)[-1],
                                                           script.line_of(call.pos))))

    def _written_in(self, script: _Script, a: int, b: int) -> List[_Function]:
        i = bisect.bisect_left(script.heads, a)
        out = []
        while i < len(script.functions) and script.functions[i].a < b:
            g = script.functions[i]
            if a <= g.head < b and (script.parent[i] < 0 or not a <= script.functions[script.parent[i]].head < b):
                out.append(g)
            i += 1
        return out

    def sink(self, script: _Script, call: _Call, marked: FrozenSet[int]) -> bool:
        """Is ``call`` one of the sinks? (True: it is - and is said, if the data reaches it.)"""
        parts = call.callee.split(".")
        last, root = parts[-1], parts[0]
        package = script.bindings.get(root, ("", None))[0].replace("node:", "")
        member = script.bindings.get(root, ("", None))[1]
        if not marked:
            return last in _PROCESS_NAMES or last in _SHELL_NAMES or last in _CODE_NAMES or last in _WRITE_PATH
        if call.callee == "?.%s" % last and _INLINE_CP.search(script.code, max(0, call.pos - 80), call.pos + len(last) + 4):
            self.found(PROCESS, script, call.pos)
            return True
        if last in _PROCESS_NAMES or (last == "exec" and (package in _PROCESS_PACKAGES or member == "exec")) or (
                len(parts) == 1 and package in _PROCESS_PACKAGES) or (package in _PROCESS_PACKAGES and package != "child_process"):
            self.found(PROCESS, script, call.pos)
            return True
        if last in _SHELL_NAMES:
            if 0 in marked and not (call.args and _HTTP.match(script.code, call.args[0][0])):
                self.found(SHELL, script, call.pos)
            return True
        if last in _CODE_NAMES and (len(parts) == 1 or last not in ("require", "import", "Function", "eval")):
            if last == "Script" and not call.new:
                return False
            self.found(CODE, script, call.pos)
            return True
        if last in _WRITE_PATH:
            k = _WRITE_PATH[last]
            if k < len(call.args):
                x, y = call.args[k]
                self.writes.append((script, x, y))
            return True
        return False

    def resolve(self, script: _Script, call: _Call) -> Tuple[str, List[_Function]]:
        """What ``call`` calls: ("functions", [...]) of the app's scripts; ("library", []) - a
        package, a built-in, a method of an object no app function is named like; ("promise",
        [f]) - the ``resolve`` of a promise made in ``f``; ("unknown", [])."""
        parts = call.callee.split(".")
        root, last = parts[0], parts[-1]
        if root == "?":
            return "library", []
        if root == "[]":
            return "unknown", []
        if len(parts) == 1:
            held = self._parameter(script, call.pos, root)
            if held is not None:
                return held
            own = script.by_name.get(root)
            if own:
                return "functions", own
            if root in script.bindings:
                return self._imported(script, root, None)
            if root in _BUILTINS or root in _KEYWORDS:
                return "library", []
            return "unknown", []
        if root in script.bindings:
            return self._imported(script, root, parts[1] if len(parts) == 2 else last)
        own = script.by_name.get(last)
        if own:
            return "functions", own
        return "library", []

    def _parameter(self, script: _Script, pos: int, name: str) -> Optional[Tuple[str, List[_Function]]]:
        """A call of a parameter of a function around ``pos`` (None: ``name`` is none):
        ``new Promise((resolve, reject) => { ... resolve(data) })`` - the promise of the function
        it is made in carries the data ("promise"), ``reject`` its error ("library"); any other
        parameter is a function handed in from somewhere: "unknown"."""
        i = script.inner(pos)
        while i >= 0:
            f = script.functions[i]
            for k, bound in enumerate(f.params):
                if name not in bound:
                    continue
                if re.search(r"new\s+Promise\s*\(\s*(?:async\s+)?\Z", script.bare[max(0, f.head - 40):f.head]):
                    if k:
                        return "library", []
                    outer = script.parent[i]
                    return "promise", [script.functions[outer]] if outer >= 0 else []
                return "unknown", []
            i = script.parent[i]
        return None

    def _imported(self, script: _Script, root: str, member: Optional[str], hops: int = 0) -> Tuple[str, List[_Function]]:
        if hops > 4:
            return "unknown", []
        spec, bound = script.bindings[root]
        name = bound if bound not in (None, "default") else member
        if not spec.startswith((".", "/")):
            return "library", []                      # a package (or a built-in module of Node)
        other = self.app.module(script.name, spec)
        if other is None:
            return "unknown", []
        if name is None:
            wanted = other.default
        else:
            wanted = other.exports.get(name, name)
        found = other.by_name.get(wanted, []) if wanted else []
        if found:
            return "functions", found
        if wanted in other.bindings:                  # handed on from another module
            return self._imported(other, wanted, None, hops + 1)
        return "library", []                          # (a value of the module that is no function)


class _App:
    def __init__(self, texts: Dict[str, str], mains: Optional[Set[str]] = None) -> None:
        self.scripts = {name: _Script(name, text) for name, text in texts.items()}
        self._paths = {self._key(name): name for name in texts}
        self.missing = ""
        # the main process's scripts: the main script, the scripts with handlers, and what they
        # require of the app's own files (pages, workers and preload scripts run elsewhere)
        todo = [name for name in sorted(self.scripts) if "ipcMain" in texts[name] or (
            mains and self._key(name).rsplit("/", 1)[-1] in mains and "node_modules/" not in self._key(name))]
        self.main: Set[str] = set()
        while todo:
            name = todo.pop()
            if name in self.main:
                continue
            self.main.add(name)
            script = self.scripts[name]
            for spec, _member in script.bindings.values():
                if spec.startswith((".", "/")) and not spec.lower().endswith((".json", ".node")):
                    other = self.module(name, spec)
                    if other is None:
                        if "node_modules/" not in self._key(name):   # (a package's own files: a library)
                            self.missing = self.missing or "a module of the main process (%s) was not read" % spec
                    else:
                        todo.append(other.name)

    @staticmethod
    def _key(name: str) -> str:
        return name.replace("\\", "/").replace("!", "/").lower()

    def module(self, near: str, spec: str) -> Optional[_Script]:
        base = posixpath.dirname(self._key(near))
        target = posixpath.normpath(posixpath.join(base, spec.lower()))
        for candidate in (target, target + ".js", target + ".cjs", target + ".mjs", target + "/index.js"):
            if candidate in self._paths:
                return self.scripts[self._paths[candidate]]
        return None


def read(texts: Dict[str, str], mains: Optional[Set[str]] = None, complete: bool = True, why: str = "") -> Reading:
    """Every ``ipcMain`` handler in ``texts`` (the scripts of one app: name -> text) and what the
    message's data reaches. ``mains``: the file names (lower case) of the app's main scripts
    (``package.json``); ``complete``: every script of the app that is needed was given."""
    big = sorted(name for name, text in texts.items() if len(text) > MAX_SCRIPT and "ipcMain" in text)
    texts = {name: text for name, text in texts.items() if len(text) <= MAX_SCRIPT}
    app = _App(texts, mains)
    if big:
        complete, why = False, why or "a script with message handlers is larger than %d MB" % (MAX_SCRIPT >> 20)
    elif not mains:
        complete, why = False, why or "the app's main script is not known"
    elif app.missing:
        complete, why = False, why or app.missing
    out: List[Handler] = []
    for name in sorted(app.main):
        script = app.scripts[name]
        for m in _HANDLER.finditer(script.bare):
            if len(out) >= MAX_HANDLERS:
                return Reading(tuple(out), False, "more than %d message handlers" % MAX_HANDLERS)
            try:
                out.append(_handler(app, script, m))
            except RecursionError:
                out.append(Handler(script.name, script.line_of(m.start()), m.group(1), "*", (NOT_KNOWN,),
                                   "the reading stopped at its limit (calls inside each other)"))
    return Reading(tuple(out), complete, why)


def _handler(app: _App, script: _Script, m: "re.Match[str]") -> Handler:
    opener = m.end() - 1
    close = script.match.get(opener, -1)
    line = script.line_of(m.start())
    spans = list(_spans(script.bare, opener, close)) if close > 0 else []
    quoted = re.match(r"""\s*(["'`])([^"'`\n$]{1,200})\1\s*$""", script.code[spans[0][0]:spans[0][1]]) if spans else None
    channel = quoted.group(2) if quoted else "*"
    run = _Run(app)
    targets: List[_Function] = []
    if len(spans) >= 2:
        x, y = spans[1]
        written = run._written_in(script, x, y)
        name = script.bare[x:y].strip()
        if written:
            targets = written[:1]
        elif re.match(_ID + r"(?:\s*\.\s*%s)?\Z" % _ID, name):
            kind, found = run.resolve(script, _Call(x, re.sub(r"\s+", "", name), False, ()))
            targets = found if kind == "functions" else []
    if not targets:
        return Handler(script.name, line, m.group(1), channel, (NOT_KNOWN,), "its handler function is not found")
    for _ in range(MAX_ROUNDS):
        state = (len(run.fields), len(run.always))
        for target in targets:                                # the parameters after the event
            run.follow(target, frozenset(range(1, len(target.params) + 8)))
        if run.fields or run.always:
            for other in (app.scripts[name] for name in sorted(app.main)):   # what reads them
                for f in other.functions:
                    run.follow(f, frozenset())
                run.follow(other.whole, frozenset())
        if (len(run.fields), len(run.always)) == state:
            break
    _written_and_started(app, run)
    reach = [what for what in (PROCESS, CODE, SHELL, WRITE) if what in run.reach]
    if run.unknown:
        reach.append(NOT_KNOWN)
    why = "; ".join(["%s (%s)" % (what, run.reach[what]) for what in (PROCESS, CODE, SHELL, WRITE) if what in run.reach]
                    + ([run.unknown] if run.unknown else []))
    if run.writes and WRITE not in run.reach:            # (said, though it counts for nothing)
        writer, x, _y = run.writes[0]
        why = "; ".join(filter(None, [why, "writes a file that nothing starts (%s, line %d)"
                                      % (writer.name.replace("\\", "/").rsplit("/", 1)[-1].rsplit("!", 1)[-1],
                                         writer.line_of(x))]))
    return Handler(script.name, line, m.group(1), channel, tuple(reach), why)


def _written_and_started(app: _App, run: _Run) -> None:
    """A file written with the message's data (in its path or its content) counts when a start of
    the app - a program, the shell's open, a code load - names that file: a text or a name of the
    written path stands in the start's argument."""
    if not run.writes or WRITE in run.reach:
        return
    for script, x, y in run.writes:
        words = {w for w in _WORD.findall(script.bare[x:y]) if w not in _COMMON and w not in _KEYWORDS}
        texts = {t for t in re.findall(r"""["'`]([^"'`\n]{3,200})["'`]""", script.code[x:y])}
        for other in (app.scripts[name] for name in sorted(app.main)):
            for call in other.calls:
                last = call.callee.split(".")[-1]
                if last not in _PROCESS_NAMES and last not in _SHELL_NAMES and last not in ("exec", "dlopen", "require",
                                                                                              "import", "Worker"):
                    continue
                if not call.args:
                    continue
                a, b = call.args[0][0], call.args[-1][1]
                if last in _SHELL_NAMES and _HTTP.match(other.code, a):
                    continue
                said = {w for w in _WORD.findall(other.bare[a:b]) if w not in _COMMON and w not in _KEYWORDS}
                shown = set(re.findall(r"""["'`]([^"'`\n]{3,200})["'`]""", other.code[a:b]))
                if said & words or shown & texts:
                    run.found(WRITE, script, x)
                    return
