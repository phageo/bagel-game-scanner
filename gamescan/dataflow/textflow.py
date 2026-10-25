"""JavaScript, Ruby and PowerShell payload resolution without a full parser.

The standard library has no parser for these languages, so this works the
other way round from the Python resolver: it finds the calls that matter
(``eval``, ``child_process.exec``, ``system`` ...), reads the argument as an
expression, and traces every variable in it *backwards* to the assignment
that feeds it - evaluating string literals, concatenation and the usual
decoders (``atob``, ``String.fromCharCode``, ``unpack('m')``, ``[char]``) on
the way. Nothing is executed; what cannot be traced becomes a ‹hole›.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/textflow.py")

import bisect
import re
from typing import Any, Dict, List, Optional, Tuple

from ..rules import find_all, mask_comments, quoted_text, shared, text_places
from . import values as V
from .values import Budget, Clock, Ref, Resolved, Sym, hole, show

MAX_SOURCE = 4 * 1024 * 1024
# JavaScript: 32 MB (phageo, 2026-10-14) - the bundles of Electron apps are 7 to 18 MB, and a bundle
# was not read at all over 4 MB. Measured against cutting webpack / esbuild bundles into their
# module functions: this one reaches every kind of bundle; it costs time, and on such a file the
# reading mostly stops at its counted steps (with the limit note) - see docs/CHANGELOG.md.
JS_MAX_SOURCE = 32 * 1024 * 1024
MAX_BATCH_LINES = 50_000            # lines of a batch file whose variables are filled in
# calls whose arguments are read (phageo, 2026-10-15, forty-sixth message: 2000, was 600 - the
# large bundles of Electron apps have 900 to 1,100 such calls and were not read to their end)
_MAX_SITES = 2000
# ... since 2026-10-15 (phageo, forty-eighth message) in each module function of a bundle (webpack's
# numbered modules, esbuild's modules by path), and the code outside them counts as one more;
# and at most this many in the whole text (_Sites)
_MAX_FILE_SITES = 20_000
_STYLE = {"js": "c", "ruby": "ruby", "powershell": "powershell"}

_PREC = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "===": 6, "!==": 6,
         "<": 7, ">": 7, "<=": 7, ">=": 7, "<<": 8, ">>": 8, "+": 9, "-": 9,
         "*": 10, "/": 10, "%": 10}
_OPS = sorted(["===", "!==", "...", "=>", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "::",
               "?.", "+=", "-=", "++", "--"], key=len, reverse=True)
_IDENT = {
    "js": re.compile(r"[A-Za-z_$][\w$]*"),
    "ruby": re.compile(r"(?:@@?|\$)?[A-Za-z_]\w*[?!]?"),
    "powershell": re.compile(r"\$(?:\{[^}\n]{1,80}\}|[\w:]+)|[A-Za-z_][\w.\-]*(?::[/\\][^\s;|)(,'\"]*)?"),
}
_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|\d+\.\d+|\d+")
_JS_GLOBALS = frozenset("""eval Function atob unescape decodeURIComponent decodeURI String Buffer
require process window global globalThis nw fetch XMLHttpRequest setTimeout setInterval document
parseInt WebSocket EventSource Worker importScripts JSON Array Number Object Math module fs
navigator location console""".split())
_JS_SCOPES = ("window.", "global.", "globalThis.", "self.")
_KEYWORDS = frozenset("true false null nil undefined this self new typeof await void".split())
_HTTP_VERBS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"})
# names that run code or start a program, whatever object they are looked up on
_JS_RUNS = frozenset({"eval", "Function"})
_JS_RISKY = re.compile(
    r"(?:^|\.)(?:eval|Function|execScript|exec|execSync|spawn|spawnSync|execFile|execFileSync|fork"
    r"|require|importScripts|setTimeout|setInterval|setImmediate|openExternal|openItem|openPath"
    r"|dlopen|runInThisContext|runInNewContext|runInContext|constructor)$|child_process|^process\.binding")


# the names TextFlow._JS_CALL looks for (in the pattern's order)
_JS_CALL_NAMES = (
    "eval", "Function", "setTimeout", "setInterval", "exec", "execSync", "spawn", "spawnSync", "execFile",
    "execFileSync", "fork", "openExternal", "openItem", "openPath", "fetch", "importScripts", "open", "get",
    "request", "ajax", "post", "getScript", "WebSocket", "EventSource", "require", "unlinkSync", "unlink",
    "rmSync", "rm", "rmdirSync", "rmdir", "writeFileSync", "writeFile", "appendFileSync", "createWriteStream",
    "copyFileSync", "renameSync")


def _word_char(ch: str) -> bool:
    return ch.isalnum() or ch in "_$"                   # ([\w$] of a pattern over text)


def _js_calls(regex: "re.Pattern[str]", code: str):
    """The matches of ``TextFlow._JS_CALL`` in ``code``, as ``finditer`` gives them, in order
    (phageo, 2026-10-15: the flow readings' searches where a match can begin). A match is up to five
    ``name .`` parts and one of the called names before a bracket; it begins at the name, or at
    the beginning of one of those parts. So it is tried only there: at each place where a called
    name stands before ``(`` (a plain search, shared with the other readings of the text), and at
    the parts in front of it. The pattern begins with "not after a letter", which the search over
    the whole text tries at every character (most of this reading's time on a large bundle)."""
    if len(code) < 64 * 1024:
        yield from regex.finditer(code)
        return
    places = text_places(code)
    found = set()
    n = len(code)
    for name in dict.fromkeys(_JS_CALL_NAMES):
        if not places.has(frozenset({name.lower()})):
            continue
        at = code.find(name)
        while at != -1:
            j = at + len(name)
            while j < n and code[j].isspace():
                j += 1
            if j < n and code[j] == "(":
                found.add(at)
                _parts_before(code, at, 5, True, found)      # the "name ." parts in front of it
            at = code.find(name, at + 1)
    yield from _matched(regex, code, found)


def _id_start(code: str, end: int) -> int:
    """Where the name that ends at ``end`` begins (-1: no name there, or it does not begin
    with a letter, ``_`` or ``$``)."""
    k = end
    while k >= 0 and _word_char(code[k]):
        k -= 1
    k += 1
    if k > end or not (code[k].isascii() and (code[k].isalpha() or code[k] in "_$")):
        return -1
    return k


def _parts_before(code: str, at: int, most: int, spaced: bool, found: set) -> None:
    """Add the beginnings of up to ``most`` ``name .`` parts in front of ``at`` to ``found``
    (``spaced``: blanks may stand around the dot)."""
    k = at
    for _ in range(most):
        k -= 1
        while spaced and k >= 0 and code[k].isspace():
            k -= 1
        if k < 0 or code[k] != ".":
            return
        k -= 1
        while spaced and k >= 0 and code[k].isspace():
            k -= 1
        k = _id_start(code, k) if k >= 0 else -1
        if k < 0:
            return
        found.add(k)


def _matched(regex: "re.Pattern[str]", code: str, places: set):
    """The matches of ``regex`` at ``places``, in order and never inside one already made."""
    behind, match = 0, regex.match
    for place in sorted(places):
        if place < behind:
            continue
        m = match(code, place)
        if m is not None:
            yield m
            behind = m.end() if m.end() > place else place + 1


_COMPUTED_KEY = re.compile(r"\[(?=[^\]\n]{1,300}\]\s*\()")


def _js_computed(regex: "re.Pattern[str]", code: str):
    """The matches of ``TextFlow._JS_COMPUTED`` (``obj.name[...](``), as ``finditer`` gives
    them, tried only where one can begin: at the name in front of each ``[`` that is followed by
    ``...](`` (found fast: the pattern begins with the bracket), and at up to three ``name.``
    parts in front of that name."""
    if len(code) < 64 * 1024:
        yield from regex.finditer(code)
        return
    found = set()
    for m in _COMPUTED_KEY.finditer(code):
        k = m.start() - 1
        while k >= 0 and code[k].isspace():
            k -= 1
        k = _id_start(code, k) if k >= 0 else -1
        if k >= 0:
            found.add(k)
            _parts_before(code, k, 3, False, found)
    yield from _matched(regex, code, found)


# where a module function of a bundle begins (in the text with the strings' insides blanked):
# a member of an object written `625764(e, t, n) {` (webpack 5), `625764: function (e, t, n) {` /
# `625764: (e, t, n) => {` (webpack 4 and 5), or the same with a quoted name - esbuild's
# `"src/app.js"(exports, module) {` inside `__commonJS({` / `__esm({`, webpack's `"./src/a.js": ...`
_MODULE_HEAD = re.compile(
    r"""(?<=[{,])\s*(?:\d+|"[^"\n]*"|'[^'\n]*')\s*"""
    r"""(?::\s*(?:function\b\s*[\w$]*\s*\([\w$,\s]{0,80}\)|\([\w$,\s]{0,80}\)\s*=>)|\([\w$,\s]{0,80}\))\s*\{""")
_MAX_MODULES = 100_000


def module_spans(code: str) -> List[Tuple[int, int, int]]:
    """The module functions of a bundle, as (start, end, parent) - the body's brackets in
    ``code`` (comments blanked) and the index of the module it stands in (-1: none) -, in order.
    A module may hold a table of modules of its own (a bundle inside a bundle: ELE-01's app
    bundle has one of 2.8 MB with 1,742 modules in it); a call belongs to the innermost one. A
    text without any gives []. Found once per text and shared by its readings; nothing of it
    counts steps (one pass over the brackets)."""
    def find() -> List[Tuple[int, int, int]]:
        from .remote import _MASKS, _blank             # (remote imports this module)
        bare = shared("bare", code, lambda: _MASKS["c"].sub(_blank, code))
        heads = []
        for m in _MODULE_HEAD.finditer(bare):
            heads.append(m.end() - 1)                  # the "{" of the body
            if len(heads) >= _MAX_MODULES:
                break
        if not heads:
            return []
        wanted, spans, stack, i = set(heads), [], [], 0
        for m in re.finditer(r"[{}]", bare):
            if m.group(0) == "{":
                stack.append(m.start())
            elif stack:
                opener = stack.pop()
                if opener in wanted:
                    spans.append((opener, m.start()))
        spans.sort()
        out: List[Tuple[int, int, int]] = []
        around: List[int] = []                         # the modules the next one may stand in
        for start, end in spans:
            while around and out[around[-1]][1] < start:
                around.pop()
            out.append((start, end, around[-1] if around else -1))
            around.append(len(out) - 1)
        return out
    return shared("modules", code, find)


class _Sites:
    """Which calls of a text are looked at (phageo, 2026-10-15, forty-eighth message): at most
    ``_MAX_SITES`` in each module function of a bundle - the code outside them counts as one
    more - and ``_MAX_FILE_SITES`` in the whole text. A text that is no bundle is one module, as
    before. A call that is not looked at is said with the limit note."""

    def __init__(self, flow: "TextFlow") -> None:
        self.flow = flow
        self.spans = module_spans(flow.code) if flow.dialect == "js" and flow.layer == 0 else []
        self.starts = [s for s, _, _ in self.spans]
        self.counts: Dict[int, int] = {}
        self.total = 0

    def _unit(self, pos: int) -> int:
        """The innermost module around ``pos`` (-1: none)."""
        i = bisect.bisect_right(self.starts, pos) - 1
        while i >= 0 and pos >= self.spans[i][1]:
            i = self.spans[i][2]
        return i

    def take(self, pos: int) -> Optional[bool]:
        """True: look at the call at ``pos``; False: not (its module has had its calls); None:
        look at no more calls of this text."""
        self.total += 1
        if not self.starts:
            if self.total > _MAX_SITES:
                self.flow._too_many_sites()
                return None
            return True
        if self.total > _MAX_FILE_SITES:
            self.flow._too_many_sites(_MAX_FILE_SITES)
            return None
        unit = self._unit(pos)
        count = self.counts[unit] = self.counts.get(unit, 0) + 1
        if count > _MAX_SITES:
            self.flow._too_many_sites(module=True)
            return False
        return True


class RList(list):
    """A list that was reversed on the way (the classic string-reversal trick)."""


class _Parse:
    """What a reading of a text finds out about the text alone - where its braces are and how
    deep, where its lines begin, where each name is given a value and declared as a
    parameter. Filled as the readings ask for it; shared by every reading of the same text."""

    __slots__ = ("brace_pos", "brace_depth", "brace_end", "lines", "assigned", "unpacked", "params", "defs")

    def __init__(self, code: str, dialect: str) -> None:
        self.brace_pos: List[int] = []
        self.brace_depth: List[int] = []
        self.brace_end: Optional[List[int]] = None       # where each brace's block ends (TextFlow._visible)
        self.lines: Optional[List[int]] = None
        self.assigned: Optional[Dict[str, List[Tuple[int, str, int]]]] = None
        self.unpacked: Optional[Dict[str, List[Tuple[int, str, int]]]] = None
        self.params: Optional[Dict[str, List[int]]] = None
        self.defs: Dict[str, List[Tuple[int, str, int]]] = {}
        if dialect != "ruby":
            depth = 0
            for m in re.finditer(r"[{}]", code):
                depth = depth + 1 if m.group(0) == "{" else max(0, depth - 1)
                self.brace_pos.append(m.start())
                self.brace_depth.append(depth)


class TextFlow:
    def __init__(self, text: str, dialect: str, clock: Clock, layer: int = 0,
                 line: Optional[int] = None, hidden: Optional[set] = None) -> None:
        self.dialect, self.clock, self.layer, self.fixed_line = dialect, clock, layer, line
        self.code = mask_comments(text, _STYLE[dialect])
        # as written, same positions (Ruby's %x{...}: a "#" inside it is not a comment)
        self.text = text if len(text) == len(self.code) else self.code
        self.hits: List[Resolved] = []
        self.payloads: List[Tuple[int, str, str]] = []
        self.hidden: set = set() if hidden is None else hidden
        self.seen: set = set()
        self.opaque = 0
        # (line, command) of command lines written out in full - nothing to resolve, so no
        # finding of their own; kept for the shell download-and-execute chain only
        self.started: List[Tuple[int, str]] = []
        self._memo: Dict[int, Any] = {}
        self._active: set = set()
        # what depends on the text alone is read once for every reading of the same text
        # (rules.shared; phageo, 2026-10-14, forty-second message)
        self._parse = parse = shared("text " + dialect, self.code, lambda: _Parse(self.code, dialect))
        # (JavaScript: the places a name is given a value are found without counting steps - for
        # the other languages finding them counts, so each reading finds them itself)
        self._defs: Dict[str, List[Tuple[int, str, int]]] = parse.defs if dialect == "js" else {}
        self._params: Optional[Dict[str, List[int]]] = parse.params
        self._unpacked: Optional[Dict[str, List[Tuple[int, str, int]]]] = parse.unpacked
        self._assigned: Optional[Dict[str, List[Tuple[int, str, int]]]] = parse.assigned
        self._brace_pos: List[int] = parse.brace_pos
        self._brace_depth: List[int] = parse.brace_depth
        self._lines: Optional[List[int]] = parse.lines
        self._trace: List[str] = []
        self._paren = 0

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
        if isinstance(value, list):
            return isinstance(value, RList) or any(self._is_hidden(v) for v in value[:64])
        return False

    def _mark(self, result: Any, *sources: Any) -> Any:
        if any(self._is_hidden(s) for s in sources):
            self._hide(result)
        return result

    # -- positions -------------------------------------------------------------------
    def line_of(self, pos: int) -> int:
        if self.fixed_line:
            return self.fixed_line
        if self._lines is None:
            self._lines = self._parse.lines = [m.start() for m in re.finditer(r"\n", self.code)]
        return bisect.bisect_left(self._lines, pos) + 1

    def _depth_at(self, pos: int) -> int:
        i = bisect.bisect_left(self._brace_pos, pos)
        return self._brace_depth[i - 1] if i else 0

    def _visible(self, definition: int, use: int) -> bool:
        """Is something defined at ``definition`` still in scope at ``use``?"""
        if self.dialect == "ruby":
            return True
        a, b = bisect.bisect_left(self._brace_pos, definition), bisect.bisect_left(self._brace_pos, use)
        if b <= a:
            return True
        if b - a > 20000:
            return self._depth_at(definition) == 0
        # in scope while no brace between the two goes below the depth at ``definition``: the
        # first brace that does is found once per brace of the text (_block_ends) - the same
        # answer as the lowest depth of the stretch, which was most of the time of this reading
        # in a bundle read to its end (phageo, 2026-10-15, forty-eighth message)
        ends = self._parse.brace_end
        if ends is None:
            ends = self._block_ends()
        return b <= ends[a]

    def _block_ends(self) -> List[int]:
        """For each brace ``i``: the first brace at or after it whose depth is below the depth
        before it (the end of the block ``i`` stands in; ``len`` if none). The depth goes up or
        down by one at most from brace to brace, so that is the first brace one lower."""
        depths = self._brace_depth
        n = len(depths)
        ends = [n] * n
        nearest: Dict[int, int] = {}
        for i in range(n - 1, -1, -1):
            nearest[depths[i]] = i
            ends[i] = nearest.get((depths[i - 1] if i else 0) - 1, n)
        self._parse.brace_end = ends
        return ends

    # -- tokens ------------------------------------------------------------------------
    def _skip(self, pos: int, newlines: Optional[bool] = None) -> int:
        code, n = self.code, len(self.code)
        across = (self.dialect == "js" or self._paren > 0) if newlines is None else newlines
        while pos < n:
            ch = code[pos]
            if ch in " \t\r" or (ch == "\n" and across):
                pos += 1
            elif ch == "`" and self.dialect == "powershell" and code[pos + 1:pos + 2] == "\n":
                pos += 2                              # PowerShell line continuation
            else:
                break
        return pos

    def tok(self, pos: int) -> Tuple[str, Any, int]:
        """``(kind, value, end)``; kinds: str, num, id, op, nl, end."""
        pos = self._skip(pos)
        code = self.code
        if pos >= len(code):
            return "end", "", pos
        ch = code[pos]
        if ch == "\n":
            return "nl", "\n", pos + 1
        if ch in "'\"" or (ch == "`" and self.dialect == "js"):
            value, end = self._string(pos)
            return "str", value, end
        if ch.isdigit():
            m = _NUMBER.match(code, pos)
            text = m.group(0)
            return "num", (int(text, 16) if text[:2].lower() == "0x" else
                           float(text) if "." in text else int(text)), m.end()
        m = _IDENT[self.dialect].match(code, pos)
        if m:
            return "id", m.group(0), m.end()
        for op in _OPS:
            if code.startswith(op, pos):
                return "op", op, pos + len(op)
        return "op", ch, pos + 1

    def _string(self, pos: int) -> Tuple[Any, int]:
        code, quote, n = self.code, self.code[pos], len(self.code)
        raw = (quote == "'" and self.dialect in ("ruby", "powershell"))
        interpolate = (quote == "`" and self.dialect in ("js", "ruby")) or (
            quote == '"' and self.dialect in ("ruby", "powershell"))
        escape = "`" if self.dialect == "powershell" else "\\"
        parts: List[Any] = []
        buf: List[str] = []
        escapes = 0
        i = pos + 1
        while i < n:
            self.clock.tick(0 if i & 63 else 1)
            ch = code[i]
            if ch == quote:
                if raw and self.dialect == "powershell" and code[i + 1:i + 2] == quote:
                    buf.append(quote)
                    i += 2
                    continue
                i += 1
                break
            if ch == "\n" and quote != "`" and self.dialect == "js":
                break
            if ch == escape and not (raw and self.dialect == "powershell") and i + 1 < n:
                nxt = code[i + 1]
                if raw:                                   # Ruby '..': only \\ and \'
                    buf.append(nxt if nxt in "\\'" else ch + nxt)
                    i += 2
                    continue
                m = re.compile(r"x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})").match(code, i + 1)
                if m and escape == "\\":
                    try:
                        buf.append(chr(int(next(g for g in m.groups() if g), 16)))
                        escapes += 1
                    except (ValueError, OverflowError):
                        pass
                    i = m.end()
                    continue
                buf.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0", "e": "\x1b"}.get(nxt, nxt))
                i += 2
                continue
            if interpolate:
                opener = {"js": "${", "ruby": "#{", "powershell": "$("}[self.dialect]
                if code.startswith(opener, i):
                    close = ")" if self.dialect == "powershell" else "}"
                    saved, self._paren = self._paren, self._paren + 1
                    try:
                        value, end = self.ternary(i + 2)
                    finally:
                        self._paren = saved
                    end = self._skip(end, True)
                    if code[end:end + 1] != close:
                        value, end = hole("expr"), self._closing(i + 1, opener[1], close)
                    parts.append("".join(buf))
                    parts.append(value)
                    buf = []
                    i = end + 1
                    continue
                if self.dialect == "powershell" and ch == "$":
                    m = re.compile(r"\$(?:\{([^}\n]{1,80})\}|((?:env:)?\w+))").match(code, i)
                    if m:
                        parts.append("".join(buf))
                        parts.append(self.lookup("$" + (m.group(1) or m.group(2)), pos))
                        buf = []
                        i = m.end()
                        continue
            buf.append(ch)
            i += 1
        text = "".join(buf)
        if parts:
            pieces = parts + [text]
            out = "".join(show(p) for p in pieces)
            value: Any = Sym(out) if any(isinstance(p, (Sym, Ref)) for p in pieces) else out
            return self._mark(value, *pieces), i
        return (self._hide(text) if escapes >= 4 else text), i

    def _closing(self, pos: int, opener: str, closer: str) -> int:
        """Position of the bracket that closes the one at ``pos``."""
        depth, n, code = 0, len(self.code), self.code
        i = pos
        while i < n and i - pos < 200000:
            ch = code[i]
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return i
            elif ch in "'\"":
                j = code.find(ch, i + 1)
                i = j if j != -1 else i
            i += 1
        return n

    def _recover(self, pos: int) -> int:
        """Skip to the end of an argument the parser could not read."""
        depth, n, code = 0, len(self.code), self.code
        i = pos
        while i < n and i - pos < 200000:
            ch = code[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    return i
                depth -= 1
            elif ch == "," and depth == 0:
                return i
            elif ch in ";\n" and depth == 0 and (ch == ";" or self._paren == 0):
                return i
            elif ch in "'\"`":
                kind, _value, end = self.tok(i) if ch != "`" or self.dialect == "js" else ("op", "", i + 1)
                i = max(end, i + 1) - 1
            i += 1
        return n

    # -- expressions -------------------------------------------------------------------
    def ternary(self, pos: int) -> Tuple[Any, int]:
        value, pos = self.expr(pos, 0)
        kind, op, end = self.tok(pos)
        if kind == "op" and op == "?" and self.dialect == "js":
            first, pos = self.ternary(end)
            kind, op, end = self.tok(pos)
            if kind == "op" and op == ":":
                second, pos = self.ternary(end)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    return (first if value else second), pos
                return first, pos
        return value, pos

    def expr(self, pos: int, floor: int) -> Tuple[Any, int]:
        self.clock.tick(4)
        left, pos = self.unary(pos)
        while True:
            kind, op, end = self.tok(pos)
            if kind != "op" or op not in _PREC or _PREC[op] < floor:
                break
            if self.dialect == "powershell" and op == "-":
                break                                 # a parameter (-Uri), not arithmetic
            right, pos = self.expr(self._skip(end, True), _PREC[op] + 1)
            left = self.binary(op, left, right)
        return left, pos

    def binary(self, op: str, a: Any, b: Any) -> Any:
        number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
        if op == "+" or (op == "<<" and isinstance(a, (str, Sym))):
            if number(a) and number(b):
                return a + b
            if isinstance(a, list) and isinstance(b, list):
                return a + b
            if number(a) and isinstance(b, (str, Sym)):
                a = show(a)
            if number(b) and isinstance(a, (str, Sym)):
                b = show(b)
            joined = V.concat(a, b)
            if joined is not None:
                return self._mark(joined, a, b)
        elif op == "||":
            return a if isinstance(a, (str, Sym)) and show(a) else b if not isinstance(a, str) else a
        elif isinstance(a, int) and isinstance(b, int):
            try:
                if op == "-":
                    return a - b
                if op == "*" and abs(a) < 1 << 64 and abs(b) < 1 << 64:
                    return a * b
                if op == "/":
                    return a // b if a % b == 0 else a / b
                if op == "%":
                    return a % b
                if op == "^":
                    return a ^ b
                if op == "&":
                    return a & b
                if op == "|":
                    return a | b
                if op == "<<" and 0 <= b <= 64:
                    return a << b
                if op == ">>" and 0 <= b <= 4096:
                    return a >> b
            except ZeroDivisionError:
                pass
        elif op == "*" and isinstance(a, str) and isinstance(b, int) and self.dialect == "ruby":
            if len(a) * max(b, 0) > V.MAX_TEXT:
                raise Budget()
            return a * b
        return hole("expr")

    def unary(self, pos: int) -> Tuple[Any, int]:
        kind, value, end = self.tok(pos)
        if kind == "op" and value in ("!", "-", "~", "+"):
            if value == "-" and self.dialect == "powershell":
                m = re.compile(r"-join\b", re.I).match(self.code, self._skip(pos))
                if m:
                    inner, after = self.unary(m.end())
                    if isinstance(inner, list) and all(isinstance(i, (str, Sym)) for i in inner):
                        return self._join(inner, ""), after
                    return hole("joined"), after
            inner, after = self.unary(end)
            if value == "-" and isinstance(inner, (int, float)):
                return -inner, after
            if value == "+":
                return inner, after
            return hole("expr"), after
        if kind == "id" and value in ("new", "await", "typeof", "void") and self.dialect == "js":
            inner, after = self.unary(end)
            return (inner if value in ("new", "await") else hole("expr")), after
        if kind == "op" and value == "[" and self.dialect == "powershell":
            close = self.code.find("]", end)
            name = self.code[end:close].strip() if close != -1 else ""
            if re.fullmatch(r"[\w.]+", name):
                after = self._skip(close + 1)
                if self.code.startswith("::", after):
                    return self.postfix(Ref(name.split(".")[-1]), after)
                inner, after = self.unary(close + 1)          # a cast
                if name.lower() == "char" and isinstance(inner, int) and 0 <= inner < 0x110000:
                    return self._hide(chr(inner)), after
                if name.lower() == "char[]" or name.lower() == "string":
                    return inner, after
                return inner if isinstance(inner, (str, Sym)) else hole("cast"), after
        value, pos = self.primary(pos)
        return self.postfix(value, pos)

    def primary(self, pos: int) -> Tuple[Any, int]:
        kind, value, end = self.tok(pos)
        if kind in ("str", "num"):
            return value, end
        if kind == "id":
            if value == "function" and self.dialect == "js":
                return hole("function"), self._after_function(end)
            if value in _KEYWORDS:
                return hole(value), end
            if self.dialect == "ruby" and self.code[end:end + 1] == ":" and \
                    self.code[end:end + 2] != "::":
                return hole(value), end               # a keyword argument label
            if self.dialect == "powershell" and not value.startswith("$"):
                return value, end                     # a bare word is a string
            start = self._skip(pos)
            return self.lookup(value, start), end
        if kind == "op" and value == "(":
            self._paren += 1
            try:
                inner, after = self.ternary(end)
                items = [inner]
                while self.tok(after)[1] == "," and self.dialect == "powershell":
                    inner, after = self.ternary(self.tok(after)[2])
                    items.append(inner)
                closing = self.tok(after)
            finally:
                self._paren -= 1
            if closing[0] == "op" and closing[1] == ")":
                return (items[0] if len(items) == 1 else items), closing[2]
            return hole("expr"), self._closing(self._skip(pos), "(", ")") + 1
        if kind == "op" and value == "[":
            items, after = self.sequence(end, "]")
            return items, after
        if kind == "op" and value == "@" and self.dialect == "powershell" and \
                self.code[end:end + 1] == "(":
            items, after = self.sequence(end + 1, ")")
            return items, after
        if kind == "op" and value == "{":
            return hole("object"), self._closing(self._skip(pos), "{", "}") + 1
        if kind == "op" and value == ":" and self.dialect == "ruby":
            name = self.tok(end)
            return (name[1] if name[0] == "id" else hole("symbol")), name[2]
        return hole("expr"), pos                      # nothing readable here

    def _after_function(self, pos: int) -> int:
        brace = self.code.find("{", pos)
        return self._closing(brace, "{", "}") + 1 if brace != -1 else pos

    def sequence(self, pos: int, closer: str) -> Tuple[List[Any], int]:
        """Comma-separated expressions up to ``closer`` (position after it)."""
        items: List[Any] = []
        self._paren += 1
        try:
            while len(items) < 4096:
                kind, value, end = self.tok(pos)
                if kind == "end":
                    return items, pos
                if kind == "op" and value == closer:
                    return items, end
                if kind == "op" and value == "...":
                    pos = end
                    continue
                item, after = self.ternary(pos)
                kind, value, end = self.tok(after)
                if not (kind == "op" and value in (",", closer)):
                    item, after = hole("expr"), self._recover(after)
                    kind, value, end = self.tok(after)
                items.append(item)
                if kind == "op" and value == ",":
                    pos = end
                elif kind == "op" and value == closer:
                    return items, end
                else:
                    return items, after
            return items, pos
        finally:
            self._paren -= 1

    def postfix(self, value: Any, pos: int) -> Tuple[Any, int]:
        for _ in range(64):
            kind, op, end = self.tok(pos)
            if kind == "op" and op in (".", "::", "?.") and not (
                    self.dialect == "ruby" and op == "." and self.code[end:end + 1] == "."):
                name = self.tok(end)
                if name[0] != "id":
                    break
                after = name[2]
                if self.code[after:after + 1] == "(":
                    args, after = self.sequence(after + 1, ")")
                    value = self.method(value, name[1], args, pos)
                else:
                    args = self._bare_args(name[1], after)
                    if args is not None:
                        value, after = self.method(value, name[1], args[0], pos), args[1]
                    else:
                        value = self.member(value, name[1])
                pos = after
            elif kind == "op" and op == "(" and self.code[self._skip(pos, False):][:1] == "(":
                args, pos = self.sequence(end, ")")
                value = self.apply(value, args, end)
            elif kind == "op" and op == "[" and self.code[self._skip(pos, False):][:1] == "[":
                self._paren += 1
                try:
                    index, after = self.ternary(end)
                finally:
                    self._paren -= 1
                closing = self.tok(after)
                if not (closing[0] == "op" and closing[1] == "]"):
                    return hole("item"), self._closing(self._skip(pos), "[", "]") + 1
                value, pos = self.index(value, index), closing[2]
            else:
                break
        return value, pos

    _RUBY_BARE = frozenset({"decode64", "strict_decode64", "urlsafe_decode64", "inflate"})

    def _bare_args(self, name: str, pos: int):
        """Ruby lets a call drop its brackets: ``Base64.decode64 text``."""
        if self.dialect != "ruby" or name not in self._RUBY_BARE:
            return None
        start = self._skip(pos, False)
        if start == pos or self.code[start:start + 1] in "\n;)=":
            return None
        value, after = self.ternary(start)
        return [value], after

    # -- variables: backward tracing ------------------------------------------------
    _JS_NAME = re.compile(r"[A-Za-z_$][\w$]*\Z")
    _JS_ASSIGNED = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(\+?=)(?![=>])")

    def _definitions(self, name: str) -> List[Tuple[int, str, int]]:
        found = self._defs.get(name)
        if found is not None:
            return found
        if self.dialect == "js" and self._JS_NAME.match(name):
            # one pass over the file for every name (the same places a search for this one
            # name finds: a name is followed by "=" or "+=" only where it ends). Before
            # 2026-10-12 the file was read once per name, which the steps did not count: a
            # large script took seconds, and only the clock stopped it.
            if self._assigned is None:
                assigned: Dict[str, List[Tuple[int, str, int]]] = {}
                for m in self._JS_ASSIGNED.finditer(self.code):
                    places = assigned.setdefault(m.group(1), [])
                    if len(places) < 400:
                        places.append((m.start(), "=" if m.group(2) == "=" else "+", m.end()))
                self._assigned = self._parse.assigned = assigned
            found = list(self._assigned.get(name, ()))
        else:
            # reading the whole file for one name is the expensive part here, so the steps
            # count it (one per 512 characters): the count, not the clock, is the limit
            self.clock.tick((len(self.code) >> 9) + 1)
            quoted = re.escape(name)
            if self.dialect == "js":
                rx = re.compile(r"(?<![\w$.])%s\s*(\+?=)(?![=>])" % quoted)
            elif self.dialect == "ruby":
                rx = re.compile(r"(?:(?<![\w@$.:])%s[ \t]*(\+?=)(?![=~>])|(?m:^[ \t]*)%s[ \t]*(<<)(?!<))"
                                % (quoted, quoted))
            else:
                rx = re.compile(r"%s\s*(\+?=)(?!=)" % quoted, re.I)
            found = []
            for m in rx.finditer(self.code):
                if len(found) >= 400:
                    break
                found.append((m.start(), "=" if (m.group(1) or "") == "=" else "+", m.end()))
        if self.dialect == "js":                      # const {exec} = require('child_process')
            if self._unpacked is None:                # one pass over the file, for every name
                unpacked: Dict[str, List[Tuple[int, str, int]]] = {}
                for m in re.finditer(r"\{([^{}=;]{1,200})\}\s*=(?!=)", self.code):
                    for inner in re.findall(r"[A-Za-z_$][\w$]*", m.group(1)):
                        unpacked.setdefault(inner, []).append((m.start(), "." + inner, m.end()))
                self._unpacked = self._parse.unpacked = unpacked
            if name in self._unpacked:
                found = sorted(found + self._unpacked[name])
        self._defs[name] = found
        return found

    def _parameters(self) -> Dict[str, List[int]]:
        """Where each name is declared as a parameter (positions, ascending)."""
        if self._params is None:
            if self.dialect == "js":
                rx = re.compile(r"function\b[^(){};=]{0,80}\(([^()]{0,300})\)|\(([^()]{0,300})\)\s*=>"
                                r"|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>|catch\s*\(\s*([\w$]+)\s*\)"
                                r"|(?:var|let|const)\s+([\w$]+)\s+(?:of|in)\b")
            elif self.dialect == "ruby":
                rx = re.compile(r"\bdef\s+[\w.?!=]+[ \t]*\(?([^)\n]{0,200})\)?|\|([^|\n]{1,80})\|")
            else:
                rx = re.compile(r"\bparam\s*\(([^)]{0,400})\)|\bfunction\s+[\w-]+\s*\(([^)]{0,300})\)"
                                r"|\bforeach\s*\(\s*(\$\w+)\s+in\b", re.I)
            params: Dict[str, List[int]] = {}
            for m in rx.finditer(self.code):
                found = re.findall(r"[@$]?[A-Za-z_$][\w$]*", next(g for g in m.groups() if g is not None))
                for name in set(n.lower() if self.dialect == "powershell" else n for n in found):
                    params.setdefault(name, []).append(m.end())
            self._params = self._parse.params = params
        return self._params

    def lookup(self, name: str, pos: int) -> Any:
        self.clock.tick(8)
        if self.dialect == "powershell":
            lowered = name.lower()
            if lowered.startswith("$env:"):
                return Sym("%" + name[5:].upper() + "%")
            if lowered in ("$true", "$false", "$null", "$_", "$args", "$psscriptroot", "$pwd"):
                return hole(name[1:])
        definitions = self._definitions(name)
        chosen = None
        for d in reversed(definitions[:bisect.bisect_left(definitions, (pos, "", 0))]):
            if d[1] != "+" and self._visible(d[0], pos):
                chosen = d
                break
        key = name.lower() if self.dialect == "powershell" else name
        param = -1
        places = self._parameters().get(key, ())
        for p in reversed(places[:bisect.bisect_right(places, pos)]):
            if self.dialect == "ruby":
                param = p
                break
            # the name is a parameter here if ``pos`` lies inside that function's body
            brace = self.code.find("{", p, p + 200)
            if (brace != -1 and brace < pos and self._visible(brace + 1, pos)) or (
                    brace == -1 and pos - p < 300 and ";" not in self.code[p:pos]):
                param = p
                break
        if chosen is None and param == -1:
            chosen = next((d for d in definitions if d[1] != "+" and (
                self.dialect == "ruby" or self._depth_at(d[0]) == 0)), None)
            if chosen is None:
                return self._global(name)
        if chosen is None or param > chosen[0]:
            return hole(name.lstrip("$@"))
        value = self._value_at(chosen, name)
        appended = 0
        for d in definitions:
            if d[1] == "+" and chosen[0] < d[0] < pos and self._visible(d[0], pos) and appended < 300:
                appended += 1
                extra = self._value_at(d, name)
                joined = self.binary("+", value, extra)
                value = joined
        step = "%s <- line %d" % (name, self.line_of(chosen[0]))
        if self.layer == 0 and step not in self._trace and len(self._trace) < 5:
            self._trace.append(step)
        return value

    def _value_at(self, definition: Tuple[int, str, int], name: str) -> Any:
        start = definition[2]
        if start in self._memo:
            return self._memo[start]
        if start in self._active or len(self._active) > 24:
            return hole(name.lstrip("$@"))
        self._active.add(start)
        saved, self._paren = self._paren, 0
        try:
            value, _ = self.ternary(start)
            if definition[1].startswith("."):
                value = self.member(value, definition[1][1:])
        finally:
            self._paren = saved
            self._active.discard(start)
        self._memo[start] = value
        return value

    def _global(self, name: str) -> Any:
        if self.dialect == "js" and name in _JS_GLOBALS:
            return Ref(name)
        if self.dialect == "ruby" and name[:1].isupper():
            return Ref(name)
        return hole(name.lstrip("$@"))

    # -- members, methods and known functions -----------------------------------------
    @staticmethod
    def _canon(name: str) -> str:
        name = name.replace("()", "")
        changed = True
        while changed:
            changed = False
            for prefix in _JS_SCOPES:
                if name.startswith(prefix):
                    name, changed = name[len(prefix):], True
        return name

    def member(self, obj: Any, name: str) -> Any:
        if isinstance(obj, Ref):
            full = self._canon(obj.name + "." + name)
            if full.startswith("process.env."):
                return Sym("%" + name + "%")
            return Ref(full, obj.dynamic)
        if name == "length" and isinstance(obj, (str, list)):
            return len(obj)
        return self.method(obj, name, [], 0)

    def index(self, obj: Any, index: Any) -> Any:
        if isinstance(obj, Ref):
            name = self._canon(obj.name)
            if isinstance(index, str):
                if name in ("ENV", "process.env"):
                    return Sym("%" + index + "%")
                return Ref(name + "." + index, True)          # obj['ex' + 'ec']
            return hole(name + "[]")
        try:
            if isinstance(obj, (str, list)) and isinstance(index, int):
                return self._mark(obj[index], obj)
            if isinstance(obj, list) and isinstance(index, list) and self.dialect == "powershell":
                return [obj[i] for i in index if isinstance(i, int)]
        except IndexError:
            pass
        return hole("item")

    def _join(self, items: List[Any], sep: Any) -> Any:
        if not isinstance(sep, str) or not all(isinstance(i, (str, Sym, int)) for i in items):
            return hole("joined")
        if sum(len(show(i)) for i in items) + len(sep) * len(items) > V.MAX_TEXT:
            raise Budget()
        text = sep.join(show(i) for i in items)
        value = Sym(text) if any(isinstance(i, Sym) for i in items) else text
        return self._hide(value) if isinstance(items, RList) else self._mark(value, *items[:256])

    def apply(self, func: Any, args: List[Any], pos: int) -> Any:
        """Call of a plain name: ``atob(x)``, ``require('fs')``, ``URI(x)``."""
        if isinstance(func, Ref):
            return self.known(self._canon(func.name), func, args, pos)
        return hole("call")

    def known(self, name: str, ref: Ref, args: List[Any], pos: int) -> Any:
        first = args[0] if args else None
        low = name.lower()
        try:
            if self.dialect == "js":
                if name.split(".")[-1] == "require" and isinstance(first, str):
                    return Ref(first[5:] if first.startswith("node:") else first,
                               not self._literal_at(pos))
                if name == "atob" and isinstance(first, str):
                    return self._hide(V.b64(first).decode("latin-1"))
                if name == "unescape" and isinstance(first, str):
                    out = V.js_unescape(first)
                    return self._hide(out) if out != first else out
                if name in ("decodeURIComponent", "decodeURI") and isinstance(first, str):
                    out = V.url_unquote(first)
                    return self._hide(out) if out != first else out
                if name in ("String.fromCharCode", "String.fromCodePoint"):
                    if args and all(isinstance(a, int) and 0 <= a < 0x110000 for a in args):
                        return self._hide("".join(chr(a) for a in args))
                    return hole("chars")
                if name == "parseInt" and isinstance(first, str) and len(first) <= 80:
                    base = args[1] if len(args) > 1 and isinstance(args[1], int) else 10
                    return int(first, base)
                if name == "String" and isinstance(first, (str, Sym, int)):
                    return first if not isinstance(first, int) else str(first)
                if name == "Buffer.from" and isinstance(first, str):
                    codec = args[1].lower() if len(args) > 1 and isinstance(args[1], str) else "utf8"
                    if codec == "base64":
                        return self._hide(V.b64(first))
                    if codec == "hex":
                        return self._hide(V.unhex(first))
                    return first.encode("utf-8", "replace")
            elif self.dialect == "ruby":
                tail = name.split(".")[-1]
                if tail in ("decode64", "strict_decode64", "urlsafe_decode64") and isinstance(first, str):
                    return self._hide(V.text_of(V.b_decode(
                        "urlsafe" if tail.startswith("urlsafe") else "b64", first)))
                if name in ("Zlib.Inflate.inflate", "Zlib.inflate") and isinstance(first, (str, bytes)):
                    return self._hide(V.text_of(V.decompress("zlib", first)))
                if name in ("URI", "URI.parse", "URI.join", "String", "Kernel.String") and \
                        isinstance(first, (str, Sym)):
                    return first
                if name == "File.join" and args and all(isinstance(a, (str, Sym)) for a in args):
                    text = "/".join(show(a) for a in args)
                    return Sym(text) if any(isinstance(a, Sym) for a in args) else text
            else:
                if low.endswith(_IND[0]) and isinstance(first, str):
                    return self._hide(V.b64(first))
                if low.endswith("getstring") and isinstance(first, bytes):
                    codec = "utf-16-le" if ".unicode." in "." + low else "utf-8"
                    return self._hide(first.decode(codec, "replace"))
        except (ValueError, TypeError, OverflowError):
            return hole(name + "()")
        return Ref(ref.name + "()", ref.dynamic)

    def method(self, obj: Any, name: str, args: List[Any], pos: int) -> Any:
        if isinstance(obj, Ref):
            return self.known(self._canon(obj.name + "." + name), Ref(obj.name + "." + name, obj.dynamic),
                              args, pos)
        first = args[0] if args else None
        low = name.lower() if self.dialect == "powershell" else name
        try:
            if isinstance(obj, Sym):
                if low in ("trim", "toString", "toLowerCase", "toUpperCase", "strip", "chomp", "to_s",
                           "downcase", "upcase", "dup", "freeze", "tolower", "toupper", "tostring",
                           "force_encoding", "encode"):
                    return obj
                return hole(V.known_part(obj.text) and "text" or obj.text[1:-1] + "." + name)
            if isinstance(obj, bytes):
                if name in ("toString", "to_s") or low == "tostring":
                    codec = first.lower() if isinstance(first, str) else "utf8"
                    if codec in ("utf8", "utf-8", "ascii", "latin1", "binary", "utf16le", "ucs2"):
                        return self._mark(obj.decode(
                            "utf-16-le" if codec in ("utf16le", "ucs2") else
                            "latin-1" if codec in ("latin1", "binary") else "utf-8", "replace"), obj)
                return hole("bytes")
            if isinstance(obj, int) and not isinstance(obj, bool):
                if name == "chr" and 0 <= obj < 0x110000:
                    return self._hide(chr(obj))
                if name in ("toString", "to_s"):
                    return str(obj)
                return hole("number")
            if isinstance(obj, str):
                if low in ("split",):
                    if first == "" or (first is None and self.dialect == "js" and args):
                        return list(obj)
                    if isinstance(first, str):
                        return obj.split(first)
                    if first is None:
                        return obj.split() if self.dialect == "ruby" else [obj]
                if name in ("chars", "each_char"):
                    return list(obj)
                if name == "bytes":
                    return list(obj.encode("latin-1", "replace"))
                if name == "reverse":
                    return self._hide(obj[::-1])
                if low in ("trim", "strip", "chomp"):
                    return self._mark(obj.strip(), obj)
                if low in ("tolowercase", "downcase", "tolower") or name == "toLowerCase":
                    return self._mark(obj.lower(), obj)
                if low in ("touppercase", "upcase", "toupper") or name == "toUpperCase":
                    return self._mark(obj.upper(), obj)
                if name in ("toString", "to_s", "to_str", "dup", "freeze", "force_encoding", "encode",
                            "valueOf") or low == "tostring":
                    return obj
                if name == "concat" and all(isinstance(a, (str, Sym)) for a in args):
                    out: Any = obj
                    for a in args:
                        out = self.binary("+", out, a)
                    return out
                if low in ("replace", "replaceall", "gsub", "sub") and len(args) == 2 and \
                        all(isinstance(a, str) for a in args):
                    if len(obj) * (len(args[1]) + 1) > 4 * V.MAX_TEXT:
                        raise Budget()
                    once = name in ("replace", "sub") and self.dialect != "powershell"
                    return self._mark(obj.replace(args[0], args[1], 1 if once else -1), obj, *args)
                if name == "delete" and isinstance(first, str) and self.dialect == "ruby":
                    return self._mark("".join(c for c in obj if c not in first), obj)
                if name == "tr" and len(args) == 2 and all(isinstance(a, str) for a in args):
                    return self._hide(_tr(obj, args[0], args[1]))
                if name == "charAt" and isinstance(first, int):
                    return obj[first:first + 1]
                if name == "charCodeAt":
                    return ord(obj[first if isinstance(first, int) else 0])
                if name == "ord":
                    return ord(obj[0])
                if name in ("hex",) and self.dialect == "ruby":
                    return int(obj, 16)
                if name == "to_i":
                    return int(obj, args[0] if args and isinstance(args[0], int) else 10)
                if name in ("substr", "substring", "slice") or low == "substring":
                    a = first if isinstance(first, int) else 0
                    b = args[1] if len(args) > 1 and isinstance(args[1], int) else None
                    if name == "substr" or low == "substring" and self.dialect == "powershell":
                        return self._mark(obj[a:a + b] if b is not None else obj[a:], obj)
                    return self._mark(obj[a:b], obj)
                if name == "repeat" and isinstance(first, int):
                    if len(obj) * max(first, 0) > V.MAX_TEXT:
                        raise Budget()
                    return obj * first
                if name in ("unpack", "unpack1") and isinstance(first, str):
                    if first[:1] == "m":
                        text = self._hide(V.text_of(V.b64(obj)))
                        return text if name == "unpack1" else [text]
                    if first[:1] in "UCc":
                        return [ord(c) for c in obj]
                return hole(name + "()")
            if isinstance(obj, list):
                if name == "join" or low == "join":
                    return self._join(obj, first if isinstance(first, str) else
                                      ("," if self.dialect == "js" and not args else ""))
                if name == "reverse":
                    return RList(obj[::-1])
                if name in ("first",):
                    return obj[0]
                if name == "last":
                    return obj[-1]
                if name == "concat" and isinstance(first, list):
                    return obj + first
                if name == "slice":
                    a = first if isinstance(first, int) else 0
                    b = args[1] if len(args) > 1 and isinstance(args[1], int) else None
                    return obj[a:b]
                if name == "pack" and isinstance(first, str):
                    if first[:1] in "UCc" and all(isinstance(i, int) and 0 <= i < 0x110000 for i in obj):
                        return self._hide("".join(chr(i) for i in obj))
                    if first[:1] == "H" and obj and isinstance(obj[0], str):
                        return self._hide(V.text_of(V.unhex(obj[0])))
                return hole(name + "()")
        except (ValueError, TypeError, IndexError, OverflowError):
            pass
        return hole(name + "()")

    # -- reading a call site --------------------------------------------------------------
    def _literal_at(self, pos: int) -> bool:
        """Is the first argument at ``pos`` nothing but one plain string?"""
        start = self._skip(pos, True)
        ch = self.code[start:start + 1]
        if ch not in ("'", '"', "`"):
            return self.dialect == "powershell" and bool(re.match(r"[\w.:/\\-]+\s*(?:$|[\n;|)])",
                                                                  self.code[start:start + 300]))
        saved = len(self._trace)
        before = set(self.hidden)
        value, end = self._string(start)
        del self._trace[saved:]
        nxt = self.code[self._skip(end, True):][:1]
        plain = isinstance(value, str) and value not in self.hidden - before
        return plain and nxt in (",", ")", ";", "", "\n", "|") or (
            plain and self._paren == 0 and self.code[self._skip(end, False):][:1] in ("\n", ""))

    def _plain_key(self, pos: int) -> Optional[str]:
        """``obj["name"]``: the name, if the key at ``pos`` is nothing but one plain
        string - no escapes, nothing joined or decoded (None otherwise)."""
        start = self._skip(pos, True)
        if self.code[start:start + 1] not in ("'", '"'):
            return None
        end = self.code.find(self.code[start], start + 1)
        after = self._skip(end + 1, True)
        if end == -1 or self.code[after:after + 1] != "]":
            return None
        text = self.code[start + 1:end]
        return None if "\\" in text or "\n" in text else text

    def _quoted_key(self, pos: int) -> bool:
        """Is the key at ``pos`` written with a string in it (``["ev" + "al"]``)?"""
        end = self.code.find("]", pos, pos + 300)
        return end != -1 and re.search(r"""["'`]""", self.code[pos:end]) is not None

    def arguments(self, pos: int, bracket: bool) -> List[Any]:
        """Arguments of the call whose list starts at ``pos``."""
        if bracket:
            return self.sequence(pos, ")")[0]
        items: List[Any] = []
        saved, self._paren = self._paren, 0
        try:
            while len(items) < 16:
                value, after = self.ternary(pos)
                if after == pos:
                    break
                items.append(value)
                kind, op, end = self.tok(after)
                if kind == "op" and op == ",":
                    pos = self._skip(end, True)
                else:
                    break
        finally:
            self._paren = saved
        return items

    def record(self, pos: int, kind: str, sink: str, value: Any, literal: bool,
               dynamic: bool = False, delete: bool = False) -> Optional[Resolved]:
        if isinstance(value, Ref) or value is None:
            return None
        text = show(value).strip()
        if len(V.known_part(text).strip()) < 3:
            if kind == "command":
                self.opaque += 1
            return None
        line = self.line_of(pos)
        if (kind, line, text) in self.seen or len(self.hits) >= 200:
            return None
        self.seen.add((kind, line, text))
        partial = V.is_partial(text)
        trivial = literal and not dynamic and self.layer == 0
        hit = Resolved(kind=kind, line=line, sink=sink, value=text[:4000],
                       hidden=self._is_hidden(value), partial=partial, delete=delete,
                       dynamic=dynamic, trivial=trivial, layer=self.layer,
                       trace=tuple(self._trace))
        self.hits.append(hit)
        if kind == "exec" and not partial and self.layer < V.MAX_DEPTH:
            inner = TextFlow(text, self.dialect, self.clock, self.layer + 1, line, self.hidden)
            inner.run()
            self.hits.extend(inner.hits[:200 - len(self.hits)])
            if not trivial:
                self.payloads.append((line, self.dialect, text))
            self.payloads.extend(inner.payloads)
        return hit

    def run(self) -> None:
        try:
            getattr(self, "_sites_" + self.dialect)()
        except (Budget, RecursionError) as exc:
            self.clock.ended(exc)                    # (the clock keeps which limit it was)

    def _too_many_sites(self, most: int = 0, module: bool = False) -> None:
        """The calls behind the first ``_MAX_SITES`` are not looked at: said, as every limit
        of this reading (until 2026-10-12 it was silent). Only for the file itself - a
        decoded layer with that many calls is its own, smaller matter. (``module``: those of
        one module function of a bundle; ``most``: the limit of the whole text - _Sites.)"""
        if self.layer == 0:
            self.clock.stopped = self.clock.stopped or (
                "more than %d calls to look at in one module function" % _MAX_SITES if module else
                "more than %d calls to look at" % (most or _MAX_SITES))

    def _site(self, pos: int, bracket: bool = True) -> List[Any]:
        self.clock.tick(20)
        del self._trace[:]
        return self.arguments(pos, bracket)

    # -- JavaScript ---------------------------------------------------------------------------
    _JS_CALL = re.compile(
        r"(?<![\w$.])((?:[A-Za-z_$][\w$]*\s*\.\s*){0,5}(?:%s))\s*\(" % "|".join(_JS_CALL_NAMES))
    _JS_DIRECT = re.compile(
        r"""require\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)\s*\.\s*(\w+)\s*\(""")
    _JS_ALIAS = re.compile(
        r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)"""
        r"""(?!\s*\.\s*\w+\s*\()|\{([^{}]{0,200})\}\s*=\s*require\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)""")
    _JS_COMPUTED = re.compile(r"(?<![\w$.])((?:[A-Za-z_$][\w$]*\.){0,3}[A-Za-z_$][\w$]*)\s*\[(?=[^\]\n]{1,300}\]\s*\()")
    _JS_SPAWN = frozenset({"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"})
    _JS_DELETE = frozenset({"unlinkSync", "unlink", "rmSync", "rm", "rmdirSync", "rmdir"})
    _JS_WRITE = {"writeFileSync": 0, "writeFile": 0, "appendFileSync": 0, "createWriteStream": 0,
                 "copyFileSync": 1, "renameSync": 1}

    def _command(self, args: List[Any]) -> Any:
        if len(args) > 1 and isinstance(args[1], list) and args[1]:
            return [args[0]] + list(args[1])
        return args[0] if args else None

    def _sites_js(self) -> None:
        rooted: Dict[str, int] = {}
        direct = 0
        for m in self._JS_DIRECT.finditer(self.code):
            direct += 1
            if m.group(1) in self._JS_SPAWN:
                args = self._site(m.end())
                self.record(m.start(), "command", "child_process." + m.group(1),
                            self._command(args), self._literal_at(m.end()))
        sites = _Sites(self)
        for m in _js_calls(self._JS_CALL, self.code):
            take = sites.take(m.start())
            if take is None:
                break
            if not take:
                continue
            parts = [p.strip() for p in m.group(1).split(".")]
            last, start = parts[-1], m.end()
            del self._trace[:]
            root = Ref(parts[0]) if parts[0] in ("this",) else self.lookup(parts[0], m.start())
            name = self._canon(".".join([root.name] + parts[1:])) if isinstance(root, Ref) else ""
            dynamic = isinstance(root, Ref) and root.dynamic
            if name.startswith("child_process.") and last in self._JS_SPAWN:
                rooted[parts[0]] = rooted.get(parts[0], 0) + 1
                args = self.arguments(start, True)
                self.record(m.start(), "command", name, self._command(args),
                            self._literal_at(start), dynamic)
            elif name in ("eval", "Function", "setTimeout", "setInterval", "importScripts") or (
                    last == "eval" and len(parts) == 2 and parts[0] in ("window", "global", "globalThis")):
                args = self.arguments(start, True)
                if not args:
                    continue
                value = args[-1] if name == "Function" else args[0]
                if name in ("setTimeout", "setInterval") and not isinstance(value, str):
                    continue
                self.record(m.start(), "url" if name == "importScripts" else "exec", name or "eval",
                            value, self._literal_at(start) and len(args) == 1 or (
                                name in ("setTimeout", "setInterval") and self._literal_at(start)),
                            dynamic)
            elif last in ("openExternal", "openItem", "openPath"):
                args = self.arguments(start, True)
                if args:
                    self._web(m.start(), "shell." + last, args[0], self._literal_at(start), True)
            elif name in ("fetch", "WebSocket", "EventSource", "open") or (
                    name.split(".")[0] in ("http", "https", "request", "axios", "$", "jQuery", "got")
                    and last in ("get", "request", "post", "ajax", "getScript")):
                args = self.arguments(start, True)
                if args:
                    self._web(m.start(), name, args[0], self._literal_at(start))
            elif last == "open" and len(parts) > 1:
                args = self.arguments(start, True)
                if len(args) >= 2 and isinstance(args[0], str) and args[0].upper() in _HTTP_VERBS:
                    self._web(m.start(), "XMLHttpRequest.open", args[1], False)
            elif name.split(".")[-1] == "require" and len(parts) <= 3:
                args = self.arguments(start, True)
                if args and isinstance(args[0], str) and not self._literal_at(start):
                    self.record(m.start(), "call", "require", args[0], False, True)
            elif name.startswith("fs.") and (last in self._JS_DELETE or last in self._JS_WRITE):
                args = self.arguments(start, True)
                index = self._JS_WRITE.get(last, 0)
                if len(args) > index:
                    self.record(m.start(), "path", name, args[index],
                                index == 0 and self._literal_at(start), dynamic,
                                last in self._JS_DELETE)
        # window['ev' + 'al'](...), cp['ex' + 'ec'](...): the function is picked by a built-up name
        for m in _js_computed(self._JS_COMPUTED, self.code):
            take = sites.take(m.start())
            if take is None:
                break
            if not take:
                continue
            del self._trace[:]
            parts = [p.strip() for p in m.group(1).split(".")]
            root = Ref(parts[0]) if parts[0] == "this" else self.lookup(parts[0], m.start())
            plain = self._plain_key(m.end())
            if not isinstance(root, Ref):
                # obj["eval"](...), obj["ev" + "al"](...): whatever obj is, the name says
                # what runs. Only a key that is written with a string in it is looked at.
                if plain is not None and plain not in _JS_RUNS:
                    continue
                if plain is None and not self._quoted_key(m.end()):
                    continue
            self.clock.tick(20)
            self._paren += 1
            try:
                key, after = self.ternary(m.end())
            finally:
                self._paren -= 1
            closing = self.tok(after)
            after_key = self._skip(closing[2])
            if not isinstance(key, str) or closing[1] != "]" or self.code[after_key:after_key + 1] != "(":
                continue
            if isinstance(root, Ref):
                name = self._canon(".".join([root.name] + parts[1:] + [key]))
                name = name[5:] if name.startswith("this.") else name
            elif key in _JS_RUNS:
                name = key
            else:
                continue
            # nodePath["normalize"](...) is an ordinary call written the way minifiers
            # and Emscripten write it: nothing is hidden. It is left alone only if the
            # name is one plain string that is not built at runtime, and not a risky name.
            if plain is not None and not _JS_RISKY.search(name):
                continue
            self.record(m.start(), "call", "[...]", name, False, True)
            args = self.arguments(self._skip(closing[2]) + 1, True)
            if not args:
                continue
            if name in ("eval", "Function"):
                self.record(m.start(), "exec", name, args[-1], False, True)
            elif name.startswith("child_process.") and key in self._JS_SPAWN:
                self.record(m.start(), "command", name, self._command(args), False, True)
        # Is every use of child_process accounted for? (the ContextEngine relies on this
        # before it accepts "this plugin only opens a web page")
        aliases, defined = [], 0
        for m in find_all(self._JS_ALIAS, self.code):
            defined += 1
            aliases += [m.group(1)] if m.group(1) else re.findall(r"[A-Za-z_$][\w$]*", m.group(2))
        if self._module_uses("child_process") != defined + direct:
            self.opaque += 1
        for alias in dict.fromkeys(aliases):
            uses = len(re.findall(r"(?<![\w$.])%s(?![\w$])" % re.escape(alias), self.code))
            if uses != 1 + rooted.get(alias, 0):
                self.opaque += 1

    # a module's name as one quoted element of a list of quoted texts: ["assert", "child_process", ...]
    _LIST_BEFORE = re.compile(r"""(?<![\w$)\]\s])(\s*)\[\s*(?:(["'])[^"'\\\n]{0,200}\2\s*,\s*){0,400}\Z""")
    _LIST_AFTER = re.compile(r"""(?:\s*,\s*(["'])[^"'\\\n]{0,200}\1){0,400}\s*,?\s*\]""")    # (used with match)
    _MODULE_LOAD = re.compile(r"(?<![\w$.])(?:require|import)\s*\(")
    _NAMED_MODULE = re.compile(r"""\s*(["'])[^"'\\\n]{1,200}\1\s*\)""")

    def _module_uses(self, word: str) -> int:
        """How often ``word``, a module's name, stands in the code where it can reach a
        ``require`` / ``import`` (phageo, 2026-10-15, forty-sixth message): a name in a string counts
        only as such a call's argument or when it reaches one - not as an element of a list. So
        a quoted element of a list of quoted texts (``["assert", "child_process", ...]``: the
        list of Node's built-in modules a compiler keeps) is no use - unless the file loads a
        module whose name is not written out (``require(x)``, ``import(x)`` in its code): only
        through such a call can an element of a list reach one."""
        code = self.code
        places = [m.start() for m in re.finditer(re.escape(word), code)]
        if not places:
            return 0
        dynamic: Optional[bool] = None
        uses = 0
        for at in places:
            quote = code[at - 1:at] if at else ""
            end = at + len(word)
            if quote not in ("'", '"') or code[end:end + 1] != quote:
                uses += 1
                continue
            before = self._LIST_BEFORE.search(code, max(0, at - 1 - 20_000), at - 1)
            after = self._LIST_AFTER.match(code, end + 1, min(len(code), end + 1 + 20_000))
            if before is None or after is None:
                uses += 1
                continue
            if dynamic is None:
                texts = quoted_text(code)
                dynamic = any(not texts.holds(m.start()) and not self._NAMED_MODULE.match(code, m.end())
                              for m in self._MODULE_LOAD.finditer(code))
            if dynamic:
                uses += 1
        return uses

    def _web(self, pos: int, sink: str, value: Any, literal: bool, launch: bool = False) -> None:
        text = show(value) if isinstance(value, (str, Sym)) else ""
        remote = re.match(r"\s*(?:[a-z][a-z0-9+.\-]*:)?//", text, re.I) or self._is_hidden(value)
        # the shell's open (phageo, 2026-10-15, forty-sixth message): an http(s) address is a page
        # the browser opens; a file, a folder or an address of any other kind is started
        browser = re.match(r"\s*https?://", text, re.I) is not None
        if launch and text and not browser and not re.match(r"\s*" + V.OPEN, text):
            self.record(pos, "command", sink, value, literal)        # opens a local file
        elif remote:
            self.record(pos, "url", sink, value, literal)

    # -- Ruby -----------------------------------------------------------------------------------
    _RB_CALL = re.compile(
        _IND[1])
    _RB_TICKS = re.compile(r"""(?<![\w"'`\\])`([^`\n]{3,400})`""")
    _RB_PERCENT = re.compile(r"(?<![\w%])%x([{(\[<!|/])")
    _RB_CLOSER = {"{": "}", "(": ")", "[": "]", "<": ">"}

    def _sites_ruby(self) -> None:
        sites = 0
        for m in self._RB_CALL.finditer(self.code):
            sites += 1
            if sites > _MAX_SITES:
                self._too_many_sites()
                break
            name = (m.group(1) or m.group(2)).replace("::", ".")
            bracket, start = m.group(3) == "(", m.end()
            if not bracket:
                nxt = self.code[start:start + 1]
                if start == m.end(1 if m.group(1) else 2) or not nxt or nxt in "\n=;,.)|&}]":
                    continue                          # not a call with arguments
                if re.match(r"(?:if|unless|rescue|do|and|or|then|end)\b", self.code[start:start + 8]):
                    continue
            args = self._site(start, bracket)
            if not args:
                continue
            first, literal = args[0], self._literal_at(start)
            if name.endswith("eval"):
                self.record(m.start(), "exec", name, first, literal)
            elif name in ("system", "exec", "spawn", _IND[2]) or name.startswith("Open3."):
                texts = [a for a in args if isinstance(a, (str, Sym))]
                self.record(m.start(), "command", name, texts if len(texts) > 1 else first,
                            literal and len(args) == 1)
            elif name in ("open", "URI.open"):
                text = show(first) if isinstance(first, (str, Sym)) else ""
                if text.lstrip().startswith("|"):
                    self.record(m.start(), "command", "open", Sym(text.lstrip()[1:])
                                if isinstance(first, Sym) else self._mark(text.lstrip()[1:], first), literal)
                elif "://" in text:
                    self.record(m.start(), "url", name, first, literal)
            elif name in ("load", "require"):
                if isinstance(first, str) and not literal:
                    self.record(m.start(), "call", name, first, False, True)
            elif name.startswith("Net.HTTP"):
                self.record(m.start(), "url", "Net::HTTP", first, literal)
            elif name.startswith(("TCPSocket", "UDPSocket")):
                if isinstance(first, (str, Sym)) and len(args) > 1:
                    host = "tcp://%s:%s" % (show(first), show(args[1]))
                    self.record(m.start(), "url", name, Sym(host) if isinstance(first, Sym)
                                else self._mark(host, first), literal)
            elif name == "Win32API.new":
                if len(args) > 1 and all(isinstance(a, str) for a in args[:2]) and not (
                        literal and self._is_plain_pair(start)):
                    self.record(m.start(), "call", name, "%s!%s" % (args[0], args[1]), False, True)
            else:
                self.record(m.start(), "path", name, first, literal, False, True)
        for m in self._RB_TICKS.finditer(self.code):
            if "#{" not in m.group(1):
                # a plain command: the ordinary rules see it - and the shell chain reads it
                self._started(m.start(), m.group(1))
                continue
            del self._trace[:]
            value, _ = self._string(m.start())        # read like a "..." string
            self.record(m.start(), "command", "`...`", value, False)
        for m in self._RB_PERCENT.finditer(self.code):        # %x{...}: backticks in other brackets
            sites += 1
            if sites > _MAX_SITES:
                self._too_many_sites()
                break
            end = self._percent_end(m.end(), m.group(1))
            if end is None:
                continue
            body = self.text[m.end():end]
            if "#{" not in body:
                self._started(m.start(), body)
                continue
            del self._trace[:]
            self.clock.tick(20)
            self.record(m.start(), "command", "%x", self._interpolated(m.end(), end), False)

    def _started(self, pos: int, command: str) -> None:
        if len(command.strip()) >= 3 and len(self.started) < 200:
            self.started.append((self.line_of(pos), command.strip()[:4000]))

    def _percent_end(self, pos: int, opener: str) -> Optional[int]:
        """Where the ``%x`` literal that starts at ``pos`` ends (on its line,
        within 400 characters; brackets of its own kind may nest)."""
        closer, depth = self._RB_CLOSER.get(opener, opener), 0
        for i in range(pos, min(len(self.text), pos + 400)):
            ch = self.text[i]
            if ch == "\n":
                return None
            if self.text[i - 1] == "\\":
                continue
            if ch == opener and closer != opener:
                depth += 1
            elif ch == closer:
                if depth == 0:
                    return i
                depth -= 1
        return None

    def _interpolated(self, start: int, end: int) -> Any:
        """The text between ``start`` and ``end`` with each ``#{...}`` resolved."""
        value: Any = ""
        pos = start
        while pos < end:
            at = self.text.find("#{", pos, end)
            if at == -1:
                at = end
            value = V.concat(value, self.text[pos:at])
            if at >= end:
                break
            close = self.text.find("}", at, end)
            if close == -1:
                return None
            # (outside quotes the comment mask has blanked "#{...}": read it as written)
            masked, self.code = self.code, self.code[:at] + self.text[at:close + 1] + self.code[close + 1:]
            self._paren += 1
            try:
                inner, after = self.ternary(at + 2)
                complete = self._skip(after, True) == close
            finally:
                self._paren -= 1
                self.code = masked
            if isinstance(inner, bool) or not isinstance(inner, (str, Sym, Ref, int)) or not complete:
                inner = Sym(V.OPEN + self.text[at + 2:close].strip()[:40] + V.CLOSE)
            joined = V.concat(value, str(inner) if isinstance(inner, int) else inner)
            if joined is None:
                return None
            value = self._mark(joined, inner)
            pos = close + 1
        return value

    def _is_plain_pair(self, pos: int) -> bool:
        return re.match(r"""\s*(['"])[^'"\n#]*\1\s*,\s*(['"])[^'"\n#]*\2""", self.code[pos:pos + 300]) is not None

    # -- PowerShell -----------------------------------------------------------------------------
    _PS_CALL = re.compile(
        _IND[3], re.I)
    _PS_PIPED = re.compile(_IND[4])

    def _sites_powershell(self) -> None:
        sites = 0
        for m in self._PS_CALL.finditer(self.code):
            sites += 1
            if sites > _MAX_SITES:
                self._too_many_sites()
                break
            start = m.end()
            bracket = (m.group(2) or m.group(4)) == "("
            if self.code[start:start + 1] in ("", "\n", "|", ";", "-") and not bracket:
                continue
            args = self._site(start, bracket)
            if not args:
                continue
            literal = self._literal_at(start)
            if m.group(1):
                self.record(m.start(), "exec", _IND[5], args[0], literal)
            elif m.group(3):
                self.record(m.start(), "url", m.group(3), args[0], literal)
            elif m.group(5):
                self.record(m.start(), "url", m.group(5), args[0], literal)
            else:
                self.record(m.start(), "command", m.group(6) or "&", args[0], literal)
        for m in self._PS_PIPED.finditer(self.code):
            del self._trace[:]
            self._paren = 0
            value, _ = self.ternary(m.start(1))
            self.record(m.start(), "exec", _IND[5], value, False)


def _tr(text: str, source: str, target: str) -> str:
    """Ruby ``String#tr`` with character ranges (how ROT13 is written in Ruby)."""
    def expand(spec: str) -> str:
        out, i = [], 0
        while i < len(spec):
            if i + 2 < len(spec) and spec[i + 1] == "-" and ord(spec[i]) <= ord(spec[i + 2]):
                out.extend(chr(c) for c in range(ord(spec[i]), ord(spec[i + 2]) + 1))
                i += 3
            else:
                out.append(spec[i])
                i += 1
        return "".join(out)[:4096]
    a, b = expand(source), expand(target)
    if not a or not b:
        return text
    table = {ord(c): b[min(i, len(b) - 1)] for i, c in enumerate(a)}
    return text.translate(table)


# -- batch files ---------------------------------------------------------------------------
_BAT_SET = re.compile(r"""(?im)^[ \t@]*set[ \t]+(?:/a[ \t]+)?"?([\w#$.\-]{1,60})=([^\n"]*)"?[ \t]*$""")
_BAT_VAR = re.compile(r"[%!]([\w#$.\-]{1,60})[%!]")
_BAT_ENV = frozenset("""appdata localappdata userprofile temp tmp systemroot windir programfiles
programdata comspec homedrive homepath username computername cd date time random errorlevel
public systemdrive path pathext os processor_architecture""".split())


def batch_expand(text: str) -> List[Tuple[int, str]]:
    """Lines of a batch file whose ``%variables%`` could be filled in from the
    file's own ``set`` commands: ``(line number, expanded line)``."""
    if len(text) > MAX_SOURCE:
        return []
    table: Dict[str, str] = {}
    for m in _BAT_SET.finditer(text):
        name = m.group(1).lower()
        if name not in _BAT_ENV and len(table) < 2000:
            table[name] = m.group(2).rstrip()[:2000]
    if not table:
        return []
    out: List[Tuple[int, str]] = []
    for number, line in enumerate(text.split("\n")[:MAX_BATCH_LINES], 1):
        if "%" not in line and "!" not in line or _BAT_SET.match(line):
            continue
        expanded = line
        for _ in range(4):
            fresh = _BAT_VAR.sub(lambda m: table.get(m.group(1).lower(), m.group(0)), expanded)
            if fresh == expanded or len(fresh) > 8000:
                break
            expanded = fresh
        if expanded != line:
            out.append((number, expanded.strip()))
            if len(out) >= 500:
                break
    return out


def limit(dialect: str) -> int:
    """Characters of a script of ``dialect`` that are read."""
    return JS_MAX_SOURCE if dialect == "js" else MAX_SOURCE


def analyse(text: str, dialect: str, clock: Optional[Clock] = None) -> TextFlow:
    clock = clock or Clock()
    most = limit(dialect)
    if len(text) > most:                    # not read at all: said (silent until 2026-10-12)
        clock.stopped = clock.stopped or "larger than %d MB" % (most >> 20)
    flow = TextFlow(text if len(text) <= most else "", dialect, clock)
    flow.run()
    return flow
