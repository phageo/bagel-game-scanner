"""Remote code execution in Ruby (RPG Maker XP / VX / VX Ace), and what a
``ShellExecute`` call opens.

The Ruby counterpart of :mod:`gamescan.dataflow.remote`:

``source``  a download - ``URLDownloadToFile`` / the WinINet functions through
            ``Win32API``, ``open-uri``, ``Net::HTTP``, a ``TCPSocket``
``flow``    the answer travels through variables and method arguments, or it
            is the file the download was written to
``sink``    ... and is executed: ``eval`` and its relatives, ``system`` /
            ``exec`` / ``spawn`` / backticks, or the downloaded file is started
            with ``WinExec`` / ``ShellExecute`` / ``CreateProcess`` or loaded
            with ``load`` / ``require`` (a dropper)

The address decides, as in JavaScript: remote, decoded or not resolvable -
reported; this PC - nothing is reported.

:func:`shell_execute` answers a smaller question for the many games that use
``ShellExecute`` only to open their web page or a manual: what do the calls
open? A web address or a document of the game is not a program start.

This is a tracer over lines of text, not a Ruby parser. A variable counts from
the line that sets it; a method's parameters count inside that method; values
are resolved with the payload resolver (:mod:`gamescan.dataflow.textflow`).
Nothing is executed.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_rb.py")

import re
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from . import values as V
from .remote import HIDDEN, LOCAL, REMOTE, UNRESOLVED, Hit
from .textflow import MAX_SOURCE, TextFlow
from .values import Budget, Clock, Sym, show

MAX_STEPS = 300_000                 # the limit: the same file is always cut at the same place
MAX_SECONDS = V.SAFETY_SECONDS      # a far safety cap only; when it fires that is said too
_MAX_LINES = 60_000
_MAX_HITS = 8
_PASSES = 4                         # readings before the last: a value is followed over that many hand-overs
_MAX_METHODS = 20_000               # methods of one script
_MAX_FIELDS = 2_000                 # fields (@x per class, attr_...) of one script
_MAX_CLASSES = 2_000                # classes / modules of one script
_MAX_LAMBDAS = 2_000                # blocks kept in a name
_MAX_TARGETS = 4                    # classes one obj.name can stand for

_NAME = r"(?:@@?|\$)?[A-Za-z_]\w*"
_HINT = re.compile(r"Win32API|open-uri|Net::HTTP|TCPSocket|URI\b|OpenURI")
_API = re.compile(r"(%s)\s*=\s*Win32API\.new\s*\(\s*(['\"])([^'\"\n]{1,40})\2\s*,\s*(['\"])(\w{3,40})\4" % _NAME)
_API_INLINE = re.compile(r"Win32API\.new\s*\(\s*(['\"])([^'\"\n]{1,40})\1\s*,\s*(['\"])(\w{3,40})\3")
_DOWNLOADS = re.compile(r"^URLDownloadTo(?:Cache)?File[AW]?$", re.I)
_OPENS_URL = re.compile(_IND[0], re.I)
_READS = re.compile(r"^(?:InternetReadFile|WinHttpReadData|recv)$", re.I)
_STARTS = re.compile(_IND[1], re.I)
_SHELL_EXECUTE = re.compile(_IND[2], re.I)
_ASSIGN = re.compile(r"^\s*(%s(?:\s*,\s*%s)*)\s*(?:\|\||\+|<<)?=(?![=~>])\s*(.+)$" % (_NAME, _NAME))
_APPEND = re.compile(r"^\s*(%s)\s*<<\s*(.+)$" % _NAME)
_DEF = re.compile(r"^(\s*)def\s+(?:self\.)?([A-Za-z_]\w*[?!=]?)\s*(?:\(([^)]*)\)|([^\n]*))?")
_BLOCK = re.compile(r"(?:\{|\bdo)\s*\|\s*([A-Za-z_]\w*)")
_SCOPE_END = re.compile(r"^\s*(?:def|class|module)\b")
# requests whose answer is a value in the script
_FETCH = re.compile(
    r"(?<![\w.:])(?:Kernel\.)?open\s*\(?|URI\.open\s*\(?|OpenURI\.open_uri\s*\(?"
    r"|Net::HTTP\.(?:get_response|get_print|get|post_form|start|new)\s*\(?"
    r"|(?:TCPSocket|UDPSocket)\.(?:new|open)\s*\(?|URI(?:\.parse)?\s*\(")
_FETCH_READS = re.compile(r"\)\s*\.\s*(?:read|open|body)\b")
_EVAL = re.compile(r"(?:(?<![\w.:@$])(?:Kernel\.|binding\.)?(eval)|(?<![\w:@$])(instance_eval|class_eval"
                   r"|module_eval|instance_exec|class_exec))\b[ \t]*\(?")
_COMMAND = re.compile(_IND[3])
_TICKS = re.compile(r"(?<![\w\"'\\])`([^`\n]{1,400})`|%x\s*[\{\(\[<]([^\n]{1,400})")
_LOAD = re.compile(r"(?<![\w.:@$])(load|require|require_relative)\b[ \t]*\(?")
_FILE_WRITE = re.compile(r"\b(?:File|IO)\.(?:write|binwrite)\s*\(?")
_FILE_OPEN = re.compile(r"\bFile\.(?:open|new)\s*\(")
_HANDLE_WRITE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\.\s*(?:write|print|puts|syswrite)\b\s*\(?|<<)\s*(.+)$")
_ATTR = re.compile(r"^\s*attr_(accessor|reader|writer)\b(.+)$")
_ATTR_WRITE = re.compile(r"^\s*((?:@@?|\$)?[A-Za-z_][\w.]*?)\s*\.\s*([a-z_]\w*)\s*=(?![=~>])\s*(.+)$")
_MEMBER = re.compile(r"((?:@@?|\$)?[A-Za-z_]\w*)\s*(?:\.|::)\s*([a-z_]\w*[?!]?)(?![\w(]*\s*=(?![=~]))")
_LAMBDA = re.compile(r"((?:@@?|\$)?[A-Za-z_]\w*)\s*=\s*(?:(?:lambda|proc|Proc\.new)\s*(?:\{|do)\s*(?:\|([^|]*)\|)?"
                     r"|->\s*(?:\(([^)]*)\))?\s*(?:\{|do))")
_YIELD = re.compile(r"(?<![\w.@$])yield\b[ \t]*\(?(.*)$")
_NEW = re.compile(r"(?<![\w.@$:])([A-Z]\w*)\s*\.\s*new\b[ \t]*(\(?)")
_OUT_CALL = re.compile(r"(?:(?<![\w.@$:])|(?<=\.))([a-z_]\w*[?!]?)[ \t]*\(")
_TOKEN = re.compile(r"[A-Za-z_]\w*[?!]?")
_REMOTE_AT = re.compile(r"\s*(?:https?|wss?|ftps?|tcp)://", re.I)
_LOCAL_AT = re.compile(r"\s*(?:file:|(?:https?|wss?|ftp|tcp)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)"
                       r"(?:[:/]|$)|(?:localhost|127\.\d+\.\d+\.\d+)$)", re.I)

# -- what ShellExecute opens -----------------------------------------------------------------
LOW, MEDIUM, HIGH = "low", "medium", "high"
_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}
_DOCUMENTS = frozenset(".txt .htm .html .pdf .rtf .md .png .jpg .jpeg .gif .bmp .chm".split())
_SHORTENERS = re.compile(r"^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly"
                         r"|shorturl\.at|rb\.gy|tiny\.cc)$", re.I)
_HOST = re.compile(r"^(https?)://([^/\s:@?#]+)(?::\d+)?(?:[/?#]\S*)?$", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^\[")
_BAD_PATH = re.compile(r"^[A-Za-z]:|^[\\/]|^~|%[A-Za-z_]+%|\$|(?:^|[\\/])\.\.(?:[\\/]|$)|[<>|&;\"`*?]")


class _Source:
    __slots__ = ("what", "line", "kind", "address")

    def __init__(self, what: str, line: int, kind: str, address: str) -> None:
        self.what, self.line, self.kind, self.address = what, line, kind, address


def _classify(value: Any, hidden: bool) -> Tuple[str, str]:
    """``(kind, address)`` of an address value from the resolver."""
    if not isinstance(value, (str, Sym)):
        return UNRESOLVED, ""
    text = show(value).strip()
    if hidden:
        return HIDDEN, text[:200]
    known = V.known_part(text)
    if _LOCAL_AT.match(known):
        return LOCAL, text[:200]
    if _REMOTE_AT.match(known):
        return REMOTE, text[:200]
    if isinstance(value, str) and re.match(r"[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:/|$)", text):
        return REMOTE, text[:200]                         # a host name without a scheme
    return UNRESOLVED, text[:120]


def _leaf(text: str) -> str:
    return re.split(r"[\\/]", text.strip().strip("\"'"))[-1].lower()


class _Lines:
    """The script as lines, with a resolver for the values at a call."""

    def __init__(self, text: str, clock: Clock) -> None:
        self.clock = clock
        self.flow = TextFlow(text[:MAX_SOURCE], "ruby", clock)
        self.code = self.flow.code                        # comments blanked, same positions
        self.starts = [0] + [m.end() for m in re.finditer(r"\n", self.code)][:_MAX_LINES]
        self.lines = self.code.split("\n")[:_MAX_LINES + 1]
        self.literal: Dict[str, List[Tuple[int, str]]] = {}
        for number, line in enumerate(self.lines, 1):
            m = re.match(r"\s*(%s)\s*=\s*(['\"])([^'\"\n#]*)\2\s*$" % _NAME, line)
            if m:
                self.literal.setdefault(m.group(1), []).append((number, m.group(3)))

    def values(self, line: int, column: int, bracket: bool = True) -> List[Any]:
        """The argument values of the call whose list starts at (line, column)."""
        self.clock.tick(20)
        try:
            return self.flow._site(self.starts[line - 1] + column, bracket)
        except (Budget, RecursionError):
            raise
        except Exception:
            return []

    def hidden(self, value: Any) -> bool:
        return self.flow._is_hidden(value)

    def nearest(self, raw: str, line: int) -> Optional[str]:
        """A plain name's most recent literal value above ``line`` (the event
        scripts of a map all use the same few names, one after the other)."""
        name = raw.strip()
        found = [text for number, text in self.literal.get(name, ()) if number <= line]
        return found[-1] if found else None

    def raw_args(self, line: int, column: int) -> List[str]:
        """The arguments as written, split at top-level commas (the list may
        run over the next lines)."""
        text = self.code[self.starts[line - 1] + column: self.starts[line - 1] + column + 1200]
        out, depth, quote, current = [], 0, "", []
        for ch in text:
            if quote:
                current.append(ch)
                if ch == quote:
                    quote = ""
                continue
            if ch in "\"'`":
                quote = ch
                current.append(ch)
            elif ch in "([{":
                depth += 1
                current.append(ch)
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                out.append("".join(current).strip())
                current = []
            elif ch == "\n" and depth == 0 and not (current and "".join(current).rstrip().endswith(",")) \
                    and not (out and not "".join(current).strip()):
                break
            else:
                current.append(ch)
        if "".join(current).strip():
            out.append("".join(current).strip())
        return out[:16]


def _code_only(text: str) -> str:
    """The line with string contents blanked - except what is inside ``#{...}``."""
    out, i, n, quote = [], 0, len(text), ""
    while i < n:
        ch = text[i]
        if not quote:
            if ch in "\"'`":
                quote = ch
            out.append(ch)
        elif ch == "\\":
            out.append("  ")
            i += 1
        elif ch == quote:
            quote = ""
            out.append(ch)
        elif ch == "#" and quote != "'" and text[i + 1:i + 2] == "{":
            end = text.find("}", i)
            end = n if end < 0 else end
            out.append(" " + text[i + 1:end + 1])
            i = end
        else:
            out.append(" ")
        i += 1
    return "".join(out)


class _Flow:
    def __init__(self, text: str, clock: Clock) -> None:
        self.src = _Lines(text, clock)
        self.clock = clock
        self.apis: Dict[str, List[Tuple[int, str]]] = {}        # handle -> [(line, function)]
        self.taint: Dict[str, List[Tuple[_Source, int, int]]] = {}
        self.drops: List[Tuple[_Source, int, str, str]] = []    # source, line, name / leaf, shown
        self.defs: Dict[str, Tuple[int, int, List[str]]] = {}   # method -> (first, last line, params)
        self.ranges: List[Tuple[int, int]] = []
        self.handles: Dict[str, Tuple[int, str, Any]] = {}      # file handle -> (line, raw path, value)
        self.hits: List[Hit] = []
        self.changed = False
        self.open_uri = re.search(r"open-uri|OpenURI", self.src.code) is not None
        # objects (2026-10-12): which class a line stands in; every method with its class;
        # the fields a class declares; what a method gives back and hands to its block;
        # blocks kept in a name; downloads handed to methods this script does not define
        self.owners: List[str] = []
        self.methods: Dict[str, List[Tuple[int, int, List[str], str, str]]] = {}
        self.readers: Dict[str, List[str]] = {}
        self.writers: Dict[str, List[str]] = {}
        self.rets: Dict[str, List[Tuple[str, _Source]]] = {}
        self.yields: Dict[str, _Source] = {}
        self.lambdas: Dict[str, Tuple[int, int, List[str]]] = {}
        self.handed: Dict[str, _Source] = {}
        self.cut = ""
        self.fields = 0
        self._prepare()

    # -- preparation ----------------------------------------------------------------
    def _prepare(self) -> None:
        lines = self.src.lines
        joined = self.src.code
        for m in _API.finditer(joined):
            line = joined.count("\n", 0, m.start()) + 1
            self.apis.setdefault(m.group(1), []).append((line, m.group(5)))
        self.owners = _owners(lines)
        if len(set(self.owners)) > _MAX_CLASSES:
            self.cut = "more than %d classes" % _MAX_CLASSES
        current: Optional[Tuple[str, int, int, List[str], str]] = None
        fields = count = 0

        def close(last: int) -> None:
            name, first, _indent, params, block = current
            self.defs[name] = (first, last, params)
            self.ranges.append((first, last))
            owner = self.owners[first - 1] if first <= len(self.owners) else ""
            self.methods.setdefault(name, []).append((first, last, params, owner, block))

        for number, line in enumerate(lines, 1):
            self.clock.tick()
            if _SCOPE_END.match(line) and current is not None:
                close(number - 1)
                current = None
            elif current is not None and number > current[1] and re.match(r"\s*end\b", line) \
                    and len(line) - len(line.lstrip()) <= current[2]:
                close(number)                               # the method's own end (by its indentation)
                current = None
                continue
            m = _DEF.match(line)
            if m:
                raw = [p.strip() for p in (m.group(3) or m.group(4) or "").split(",")]
                params = [p.lstrip("*&").split("=")[0].strip() for p in raw]
                block = next((p.lstrip("&").strip() for p in raw if p.startswith("&")), "")
                count += 1
                if count > _MAX_METHODS:
                    self.cut = V.also(self.cut, "more than %d methods" % _MAX_METHODS)
                    current = None
                    continue
                current = (m.group(2), number, len(m.group(1)), [p for p in params if p], block)
                continue
            m = _ATTR.match(line)
            if m:                                           # attr_accessor :a, :b
                owner = self.owners[number - 1]
                for name in re.findall(r":([A-Za-z_]\w*)", m.group(2)):
                    fields += 1
                    if fields > _MAX_FIELDS:
                        self.cut = V.also(self.cut, "more than %d fields" % _MAX_FIELDS)
                        break
                    if m.group(1) != "writer" and owner not in self.readers.setdefault(name, []):
                        self.readers[name].append(owner)
                    if m.group(1) != "reader" and owner not in self.writers.setdefault(name, []):
                        self.writers[name].append(owner)
                continue
            m = _LAMBDA.search(line)
            if m and len(self.lambdas) < _MAX_LAMBDAS:      # run = lambda { |code| ... }
                params = [p.strip().lstrip("*&").split("=")[0].strip() for p in (m.group(2) or m.group(3) or "").split(",")]
                self.lambdas[m.group(1)] = (number, self._block_end(number, m.end()), [p for p in params if p])
        if current is not None:
            close(len(lines))

    def _block_end(self, number: int, column: int) -> int:
        """The last line of the block that opens on line ``number`` at ``column`` (by its
        closing bracket on the same line, else by the indentation of its ``end`` / ``}``)."""
        lines = self.src.lines
        line = lines[number - 1]
        rest = line[column:]
        if rest.count("}") > rest.count("{") or re.search(r"\bend\b", rest):
            return number
        indent = len(line) - len(line.lstrip())
        for later in range(number + 1, min(len(lines), number + 2000) + 1):
            text = lines[later - 1]
            if text.strip() and len(text) - len(text.lstrip()) <= indent and text.lstrip().startswith(("end", "}")):
                return later
        return min(len(lines), number + 2000)

    def owner_at(self, line: int) -> str:
        return self.owners[line - 1] if 0 < line <= len(self.owners) else ""

    def _range(self, name: str, line: int) -> Tuple[int, int]:
        """Where a value set at ``line`` counts."""
        last = len(self.src.lines)
        if name[:1] in "@$" or name[:1].isupper():
            return 0, last                                # fields, globals, constants: everywhere
        for first, end in self.ranges:
            if first <= line <= end:
                return line, end                          # a local: to the end of its method
        return line, last

    def api(self, handle: str, line: int) -> Optional[str]:
        found = [name for at, name in self.apis.get(handle, ()) if at <= line]
        return found[-1] if found else (self.apis[handle][0][1] if handle in self.apis else None)

    # -- taint ----------------------------------------------------------------------
    def mark(self, name: str, source: Optional[_Source], line: int, span=None, owner: Optional[str] = None) -> None:
        if source is None or not name:
            return
        first, last = span or self._range(name, line)
        if name[:1] == "@" and name[:2] != "@@":           # a field belongs to its class: "Owner.@x"
            name = "%s.%s" % (self.owner_at(line) if owner is None else owner, name)
            if name not in self.taint:
                self.fields += 1
                if self.fields > _MAX_FIELDS:
                    self.cut = V.also(self.cut, "more than %d fields" % _MAX_FIELDS)
                    return
        entries = self.taint.setdefault(name, [])
        if not any(a <= first and last <= b for _s, a, b in entries) and len(entries) < 50:
            entries.append((source, first, last))
            self.changed = True

    def held(self, text: str, line: int) -> List[_Source]:
        """The downloads the names in a piece of code hold (a field only in its own class)."""
        if not self.taint:
            return []
        code = _code_only(text)
        owner = None
        out: List[_Source] = []
        for name, entries in self.taint.items():
            shown = name
            if ".@" in name:
                cls, _, field = name.partition(".@")
                if owner is None:
                    owner = self.owner_at(line)
                if cls != owner:
                    continue
                shown = "@" + field
            if shown not in code:
                continue
            if re.search(r"(?<![\w@$.])%s(?![\w?!])" % re.escape(shown), code):
                out += [source for source, first, last in entries if first <= line <= last]
        return out

    def field(self, owner: str, name: str, line: int) -> Optional[_Source]:
        return next((source for source, first, last in self.taint.get("%s.@%s" % (owner, name), ())
                     if first <= line <= last), None)

    def objects(self, text: str, line: int) -> List[_Source]:
        """The downloads a piece of code reaches through objects: a field read from outside
        (``obj.name`` with ``attr_reader``), and what a method gives back (``obj.name``,
        ``Owner.name``, a bare ``name`` in its class or at the top of the script)."""
        if not (self.rets or self.readers):
            return []
        code = _code_only(text)
        owner = self.owner_at(line)
        out: List[_Source] = []
        for m in _MEMBER.finditer(code):
            receiver, name = m.group(1), m.group(2)
            for cls in self.readers.get(name, ())[:_MAX_TARGETS]:
                found = self.field(cls, name, line)
                if found is not None:
                    out.append(found)
            if any(self.field(cls, name, line) is not None for cls in self.readers.get(name, ())[_MAX_TARGETS:]):
                self._too_many(name)                        # a class behind the limit holds a download there
            given = self.rets.get(name, ())
            exact = [source for cls, source in given if cls == receiver]
            # (Owner.name where this script has that class's method: that one, and no other class's)
            known = any(entry[3] == receiver for entry in self.methods.get(name, ()))
            out += exact if exact or known else [source for _cls, source in given[:_MAX_TARGETS]]
        for name in set(_TOKEN.findall(code)) & (self.rets.keys() | self.readers.keys()):
            if not re.search(r"(?<![\w.@$:])%s(?![\w?!(]*\s*=(?![=~]))(?![\w?!])" % re.escape(name), code):
                continue                                    # (not a bare call: after a dot - handled above)
            out += [source for cls, source in self.rets.get(name, ()) if cls in (owner, "")]
            if owner in self.readers.get(name, ()):
                found = self.field(owner, name, line)
                if found is not None:
                    out.append(found)
        return out

    def tainted(self, text: str, line: int) -> Optional[_Source]:
        """The download a piece of code uses (a tainted name in it, or an object), or None."""
        found = self.held(text, line) or self.objects(text, line)
        return found[0] if found else None

    def inline(self, text: str, line: int, offset: int = 0) -> Optional[_Source]:
        """A request written inside this piece of code."""
        code = _code_only(text)
        for m in _FETCH.finditer(code):
            what = re.sub(r"[\s(]+$", "", m.group(0))
            bracket = m.group(0).rstrip().endswith("(")
            values = self.src.values(line, offset + m.end(), bracket)
            first = values[0] if values else None
            if what.endswith("open") and what not in ("URI.open", "OpenURI.open_uri"):
                shown = show(first) if isinstance(first, (str, Sym)) else ""
                if "://" not in shown and not (self.open_uri and isinstance(first, Sym)):
                    continue                              # a file of this PC
            if what in ("URI", "URI.parse") and not _FETCH_READS.search(code[m.end():]):
                continue                                  # an address object, not a request
            if what.startswith(("TCPSocket", "UDPSocket")) and len(values) > 1 and \
                    isinstance(first, (str, Sym)):
                first = Sym("tcp://%s:%s" % (show(first), show(values[1]))) if isinstance(first, Sym) \
                    else "tcp://%s:%s" % (first, show(values[1]))
            kind, address = _classify(first, self.src.hidden(first))
            if kind == UNRESOLVED and not address:
                raw = self.src.raw_args(line, offset + m.end())
                address = raw[0][:80] if raw else ""
            if kind != LOCAL:
                return _Source(what.replace("Kernel.", ""), line, kind, address)
        return None

    def source_of(self, text: str, line: int, offset: int = 0) -> Optional[_Source]:
        return self.inline(text, line, offset) or self.tainted(text, line)

    # -- one pass over the lines ---------------------------------------------------------
    def run(self) -> List[Hit]:
        for final in [False] * _PASSES + [True]:
            self.changed = False
            for number, line in enumerate(self.src.lines, 1):
                self.clock.tick()
                if line.strip():
                    self.line(number, line, final)
            if not final:
                self._given()
            if not final and not self.changed:
                continue
        return self.hits

    def _given(self) -> None:
        """What every method gives back (``return x``, or its last statement) and what it
        hands to the block it is called with (``yield x``, ``block.call(x)``)."""
        lines = self.src.lines
        for name, entries in self.methods.items():
            for first, last, _params, owner, block in entries:
                self.clock.tick(4)
                body = range(first + 1, min(last, len(lines)) + 1)
                given = None
                for number in body:
                    line = lines[number - 1]
                    m = re.match(r"\s*return\b(.+)$", line)
                    if m and given is None:
                        given = self.source_of(m.group(1), number, m.start(1))
                    handed = _YIELD.search(line)
                    if handed is None and block and block in line:
                        handed = re.search(r"(?<![\w@$.])%s\s*\.\s*(?:call|yield)\b[ \t]*\(?(.*)$" % re.escape(block), line)
                    if handed is not None and name not in self.yields:
                        source = self.source_of(handed.group(1), number, handed.start(1))
                        if source is not None:
                            self.yields[name] = source
                            self.changed = True
                for number in reversed(body):
                    line = lines[number - 1]
                    if not line.strip() or re.match(r"\s*end\b", line):
                        continue
                    if given is None and not _ASSIGN.match(line):
                        given = self.source_of(line, number)
                    break
                known = self.rets.setdefault(name, [])
                if given is not None and all(cls != owner for cls, _source in known) and len(known) < 16:
                    known.append((owner, given))
                    self.changed = True

    def line(self, number: int, line: str, final: bool) -> None:
        self._api_calls(number, line, final)
        m = _ASSIGN.match(line)
        if m:
            source = self.source_of(m.group(2), number, m.start(2))
            for name in re.split(r"\s*,\s*", m.group(1)):
                self.mark(name, source, number)
            opened = _FILE_OPEN.search(m.group(2))
            if opened:
                self._remember_handle(m.group(1).strip(), number, m.start(2) + opened.end())
        m = _APPEND.match(line)
        if m:
            self.mark(m.group(1), self.source_of(m.group(2), number, m.start(2)), number)
        block = _BLOCK.search(line)
        if block:
            head = line[:block.start()]
            self.mark(block.group(1), self.source_of(head, number), number)
            opened = _FILE_OPEN.search(head)
            if opened:
                self._remember_handle(block.group(1), number, opened.end())
            if self.yields:                                 # fetch { |code| ... }: what fetch hands to its block
                for name in set(_TOKEN.findall(head)) & self.yields.keys():
                    self.mark(block.group(1), self.yields[name], number)
        m = _ATTR_WRITE.match(line)
        if m and (m.group(2) in self.writers or (m.group(2) + "=") in self.methods):
            source = self.source_of(m.group(3), number, m.start(3))     # obj.name = <download>
            if source is not None and max(len(self.writers.get(m.group(2), ())),
                                          len(self.methods.get(m.group(2) + "=", ()))) > _MAX_TARGETS:
                self._too_many(m.group(2))
            for cls in self.writers.get(m.group(2), ())[:_MAX_TARGETS]:
                self.mark("@" + m.group(2), source, number, owner=cls)
            for first, last, params, _owner, _block in self.methods.get(m.group(2) + "=", ())[:_MAX_TARGETS]:
                if params:
                    self.mark(params[0], source, first, (first, last))
        if self.lambdas:
            self._calls_to_lambdas(number, line)
        self._calls_to_methods(number, line)
        self._writes(number, line)
        if final:
            self._sinks(number, line)

    def _remember_handle(self, name: str, line: int, column: int) -> None:
        raw = self.src.raw_args(line, column)
        values = self.src.values(line, column)
        mode = raw[1] if len(raw) > 1 else ""
        if raw and re.search(r"[wa+]", mode):
            self.handles[name] = (line, raw[0], values[0] if values else None)

    def _calls_to_lambdas(self, number: int, line: str) -> None:
        """``run.call(x)`` / ``run.(x)`` / ``run[x]``: the block kept in ``run`` gets ``x``."""
        for name, (first, last, params) in self.lambdas.items():
            if not params or name not in line or first == number:
                continue
            for m in re.finditer(r"(?<![\w@$.])%s\s*(?:\.\s*(?:call|yield)\b[ \t]*\(?|\.\(|\[)" % re.escape(name), line):
                for index, raw in enumerate(self.src.raw_args(number, m.end())[:len(params)]):
                    self.mark(params[index], self.handed_in(raw, number, line), first, (first, last))

    def handed_in(self, raw: str, number: int, line: str) -> Optional[_Source]:
        """The download an argument is (a request written inside it is resolved at its own
        place in the line)."""
        at = line.find(raw)
        return self.source_of(raw, number, at if at >= 0 else 0)

    def _calls_to_methods(self, number: int, line: str) -> None:
        """What a call hands to a method of this script: a bare ``name(x)``, a call on an
        object (``obj.name(x)`` - every class that has such a method, ``Owner.name(x)`` -
        that class), and ``Owner.new(x)``, which reaches ``initialize``."""
        tokens = set(_TOKEN.findall(line))
        for name in tokens & self.methods.keys():
            entries = [e for e in self.methods[name] if e[2] and e[0] != number]
            if not entries or name == "initialize":
                continue
            for m in re.finditer(r"(?<![\w@$])%s(?![\w?!])[ \t]*(\(?)" % re.escape(name), line):
                if not m.group(1) and line[m.end():m.end() + 1] in ("", "=", ".", ")"):
                    continue
                if re.search(r"\bdef\s+(?:\w+\s*\.\s*)?$", line[:m.start()]):
                    continue                                # "def name(x)" of another class: no call
                before = re.search(r"([A-Z]\w*)\s*(?:\.|::)\s*$", line[:m.start()])
                chosen = [e for e in entries if before and e[3] == before.group(1)] or entries[:_MAX_TARGETS]
                raw_args = self.src.raw_args(number, m.end())
                if len(chosen) < len(entries) and not (before and chosen[0][3] == before.group(1)) \
                        and any(self.handed_in(raw, number, line) is not None for raw in raw_args):
                    self._too_many(name)                    # a download handed to obj.name(...)
                for first, last, params, _owner, _block in chosen:
                    for index, raw in enumerate(raw_args[:len(params)]):
                        self.mark(params[index], self.handed_in(raw, number, line), first, (first, last))
                        if raw.strip() in self.lambdas and params[index] not in self.lambdas \
                                and len(self.lambdas) < _MAX_LAMBDAS:
                            self.lambdas[params[index]] = self.lambdas[raw.strip()]     # a block handed on
        if "new" in tokens and "initialize" in self.methods:
            for m in _NEW.finditer(line):
                raw_args = self.src.raw_args(number, m.end())
                for first, last, params, owner, _block in self.methods["initialize"]:
                    if owner == m.group(1):
                        for index, raw in enumerate(raw_args[:len(params)]):
                            self.mark(params[index], self.handed_in(raw, number, line), first, (first, last))
        if "(" in line:                      # a download handed to a method of another script
            for m in _NEW.finditer(line):
                if m.group(2) and not any(e[3] == m.group(1) for e in self.methods.get("initialize", ())):
                    self._hand("rb:%s.new>" % m.group(1), number, m.end())
            for m in _OUT_CALL.finditer(line):
                if m.group(1) not in self.methods and m.group(1) not in _WORDS and m.group(1) != "new":
                    self._hand("rb:>%s" % m.group(1), number, m.end())

    def _too_many(self, name: str) -> None:
        """``obj.name`` stands for at most ``_MAX_TARGETS`` classes of the script. When a
        download goes that way and there are more, the classes behind the limit are not
        followed - said as a limit (SCRIPT-LIMIT-001; phageo, 2026-10-12), not left silent."""
        self.cut = V.also(self.cut, "more than %d classes for one obj.%s" % (_MAX_TARGETS, name[:40]))

    def _hand(self, key: str, number: int, column: int) -> None:
        if key in self.handed or len(self.handed) >= _MAX_SHARED:
            return
        line = self.src.lines[number - 1]
        for raw in self.src.raw_args(number, column)[:8]:
            source = self.handed_in(raw, number, line)
            if source is not None and source.what != SHARED:
                self.handed[key] = source
                return

    # -- Win32API calls ----------------------------------------------------------------
    def _api_sites(self, number: int, line: str):
        """``(function, column after the bracket)`` of each Win32API call on the line."""
        for m in re.finditer(r"(%s)\s*\.\s*(?:call|Call)\s*\(" % _NAME, line):
            function = self.api(m.group(1), number)
            if function:
                yield function, m.end()
        for m in _API_INLINE.finditer(line):
            rest = line[m.end():]
            call = re.search(r"\)\s*\.\s*(?:call|Call)\s*\(", rest)
            if call:
                yield m.group(4), m.end() + call.end()

    def _api_calls(self, number: int, line: str, final: bool) -> None:
        if "all" not in line:                                 # .call / .Call
            return
        for function, column in self._api_sites(number, line):
            raw = self.src.raw_args(number, column)
            values = self.src.values(number, column)
            if _DOWNLOADS.match(function) and len(raw) > 2:
                address = values[1] if len(values) > 1 else None
                if not isinstance(address, (str, Sym)):
                    known = self.src.nearest(raw[1], number)
                    address = known if known is not None else Sym(V.OPEN + raw[1][:60] + V.CLOSE)
                kind, shown = _classify(address, self.src.hidden(address))
                if kind != LOCAL:
                    self._drop(_Source(function, number, kind, shown), number, raw[2],
                               values[2] if len(values) > 2 else None)
            elif _OPENS_URL.match(function) and len(raw) > 1:
                address = values[1] if len(values) > 1 else None
                kind, shown = _classify(address, self.src.hidden(address))
                if kind == UNRESOLVED and not shown:
                    shown = raw[1][:80]
                if kind != LOCAL:
                    self.mark("\0wininet", _Source(function, number, kind, shown), number, (0, 1 << 30))
            elif _READS.match(function) and len(raw) > 1:
                opened = self.taint.get("\0wininet")
                name = re.match(_NAME, raw[1])
                if opened and name:
                    self.mark(name.group(0), opened[0][0], number)
            elif final and _STARTS.match(function):
                drop = self._dropped(" ".join(raw), values, number)
                if drop is not None:
                    self._hit("dropper", function, drop[0], number, drop[3])
                else:
                    source = self.tainted(" ".join(raw), number)
                    if source is not None:
                        self._hit("command", function, source, number)

    # -- files written from the network --------------------------------------------------
    def _drop(self, source: Optional[_Source], line: int, raw: str, value: Any) -> None:
        if source is None:
            return
        names = set()
        name = re.fullmatch(_NAME, raw.strip())
        if name:
            names.add("name:" + raw.strip())
            known = self.src.nearest(raw, line)
            if known and len(_leaf(known)) >= 3:
                names.add("file:" + _leaf(known))
        if isinstance(value, str) and len(_leaf(value)) >= 3:
            names.add("file:" + _leaf(value))
        literal = re.fullmatch(r"\s*(['\"])([^'\"]+)\1\s*", raw)
        if literal and len(_leaf(literal.group(2))) >= 3:
            names.add("file:" + _leaf(literal.group(2)))
        shown = show(value) if isinstance(value, (str, Sym)) else raw.strip()[:80]
        for item in names:
            if not any(d[2] == item and d[0].line == source.line for d in self.drops) and len(self.drops) < 200:
                self.drops.append((source, line, item, shown[:120]))
                self.changed = True

    def _dropped(self, raw: str, values: List[Any], line: int):
        if not self.drops:
            return None
        code = _code_only(raw)
        words = set()
        for value in values:
            if isinstance(value, (str, Sym)):
                words.update(_leaf(w) for w in re.split(r"[\s\"']+", V.known_part(show(value))) if w)
        words.update(_leaf(w) for w in re.findall(r"['\"]([^'\"\n]+)['\"]", raw))
        for part in re.findall(r"['\"]([^'\"\n]+)['\"]", raw):
            words.update(_leaf(w) for w in part.split())
        for source, at, item, shown in self.drops:
            if at > line:
                continue
            kind, _, name = item.partition(":")
            if kind == "file" and name in words:
                return source, at, item, shown
            if kind == "name" and re.search(r"(?<![\w@$.])%s(?![\w?!])" % re.escape(name), code):
                return source, at, item, shown
        return None

    def _writes(self, number: int, line: str) -> None:
        m = _FILE_WRITE.search(line)
        if m:
            raw = self.src.raw_args(number, m.end())
            if len(raw) > 1:
                values = self.src.values(number, m.end(), line[m.end() - 1:m.end()] == "(")
                self._drop(self.source_of(raw[1], number), number, raw[0], values[0] if values else None)
        m = _HANDLE_WRITE.match(line)
        if m and m.group(1) in self.handles:
            opened, raw, value = self.handles[m.group(1)]
            if opened <= number:
                self._drop(self.source_of(m.group(2), number, m.start(2)), number, raw, value)

    # -- sinks ----------------------------------------------------------------------
    def _hit(self, how: str, sink: str, source: _Source, line: int, detail: str = "") -> None:
        if len(self.hits) < _MAX_HITS and not any(
                h.source_line == source.line and h.line == line for h in self.hits):
            self.hits.append(Hit(how=how, line=line, sink=sink, source=source.what, source_line=source.line,
                                 kind=source.kind, address=source.address, detail=detail))

    def _sinks(self, number: int, line: str) -> None:
        for m in _EVAL.finditer(line):
            source = self.source_of(line[m.end():], number, m.end())
            if source is not None:
                self._hit("code", m.group(1) or m.group(2), source, number)
        for m in _COMMAND.finditer(line):
            rest, name = line[m.end():], m.group(1) or m.group(2)
            drop = self._dropped(rest, self.src.values(number, m.end(), m.group(0).rstrip().endswith("(")),
                                 number)
            if drop is not None:
                self._hit("dropper", name, drop[0], number, drop[3])
                continue
            source = self.source_of(rest, number, m.end())
            if source is not None:
                self._hit("command", name, source, number)
        for m in _TICKS.finditer(line):
            body = m.group(1) or m.group(2) or ""
            drop = self._dropped('"%s"' % body, [], number)
            source = drop[0] if drop is not None else self.tainted('"%s"' % body, number)
            if source is not None:
                self._hit("dropper" if drop is not None else "command", "`...`", source, number,
                          drop[3] if drop is not None else "")
        for m in _LOAD.finditer(line):
            rest = line[m.end():]
            drop = self._dropped(rest, self.src.values(number, m.end(), m.group(0).rstrip().endswith("(")),
                                 number)
            if drop is None and self.drops:                   # require "helper" for helper.rb
                named = re.match(r"""\s*['"]([\w./\\-]+)['"]""", rest)
                if named:
                    wanted = "file:" + _leaf(named.group(1)) + ".rb"
                    drop = next((d for d in self.drops if d[2] == wanted and d[1] <= number), None)
            if drop is not None:
                self._hit("dropper", m.group(1), drop[0], number, drop[3])


def analyse(text: str) -> List[Hit]:
    """What ``text`` (Ruby) executes that came from the network. Never raises."""
    return study(text)[0]


def study(text: str) -> Tuple[List[Hit], str]:
    """``(hits, cut)``: the same, and the limit the reading stopped at ("": none) - a count
    (steps, lines, size), so that the same file always gets the same answer. The clock
    is only an emergency brake; when it is what stopped the reading it is named."""
    if not text or not _HINT.search(text):
        return [], ""
    cut = "larger than %d MB" % (MAX_SOURCE >> 20) if len(text) > MAX_SOURCE else \
        "more than %d lines" % _MAX_LINES if text.count("\n", 0, MAX_SOURCE) > _MAX_LINES else ""
    flow, clock = None, Clock(MAX_STEPS, MAX_SECONDS)
    try:
        flow = _Flow(text, clock)
        hits = flow.run()
        return hits, V.also(cut, flow.cut)
    except Budget:
        cut = V.also(cut, "more than %d steps" % MAX_STEPS if clock.steps <= 0 else "%.0f seconds" % MAX_SECONDS)
        return (flow.hits if flow is not None else []), cut
    except RecursionError:
        return (flow.hits if flow is not None else []), cut or "nested too deeply"
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""


# -- across script sections -----------------------------------------------------------------------
# One script of a game stores a download under a name every script can reach, another
# runs what that name holds (the sections of Scripts.rxdata / .rvdata / .rvdata2 and the
# loose .rb files of a game are one program). Each script leaves a short summary here;
# the scanner joins them after the whole folder was scanned (dataflow/shared.py), one hop.
#
# What scripts share:   $globals;  constants (NAME, Module::NAME);  what a method gives back -
# a method at the top of a script, or of a class / module that any script can reopen
# ("Owner.name()": called as Owner.name / Owner::name, or by its bare name inside that
# class in another script);  and a file: one script writes a download to it, another
# starts it.
SHARED = "\0shared"
_SINK_HINT = re.compile(_IND[4])
_OWNER = re.compile(r"^(\s*)(?:class|module)\s+((?:[A-Z]\w*::)*[A-Z]\w*)")
_END = re.compile(r"^(\s*)end\b")
_GLOBAL = re.compile(r"\$[A-Za-z_]\w*")
_OWN_GLOBALS = frozenset("$stdout $stderr $stdin $PROGRAM_NAME $LOAD_PATH $LOADED_FEATURES $DEBUG $TEST $BTEST "
                         "$VERBOSE $KCODE $SAFE".split())
_CONSTANT_CALL = re.compile(r"(?<![\w:.@$])((?:[A-Z]\w*::)*[A-Z]\w*)(?:\.|::)([a-z_]\w*[?!]?)")
_SHARED_CONSTANT = re.compile(r"(?<![\w.@$:])(?:[A-Z]\w*::)*([A-Z]\w*)(?![\w(.:])")
_BARE = re.compile(r"(?<![\w.@$:'\"])([a-z_]\w*[?!]?)(?![\w:]|\s*=(?![=~]))")
_WORDS = frozenset("""if unless else elsif end while until do then and or not nil true false self return yield def
class module begin rescue ensure case when in for break next redo retry super puts print p pp require load
require_relative eval instance_eval class_eval module_eval instance_exec class_exec system exec spawn lambda proc
binding raise loop catch throw new call send open read write format sprintf rand sleep exit abort gets
defined? block_given? attr_accessor attr_reader attr_writer include extend private public protected alias""".split())
_NOTHING = re.compile(r"^\s*(?:nil|false|''|\"\"|\[\]|\{\}|0)?\s*$")
_FILE_WORD = re.compile(r"[^\s\"'\\/]+\.[A-Za-z0-9]{1,5}$")
_MAX_SHARED = 200                   # names of each kind one script shares
_MAX_KEYS = 12                      # shared names one expression can stand for


class Shared:
    """What one script shares with the other scripts of its game, in the form the join
    wants (:mod:`gamescan.dataflow.shared`): ``fills`` - shared name -> the download stored
    under it ``(request, line, kind, address)``; ``runs`` - shared name -> where its value
    is run ``(how, sink, line, detail)``; ``drops`` - ``file:<name>`` -> the download
    written to that file; ``starts`` - ``file:<name>`` -> where it is started ``(sink,
    line)``. ``cut``: a reading stopped at its limit ("": none)."""

    __slots__ = ("fills", "runs", "drops", "starts", "cut")

    def __init__(self) -> None:
        self.fills: Dict[str, tuple] = {}
        self.runs: Dict[str, tuple] = {}
        self.drops: Dict[str, tuple] = {}
        self.starts: Dict[str, tuple] = {}
        self.cut = ""

    def __bool__(self) -> bool:
        return bool(self.fills or self.runs or self.drops or self.starts)


def _owners(lines: List[str]) -> List[str]:
    """For every line: the class / module it stands in ("": none) - by the indentation of
    ``class`` / ``module`` and their ``end``, as RPG Maker's scripts are written."""
    out, stack = [], []
    for line in lines:
        closing = _END.match(line)
        if closing and stack and len(closing.group(1)) <= stack[-1][0]:
            out.append(stack[-1][1])
            stack.pop()
            continue
        opening = _OWNER.match(line)
        if opening and len(stack) < 32:
            stack.append((len(opening.group(1)), opening.group(2).rsplit("::", 1)[-1]))
        out.append(stack[-1][1] if stack else "")
    return out


class _SharedFlow(_Flow):
    """The second reading of a script: every name it shares with the other scripts stands
    for "whatever another script stored there", and the sinks such a value reaches are
    written down (``runs``) instead of reported."""

    def __init__(self, text: str, clock: Clock) -> None:
        super().__init__(text, clock)
        self.runs: Dict[str, tuple] = {}
        self.starts: Dict[str, tuple] = {}
        self.assigned = set()               # what this script sets itself: its own, not shared
        for line in self.src.lines:
            m = _ASSIGN.match(line)
            if m and not _NOTHING.match(m.group(2)):
                self.assigned.update(name.strip() for name in m.group(1).split(","))
            m = _BLOCK.search(line)
            if m:
                self.assigned.add(m.group(1))
        for _first, _last, params in self.defs.values():
            self.assigned.update(params)
        self.assigned.update(self.lambdas)
        # what a method of this script is handed by another script: "whatever was handed over"
        for name, entries in self.methods.items():
            for first, last, params, owner, _block in entries:
                key = "rb:%s.new>" % owner if name == "initialize" else "rb:>%s" % name
                for param in params:
                    self.mark(param, _Source(SHARED, first, UNRESOLVED, key), first, (first, last))

    def shared_in(self, text: str, line: int) -> Optional[_Source]:
        """The shared names ``text`` stands for (one source that names them all), or None."""
        code = _code_only(text)                 # (texts blanked, except what stands in #{...})
        keys: List[str] = []
        for m in _GLOBAL.finditer(code):
            if m.group(0) not in self.assigned and m.group(0) not in _OWN_GLOBALS:
                keys.append("rb:" + m.group(0))
        for m in _CONSTANT_CALL.finditer(code):
            keys.append("rb:%s.%s()" % (m.group(1).rsplit("::", 1)[-1], m.group(2)))
        for m in _SHARED_CONSTANT.finditer(code):
            if m.group(1) not in self.assigned:
                keys.append("rb:" + m.group(1))
        owner = self.owner_at(line)
        for m in re.finditer(r"(?<![\w@$])@([A-Za-z_]\w*)", code):       # a field of a class another script reopens
            if "@" + m.group(1) not in self.assigned:
                keys.append("rb:%s.@%s" % (owner, m.group(1)))
        for m in _MEMBER.finditer(code):                    # obj.name: a method / field of a class defined elsewhere
            if m.group(2) not in self.methods and m.group(2) not in self.readers and m.group(2) not in _WORDS \
                    and not m.group(1)[:1].isupper():
                keys.append("rb:.%s()" % m.group(2))
        for m in _BARE.finditer(code):
            name = m.group(1)
            if name in _WORDS or name in self.assigned or name in self.defs:
                continue
            keys.append("rb:%s()" % name)
            if owner:
                keys.append("rb:%s.%s()" % (owner, name))
        keys = list(dict.fromkeys(keys))[:_MAX_KEYS]
        return _Source(SHARED, line, UNRESOLVED, "|".join(keys)) if keys else None

    def tainted(self, text: str, line: int) -> Optional[_Source]:
        found = self.held(text, line) + self.objects(text, line)
        own = next((source for source in found if source.what != SHARED), None)
        if own is not None:
            return own
        # (every shared name in it counts, not only the first variable that holds one)
        keys: List[str] = []
        for source in found:
            keys += source.address.split("|")
        direct = self.shared_in(text, line)     # ... and the shared names written out in it
        if direct is not None:
            keys += direct.address.split("|")
        keys = list(dict.fromkeys(keys))[:_MAX_KEYS]
        return _Source(SHARED, line, UNRESOLVED, "|".join(keys)) if keys else None

    def _hit(self, how: str, sink: str, source: _Source, line: int, detail: str = "") -> None:
        if source.what != SHARED:
            return                              # a chain inside this script: the first reading's business
        for key in source.address.split("|"):
            if key and len(self.runs) < _MAX_SHARED:
                self.runs.setdefault("store:" + key, (how, sink, line, detail))

    def _started(self, sink: str, text: str, line: int) -> None:
        """The files a start names by a written-out name: another script may have written them."""
        for part in re.findall(r"['\"`]([^'\"`\n]+)['\"`]", text) or [text]:
            for word in part.split():
                leaf = _leaf(word)
                if _FILE_WORD.match(leaf) and len(self.starts) < _MAX_SHARED:
                    self.starts.setdefault("file:" + leaf, (sink, line))

    def _sinks(self, number: int, line: str) -> None:
        super()._sinks(number, line)
        for m in _COMMAND.finditer(line):
            self._started(m.group(1) or m.group(2), line[m.end():], number)
        for m in _TICKS.finditer(line):
            self._started("`...`", '"%s"' % (m.group(1) or m.group(2) or ""), number)
        for m in _LOAD.finditer(line):
            self._started(m.group(1), line[m.end():], number)
        if "all" in line:
            for function, column in self._api_sites(number, line):
                if _STARTS.match(function):
                    self._started(function, " ".join(self.src.raw_args(number, column)), number)


def _limit(clock: Clock) -> str:
    return "more than %d steps" % MAX_STEPS if clock.steps <= 0 else "%.0f seconds" % MAX_SECONDS


def shared(text: str) -> Shared:
    """What the Ruby script ``text`` shares with the other scripts of its game. Never raises."""
    out = Shared()
    if not text:
        return out
    net, sink = _HINT.search(text) is not None, _SINK_HINT.search(text) is not None
    if not net and not sink:
        return out
    try:
        if net:                                 # what it stores from a download
            clock = Clock(MAX_STEPS, MAX_SECONDS)
            flow = _Flow(text, clock)
            try:
                flow.run()
            except Budget:
                out.cut = _limit(clock)
            except RecursionError:
                out.cut = "nested too deeply"
            for name, entries in sorted(flow.taint.items()):
                if (name[:1] == "$" or name[:1].isupper()) and entries and len(out.fills) < _MAX_SHARED:
                    source = entries[0][0]
                    out.fills["store:rb:" + name] = (source.what, source.line, source.kind, source.address)
            def fill(key: str, source: _Source) -> None:
                if len(out.fills) < 2 * _MAX_SHARED:
                    out.fills.setdefault("store:" + key, (source.what, source.line, source.kind, source.address))

            for name, entries in sorted(flow.taint.items()):
                if ".@" in name and entries:                # a field of a class: "Owner.@x"
                    fill("rb:" + name, entries[0][0])
                    cls, _, field = name.partition(".@")
                    if cls in flow.readers.get(field, ()):  # ... that can be read from outside: obj.x
                        fill("rb:.%s()" % field, entries[0][0])
            for name, given in sorted(flow.rets.items()):  # what a method gives back
                for owner, source in given:
                    fill("rb:%s.%s()" % (owner, name) if owner else "rb:%s()" % name, source)
                    fill("rb:.%s()" % name, source)         # (called on an object: obj.name)
            for key, source in sorted(flow.handed.items()): # what it hands to a method of another script
                fill(key, source)
            out.cut = V.also(out.cut, flow.cut)
            for source, line, item, shown in flow.drops:
                if item.startswith("file:") and len(out.drops) < _MAX_SHARED:
                    out.drops.setdefault(item, (source.what, source.line, source.kind, source.address, shown))
        if sink:                                # what it runs that another script may have stored
            clock = Clock(MAX_STEPS, MAX_SECONDS)
            second = None
            try:
                second = _SharedFlow(text, clock)
                second.run()
            except Budget:
                out.cut = V.also(out.cut, _limit(clock))
            except RecursionError:
                out.cut = V.also(out.cut, "nested too deeply")
            if second is not None:
                out.runs, out.starts = second.runs, second.starts
                out.cut = V.also(out.cut, second.cut)
    except Exception:                    # an analysis aid must never break the scan itself
        pass
    return out


# -- ShellExecute: what is opened --------------------------------------------------------------
def opened_target(verb: Any, target: Any) -> Tuple[str, str]:
    """``(level, what)`` for one ShellExecute call: LOW for an https address or
    a document of the game, MEDIUM for an address that is harder to judge,
    HIGH for a program, a script, anything outside the game folder - and for
    whatever could not be resolved."""
    if isinstance(verb, str) and verb.strip().lower() not in ("", "open"):
        return HIGH, "verb %s" % verb.strip()[:20]
    if not isinstance(target, str) or not target.strip() or V.is_partial(target):
        return HIGH, "not resolved" + (" (%s)" % show(target)[:80] if isinstance(target, (str, Sym)) else "")
    text = target.strip()
    web = _HOST.match(text)
    if web:
        host = web.group(2)
        plain = web.group(1).lower() == "https" and not _IP.match(host) and not _SHORTENERS.match(host) \
            and "." in host
        return (LOW if plain else MEDIUM), text[:200]
    if re.match(r"mailto:[\w.+-]+@[\w.-]+$", text, re.I):
        return LOW, text[:200]
    if re.match(r"[a-z][a-z0-9+.-]*:", text, re.I) and not re.match(r"[A-Za-z]:[\\/]", text):
        return HIGH, text[:200]                               # file:, shell:, ms-settings: ...
    if _BAD_PATH.search(text):
        return HIGH, text[:200]
    extension = re.search(r"\.[A-Za-z0-9]{1,6}$", text)
    if extension is None:
        return MEDIUM, text[:200]                             # a folder, or a file without a type
    return (LOW if extension.group(0).lower() in _DOCUMENTS else HIGH), text[:200]


class Opened(NamedTuple):
    level: str                   # LOW, MEDIUM or HIGH over all calls
    what: List[str]              # what the calls open (or why a call counts as HIGH)
    calls: int                   # ShellExecute calls that were read
    handles: Tuple[str, ...]     # the names the function was declared under


def shell_execute(text: str) -> Optional[Opened]:
    """What every ``ShellExecute`` call of a Ruby text opens, or None when the
    text declares no ``ShellExecute``. A declaration that is never called, or
    one call that cannot be resolved, keeps it HIGH."""
    found = _shell_execute(text)
    return None if found is None else Opened(*found)


def _shell_execute(text: str):
    if not text or _IND[5] not in text:
        return None
    try:
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        flow = _Flow(text, clock)
        declared = {handle for handle, items in flow.apis.items()
                    if any(_SHELL_EXECUTE.match(name) for _line, name in items)}
        inline = any(_SHELL_EXECUTE.match(m.group(4)) for m in _API_INLINE.finditer(flow.src.code))
        if not declared and not inline:
            return None
        level, opened, calls = LOW, [], 0
        for number, line in enumerate(flow.src.lines, 1):
            clock.tick()
            if "all" not in line:
                continue
            for function, column in flow._api_sites(number, line):
                if not _SHELL_EXECUTE.match(function):
                    continue
                calls += 1
                raw = flow.src.raw_args(number, column)
                values = flow.src.values(number, column)
                picked = []
                for index in (1, 2):
                    value = values[index] if index < len(values) else None
                    if index < len(raw):
                        # a plain name: the literal most recently assigned to it above
                        known = flow.src.nearest(raw[index], number)
                        value = known if known is not None else value
                    if value is None and index < len(raw) and raw[index].strip() in ("nil", "0", "''", '""'):
                        value = ""
                    picked.append(value)
                if flow.src.hidden(picked[1]):
                    one, what = HIGH, "decoded: %s" % show(picked[1])[:80]
                else:
                    one, what = opened_target(picked[0], picked[1])
                if _RANK[one] > _RANK[level]:
                    level = one
                if what not in opened and len(opened) < 4:
                    opened.append(what)
        # every use of a declared handle must be one of the calls that were read
        bare = "\n".join(_code_only(line) for line in flow.src.lines)      # not inside strings
        uses = sum(len(re.findall(r"(?<![\w@$.])%s(?![\w?!])" % re.escape(handle), bare))
                   for handle in declared)
        declarations = sum(len(items) for handle, items in flow.apis.items() if handle in declared)
        handles = tuple(sorted(declared))
        if calls == 0 or uses > declarations + calls:
            return HIGH, opened or ["no call could be read"], calls, handles
        return level, opened, calls, handles
    except (Budget, RecursionError):
        return HIGH, ["analysis limit reached"], 0, ()
    except Exception:
        return None

# -- files of the game itself: what File.delete removes, what SetFileAttributes changes ---------
_SET_ATTRIBUTES = re.compile(r"^SetFileAttributes[AW]?$", re.I)
_PLAIN_ATTRIBUTES = 0x01 | 0x02 | 0x20 | 0x80             # read-only, hidden, archive, normal
_CONSTANT = r"(?:[A-Z]\w*::)*[A-Z]\w*"
_TERM = r"""'[^'\\\n]*'|"[^"\\\n]*"|%s""" % _CONSTANT
_JOINED = re.compile(r"\s*(?:%s)(?:\s*\+\s*(?:%s))*\s*" % (_TERM, _TERM))
# "#{index + 1}": a number counted from a name - it cannot be a piece of a path
_NUMBERED = re.compile(r"#\{\s*(?:[a-z_]\w*\s*[+\-*]\s*\d+|\d+\s*[+\-*]\s*[a-z_]\w*|[a-z_]\w*\.to_i)\s*\}")
_DELETES = re.compile(r"\bFile\.(?:delete|unlink)\b[ \t]*(\(?)")
_PROGRAMS = frozenset(".exe .dll .scr .com .bat .cmd .ps1 .vbs .vbe .js .jse .wsf .hta .lnk .rb .rbw "
                      ".msi .pif .cpl .sys .jar .py .reg .url".split())
_ENGINE_FOLDERS = frozenset("data graphics audio system fonts movies".split())
_OWN_DEPTH = 4


def own_path(path: str, in_folder: bool) -> bool:
    """Is ``path`` a file or folder of the game itself that is neither part of
    the engine nor a program: relative, never leaving the game's folder, not
    under ``Data`` / ``Graphics`` / ``Audio`` ..., no program or script
    extension. ``in_folder`` asks for a file inside a sub-folder."""
    text = path.strip()
    if not text or text != path or _BAD_PATH.search(text) or ":" in text or "#{" in text:
        return False
    parts = re.split(r"[\\/]", text)
    if any(not part or part.strip(". ") != part for part in parts):
        return False                                      # empty, ".", "..", "name." or "name "
    if parts[0].lower() in _ENGINE_FOLDERS or (in_folder and len(parts) < 2):
        return False
    extension = re.search(r"\.[^.]+$", parts[-1])
    return extension is None or extension.group(0).lower() not in _PROGRAMS


class _Own:
    """What a path expression is made of: quoted text, constants that are given
    one literal and never changed, a name of the method that is set from such
    values, and methods of the script that return nothing else."""

    def __init__(self, flow: _Flow) -> None:
        self.flow = flow
        self.lines = flow.src.lines
        self.bare = [_code_only(line) for line in self.lines]            # not inside strings

    def constant(self, name: str) -> Optional[str]:
        leaf = name.rsplit("::", 1)[-1]
        found = self.flow.src.literal.get(leaf, ())
        if len(found) != 1:
            return None
        changed = re.compile(r"(?<![\w@$.])%s(?![\w?!])\s*(?:<<|\[|\.\s*\w+!|\.\s*(?:replace|concat|insert"
                             r"|prepend|clear|force_encoding|instance_\w+|send|__send__)\b"
                             r"|(?:\|\||&&|[+\-*/%%])?=(?![=~>]))" % re.escape(leaf))
        writes = sum(len(changed.findall(line)) for line in self.bare)
        return found[0][1] if writes == 1 else None       # the one assignment, and nothing else

    def _scope(self, line: int) -> Tuple[int, int, List[str]]:
        for first, last, params in self.flow.defs.values():
            if first <= line <= last:
                return first, last, params
        return 1, len(self.lines), []

    def _local(self, name: str, line: int, depth: int) -> Tuple[bool, Optional[List[str]]]:
        """``(is it a name of this method, its paths)`` - every value it is given counts."""
        first, last, params = self._scope(line)
        if name in params:
            return True, None
        written = re.compile(r"(?<![\w@$.:])%s(?![\w?!(])\s*(?:<<|(?:\|\||&&|[+\-*/%%])?=(?![=~>]))"
                             % re.escape(name))
        out: List[str] = []
        bound = False
        for number in range(first, last + 1):
            self.flow.clock.tick()
            bare = self.bare[number - 1]
            loop = re.match(r"\s*for\s+%s\s+in\s+\[" % re.escape(name), bare)
            block = re.search(r"\|[^|\n]*(?<![\w@$])%s(?!\w)[^|\n]*\|" % re.escape(name), bare)
            if loop:
                items = self.flow.src.raw_args(number, loop.end())
                rest = self.lines[number - 1][loop.end():]
                if not items or not re.search(r"\]\s*(?:do\s*)?$", rest):
                    return True, None
            elif block:
                return True, None                         # a block's name: not followed
            elif written.search(bare):
                m = re.match(r"\s*%s\s*=(?![=~>])\s*(.+?)\s*$" % re.escape(name), self.lines[number - 1])
                if m is None or len(written.findall(bare)) != 1:
                    return True, None
                items = [m.group(1)]
            else:
                continue
            bound = True
            for item in items:
                paths = self.paths(item, number, depth + 1)
                if paths is None:
                    return True, None
                out.extend(paths)
        return bound, (out if bound else None)

    def _returned(self, name: str, depth: int) -> Optional[List[str]]:
        if sum(len(re.findall(r"\bdef\s+(?:self\.)?%s(?![\w?!])" % re.escape(name), line))
               for line in self.bare) != 1:
            return None
        first, last, _params = self.flow.defs[name]
        body = [(number, self.lines[number - 1].strip()) for number in range(first + 1, last + 1)]
        body = [(number, line) for number, line in body if line and line != "end"]
        if len(body) > 1 and not all(line.startswith("return ") for _number, line in body):
            return None
        out: List[str] = []
        for number, line in body:
            paths = self.paths(line[7:] if line.startswith("return ") else line, number, depth + 1)
            if paths is None:
                return None
            out.extend(paths)
        return out or None

    def paths(self, raw: str, line: int, depth: int = 0) -> Optional[List[str]]:
        """Every path ``raw`` can stand for at ``line``, or None when one of
        them is not known."""
        self.flow.clock.tick(5)
        raw = raw.strip()
        if depth > _OWN_DEPTH or not raw:
            return None
        if _JOINED.fullmatch(raw):
            out = ""
            for term in re.finditer(_TERM, raw):
                text = term.group(0)
                if text[0] == "'":
                    out += text[1:-1]
                elif text[0] == '"':
                    out += _NUMBERED.sub("0", text[1:-1])
                else:
                    value = self.constant(text)
                    if value is None:
                        return None
                    out += value
            return None if "#{" in out or "\\" in out else [out]
        m = re.fullmatch(r"(?:self\.)?([a-z_]\w*[?!]?)\s*(\(.*\))?", raw)
        if m is None:
            return None
        name = m.group(1)
        if m.group(2) is None:
            local, paths = self._local(name, line, depth)
            if local:
                return paths
        return self._returned(name, depth) if name in self.flow.defs else None


def own_deletes(text: str) -> Dict[int, List[str]]:
    """``{line: paths}`` for the lines whose every ``File.delete`` /
    ``File.unlink`` removes only files of the game itself (:func:`own_path`,
    inside a sub-folder). A line with one path that is not known is left out."""
    if not text or not re.search(r"File\.(?:delete|unlink)", text):
        return {}
    out: Dict[int, List[str]] = {}
    try:
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        flow = _Flow(text, clock)
        own = _Own(flow)
        for number, bare in enumerate(own.bare, 1):
            clock.tick()
            found: Optional[List[str]] = []
            for m in _DELETES.finditer(bare):
                items = flow.src.raw_args(number, m.end()) if m.group(1) else []
                paths = [own.paths(item, number) for item in items]
                if not paths or any(p is None or not all(own_path(one, True) for one in p) for p in paths):
                    found = None
                    break
                found.extend(one for p in paths for one in p)
            if found:
                out[number] = list(dict.fromkeys(found))[:4]
        return out
    except (Budget, RecursionError):
        return {}
    except Exception:
        return {}


class Attributes(NamedTuple):
    lines: Tuple[int, ...]       # where SetFileAttributes is declared
    what: List[str]              # the folders / files of the game its calls change


def own_attributes(text: str) -> Optional[Attributes]:
    """The ``SetFileAttributes`` declarations of a Ruby text whose every call
    was read and only sets plain attributes (hidden, normal, read-only,
    archive) on a folder or file of the game itself - else None."""
    if not text or "SetFileAttributes" not in text:
        return None
    try:
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        flow = _Flow(text, clock)
        own = _Own(flow)
        declared = {handle for handle, items in flow.apis.items()
                    if any(_SET_ATTRIBUTES.match(name) for _line, name in items)}
        if not declared or any(not _SET_ATTRIBUTES.match(name) for handle in declared
                               for _line, name in flow.apis[handle]):
            return None
        declarations = sum(len(flow.apis[handle]) for handle in declared)
        if sum(1 for m in _API_INLINE.finditer(flow.src.code) if _SET_ATTRIBUTES.match(m.group(4))) \
                != declarations:
            return None                                   # one that is called where it is made
        what: List[str] = []
        calls = 0
        for number, line in enumerate(flow.src.lines, 1):
            clock.tick()
            if "all" not in line:
                continue
            for function, column in flow._api_sites(number, line):
                if not _SET_ATTRIBUTES.match(function):
                    continue
                calls += 1
                raw = flow.src.raw_args(number, column)
                if len(raw) != 2 or not re.fullmatch(r"0[xX][0-9A-Fa-f]{1,8}|\d{1,9}", raw[1]):
                    return None
                if int(raw[1], 0) & ~_PLAIN_ATTRIBUTES:
                    return None
                paths = own.paths(raw[0], number)
                if paths is None or not all(own_path(one, False) for one in paths):
                    return None
                what.extend(paths)
        uses = sum(len(re.findall(r"(?<![\w@$.])%s(?![\w?!])" % re.escape(handle), line))
                   for handle in declared for line in own.bare)
        if calls == 0 or uses > declarations + calls:
            return None
        lines = tuple(sorted(line for handle in declared for line, _name in flow.apis[handle]))
        return Attributes(lines, list(dict.fromkeys(what))[:4])
    except (Budget, RecursionError):
        return None
    except Exception:
        return None
