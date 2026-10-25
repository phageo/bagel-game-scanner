"""Remote code execution in VBScript (``.vbs``, and the VBScript blocks of ``.wsf`` and
``.hta`` files): does what the script runs come from the network?

The counterpart of :mod:`gamescan.dataflow.remote_sh` for the Windows Script Host:

``source``  a request object - ``MSXML2.XMLHTTP``, ``Microsoft.XMLHTTP``,
            ``MSXML2.ServerXMLHTTP``, ``WinHttp.WinHttpRequest`` (any version) - and
            what it hands back: ``responseBody`` / ``responseText`` /
            ``responseStream`` / ``responseXML``
``flow``    the answer is kept in a variable, handed to a ``Sub`` / ``Function`` of the
            script, or written to a file: ``ADODB.Stream`` ``Write`` + ``SaveToFile``,
            or a file of ``Scripting.FileSystemObject`` (``CreateTextFile`` /
            ``OpenTextFile`` + ``Write``)
``sink``    ... and is run: ``Execute`` / ``ExecuteGlobal`` / ``Eval`` on the text, or
            the written file is started with ``WScript.Shell`` ``Run`` / ``Exec`` or
            ``Shell.Application`` ``ShellExecute``

The name of an object (``CreateObject("...")``) is worked out through variables
and joined texts (``a = "WScript" : b = a & ".Shell"``, ``Chr``, ``StrReverse``).
A request object whose name cannot be worked out is still known by what is read
from it (``.responseBody`` ...). ``GetObject("script:http://...")`` and a ``.wsf``
/ ``.hta`` ``<script src="http://...">`` load a remote script by themselves and are
reported as loaders. The command lines the script starts are returned as well:
they are PowerShell / batch and are read by that tracer.

A tracer over statements, not a parser, and not an interpreter: variables are
followed by name (one script-wide set of names, whatever ``Sub`` they are in),
branches are not taken, the script is read twice so that a ``Sub`` defined below
its call is known. Nothing is executed. Limits as for PowerShell.

Not read: encoded scripts (``.vbe``), JScript blocks, classes (``Class`` ...
``End Class`` is read as plain statements), ``ExecuteGlobal`` of a text that is
itself built to download (the text is not parsed again).
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_vbs.py")

import re
from typing import Dict, List, NamedTuple, Optional, Tuple

from ..rules import mask_comments
from . import values as V
from .remote import REMOTE, UNRESOLVED, Hit
from .textflow import MAX_SOURCE

MAX_STEPS = 300_000                 # statements looked at (both readings)
_MAX_LINES = 50_000
_MAX_LINE = 20_000                  # characters of one statement
_MAX_HITS = 8
_MAX_COMMANDS = 200
_MAX_DEPTH = 12                     # joined texts inside joined texts


_REQUEST = re.compile(r"(?i)^(?:msxml2|microsoft)\.(?:server)?xmlhttp(?:\.\d+(?:\.\d+)?)?$|^winhttp\.winhttprequest(?:\.\d+(?:\.\d+)?)?$")
_KINDS = (("stream", re.compile(r"(?i)^adodb\.stream$")), ("shell", re.compile(r"(?i)^wscript\.shell$")),
          ("app", re.compile(r"(?i)^shell\.application$")), ("fso", re.compile(r"(?i)^scripting\.filesystemobject$")))
_ANSWER = re.compile(r"(?i)\b([A-Za-z_]\w*)\s*\.\s*(responsebody|responsetext|responsestream|responsexml)\b")
_CREATE = re.compile(r"(?i)\b(?:wscript\s*\.\s*)?(createobject|getobject)\s*\(")
_NAME = re.compile(r"[A-Za-z_]\w*")
_STRING = re.compile(r'"(?:[^"]|"")*"')
_HELD = re.compile(r"\x00(\d+)\x00")
_ASSIGN = re.compile(r"(?i)^\s*(?:set\s+|const\s+|let\s+)?([A-Za-z_]\w*)\s*=(?!=)\s*(.+)$", re.S)
_PROC = re.compile(r"(?i)^\s*(?:public\s+|private\s+)?(?:default\s+)?(sub|function)\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?")
_IF = re.compile(r"(?i)^\s*(?:else)?if\b.*?\bthen\b(.*)$", re.S)
_CALL = re.compile(_IND[0])
_INLINE = re.compile(_IND[1])
_EXECUTE = re.compile(r"(?i)(?:^|[\s:(=])(executeglobal|execute|eval)\b\s*\(?")
_LOCAL_URL = re.compile(r"(?i)^(?:https?|ftp)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?:[:/]|$)")
_REMOTE_URL = re.compile(r"(?i)^(?:https?|ftp)://")
_FILE = re.compile(r"[^\\/\s\"]+\.[A-Za-z0-9]{1,8}$")
_BLOCK = re.compile(r"(?is)<script\b([^>]*[^/>])?>(.*?)</script\s*>")
_TAG = re.compile(r"(?is)<script\b([^>]*)>")
_ATTRIBUTE = re.compile(r"""(?is)\b(language|type|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_KEYWORDS = frozenset("""and as call case const dim do each else elseif empty end eqv error exit false for function
get if imp in is let loop me mod new next not nothing null on option or preserve private public redim rem resume
select set step stop sub then to true until wend while with xor createobject getobject wscript chr chrw strreverse
lcase ucase trim cstr replace mid left right len""".split())


class Download(NamedTuple):
    source: str             # "http.responseBody"
    line: int
    kind: str               # REMOTE, UNRESOLVED
    address: str


class Result(NamedTuple):
    hits: List[Hit]
    commands: List[Tuple[int, str]]     # (line, command line the script starts)
    cut: str = ""                       # "": read to the end - or the limit that was reached


class _Limit(Exception):
    pass


class _Var:
    __slots__ = ("kind", "addresses", "download", "dropped", "texts", "path", "names")

    def __init__(self) -> None:
        self.kind = ""                  # request, stream, shell, app, fso, file, object (a name not worked out)
        self.addresses: List[Optional[str]] = []    # a request object: where it was opened to (None: not worked out)
        self.download: Optional[Download] = None    # the value came from a download
        self.dropped: Optional[Download] = None     # the value is the path of a file a download was written to
        self.texts: List[str] = []      # the texts it was set to (one: a constant)
        self.path = ""                  # a file object: its path, when it could be worked out
        self.names: List[str] = []      # ... and the variables its path was given with


def _split(text: str, separator: str) -> List[str]:
    """``text`` cut at ``separator`` outside brackets (texts are held back already)."""
    out, depth, start = [], 0, 0
    for at, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        elif char == separator and depth == 0:
            out.append(text[start:at])
            start = at + 1
    out.append(text[start:])
    return out


class _Flow:
    def __init__(self) -> None:
        self.vars: Dict[str, _Var] = {}
        self.procs: Dict[str, List[str]] = {}
        self.texts: List[str] = []          # the texts of the statement at hand, held back
        self.dropped_files: Dict[str, Download] = {}
        self.hits: List[Hit] = []
        self.commands: List[Tuple[int, str]] = []
        self.steps = 0
        self.final = False
        self.cut = ""

    def var(self, name: str) -> _Var:
        name = name.lower()
        if name not in self.vars:
            if len(self.vars) > 20_000:
                raise _Limit()
            self.vars[name] = _Var()
        return self.vars[name]

    # -- texts -------------------------------------------------------------------------
    def value(self, expr: str, depth: int = 0) -> Optional[str]:
        """The text ``expr`` stands for, when it can be worked out: texts, variables that
        hold one text, ``&`` / ``+``, ``Chr``, ``StrReverse``, ``LCase`` / ``UCase`` / ``Trim``."""
        if depth > _MAX_DEPTH:
            return None
        parts = []
        for piece in _split(expr.replace("+", "&"), "&"):
            piece = piece.strip()
            while piece.startswith("(") and piece.endswith(")") and len(_split(piece[1:-1], ",")) == 1 \
                    and piece[1:-1].count("(") == piece[1:-1].count(")"):
                piece = piece[1:-1].strip()
            held = _HELD.fullmatch(piece)
            if held:
                parts.append(self.texts[int(held.group(1))])
                continue
            call = re.fullmatch(r"(?is)(chrw?|strreverse|lcase|ucase|trim|cstr)\s*\((.*)\)", piece)
            if call:
                name, inner = call.group(1).lower(), call.group(2)
                if name.startswith("chr"):
                    if not inner.strip().isdigit() or int(inner) > 0x10FFFF:
                        return None
                    parts.append(chr(int(inner)))
                    continue
                text = self.value(inner, depth + 1)
                if text is None:
                    return None
                parts.append(text[::-1] if name == "strreverse" else text.lower() if name == "lcase"
                             else text.upper() if name == "ucase" else text.strip() if name == "trim" else text)
                continue
            if _NAME.fullmatch(piece) and piece.lower() in self.vars and len(self.vars[piece.lower()].texts) == 1:
                parts.append(self.vars[piece.lower()].texts[0])
                continue
            return None
        return "".join(parts)[:4000]

    def names(self, expr: str) -> List[str]:
        return [name.lower() for name in _NAME.findall(_HELD.sub(" ", expr)) if name.lower() not in _KEYWORDS]

    def shown(self, expr: str) -> str:
        return _HELD.sub(lambda m: '"%s"' % self.texts[int(m.group(1))], expr).strip()[:120]

    # -- what an expression carries ------------------------------------------------------
    def download_in(self, expr: str, line: int) -> Optional[Download]:
        """The download ``expr`` holds: an answer read from a request object, or a variable
        that was set from one."""
        for match in _ANSWER.finditer(expr):
            request = self.vars.get(match.group(1).lower())
            addresses = request.addresses if request is not None else []
            known = [a for a in addresses if a is not None]
            if addresses and len(known) == len(addresses) and all(_LOCAL_URL.match(a) for a in known):
                continue                                    # asked of this PC only
            remote = sorted(a for a in known if not _LOCAL_URL.match(a))
            source = "%s.%s" % (match.group(1), match.group(2))
            if remote:
                return Download(source, line, REMOTE, remote[0][:300])
            return Download(source, line, UNRESOLVED, "")
        for name in self.names(expr):
            held = self.vars.get(name)
            if held is not None and held.download is not None:
                return held.download
        return None

    def dropped_in(self, expr: str) -> Optional[Tuple[Download, str]]:
        """``(download, file)`` when ``expr`` names a file a download was written to."""
        for name in self.names(expr):
            held = self.vars.get(name)
            if held is not None and held.dropped is not None:
                return held.dropped, name
        texts = [self.texts[int(n)] for n in _HELD.findall(expr)]
        whole = self.value(expr)
        for text in texts + ([whole] if whole else []):
            lowered = text.lower()
            for file, download in sorted(self.dropped_files.items()):
                if file in lowered:
                    return download, file
        return None

    def drop(self, path: str, download: Download) -> None:
        """``download`` was written to the file ``path`` names: the variable that holds the
        path (of a joined path that cannot be worked out: its last part, the file), and
        the file's name when the path can be worked out."""
        self.drop_at(self.names(path), self.value(path), download)

    def drop_at(self, names: List[str], text: Optional[str], download: Download) -> None:
        if names and (len(names) == 1 or text is None):
            held = self.var(names[-1])
            if held.dropped is None:
                held.dropped = download
        if text:
            leaf = _FILE.search(text.strip())
            if leaf and len(self.dropped_files) < 256:
                self.dropped_files.setdefault(leaf.group(0).lower(), download)

    def hit(self, how: str, line: int, sink: str, download: Download, detail: str = "") -> None:
        if not self.final or len(self.hits) >= _MAX_HITS:
            return
        if any(h.line == line and h.sink == sink for h in self.hits):
            return
        self.hits.append(Hit(how, line, sink, download.source, download.line, download.kind, download.address, detail))

    # -- objects -------------------------------------------------------------------------
    def kind_of(self, expr: str) -> str:
        """What ``CreateObject(...)`` in ``expr`` makes ("": none there)."""
        match = _CREATE.search(expr)
        if match is None:
            return ""
        arguments = _split(self._arguments(expr[match.end():]), ",")
        if match.group(1).lower() == "getobject" and len(arguments) > 1:
            return ""                                       # GetObject(, "Word.Application"): a running program
        name = self.value(arguments[0])
        if name is None:
            return "object"
        name = name.strip()
        if match.group(1).lower() == "getobject":
            return "loader:" + name if name.lower().startswith("script:") else ""
        if _REQUEST.match(name):
            return "request"
        for kind, pattern in _KINDS:
            if pattern.match(name):
                return kind
        return ""

    # -- one statement -------------------------------------------------------------------
    def statement(self, text: str, line: int) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise _Limit()
        text = text[:_MAX_LINE].strip()
        if not text:
            return
        branch = _IF.match(text)
        if branch:                                          # If ... Then <statement> [Else <statement>]
            for part in re.split(r"(?i)\belse\b", branch.group(1)):
                if part.strip() and not re.fullmatch(r"(?i)\s*end\s+if\s*", part):
                    self.statement(part, line)
            return
        proc = _PROC.match(text)
        if proc:
            params = [re.sub(r"(?i)\b(byval|byref)\b", "", p).strip().lower() for p in (proc.group(3) or "").split(",")]
            self.procs[proc.group(2).lower()] = [p for p in params if p]
            return
        # a remote script loaded by GetObject("script:...")
        made = self.kind_of(text)
        if made.startswith("loader:"):
            address = made[len("loader:") + len("script:"):].strip()
            if _REMOTE_URL.match(address) and not _LOCAL_URL.match(address):
                self.hit("loader", line, "GetObject(\"script:...\")", Download("", line, REMOTE, address[:300]))
            made = ""
        assigned = _ASSIGN.match(text)
        target = assigned.group(1).lower() if assigned and assigned.group(1).lower() not in _KEYWORDS else ""
        expr = assigned.group(2) if target else text
        # -- calls on objects -----------------------------------------------------------
        for match in _CALL.finditer(text):
            name, method = match.group(1).lower(), match.group(2).lower()
            held = self.vars.get(name)
            kind = held.kind if held is not None else ""
            arguments = _split(self._arguments(text[match.end():]), ",")
            if method == "open" and kind in ("request", "object") and len(arguments) > 1:
                address = self.value(arguments[1])
                if kind == "request" or (address and _REMOTE_URL.match(address)):
                    held.kind = "request"
                    if address not in held.addresses and len(held.addresses) < 16:
                        held.addresses.append(address)
            elif method in ("write", "writetext", "writeline") and held is not None:
                download = self.download_in(",".join(arguments), line)
                if download is not None:
                    if kind == "file":
                        self.drop_at(held.names, held.path or None, download)
                    else:                                   # a stream: saved to its file later
                        held.download = held.download or download
            elif method == "savetofile" and held is not None and held.download is not None:
                self.drop(arguments[0], held.download)
            elif method in ("createtextfile", "opentextfile") and target:
                made_file = self.var(target)
                # (kept worked out: the texts of this line are gone when the file is written to)
                made_file.kind, made_file.names = "file", self.names(arguments[0])
                made_file.path = self.value(arguments[0]) or ""
            elif method in ("run", "exec", _IND[2]) and kind in ("shell", "app", "object"):
                self.start(arguments[:2] if method == _IND[2] else arguments[:1], line,
                           "%s.%s" % (match.group(1), match.group(2)))
        for match in _INLINE.finditer(text):                # CreateObject("WScript.Shell").Run ...
            if made in ("shell", "app", "object"):
                arguments = _split(self._arguments(text[match.end():]), ",")
                self.start(arguments[:2] if match.group(1).lower() == _IND[2] else arguments[:1], line,
                           "CreateObject(...).%s" % match.group(1))
        # -- the text is run as code ----------------------------------------------------
        for match in _EXECUTE.finditer(text):
            download = self.download_in(text[match.end():], line)
            if download is not None:
                self.hit("code", line, match.group(1), download)
        # -- a Sub / Function of the script is handed something ------------------------------
        for name, params in self.procs.items():
            for match in re.finditer(r"(?i)(?:^|[^\w.])%s\b\s*\(?" % re.escape(name), text):
                arguments = _split(self._arguments(text[match.end():]), ",")
                for param, argument in zip(params, arguments):
                    self.assign(param, argument, line, "")
        # -- an assignment ---------------------------------------------------------------
        if target:
            self.assign(target, expr, line, made)

    @staticmethod
    def _arguments(rest: str) -> str:
        """The arguments at the start of ``rest`` (up to the bracket that closes the call)."""
        depth = 0
        for at, char in enumerate(rest):
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    return rest[:at]
                depth -= 1
        return rest

    def assign(self, target: str, expr: str, line: int, made: str) -> None:
        held = self.var(target)
        if made and not made.startswith("loader:"):
            held.kind = made
        text = self.value(expr)
        if text is not None and text not in held.texts and len(held.texts) < 4:
            held.texts.append(text)
        download = self.download_in(expr, line)
        if download is not None and held.download is None:
            held.download = download
        names = self.names(expr)
        for name in names:                                  # Set b = a: the same object; p = q: the same path
            other = self.vars.get(name)
            if other is None or other is held:
                continue
            if not held.kind and other.kind and len(names) == 1:
                held.kind, held.addresses, held.path, held.names = other.kind, other.addresses, other.path, other.names
            if other.dropped is not None and held.dropped is None:
                held.dropped = other.dropped

    def start(self, arguments: List[str], line: int, sink: str) -> None:
        """Something is started: is it a download, or a file one was written to?"""
        joined = ",".join(arguments)
        command = " ".join(filter(None, (self.value(argument) for argument in arguments)))
        if command and self.final and len(self.commands) < _MAX_COMMANDS:
            self.commands.append((line, command))
        download = self.download_in(joined, line)
        if download is not None:
            self.hit("command", line, sink, download)
            return
        dropped = self.dropped_in(joined)
        if dropped is not None:
            self.hit("dropper", line, sink, dropped[0], command or dropped[1])

    # -- a whole script ------------------------------------------------------------------
    def script(self, text: str, first_line: int = 1) -> None:
        code = mask_comments(text, "vbs")
        lines = code.split("\n")
        if len(lines) > _MAX_LINES:
            self.cut = "more than %d lines" % _MAX_LINES
        lines = lines[:_MAX_LINES]
        number = 0
        while number < len(lines):
            line, at = lines[number].rstrip("\r"), first_line + number
            while line.rstrip().endswith(" _") and number + 1 < len(lines):
                number += 1
                line = line.rstrip()[:-1] + " " + lines[number].rstrip("\r")
            number += 1
            if not line.strip():
                continue
            self.texts = []

            def hold(match: "re.Match[str]") -> str:
                self.texts.append(match.group(0)[1:-1].replace('""', '"'))
                return "\x00%d\x00" % (len(self.texts) - 1)

            held = _STRING.sub(hold, line)
            for part in _split(held, ":"):
                self.statement(part, at)


def blocks(text: str, language: str = "vbs", default: str = "") -> Tuple[List[Tuple[int, str]], List[Tuple[int, str]]]:
    """``(script blocks of one language, remote script addresses)`` of a ``.wsf`` / ``.hta``
    / ``.html`` file, each with the line it begins at. ``language``: ``"vbs"`` or
    ``"js"`` - a block belongs to it when its ``language`` (or ``type``) says so; one
    that names no language belongs to ``default`` (an ``.hta`` / ``.html``: JScript)."""
    wanted = language
    code: List[Tuple[int, str]] = []
    remote: List[Tuple[int, str]] = []

    def attributes_of(tag: str) -> Dict[str, str]:
        return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in _ATTRIBUTE.finditer(tag)}

    for match in list(_TAG.finditer(text))[:2000]:          # every opening tag, also one closed in itself
        address = attributes_of(match.group(1)).get("src", "").strip().rstrip("/")
        if _REMOTE_URL.match(address) and not _LOCAL_URL.match(address):
            remote.append((text.count("\n", 0, match.start()) + 1, address[:300]))
    for match in list(_BLOCK.finditer(text))[:2000]:
        attributes = attributes_of(match.group(1) or "")
        line = text.count("\n", 0, match.start(2)) + 1
        said = (attributes.get("language", "") + " " + attributes.get("type", "")).lower().strip()
        kind = "vbs" if "vbs" in said else "js" if ("jscript" in said or "javascript" in said or "ecmascript" in said) \
            else default if not said else ""
        if kind == wanted:
            code.append((line, match.group(2)))
    return code, remote


def analyse(text: str, wrapped: bool = False) -> Result:
    """What the VBScript in ``text`` runs that came from the network, and the command
    lines it starts. ``wrapped``: ``text`` is a ``.wsf`` / ``.hta`` file - its VBScript
    blocks are read. Never raises."""
    cut = "larger than %d MB" % (MAX_SOURCE >> 20) if len(text or "") > MAX_SOURCE else ""
    text = (text or "")[:MAX_SOURCE]
    flow = _Flow()
    try:
        parts = [(1, text)]
        if wrapped:
            parts, remote = blocks(text)
            flow.final = True
            for line, address in remote:
                flow.hit("loader", line, "script src", Download("", line, REMOTE, address))
            flow.final = False
        for final in (False, True):                         # twice: a Sub below its call is known then
            flow.final = final
            for line, code in parts:
                flow.script(code, line)
    except (_Limit, RecursionError):
        cut = V.also(cut, "more than %d statements" % MAX_STEPS)
    except Exception:                    # an analysis aid must never break the scan itself
        return Result([], [])
    return Result(flow.hits, flow.commands, V.also(cut, flow.cut))
