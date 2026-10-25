"""Remote code execution in PowerShell and batch files.

The counterpart of :mod:`gamescan.dataflow.remote` for the two Windows shell
languages:

``source``  a download - ``DownloadString`` / ``DownloadData`` /
            ``DownloadFile``, ``Invoke-WebRequest`` / ``Invoke-RestMethod`` and
            their aliases, ``Start-BitsTransfer``, ``bitsadmin``, ``certutil
            -urlcache``, ``curl``, ``wget``
``flow``    the answer is piped on, kept in a variable, or it is the file the
            download was written to
``sink``    ... and is executed: ``Invoke-Expression`` / ``iex``, a script
            block or assembly built from it, another interpreter it is piped
            into - or the downloaded file is started (``Start-Process``,
            ``start``, ``call``, ``&``, the file name as a command,
            ``rundll32``, ``regsvr32``, ``wscript`` ...)

Programs that fetch and run an address by themselves (``mshta``, ``msiexec
/i``, ``regsvr32 /i:``) are reported as loaders. A batch file's
``powershell -Command "..."`` is read as PowerShell, ``-EncodedCommand`` is
decoded first. The address decides, as in JavaScript: remote, decoded or not
resolvable - reported; this PC - nothing is reported.

A tracer over statements, not a parser: variables are followed by name, a
variable counts from the line that sets it, quoting is handled approximately.
Nothing is executed.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_sh.py")

import re
from typing import Dict, List, Optional, Tuple

from ..rules import mask_comments
from . import values as V
from .remote import HIDDEN, LOCAL, REMOTE, UNRESOLVED, Hit
from .textflow import MAX_SOURCE, batch_expand
from .values import Budget, Clock

MAX_STEPS = 300_000                 # the limit: the same file is always cut at the same place
MAX_SECONDS = V.SAFETY_SECONDS      # a far safety cap only, for what nobody foresaw (the steps are the limit)
_MAX_LINES = 50_000
_MAX_HITS = 8

_HINT = re.compile(_IND[0])
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'`)<>|;,]+")
_LOCAL_URL = re.compile(r"(?i)^(?:https?|ftp)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?:[:/]|$)")
_PS_VAR = re.compile(r"\$(?:\{([\w:]+)\}|([A-Za-z_][\w:]*))")
_PS_ASSIGN = re.compile(r"^\s*\$([A-Za-z_]\w*)\s*=\s*(.+)$", re.S)
_PS_LITERAL = re.compile(r"""^\s*\$([A-Za-z_]\w*)\s*=\s*(['"])([^'"`$]*)\2\s*$""")
# requests whose answer is a value
_CONTENT = re.compile(_IND[1])
_TO_FILE = re.compile(_IND[2])
_DOWNLOAD_FILE = re.compile(_IND[3])
_INTERPRETERS = _IND[4]
_PIPED = re.compile(r"(?i)\|\s*(?:&\s*)?(%s)\b" % _INTERPRETERS)
_IEX = re.compile(_IND[5])
_BUILDS_CODE = re.compile(_IND[6])
# what starts a file: the word in front of it
_STARTERS = re.compile(
    _IND[7])
_LOADERS = re.compile(_IND[8])
_SPLIT_PS = re.compile(r";|\r?\n")
_QUOTED = re.compile(r"""(['"])(.*?)\1""")
_POWERSHELL = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b(.*)$", re.S)


def _words(text: str) -> List[str]:
    """The statement as words; a quoted part is one word, without its quotes."""
    out, current, quote = [], [], ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                current.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch in " \t\r\n,":
            if current:
                out.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        out.append("".join(current))
    return out[:200]


def _leaf(text: str) -> str:
    return re.split(r"[\\/]", text.strip().strip("\"'"))[-1].lower()


def _statements(line: str, batch: bool) -> List[str]:
    """Split a line into statements at ``;`` (PowerShell) or ``&`` / ``&&`` /
    ``||`` (batch), outside quotes."""
    out, current, quote, i, n = [], [], "", 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            current.append(ch)
        elif (not batch and ch == ";") or (batch and ch == "&") or (batch and line[i:i + 2] == "||"):
            out.append("".join(current))
            current = []
            if line[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            current.append(ch)
        i += 1
    out.append("".join(current))
    return [s for s in out if s.strip()][:50]


class _Source:
    __slots__ = ("what", "line", "kind", "address")

    def __init__(self, what: str, line: int, kind: str, address: str) -> None:
        self.what, self.line, self.kind, self.address = what, line, kind, address


class _Flow:
    def __init__(self, clock: Clock, decoded: bool = False) -> None:
        self.clock, self.decoded = clock, decoded
        self.literal: Dict[str, List[Tuple[int, str]]] = {}        # PowerShell variable -> literals
        self.taint: Dict[str, Tuple[_Source, int]] = {}
        self.drops: List[Tuple[_Source, int, str, str]] = []       # source, line, leaf / text, shown
        self.hits: List[Hit] = []
        self.cut = ""                   # a limit that is a count was reached (lines, size)

    # -- values ---------------------------------------------------------------------
    def fill(self, text: str, line: int) -> str:
        """The statement with the PowerShell variables whose literal value is known filled in."""
        def repl(m):
            name = (m.group(1) or m.group(2)).lower()
            known = [value for at, value in self.literal.get(name, ()) if at <= line]
            return known[-1] if known else m.group(0)
        for _ in range(3):
            fresh = _PS_VAR.sub(repl, text)
            if fresh == text:
                break
            text = fresh[:8000]
        return text

    def address(self, text: str, hint: str = "") -> Tuple[str, str]:
        """``(kind, address)`` for the request in a statement (variables filled in)."""
        found = _URL.search(text)
        if found:
            url = found.group(0).rstrip(".")
            if _LOCAL_URL.match(url):
                return LOCAL, url
            return (HIDDEN if self.decoded else REMOTE), url[:200]
        return UNRESOLVED, hint[:80]

    def _hit(self, how: str, sink: str, source: _Source, line: int, detail: str = "") -> None:
        if len(self.hits) < _MAX_HITS and not any(
                h.source_line == source.line and h.line == line and h.sink == sink for h in self.hits):
            self.hits.append(Hit(how=how, line=line, sink=sink, source=source.what, source_line=source.line,
                                 kind=source.kind, address=source.address, detail=detail))

    # -- one statement --------------------------------------------------------------
    def statement(self, raw: str, line: int, batch: bool) -> None:
        self.clock.tick(5)
        text = self.fill(raw, line)
        if batch:
            inner = _POWERSHELL.search(text)
            if inner and not re.match(r"(?i)\s*(?:rem\b|::|echo\b)", text):
                script = V.powershell_encoded(text)
                if script is not None:
                    nested = _Flow(self.clock, decoded=True)
                    nested.literal, nested.taint, nested.drops, nested.hits = \
                        self.literal, self.taint, self.drops, self.hits
                    nested.script(script, False, line)
                    return
                command = re.sub(r"(?i)^\s*(?:-\w+(?:\s+(?:bypass|hidden|unrestricted|remotesigned|\d+))?\s+)*"
                                 r"(?:-c(?:ommand)?\s+)?", "", inner.group(1).strip())
                command = command.strip()
                if len(command) > 1 and command[0] in "\"'" and command[-1] == command[0]:
                    command = command[1:-1]
                for part in _statements(command, False):
                    self.statement(part, line, False)
                return
        elif V.powershell_encoded(text) is not None and re.search(r"(?i)\b(?:powershell|pwsh)", text):
            nested = _Flow(self.clock, decoded=True)
            nested.literal, nested.taint, nested.drops, nested.hits = \
                self.literal, self.taint, self.drops, self.hits
            nested.script(V.powershell_encoded(text), False, line)
            return
        words = _words(text)
        if not words:
            return
        literal = _PS_LITERAL.match(raw)
        if literal and not batch:
            self.literal.setdefault(literal.group(1).lower(), []).append((line, literal.group(3)))
        source = self._content(text, raw, line)
        dropped_here = self._download_to_file(text, raw, words, line)
        assign = None if batch else _PS_ASSIGN.match(raw)
        if assign:
            carried = source or self._tainted(assign.group(2), line)
            if carried is not None and not dropped_here:
                self.taint.setdefault(assign.group(1).lower(), (carried, line))
        # sinks
        piped = _PIPED.search(text)
        if piped and source is not None and not dropped_here:
            self._hit("code", "| " + piped.group(1), source, line)
        iex = _IEX.search(text)
        if iex and not (piped and piped.group(1).lower() in (_IND[9], _IND[10]) and source is not None):
            carried = source or self._tainted(text[iex.end():] if not piped else text, line)
            if carried is not None:
                self._hit("code", _IND[11], carried, line)
        built = _BUILDS_CODE.search(text)
        if built:
            carried = source or self._tainted(text[built.end():], line)
            if carried is not None:
                self._hit("code", re.sub(r"\s+", "", built.group(0))[:40], carried, line)
        if not dropped_here:
            self._loader(words, text, line)
            self._start(words, raw, text, line, batch)

    def _tainted(self, text: str, line: int) -> Optional[_Source]:
        for m in _PS_VAR.finditer(text):
            found = self.taint.get((m.group(1) or m.group(2)).lower())
            if found is not None and found[1] <= line:
                return found[0]
        return None

    def _content(self, text: str, raw: str, line: int) -> Optional[_Source]:
        """A request in this statement whose answer stays a value (not written to a file)."""
        found = _CONTENT.search(text)
        if not found or _TO_FILE.search(text):
            return None
        what = found.group(1) or found.group(2) or re.sub(r"[\s\[\]]|::Create", "", found.group(3))
        if found.group(2) and re.search(_IND[12], text[:found.start()]):
            return None
        at = raw.lower().find(found.group(0).lower()[:10])
        variable = _PS_VAR.search(raw[at:] if at >= 0 else raw)
        hint = variable.group(0) if variable else text[found.end():].strip(" ()'\"")[:60]
        kind, address = self.address(text[found.start():], hint)
        if kind == LOCAL:
            return None
        return _Source(what, line, kind, address)

    def _drop(self, source: _Source, line: int, path: str) -> None:
        path = path.strip().strip("\"'")
        if not path:
            return
        for item in {path.lower(), _leaf(path)}:
            if (len(item) >= 3 or item[:1] in "$%") and len(self.drops) < 200 and not any(
                    d[2] == item and d[0].line == source.line for d in self.drops):
                self.drops.append((source, line, item, path[:120]))

    def _download_to_file(self, text: str, raw: str, words: List[str], line: int) -> bool:
        """Record a download that is written to a file. True if this statement is one."""
        low = [w.lower() for w in words]
        path = None
        what = ""
        m = _DOWNLOAD_FILE.search(text)
        if m:
            parts = [p.strip() for p in m.group(1).split(",")]
            what, path = _IND[13], parts[1] if len(parts) > 1 else None
        elif any(w in (_IND[14], "iwr", "invoke-restmethod", "irm") for w in low):
            what = next(w for w in words if w.lower() in (_IND[14], "iwr", "invoke-restmethod", "irm"))
            path = self._after(words, ("-outfile", "-o"))
        elif any(w in ("start-bitstransfer",) for w in low):
            what = "Start-BitsTransfer"
            path = self._after(words, ("-destination",))
            if path is None:
                plain = [w for w in words[low.index("start-bitstransfer") + 1:] if not w.startswith("-")]
                path = plain[1] if len(plain) > 1 else None
        elif any(re.fullmatch(_IND[15], w) for w in low) and "/transfer" in low:
            what = _IND[16]
            plain = [w for w in words[low.index("/transfer") + 1:] if not w.startswith("/")]
            plain = [w for w in plain if w.lower() not in ("foreground", "high", "normal", "low")]
            path = plain[-1] if len(plain) >= 3 or (len(plain) == 2 and _URL.match(plain[0])) else None
            if path is not None and _URL.match(path):
                path = None
        elif any(re.fullmatch(_IND[17], w) for w in low) and any("urlcache" in w for w in low):
            what = _IND[18]
            plain = [w for w in words if not w.startswith(("-", "/")) and not re.fullmatch(_IND[19], w)]
            after = [w for w in plain if not _URL.match(w)]
            path = after[-1] if after and any(_URL.match(w) or "$" in w or "%" in w for w in plain) else None
        elif any(re.fullmatch(r"(?:curl|wget)(?:\.exe)?", w) for w in low):
            what = next(w for w in words if re.fullmatch(r"(?i)(?:curl|wget)(?:\.exe)?", w))
            path = self._after(words, ("-o", "--output", "-outfile")) or self._after_exact(words, "-O", what)
            if path is None and any(w in ("-O", "--remote-name") for w in words):
                url = _URL.search(text)
                path = _leaf(url.group(0)) if url else None
            if path is None:
                redirect = re.search(r">\s*([^\s|&]+)", text)
                path = redirect.group(1) if redirect else None
        if not what or path is None:
            return False
        kind, address = self.address(text, next((w for w in words if w.startswith(("$", "%"))), ""))
        if kind != LOCAL:
            self._drop(_Source(what, line, kind, address), line, path)
        return True

    @staticmethod
    def _after(words: List[str], options: Tuple[str, ...]) -> Optional[str]:
        for index, word in enumerate(words[:-1]):
            if word.lower() in options and word != "-O":
                return words[index + 1]
        return None

    @staticmethod
    def _after_exact(words: List[str], option: str, tool: str) -> Optional[str]:
        """``wget -O file`` names the file; ``curl -O`` does not."""
        if not tool.lower().startswith("wget"):
            return None
        for index, word in enumerate(words[:-1]):
            if word == option:
                return words[index + 1]
        return None

    def _loader(self, words: List[str], text: str, line: int) -> None:
        """A program that fetches and runs a remote address by itself."""
        first = _LOADERS.match(_leaf(words[0]))
        if not first:
            return
        url = _URL.search(text)
        if url and not _LOCAL_URL.match(url.group(0)):
            if len(self.hits) < _MAX_HITS:
                self.hits.append(Hit(how="loader", line=line, sink=first.group(1).lower(), source="",
                                     source_line=line, kind=HIDDEN if self.decoded else REMOTE,
                                     address=url.group(0)[:200]))

    def _start(self, words: List[str], raw: str, text: str, line: int, batch: bool) -> None:
        """A statement that starts a file a download was written to."""
        if not self.drops:
            return
        head = _leaf(words[0])
        candidates: List[str] = []
        if _STARTERS.match(head) or _STARTERS.match(words[0]):
            candidates = [w for w in words[1:] if not re.fullmatch(r"[-/][\w:]+", w)]
            for word in list(candidates):                       # cmd /c "a.exe /s", /tr "a.exe"
                candidates += word.split()
        elif batch or re.search(r"[\\/.]", words[0]):
            candidates = [words[0]]                             # the file name as the command
        keys = set()
        for word in candidates:
            word = word.strip("\"'")
            keys.add(word.lower())
            keys.add(_leaf(word))
        for source, at, item, shown in self.drops:
            if at <= line and item in keys:
                self._hit("dropper", words[0] if candidates != [words[0]] else "run", source, line, shown)
                return

    # -- a whole script ---------------------------------------------------------------
    def script(self, text: str, batch: bool, fixed_line: int = 0) -> None:
        if len(text) > MAX_SOURCE:
            self.cut = "larger than %d MB" % (MAX_SOURCE >> 20)
        text = text[:MAX_SOURCE]
        expanded = dict(batch_expand(text)) if batch else {}
        code = mask_comments(text, "bat" if batch else "powershell")
        lines = code.split("\n")
        if len(lines) > _MAX_LINES:
            self.cut = V.also(self.cut, "more than %d lines" % _MAX_LINES)
        lines = lines[:_MAX_LINES]
        number = 0
        while number < len(lines):
            line = expanded.get(number + 1, lines[number])
            first = number + 1
            while line.rstrip().endswith("`" if not batch else "^") and number + 1 < len(lines):
                number += 1
                line = line.rstrip()[:-1] + " " + expanded.get(number + 1, lines[number])
            number += 1
            if not line.strip():
                continue
            self.clock.tick()
            for part in _statements(line, batch):
                self.statement(part, fixed_line or first, batch)


_MAX_COMMANDS = 200
_MAX_COMMAND = 8000


def analyse_commands(commands) -> List[Hit]:
    """The same for command lines that a script in another language starts
    (``os.system("powershell -c ...")`` in Python, ``system`` / backticks in
    Ruby), as the payload resolver worked them out: ``(line, command)`` pairs.
    They are read together, in their order in the script, like the lines of
    one batch file - so a download in one command and the start of the file
    in a later one is found too. Lines in the result are lines of the script.
    Never raises."""
    lines, at = [], {}
    for line, command in sorted((c for c in commands if c[1] and c[1].strip()),
                                key=lambda c: c[0])[:_MAX_COMMANDS]:
        # one command, one line; a script handed over with line breaks keeps its statements
        lines.append(re.sub(r"\s*\r?\n\s*", "; ", command.strip()[:_MAX_COMMAND]))
        at[len(lines)] = line
    hits = analyse("\n".join(lines), "batch")
    for hit in hits:
        hit.line, hit.source_line = at.get(hit.line, hit.line), at.get(hit.source_line, hit.source_line)
    return hits


def analyse(text: str, language: str) -> List[Hit]:
    """What ``text`` (``"powershell"`` or ``"batch"``) executes that came from
    the network. Never raises."""
    return study(text, language)[0]


def study(text: str, language: str) -> Tuple[List[Hit], str]:
    """``(hits, cut)``: the same, and whether the reading stopped at a limit - ``cut``
    names it ("": read to the end). The limits are counts - the number of steps, of
    lines, the size - so the same file always gets the same answer. The clock is
    only an emergency brake; when it does stop the reading that is said too."""
    if not text or not _HINT.search(text):
        return [], ""
    flow = _Flow(Clock(MAX_STEPS, MAX_SECONDS))
    cut = ""
    try:
        flow.script(text, language == "batch")
    except Budget:
        cut = "more than %d steps" % MAX_STEPS if flow.clock.steps <= 0 else "%.0f seconds" % MAX_SECONDS
    except RecursionError:
        cut = "nested too deeply"
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""
    return flow.hits, V.also(cut, flow.cut)


# -- across files -----------------------------------------------------------------------------------
# One script downloads, another runs it. Each batch / PowerShell / sh script leaves a short
# summary; the scanner joins them after the whole folder was scanned (dataflow/shared.py),
# one hop. What two scripts share:
#
# * an environment variable - set from a download in one (batch: for /f ... in ('curl ...')
#   do set NAME=...; PowerShell: $env:NAME = ..., [Environment]::SetEnvironmentVariable,
#   setx; sh: export NAME=$(curl ...)) and run in another, which does not set it itself
#   (batch: %NAME% as the command or handed to call / start / cmd / powershell; PowerShell:
#   Invoke-Expression, a script block, & or Start-Process on $env:NAME; sh: eval, sh -c, the
#   variable as the command). Windows names are one name whatever their case;
# * the arguments of a script - one script hands a download to another it calls or starts
#   (call b.bat %NAME%, powershell -File b.ps1 $x, sh b.sh "$NAME"), and that script runs
#   what it was handed (%1, $args, $1). Any argument, not one by its position;
# * a file - one script writes a download to it, another starts it.
#
# Not asked: whether the first script really starts the second. The summaries are read
# from statements with a few patterns, not by the tracer above (which keeps no batch or
# sh variables); what a script does with a value in between is followed for PowerShell
# variables only.
SHARED = "\0shared"
_MAX_SHARED = 200
_OWN_ENV = frozenset("""path pathext temp tmp cd date time random errorlevel comspec systemroot windir userprofile
appdata localappdata programfiles programdata homedrive homepath username computername os processor_architecture
cmdcmdline cmdextversion public allusersprofile number_of_processors home user shell pwd lang term ifs""".split())
_BAT_ENV = re.compile(r"[%!]([A-Za-z_][\w]*)[%!]")
_BAT_ARG = re.compile(r"%(?:~[a-z]*)?([1-9*])")
_BAT_SET = re.compile(r"(?i)^\s*@?\s*(?:set|setx)\s+(?:/[ap]\s+)?\"?([A-Za-z_]\w*)\s*[= ]")
_BAT_FOR = re.compile(r"(?is)\bfor\s+/f\b.*?\bin\s*\(\s*'(.+)'\s*\)\s*do\s+@?\s*(?:set|setx)\s+\"?([A-Za-z_]\w*)\s*[= ]")
_PS_ENV = re.compile(r"(?i)\$env:([A-Za-z_]\w*)")
_PS_ENV_SET = re.compile(r"(?is)^\s*\$env:([A-Za-z_]\w*)\s*=\s*(.+)$")
_PS_ENV_CALL = re.compile(r"(?is)\[(?:System\.)?Environment\]\s*::\s*SetEnvironmentVariable\s*\(\s*['\"](\w+)['\"]\s*,(.+)$")
_PS_SETX = re.compile(r"(?is)^\s*setx(?:\.exe)?\s+['\"]?([A-Za-z_]\w*)['\"]?\s+(.+)$")
_PS_ARGS = re.compile(r"(?i)\$args\b|\$PSBoundParameters\b")
_SH_SET = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$", re.S)
_SH_FETCH = re.compile(r"(?:\$\(|`)\s*((?:curl|wget)\b[^)`]*)")
_SH_VAR = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")
_SH_ARG = re.compile(r"\$\{?([1-9@*])\}?")
_SH_RUNS = re.compile(r"^(?:eval|exec|source|\.|(?:ba|z|k|da)?sh|python\d?)$")
_SCRIPT_NAME = re.compile(r"(?i)[^\s\"'\\/|&;<>]+\.(?:bat|cmd|ps1|sh|bash|command)$")
_FILE_NAME = re.compile(r"(?i)^[^\s\"'|&;<>%$!]+\.[a-z0-9]{1,5}$")
_SH_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")


class Shared:
    """What one script shares with the other scripts of its folder, in the form the join
    wants (:mod:`gamescan.dataflow.shared`): ``fills`` / ``runs`` by shared name, ``drops``
    / ``starts`` by ``file:<name>``. ``cut``: the reading stopped at its limit ("": none)."""

    __slots__ = ("fills", "runs", "drops", "starts", "cut")

    def __init__(self) -> None:
        self.fills: Dict[str, tuple] = {}
        self.runs: Dict[str, tuple] = {}
        self.drops: Dict[str, tuple] = {}
        self.starts: Dict[str, tuple] = {}
        self.cut = ""

    def __bool__(self) -> bool:
        return bool(self.fills or self.runs or self.drops or self.starts)


def _env_key(name: str, sh: bool = False) -> str:
    return "store:sh:$%s" % name if sh else "store:sh:%%%s%%" % name.upper()


def _arg_key(script: str) -> str:
    return "store:sh:argument of %s" % _leaf(script)


class _SharedFlow(_Flow):
    """The second reading of a PowerShell script: an environment variable it does not set
    itself, and its arguments, stand for "whatever another script put there"; where such a
    value is run is written down (``runs``)."""

    def __init__(self, clock: Clock) -> None:
        super().__init__(clock)
        self.runs: Dict[str, tuple] = {}

    def _hit(self, how: str, sink: str, source: _Source, line: int, detail: str = "") -> None:
        if source.what == SHARED and len(self.runs) < _MAX_SHARED:
            self.runs.setdefault(source.address, (how, sink, line, detail))

    def _start(self, words: List[str], raw: str, text: str, line: int, batch: bool) -> None:
        head = _leaf(words[0])
        if _STARTERS.match(head) or _STARTERS.match(words[0]):
            carried = self._tainted(" ".join(words[1:]), line)
            if carried is not None:
                self._hit("command", words[0], carried, line)


def _fill(flow: "_Flow", command: str, line: int) -> Optional[tuple]:
    """``(request, line, kind, address)`` when ``command`` is a download whose answer is a value."""
    found = _CONTENT.search(command)
    if not found or _TO_FILE.search(command):
        return None
    kind, address = flow.address(command)
    if kind == LOCAL:
        return None
    return ((found.group(1) or found.group(2) or "request"), line, kind, address)


def _called(words: List[str]) -> Tuple[str, List[str]]:
    """``(script, its arguments)`` when the statement calls or starts another script."""
    for index, word in enumerate(words[:8]):
        if _SCRIPT_NAME.fullmatch(_leaf(word)) and index < len(words):
            return word.strip("\"'"), words[index + 1:]
    return "", []


def _starts(out: Shared, words: List[str], line: int, batch: bool) -> None:
    """The files a statement starts by a written-out name (another script may have written them)."""
    head = _leaf(words[0])
    candidates: List[str] = []
    if _STARTERS.match(head) or _STARTERS.match(words[0]) or _SH_RUNS.match(head):
        candidates = [w for w in words[1:] if not re.fullmatch(r"[-/][\w:]+", w)]
        for word in list(candidates):
            candidates += word.split()
    elif batch or re.search(r"[\\/.]", words[0]):
        candidates = [words[0]]
    for word in candidates:
        leaf = _leaf(word)
        if _FILE_NAME.match(leaf) and len(out.starts) < _MAX_SHARED:
            out.starts.setdefault("file:" + leaf, (words[0] if candidates != [words[0]] else "run", line))


def shared(text: str, language: str, name: str = "") -> Shared:
    """What the script ``text`` (``"batch"``, ``"powershell"`` or ``"sh"``; ``name``: its
    file name) shares with the other scripts of its folder. Never raises."""
    out = Shared()
    if not text or not text.strip():
        return out
    try:
        if len(text) > MAX_SOURCE:
            out.cut = "larger than %d MB" % (MAX_SOURCE >> 20)
        text = text[:MAX_SOURCE]
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        batch, sh = language == "batch", language == "sh"
        flow = _Flow(clock)
        try:
            if sh:
                _shared_sh(out, flow, text, name, clock)
            else:
                # what it downloads to files, and (PowerShell) into variables
                if _HINT.search(text):
                    flow.script(text, batch)
                _shared_windows(out, flow, text, batch, name, clock)
        except Budget:
            out.cut = V.also(out.cut, "more than %d steps" % MAX_STEPS if clock.steps <= 0 else "%.0f seconds" % MAX_SECONDS)
        except RecursionError:
            out.cut = V.also(out.cut, "nested too deeply")
        out.cut = V.also(out.cut, flow.cut)
        for source, line, item, shown in flow.drops:
            leaf = _leaf(item)
            if _FILE_NAME.match(leaf) and len(out.drops) < _MAX_SHARED:
                out.drops.setdefault("file:" + leaf, (source.what, source.line, source.kind, source.address, shown))
    except Exception:                    # an analysis aid must never break the scan itself
        pass
    return out


def _lines(text: str, style: str) -> List[Tuple[int, str]]:
    code = mask_comments(text, style)
    lines = code.split("\n")
    return [(number, line) for number, line in enumerate(lines[:_MAX_LINES], 1) if line.strip()]


def _shared_windows(out: Shared, flow: "_Flow", text: str, batch: bool, name: str, clock: Clock) -> None:
    lines = _lines(text, "bat" if batch else "powershell")
    if text.count("\n") >= _MAX_LINES:
        out.cut = V.also(out.cut, "more than %d lines" % _MAX_LINES)
    own = set()                                 # the environment variables this script sets itself
    held: Dict[str, tuple] = {}                 # ... of which these from a download
    for number, line in lines:
        clock.tick(3)
        if batch:
            loop = _BAT_FOR.search(line)
            if loop:
                own.add(loop.group(2).upper())
                fill = _fill(flow, loop.group(1), number)
                if fill is not None:
                    held[loop.group(2).upper()] = fill
            for part in _statements(line, True):
                m = _BAT_SET.match(part)
                if m:
                    own.add(m.group(1).upper())
        else:
            for part in _statements(line, False):
                m = _PS_ENV_SET.match(part) or _PS_ENV_CALL.search(part) or _PS_SETX.match(part)
                if m:
                    own.add(m.group(1).upper())
                    source = flow._content(part, part, number) or flow._tainted(m.group(2), number)
                    if source is not None and source.what != SHARED:
                        held[m.group(1).upper()] = (source.what, source.line, source.kind, source.address)
    for key, fill in sorted(held.items()):
        if len(out.fills) < _MAX_SHARED:
            out.fills[_env_key(key)] = fill
    # the second reading: what it runs that another script may have put there
    second = _SharedFlow(clock)
    if not batch:
        used = {m.group(1).upper() for m in _PS_ENV.finditer(text)} - own - {n.upper() for n in _OWN_ENV}
        for env in sorted(used)[:_MAX_SHARED]:
            second.taint["env:" + env.lower()] = (_Source(SHARED, 0, UNRESOLVED, _env_key(env)), 0)
        if name and _PS_ARGS.search(text):
            for variable in ("args", "psboundparameters"):
                second.taint[variable] = (_Source(SHARED, 0, UNRESOLVED, _arg_key(name)), 0)
        if second.taint:
            second.script(text, False)
            out.runs.update(second.runs)
    for number, line in lines:
        clock.tick(3)
        for part in _statements(line, batch):
            words = _words(part)
            if not words:
                continue
            _starts(out, words, number, batch)
            script, arguments = _called(words)
            handed = " ".join(arguments)
            if script:                          # a download handed to another script as an argument
                fill = None
                if batch:
                    fill = next((held[m.group(1).upper()] for m in _BAT_ENV.finditer(handed)
                                 if m.group(1).upper() in held), None)
                else:
                    source = flow._tainted(handed, number)
                    env = next((held[m.group(1).upper()] for m in _PS_ENV.finditer(handed)
                                if m.group(1).upper() in held), None)
                    fill = env or ((source.what, source.line, source.kind, source.address)
                                   if source is not None and source.what != SHARED else None)
                if fill is not None and len(out.fills) < _MAX_SHARED:
                    out.fills.setdefault(_arg_key(script), fill)
            if not batch:
                continue
            # batch: a shared value is run when it is the command itself, or is handed to
            # something that runs it (call, start, cmd /c, powershell -Command ...)
            head = _leaf(words[0])
            runs_rest = bool(_STARTERS.match(head) or _STARTERS.match(words[0]))
            spots = [words[0]] + (words[1:] if runs_rest else [])
            for index, word in enumerate(spots):
                for m in _BAT_ENV.finditer(word):
                    env = m.group(1).upper()
                    if env not in own and env.lower() not in _OWN_ENV and len(out.runs) < _MAX_SHARED:
                        out.runs.setdefault(_env_key(env), ("command", "run" if index == 0 else words[0], number, ""))
                if name and _BAT_ARG.search(word) and len(out.runs) < _MAX_SHARED:
                    out.runs.setdefault(_arg_key(name), ("command", "run" if index == 0 else words[0], number, ""))


def _shared_sh(out: Shared, flow: "_Flow", text: str, name: str, clock: Clock) -> None:
    lines = _lines(text, "sh")
    if text.count("\n") >= _MAX_LINES:
        out.cut = V.also(out.cut, "more than %d lines" % _MAX_LINES)
    own, exported = set(), set()
    held: Dict[str, tuple] = {}
    statements: List[Tuple[int, str]] = []
    for number, line in lines:
        for part in _SH_SPLIT.split(line):
            if part.strip():
                statements.append((number, part.strip()))
    for number, part in statements:
        clock.tick(3)
        m = _SH_SET.match(part)
        if m:
            own.add(m.group(1))
            fetch = _SH_FETCH.search(m.group(2))
            fill = _fill(flow, fetch.group(1), number) if fetch else None
            if fill is not None:
                held[m.group(1)] = fill
            if part.startswith("export"):
                exported.add(m.group(1))
        elif part.startswith("export "):
            exported.update(re.findall(r"[A-Za-z_]\w*", part[7:]))
        words = _words(part)
        if words and re.fullmatch(r"(?:curl|wget)(?:\.exe)?", _leaf(words[0])):
            flow._download_to_file(part, part, words, number)       # ... to a file: flow.drops
    for key in sorted(held):
        if key in exported and len(out.fills) < _MAX_SHARED:
            out.fills[_env_key(key, True)] = held[key]
    for number, part in statements:
        clock.tick(3)
        words = _words(part)
        if not words or _SH_SET.match(part):
            continue
        _starts(out, words, number, False)
        head = _leaf(words[0])
        script, arguments = _called(words)
        if script:
            fill = next((held[m.group(1)] for m in _SH_VAR.finditer(" ".join(arguments)) if m.group(1) in held), None)
            if fill is not None and len(out.fills) < _MAX_SHARED:
                out.fills.setdefault(_arg_key(script), fill)
        runs_rest = bool(_SH_RUNS.match(head))
        spots = [words[0]] + (words[1:] if runs_rest else [])
        for index, word in enumerate(spots):
            for m in _SH_VAR.finditer(word):
                env = m.group(1)
                if env not in own and env.lower() not in _OWN_ENV and len(out.runs) < _MAX_SHARED:
                    out.runs.setdefault(_env_key(env, True), ("command", "run" if index == 0 else words[0], number, ""))
            if name and _SH_ARG.search(word) and len(out.runs) < _MAX_SHARED:
                out.runs.setdefault(_arg_key(name), ("command", "run" if index == 0 else words[0], number, ""))
