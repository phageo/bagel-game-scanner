"""Download-and-run in the script of an NSIS installer.

The instructions come from :func:`gamescan.unpack.nsis.instructions` - data,
read once, in the order of the table; nothing is interpreted. A download is
a call into a download plug-in (``NSISdl``, ``inetc``, ``NScurl`` ...) or a
``System::Call`` of a Windows download function; a start is ``Exec`` /
``ExecWait`` / ``ExecShell``, a plug-in that starts programs (``nsExec`` ...),
or a call into a library. The two are tied when the file the download is
saved to is named in what is started.

What is started without having been downloaded - a file of the package, a
program of the PC - is no chain: the files of the package are scanned
themselves. The command lines the script starts are also read like the
lines of one batch file (:func:`remote_sh.analyse_commands`): PowerShell,
certutil, bitsadmin and curl download too.

A tracer, like the others: variables are followed by their last ``StrCpy``
before the instruction (the table's order, not the order things run in);
what a plug-in or the registry puts into a variable is not known.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_nsis.py")

import re
from typing import Dict, List, NamedTuple, Optional, Tuple

from ..unpack import nsis
from . import remote_sh
from .remote import LOCAL, REMOTE, UNRESOLVED, Hit
from .remote_inno import DOWNLOAD_WORDS
from .values import SAFETY_SECONDS, Budget, Clock

MAX_STEPS = 400_000             # the limit: the same installer is always cut at the same place
MAX_SECONDS = SAFETY_SECONDS    # a far safety cap only; when it fires that is said too
_MAX_ARGUMENTS = 32             # texts pushed for one plug-in call
_MAX_DOWNLOADS = 256
_MAX_STARTS = 4096
_MAX_HITS = 8
_MAX_DEPTH = 4                  # a variable inside the value of a variable ...
_MAX_VARIABLES = 16             # variables written out in one text
_MAX_TEXT = 2048                # a text with its variables written out

_DOWNLOADERS = {"nsisdl": ("download", "download_quiet"), "inetc": ("get", "post", "put", "head"),
                "inetload": ("load",), "nscurl": ("http",), "nsxfer": ("request", "transfer"),
                "inetbgdl": ("get",)}
_STARTERS = frozenset({"nsexec", "execdos", "execcmd", "shellexecasuser", "stdutils", "uac", "nsprocess"})
_STARTS = re.compile(r"(?i)exec|shell|run|create")
_SYSTEM_DOWNLOAD = re.compile(_IND[0])
_SYSTEM_START = re.compile(_IND[1])
_ADDRESS = re.compile(r"(?i)\A(?:https?|ftp)://")
_ADDRESS_IN = re.compile(r"(?i)(?:https?|ftp)://[^\s\"'`,()<>]+")
_LOCAL = re.compile(r"(?i)\A(?:https?|ftp)://(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|\Z)")
_VARIABLE = re.compile(r"\$(?:R?\d|[A-Za-z_]\w*)")
_QUOTED = re.compile(r"\"([^\"]*)\"|'([^']*)'|`([^`]*)`|\b([rR]\d)\b")
_NAME_BEFORE = re.compile(r"[\w.\-]\Z")
_NAME_AFTER = re.compile(r"\A[\w.]")


class Download(NamedTuple):
    what: str               # NSISdl::download, System::Call URLDownloadToFile ...
    index: int
    kind: str               # remote | unresolved | local
    address: str
    saved: str              # where it is written ("" = not known)


class Start(NamedTuple):
    what: str               # Exec, ExecShell, nsExec::Exec ...
    index: int
    command: str
    library: bool = False   # a call into a library: ``command`` is the library's path


class Found(NamedTuple):
    hits: List[Hit]                 # ``line`` / ``source_line`` are instruction numbers (from 1)
    commands: List[Tuple[int, str]]         # every command line the script starts
    cut: str = ""                   # the limit the reading stopped at ("": it read to the end)
    # does the script name anything that downloads - a download plug-in, a Windows download
    # function, a text that speaks of downloading (as remote_inno.names_download)? True also
    # when the reading failed
    downloads: bool = True


def _plugin(path: str) -> str:
    leaf = re.split(r"[\\/]", path)[-1].lower()
    return leaf[:-4] if leaf.endswith(".dll") else leaf


def _kind(address: str) -> str:
    if _LOCAL.match(address):
        return LOCAL
    return REMOTE if _ADDRESS.match(address) and not _VARIABLE.search(address) else UNRESOLVED


def _same(text: str) -> str:
    return text.replace("/", "\\").lower().strip("\"' \t")


def _named_in(saved: str, command: str) -> bool:
    """Is the file ``saved`` named in ``command``? A bare file name also fits
    a longer path that ends in it."""
    saved, command = _same(saved), command.replace("/", "\\").lower()
    if not saved or saved.endswith("\\"):
        return False
    at = command.find(saved)
    while at >= 0:
        before, after = command[:at], command[at + len(saved):]
        if not _NAME_AFTER.match(after) and (not _NAME_BEFORE.search(before) or "\\" not in saved
                                             and before.endswith("\\")):
            return True
        at = command.find(saved, at + 1)
    return False


class _Flow:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.values: Dict[str, Optional[str]] = {}
        self.downloads: List[Download] = []
        self.starts: List[Start] = []
        self.named = False          # a text of the instructions speaks of downloading

    def expand(self, text: str, depth: int = 0) -> str:
        """``text`` with the variables whose value is known written out."""
        if depth >= _MAX_DEPTH or not 0 < text.count("$") <= _MAX_VARIABLES:
            return text
        self.clock.tick()

        def value(match: "re.Match[str]") -> str:
            known = self.values.get(match.group(0))
            return match.group(0) if known is None else self.expand(known, depth + 1)
        return _VARIABLE.sub(value, text)[:_MAX_TEXT]

    def run(self, program: List[nsis.Instruction]) -> None:
        pushed: List[Tuple[int, str]] = []
        for op in program:
            self.clock.tick()
            if not self.named and any(text and DOWNLOAD_WORDS.search(text) for text in op.texts):
                self.named = True
            if op.code == nsis.PUSH_POP:
                if op.numbers[1]:                               # Pop: whatever was on the stack
                    self.values[nsis.variable(op.numbers[0])] = None
                elif not op.numbers[2]:
                    if pushed and pushed[-1][0] != op.index - 1:
                        pushed = []
                    pushed.append((op.index, self.expand(op.texts[0])))
                continue
            arguments = []
            if op.code == nsis.CALL_DLL and pushed and pushed[-1][0] == op.index - 1:
                arguments = [text for _index, text in reversed(pushed[-_MAX_ARGUMENTS:])]
            pushed = []
            if op.code == nsis.ASSIGN:
                # StrCpy $var "text" [length [start]]: a part of a text is not followed
                whole = not op.numbers[2] and not op.numbers[3]
                self.values[nsis.variable(op.numbers[0])] = self.expand(op.texts[1]) if whole else None
            elif op.code == nsis.EXECUTE:
                self.start("Exec", op.index, self.expand(op.texts[0]))
            elif op.code == nsis.EXEC_SHELL:
                self.start("ExecShell", op.index, " ".join(self.expand(t) for t in op.texts[1:3] if t))
            elif op.code == nsis.CALL_DLL:
                self.call(op, arguments)

    def start(self, what: str, index: int, command: str, library: bool = False) -> None:
        if command.strip() and len(self.starts) < _MAX_STARTS:
            self.starts.append(Start(what, index, command, library))

    def download(self, what: str, index: int, address: str, saved: str) -> None:
        if len(self.downloads) < _MAX_DOWNLOADS:
            self.downloads.append(Download(what, index, _kind(address), address, saved))

    def call(self, op: nsis.Instruction, arguments: List[str]) -> None:
        library, function = self.expand(op.texts[0]), op.texts[1]
        plugin = _plugin(library)
        what = "%s::%s" % (re.split(r"[\\/]", library)[-1][:-4] if library.lower().endswith(".dll")
                           else plugin, function)
        self.start(what, op.index, library, True)           # a call into a library runs that library
        if plugin in _DOWNLOADERS and function.lower() in _DOWNLOADERS[plugin]:
            plain = [a for a in arguments if not a.startswith("/")]
            at = [i for i, a in enumerate(arguments) if _ADDRESS.match(a)]
            if at:
                for i in at:
                    saved = arguments[i + 1] if i + 1 < len(arguments) else ""
                    self.download(what, op.index, arguments[i], "" if saved.startswith("/") else saved)
            else:
                # no address written out: the first text with a variable in it, or nothing known
                i = next((i for i, a in enumerate(plain) if "$" in a), None)
                self.download(what, op.index, plain[i] if i is not None else "",
                              plain[i + 1] if i is not None and i + 1 < len(plain) else "")
        elif plugin == "system" and arguments:
            self.system(what, op.index, arguments[0])
        elif plugin in _STARTERS and _STARTS.search(function):
            self.start(what, op.index, " ".join(a for a in arguments if not a.startswith("/")))

    def system(self, what: str, index: int, call: str) -> None:
        """``System::Call 'urlmon::URLDownloadToFile(i 0, t "address", t "file", ...)'``"""
        texts = []
        for match in _QUOTED.finditer(call[:4096]):
            register = match.group(4)
            if register:                                    # r0 - r9 / R0 - R9 are $0 - $9 / $R0 - $R9
                texts.append(self.expand("$" + ("R" if register[0] == "R" else "") + register[1]))
            else:
                texts.append(self.expand(next(g for g in match.groups()[:3] if g is not None)))
        name = _SYSTEM_DOWNLOAD.search(call)
        if name:
            label = "%s %s" % (what, name.group(0))
            at = next((i for i, t in enumerate(texts) if _ADDRESS.match(t)), None)
            if at is None:
                at = next((i for i, t in enumerate(texts) if "$" in t), None)
            self.download(label, index, texts[at] if at is not None else "",
                          texts[at + 1] if at is not None and at + 1 < len(texts) else "")
        name = _SYSTEM_START.search(call)
        if name:
            self.start("%s %s" % (what, name.group(0)), index, " ".join(texts))

    def hits(self) -> List[Hit]:
        out: List[Hit] = []
        for start in self.starts:
            for download in self.downloads:
                self.clock.tick()
                if download.kind != LOCAL and start.index != download.index \
                        and _named_in(download.saved, start.command):
                    out.append(Hit("dropper", start.index + 1, start.what, download.what, download.index + 1,
                                   download.kind, download.address, download.saved))
                    break
            if len(out) >= _MAX_HITS:
                break
        return out


def analyse(header: bytes) -> Found:
    """What the script of an NSIS installer (its unpacked ``header``) starts
    that it downloaded before. Never raises."""
    clock = Clock(MAX_STEPS, MAX_SECONDS)
    flow = _Flow(clock)
    hits: List[Hit] = []
    try:
        try:
            flow.run(nsis.instructions(header))
        except Budget as exc:
            clock.ended(exc)             # what was read up to the limit still counts - and it is said
        hits = flow.hits()
    except (Budget, RecursionError) as exc:
        clock.ended(exc)
    except Exception:                    # an analysis aid must never break the scan itself
        return Found([], [])
    commands = [(start.index + 1, start.command) for start in flow.starts if not start.library]
    seen = {(hit.line, hit.source_line) for hit in hits}
    for hit in remote_sh.analyse_commands(commands):
        if (hit.line, hit.source_line) not in seen and len(hits) < 2 * _MAX_HITS:
            hits.append(hit)
    return Found(hits, commands, clock.stopped, bool(flow.downloads) or flow.named)
