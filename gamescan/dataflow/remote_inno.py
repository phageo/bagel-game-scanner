"""Download-and-run in the ``[Code]`` and ``[Run]`` of an Inno Setup installer.

The compiled ``[Code]`` comes from :func:`gamescan.unpack.ifps.load` - data,
read once; nothing is interpreted or run. A download is a call of one of
Inno Setup's download functions (``DownloadTemporaryFile``, the ``Add`` of a
download page), of the function of a download plug-in (``idpAddFile`` ...) or
of a Windows download function the script imports. A start is ``Exec`` /
``ShellExec``, a ``[Run]`` row, a Windows function that starts programs, or a
library the script imports functions from. The two are tied when the file
the download is saved to is named in what is started - also under the name a
``[Files]`` row copies it to.

What is started without having been downloaded - a file of the package, a
program of the PC - is no chain: the files of the package are scanned
themselves. The command lines the script starts are also read like the
lines of one batch file (:func:`remote_sh.analyse_commands`).

A tracer, like the others: the instructions of a procedure are read once,
from top to bottom, with the stack of the script machine as a list of texts;
a variable has the text it was given last on the way. A procedure of the
script that is called is read at the call, with what it is handed. Jumps are
not followed; what a function of Inno Setup returns is not known, except for
the few that hand a text on (``ExpandConstant`` ...).
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_inno.py")

import re
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from ..unpack import ifps
from . import remote_sh
from .remote import LOCAL, REMOTE, UNRESOLVED, Hit
from .values import CLOSE, OPEN, SAFETY_SECONDS, Budget, Clock

MAX_STEPS = 1_000_000           # instructions read in one reading (the same file, the same answer)
MAX_SECONDS = SAFETY_SECONDS    # ... and a far safety cap
_MAX_DEPTH = 3                  # procedures of the script read inside one another
_MAX_STACK = 4096
_MAX_ARGUMENTS = 16             # what is handed to one call
_MAX_DOWNLOADS = 256
_MAX_STARTS = 4096
_MAX_HITS = 8
_MAX_TEXT = 2048                # a text that was put together
_MAX_GLOBALS = 10_000
_MAX_COPIES = 8                 # [Files] rows that copy one downloaded file
_PARAMETERS = 16                # places below a procedure that is read by itself
HOLE = OPEN + CLOSE             # a part that is only known when the installer runs

NO_CODE, READ, UNREAD = "none", "read", "unread"
ROW = "[Run]"                   # the ``sink`` of a hit whose start is a row, not an instruction

# Inno Setup's own download functions: where the address and the file name stand
_DOWNLOADS = {"DOWNLOADTEMPORARYFILE": (0, 1), "DOWNLOADTEMPORARYFILEWITHISSIGVERIFY": (0, 2)}
_PAGE, _PAGE_ADDS = "TDOWNLOADWIZARDPAGE", ("ADD", "ADDEX", "ADDWITHISSIGVERIFY", "ADDEXWITHISSIGVERIFY")
_PAGES = ("CREATEDOWNLOADPAGE",)
# functions of libraries: download plug-ins (Inno Download Plugin, InnoTools Downloader,
# isxdl) and Windows' own
_LIBRARY_DOWNLOAD = re.compile(_IND[0])
_NETWORK_LIBRARIES = frozenset({"urlmon", "wininet", "winhttp", "ws2_32", "wsock32", "idp", "itdownload",
                                "isxdl", "libcurl", "inetc"})
_STARTS = {"EXEC": (0, 1), "EXECASORIGINALUSER": (0, 1), "EXECANDLOGOUTPUT": (0, 1),
           "EXECANDCAPTUREOUTPUT": (0, 1), "SHELLEXEC": (1, 2), "SHELLEXECASORIGINALUSER": (1, 2)}
_LIBRARY_START = re.compile(_IND[1])
# functions of Inno Setup that hand their text on, as far as a file name goes
_HAND_ON = frozenset({"EXPANDCONSTANT", "EXPANDCONSTANTEX", "REMOVEBACKSLASH", "REMOVEBACKSLASHUNLESSROOT",
                      "ADDQUOTES", "REMOVEQUOTES", "TRIM", "TRIMLEFT", "TRIMRIGHT", "EXPANDFILENAME",
                      "EXPANDUNCFILENAME", "ADDBACKSLASH"})
# words in the texts of the code that speak of downloading (a command line, a COM object)
_DOWNLOAD_WORDS = re.compile(_IND[2])
DOWNLOAD_WORDS = _DOWNLOAD_WORDS        # (the NSIS reading asks the same: remote_nsis)
_ADDRESS = re.compile(r"(?i)\A(?:https?|ftp)://")
_LOCAL = re.compile(r"(?i)\A(?:https?|ftp)://(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|\Z)")
_NAME_BEFORE = re.compile(r"[\w.\-]\Z")
_NAME_AFTER = re.compile(r"\A[\w.]")
_FORMAT = re.compile(r"%[-\d.*:]*[a-zA-Z]")
_COMMAND_PROCESSOR = re.compile(r"(?i)\{cmd\}")      # Inno Setup's constant for cmd.exe
_HOLES = re.compile("(?:" + re.escape(HOLE) + "){2,}")


class Download(NamedTuple):
    what: str               # DownloadTemporaryFile, TDownloadWizardPage.Add, urlmon.dll URLDownloadToFileW ...
    index: int              # the number of the instruction (from 1)
    kind: str               # remote | unresolved | local
    address: str
    saved: str              # where it is written ("" = not known)


class Start(NamedTuple):
    what: str               # Exec, ShellExec, [Run] ...
    index: int              # the number of the instruction; a row: minus its number
    command: str
    library: bool = False   # a library the script calls into: ``command`` is its name


class Found(NamedTuple):
    hits: List[Hit]                 # ``line`` / ``source_line``: instruction numbers; a row: minus its number
    commands: List[Tuple[int, str]]         # every command line the installer starts
    state: str                      # NO_CODE, READ, or UNREAD: the [Code] was not read to its end
    downloads: bool                 # does the [Code] name anything that downloads?
    problem: str = ""               # UNREAD: why


class _Ref(NamedTuple):
    """A place handed on instead of its value: a result, a ``var`` parameter."""
    place: int              # a place on the stack (0 and up) or a variable of the script (below 0)


def _same(text: str) -> str:
    return text.replace("/", "\\").lower().strip("\"' \t")


def _named_in(saved: str, command: str) -> bool:
    """Is the file ``saved`` named in ``command``? A bare file name also fits a
    longer path that ends in it, and so does the file name behind a folder
    that is only known when the installer runs."""
    saved, command = _same(saved), command.replace("/", "\\").lower()
    if not saved or saved.endswith("\\") or HOLE in saved.rsplit("\\", 1)[-1]:
        return False
    leaf = saved.rsplit("\\", 1)[-1]
    for name in dict.fromkeys((saved, HOLE + "\\" + leaf, HOLE + leaf)):
        at = command.find(name)
        while at >= 0:
            before, after = command[:at], command[at + len(name):]
            if not _NAME_AFTER.match(after) and (not _NAME_BEFORE.search(before) or "\\" not in name
                                                 and before.endswith("\\")):
                return True
            at = command.find(name, at + 1)
    return False


def _kind(address: str) -> str:
    if _LOCAL.match(address):
        return LOCAL
    # (``{code:...}`` / ``{param:...}`` in an address is filled in when the installer runs)
    return REMOTE if _ADDRESS.match(address) and HOLE not in address and "{" not in address else UNRESOLVED


def _join(left: Optional[str], right: Optional[str]) -> Optional[str]:
    if left is None and right is None:
        return None
    text = (HOLE if left is None else left) + (HOLE if right is None else right)
    return _HOLES.sub(HOLE, text)[:_MAX_TEXT]


def _library(name: str) -> str:
    """``files:idp.dll`` / ``{tmp}\\x.dll`` / ``urlmon.dll`` -> ``idp`` / ``x`` / ``urlmon``."""
    leaf = re.split(r"[\\/:,]", name.strip())[-1].lower()
    return leaf[:-4] if leaf.endswith(".dll") else leaf


def names_download(script: ifps.Script) -> bool:
    """Does the compiled code name anything that downloads - a download function
    of Inno Setup, of a plug-in or of Windows, a network library, or a text that
    speaks of downloading (a command line, a COM object)?"""
    for procedure in script.procedures:
        if procedure.external:
            if procedure.name in _DOWNLOADS or procedure.name in _PAGES or procedure.owner == _PAGE:
                return True
            if procedure.library and (_library(procedure.library) in _NETWORK_LIBRARIES
                                      or _LIBRARY_DOWNLOAD.search(procedure.function)):
                return True
        for instruction in procedure.code:
            for operand in instruction.operands:
                if operand.kind == ifps.CONSTANT and isinstance(operand.value, str) \
                        and _DOWNLOAD_WORDS.search(operand.value):
                    return True
    return False


class _Flow:
    def __init__(self, script: ifps.Script) -> None:
        self.script = script
        self.clock = Clock(MAX_STEPS, MAX_SECONDS)
        self.variables: Dict[int, Optional[str]] = {}       # the variables of the script
        self.stack: List[object] = []
        self.downloads: Dict[Tuple[int, str, str], Download] = {}
        self.starts: Dict[Tuple[int, str], Start] = {}
        self.first: Dict[int, int] = {}                     # procedure -> the number of its first instruction
        count = 0
        for procedure in script.procedures:
            self.first[procedure.index] = count + 1
            count += len(procedure.code)

    # -- places ------------------------------------------------------------------------------
    def place(self, number: int, base: int) -> Optional[int]:
        """Where variable ``number`` of a procedure whose own places begin at ``base``
        is: a place on the stack (0 and up) or a variable of the script (below 0)."""
        if number < ifps.GLOBALS_END:
            return -1 - number
        at = base + (number - ifps.LOCALS)
        if number > ifps.LOCALS:
            at -= 1
        return at if 0 <= at < len(self.stack) else None

    def held(self, place: Optional[int]):
        """What stands at ``place`` itself (a text, nothing, or a reference)."""
        if place is None:
            return None
        if place < 0:
            return self.variables.get(-1 - place)
        return self.stack[place] if place < len(self.stack) else None

    def get(self, place: Optional[int]) -> Optional[str]:
        value = self.held(place)
        for _ in range(4):
            if not isinstance(value, _Ref):
                break
            value = self.held(value.place)
        return value if isinstance(value, str) else None

    def put(self, place: Optional[int], value: Optional[str]) -> None:
        for _ in range(4):
            held = self.held(place)
            if not isinstance(held, _Ref):
                break
            place = held.place
        if place is None:
            return
        if place < 0:
            if -1 - place in self.variables or len(self.variables) < _MAX_GLOBALS:
                self.variables[-1 - place] = value
        elif place < len(self.stack):
            self.stack[place] = value

    def refer(self, operand: ifps.Operand, base: int):
        """A reference to the variable ``operand`` names (to what it refers to itself)."""
        place = self.place(operand.number, base) if operand.kind == ifps.VARIABLE else None
        held = self.held(place)
        return held if isinstance(held, _Ref) else None if place is None else _Ref(place)

    def read(self, operand: ifps.Operand, base: int, joined: bool = False) -> Optional[str]:
        if operand.kind == ifps.CONSTANT:
            if isinstance(operand.value, str):
                return operand.value
            if joined and operand.number in (ifps.CHAR, ifps.WIDE_CHAR) and isinstance(operand.value, int) \
                    and operand.value >= 0x20:
                return chr(operand.value)
            return None
        return self.get(self.place(operand.number, base)) if operand.kind == ifps.VARIABLE else None

    def write(self, operand: ifps.Operand, base: int, value: Optional[str]) -> None:
        if operand.kind == ifps.VARIABLE:
            self.put(self.place(operand.number, base), value)

    def push(self, value) -> None:
        if len(self.stack) >= _MAX_STACK:
            raise Budget()
        self.stack.append(value)

    # -- reading -----------------------------------------------------------------------------
    def run(self) -> None:
        """Every procedure of the script, by itself (what it is handed is not known
        then). Called twice: the first time for what the variables of the script are
        given anywhere, the second time for the calls."""
        self.clock = Clock(MAX_STEPS, MAX_SECONDS)
        self.downloads, self.starts = {}, {}
        try:
            for procedure in self.script.procedures:
                if not procedure.external and procedure.code:
                    self.stack = [None] * _PARAMETERS
                    self.walk(procedure, _PARAMETERS, 0)
        finally:
            self.stack = []

    def walk(self, procedure: ifps.Procedure, base: int, depth: int) -> None:
        code = procedure.code
        first = self.first[procedure.index]
        heights: Dict[int, int] = {}            # offset of a jump target -> how high the stack is there
        loose = False                           # behind a jump away or a return: the stack is another
        for at, op in enumerate(code):
            self.clock.tick()
            if loose and op.offset in heights:
                height = max(heights[op.offset], base)
                del self.stack[height:]
                self.stack.extend([None] * (height - len(self.stack)))
            loose = False
            c = op.code
            if c == ifps.PUSH_TYPE:
                self.push(None)
            elif c == ifps.ASSIGN:
                self.write(op.operands[0], base, self.read(op.operands[1], base))
            elif c == ifps.POP:
                if len(self.stack) > base:
                    self.stack.pop()
            elif c == ifps.PUSH:
                self.push(self.read(op.operands[0], base))
            elif c == ifps.PUSH_VAR:
                self.push(self.refer(op.operands[0], base))
            elif c == ifps.SET_POINTER:
                target = op.operands[0]
                place = self.place(target.number, base) if target.kind == ifps.VARIABLE else None
                if place is not None and place >= 0:
                    self.stack[place] = self.refer(op.operands[1], base)
            elif c == ifps.CALCULATE:
                value = None
                if op.extra == 0:               # +
                    value = _join(self.read(op.operands[0], base, True), self.read(op.operands[1], base, True))
                self.write(op.operands[0], base, value)
            elif c == ifps.CALL:
                pops = 0
                while at + 1 + pops < len(code) and code[at + 1 + pops].code == ifps.POP:
                    pops += 1
                result = at > 0 and code[at - 1].code == ifps.PUSH_VAR
                self.call(op.number, first + at, base, depth, result, pops)
            elif c in (ifps.COMPARE, ifps.NOT, ifps.NEGATE, ifps.INTEGER_NOT, ifps.INCREMENT, ifps.DECREMENT,
                       ifps.SET_COPY_POINTER):
                self.write(op.operands[0], base, None)
            elif c in ifps.JUMPS:
                height = len(self.stack) - (1 if c == ifps.POP_GOTO else 2 if c == ifps.POP2_GOTO else 0)
                heights.setdefault(op.number, height)
                loose = c in (ifps.GOTO, ifps.POP_GOTO, ifps.POP2_GOTO)
            elif c == ifps.RETURN:
                loose = True
        del self.stack[base:]

    def call(self, number: int, index: int, base: int, depth: int, result: bool, pops: int) -> None:
        if not 0 <= number < len(self.script.procedures):
            return
        procedure = self.script.procedures[number]
        top = len(self.stack) - 1
        # a function: the place for its result was pushed last, as a reference
        target = self.stack[top] if result and top >= base and isinstance(self.stack[top], _Ref) else None
        first = top - 1 if target is not None else top
        # what was pushed for the call is popped behind it
        count = pops - (1 if target is not None else 0)
        if count <= 0 and procedure.external:
            count = _MAX_ARGUMENTS // 2
        places = [first - i for i in range(max(0, min(count, _MAX_ARGUMENTS, first - base + 1)))]
        if not procedure.external:
            if depth + 1 < _MAX_DEPTH and procedure.code:
                self.walk(procedure, len(self.stack), depth + 1)        # read with what it is handed
            else:
                self.forget(places, target)
            return
        value = self.external(procedure, index, [self.get(place) for place in places])
        self.forget(places, None)
        if target is not None:
            self.put(target.place, value)

    def forget(self, places: List[int], target: Optional[_Ref]) -> None:
        """What a call was handed by reference is not known afterwards."""
        for place in places:
            held = self.stack[place]
            if isinstance(held, _Ref):
                self.put(held.place, None)
        if target is not None:
            self.put(target.place, None)

    def external(self, procedure: ifps.Procedure, index: int, arguments: List[Optional[str]]) -> Optional[str]:
        """A call of something outside the script; what it returns, if that is known."""
        name = procedure.name

        def text(at: int) -> Optional[str]:
            return arguments[at] if 0 <= at < len(arguments) else None

        if name in _HAND_ON:
            value = text(0)
            if name == "ADDBACKSLASH" and value is not None and not value.endswith("\\"):
                value += "\\"
            return value
        if name == "FORMAT":
            return None if text(0) is None else _HOLES.sub(HOLE, _FORMAT.sub(HOLE, text(0)))[:_MAX_TEXT]
        if name in _DOWNLOADS:
            self.download(_SPELLED.get(name, name), index, arguments, _DOWNLOADS[name], "{tmp}\\")
        elif procedure.owner == _PAGE and procedure.function in _PAGE_ADDS:
            # (the page itself is handed over first)
            self.download("TDownloadWizardPage.%s" % _SPELLED.get(procedure.function, procedure.function), index,
                          arguments, (1, 3 if "ISSIG" in procedure.function else 2), "{tmp}\\")
        elif procedure.library and (_LIBRARY_DOWNLOAD.search(procedure.function)
                                    or _library(procedure.library) in _NETWORK_LIBRARIES):
            at = next((i for i, a in enumerate(arguments) if a is not None and _ADDRESS.match(a)), None)
            if at is not None or _LIBRARY_DOWNLOAD.search(procedure.function):
                self.download("%s %s" % (procedure.library, procedure.function), index, arguments,
                              (0, 1) if at is None else (at, at + 1), "")
        elif name in _STARTS:
            program, parameters = (text(i) for i in _STARTS[name])
            if program is not None or parameters is not None:
                self.start(_SPELLED.get(name, name), index,
                           " ".join(HOLE if part is None else part for part in (program, parameters)).strip())
        elif procedure.library and _LIBRARY_START.search(procedure.function):
            known = [a for a in arguments if a]
            if known:
                self.start("%s %s" % (procedure.library, procedure.function), index, " ".join(known))
        return None

    def download(self, what: str, index: int, arguments: List[Optional[str]], where: Tuple[int, int],
                 folder: str) -> None:
        at = next((i for i, a in enumerate(arguments) if a is not None and _ADDRESS.match(a)), where[0])
        address = arguments[at] if at < len(arguments) and arguments[at] is not None else ""
        name_at = where[1] + (at - where[0])
        saved = arguments[name_at] if 0 <= name_at < len(arguments) and arguments[name_at] is not None else ""
        if saved and folder and "\\" not in saved and "/" not in saved:
            saved = folder + saved              # a bare name: Inno Setup saves into its temporary folder
        key = (index, address, saved)
        if key not in self.downloads and len(self.downloads) < _MAX_DOWNLOADS:
            self.downloads[key] = Download(what, index, _kind(address), address, saved)

    def start(self, what: str, index: int, command: str, library: bool = False) -> None:
        key = (index, command)
        if command.strip() and key not in self.starts and len(self.starts) < _MAX_STARTS:
            self.starts[key] = Start(what, index, command, library)

    def found(self) -> Tuple[List[Download], List[Start]]:
        """The downloads and starts, in the order of the instructions. A procedure
        is read by itself and again at every call of it: where an address was read
        at an instruction, the readings of that instruction that did not get one
        are left out - and so are the starts with a part missing where a whole
        command line was read."""
        resolved = {d.index for d in self.downloads.values() if d.kind != UNRESOLVED}
        downloads = [d for d in self.downloads.values() if d.kind != UNRESOLVED or d.index not in resolved]
        whole = {s.index for s in self.starts.values() if HOLE not in s.command}
        starts = [s for s in self.starts.values() if HOLE not in s.command or s.index not in whole]
        return sorted(downloads, key=lambda d: d.index), sorted(starts, key=lambda s: s.index)


_SPELLED = {"DOWNLOADTEMPORARYFILE": "DownloadTemporaryFile",
            "DOWNLOADTEMPORARYFILEWITHISSIGVERIFY": "DownloadTemporaryFileWithISSigVerify",
            "ADD": "Add", "ADDEX": "AddEx", "ADDWITHISSIGVERIFY": "AddWithISSigVerify",
            "ADDEXWITHISSIGVERIFY": "AddExWithISSigVerify", "EXEC": "Exec",
            "EXECASORIGINALUSER": "ExecAsOriginalUser", "EXECANDLOGOUTPUT": "ExecAndLogOutput",
            "EXECANDCAPTUREOUTPUT": "ExecAndCaptureOutput", "SHELLEXEC": "ShellExec",
            "SHELLEXECASORIGINALUSER": "ShellExecAsOriginalUser"}


def _copies(saved: str, files: Sequence[Tuple[str, str]]) -> List[str]:
    """Where the ``[Files]`` rows put the downloaded file ``saved`` (a row whose
    source is that file: ``Source: "{tmp}\\x.exe"; DestDir: "{app}"; Flags: external``)."""
    out: List[str] = []
    if saved and HOLE not in saved:
        for source, destination in files:
            if source and destination and _same(source) == _same(saved) and len(out) < _MAX_COPIES:
                out.append(destination)
    return out


def position(number: int) -> str:
    """``instruction 12`` / ``row 2`` for the numbers of a hit ("" = no place of its own)."""
    return "instruction %d" % number if number > 0 else "row %d" % -number if number < 0 else ""


def analyse(block: bytes, rows: Optional[Sequence] = None,
            files: Optional[Sequence[Tuple[str, str]]] = None) -> Found:
    """What an Inno Setup installer starts that it downloaded before: ``block``
    is its unpacked setup script, ``rows`` its ``[Run]`` rows (``(number,
    filename, parameters)``) and ``files`` the source and destination of its
    ``[Files]`` rows, as far as they are known. Never raises."""
    try:
        code = ifps.find(block)
        script, problem = None, ""
        if code is None:
            if ifps.named(block):
                problem = "the compiled code was not found where it should be"
        else:
            try:
                script = ifps.load(code)
            except ifps.IfpsError as exc:
                problem = str(exc) or "the compiled code is damaged"
        # (without [Code], or with [Code] that cannot be read, the rows are still read:
        # a row can download and start something in one command line)
        downloads: List[Download] = []
        starts: List[Start] = []
        if script is not None:
            flow = _Flow(script)
            problem = "its instructions were not read to their end" if script.cut else ""
            for _reading in range(2):
                try:
                    flow.run()
                except (Budget, RecursionError):
                    problem = "the reading stopped at its limit"
            downloads, starts = flow.found()
        seen = set()
        for procedure in script.procedures if script is not None else ():     # a library the script calls into is run
            if procedure.external and procedure.library and procedure.library not in seen \
                    and len(starts) < _MAX_STARTS:
                seen.add(procedure.library)
                starts.append(Start("library %s" % procedure.library, 0, procedure.library, True))
        for row in list(rows or ())[:_MAX_STARTS]:
            starts.append(Start(ROW, -row[0], ("%s %s" % (row[1], row[2])).strip()))
        hits: List[Hit] = []
        for start in starts:
            for download in downloads:
                if download.kind == LOCAL or start.index == download.index:
                    continue
                if any(_named_in(place, start.command)
                       for place in [download.saved] + _copies(download.saved, files or ())):
                    hits.append(Hit("dropper", start.index, start.what, download.what, download.index,
                                    download.kind, download.address, download.saved))
                    break
            if len(hits) >= _MAX_HITS:
                break
        # the command lines, in their order: the instructions first, then the rows
        lines = [(n + 1, start) for n, start in enumerate(s for s in starts if not s.library)]
        at = {n: start.index for n, start in lines}
        known = {(hit.line, hit.source_line) for hit in hits}
        for hit in remote_sh.analyse_commands([(n, _COMMAND_PROCESSOR.sub("cmd.exe", start.command.replace(HOLE, "")))
                                               for n, start in lines]):
            hit.line, hit.source_line = at.get(hit.line, hit.line), at.get(hit.source_line, hit.source_line)
            if (hit.line, hit.source_line) not in known and len(hits) < 2 * _MAX_HITS:
                hits.append(hit)
        state = UNREAD if problem else NO_CODE if script is None else READ
        return Found(hits, [(start.index, start.command) for _n, start in lines], state,
                     script is not None and names_download(script), problem)
    except Exception:                    # an analysis aid must never break the scan itself
        return Found([], [], UNREAD, False, "the reading failed")
