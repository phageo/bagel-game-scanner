"""Handler base class. Adding a new engine = adding one subclass."""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/handlers/base.py")

import re
from typing import FrozenSet, Iterable, List, Optional, Tuple

from .. import dataflow, electron_official, engine_hashes, inno_official, known_findings, library_hashes, localdrop, redist
from ..dataflow import _RISKY_COMMAND, electron_windows, remote, remote_inno, remote_nsis, remote_py, remote_rb, remote_sh, remote_vbs, self_update, shared, values
from ..defender import AMSI_DETECTED
from ..entropy import HIGH as HIGH_ENTROPY, high_entropy_literals, profile
from ..models import Category, FileContext, Finding, Severity
from ..rules import RuleEngine
from ..unpack import ifps, inno, nsis, screnc

_PE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".pyd", ".node", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".com",
    ".mui", ".efi", ".ax", ".acm", ".asi", ".winmd", ".plugin", ".rll", ".x64", ".x86",
    ".sfx",     # self-extractor modules (7-Zip, WinRAR)
    ".tmp",     # installers unpack their helper programs as .tmp
})
_DOUBLE_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|bmp|txt|pdf|docx?|xlsx?|mp[34]|ogg|wav|zip|rar|7z|json|rpy|sav|save)"
    r"\.(?:exe|scr|com|pif|bat|cmd|vbs|js|lnk|ps1|hta)$")


_INSTALLER_SCRIPT = "[installer script]"        # the script of an NSIS / Inno Setup installer
REMOTE_CODE_REASON = (
    "What this file runs comes from the network: it requests data from an address and "
    "executes what comes back - as code, as a command, or as a file that is written to "
    "disk and then started - or it loads a script directly from a remote address. "
    "Whoever controls that address decides what runs on this PC.")
# a chain whose download and execution are in two files (Scanner._join_shared)
ACROSS_FILES = "  [across two files]"
ACROSS_FILES_REASON = (
    " Here the two halves are in two files: one file downloads the data and stores it under "
    "a name both files use, and this file runs what that name holds.")
ACROSS_FILES_DROP_REASON = (
    " Here the two halves are in two files: one file downloads the data and writes it to a "
    "file on disk, and this file starts that file.")
JOIN_CUT = "PY-JOIN-001"            # the second reading of a script stopped at its limit
TEXT_RUN_TITLE = "Attack chain: Text of the script run as a program"
TEXT_RUN_REASON = (
    "This script holds a text and has it run as a program: it writes the text to a file and "
    "then starts or loads that file, or it hands the text to an interpreter on its command "
    "line. That is how a second script is kept out of sight inside the first one; helper and "
    "update scripts are written the same way. The text was read like a script of its own - "
    "its findings are listed with this file.")
# <program> [a few switches] <code flag> <text>: a script runtime runs the text as its program
# (phageo, 2026-10-14: scoped to script runtimes with a code flag - Node.js / Electron / the
# running program itself with -e / --eval / -p, PowerShell with -Command, Python with -c)
_INLINE = (
    # (payload language, programs, the running program itself counts, the code flag)
    ("js", frozenset({"node", "nodejs", "electron", "nw", "bun", "deno"}), True,
     re.compile(r"(?s)\s*(\S+)\s+(?:\S+\s+){0,6}?(-e|--eval|-p|--print|-pe)\s+(\S.*)\Z")),
    ("powershell", frozenset({"powershell", "pwsh"}), False,
     re.compile(r"(?si)\s*(\S+)\s+(?:\S+\s+){0,10}?(-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)\s+(\S.*)\Z")),
    ("python", frozenset({"python", "python3", "pythonw", "py"}), False,
     re.compile(r"(?s)\s*(\S+)\s+(?:\S+\s+){0,6}?(-c)\s+(\S.*)\Z")),
)
REMOTE_ARGUMENT = "CHAIN-REMOTE-ARG"    # downloaded data is an argument of a program that is started
# a file of the game read, decoded, written or unpacked, and started - no download (phageo, 2026-10-17)
LOCAL_DROP = "CHAIN-LOCAL-DROP"
LOCAL_DROP_TITLE = "Attack chain: File of the game decoded, written and started"
LOCAL_DROP_REASON = (
    "This script reads a file of the game, decodes it, writes the result to disk (or unpacks it there "
    "as an archive) and then starts what it wrote. Nothing is downloaded: what runs was carried inside "
    "the game's own files in an encoded form, where a scanner does not see a program. Installers and "
    "launchers sometimes unpack a bundled tool this way; a game rarely does.")
LOCAL_DROP_PROVEN = (
    " The scanner applied the script's own decoding steps to that file in memory - nothing was written "
    "to disk - and the result is %s. So what this script starts is a program that was hidden in the "
    "game's files.")
# a start that reaches the written file through its folder (phageo, 2026-10-18)
LOCAL_DROP_FOLDER_TITLE = "Attack chain: File of the game decoded, written, and a program started beside it"
IN_FOLDER_REASON = (
    " The program is not started by the written file's own name: it is started in the folder the file "
    "was written to (as its working folder), or it lies in that folder itself. A program finds its "
    "libraries and data files in its own folder and in the one it works in, so starting it there runs "
    "or loads what was written - a library put beside a genuine program is the usual way to do it.")
REMOTE_IN_FOLDER_REASON = (
    "This file downloads something, writes it to disk and then starts a program in the folder it wrote "
    "to (as its working folder), or a program that lies in that folder. A program finds its libraries "
    "and data files in its own folder and in the one it works in, so what was downloaded is run or "
    "loaded that way. The downloaded content itself cannot be checked here, so the level is HIGH.")
TEXT_RUN = "CHAIN-TEXT-RUN"       # a text of the script is written to a file that is then started
REDIST_NOTE = "INST-REDIST-001"     # an installer downloads and runs an official redistributable
INSTALLER_NOTE = "  [in the installer's instructions]"
INSTALLER_UNREAD = "INNO-CODE-001"  # an Inno Setup installer's [Code] / [Run] rows were not read to the end
TRACER_CUT = "SCRIPT-LIMIT-001"     # the download-and-run reading of a script stopped at a limit that is a count
# marks of a file's data-flow reading, for chains of nearness it disproves (chains.NO_FLOW):
# the JavaScript reading ran, and a reading stopped at a limit or failed (also where no note
# is made - an official or published file)
FLOW_READ, FLOW_CUT = "flow_read", "flow_cut"
# import() whose address is made only of the app's own values (phageo, 2026-10-14, forty-second message)
LOCAL_IMPORT = (" Every part of the address this import() is given is written-out text or one of the "
                "app's own values - its folder, this PC's settings, environment variables -, nothing from "
                "the network, a file from elsewhere or a page of the app - so the level is lowered.")
LOCAL_BLOB = (" What this loads is a blob: or data: address made from a text inside the app; the "
              "scanner read the whole script and no download reaches that text - so the level is lowered. "
              "The app runs code it makes itself (a built-in script editor, a module it generates).")
# ... and a text followed back to its every source (phageo, 2026-10-15, forty-sixth message)
LOCAL_BLOB_TRACED = (" What this loads is a blob: or data: address made from a text whose every part was "
                     "followed back to written-out text or one of the app's own values - nothing from the "
                     "network, a file from elsewhere or a page of the app - so the level is lowered, also "
                     "where the rest of the script was not read to its end.")
ENCODED_UNREAD = "ENC-SCRIPT-001"   # a Script Encoder block (.vbe / .jse / #@~^) could not be decoded
# a lock file directly in the temporary folder: no sub-folder, no wild card, and an
# extension nothing runs (parts in ‹› are only known at run time)
OWN_LOCK_PATH = re.compile(r"(?i)%te?mp%[\\/]+(?:[^\\/%:*?\"<>|‹›]|‹[^›]*›)+\.(?:lock|pid)")
# decoded code is scanned with the ordinary rules: (rule language, comment style)
_PAYLOAD_RULES = {"python": ("python", "python"), "js": ("js", "c"), "ruby": ("ruby", "ruby"),
                  "powershell": ("shell", "powershell"), "batch": ("shell", "bat")}
_RISKY_CALL = re.compile(
    _IND[0])
_ASSET_DIR = re.compile(
    r"(^|/)(?:img|images?|audio|bgm|bgs|se|sounds?|music|fonts?|movies?|saves?|data|gui)/"
    r"[^!]*\.(?:exe|scr|com|pif|bat|cmd|vbs|vbe|ps1|lnk|hta)$")


class BaseHandler:
    """One subclass per engine family.

    Class attributes:
      ``extensions``  file extensions the handler claims
      ``baseline``    ``(regex, description)`` pairs matching known engine /
                      library files (matched against the lower-cased relative
                      path); the ContextEngine decides what that means
      ``markers``     regexes whose presence means "this engine is in use"
      ``magics``      leading bytes that identify a file regardless of its name
    """

    name = "base"
    engine = ""
    extensions: FrozenSet[str] = frozenset()
    magics: Tuple[bytes, ...] = ()
    streamed: FrozenSet[str] = frozenset()   # extensions read from disk, not from ctx.data
    baseline: Tuple[Tuple[str, str], ...] = ()
    markers: Tuple[str, ...] = ()
    # scripts whose top-level names are shared by all scripts of the game (Ren'Py's store)
    store_scripts: FrozenSet[str] = frozenset()

    def __init_subclass__(cls, **kw) -> None:
        super().__init_subclass__(**kw)
        cls._baseline_rx = [(re.compile(p), d) for p, d in cls.baseline]
        cls._marker_rx = [re.compile(p) for p in cls.markers]

    # -- routing ---------------------------------------------------------------
    def can_handle(self, ctx: FileContext) -> bool:
        return ctx.ext in self.extensions

    def baseline_reason(self, ctx: FileContext) -> str:
        for rx, desc in self._baseline_rx:
            if rx.search(ctx.key):
                return self.confirmed(ctx, desc)
        return ""

    def confirmed(self, ctx: FileContext, desc: str) -> str:
        """``desc`` if the file is not just named like that engine component
        but also built like it; otherwise "" - and the mismatch is noted, to
        be reported with the file's other findings (``ENGINE-001``)."""
        problem = self.structure(ctx, desc)
        if problem:
            from . import engine_files
            if "engine_unsigned" in ctx.cache:
                pass                                # built right, not signed: ENGINE-002
            elif not ctx.is_pe or engine_files.claims_identity(ctx, desc):
                ctx.cache["engine_mismatch"] = (desc, problem)
            return ""
        return desc

    def structure(self, ctx: FileContext, desc: str) -> str:
        """What is wrong with the file as an instance of ``desc`` ("" = nothing).
        Programs are checked here; handlers add the checks for their scripts."""
        from . import engine_files
        return engine_files.binary(ctx, desc) if ctx.is_pe else ""

    def detects_engine(self, key: str) -> bool:
        return any(rx.search(key) for rx in self._marker_rx)

    def engine_for(self, key: str) -> str:
        """Name of the engine this path gives away ("" = none). Handlers that
        cover several engine versions override it to say which one."""
        return self.engine if self.detects_engine(key) else ""

    # -- scanning --------------------------------------------------------------
    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        raise NotImplementedError

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        """Yield files contained in ``ctx`` (archives); scanned like any other."""
        return ()

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        """Findings that are only known once ``expand`` has run to its end
        (what in an archive could not be opened)."""
        return []

    def scan_file(self, ctx: FileContext, rules: RuleEngine, kept=None, keep=None) -> List[Finding]:
        """``kept``: a reading of this exact file kept when the tables were built
        (``known_findings``) - given back instead of reading the file again. ``keep``: the
        builder's - handed what the reading found and the notes it left."""
        out = self._name_checks(ctx)
        if kept is not None:
            try:
                out += known_findings.replay(kept, ctx)
            except known_findings.Mismatch:             # a kept text not in the file: read it
                kept = None
        if kept is None:
            pre = {k: repr(v) for k, v in ctx.cache.items()} if keep is not None else {}
            found = self.scan(ctx, rules)
            if keep is not None:
                # (a note that was there before and that the reading changed: not kept)
                changed = any(k not in ctx.cache or repr(ctx.cache[k]) != v for k, v in pre.items())
                keep(found, known_findings.before(pre), None if changed else
                     {k: v for k, v in ctx.cache.items() if k not in pre})
            out += found
        unsigned = ctx.cache.get("engine_unsigned")
        if unsigned and out and not ctx.baseline and not ctx.cache.get("engine_mismatch"):
            # say why this engine-like file's findings are shown (only if there are any)
            note = self.make(
                ctx, "ENGINE-002", "Engine component without its vendor's signature",
                Category.EVASION, Severity.LOW,
                "The file has the name and the structure of a component of the game engine, "
                "but it does not carry a valid digital signature from that component's vendor. "
                "Name and structure can be imitated, so the file is not exempted: it was "
                "scanned like any unknown program, and its other findings stand.",
                "%s: %s" % unsigned, 0.3)
            note.chainable = False
            out.append(note)
        return out

    def make(self, ctx: FileContext, rule_id: str, title: str, category: Category,
             severity: Severity, reason: str, evidence: str = "", confidence: float = 0.6,
             line: Optional[int] = None, snippet: str = "") -> Finding:
        """Build a structural (non-regex) finding."""
        return Finding(rule_id=rule_id, title=title, category=category, severity=severity,
                       file=ctx.relpath, line=line, snippet=snippet or evidence,
                       evidence=evidence, confidence=confidence, reason=reason,
                       handler=self.name)

    # -- Windows antimalware engine (AMSI) --------------------------------------
    def antimalware(self, ctx: FileContext, rules: RuleEngine, text: str,
                    what: str) -> List[Finding]:
        """Show content this handler *extracted* to the installed antimalware
        engine. On disk that content is hidden inside a compiled, compressed or
        encrypted file, so Windows Defender never gets to see it by itself."""
        amsi = getattr(rules, "amsi", None)
        if amsi is None or not text:
            return []
        result = amsi.scan(text, "%s (%s)" % (ctx.relpath, what))
        if result is None or result < AMSI_DETECTED:
            return []
        return [self.make(
            ctx, "AMSI-001", "Windows antimalware engine flags the extracted content",
            Category.SIGNATURE, Severity.CRITICAL,
            "Content unpacked from this file was shown to the antimalware engine installed "
            "on this PC (Windows Defender, through AMSI), and it identified it as malware.",
            "%s from %s (AMSI result %d)" % (what, ctx.name, result), 0.95)]

    # -- payload resolution (data-flow analysis) ---------------------------------
    @staticmethod
    def page_scripts(text: str) -> str:
        """The JavaScript blocks of an HTML page, joined, each on the lines it has in the
        page (so that line numbers hold). For a page larger than the JavaScript tracer
        reads: its limit is a limit on script, and a page is mostly not script."""
        out, line = [], 1
        for at, code in remote_vbs.blocks(text, "js", "js")[0]:
            out.append("\n" * max(at - line, 0))
            out.append(code)
            line = max(at, line) + code.count("\n")
        return "".join(out)

    def resolve_payloads(self, ctx: FileContext, rules: RuleEngine, text: str,
                         language: str, chain_text: Optional[str] = None) -> List[Finding]:
        """Report what really reaches exec / the shell / the network once the
        script's string building, decoding and variable passing are undone,
        and run the ordinary rules over any code that was hidden that way."""
        result = dataflow.analyse(text, language)
        seen = ctx.cache.setdefault("dataflow", {"commands": [], "opaque": 0})
        seen["commands"] += result.commands
        seen["opaque"] += result.opaque
        if language in ("python", "renpy"):
            seen.setdefault("own_locks", set()).update(self._own_locks(text, result.resolved))
        out = [self._resolved(ctx, hit, language) for hit in result.resolved]
        if result.cut:
            # this reading stopped at its step limit (or at its emergency brake): said, as
            # for the tracers below (phageo, 2026-10-12) - one note per file
            out += self.tracer_cut(ctx, "%s (reading what reaches exec / the shell)" % result.cut)
        for line, payload_language, code in result.payloads:
            rule_language, style = _PAYLOAD_RULES[payload_language]
            for f in rules.scan(code, rule_language, ctx, self.name, comment_style=style,
                                numbered=False, quoted=payload_language == "js"):
                f.line = line or None
                f.evidence += "  [in code decoded at line %d]" % line
                out.append(f)
            out += self.antimalware(ctx, rules, code, "decoded payload")
        if language == "js":
            ctx.cache[FLOW_READ] = True
            # what the script's process starts are made of (ContextEngine: severity by flow)
            ctx.cache["js_starts"] = remote.starts(text)
            ctx.cache["js_asks_only"] = "child_process" in text and remote.asked_for_nothing(text)
            # (chain_text: what the download-and-run chain reads when that is not the whole
            # file - the script blocks of a large HTML page)
            out += self.remote_code(ctx, text if chain_text is None else chain_text)
            out += self.written_texts(ctx, rules, text if chain_text is None else chain_text)
            for line, payload_language, code in result.payloads:
                if payload_language == "js":
                    out += self.remote_code(ctx, code, line)
        elif language in ("python", "renpy"):
            out += self.remote_code(ctx, text, language=language, resolved=result.resolved)
            for line, payload_language, code in result.payloads:
                if payload_language == "python":
                    out += self.remote_code(ctx, code, line, language="python")
        elif language == "ruby":
            out += self.remote_code(ctx, text, language="ruby")
            for line, payload_language, code in result.payloads:
                if payload_language == "ruby":
                    out += self.remote_code(ctx, code, line, language="ruby")
        elif language in ("powershell", "batch") and ctx.name.startswith(_INSTALLER_SCRIPT):
            # an installer's script is a list of texts, not a batch file: its instructions
            # are read instead (NSIS: the instruction table; Inno Setup: [Code] and [Run])
            out += self.installer_code(ctx, rules)
        elif language in ("powershell", "batch"):
            out += self.remote_code(ctx, text, language=language)
        command_lines = list(result.command_lines)
        if language == "js":
            # ... and what a JScript under the Windows Script Host starts with WScript.Shell
            # Run / Exec or Shell.Application ShellExecute (as for VBScript)
            stopped: List[str] = []
            command_lines += remote.wsh_commands(text, stopped)
            if stopped:
                out += self.tracer_cut(ctx, stopped[0])
        if language == "js" and command_lines:
            out += self.inline_programs(ctx, rules, command_lines)
        if language in ("python", "renpy", "ruby", "js") and command_lines:
            # the command lines this script starts (os.system("powershell -c ..."), Ruby's
            # system / backticks / %x{} / IO.popen / Open3, JavaScript's child_process exec /
            # spawn / execFile / fork) are PowerShell or batch themselves: the shell chain
            # reads them
            out += self._remote_findings(ctx, remote_sh.analyse_commands(command_lines),
                                         note="  [in a command line this script starts]")
        return out

    @staticmethod
    def _own_locks(text: str, resolved) -> set:
        """Names that hold the path of a lock file this script itself creates
        in the temporary folder (``self.lockfile`` of the usual "only one copy
        of the game at a time" helper): the script opens ``%TEMP%/<name>.lock``
        for writing, the path came from that name, and the name is assigned
        exactly once in the file - so a later ``os.unlink(name)`` deletes that
        file and nothing else (``context._own_lock_file``)."""
        names = set()
        for hit in resolved:
            if hit.kind != "path" or hit.delete or hit.hidden or not OWN_LOCK_PATH.fullmatch(hit.value):
                continue
            for step in hit.trace:
                name = step.split(" <- ", 1)[0].strip()
                if re.fullmatch(r"[A-Za-z_][\w.]{0,80}", name) and len(re.findall(
                        r"(?<![\w.])" + re.escape(name) + r"\s*(?:[-+*/%|&^]|//|>>|<<)?=(?!=)", text)) == 1:
                    names.add(name)
        return names

    def inline_programs(self, ctx: FileContext, rules: RuleEngine, command_lines) -> List[Finding]:
        """CHAIN-TEXT-RUN, the other way: a text of this JavaScript file is handed to a
        script runtime as the program to run - ``node -e <text>``, ``spawn(process.execPath,
        ["-e", text])``, ``powershell -Command <text>``, ``python -c <text>`` - in a command
        line the data-flow reading resolved. No file is written at all. Reported and read
        like a text that is written and started. Only these runtimes and their code flags:
        another program's ``-e`` or ``-c`` is an argument, not a program."""
        out: List[Finding] = []
        chains = 0
        for line, command in command_lines[:400]:
            m = language = None
            for language, programs, itself, pattern in _INLINE:
                m = pattern.match(command)
                if m is not None:
                    program = re.split(r"[\\/]", m.group(1).strip("\"'"))[-1].lower()
                    program = program[:-4] if program.endswith(".exe") else program
                    if program in programs or (itself and ("execPath" in m.group(1) or "argv" in m.group(1))):
                        break
                    m = None
            if m is None or chains >= 4 * remote.MAX_WRITTEN:
                continue
            chains += 1
            code = m.group(3).strip()
            if code[:1] in "\"'" and code[-1:] == code[:1]:
                code = code[1:-1]
            if len(code.strip()) < 8:
                continue
            flow = "text handed to %s %s as its program (line %d)" % (m.group(1)[:60], m.group(2), line)
            chain = self.make(ctx, TEXT_RUN, TEXT_RUN_TITLE, Category.CHAIN, Severity.HIGH, TEXT_RUN_REASON, flow, 0.6,
                              line=line or None, snippet=flow)
            chain.chainable = False
            out.append(chain)
            rule_language, style = _PAYLOAD_RULES[language]
            inner = rules.scan(code, rule_language, ctx, self.name, comment_style=style, numbered=False,
                               quoted=language == "js")
            for f in inner:
                f.line = line or None
                f.evidence += "  [in text this script hands to an interpreter as its program, line %d]" % line
            out += inner
            if language != "powershell":             # (a PowerShell command line is read by the shell chain already)
                out += self.remote_code(ctx, code, line, language=language)
        return out

    def written_texts(self, ctx: FileContext, rules: RuleEngine, text: str) -> List[Finding]:
        """CHAIN-TEXT-RUN: a text of this JavaScript file is written to a file that the
        script then starts or loads (:func:`gamescan.dataflow.remote.written_and_started`;
        phageo, 2026-10-13). A word inside a quoted text is no call site on its own - but such
        a text is a program: the chain is reported (HIGH: helpers and updaters do it too),
        and the written text is read with the rules of the language its file's ending
        names, and by that language's download-and-run reading - what it does decides the
        rest. Bounded: ``remote.MAX_WRITTEN`` texts, ``remote.MAX_WRITTEN_TEXT`` characters."""
        found, cut = remote.written_and_started(text)
        out: List[Finding] = []
        for item in found:
            flow = "text written to %s (line %d) -> %s (line %d)" % (
                item.path or "a file whose name is not resolved", item.write_line, item.sink, item.line)
            chain = self.make(ctx, TEXT_RUN, TEXT_RUN_TITLE, Category.CHAIN, Severity.HIGH, TEXT_RUN_REASON,
                              flow, 0.6, line=item.line, snippet=flow)
            chain.chainable = False
            out.append(chain)
            note = "  [in text this script writes to a file and starts, line %d]" % item.write_line
            inner: List[Finding] = []
            if item.language in _PAYLOAD_RULES:
                rule_language, style = _PAYLOAD_RULES[item.language]
                inner = rules.scan(item.text, rule_language, ctx, self.name, comment_style=style, numbered=False,
                                   quoted=item.language == "js")
                if item.language in ("js", "python", "ruby", "powershell", "batch"):
                    out += self.remote_code(ctx, item.text, item.write_line, language=item.language)
            elif item.language in ("vbs", "sh"):
                inner = rules.scan(item.text, "shell", ctx, self.name, comment_style=item.language, numbered=False)
            else:                                        # a program, or an ending that is not known
                inner = rules.scan(item.text, "strings", ctx, self.name, numbered=False)
            for f in inner:
                f.line = item.write_line
                f.evidence += note
            out += inner
        if cut:
            out += self.tracer_cut(ctx, "%s (reading what is written to a file and started)" % cut)
        return out

    def engine_trust(self, ctx: FileContext, chain: Finding) -> None:
        """Adjust a CHAIN-REMOTE-CODE finding found in one of the engine's own
        scripts (the engine's updater downloads and runs things by design).
        Nothing here: only a handler that can *verify* its engine's files does."""

    def remote_code(self, ctx: FileContext, text: str, decoded_at: int = 0, language: str = "js",
                    resolved=()) -> List[Finding]:
        """CHAIN-REMOTE-CODE: what the script executes was fetched from the network
        (followed through the data, see :mod:`gamescan.dataflow.remote` for
        JavaScript and :mod:`gamescan.dataflow.remote_py` for Python / Ren'Py).
        CRITICAL, so no baseline - not even an engine / library folder -
        silences it."""
        if language == "js":
            failed: List[str] = []
            # (a file of a verified updater library: its own signature check counts as one)
            hits, cut = remote.study(text, failed, updater=remote.updater_library(ctx.baseline))
            if failed:                   # (a reading that failed proves nothing: chains.NO_FLOW)
                ctx.cache[FLOW_CUT] = True
            if cut:
                return self._remote_findings(ctx, hits, decoded_at) + self.tracer_cut(ctx, cut)
            return self._remote_findings(ctx, hits, decoded_at, whole=not ctx.cache.get(FLOW_CUT))
        elif language == "ruby":
            hits, cut = remote_rb.study(text)
            if not decoded_at:
                # ... and what the script shares with the other scripts of the game - the
                # sections of Scripts.rxdata and loose .rb files are one program (joined after
                # the whole folder was scanned: Scanner._join_shared, dataflow/shared.py)
                share = remote_rb.shared(text)
                self._share(ctx, share)
                cut = values.also(cut, share.cut)
            if cut:
                return self._remote_findings(ctx, hits, decoded_at) + self.tracer_cut(ctx, cut)
        elif language in ("powershell", "batch"):
            hits, cut = remote_sh.study(text, language)
            if not decoded_at:
                # ... and what the script shares with the other scripts of its folder (an
                # environment variable, its arguments, a file) - joined after the whole folder
                # was scanned (Scanner._join_shared, dataflow/shared.py)
                share = remote_sh.shared(text, language, ctx.name)
                self._share(ctx, share)
                cut = values.also(cut, share.cut)
            if cut:
                return self._remote_findings(ctx, hits, decoded_at) + self.tracer_cut(ctx, cut)
        elif decoded_at:
            # (code that was decoded out of the script: a reading of it that stops is said too)
            hits, cut = remote_py.read(text, language == "renpy", resolved)
            if cut:
                return self._remote_findings(ctx, hits, decoded_at) + self.tracer_cut(
                    ctx, "%s (in code decoded at line %d)" % (cut, decoded_at))
        else:
            # ... and what the file shares with other files: the names it stores a
            # download under, and the names whose value it runs. They are joined after
            # the whole folder was scanned (Scanner._join_shared, dataflow/shared.py)
            hits, share = remote_py.study(text, language == "renpy", resolved,
                                          store=ctx.ext in self.store_scripts)
            # (every script says what it imports: a module another script downloaded is
            # run by a plain import, and a script that only imports leaves nothing else)
            ctx.cache.setdefault("imported", {}).update(remote_py.imported(text))
            if share:
                names = ctx.cache.setdefault("shared_names", {"fills": {}, "runs": {}, "drops": {},
                                                              "starts": {}})
                for kind, known in names.items():
                    for name, value in getattr(share, kind).items():
                        known.setdefault(name, value)
            notes = self.tracer_cut(ctx, share.limit) if share.limit else []
            notes += self.local_code(ctx, text, language)
            if share.cut and not self.official_script(ctx):
                return self._remote_findings(ctx, hits, decoded_at) + notes + [self.reading_cut(ctx, share.cut)]
            return self._remote_findings(ctx, hits, decoded_at) + notes
        return self._remote_findings(ctx, hits, decoded_at)

    def local_code(self, ctx: FileContext, text: str, language: str) -> List[Finding]:
        """CHAIN-LOCAL-DROP (phageo, 2026-10-17): this Python / Ren'Py script reads a file of the
        game, decodes it, writes the result to a file (or unpacks it as an archive) and starts
        what it wrote - no download (``remote_py.local_drops``). HIGH. The finding keeps the
        file name it read and the decoding steps (``context["local_drop"]``): once the whole scan
        was seen the scanner applies those steps to that file in memory, and a result that is a
        program or an archive holding one makes it CRITICAL (``Scanner._join_local``,
        :mod:`gamescan.localdrop`)."""
        found, cut = remote_py.local_drops(text, language == "renpy")
        out: List[Finding] = []
        for item in found:
            flow = "reads %s (line %d) -> decodes it: %s -> %s %s (line %d) -> %s (line %d)" % (
                item.read or "a file whose name is not resolved", item.read_line, localdrop.shown(item.steps),
                "unpacks it as an archive into" if item.extracted else "writes it to",
                item.written or "a file whose name is not resolved", item.write_line, item.sink, item.line)
            via = getattr(item, "via", "")
            if via:
                flow += " - started %s" % ("in that folder (its working folder)" if via == remote_py.WORKING_FOLDER
                                           else "from that folder (the program lies there)")
                if len(item.others) > 1:
                    flow += "; %d decoded files were written there" % len(item.others)
            f = self.make(ctx, LOCAL_DROP, LOCAL_DROP_FOLDER_TITLE if via else LOCAL_DROP_TITLE, Category.CHAIN,
                          Severity.HIGH, LOCAL_DROP_REASON + (IN_FOLDER_REASON if via else ""),
                          flow, 0.6, line=item.line, snippet=flow)
            f.chainable = False
            if via:
                f.context["in_folder"] = via
            f.context["local_drop"] = {"file": localdrop.leaf(item.read), "steps": item.steps,
                                       # (through a folder: every decoded file written there may be it)
                                       "also": [{"file": localdrop.leaf(read), "steps": steps}
                                                for read, steps in getattr(item, "others", ())]}
            out.append(f)
        if cut:
            out += self.tracer_cut(ctx, "%s (reading what a script decodes from a file of the game)" % cut)
        return out

    @staticmethod
    def _share(ctx: FileContext, share) -> None:
        """Keep what a script shares with other files (``fills`` / ``runs`` / ``drops`` /
        ``starts``) for the join across files."""
        if share:
            names = ctx.cache.setdefault("shared_names", {"fills": {}, "runs": {}, "drops": {}, "starts": {}})
            for kind, known in names.items():
                for name, value in getattr(share, kind).items():
                    known.setdefault(name, value)

    def installer_code(self, ctx: FileContext, rules: Optional[RuleEngine] = None) -> List[Finding]:
        """What the instructions of an installer download and then start: an NSIS
        installer's instruction table (:mod:`gamescan.dataflow.remote_nsis`), an
        Inno Setup installer's compiled ``[Code]`` and ``[Run]`` rows
        (:mod:`gamescan.dataflow.remote_inno`). Starting a file of the package is
        no chain - that file is scanned itself. A download over https from the
        hand-kept list of official redistributable addresses (:mod:`gamescan.redist`)
        is a visible LOW note that nothing hides; every other download that is
        started is CHAIN-REMOTE-CODE, as in the other languages."""
        header = getattr(ctx.data, "header", b"")
        block = getattr(ctx.data, "block", b"")
        out: List[Finding] = []
        if header:
            read = remote_nsis.analyse(header)
            hits, place = read.hits, lambda number: "instruction %d" % number
            if read.cut:
                # the reading of the instructions stopped at its limit: said (it was a silent
                # two-second clock until 2026-10-12)
                out += self.tracer_cut(ctx, "%s (reading the installer's instructions)" % read.cut)
            elif not read.downloads:
                # read to their end, and nothing in them downloads: a download word or a tool's
                # name in the name of a file the installer installs is a file name - as for Inno
                # Setup (ContextEngine._installed_name; phageo, 2026-10-17, fifty-ninth message)
                names = nsis.installed_texts(header)
                if names:
                    ctx.cache["installed_names"] = names
        elif block:
            rows, files = getattr(ctx.data, "rows", None), getattr(ctx.data, "files", None)
            tools = next((rule.regex for rule in getattr(rules, "rules", ()) if rule.id == "LOL-001"), None)
            if tools is not None:
                # the name of a system tool in a standard message of Inno Setup ("RegSvr32
                # failed with exit code %1") is no instruction (ContextEngine._standard_message)
                lines = [line for line in dict.fromkeys(ctx.text().split("\n")) if tools.search(line)]
                ctx.cache["standard_messages"] = inno.message_lines(
                    block, lines, inno_official.standard_message, ifps.locate(block))
            found = remote_inno.analyse(block, rows, files)
            hits, place = found.hits, remote_inno.position
            # (without a file table the rows cannot be found, and ARC-002 already says that
            # the file table was not read)
            unread = found.problem if found.state == remote_inno.UNREAD else \
                "the [Run] rows were not found" if rows is None and files is not None else ""
            if unread:
                out.append(self.installer_unread(ctx, unread))
            elif files is not None and not found.downloads:
                # the [Code] was read to its end (or there is none), the [Run] rows were
                # read, and the code names nothing that downloads: a download word in the
                # name of a file the installer installs is a file name
                # (ContextEngine._installed_name)
                ctx.cache["installed_names"] = frozenset(
                    destination.strip() for _source, destination in files if destination.strip())
        else:
            return []
        for hit in hits:
            where = hit.address if hit.kind == remote.REMOTE else \
                "not resolved" + (" (%s)" % hit.address if hit.address else "")
            flow = " -> ".join("%s (%s)" % (what, place(number)) if place(number) else what
                               for what, number in ((hit.source, hit.source_line), (hit.sink, hit.line)))
            flow += "; address: %s" % where
            if hit.how == "dropper" and hit.detail:
                flow += "; written to disk as: " + hit.detail
            entry = redist.official(hit.address) if hit.kind == remote.REMOTE else None
            if entry is not None:
                f = self.make(
                    ctx, REDIST_NOTE, "Installer downloads and runs an official redistributable",
                    Category.NETWORK, Severity.LOW,
                    "This installer downloads a file and starts it. The address is on the scanner's "
                    "list of official download addresses of common redistributables (Visual C++, "
                    "DirectX, .NET, OpenAL), and it is requested over https, so this is what "
                    "ordinary game installers do. The downloaded file itself could not be checked: "
                    "it is not part of the package.",
                    "%s  [%s]" % (flow, entry.what), 0.3, snippet=flow)
            else:
                f = self.make(
                    ctx, "CHAIN-REMOTE-CODE", "Attack chain: Remote code execution", Category.CHAIN,
                    Severity.CRITICAL, REMOTE_CODE_REASON, flow + INSTALLER_NOTE,
                    0.85 if hit.kind == remote.REMOTE else 0.65, snippet=flow)
            f.chainable = False
            out.append(f)
        return out

    def tracer_cut(self, ctx: FileContext, limit: str) -> List[Finding]:
        """SCRIPT-LIMIT-001: the reading that follows a download to where it is run
        stopped at a limit in this script - one note for every tracer (JavaScript, Python,
        Ruby, PowerShell, batch, VBScript; phageo, 2026-10-12). A "could not be read" note
        (CLAUDE.md, rule 15): never hidden, and the launcher asks. The limits are counts -
        steps, lines, size - so the same file always gets the same answer (as
        PY-JOIN-001); only the PowerShell / batch tracer also names its emergency clock.

        One note per file. It names the cause of every limit that was reached - size, a
        step limit (any count) or the safety cap by the clock (``values.cause``; phageo,
        2026-10-13) - so a second cause is no longer hidden behind the first: a reading
        that stops after the note is made adds its limit to the note, when its cause is
        not named there yet. None for a file that is verifiably an official file of its
        engine or of a known library - what those do is known (as for PY-JOIN-001)."""
        ctx.cache[FLOW_CUT] = True
        first, *more = [part for part in limit.split("; ") if part] or [limit]
        told = ctx.cache.get("tracer_cut")
        if told:
            note, kinds = told
            for part in [first] + more:
                if values.cause(part) not in kinds:
                    kinds.add(values.cause(part))
                    note.evidence += "; also: %s [cause: %s]" % (part[:120], values.cause(part))
            return []
        if self.official_script(ctx) \
                or ctx.baseline.startswith((engine_hashes.VERIFIED, library_hashes.VERIFIED)) \
                or engine_hashes.verified(ctx.sha256) \
                or electron_official.verified(ctx.sha256):   # (any file of an official engine archive)
            return []
        note = self.make(
            ctx, TRACER_CUT, "Script not read to its end for download-and-run",
            Category.OBFUSCATION, Severity.LOW,
            "The scanner follows what a script downloads to the place where it is run. For this "
            "script that reading reached its limit and stopped early, so a download-and-run "
            "further down in the script could have been missed. The ordinary rules read the "
            "whole file as usual.",
            "the download-and-run reading stopped at its limit: %s [cause: %s]" % (first[:120], values.cause(first)), 0.3)
        note.chainable = False
        ctx.cache["tracer_cut"] = (note, {values.cause(first)})
        if more:
            self.tracer_cut(ctx, "; ".join(more))
        return [note]

    def decode_script(self, ctx: FileContext, text: str) -> Tuple[str, List[Finding]]:
        """``text`` with its Script Encoder blocks (``#@~^ ... ^#~@`` - a ``.vbe`` / ``.jse``
        file, an encoded block of a ``.wsf`` / ``.hta`` / ``.html`` file) replaced by the
        script they hide (:mod:`gamescan.unpack.screnc`; data only), and a note for every
        block that could not be decoded: ENC-SCRIPT-001, a "could not be read" note
        (CLAUDE.md, rule 15) - never hidden, and the launcher asks."""
        if not screnc.encoded(text):
            return text, []
        decoded, problems = screnc.decode(text)
        notes: List[Finding] = []
        for problem in dict.fromkeys(problems):
            note = self.make(
                ctx, ENCODED_UNREAD, "Encoded script could not be decoded",
                Category.OBFUSCATION, Severity.LOW,
                "This file holds a script in the form of Microsoft's Script Encoder, which Windows "
                "decodes and runs like a plain script. The scanner decodes it too and reads what it "
                "hides. Here that did not work - the block is damaged, cut short, or not what it "
                "claims to be - so what it would run could not be inspected.",
                "Script Encoder block: %s" % problem[:160], 0.3)
            note.chainable = False
            notes.append(note)
        if decoded != text:
            ctx.cache["decoded_script"] = True
        return decoded, notes

    def vbscript_code(self, ctx: FileContext, text: str, wrapped: bool = False) -> List[Finding]:
        """CHAIN-REMOTE-CODE in VBScript (:mod:`gamescan.dataflow.remote_vbs`): what the
        script downloads and then runs - as code (``Execute``), or as a file it wrote and
        starts. ``wrapped``: a ``.wsf`` / ``.hta`` / ``.html`` file - its VBScript blocks.
        The command lines the script starts (``WScript.Shell`` ``Run`` / ``Exec``,
        ``ShellExecute``) are PowerShell or batch themselves: the shell chain reads them,
        as for the other languages."""
        found = remote_vbs.analyse(text, wrapped=wrapped)
        out = self._remote_findings(ctx, found.hits)
        if found.commands:
            out += self._remote_findings(ctx, remote_sh.analyse_commands(found.commands),
                                         note="  [in a command line this script starts]")
        if found.cut:
            out += self.tracer_cut(ctx, found.cut)
        return out

    def jscript_blocks(self, ctx: FileContext, text: str, default: str = "") -> List[Finding]:
        """The JScript blocks of a ``.wsf`` / ``.hta`` file, handed to the JavaScript chain
        (with the file's own line numbers)."""
        out: List[Finding] = []
        commands: List[Tuple[int, str]] = []
        for line, code in remote_vbs.blocks(text, "js", default)[0][:64]:
            block = "\n" * (line - 1) + code
            out += self.remote_code(ctx, block, language="js")
            stopped: List[str] = []
            commands += remote.wsh_commands(block, stopped)
            if stopped:
                out += self.tracer_cut(ctx, stopped[0])
        if commands:                                # the command lines the blocks start: the shell chain
            out += self._remote_findings(ctx, remote_sh.analyse_commands(commands),
                                         note="  [in a command line this script starts]")
        return out

    def installer_unread(self, ctx: FileContext, why: str) -> Finding:
        """INNO-CODE-001: the ``[Code]`` of an Inno Setup installer (or its ``[Run]``
        rows) could not be read to the end. A "could not be read" note (CLAUDE.md,
        rule 15): never hidden, and the launcher asks."""
        note = self.make(
            ctx, INSTALLER_UNREAD, "Installer's own instructions could not be fully read",
            Category.EVASION, Severity.LOW,
            "An Inno Setup installer can carry a small program of its own (its [Code] section) "
            "and a list of programs it starts ([Run]). The scanner reads both to see whether the "
            "installer downloads something and then starts it. Here that reading did not get to "
            "the end, so a download-and-run by the installer itself could have been missed. The "
            "files the installer carries were scanned as usual.",
            "Inno Setup [Code] / [Run]: %s" % why[:200], 0.3)
        note.chainable = False
        return note
    def official_script(self, ctx: FileContext) -> bool:
        """Is this script verifiably an official file of its engine? False here:
        only a handler that can verify its engine's files says yes."""
        return False

    def reading_cut(self, ctx: FileContext, limit: str = remote_py.STEPS) -> Finding:
        """PY-JOIN-001: the reading that looks for the second half of a chain across
        two files (``remote_py.study``) stopped at its limit in this script. A "could
        not be read" note (CLAUDE.md, rule 15): never hidden, and the launcher asks.
        Not made for a verified official engine file - what those do is known.
        The limit is a number of steps, so the same file always gets the same
        answer; the clock (``limit`` is ``remote_py.SECONDS``) is only a brake."""
        note = self.make(
            ctx, JOIN_CUT, "Script not read to its end for chains across files",
            Category.OBFUSCATION, Severity.LOW,
            "The scanner reads every script a second time to see whether it runs something "
            "that another file of the game downloaded. For this script that second reading "
            "reached its limit and stopped early, so a download-and-run chain that begins in "
            "another file and ends in this one could have been missed. Everything else about "
            "the file was checked as usual.",
            "the reading for chains across files stopped at its limit of "
            + ("%.0f seconds [cause: %s]" % (remote_py.SHARED_SECONDS, values.SAFETY_CAP) if limit == remote_py.SECONDS
               else "%d steps [cause: %s]" % (remote_py.SHARED_STEPS, values.STEP_LIMIT)), 0.3)
        note.chainable = False
        return note

    def engine_state(self, ctx: FileContext) -> Tuple[str, str]:
        """``(state, official name)`` of a script as a file of its engine, for a
        chain across files. ``("", "")``: this handler cannot verify engine files."""
        return "", ""

    def joined_trust(self, chain: Finding, states: List[Tuple[str, str]]) -> None:
        """Adjust a chain across files by the ``engine_state`` of each file in it.
        Nothing here (see ``engine_trust``)."""

    def joined_code(self, ctx: FileContext, link, states: List[Tuple[str, str]]) -> Finding:
        """CHAIN-REMOTE-CODE across two files (``dataflow.shared.Link``): the file
        of ``ctx`` runs what another file downloaded and stored under a shared
        name - or starts the file another file wrote a download to. The same
        finding as inside one file, and judged the same way."""
        what, source_line, kind, address = link.fill
        how, sink, line, detail = link.run
        where = {remote.REMOTE: address, remote.HIDDEN: address + "  [decoded]"}.get(
            kind, "not resolved" + (" (%s)" % address if address else ""))
        tie = {shared.FILE: "file %s", shared.PATH: "path in shared name %s", shared.MODULE: "module %s"}.get(
            link.kind, "shared name %s") % link.shown
        flow = "%s (line %d) [%s] -> %s -> %s (line %d) [%s]; address: %s" % (
            what, source_line, link.filler.file, tie, sink, line, link.runner.file, where)
        if how == "dropper":
            flow += "; written to disk as: " + detail
        flow += ACROSS_FILES
        f = self.make(
            ctx, "CHAIN-REMOTE-CODE", "Attack chain: Remote code execution", Category.CHAIN,
            Severity.CRITICAL,
            REMOTE_CODE_REASON + (ACROSS_FILES_REASON if link.kind == shared.NAME else ACROSS_FILES_DROP_REASON),
            flow,
            {remote.REMOTE: 0.85, remote.HIDDEN: 0.85}.get(kind, 0.65), line=line, snippet=flow)
        f.chainable = False
        self.joined_trust(f, states)
        return f

    def _remote_findings(self, ctx: FileContext, hits, decoded_at: int = 0, note: str = "",
                         whole: bool = False) -> List[Finding]:
        """The findings for what a download-and-execute tracer found (``remote.Hit``).
        ``whole``: the JavaScript reading read the script to its end (for a checked
        self-update, ``dataflow/self_update.py``)."""
        out: List[Finding] = []
        for hit in hits:
            where = {remote.REMOTE: hit.address, remote.HIDDEN: hit.address + "  [decoded]"}.get(
                hit.kind, "not resolved" + (" (%s)" % hit.address if hit.address else ""))
            if hit.how == "loader" and not hit.source:
                flow = "%s loads %s" % (hit.sink, where)
            else:
                flow = "%s (line %d) -> %s (line %d); address: %s" % (
                    hit.source, decoded_at or hit.source_line, hit.sink, decoded_at or hit.line, where)
            if hit.how == "dropper":
                flow += "; written to disk as: " + hit.detail
            if decoded_at:
                flow += "  [in code decoded at line %d]" % decoded_at
            flow += note
            if hit.how == "argument":
                # spawn / execFile without a shell, a program that is not downloaded: what was
                # downloaded is an argument, the environment or the folder - data handed to a
                # program, not a program (phageo, 2026-10-14). HIGH, never part of a chain.
                f = self.make(
                    ctx, REMOTE_ARGUMENT, "Attack chain: Downloaded data handed to a program", Category.CHAIN,
                    Severity.HIGH,
                    "This file requests data from an address and hands what comes back to a program it "
                    "starts - as an argument, in the environment or as the folder to work in. The "
                    "program itself is not downloaded and no shell reads the text, so what was "
                    "downloaded is not run as code here; what the started program does with it "
                    "decides. Look at which program is started and what it is given.",
                    flow, 0.5, line=decoded_at or hit.line, snippet=flow)
                f.chainable = False
                out.append(f)
                continue
            if hit.weak and getattr(hit, "text_from", "") == "app" and not whole and hit.sink != "import":
                # a Worker / importScripts of a blob: / data: URL whose text nothing found reaches,
                # in a script not read to its end: as before the rule of 2026-10-15 (forty-sixth
                # message) - an object URL is no address, nothing is said
                continue
            if hit.weak:
                # WebAssembly / script element / import() / Worker with an address that
                # could not be resolved: HIGH, and only because the file names a remote
                # address in its code (so a baseline may silence it, unlike the chain below)
                f = self.make(
                    ctx, "CHAIN-REMOTE-LOAD", "Attack chain: Code loaded from an address that is not shown",
                    Category.CHAIN, Severity.HIGH,
                    "This file loads code from an address that could not be read from it - the "
                    "address only arrives when the script runs - and the same file names a remote "
                    "address in its code. Handing the address in from elsewhere is how a download "
                    "is kept out of sight; it is also how ordinary script loaders are written, so "
                    "look at where the address comes from.",
                    flow + "; remote address in this file: " + hit.seen, 0.5,
                    line=decoded_at or hit.line, snippet=flow)
                if getattr(hit, "local", False):
                    # import() whose address is made only of the app's own values (phageo,
                    # 2026-10-14): what it loads lies in the app's folder or settings
                    f.severity = Severity.MEDIUM
                    f.reason += LOCAL_IMPORT
                elif getattr(hit, "text_from", "") == "app" and whole:
                    # import() of a blob: / data: URL whose text no download reaches, in a
                    # script read to its end (phageo, 2026-10-15, forty-fifth message; a Worker and
                    # importScripts too since the forty-sixth)
                    f.severity = Severity.MEDIUM
                    f.reason += LOCAL_BLOB
                elif getattr(hit, "text_from", "") == "local":
                    # ... whose text was followed back to written-out text and the app's own
                    # values: so also in a script not read to its end (forty-sixth message)
                    f.severity = Severity.MEDIUM
                    f.reason += LOCAL_BLOB_TRACED
                f.chainable = False
                self._renderer_mark(f, hit, decoded_at, note)
                out.append(f)
                continue
            folder = getattr(hit, "folder", "")
            if folder:
                # started through the folder it was written to, not by its own name (phageo,
                # 2026-10-18): HIGH - what was downloaded cannot be shown to be a program
                flow += " - a program is started %s" % ("in that folder (its working folder)"
                                                       if folder == remote_py.WORKING_FOLDER
                                                       else "from that folder (it lies there)")
            f = self.make(
                ctx, "CHAIN-REMOTE-CODE", "Attack chain: Remote code execution", Category.CHAIN,
                Severity.HIGH if folder else Severity.CRITICAL, REMOTE_IN_FOLDER_REASON if folder
                else REMOTE_CODE_REASON,
                flow, {remote.REMOTE: 0.85, remote.HIDDEN: 0.85}.get(hit.kind, 0.65),
                line=decoded_at or hit.line, snippet=flow)
            f.chainable = False
            if folder:
                f.context["in_folder"] = folder
            self.engine_trust(ctx, f)
            mark = self_update.candidate(hit) if whole and not decoded_at and not note else None
            if mark is not None and f.severity is Severity.CRITICAL:
                # (perhaps a checked self-update: judged after the scan, with the app's own
                # settings - Scanner._join_updates; phageo, 2026-10-14, forty-third message; with
                # the script's other starts, for what is folded into it - Scanner._fold_update)
                found = ctx.cache.get("js_starts") or ()
                mark["start_line"] = hit.line
                mark["starts"] = [(s.line, s.kind, s.local) for s in found if s.via == "child_process"]
                mark["check_lines"] = [s.line for s in found if s.via == "check"]
                f.context[self_update.SELF_UPDATE] = mark
            if f.severity is Severity.CRITICAL:
                self._renderer_mark(f, hit, decoded_at, note)
                if hit.how == "loader" and hit.sink == "script.src" and not decoded_at and not note:
                    # a script element this script makes, given a remote address: judged by the
                    # window it runs in once the app was read (Scanner._join_script_elements)
                    f.context[electron_windows.SCRIPT_ELEMENT] = True
            out.append(f)
        return out

    @staticmethod
    def _renderer_mark(f: Finding, hit, decoded_at: int, note: str) -> None:
        """A JavaScript script's own code-loading sink - import(), eval, new Function, a Worker,
        importScripts: marked, so that it can be judged by the windows the script runs in once
        the whole app was read (Scanner._join_renderer; phageo, 2026-10-15, forty-seventh message)."""
        if isinstance(hit, remote.Hit) and hit.how in ("code", "loader") and not decoded_at and not note \
                and hit.sink in electron_windows.RENDERER_SINKS:
            f.context[electron_windows.RENDERER] = hit.sink

    def _resolved(self, ctx: FileContext, hit: "dataflow.Resolved", language: str) -> Finding:
        value = hit.value
        if hit.kind == "exec":
            spec = ("DF-EXEC-001", "Executed code resolved", Category.OBFUSCATION,
                    Severity.HIGH if hit.hidden else Severity.LOW, 0.85 if hit.hidden else 0.3,
                    "The code passed to an exec/eval call was reconstructed by following how the "
                    "script builds it. This is what actually runs.")
        elif hit.kind == "command":
            risky = hit.hidden or hit.dynamic or _RISKY_COMMAND.search(value) is not None
            spec = ("DF-CMD-001", "Command line resolved", Category.PROCESS,
                    Severity.HIGH if risky else Severity.MEDIUM, 0.8 if risky else 0.55,
                    "The command this script starts was reconstructed by tracing its variables "
                    "back to where they are set. This is the program that actually runs.")
        elif hit.kind == "url":
            raw_ip = re.search(r"//\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", value) is not None
            spec = ("DF-URL-001", "Network address resolved", Category.NETWORK,
                    Severity.HIGH if raw_ip else Severity.MEDIUM if hit.hidden else Severity.LOW,
                    0.75 if raw_ip else 0.65 if hit.hidden else 0.35,
                    "The address this script connects to was reconstructed by tracing its "
                    "variables back to where they are set.")
        elif hit.kind == "path":
            spec = ("DF-PATH-001", "File target resolved", Category.FILESYSTEM, Severity.MEDIUM,
                    0.5, "The file this script deletes or writes was reconstructed by tracing "
                         "its variables back to where they are set.")
        else:
            risky = _RISKY_CALL.search(value) is not None or (
                language == "js" and value.rsplit(".", 1)[-1] == "Function")
            spec = ("DF-CALL-001", "Hidden function call resolved", Category.EXECUTION,
                    Severity.HIGH if risky else Severity.MEDIUM, 0.75 if risky else 0.5,
                    "A function or module is looked up by a name assembled at runtime, so the "
                    "real call never appears in the file. This is the name it resolves to.")
        rule_id, title, category, severity, confidence, reason = spec
        notes = ""
        if hit.trace:
            notes += "  [%s]" % "; ".join(hit.trace)
        if hit.hidden:
            notes += "  [decoded]"
        if hit.layer:
            notes += "  [inside decoded code]"
        if hit.partial:
            confidence = max(0.2, confidence - 0.1)
            notes += "  [parts in ‹› are only known at runtime]"
        shown = value if len(value) <= 300 else value[:297] + "..."
        f = self.make(ctx, rule_id, title, category, severity, reason,
                      "%s receives: %s%s" % (hit.sink, shown, notes), confidence,
                      line=hit.line, snippet=shown)
        f.tags = {"command": ("spawn",), "url": ("url",),
                  "path": ("delete",) if hit.delete else ()}.get(hit.kind, ())
        f.context = {"match": value, "line_text": value, "window": value, "code_line": value,
                     "code_window": value, "language": language, "resolved": True}
        return f

    # -- statistical entropy analysis ------------------------------------------
    def entropy_literals(self, ctx: FileContext, text: str, language: str,
                         limit: int = 3) -> List[Finding]:
        """Long string literals whose content is statistically random."""
        out: List[Finding] = []
        for start, end, value in high_entropy_literals(text)[:limit]:
            literal = text[start:end]
            f = self.make(
                ctx, "ENT-STR-001", "High-entropy string literal", Category.OBFUSCATION,
                Severity.MEDIUM, "A long string in the code is statistically close to random "
                "data, which is what encrypted or custom-encoded payloads look like.",
                "%d characters, entropy %.2f bits/char" % (end - start - 2, value), 0.45,
                line=text.count("\n", 0, start) + 1, snippet=literal[:140] + "...")
            f.tags = ("blob",)
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            f.context = {"match": literal, "line_text": literal[:600], "window": literal[:600],
                         "language": language,
                         # what stands in front of and behind the literal on its line
                         "before": text[max(line_start, start - 300):start],
                         "after": text[end:len(text) if line_end < 0 else line_end][:200],
                         "line_from_start": start - line_start <= 300}
            out.append(f)
        return out

    def pe_entropy(self, ctx: FileContext) -> List[Finding]:
        """Packed code, encrypted data sections and encrypted overlays."""
        pe, out = ctx.pe, []
        for s in pe.sections:
            name = s.name or "(unnamed)"
            if s.executable and s.entropy >= HIGH_ENTROPY:
                out.append(self.make(ctx, "PE-PACK-002", "High-entropy code section",
                                     Category.PACKING, Severity.MEDIUM,
                                     "Executable code that looks like random data is "
                                     "usually encrypted or compressed.",
                                     "%s entropy %.2f / 8.00" % (name, s.entropy), 0.5))
            elif (not s.executable and s.raw_size >= 64 * 1024 and s.entropy >= 7.5
                  and s.name.lower() not in (".rsrc", ".reloc")):
                prof = profile(ctx.data[s.raw_ptr:s.raw_ptr + s.raw_size])
                out.append(self.make(ctx, "PE-ENT-002", "Encrypted data section",
                                     Category.PACKING, Severity.MEDIUM,
                                     "A large data section is statistically random, which "
                                     "suggests a payload that is decrypted at runtime.",
                                     "%s: %s" % (name, prof.describe()), 0.4))
        if pe.overlay_size >= 32 * 1024 and not ctx.truncated:
            prof = profile(ctx.data[pe.overlay_offset:pe.overlay_offset + pe.overlay_size])
            if prof.overall >= HIGH_ENTROPY:
                encrypted = prof.kind == "encrypted"
                out.append(self.make(
                    ctx, "PE-ENT-001", "High-entropy data appended to executable",
                    Category.PACKING, Severity.MEDIUM if encrypted else Severity.LOW,
                    "Data stuck onto the end of the program is encrypted or compressed. "
                    "Installers do this legitimately; droppers hide their payload the "
                    "same way.", "%d KB overlay: %s" % (pe.overlay_size // 1024, prof.describe()),
                    0.4 if encrypted else 0.3))
        return out

    def _name_checks(self, ctx: FileContext) -> List[Finding]:
        out: List[Finding] = []
        mismatch = ctx.cache.get("engine_mismatch")
        if mismatch and not ctx.baseline:           # (not if a valid signature vouches for it)
            program = ctx.is_pe
            out.append(self.make(
                ctx, "ENGINE-001", "Named like an engine file, but not built like one",
                Category.EVASION, Severity.MEDIUM if program else Severity.LOW,
                "The file has the name and place of a component of the game engine, which "
                "would exempt it from most checks - but its content does not have that "
                "component's structure. It is therefore judged like any other file.",
                "expected: %s; but %s" % mismatch, 0.5 if program else 0.3))
        if _DOUBLE_EXT.search(ctx.name):
            out.append(self.make(
                ctx, "NAME-001", "Deceptive double extension", Category.EVASION,
                Severity.HIGH, "The file name pretends to be a document or media file "
                "but is actually executable.", ctx.name, 0.85))
        if _ASSET_DIR.search(ctx.key):
            out.append(self.make(
                ctx, "NAME-004", "Program hidden among game assets", Category.EVASION,
                Severity.MEDIUM, "An executable or script sits in a folder that should only "
                "hold images, audio, saves or data.", ctx.relpath, 0.5))
        if ctx.is_pe and ctx.ext not in _PE_EXTENSIONS:
            out.append(self.make(
                ctx, "NAME-002", "Disguised executable", Category.EVASION, Severity.HIGH,
                "The file contains a Windows program but its extension (%s) says "
                "otherwise." % (ctx.ext or "none"), "MZ header in " + ctx.name, 0.8))
        elif ctx.is_pe and ctx.ext in (".scr", ".com", ".cpl"):
            out.append(self.make(
                ctx, "NAME-003", "Unusual executable type", Category.EVASION,
                Severity.MEDIUM, "Games do not normally ship %s programs; the type is "
                "popular for disguising malware." % ctx.ext, ctx.name, 0.5))
        return out
