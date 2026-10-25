"""RPG Maker XP / VX / VX Ace: encrypted archives, script tables and Ruby."""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/handlers/rgss.py")

import hashlib
import io
import re
from typing import Iterable, List

from ..dataflow import remote_rb
from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..pe import extract_strings
from ..rules import RuleEngine
from ..unpack import rgss, spool
from . import containers
from .base import BaseHandler
from .media import EXTENSIONS as MEDIA_EXTS

_ARCHIVES = frozenset({".rgssad", ".rgss2a", ".rgss3a"})
_DATA = frozenset({".rxdata", ".rvdata", ".rvdata2"})
_MEMBER_EXTS = _DATA | frozenset({
    ".rb", ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk"})
_MAX_TOTAL = 8 << 30                 # scripts, data and programs of one archive
_MAX_MEMBERS = 5000
_MAX_MEDIA_MEMBERS = 20_000
_MAX_MEDIA_TOTAL = 16 << 30
_SCRIPTS_FILE = re.compile(r"(^|[/!])scripts\.r[xv]data2?$")
_UNSAFE = re.compile(r"[^\w.\- ]+")
_COMMAND_LIKE = re.compile(r"""(?=.*[a-z]{4})[\w .:/\\\-"'=%$|&>]+""")
# the other functions RB-NATIVE-002 reports: a declaration naming one of them is not
# "ShellExecute only"
_OTHER_NATIVE = re.compile(_IND[0])
_DECLARES = re.compile(rb"Win32API\.new\s*\(")
_DECLARES_SHELL = re.compile(_IND[1])
_LIBRARY = re.compile(r"""Win32API\.new\s*\(\s*(['"])([\w.\- ]{1,60})\1\s*,""")
# everything RB-FS-001 reports
_DELETE_CALLS = re.compile(r"\bFile\.(?:delete|unlink)\b|\bFileUtils\.(?:rm|rm_r|rm_rf|remove_dir|remove_entry\w*)\b"
                           r"|\bDir\.(?:rmdir|delete|unlink)\b")
SHELL_OPENS = (_IND[2])
SHELL_OPENS_MEDIUM = (" It is MEDIUM rather than LOW because what is opened is harder to judge: an "
                      "address without encryption, a bare network address, a link shortener, or a "
                      "folder.")
_VERSIONS = (
    ("XP", re.compile(r"\.rgssad$|\.rxdata$|rgss1\d\d\w?\.dll$")),
    ("VX Ace", re.compile(r"\.rgss3a$|\.rvdata2$|rgss3\d\d\w?\.dll$")),
    ("VX", re.compile(r"\.rgss2a$|\.rvdata$|rgss2\d\d\w?\.dll$")),
)


class RgssHandler(BaseHandler):
    name = "rgss"
    engine = "RPG Maker XP / VX / VX Ace"
    extensions = _ARCHIVES | _DATA | frozenset({".rb", ".rbw"})
    magics = (rgss.MAGIC,)
    markers = (r"\.rgss(?:ad|2a|3a)$", r"(^|[/!])data/scripts\.r[xv]data2?$",
               r"(^|[/!])rgss\d\w*\.dll$")
    # The engine's stock scripts, recognised by script name. Like every name- or
    # path-based baseline this can be imitated, so CRITICAL findings and complete
    # CRITICAL chains inside such a script are still reported.
    baseline = (                                   # matched against the lower-cased path
        (r"!(?:\d+_)?(?:game_\w+|scene_\w+|window_\w+|sprite_\w+|spriteset_\w+|arrow_\w+"
         r"|interpreter|cache|datamanager|scenemanager|battlemanager|vocab|sound|main)"
         r"(?: \d+)?\.rb$",                        # XP splits long classes: "Game_Character 2"
         "RPG Maker default script"),
    )

    def can_handle(self, ctx: FileContext) -> bool:
        return not ctx.is_pe and (ctx.ext in self.extensions or ctx.data.startswith(rgss.MAGIC))

    def structure(self, ctx: FileContext, desc: str) -> str:
        # A stock script is trusted for its name - so it must at least be what
        # the name says: "Game_Interpreter" defines class Game_Interpreter,
        # "Vocab" defines module Vocab, "Main" starts the game.
        if ctx.is_pe:
            return super().structure(ctx, desc)
        leaf = ctx.relpath.rsplit("!", 1)[-1]
        name = re.sub(r"^\d+_|\.rb$", "", leaf)
        name = re.sub(r" \d+$", "", name).strip()
        text = ctx.text()
        if name.lower() == "main":
            if re.search(r"rgss_main|\$scene\b|SceneManager\.run|Graphics\.(?:freeze|transition)", text):
                return ""
            return "it does not start the game"
        if re.search(r"(?mi)^\s*(?:class|module)\s+%s\b" % re.escape(name), text):
            return ""
        return "it does not define %s" % name

    def engine_for(self, key: str) -> str:
        # the three generations are told apart by their file names:
        #   XP      Game.rgssad  Data/*.rxdata   RGSS1xx.dll
        #   VX      Game.rgss2a  Data/*.rvdata   RGSS2xx.dll
        #   VX Ace  Game.rgss3a  Data/*.rvdata2  RGSS3xx.dll
        if not self.detects_engine(key):
            return ""
        for version, rx in _VERSIONS:
            if rx.search(key):
                return "RPG Maker " + version
        return self.engine

    # -- helpers -------------------------------------------------------------------
    @staticmethod
    def _is_archive(ctx: FileContext) -> bool:
        return ctx.data.startswith(rgss.MAGIC)

    def _scripts(self, ctx: FileContext):
        """Parsed script table of a Scripts data file (cached), or an error string."""
        if "scripts" not in ctx.cache:
            try:
                ctx.cache["scripts"] = rgss.load_scripts(ctx.data)
            except rgss.RgssError as exc:
                ctx.cache["scripts"] = str(exc)
        return ctx.cache["scripts"]

    def _entries(self, ctx: FileContext):
        if "entries" not in ctx.cache:
            try:
                with self._stream(ctx) as stream:
                    ctx.cache["entries"] = rgss.list_archive(stream)
            except (rgss.RgssError, OSError) as exc:
                ctx.cache["entries"] = str(exc)
        return ctx.cache["entries"]

    @staticmethod
    def _stream(ctx: FileContext):
        # a large archive is only partly in memory: read it from disk instead
        return open(ctx.path, "rb") if ctx.truncated else io.BytesIO(ctx.data)

    # -- scanning ------------------------------------------------------------------
    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if self._is_archive(ctx):
            entries = self._entries(ctx)
            if isinstance(entries, str):
                return [self.make(ctx, "RGSS-FMT-002", "Unreadable RPG Maker archive",
                                  Category.OBFUSCATION, Severity.LOW,
                                  "The encrypted game archive could not be opened, so the "
                                  "scripts inside it were not inspected.", entries, 0.3)]
            return []                              # members are scanned through expand()
        if ctx.ext in (".rb", ".rbw"):
            text = ctx.text()
            found = rules.scan(text, "ruby", ctx, self.name, comment_style="ruby")
            self._shell_execute(found, remote_rb.shell_execute(text))
            self._own_files(found, text)
            return (found
                    + self.entropy_literals(ctx, text, "ruby")
                    + self.resolve_payloads(ctx, rules, text, "ruby")
                    + self.antimalware(ctx, rules, text, "Ruby script"))
        if _SCRIPTS_FILE.search(ctx.key):
            scripts = self._scripts(ctx)
            if isinstance(scripts, str):
                return [self.make(ctx, "RGSS-FMT-001", "Unreadable RPG Maker script table",
                                  Category.OBFUSCATION, Severity.LOW,
                                  "The game's script file is not in the expected format, so "
                                  "its Ruby code was not inspected.", scripts, 0.3)]
            return []                              # each script is scanned as a .rb child
        # other data files (maps, common events) hold "Script" event commands as strings
        text = "\n".join(extract_strings(ctx.data, 6))
        found = rules.scan(text, "ruby", ctx, self.name, numbered=False)
        # these strings come out of binary data: two stray backticks around
        # bytes are not a command unless what is between them reads like one
        found = [f for f in found if f.rule_id != "RB-PROC-002"
                 or _COMMAND_LIKE.fullmatch(f.context.get("match", "").strip("`"))]
        if b"Win32API" in ctx.data or b"open-uri" in ctx.data or b"Net::HTTP" in ctx.data:
            found += self._event_scripts(ctx, found)
        return found

    def _event_scripts(self, ctx: FileContext, found: List[Finding]) -> List[Finding]:
        """The "Script" commands of a map or common-event file, read as the
        lines they are: what ShellExecute opens there, and whether a download
        is executed. Returns the chains found."""
        script = "\n".join(rgss.marshal_strings(ctx.data))
        opened = remote_rb.shell_execute(script)
        if opened is not None:
            # the lines were picked out of binary data: lower nothing unless every
            # declaration and every call in the raw file was among them
            declared = len(re.findall(_IND[3], ctx.data))
            called = sum(ctx.data.count(("%s.%s(" % (handle, method)).encode("utf-8", "replace"))
                         for handle in opened.handles for method in ("call", "Call"))
            if script.count(_IND[4]) == declared and opened.calls >= called:
                # (matches from binary data are reported once per text: the one
                # "Win32API.new(" note stands for every declaration of the file)
                only = len(_DECLARES.findall(ctx.data)) == len(_DECLARES_SHELL.findall(ctx.data))
                self._shell_execute(found, opened, only)
        chains = self.remote_code(ctx, script, language="ruby")
        for chain in chains:
            chain.line = None                      # a line of the event script, not of the file
        return chains

    @staticmethod
    def _shell_execute(found: List[Finding], opened, unnumbered: bool = False) -> None:
        """A ``ShellExecute`` whose every call was read and only opens a web
        address or a document of the game is not a program start: the
        declaration is reported as what it is (``RB-NATIVE-003``, LOW or
        MEDIUM, with what is opened). One call that could not be resolved, or
        that starts a program, leaves it HIGH.

        The plain "calls a Windows function" note (``RB-NATIVE-001``) on a
        declaration that was lowered this way says nothing the lowered finding
        does not: it is marked as the same declaration. In a script that is
        the note on the same line, when the line declares nothing else; in
        strings out of binary data (no lines, ``unnumbered``) only when every
        declaration of the file is such a ``ShellExecute``."""
        if opened is None or opened.level == remote_rb.HIGH:
            return
        lowered = set()
        for f in found:
            if f.rule_id != "RB-NATIVE-002":
                continue
            matched = f.context.get("match", "") or f.snippet
            if _IND[4] not in matched or _OTHER_NATIVE.search(matched):
                continue
            f.rule_id = "RB-NATIVE-003"
            f.title = _IND[5]
            f.severity = Severity.LOW if opened.level == remote_rb.LOW else Severity.MEDIUM
            f.confidence = 0.3
            f.chainable = False
            f.reason = SHELL_OPENS if opened.level == remote_rb.LOW else SHELL_OPENS + SHELL_OPENS_MEDIUM
            f.evidence = "%s; opens: %s" % (f.evidence, "; ".join(opened.what))[:300]
            lowered.add(f.line)
        for f in found:
            if f.rule_id != "RB-NATIVE-001" or f.line not in lowered \
                    or not f.context.get("match", "").startswith("Win32API"):
                continue
            if unnumbered if f.line is None else \
                    len(_DECLARES.findall(f.context.get("code_line", "").encode())) == 1:
                f.context["same_declaration"] = "RB-NATIVE-003"

    @staticmethod
    def _own_files(found: List[Finding], text: str) -> None:
        """Marks what the script does to files of the game itself, as far as
        every path was read (``remote_rb.own_attributes`` / ``own_deletes``):
        a ``SetFileAttributes`` declaration whose calls only hide or show such
        a folder, and a ``File.delete`` of files in a folder of the game. The
        ContextEngine decides what follows from the mark."""
        attributes = remote_rb.own_attributes(text)
        deletes = remote_rb.own_deletes(text)
        for f in found:
            line = f.context.get("code_line", "")
            if f.context.get("in_comment") or not f.context.get("whole_line"):
                continue
            if f.rule_id == "RB-NATIVE-001" and len(_DECLARES.findall(line.encode())) == 1:
                # the library as written - for the scanner's look at the folder once
                # everything in it was scanned (Scanner._own_libraries)
                library = _LIBRARY.search(line)
                if library:
                    f.context["library"] = library.group(2)
            if f.rule_id == "RB-NATIVE-001" and attributes is not None and f.line in attributes.lines \
                    and len(_DECLARES.findall(line.encode())) == 1 and "SetFileAttributes" in line:
                f.context["own_attributes"] = attributes.what
            elif f.rule_id == "RB-FS-001" and f.line in deletes \
                    and len(_DELETE_CALLS.findall(line)) == 1:
                f.context["own_delete"] = deletes[f.line]

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        if self._is_archive(ctx):
            entries = self._entries(ctx)
            if isinstance(entries, str):
                return
            total = media_total = 0
            try:
                with self._stream(ctx) as stream:
                    def ext_of(entry):
                        return "." + entry.name.rsplit(".", 1)[-1].lower() \
                            if "." in entry.name else ""
                    # scripts and data first; pictures and sound (read by structure,
                    # see handlers/media.py) after them, with a budget of their own
                    wanted = [e for e in entries if ext_of(e) in _MEMBER_EXTS]
                    pictures = [e for e in entries if ext_of(e) in MEDIA_EXTS]
                    ordered = wanted[:_MAX_MEMBERS] + pictures[:_MAX_MEDIA_MEMBERS]
                    # what is left out for a count or a size is said (after_expand) - the
                    # counts and the budget of scripts were silent until 2026-10-12
                    left = len(wanted) - len(wanted[:_MAX_MEMBERS])
                    left_media = len(pictures) - len(pictures[:_MAX_MEDIA_MEMBERS])
                    if left:
                        ctx.cache.setdefault("member_errors", []).append(
                            "more than %d script / data / program members: %d were not inspected"
                            % (_MAX_MEMBERS, left))
                    if left_media:
                        ctx.cache.setdefault("member_errors", []).append(
                            "more than %d picture / sound members: %d were not inspected"
                            % (_MAX_MEDIA_MEMBERS, left_media))
                    for entry in ordered:
                        if ext_of(entry) in MEDIA_EXTS:
                            if media_total + entry.size > _MAX_MEDIA_TOTAL:
                                ctx.cache["media_skipped"] = ctx.cache.get("media_skipped", 0) + 1
                                continue
                            media_total += entry.size
                        elif total + entry.size > _MAX_TOTAL:
                            ctx.cache["members_skipped"] = ctx.cache.get("members_skipped", 0) + 1
                            continue
                        try:
                            data = spool.collect(rgss.entry_pieces(stream, entry))
                        except (rgss.RgssError, spool.SpoolError) as exc:
                            ctx.cache.setdefault("member_errors", []).append(
                                "%s: %s" % (entry.name, exc))
                            continue
                        if ext_of(entry) not in MEDIA_EXTS:
                            total += entry.size
                        yield containers.child(ctx, entry.name, data)
            except OSError:
                return
        elif _SCRIPTS_FILE.search(ctx.key):
            scripts = self._scripts(ctx)
            if isinstance(scripts, str):
                return
            for number, (name, source) in enumerate(scripts, 1):
                if source.strip():
                    label = "%03d_%s.rb" % (number, _UNSAFE.sub("_", name)[:60] or "unnamed")
                    yield self._child(ctx, label, source.encode("utf-8"))

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        notes = list(ctx.cache.pop("member_errors", []))
        skipped = ctx.cache.pop("media_skipped", 0)
        if skipped:
            notes.append("%d picture / sound member(s) beyond the %d GB budget were not inspected"
                         % (skipped, _MAX_MEDIA_TOTAL >> 30))
        skipped = ctx.cache.pop("members_skipped", 0)
        if skipped:
            notes.append("%d script / data / program member(s) beyond the %d GB budget were not inspected"
                         % (skipped, _MAX_TOTAL >> 30))
        return [self.make(ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION,
                          Severity.LOW, NOT_INSPECTED, note[:300], 0.3) for note in notes[:5]]

    @staticmethod
    def _child(ctx: FileContext, name: str, data: bytes) -> FileContext:
        return FileContext(path=ctx.path, relpath="%s!%s" % (ctx.relpath, name), data=data,
                           size=len(data), sha256=hashlib.sha256(data).hexdigest())
