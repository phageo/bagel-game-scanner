"""Ren'Py: .rpy / .py source, compiled .rpyc scripts, the engine's compiled
Python (.pyo / .pyc, compared with the official SDK) and .rpa archives."""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/handlers/renpy.py")

import hashlib
import io
import pickle
import re
import zlib
from typing import Iterable, List

from .. import localdrop
from ..dataflow import remote_py
from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..rules import RuleEngine
from ..unpack import limits, pycalls, pyo, rpyc
from . import renpy_engine
from .base import BaseHandler

_SOURCE = frozenset({".rpy", ".rpym", ".py", ".pyw"})
_COMPILED = frozenset({".rpyc", ".rpymc"})
_BYTECODE = frozenset(renpy_engine.BYTECODE)     # compiled Python: compared, and its calls rebuilt
# added to the evidence of a finding the rules made in rebuilt calls
REBUILT = "  [in a call rebuilt from the compiled file]"
_MEMBER_EXTS = _SOURCE | _COMPILED | frozenset({
    ".js", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".exe", ".dll", ".pyd", ".scr", ".com"})# does the script execute text at all? (then a string literal may be code after all -
# context._text_literal; comments count too, on purpose)
_RUNS_TEXT = re.compile(_IND[0])
# does the script decode anything at all? (then a literal that looks like a sentence may
# be data after all - context._natural_text; wide on purpose, comments count too)
_DECODES_TEXT = re.compile(r"base64|b(?:16|32|64|85)decode|a85decode|\bcodecs\b|\bzlib\b|\bmarshal\b"
                           r"|\bpickle\b|fromhex|unhexlify|\bbinascii\b|\.decode\b|\bbz2\b|\blzma\b"
                           r"|\bgzip\b|rot_?13|maketrans|\.translate\s*\(|\bord\s*\(|\bunichr\s*\(")
# can the script send anything anywhere? (context._process_list; wide on purpose)
_NETWORK_CALL = (_IND[1])
_USES_NETWORK = re.compile(_NETWORK_CALL + r"|://", re.I)       # in code: an address counts too
_NAMES_NETWORK = re.compile(_NETWORK_CALL, re.I)                # in dialogue and names: calls only
_MAX_MEMBER = 32 * 1024 * 1024
_MAX_INDEX = 64 * 1024 * 1024          # compressed archive index
_MAX_MEMBERS = 50_000

# A compiled script without a Ren'Py header (phageo, 2026-10-18): what it holds, by its first
# bytes - text is read as a script; anything else is named and reported (RPY-CONTENT-001)
NOT_COMPILED = "RPY-CONTENT-001"
_TEXT_SAMPLE = 64 * 1024
# (first bytes, what they are, level)
_HEADS = (
    (b"PK\x03\x04", "a zip archive", Severity.MEDIUM), (b"7z\xbc\xaf\x27\x1c", "a 7z archive", Severity.MEDIUM),
    (b"Rar!\x1a\x07", "a RAR archive", Severity.MEDIUM), (b"\x1f\x8b", "gzip data", Severity.MEDIUM),
    (b"BZh", "bzip2 data", Severity.MEDIUM), (b"\xfd7zXZ\x00", "xz data", Severity.MEDIUM),
    (b"MSCF", "a cabinet archive", Severity.MEDIUM), (b"RPA-", "a Ren'Py archive", Severity.MEDIUM),
    (b"\x7fELF", "a Linux program", Severity.HIGH), (b"\xcf\xfa\xed\xfe", "a macOS program", Severity.HIGH),
    (b"\x89PNG", "a PNG picture", Severity.LOW), (b"\xff\xd8\xff", "a JPEG picture", Severity.LOW),
    (b"OggS", "Ogg sound", Severity.LOW), (b"RIFF", "a RIFF file (sound or video)", Severity.LOW),
)
_ENCRYPTED = 7.5        # bits per byte from which data is taken for encrypted or random


def _entropy(data: bytes) -> float:
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


def script_text(data: bytes):
    """The text of a file that is plain text (UTF-8, no NUL, at least 95 % printable in its
    first 64 KB) - None when it is not."""
    sample = bytes(data[:_TEXT_SAMPLE])
    if not sample.strip() or b"\0" in sample:
        return None
    for cut in range(4):                      # (a character cut in two at the end of the sample)
        try:
            sample.decode("utf-8") if not cut else sample[:-cut].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    printable = sum(1 for b in sample if b >= 32 or b in (9, 10, 13))
    if printable < 0.95 * len(sample):
        return None
    return bytes(data).decode("utf-8", "replace")


def content_kind(data: bytes):
    """What a file holds that is no compiled Ren'Py script and no text, by its first bytes:
    ``(what, level)``."""
    from .. import localdrop
    head = bytes(data[:8])
    if head[:2] == b"MZ":
        what = localdrop.proof(bytes(data[:4096])) or "something that starts like a Windows program"
        return what, Severity.HIGH
    for magic, what, level in _HEADS:
        if head.startswith(magic):
            return what, level
    if _entropy(bytes(data[:_TEXT_SAMPLE])) >= _ENCRYPTED:
        return "encrypted or random data", Severity.MEDIUM
    return "binary data of no known kind", Severity.LOW


class _NoGlobalsUnpickler(pickle.Unpickler):
    """Unpickles plain containers only - never imports or calls game code.

    The exceptions are ``bytes`` and ``_codecs.encode``, which is how Python 3
    writes a ``bytes`` value in pickle protocol 2 (Ren'Py 8 archives); they
    can only produce a bytes object.
    """

    def find_class(self, module, name):
        if (module, name) in (("builtins", "bytes"), ("__builtin__", "bytes")):
            return rpyc.no_alloc(bytes)
        if (module, name) == ("_codecs", "encode"):
            import _codecs
            return _codecs.encode
        raise pickle.UnpicklingError("globals are not allowed in an archive index")


class RenPyHandler(BaseHandler):
    name = "renpy"
    engine = "Ren'Py"
    extensions = _SOURCE | _COMPILED | _BYTECODE | frozenset({".rpa", ".rpi"})
    markers = (r"(^|/)renpy/.+\.py[co]?$", r"\.rp(?:y|yc|a)$")
    baseline = (
        (r"(^|[/!])renpy/", "Ren'Py engine runtime"),
        (r"(^|[/!])lib/(?:python|py)[^/]*/", "bundled Python standard library"),
    )

    # archives are indexed and read straight from disk, whatever their size
    streamed = frozenset({".rpa", ".rpi"})

    def baseline_reason(self, ctx: FileContext) -> str:
        # Every Ren'Py game ships the same launcher next to its .exe
        # ("<Game>.py", which starts renpy.bootstrap). Like the other baselines
        # this is recognised by where it is and what it says it is, so CRITICAL
        # findings and complete chains inside it are still reported.
        if (ctx.ext == ".py" and "/" not in ctx.key and "!" not in ctx.key
                and b"renpy.bootstrap" in ctx.data[:65536]):
            return "Ren'Py launcher script"
        return super().baseline_reason(ctx)

    def engine_trust(self, ctx: FileContext, chain: Finding) -> None:
        """A download-and-execute chain in one of Ren'Py's own scripts (its
        updater has one): hidden when the script is verifiably the official
        one, HIGH when this copy of Ren'Py is a version that cannot be
        compared, and left CRITICAL when the version is known and the file is
        not its file - or the file is no engine file at all."""
        state = renpy_engine.status(ctx)
        if state == renpy_engine.VERIFIED:
            chain.suppress("%s: %s" % (renpy_engine.VERIFIED_SCRIPT, ctx.cache.get("engine_script_name", "")))
        elif state == renpy_engine.UNKNOWN:
            chain.severity = Severity.HIGH
            chain.confidence = min(chain.confidence, 0.5)
            chain.reason += renpy_engine.UNVERIFIED_NOTE
            # the launcher asks about this one instead of refusing (launcher._blocks)
            chain.context["engine_unverified"] = True

    store_scripts = frozenset({".rpy", ".rpym"}) | _COMPILED

    def engine_state(self, ctx: FileContext):
        state = renpy_engine.status(ctx)
        return state, ctx.cache.get("engine_script_name", "") if state == renpy_engine.VERIFIED else ""

    def official_script(self, ctx: FileContext) -> bool:
        return renpy_engine.status(ctx) == renpy_engine.VERIFIED

    def joined_trust(self, chain: Finding, states) -> None:
        """A chain across two files, judged like one inside a file: hidden only
        when every file in it is verifiably an official engine script; HIGH
        when no file speaks against it but one of them is an engine file of a
        version that cannot be compared; CRITICAL as soon as one file is a
        changed engine file or no engine file at all."""
        kinds = [state for state, _name in states]
        if all(kind == renpy_engine.VERIFIED for kind in kinds):
            chain.suppress("%s: %s" % (renpy_engine.VERIFIED_SCRIPT,
                                       "; ".join(name for _state, name in states)))
        elif all(kind in (renpy_engine.VERIFIED, renpy_engine.UNKNOWN) for kind in kinds):
            chain.severity = Severity.HIGH
            chain.confidence = min(chain.confidence, 0.5)
            chain.reason += renpy_engine.UNVERIFIED_NOTE
            chain.context["engine_unverified"] = True

    def changed_engine_file(self, ctx: FileContext) -> List[Finding]:
        """A visible LOW note for an engine script that is not the file of the
        version this copy of Ren'Py says it is. Games do change engine files
        harmlessly, so it is a note - but one a folder baseline does not hide
        (``context._SHOWN_IN_NAMED_BASELINES``). The file's ordinary findings
        keep the folder's trust; only a download-and-run chain loses it."""
        if renpy_engine.status(ctx) != renpy_engine.MISMATCH:
            return []
        note = self.make(
            ctx, "ENGINE-003", "Engine file differs from the official version",
            Category.EVASION, Severity.LOW,
            "This file is in the engine's folder, and this copy of Ren'Py is a version whose "
            "official files the scanner knows - but the file is not one of them: it was changed "
            "or added. Games do adjust engine files for harmless reasons, so this is only a "
            "note. The file was scanned, and a download-and-run chain inside it would get no "
            "trust from the folder.",
            "this engine file differs from the official version %s" % ctx.cache.get("engine_version", ""),
            0.3)
        note.chainable = False
        return [note]

    def changed_compiled_file(self, ctx: FileContext, listing=None) -> List[Finding]:
        """Compiled Python of the engine (``.pyo`` / ``.pyc``) that is not the
        compiled file of the version this copy of Ren'Py says it is. Python
        runs the compiled file instead of the source beside it. What lies
        beside it decides: a source the developer changed too explains it (a
        LOW note) - unless the compiled file calls a name that source never
        writes (``listing``: its rebuilt calls; HIGH); an official source,
        one changed in comments only, or none, does not explain it (HIGH). An official file of another listed version is a LOW
        note of its own. None of them is hidden by the folder
        (``context._SHOWN_IN_NAMED_BASELINES``)."""
        state = renpy_engine.compiled_status(ctx)
        version = ctx.cache.get("engine_version", "")
        if state == renpy_engine.LEFTOVER:
            # official, but of another listed version: what an update of the engine leaves
            # behind. Nothing in it was changed, so it is a note.
            note = self.make(
                ctx, "ENGINE-006", "Compiled engine file of another Ren'Py version",
                Category.EVASION, Severity.LOW,
                "This compiled file is an official Ren'Py file - but of another version than "
                "the one this copy of Ren'Py says it is. That is what is left behind when a "
                "game is moved to another version of the engine. Nothing in the file was "
                "changed, so this is only a note.",
                "leftover from Ren'Py %s (this copy says it is %s)"
                % (", ".join(ctx.cache.get("compiled_versions", ())), version), 0.3)
            note.chainable = False
            return [note]
        if state != renpy_engine.MISMATCH:
            return []
        beside = ctx.cache.get("compiled_source")
        extra = (renpy_engine.calls_not_in_source(ctx.path, listing.called)
                 if beside == renpy_engine.SOURCE_CHANGED and listing is not None else None)
        if extra:
            # the changed source explains a changed compiled file - but not one that calls
            # what the source never names
            note = self.make(
                ctx, "ENGINE-007", "Compiled engine file does something its source does not",
                Category.EVASION, Severity.HIGH,
                "This is the compiled form of an engine file whose source the developer "
                "changed. But the compiled file calls something whose name stands nowhere in "
                "that source, so it is not what the source compiles to. Python runs the "
                "compiled file, not the source: the game would do something the source does "
                "not show. The calls of the compiled file were rebuilt from its instructions "
                "and scanned; what the rules found in them is listed for this file.",
                "this compiled engine file calls %s, which the source file beside it never names"
                % ", ".join(extra[:5]) + (" (and %d more)" % (len(extra) - 5) if len(extra) > 5 else ""),
                0.7)
        elif beside in (renpy_engine.SOURCE_CHANGED, renpy_engine.SOURCE_UNREAD):
            unread = beside == renpy_engine.SOURCE_UNREAD
            note = self.make(
                ctx, "ENGINE-005", "Compiled engine file differs, and so does its source",
                Category.EVASION, Severity.LOW,
                "This is the compiled form of an engine file, and it is not the compiled file "
                "of the official version. The source file beside it was changed too, which "
                "explains it: a developer who adjusts an engine file gets a new compiled file. "
                "The source file was scanned, and it was checked that more than comments and "
                "spacing were changed in it (or that the compiled file is still the official "
                "one apart from line numbers). The calls of the compiled file were rebuilt "
                "from its instructions: every name it calls stands in the source, and the "
                "ordinary rules read the calls. It was not checked that the file is exactly "
                "what that source compiles to.",
                "this compiled engine file differs from the official version %s; "
                "so does the source file beside it%s"
                % (version, renpy_engine.UNREAD_SOURCE_NOTE if unread else ""), 0.3)
        else:
            what = {renpy_engine.SOURCE_OFFICIAL: "the source file beside it is the official one",
                    renpy_engine.SOURCE_COMMENTS: "the source file beside it differs from the official "
                                                  "one in comments and spacing only"}
            note = self.make(
                ctx, "ENGINE-004", "Compiled engine file differs while its source is untouched",
                Category.EVASION, Severity.HIGH,
                "This is the compiled form of an engine file, and it is not the compiled file "
                "of the official version - although the source file beside it is the official "
                "one (or differs from it in comments and spacing only), or there is no source "
                "file. Python runs the compiled file, not the "
                "source, so the game would run something other than what the source shows. "
                "The calls of the compiled file were rebuilt from its instructions and "
                "scanned; what the rules found in them is listed for this file.",
                "this compiled engine file differs from the official version %s; %s"
                % (version, what.get(beside, "there is no source file beside it")), 0.7)
        note.chainable = False
        return [note]

    def compiled_python(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        """``.pyo`` / ``.pyc``. An official file of the engine is left at that.
        Any other compiled Python 2.7 - an engine file that differs, a file
        of an unlisted version, a module of the game's own - has its calls
        rebuilt from its instructions (:mod:`gamescan.unpack.pycalls`: a walk
        over the bytes, nothing is run), and the ordinary Python rules read
        them, at the line numbers the file gives; the chains follow from the
        findings as for any script. A file that cannot be walked to its end
        is reported as not read. (Python 3 files that are not official ones
        are not read yet.)"""
        state = renpy_engine.compiled_status(ctx)
        if state in (renpy_engine.VERIFIED, renpy_engine.LEFTOVER) or not pyo.is_python2(ctx.data):
            return self.changed_compiled_file(ctx)
        listing = None if ctx.truncated else pycalls.rebuild(ctx.data)
        out = self.changed_compiled_file(ctx, listing)
        if out:
            # an engine file that differs (ENGINE-004 / ENGINE-005 / ENGINE-007) gets nothing
            # from the folder it sits in: what the rules find in its calls is shown, and forms
            # chains - also when its changed source explains it (phageo, 2026-10-10: nothing
            # proves that the file is what that source compiles to)
            ctx.baseline = ""
        if listing is None:
            note = self.make(ctx, "PYO-FMT-001", "Unreadable compiled Python", Category.OBFUSCATION,
                             Severity.LOW,
                             "The compiled Python file is cut off, larger than the reader's limits or "
                             "not in the form Python 2.7 writes, so its instructions could not be "
                             "inspected.", ctx.name, 0.3)
            note.chainable = False
            return out + [note]
        found = rules.scan(listing.text, "python", ctx, self.name, comment_style="python")
        for f in found:
            f.evidence += REBUILT
        # download-and-run by data flow: read from the calls of each function by itself
        # (in the flat text a name of one function is that name in every function)
        hits, cut = remote_py.read_rebuilt(listing.root, listing.text)
        chains = self._remote_findings(ctx, hits, note=REBUILT)
        if cut:
            # putting the calls together, or reading them, stopped at a limit: said (the
            # putting-together had a silent two-second clock until 2026-10-12)
            chains += self.tracer_cut(ctx, "%s (reading the calls rebuilt from the compiled file)" % cut)
        return out + found + chains

    def _script(self, ctx: FileContext, rules: RuleEngine, text: str, language: str) -> List[Finding]:
        """A script's text (``.rpy`` / ``.py``, or a ``.rpyc`` that is plain text)."""
        ctx.cache["runs_text"] = _RUNS_TEXT.search(text) is not None
        ctx.cache["decodes_text"] = _DECODES_TEXT.search(text) is not None
        ctx.cache["uses_network"] = _USES_NETWORK.search(text) is not None
        return (self.changed_engine_file(ctx)
                + rules.scan(text, "python", ctx, self.name, comment_style="python")
                + self.entropy_literals(ctx, text, "python")
                + self.resolve_payloads(ctx, rules, text, language))

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if ctx.ext in _BYTECODE:
            return self.compiled_python(ctx, rules)
        if ctx.ext in _SOURCE:
            return self._script(ctx, rules, ctx.text(), "renpy" if ctx.ext in (".rpy", ".rpym") else "python")
        if ctx.ext in _COMPILED:
            result = rpyc.decompile(ctx.data, unindent=True)
            if result is None and not ctx.truncated and not bytes(ctx.data[:5]) == b"RENPY" \
                    and rpyc.slab(ctx.data) is None:
                # no Ren'Py header at all (phageo, 2026-10-18): text is read as the script it is;
                # anything else is named by its first bytes and reported
                text = script_text(ctx.data)
                if text is not None:
                    from ..dataflow import pyflow
                    return self._script(ctx, rules, text, "python" if pyflow.parse(text) is not None else "renpy")
                what, level = content_kind(ctx.data)
                note = self.make(
                    ctx, NOT_COMPILED, "Compiled script that holds something else (%s)" % what,
                    Category.EVASION, level,
                    "This file is named like a compiled Ren'Py script, but it has no Ren'Py header and "
                    "is no text: by its first bytes it is %s. Ren'Py cannot load it as a script, so it "
                    "is something else kept under a script's name - a way to hide a program or data "
                    "among the game's files. What it holds was not read." % what,
                    "%s: no Ren'Py header; by its first bytes %s" % (ctx.name, what), 0.5 if level is Severity.HIGH
                    else 0.3)
                note.chainable = False
                return [note]
            if result is None:
                return [self.make(ctx, "RPY-FMT-001", "Unreadable compiled script",
                                  Category.OBFUSCATION, Severity.LOW,
                                  "The compiled script is not in a known Ren'Py format, "
                                  "so its contents could not be inspected.", ctx.name, 0.3)]
            code, strings, _exact = result
            # decompiled Python keeps its original line numbers; the remaining
            # strings (dialogue, names) have no position
            ctx.cache["runs_text"] = _RUNS_TEXT.search(code) is not None
            ctx.cache["decodes_text"] = _DECODES_TEXT.search(code) is not None
            ctx.cache["uses_network"] = (_USES_NETWORK.search(code) is not None
                                         or _NAMES_NETWORK.search(strings) is not None)
            return (self.changed_engine_file(ctx)
                    + rules.scan(code, "python", ctx, self.name, comment_style="python")
                    + self.entropy_literals(ctx, code, "python")
                    + self.resolve_payloads(ctx, rules, code, "python")
                    + rules.scan(strings, "python", ctx, self.name, numbered=False)
                    + self.antimalware(ctx, rules, code + "\n" + strings,
                                       "code recovered from a compiled Ren'Py script"))
        return []                                 # archives are handled by expand()

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        if ctx.ext not in (".rpa", ".rpi"):
            return
        # What of the archive is not read is said (ARC-002, after_expand) - until 2026-10-12
        # every one of these ways out was silent.
        unread = ctx.cache.setdefault("rpa_unread", [])
        large = 0
        try:
            # (an archive that is itself a member of another archive is only in memory - or in
            # a temporary file of its own. Until 2026-10-12 the path was opened whatever it
            # was: for such a member that is the outer file, or nothing, so an .rpa inside a
            # zip or an installer was never read.)
            with (open(ctx.path, "rb") if ctx.on_disk else io.BytesIO(ctx.data)) as fh:
                header = fh.readline(256).split()
                if header[:1] == [b"RPA-3.0"]:
                    offset, key = int(header[1], 16), int(header[2], 16)
                elif header[:1] == [b"RPA-2.0"]:
                    offset, key = int(header[1], 16), 0
                else:
                    unread.append("not an RPA-2.0 / RPA-3.0 archive: its members were not read")
                    return
                fh.seek(offset)
                with limits.quiet():            # (said below, as what it is: the archive's list)
                    raw = rpyc.inflate(fh.read(_MAX_INDEX), _MAX_INDEX * 4)   # bounded both ways
                if raw is None:
                    unread.append("the list of members could not be unpacked (damaged, or larger "
                                  "than %d MB): its members were not read" % (_MAX_INDEX >> 20))
                    return
                index = _NoGlobalsUnpickler(io.BytesIO(raw), encoding="latin-1").load()
                if len(index) > _MAX_MEMBERS:
                    unread.append("more than %d members: the rest was not read" % _MAX_MEMBERS)
                for name, chunks in list(index.items())[:_MAX_MEMBERS]:
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", "replace")
                    off, length = chunks[0][0] ^ key, chunks[0][1] ^ key
                    prefix = chunks[0][2] if len(chunks[0]) > 2 else b""
                    if isinstance(prefix, str):
                        prefix = prefix.encode("latin-1")
                    fh.seek(off)
                    head = (prefix + fh.read(2))[:2]
                    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    if ext not in _MEMBER_EXTS and head != b"MZ":
                        if localdrop.wanted(name, length):
                            # perhaps the file a script decodes (CHAIN-LOCAL-DROP; Scanner._join_local):
                            # kept in memory, bounded - pictures and sound are not
                            fh.seek(off)
                            localdrop.offer("%s!%s" % (ctx.relpath, name), prefix + fh.read(length - len(prefix)))
                        continue
                    if length > _MAX_MEMBER:
                        large += 1
                        if large == 1:
                            unread.append("%s: larger than %d MB, not read" % (name[:120], _MAX_MEMBER >> 20))
                        continue
                    fh.seek(off)
                    data = prefix + fh.read(length - len(prefix))
                    yield FileContext(path=ctx.path, relpath="%s!%s" % (ctx.relpath, name),
                                      data=data, size=len(data),
                                      sha256=hashlib.sha256(data).hexdigest())
        except (OSError, ValueError, IndexError, KeyError, TypeError, AttributeError,
                zlib.error, pickle.UnpicklingError, EOFError) as exc:
            # damaged or unknown archive layout
            unread.append("the archive could not be read to its end (%s)" % type(exc).__name__)
        finally:
            if large > 1:
                unread.append("%d more members larger than %d MB were not read" % (large - 1, _MAX_MEMBER >> 20))

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        out = [self.make(ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION,
                         Severity.LOW, NOT_INSPECTED, note[:300], 0.3)
               for note in ctx.cache.pop("rpa_unread", [])[:5]]
        for note in out:
            note.chainable = False
        return out
