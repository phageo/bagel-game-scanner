"""The :class:`Scanner` wires handlers, rules, context and chains together."""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/scanner.py")

import hashlib
import itertools
import json
import mmap
import os
import posixpath
import re
import sys
import tempfile
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

from . import (directx_official, electron_official, engine_hashes, inno_official, known_findings, library_hashes, localdrop,
               npm_hashes, nsis_official, official, sideload, sigblock, stealer, trust)
from .chains import ChainEngine
from .context import NPM_VERIFIED, SIGNED_BY_TRUSTED, TRUSTED_PUBLISHERS, ContextEngine, HashAllowlist
from .dataflow import electron_ipc, electron_windows, remote, self_update, shared
from .defender import Amsi, DefenderScan
from .handlers import BaseHandler, containers, default_handlers, engine_files, renpy_engine
from .handlers import text
from .handlers.base import FLOW_CUT, FLOW_READ, LOCAL_DROP, LOCAL_DROP_PROVEN, TRACER_CUT
from .chains import WAS_CRITICAL
from .handlers.text import OWN_STARTS, PACKAGE_SIGNER, TextHandler
from .memory import MemoryCenter, fingerprint
from .models import NOT_INSPECTED, TEXT_CUT, UNREAD_CONTENT, Category, FileContext, Finding, ScanReport, Severity
from .pe import parse_pe, program_inside, resource_frame_key, resource_kinds, resources_of
from .quarantine import Quarantine, QuarantineError
from .reputation import ReputationError, VirusTotalClient, findings_for
from .rules import RuleEngine, forget_shared
from .signatures import EICAR, SignatureDatabase, builtin_match
from .unpack import limits, sniff, spool

ProgressFn = Callable[[int, int, str], None]
FindingsFn = Callable[[List[Finding]], None]

_SKIP_DIRS = {".git", ".svn", ".hg"}
_OWN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # the app folder
_SIGNED = SIGNED_BY_TRUSTED
# the tag of a chain lowered because it starts and ends in one file of a published npm package -
# or, since 2026-10-20, of an official library release (library_hashes); CRITICAL ones too since then
LIBRARY_MECHANISM = (" It starts and ends inside this one file of a published npm package: "
                     "a mechanism of the library, so the level is lowered to MEDIUM.")
LIBRARY_RELEASE_MECHANISM = (" It starts and ends inside this one file of an official release of a library: "
                             "a mechanism of the library, so the level is lowered to MEDIUM.")
# ... added when the chain was CRITICAL (rule 13's exception, phageo, 2026-10-20, seventy-third message)
LIBRARY_WAS_CRITICAL = (" It was CRITICAL: the library can run code it is given, but nothing in this file "
                        "hands it an address - an app script that does is reported on its own.")
# the tag of a HIGH finding on a custom action of a signed MSI that starts a file of the package
PACKAGE_START = (" This command line of the installer's custom actions starts a file of the same package, "
                 "which Windows accepts as signed by a trusted publisher, and fetches or decodes nothing: "
                 "the installer's own step, so the level is lowered to MEDIUM.")
# what is folded into a checked self-update (Scanner._fold_update; phageo, 2026-10-15)
UPDATE_FOLDED = "Part of the app's checked self-update (CHAIN-SELF-UPDATE), shown there"
UPDATE_IMPORT = (" Its one start with a part that is not written out is the app's checked self-update "
                 "(CHAIN-SELF-UPDATE); every other program this script starts is fixed or made of the "
                 "app's own values, so the level is lowered.")
_own_hashes: Optional[frozenset] = None


_FLOWS = frozenset({"CHAIN-REMOTE-CODE", "CHAIN-REMOTE-LOAD"})   # a download that reaches a run
# the "could not be read" notes a file of an official distribution does not get (_scan_one); a scan
# error is no statement about the content, the coverage note is about the folder
_UNREAD_NOTES = frozenset({"ARC-001", "ARC-002", "UNITY-FMT-001", "RPY-FMT-001", "RGSS-FMT-001", "RGSS-FMT-002",
                           "DN-META-001", "IL2CPP-META-001", "PYO-FMT-001", "PY-JOIN-001", "INNO-CODE-001",
                           "DN-IL-001", "SCRIPT-LIMIT-001", "ENC-SCRIPT-001", "JSC-FMT-001", "EXEC-FMT-001",
                           "RPY-CONTENT-001"})
# ENGINE-008 (phageo, 2026-10-18): a program in the engine's place of a listed Ren'Py version that
# is no official file
ENGINE_PROGRAM = "ENGINE-008"
ENGINE_PROGRAM_TITLE = "Program in the engine's folder is not the official file"
ENGINE_PROGRAM_REASON = (
    "This program lies in the folder of the Ren'Py engine, and this copy of Ren'Py says it is a version "
    "whose official files the scanner knows - but this program is none of them: it was changed or added. "
    "The engine and the game's start program load the programs and libraries there as their own parts. "
    "Games rarely change the engine's programs, so this is a visible note that the folder does not hide.")
_MAX_ENGINE_PROGRAMS = 2000
_MAX_ENGINES = 64
# ENGINE-009 (phageo, 2026-10-20, seventy-third message): a program or library (not a .node add-on) in
# the folder of an app whose runtime - Electron's program, NW.js's launcher - is verified, that is in
# no official table and carries no valid signature of a trusted publisher
APP_PROGRAM = "ENGINE-009"
APP_PROGRAM_TITLE = "Program in the app's folder is no official file"
APP_PROGRAM_REASON = (
    "This program lies in the folder of an app whose runtime the scanner verified as an official build - "
    "but this program is in no table of official files and carries no valid signature of a trusted "
    "publisher. The scanner reads a program's import table and strings, not what it does, so what it is "
    "cannot be said; the app can start or load it. This is a visible note that the verified runtime "
    "beside it does not hide.")
# CHAIN-LOCAL-DROP together with persistence or evasion in the same game (phageo, 2026-10-18, fix A):
# CRITICAL, the chain itself stays HIGH. Across the files of one game - in every real sample measured
# the signs stand in other files than the chain (0 of 22 in the same file). One game (same evening):
# the same archive or installer the scan found on disk, or else the same scanned folder.
LOCAL_COMBINED = "CHAIN-LOCAL-DROP-PLUS"
LOCAL_COMBINED_WITH = ("PERSIST-001", "EVADE-001")
LOCAL_COMBINED_TITLE = "Attack chain: File of the game decoded and started, and the game hides or installs itself"
LOCAL_COMBINED_REASON = (
    "A script of this game decodes one of the game's own files, writes it and starts it (CHAIN-LOCAL-DROP), "
    "and the same game also holds high-risk signs that something hides itself from the user or the "
    "security software, or makes itself start with Windows (%s). Each sign alone is SUSPICIOUS; a hidden "
    "program carried in the game's files together with such signs is how malware hidden in games works. "
    "The signs may stand in other files of the game than the chain: the scanner does not prove that one "
    "file uses the other.")
# what the scan opens as a package of its own: archives by their ending, and any file in which
# containers.detect found an archive or an installer
_PACKAGE_EXTS = containers.ZIP_EXTS | containers.ARCHIVE_EXTS | frozenset({".msi"})
_MAX_VERSION_TEXT = 1 << 20


def _flowless(ctx: FileContext, findings: List[Finding]) -> bool:
    """Did the data-flow reading of this JavaScript file read it to its end (no limit, no
    failure) and find no download that reaches code or a program start? Then a chain of
    nearness that claims "download and run" is disproven there (chains.NO_FLOW; phageo,
    2026-10-14). A file the reading did not look at, or did not finish, is not."""
    if not ctx.cache.get(FLOW_READ) or ctx.cache.get(FLOW_CUT):
        return False
    return not any(f.rule_id in _FLOWS and f.file == ctx.relpath for f in findings)


INJECTION = "INJ-001"
# the functions that write into another process; the other injection functions start, queue,
# unmap or set a thread's state - which debuggers, runtimes and audio libraries do to their own
_WRITERS = frozenset({_IND[0], "ntwritevirtualmemory", "zwwritevirtualmemory"})
NO_WRITER = (_IND[1])


def _injection_without_writer(ctx: FileContext, findings: List[Finding]) -> None:
    """INJ-001 in a program without any function that writes into another process is MEDIUM
    (phageo, 2026-10-17, fifty-ninth message) - for every program. The import table is asked,
    and every name the rule found in the program's texts (a function found by name at run time
    counts: it is named there)."""
    found = [f for f in findings if f.rule_id == INJECTION]
    if not found or {name.lower() for name in ctx.pe.import_names} & _WRITERS:
        return
    named = {f.context.get("match", "").lower() for f in found}
    if named & _WRITERS or {name[:-1] for name in named if name[-1:] in "aw"} & _WRITERS:
        return
    for f in found:
        if f.severity is Severity.HIGH:
            f.severity = Severity.MEDIUM
            f.reason += NO_WRITER


# (Policy 7 of 2026-10-23, "a text alone in a program is MEDIUM", was removed on 2026-10-24 by
# phageo's word: it broke the malicious bar - 45 of 51 at least SUSPICIOUS with it, bar 90 %.
# A HIGH text match among a program's strings stays HIGH. docs/CHANGELOG.md, 2026-10-24.)


def _protected(path: str) -> bool:
    """Locations auto-quarantine must never touch: moving a file out of
    Windows, an installed program, Python or the scanner itself on the
    strength of a heuristic could break the PC. (Manual quarantine still
    works there.)"""
    here = os.path.normcase(os.path.abspath(path))
    roots = [os.environ.get(v) for v in ("WINDIR", "ProgramFiles", "ProgramFiles(x86)",
                                         "ProgramW6432")] + [sys.base_prefix, _OWN_DIR]
    return any(root and here.startswith(os.path.normcase(os.path.abspath(root)) + os.sep)
               for root in roots)


def _own_files() -> frozenset:
    """SHA-256 of this installation's own source files.

    Self-exclusion is by content, not by location or name: a byte-identical
    copy of the scanner is skipped wherever it sits, and nothing else can
    hide by imitating its folder layout.
    """
    global _own_hashes
    if _own_hashes is None:
        found = set()
        for base, dirs, names in os.walk(_OWN_DIR):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in names:
                if name.lower().endswith((".py", ".pyw", ".yar", ".yara")):
                    try:
                        with open(os.path.join(base, name), "rb") as fh:
                            found.add(hashlib.sha256(fh.read()).hexdigest())
                    except OSError:
                        pass
        _own_hashes = frozenset(found)
    return _own_hashes
_MAX_DEPTH = 4                      # nesting: installer > game archive > script table > script
_MAX_SIGNED_MEMBER = 256 * 1024 * 1024   # an in-memory member whose signature is verified
IL2CPP_ENGINE = "Unity (IL2CPP)"
COVERAGE = "SCAN-COVERAGE-001"
LOW_COVERAGE = 0.10                 # under this share of read bytes a folder is never CLEAN
MIN_UNREAD = 1024 * 1024            # ... when at least this much was not read
IL2CPP_NOTE = ("INFO: Unity IL2CPP game - game code compiled to machine code; no instruction-level chain "
               "check (download-and-run is not followed through the game's own code; names, texts and "
               "imported functions were scanned as usual)")
ADDON_DECRYPT = "ADDON-DECRYPT-001"
PUBLISHERS_NOTE = ("Trusted publishers: this scan used a list changed in Settings, not the built-in one - "
                   "findings in files validly signed by a listed publisher are hidden.%s%s")


def publishers_changed(publishers) -> str:
    """The report's note when the trusted-publisher list in use is not the built-in one ("" when
    it is; phageo, 2026-10-19). Compared as the context engine compares names (lower case, no
    surrounding spaces), in any order."""
    built_in = {p.strip().lower() for p in TRUSTED_PUBLISHERS}
    used = {p.strip().lower() for p in publishers if p and p.strip()}
    if used == built_in:
        return ""
    added, removed = sorted(used - built_in), sorted(built_in - used)
    return PUBLISHERS_NOTE % (" Added: %s." % ", ".join(added) if added else "",
                              " Left out: %s." % ", ".join(removed) if removed else "")


def _package_root(file: str) -> str:
    """What an add-on and the scripts of its app have in common in their paths: the part in
    front of the app's own files, or - outside an Electron app - the top folder / container."""
    root = electron_windows.app_root(file)
    if root is not None:
        return root
    low = file.replace("\\", "/").lower()
    return low.split("!", 1)[0] + "!" if "!" in low else low.split("/", 1)[0] + "/" if "/" in low else ""


_ELECTRON_VERSION = re.compile(r"Electron (\d+\.\d+\.\d+)")
PAGE_SHUT_IN = (
    "This page of an Electron app loads a script from a remote address. The window the page is "
    "shown in gives the page's scripts no access to the PC - no Node.js, an isolated world, and "
    "no function handed over that starts programs, runs text or writes files - so the remote "
    "script runs as it would in a web browser. Whoever controls that address still decides what "
    "the page shows and can read what is typed into it.")
PAGE_NOT_SHUT_IN = (
    "This page of an Electron app loads a script from a remote address, and it could not be "
    "shown that the page's scripts are shut in: the window's settings are not written out, the "
    "app's Electron version is not known, the window was not found - or its preload script "
    "hands the page a function that reaches something that starts programs, runs text or writes "
    "files. Whoever controls that address may reach the PC through it.")
PAGE_NODE_ON = (" The app itself gives the window's pages Node.js (nodeIntegration on), so this is real "
                "behaviour of the app, not something hidden in it: the level is HIGH.")
SCRIPT_ELEMENT_HIGH = (" The remote script is loaded by a script element that a script of the app's pages "
                       "makes, so it runs in one of the app's windows; by the app's own design such a "
                       "script is real behaviour of the app, not something hidden in it: the level is HIGH.")
RENDERER_SHUT_IN = (
    "This script of an Electron app's pages loads code that the scanner could not show to be the "
    "app's own - through import(), eval, new Function or a worker. The script runs only in pages "
    "whose windows give it no access to the PC - no Node.js, an isolated world, and no function "
    "handed over that starts programs, runs text or writes files - so what it loads runs as it "
    "would in a web browser and cannot start programs or read files. Whoever supplies that code "
    "still decides what the page does and can read what is typed into it.")


def _main_scripts(texts: Optional[List[str]]) -> Optional[set]:
    """The file names (lower case) of the main scripts the ``package.json`` files of an
    Electron app name (None: none was read - then where a script runs is not known)."""
    out = set()
    for text in texts or ():
        try:
            data = json.loads(text)
        except ValueError:
            return None                 # (a package.json that cannot be read: not known)
        if isinstance(data, dict):
            main = data.get("main") if isinstance(data.get("main"), str) else "index.js"
            name = main.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
            out.add(name if "." in name else name + ".js")
    return out or None


_MAX_MANAGED = 4_000                # .NET libraries of one scan whose shared names are kept for the join
_MAX_IMPORT_NAMES = 20_000          # module names whose importers are kept for the join across files
_MAX_IMPORTERS = shared._MAX_PER_FILE + 1   # ... and scripts per name (one more than the join links: it says so)
_LARGE = 64 * 1024 * 1024          # files above this report progress while they are worked on
# Bytes unpacked from one file on disk, all levels together. Members are scanned one
# at a time and large ones from a temporary file, so this bounds time, not memory.
_MAX_EXPANDED = 64 << 30


class Scanner:
    """Scan pipeline:

    1. every file goes to the first handler that claims it (unpack + rules),
    2. YARA signatures run on the raw bytes,
    3. the ContextEngine suppresses / adjusts, the ChainEngine correlates,
    4. optional: executables are verified against VirusTotal by SHA-256,
    5. optional: files with HIGH / CRITICAL findings are moved to quarantine.
    """

    max_bytes = 64 * 1024 * 1024    # per-file content cap (the hash covers it all)

    def __init__(self, handlers: Optional[List[BaseHandler]] = None,
                 rules: Optional[RuleEngine] = None,
                 context: Optional[ContextEngine] = None,
                 chains: Optional[ChainEngine] = None,
                 strict: bool = False,
                 allowlist: Optional[HashAllowlist] = None,
                 reputation: Optional[VirusTotalClient] = None,
                 max_lookups: int = 20,
                 quarantine: Optional[Quarantine] = None,
                 auto_quarantine: bool = False,
                 memory: Optional[MemoryCenter] = None,
                 signatures: Optional[SignatureDatabase] = None,
                 amsi: Union[bool, Amsi] = False,
                 defender: Optional[DefenderScan] = None) -> None:
        self.signatures = signatures
        self._match_everything = False
        self._amsi = amsi                 # True = open AMSI on first use; or a ready Amsi
        self.defender = defender          # optional MpCmdRun pass over the scan target
        self.handlers = handlers if handlers is not None else default_handlers()
        self._text = TextHandler()          # asked when no other handler takes a file
        self._engine_verified = False       # a file of this scan is an official engine file by hash
        self.rules = rules or RuleEngine()
        self.context = context or ContextEngine(allowlist=allowlist, strict=strict,
                                                memory=None if memory is False else memory)
        # memory=False: use the context's learning but do not record this scanner's
        # scans in the history (real-time protection scans one file at a time)
        self.memory = self.context.memory if memory is None else memory
        self.chains = chains or ChainEngine()
        self.reputation, self.max_lookups = reputation, max_lookups
        self.quarantine, self.auto_quarantine = quarantine, auto_quarantine
        self._extensions = frozenset().union(*(h.extensions for h in self.handlers))
        self._magics = tuple(m for h in self.handlers for m in h.magics) + (b"MZ", EICAR[:8])
        self._executables: List[Dict[str, object]] = []
        self._engines: Dict[str, bool] = {}
        self._expanded = 0
        self._cancel: Optional[threading.Event] = None
        self._shared: List[shared.Entry] = []      # what the scripts of this scan share
        self._shared_cut = False
        self._importers: Dict[str, list] = {}      # module name -> the scripts that import it
        # Electron apps: what each script says about windows and messages, and the version of
        # each verified runtime program - joined after the scan (_join_windows)
        self._app_scripts: Dict[str, object] = {}
        self._app_versions: Dict[str, str] = {}
        # ... and the small settings files of each app (a checked self-update: _join_updates)
        self._app_files: Dict[str, Dict[str, List[str]]] = {}
        # ... and, per app, how many files of its crypto packages are verified npm files and how
        # many are not (a check made with such a library counts only when it is verified)
        self._app_libraries: Dict[str, Dict[str, List[int]]] = {}
        # ... and the app's own scripts each page of an app loads (_join_renderer)
        self._app_pages: Dict[str, Tuple[str, ...]] = {}
        self._app_kept = 0
        # ... and the texts of the app's own scripts (and of scripts with message handlers): what
        # the main process does with the pages' messages (_ipc; phageo, 2026-10-15, forty-eighth message)
        self._app_texts: Dict[str, str] = {}
        self._app_cut: Dict[str, str] = {}          # app -> why not all of them were kept
        self._app_ipc: Dict[str, object] = {}
        self._app_kept_text = 0
        # ... and the app's scripts that name a browser's, Discord's or a wallet's store
        # (CHAIN-STEALER across the app; phageo, 2026-10-15, forty-ninth message)
        self._app_stores: Dict[str, Dict[str, List[str]]] = {}
        self._managed: list = []                   # what the .NET libraries of this scan share
        self._managed_cut = False
        self._forget_local()                        # (CHAIN-LOCAL-DROP proofs, SIDELOAD-001: _join_local)
        # tools/build_known_findings.py only: {sha256: [kept reading, ...]} of the table files read
        self.known_record: Optional[Dict[str, list]] = None

    # -- public API ------------------------------------------------------------
    def scan(self, target: Union[str, Sequence[str]], progress: Optional[ProgressFn] = None,
             on_findings: Optional[FindingsFn] = None,
             cancel: Optional[threading.Event] = None, label: Optional[str] = None,
             extra: Optional[List[Finding]] = None) -> ScanReport:
        """Scan a folder, a file, or a list of them.

        ``label`` names a multi-target scan in the report ("Quick scan");
        ``extra`` are findings produced outside the file pipeline (autostart
        heuristics) that belong in the same report.
        """
        targets = [os.path.abspath(target)] if isinstance(target, str) else \
            [os.path.abspath(t) for t in target]
        single = len(targets) == 1
        report = ScanReport(target=label or (targets[0] if single else "; ".join(targets)),
                            strict=self.context.strict)
        files: List[str] = []
        for item in targets:
            if os.path.isfile(item):
                files.append(item)
            elif os.path.isdir(item):
                files.extend(self._walk(item, cancel))
            elif single:
                raise FileNotFoundError(item)
        files = list(dict.fromkeys(files))
        root = targets[0] if single and os.path.isdir(targets[0]) else \
            os.path.dirname(targets[0]) if single else None
        report.files_total = len(files)
        self._executables = []
        self._shared, self._shared_cut, self._importers = [], False, {}
        self._managed, self._managed_cut = [], False
        self._forget_local()
        self._targets = [] if root else targets
        localdrop.begin()
        for path in files:                      # (a file a script decodes may be one no reader takes)
            self._local_disk.setdefault(os.path.basename(path).lower(), []).append(path)
        programs: Dict[str, str] = {}
        self._engine_verified = False
        unread: List[Tuple[int, str]] = []          # (size, file) of what no reader opened
        self._engines = engines = {}
        self._cancel = cancel
        self._match_everything = bool(len(self.rules.yara)) or (
            self.signatures is not None and self.signatures.count() > 0)
        self.context.refresh_memory()         # pick up feedback given since the last scan
        if extra:
            for f in extra:
                self.context.remember(f)
            report.findings.extend(extra)
            if on_findings:
                on_findings(list(extra))
        amsi = self._open_amsi(report)
        amsi_calls = amsi.calls if amsi is not None else 0
        if len(self.rules.yara):
            report.notes.append("YARA: %d signature(s) loaded" % len(self.rules.yara))
        for name, why in self.rules.yara.skipped:
            report.notes.append("YARA rule skipped - %s: %s" % (name, why))
        changed = publishers_changed(self.context.trusted_publishers)
        if changed:
            report.notes.append(changed)
        for done, path in enumerate(files, 1):
            if cancel is not None and cancel.is_set():
                report.cancelled = True
                break
            # several roots (quick / system scan): show full paths
            rel = (os.path.relpath(path, root) if root else path).replace(os.sep, "/")
            self._note_engine(rel.lower())
            ctx = found = None
            tick = self._ticker(progress, done - 1, report.files_total, rel)
            try:
                ctx = self._load(path, rel, tick)
                found = self._scan_ctx(ctx) if ctx is not None else None
            except Exception as exc:              # one bad file must not end the scan
                report.errors.append({"file": rel, "error": "%s: %s" % (type(exc).__name__, exc)})
                if ctx is not None:
                    # The file was read but analysing it failed. Say so in the
                    # results: a file built to break the scanner must not come
                    # out looking clean.
                    found = [Finding(
                        rule_id="SCAN-ERR-001", title="File could not be analysed",
                        category=Category.EVASION, severity=Severity.LOW, file=rel, line=None,
                        snippet=str(exc)[:200], evidence=type(exc).__name__, confidence=0.3,
                        reason="The scanner hit an error while analysing this file, so its "
                               "contents were not inspected. Malformed files are sometimes "
                               "crafted to break scanners.", handler="scanner",
                        sha256=ctx.sha256, path=ctx.path, chainable=False)]
            if found is not None and ctx.pe is not None and not ctx.truncated:
                programs[rel.lower()] = rel       # a program that was read to its end
            if ctx is not None and (ctx.ext in _PACKAGE_EXTS or ctx.cache.get("containers")):
                self._packages.add(rel)
            try:
                report.bytes_total += ctx.size if ctx is not None else os.path.getsize(path)
            except OSError:
                pass
            if found is None:
                report.files_skipped += 1
                try:
                    unread.append((ctx.size if ctx is not None else os.path.getsize(path), rel))
                except OSError:
                    pass
            else:
                report.files_scanned += 1
                report.bytes_scanned += ctx.size
                if (ctx.truncated and not ctx.cache.get("streamed")
                        and not any(ctx.ext in h.streamed for h in self.handlers)):
                    report.notes.append("%s: only the first %d MB were inspected"
                                        % (rel, self.max_bytes >> 20))
                    # ... and as a finding, the way a member of an archive that was read in
                    # part has always had one: until 2026-10-12 a file on disk had only the
                    # line above, which neither the verdict nor the launcher looks at. (Not
                    # for a file that is, by its SHA-256 - which covers all of it - an official
                    # file of an engine or a known library: what is in it is known.)
                    # (nor for the program of an Electron game that is the official one apart
                    # from its resources: that comparison reads the file to its end)
                    known = ctx.baseline.startswith((engine_hashes.VERIFIED, library_hashes.VERIFIED,
                                                     electron_official.PROGRAM_VERIFIED))
                    found = list(found) + [] if known else list(found) + [Finding(
                        rule_id="ARC-002", title="Archive could not be fully inspected",
                        category=Category.EVASION, severity=Severity.LOW, file=rel, line=None,
                        snippet="", confidence=0.3, handler="scanner",
                        evidence="only the first %d MB of this %d MB file were inspected"
                                 % (self.max_bytes >> 20, ctx.size >> 20),
                        reason=NOT_INSPECTED, sha256=ctx.sha256, path=ctx.path, chainable=False)]
                if found:
                    report.findings.extend(found)
                    if on_findings:
                        on_findings(found)
            if progress:
                progress(done, report.files_total, rel)
        report.engines = sorted(engines)
        if single and root == targets[0] and not report.cancelled:
            self._own_libraries(report, programs)
        if single and not report.cancelled:
            self._join_shared(report, on_findings)
            self._join_managed(report, on_findings)
        if not report.cancelled:
            self._join_windows(report.findings)
            self._join_updates(report.findings)
            self._join_addons(report.findings)
            found = self._join_local(report.findings)
            if found and on_findings:
                on_findings(found)
        self._forget_local()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        self._shared, self._shared_cut, self._importers = [], False, {}
        self._managed = []
        if single and root == targets[0] and not report.cancelled:
            self._coverage(report, unread, on_findings)
        if IL2CPP_ENGINE in engines:
            # a documented limit, not a finding (phageo, 2026-10-11): information only
            report.notes.append(IL2CPP_NOTE)
        if amsi is not None:
            if amsi.available:
                report.notes.append("Windows antimalware engine (AMSI): %d extracted item(s) "
                                    "checked" % (amsi.calls - amsi_calls))
            else:                                 # it stopped answering during the scan
                report.notes.append("INFO: the Windows antimalware engine (AMSI) became "
                                    "unavailable during the scan (%s)" % amsi.problem)
                self.rules.amsi = None
        if self.defender is not None and not report.cancelled:
            self._defender_pass(report, targets if label is None else None, root,
                                progress, on_findings, cancel)
        if self.reputation is not None and not report.cancelled:
            self._verify_executables(report, progress, on_findings, cancel)
        if self.auto_quarantine and self.quarantine is not None and not report.cancelled:
            self._isolate_threats(report)
        report.finished_at = time.time()
        if self.memory and not report.cancelled:
            self._remember_scan(report)
        forget_shared()                       # (the texts read once for all readings: not needed any more)
        return report

    def _coverage(self, report: ScanReport, unread: List[Tuple[int, str]],
                  on_findings: Optional[FindingsFn] = None) -> None:
        """SCAN-COVERAGE-001: most of the scanned folder lies in files that no reader
        opened - the archives of an engine the scanner does not know. Such a folder is
        never CLEAN, and the launcher asks once (phageo, 2026-10-12). A "could not be
        read" note (CLAUDE.md, rule 15): LOW, never hidden. Only for the scan of one
        folder, when less than ``LOW_COVERAGE`` of its bytes was read and at least
        ``MIN_UNREAD`` bytes were not."""
        missed = report.bytes_total - report.bytes_scanned
        if report.coverage >= LOW_COVERAGE or missed < MIN_UNREAD:
            return
        if report.engines and self._engine_verified:
            # An engine was recognised and at least one of its files is, by its SHA-256, an
            # official one: what its data files are is known, and they are not read on
            # purpose (Unity's .resS ...). The note is for a folder whose engine the scanner
            # does not know - or only seems to know: a name alone proves nothing (phageo,
            # 2026-10-12).
            return
        largest = sorted(unread, key=lambda item: (-item[0], item[1]))[:5]
        shown = ", ".join("%s (%.1f MB)" % (name[-80:], size / 1048576.0) for size, name in largest)
        report.notes.append("Coverage: %.1f %% - %.1f of %.1f MB lie in files the scanner reads; largest unread: %s"
                            % (100.0 * report.coverage, report.bytes_scanned / 1048576.0,
                               report.bytes_total / 1048576.0, shown))
        note = Finding(
            rule_id=COVERAGE, title="Most of this folder was not read", category=Category.EVASION,
            severity=Severity.LOW, file=largest[0][1] if largest else ".", line=None, snippet="",
            confidence=0.3, handler="scanner",
            evidence="only %.1f %% of the folder (%.1f of %.1f MB) lies in files the scanner reads; "
                     "%d file(s) were not opened, the largest: %s"
                     % (100.0 * report.coverage, report.bytes_scanned / 1048576.0,
                        report.bytes_total / 1048576.0, len(unread), shown),
            reason="Most of the data in this folder lies in files of kinds the scanner does not open - "
                   "such as the archives of a game engine it does not know. What is in the unread "
                   "files is not known; a folder whose content was not read is never reported as clean.",
            chainable=False)
        report.findings.append(note)
        if on_findings:
            on_findings([note])

    def _own_libraries(self, report: ScanReport, programs: Dict[str, str]) -> None:
        """A game script that calls into a library lying in the game's folder
        (``Win32API.new("Name.dll", ...)``): the declaration is judged here,
        after every file of the folder was scanned, so that it does not matter
        whether the script or the library came first. ``programs`` are the
        programs of the folder that were read to their end; what was found in
        the library decides (``ContextEngine.own_library``)."""
        inside: Optional[Dict[str, List[Finding]]] = None
        for f in report.findings:
            name = self.context.library_file(f)
            if not name:
                continue
            # where Windows looks first: beside the game's program - the folder of the
            # archive the script is in, or the one above a loose Data/Scripts file
            folder = posixpath.dirname(f.file.split("!", 1)[0])
            folders = [folder]
            if posixpath.basename(folder).lower() == "data":
                folders.append(posixpath.dirname(folder))
            keys = [("%s/%s" % (one, name) if one else name).lower() for one in folders]
            rel = next((programs[key] for key in keys if key in programs), None)
            if rel is None:
                continue
            if inside is None:
                inside = {}
                for other in report.findings:
                    inside.setdefault(other.file.split("!", 1)[0].lower(), []).append(other)
            self.context.own_library(f, rel, inside.get(rel.lower(), ()))

    def _join_shared(self, report: ScanReport, on_findings: Optional[FindingsFn] = None) -> None:
        """Download-and-run across two files of the scanned folder: one script
        stores a download under a name the scripts share (Ren'Py's store, a
        module that is imported), another runs what that name holds. Each
        script left what it shares while it was scanned (``_scan_ctx``); here,
        after every file was seen, they are joined (``dataflow/shared.py``).
        The finding is made by the handler of the file that runs, and judged
        like the same chain inside one file."""
        if not self._shared:
            return
        links, complete = shared.join(self._shared, self._importers)
        found: List[Finding] = []
        for link in links:
            tag = link.runner.tag
            handler = tag["handler"]
            # (the file's content is not needed any more - and is not kept)
            ctx = FileContext(path=tag["path"], relpath=link.runner.file, data=b"", size=0,
                              sha256=tag["sha256"], baseline=tag["baseline"])
            f = handler.joined_code(ctx, link, [link.filler.tag["state"], tag["state"]])
            f.handler, f.sha256, f.path = handler.name, ctx.sha256, ctx.path
            self.context.evaluate_joined(f, ctx)
            found.append(f)
        if found:
            report.findings.extend(found)
            if on_findings:
                on_findings(found)
        if not complete or self._shared_cut:
            report.notes.append("Download-and-run across files: a limit was reached (%d scripts, %d "
                                "chains, %.0f second) - not every pair of scripts was compared"
                                % (shared.MAX_FILES, shared.MAX_LINKS, shared.MAX_SECONDS))

    def _join_windows(self, findings: List[Finding]) -> None:
        """A page of an Electron app that loads a script by its address (phageo, 2026-10-14):
        what that script can reach depends on the window the page is shown in
        (``dataflow/electron_windows.py``). The page's finding is CHAIN-REMOTE-CODE,
        CRITICAL, when it was made. Here, after the app's scripts were all read:

        * a window with Node.js in the page or without isolation - or a preload script that
          hands the page functions and itself starts programs, with the sandbox off: it
          **stays** CRITICAL (the window is named in the evidence);
        * a preload script that hands the page a function reaching a sink, or the message
          channel itself; settings that are not written out; a version that is not known;
          no window found: PAGE-REMOTE-SCRIPT, **HIGH**;
        * the page's scripts are shut in (no Node.js, isolated, nothing handed over):
          PAGE-REMOTE-SCRIPT, **MEDIUM** - a remote script as in any web page.

        Settings that are not written are read by the defaults of the app's Electron
        version - the one of its runtime program, when the table verified it. Only pages
        inside an Electron app's own files; a page anywhere else keeps its finding."""
        pages = [f for f in findings if f.context.get(electron_windows.PAGE_SCRIPT)]
        for f in pages:
            root = electron_windows.app_root(f.file)
            if root is None:
                continue
            scripts = {name: script for name, script in self._app_scripts.items()
                       if electron_windows.app_root(name) == root}
            version = self._app_versions.get(root, "")
            page = f.file.replace("\\", "/").lower().rsplit("/", 1)[-1].rsplit("!", 1)[-1]
            windows = [(name, window) for name, script in sorted(scripts.items()) for window in script.windows]
            shown = [(name, window) for name, window in windows if page in window.loads] or windows
            ipc = self._ipc(root, findings)
            judged = [electron_windows.judge(window, version, scripts, ipc) + (name, window.line) for name, window in shown]
            state, why = electron_windows.worst((s, "%s (%s, line %d)" % (w, name.rsplit("!", 1)[-1], line))
                                                for s, w, name, line in judged)
            where = "; the window it is shown in: %s%s" % (why, "; Electron %s" % version if version else "")
            if state == electron_windows.EXPOSED:
                f.evidence += where
                exposed = [w for s, w, _name, _line in judged if s == electron_windows.EXPOSED]
                if f.severity is Severity.CRITICAL and all(w == electron_windows.NODE_ON for w in exposed):
                    # the app's own setting gives the page Node.js: what the remote script can do
                    # is real behaviour of the app, HIGH (phageo, 2026-10-17, fifty-ninth message)
                    f.severity = Severity.HIGH
                    f.context[electron_windows.REAL_BEHAVIOUR] = True
                    f.reason += PAGE_NODE_ON
                    f.evidence += "  [real behaviour of the app]"
                continue
            f.context["was"] = f.rule_id
            f.rule_id, f.title = electron_windows.LOWERED, "Page loads a script from a remote address"
            f.category, f.chainable = Category.NETWORK, False
            if state == electron_windows.SHUT_IN:
                f.severity, f.confidence = Severity.MEDIUM, 0.4
                f.reason = PAGE_SHUT_IN
            else:
                f.severity, f.confidence = Severity.HIGH, 0.5
                f.reason = PAGE_NOT_SHUT_IN
            f.evidence += where
        self._join_script_elements(findings)
        self._join_renderer(findings)

    def _join_script_elements(self, findings: List[Finding]) -> None:
        """A script element that a script of an Electron app makes and gives a remote address
        (``script.src = "https://..."``; phageo, 2026-10-17, sixtieth message): the remote script
        of a page, as in :meth:`_join_windows` - but the window it runs in is named only when
        every page that loads the making script is shown by a window found in the app (as in
        :meth:`_join_renderer`). Then those windows decide as for a page: exposed by more than
        Node.js alone (isolation off, a preload that starts programs without a sandbox) - it
        **stays** CRITICAL. Every other case - Node.js on, bridged, not known, shut in, and the
        window that cannot be named at all - is **HIGH**, tagged as the app's real behaviour:
        decision 6 of the fifty-ninth message gives the remote script of a page with Node.js
        HIGH, so one whose window is not even known is at most that."""
        for f in findings:
            if not f.context.pop(electron_windows.SCRIPT_ELEMENT, None) or f.rule_id != "CHAIN-REMOTE-CODE" \
                    or f.severity is not Severity.CRITICAL:
                continue
            root = electron_windows.app_root(f.file)
            if root is None:
                continue                                    # not an Electron app's own file: as before
            low = f.file.replace("\\", "/").lower()
            name = low.rsplit("/", 1)[-1].rsplit("!", 1)[-1]
            scripts = {key: script for key, script in self._app_scripts.items()
                       if electron_windows.app_root(key) == root}
            windows = [(key, window) for key, script in sorted(scripts.items()) for window in script.windows]
            pages = {name} if low.endswith((".html", ".htm")) else {
                page.replace("\\", "/").lower().rsplit("/", 1)[-1].rsplit("!", 1)[-1]
                for page, loaded in self._app_pages.items() if electron_windows.app_root(page) == root and name in loaded}
            shown = [[(key, window) for key, window in windows if page in window.loads] for page in sorted(pages)]
            where = electron_windows.NOT_IDENTIFIED
            if pages and all(shown):
                ipc = self._ipc(root, findings)
                version = self._app_versions.get(root, "")
                judged = [electron_windows.judge(window, version, scripts, ipc) + (key, window.line)
                          for each in shown for key, window in each]
                where = "; ".join(dict.fromkeys("%s (%s, line %d)" % (w, key.rsplit("!", 1)[-1], line)
                                                for _s, w, key, line in judged))
                if any(s == electron_windows.EXPOSED and w != electron_windows.NODE_ON for s, w, _k, _l in judged):
                    f.evidence += "; the window it runs in: %s" % where
                    continue
            f.severity = Severity.HIGH
            f.context[electron_windows.REAL_BEHAVIOUR] = True
            f.reason += SCRIPT_ELEMENT_HIGH
            f.evidence += "; the window it runs in: %s  [real behaviour of the app]" % where

    def _ipc(self, root: str, findings: List[Finding]) -> "electron_ipc.Reading":
        """What the main process of the app at ``root`` does with its pages' messages (phageo,
        2026-10-15, forty-eighth message; ``dataflow/electron_ipc.py``) - read once per app, from
        the texts its scripts left. Not complete when a script was too large or not kept, the
        app's main script is not known, or a part of the app could not be read."""
        reading = self._app_ipc.get(root)
        if reading is None:
            texts = {name: text for name, text in self._app_texts.items() if electron_windows.app_root(name) == root}
            mains = _main_scripts(self._app_files.get(root, {}).get("package.json"))
            why = self._app_cut.get(root, "")
            unread = next((f for f in findings if f.rule_id in UNREAD_CONTENT and not f.suppressed
                           and electron_windows.app_root(f.file) == root), None)
            if unread is not None and not why:
                why = "a part of the app could not be read (%s)" % unread.rule_id
            reading = self._app_ipc[root] = electron_ipc.read(texts, mains, not why, why)
        return reading

    def _join_renderer(self, findings: List[Finding]) -> None:
        """A script of an Electron app's pages that loads code - ``import()``, ``eval``,
        ``new Function``, a ``Worker``, ``importScripts`` (phageo, 2026-10-15, forty-seventh
        message): when it runs only in windows whose pages are shut in (no Node.js, isolated, no
        preload function that reaches a sink - ``electron_windows.judge``), what it loads runs as
        in a web browser and cannot reach the PC. The chain's premise is disproven (rule 13): the
        finding becomes RENDERER-CODE-LOAD, MEDIUM. Where the script runs must be known in full:

        * it is a page of the app, or a page of the app loads it by ``<script src>`` (its file
          name) - and it is not the app's main script (``package.json``, which must have been
          read) nor any window's preload script;
        * every page that runs it is shown by a window found in the app's scripts.

        Anything else - a script no page names, a page no window shows, a window that is not
        shut in - leaves the finding as it was. Messages the page sends to the main process stay
        what they were: external to whatever the main process starts."""
        for f in findings:
            sink = f.context.pop(electron_windows.RENDERER, None)
            if sink is None or f.rule_id not in ("CHAIN-REMOTE-CODE", "CHAIN-REMOTE-LOAD"):
                continue
            low = f.file.replace("\\", "/").lower()
            root = electron_windows.app_root(f.file)
            if root is None or not low.endswith((".js", ".mjs", ".cjs", ".html", ".htm")):
                continue
            name = low.rsplit("/", 1)[-1].rsplit("!", 1)[-1]
            scripts = {key: script for key, script in self._app_scripts.items()
                       if electron_windows.app_root(key) == root}
            windows = [(key, window) for key, script in sorted(scripts.items()) for window in script.windows]
            mains = _main_scripts(self._app_files.get(root, {}).get("package.json"))
            if mains is None or name in mains or any(
                    isinstance(window.preload, str) and window.preload.lower() == name for _key, window in windows):
                continue
            if low.endswith((".html", ".htm")):
                pages = {name}
            else:
                pages = {page.replace("\\", "/").lower().rsplit("/", 1)[-1].rsplit("!", 1)[-1]
                         for page, loaded in self._app_pages.items()
                         if electron_windows.app_root(page) == root and name in loaded}
            if not pages:
                continue                                # no page names it: where it runs is not known
            shown = [[(key, window) for key, window in windows if page in window.loads] for page in sorted(pages)]
            if not all(shown):
                continue                                # a page that no window found shows
            ipc = self._ipc(root, findings)
            judged = [electron_windows.judge(window, self._app_versions.get(root, ""), scripts, ipc) + (key, window.line)
                      for each in shown for key, window in each]
            if any(state != electron_windows.SHUT_IN for state, _why, _key, _line in judged):
                continue
            why = "; ".join(dict.fromkeys("%s (%s, line %d)" % (w, key.rsplit("!", 1)[-1], line)
                                          for _s, w, key, line in judged))
            version = self._app_versions.get(root, "")
            f.context["was"] = f.rule_id
            f.rule_id, f.title = electron_windows.CONTAINED, "Code loaded inside a shut-in app window"
            f.severity, f.confidence, f.category, f.chainable = Severity.MEDIUM, 0.4, Category.EXECUTION, False
            f.reason = RENDERER_SHUT_IN
            f.evidence += "; runs only in page(s) %s; the window(s) they are shown in: %s%s" % (
                ", ".join(sorted(pages)), why, "; Electron %s" % version if version else "")

    def _join_updates(self, findings: List[Finding]) -> None:
        """A checked self-update (phageo, 2026-10-14, forty-third message;
        ``dataflow/self_update.py``): a CHAIN-REMOTE-CODE that starts a downloaded file whose
        every way passes a signature check, in a script read to its end, becomes
        CHAIN-SELF-UPDATE (MEDIUM) when the download comes over HTTPS from a server the app
        names for itself - written in the script or in a settings file packed with the app.
        Read here, after every file of the app was seen. Anything else stays CRITICAL; the
        reason it stays is added to the evidence."""
        marked = [f for f in findings if self_update.SELF_UPDATE in f.context]
        if not marked:
            return
        cut = {f.file for f in findings if f.rule_id == TRACER_CUT}
        for f in marked:
            mark = f.context.pop(self_update.SELF_UPDATE)
            if f.rule_id != "CHAIN-REMOTE-CODE" or f.severity is not Severity.CRITICAL:
                continue
            app = electron_windows.app_root(f.file)
            if app is None:
                ok, why = False, "not a script of an Electron app"
            elif f.file in cut:
                ok, why = False, "the script was not read to its end"
            else:
                # (the crypto library a check is made with must itself be verified - phageo,
                # 2026-10-15, forty-sixth message)
                ok, why = self_update.libraries(mark.get("checks"), self._app_libraries.get(app, {}),
                                                app in self._app_versions)
                if ok:
                    ok, why = self_update.judge(mark, self._app_files.get(app, {}))
            if not ok:
                f.evidence += "; not a checked self-update: " + why
                continue
            f.context["was"] = f.rule_id
            f.rule_id, f.title = self_update.RULE, "Checked self-update"
            f.severity, f.confidence, f.category = Severity.MEDIUM, 0.4, Category.NETWORK
            f.reason = self_update.REASON
            f.evidence += "; checked self-update: signature check on all %d way(s), %s" % (mark["ways"], why)
            self._fold_update(f, mark, findings)

    @staticmethod
    def _fold_update(update: Finding, mark: dict, findings: List[Finding]) -> None:
        """Once the checked self-update stands, the findings of that same path are folded into
        it (phageo, 2026-10-15, forty-fifth message): the start of the checked file (DF-CMD-001 /
        LOL-001 on its line - and on the line of the check's own PowerShell, which is part of
        the update), the ``child_process`` import that start needs (JS-PROC-001) and
        the "download and run" chain of nearness made of them (CHAIN-FETCHRUN). Folded means
        hidden with the reason and named in the update's evidence. Other dynamic parts keep
        their level: the import and the chain are folded only when every other ``child_process``
        start of the script is a fixed program or made of the app's own values - and with such
        starts left, the import is what they make it (MEDIUM, as ``ContextEngine._by_flow``
        would). (The shell's ``openExternal`` and the Script Host are not ``child_process``.)"""
        line = mark.get("start_line")
        path = {line} | set(mark.get("check_lines") or ())          # (the check's own PowerShell is on it)
        others = [s for s in mark.get("starts") or () if s[0] != line]
        quiet = all(kind == remote.QUIET or local for _line, kind, local in others)
        same = [g for g in findings if g.file == update.file and g is not update and not g.suppressed]
        folded = [g for g in same if g.rule_id in ("DF-CMD-001", "LOL-001") and g.line and g.line in path]
        if quiet:
            for g in same:
                if g.rule_id != "JS-PROC-001" or g.severity is not Severity.HIGH or \
                        "child_process" not in (g.context.get("match", "") + g.snippet):
                    continue
                if others:
                    g.severity = Severity.MEDIUM
                    g.reason += UPDATE_IMPORT
                else:
                    folded.append(g)
            served = {(g.rule_id, g.line) for g in same if g.rule_id == "JS-PROC-001"} | \
                     {(g.rule_id, g.line) for g in folded}
            for g in same:
                parts = g.context.get("parts") or ()
                runs = [(rule, at) for rule, category, at in parts if category in (Category.PROCESS.value,
                                                                                    Category.EXECUTION.value)]
                if g.rule_id == "CHAIN-FETCHRUN" and runs and all(run in served or run[1] in path for run in runs):
                    folded.append(g)
        for g in folded:
            g.suppress(UPDATE_FOLDED)
        if folded:
            update.evidence += "; folded into it: " + ", ".join(
                "%s%s" % (g.rule_id, " (line %d)" % g.line if g.line else "") for g in folded)

    def _join_addons(self, findings: List[Finding]) -> None:
        """ADDON-DECRYPT-001: say in its evidence how many scripts of the same package have
        an active network finding. When the same Electron app also has a script that names a
        browser's, Discord's or a wallet's store, the three make ``CHAIN-STEALER``, CRITICAL
        (``stealer.chains``; phageo, 2026-10-15, forty-ninth message)."""
        addons = [f for f in findings if f.rule_id == ADDON_DECRYPT]
        if not addons:
            return
        network: Dict[str, set] = {}
        for f in findings:
            if not f.suppressed and (f.category is Category.NETWORK or f.rule_id.startswith("CHAIN-REMOTE")) \
                    and f.file.lower().endswith((".js", ".cjs", ".mjs", ".html", ".htm")):
                network.setdefault(_package_root(f.file), set()).add(f.file)
        for f in addons:
            f.evidence += "; scripts of the same package with a network call: %d" % len(
                network.get(_package_root(f.file), ()))
        findings.extend(stealer.chains(findings, self._app_stores, electron_windows.app_root))

    def _forget_local(self) -> None:
        """What ``_join_local`` needs, emptied (a new scan, or the end of one)."""
        self._local_disk: Dict[str, List[str]] = {}   # file name -> files of the folder scan
        self._side_programs: List[sideload.Program] = []
        self._side_libraries: List[sideload.Library] = []
        # ENGINE-008: programs in the engine's place that no official table holds, and what each
        # engine root's renpy/vc_version.py / __init__.py say (engine root -> {file: text})
        self._engine_programs: List[dict] = []
        self._engine_texts: Dict[str, Dict[str, str]] = {}
        # ENGINE-009: the folders of verified app runtimes (folder -> what the runtime is), and the
        # programs of the scan that nothing verifies
        self._runtime_roots: Dict[str, str] = {}
        self._app_programs: List[dict] = []
        # CHAIN-LOCAL-DROP-PLUS: the files on disk that are archives or installers, and the scan's
        # targets (a game root is one of them, or one of the targets)
        self._packages: set = set()
        self._targets: List[str] = []
        localdrop.end()

    def _note_engine_text(self, ctx: FileContext) -> None:
        """For ENGINE-008 (``_join_local``): the text of ``renpy/vc_version.py`` / ``__init__.py``
        of any engine root of the scan - also inside an archive, where no folder can be asked."""
        found = renpy_engine.version_file(ctx.key)
        if found and not ctx.truncated and ctx.size <= _MAX_VERSION_TEXT and len(self._engine_texts) < _MAX_ENGINES:
            try:
                self._engine_texts.setdefault(found[0], {})[found[1]] = bytes(ctx.data).decode("utf-8", "replace")
            except (TypeError, ValueError):
                pass

    def _note_engine_program(self, ctx: FileContext, handler: str) -> None:
        """For ENGINE-008 (``_join_local``; phageo, 2026-10-18, decision 2): a program or library in
        the engine's place (``lib/``, ``renpy/``) that is no file of an official table and carries
        no valid signature of a trusted publisher."""
        root = renpy_engine.engine_root(ctx.key)
        if root is None or len(self._engine_programs) >= _MAX_ENGINE_PROGRAMS:
            return
        sha = ctx.sha256
        if (engine_hashes.verified(sha) or electron_official.verified(sha) or inno_official.verified(sha)
                or nsis_official.verified(sha) or library_hashes.verified(sha) or directx_official.verified(sha)
                or ctx.baseline.startswith(_SIGNED) or self._renpy_program(ctx)):
            return
        self._engine_programs.append({"file": ctx.relpath, "root": root, "path": ctx.path, "sha256": sha,
                                      "baseline": ctx.baseline, "handler": handler,
                                      "name": sideload.leaf_of(ctx.relpath)})

    def _note_app_program(self, ctx: FileContext, handler: str) -> None:
        """For ENGINE-009 (``_join_local``; phageo, 2026-10-20, seventy-third message): a verified app
        runtime - Electron's program or NW.js's launcher, by SHA-256 or by its code apart from the
        branding resources - marks its folder; a program or library that nothing verifies (no
        official table, no valid signature of a trusted publisher, no Windows system file) is kept
        for the note. A ``.node`` add-on is not such a program (decision 3)."""
        leaf, sha, base = sideload.leaf_of(ctx.relpath), ctx.sha256, ctx.baseline
        known = official.exact(sha) or ""
        if leaf.endswith(".exe") and len(self._runtime_roots) < _MAX_ENGINES:
            runtime = ("Electron" if electron_official.PROGRAM_VERIFIED in base or (
                           electron_official.verified(sha) or "").lower().startswith("electron.exe")
                       else "NW.js" if engine_hashes.LAUNCHER_VERIFIED in base or known.lower().startswith("nw.exe")
                       else "")
            if runtime:
                self._runtime_roots.setdefault(electron_windows.program_root(ctx.relpath), runtime)
        if (leaf.endswith(".node") or known or base == "Windows system file"
                or base.startswith((_SIGNED, engine_hashes.VERIFIED, library_hashes.VERIFIED))
                or engine_hashes.LAUNCHER_VERIFIED in base or electron_official.PROGRAM_VERIFIED in base
                or len(self._app_programs) >= _MAX_ENGINE_PROGRAMS):
            return
        self._app_programs.append({"file": ctx.relpath, "low": ctx.relpath.replace("\\", "/").lower(),
                                   "path": ctx.path, "sha256": sha, "baseline": base, "handler": handler,
                                   "name": leaf})

    def _app_program_notes(self) -> List[Finding]:
        """ENGINE-009 (phageo, 2026-10-20, seventy-third message): every program of the scan that
        nothing verifies and that lies in the folder of a verified app runtime (or below it).
        MEDIUM, visible (``context._SHOWN_IN_NAMED_BASELINES``)."""
        out: List[Finding] = []
        roots = sorted(self._runtime_roots.items(), key=lambda item: len(item[0]), reverse=True)
        for tag in self._app_programs:
            runtime = next((what for root, what in roots if tag["low"].startswith(root)), None)
            if runtime is None:
                continue
            evidence = ("%s: in the folder of an app whose %s runtime is verified, but in no table of "
                        "official files and not validly signed by a trusted publisher" % (tag["name"], runtime))
            f = Finding(rule_id=APP_PROGRAM, title=APP_PROGRAM_TITLE, category=Category.EVASION,
                        severity=Severity.MEDIUM, file=tag["file"], line=None, snippet=tag["name"],
                        evidence=evidence, confidence=0.5, reason=APP_PROGRAM_REASON, handler=tag["handler"],
                        sha256=tag["sha256"], path=tag["path"], chainable=False)
            ctx = FileContext(path=tag["path"], relpath=tag["file"], data=b"", size=0, sha256=tag["sha256"],
                              baseline=tag["baseline"])
            self.context.evaluate_joined(f, ctx)
            out.append(f)
        return out

    @staticmethod
    def _renpy_program(ctx: FileContext) -> Optional[str]:
        """Which official Ren'Py SDK program this one is apart from its resource section - the
        game's start program, renamed and with its own icon (phageo, 2026-10-18, sixty-second
        message, decision 1: accepted for ENGINE-008 as a renamed ``nw.exe`` is). Only when the
        resources hold icons, icon groups, a version and a manifest and nothing else (no kind
        with a name, no program inside them), and nothing differs outside them: no signature,
        no appended data, no other byte (``pe.resource_frame_key``). None: not such a program -
        the note stays. A program larger than what is loaded is not compared (the note stays)."""
        pe = ctx.pe
        if (pe is None or pe.is_dotnet or ctx.truncated or pe.has_signature or pe.overlay_size
                or pe.entry_point not in engine_hashes.RENPY_PROGRAM_ENTRY_POINTS):
            return None
        official = engine_hashes.verified_renpy_program(resource_frame_key(ctx.data, pe))
        kinds = resource_kinds(ctx.data, pe) if official else None
        if not kinds or not set(kinds) <= engine_hashes.RENPY_PROGRAM_KINDS \
                or program_inside(resources_of(ctx.data, pe)):
            return None
        return official

    def _note_sideload(self, ctx: FileContext, handler: str) -> None:
        """For SIDELOAD-001 (``_join_local``): a program - which libraries named like Windows'
        it imports or names beside a ``LoadLibrary`` import -, or a library of such a name and
        what proves where it comes from. Names and marks only."""
        name = sideload.leaf_of(ctx.relpath)
        if name.endswith(".exe"):
            if len(self._side_programs) < sideload.MAX_PROGRAMS:
                imports = ctx.pe.imports
                program = sideload.Program(ctx.relpath, imports, sideload.loaded_names(ctx.data, imports))
                if program.imports or program.loads:
                    self._side_programs.append(program)
            return
        what = sideload.kind_of(name)
        if not what or len(self._side_libraries) >= sideload.MAX_LIBRARIES or ctx.baseline == "Windows system file":
            return
        sha = ctx.sha256
        official = (engine_hashes.verified(sha) or electron_official.verified(sha) or inno_official.verified(sha)
                    or nsis_official.verified(sha) or library_hashes.verified(sha) or directx_official.verified(sha))
        proof = why = ""
        if official:
            proof = "a file of an official release: %s" % official
        else:
            who = engine_files.signer(ctx) if ctx.pe.has_signature else None
            if who is not None and engine_files._signed_by(who, sideload.MICROSOFT):
                proof = "validly signed by %s" % who
            elif who is not None:
                why = 'it is signed by "%s", not by Microsoft' % (who or "an unnamed publisher")
            elif ctx.pe.has_signature and not ctx.on_disk and not spool.DISK:
                why = "it carries a signature, which a scan in memory cannot check"
            elif ctx.pe.has_signature:
                why = "its signature is not valid"
            else:
                why = "it has no signature"
        self._side_libraries.append(sideload.Library(ctx.relpath, proof, why, {
            "path": ctx.path, "sha256": sha, "baseline": ctx.baseline, "handler": handler, "kind": what}))

    def _join_local(self, findings: List[Finding]) -> List[Finding]:
        """After the whole scan (phageo, 2026-10-17):

        * CHAIN-LOCAL-DROP is made CRITICAL when the file the script decodes is in the scan and
          the script's own steps, applied to it in memory, give a program or an archive holding
          one (:mod:`gamescan.localdrop`; nothing is written to disk, every step is capped);
        * SIDELOAD-001 for every library named like Windows' beside a program that imports or
          loads it, unless validly signed by Microsoft or a file of an official table
          (:mod:`gamescan.sideload`).

        Returns the new findings (they are added to ``findings``)."""
        for f in findings:
            wanted = f.context.get("local_drop") if f.rule_id == LOCAL_DROP else None
            if not wanted or f.severity is Severity.CRITICAL:
                continue
            # the file the chain names, and - started through a folder (phageo, 2026-10-18) - every
            # other decoded file written to that folder: any of them may be what the program loads
            tried = []
            for one in [wanted] + list(wanted.get("also") or ()):
                pair = (one.get("file") or "", tuple(one.get("steps") or ()))
                if pair[0] and localdrop.provable(pair[1]) and pair not in tried:
                    tried.append(pair)
            for name, steps in tried:
                candidates = localdrop.kept(name)
                for path in self._local_disk.get(name, ())[:localdrop.MAX_CANDIDATES]:
                    try:
                        if os.path.getsize(path) <= localdrop.MAX_INPUT:
                            with open(path, "rb") as fh:
                                candidates.append(fh.read(localdrop.MAX_INPUT + 1))
                    except OSError:
                        pass
                shown = next((one for one in (localdrop.proof(localdrop.decode(data, steps))
                                              for data in candidates[:2 * localdrop.MAX_CANDIDATES]) if one), "")
                if shown:
                    f.severity, f.confidence = Severity.CRITICAL, max(f.confidence, 0.85)
                    f.reason += LOCAL_DROP_PROVEN % shown
                    f.evidence += "; %s, decoded in memory with these steps, is %s" % (name, shown)
                    if f.suppressed and f.suppression_reason.startswith("Engine / library baseline"):
                        f.suppressed, f.suppression_reason = False, ""      # (CRITICAL wins: rule 13)
                    break
        new: List[Finding] = []
        for library, program, how in sideload.pairs(self._side_programs, self._side_libraries):
            if library.proof:
                continue
            tag = library.tag
            evidence = "%s (named like %s) lies beside %s, which %s; %s, and it is not a file of an " \
                       "official release the scanner knows" % (library.name, tag["kind"], program.file, how,
                                                                library.why)
            f = Finding(rule_id=sideload.RULE, title=sideload.TITLE, category=Category.EVASION,
                        severity=Severity.HIGH, file=library.file, line=None, snippet=library.name,
                        evidence=evidence, confidence=0.6, reason=sideload.REASON, handler=tag["handler"],
                        sha256=tag["sha256"], path=tag["path"], chainable=False)
            ctx = FileContext(path=tag["path"], relpath=library.file, data=b"", size=0, sha256=tag["sha256"],
                              baseline=tag["baseline"])
            self.context.evaluate_joined(f, ctx)
            new.append(f)
        new += self._engine_program_notes()
        new += self._app_program_notes()
        new += self._local_combined(findings)
        findings.extend(new)
        return new

    def _game_root(self, rel: str) -> str:
        """The game a file of this scan belongs to (phageo, 2026-10-18): the archive or installer on
        disk it was unpacked from, or else the scanned folder (the target that holds it, when the
        scan has several)."""
        top = rel.split("!", 1)[0]
        if top != rel and top in self._packages:
            return "\0" + top
        low = top.lower()
        for target in sorted(self._targets, key=len, reverse=True):
            t = target.replace(os.sep, "/").rstrip("/").lower()
            if low == t or low.startswith(t + "/"):
                return t
        return ""

    def _local_combined(self, findings: List[Finding]) -> List[Finding]:
        """CHAIN-LOCAL-DROP-PLUS (phageo, 2026-10-18, fix A): an active ``CHAIN-LOCAL-DROP`` that is
        HIGH (not proven a program) and an active HIGH ``PERSIST-001`` or ``EVADE-001`` in the same
        game (:meth:`_game_root`) make one CRITICAL finding beside the chain, which stays as it is -
        one per game. Its evidence names the rules and the files of both sides."""
        drops: Dict[str, List[Finding]] = {}
        signs: Dict[str, List[Finding]] = {}
        for f in findings:
            if f.suppressed or f.severity is not Severity.HIGH:
                continue
            if f.rule_id == LOCAL_DROP:
                drops.setdefault(self._game_root(f.file), []).append(f)
            elif f.rule_id in LOCAL_COMBINED_WITH:
                signs.setdefault(self._game_root(f.file), []).append(f)
        done = {self._game_root(f.file) for f in findings if f.rule_id == LOCAL_COMBINED}
        out: List[Finding] = []
        for game in sorted(drops):
            if game not in signs or game in done:
                continue
            chain = drops[game][0]
            rules = sorted({f.rule_id for f in signs[game]})
            files = sorted({f.file for f in signs[game]})
            evidence = "%s in %s; %s in %s" % (
                LOCAL_DROP, ", ".join(sorted({f.file for f in drops[game]})[:4]), " / ".join(rules),
                ", ".join(files[:4]) + (" and %d more" % (len(files) - 4) if len(files) > 4 else ""))
            f = Finding(rule_id=LOCAL_COMBINED, title=LOCAL_COMBINED_TITLE, category=Category.CHAIN,
                        severity=Severity.CRITICAL, file=chain.file, line=chain.line, snippet=chain.snippet,
                        evidence=evidence, confidence=0.8, reason=LOCAL_COMBINED_REASON % " / ".join(rules),
                        handler=chain.handler, sha256=chain.sha256, path=chain.path, chainable=False)
            self.context.evaluate_joined(f, FileContext(path=chain.path, relpath=chain.file, data=b"",
                                                        size=0, sha256=chain.sha256))
            out.append(f)
        return out

    def _engine_program_notes(self) -> List[Finding]:
        """ENGINE-008 (phageo, 2026-10-18, decision 2): a program or library in the engine's place
        of a Ren'Py whose ``renpy/vc_version.py`` / ``__init__.py`` - found anywhere in the scan,
        inside an archive too - say a version whose official files are in the tables, and that is
        none of them. MEDIUM, visible (``context._SHOWN_IN_NAMED_BASELINES``)."""
        out: List[Finding] = []
        for tag in self._engine_programs:
            texts = self._engine_texts.get(tag["root"])
            version = renpy_engine.version_from(texts.get("renpy/vc_version.py", ""),
                                                texts.get("renpy/__init__.py", "")) if texts else None
            if not renpy_engine.version_listed(version):
                continue
            evidence = "%s: not a file of the official Ren'Py %s - %s" % (
                tag["name"], version, "the SDKs have a program of this name, and this is not it"
                if renpy_engine.sdk_program(tag["name"]) else "the SDKs have no program of this name")
            f = Finding(rule_id=ENGINE_PROGRAM, title=ENGINE_PROGRAM_TITLE, category=Category.EVASION,
                        severity=Severity.MEDIUM, file=tag["file"], line=None, snippet=tag["name"],
                        evidence=evidence, confidence=0.5, reason=ENGINE_PROGRAM_REASON, handler=tag["handler"],
                        sha256=tag["sha256"], path=tag["path"], chainable=False)
            ctx = FileContext(path=tag["path"], relpath=tag["file"], data=b"", size=0, sha256=tag["sha256"],
                              baseline=tag["baseline"])
            self.context.evaluate_joined(f, ctx)
            out.append(f)
        return out

    def _join_managed(self, report: ScanReport, on_findings: Optional[FindingsFn] = None) -> None:
        """Download-and-run across two .NET libraries of the scanned folder, one hop
        (``dataflow/remote_cs.join``): a method of one library gives a download back
        to another, which loads or starts it - or is handed a download and loads or
        starts it. Each library left what it shares while it was scanned. The
        finding is made for the library that loads or starts."""
        if len(self._managed) < 2:
            return
        from .dataflow import remote_cs
        found: List[Finding] = []
        for link in remote_cs.join([shares for shares, _tag in self._managed]):
            tag, other = self._managed[link.runner][1], self._managed[link.other][1]
            handler = tag["handler"]
            ctx = FileContext(path=tag["path"], relpath=tag["file"], data=b"", size=0,
                              sha256=tag["sha256"], baseline=tag["baseline"])
            f = handler.joined_managed(ctx, link, other["file"], [tag["official"], other["official"]])
            f.handler, f.sha256, f.path = handler.name, ctx.sha256, ctx.path
            self.context.evaluate_joined(f, ctx)
            found.append(f)
        if found:
            report.findings.extend(found)
            if on_findings:
                on_findings(found)
        if self._managed_cut:
            report.notes.append("Download-and-run across .NET libraries: more than %d libraries share "
                                "something - not every pair was compared" % _MAX_MANAGED)

    def _remember_scan(self, report: ScanReport) -> None:
        """Mark what is new since the last scan of this target, then store the scan."""
        try:
            previous = self.memory.previous_fingerprints(report.target)
            if previous is not None:
                fresh = 0
                for f in report.findings:
                    f.is_new = fingerprint(f) not in previous
                    fresh += f.is_new and not f.suppressed
                report.notes.append("Memory: %d active finding(s) are new since the last scan "
                                    "of this target" % fresh)
            self.memory.record_scan(report)
        except Exception as exc:                  # a broken database must not lose the scan
            report.notes.append("Memory center unavailable: %s" % exc)

    def scan_bytes(self, relpath: str, data: bytes, path: str = "") -> List[Finding]:
        """Scan in-memory content as if it were the file ``relpath``."""
        ctx = FileContext(path=path or relpath, relpath=relpath.replace("\\", "/"),
                          data=data, size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self._match_everything = bool(len(self.rules.yara)) or (
            self.signatures is not None and self.signatures.count() > 0)
        self._shared, self._shared_cut, self._importers = [], False, {}    # one file: nothing to join it with
        self._managed, self._managed_cut = [], False
        self._forget_local()
        localdrop.begin()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        found = self._scan_ctx(ctx) or []
        self._join_windows(found)          # (an installer or archive holds a whole app)
        self._join_updates(found)
        self._join_addons(found)
        self._join_local(found)
        self._forget_local()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        return found

    # -- internals -------------------------------------------------------------
    def _walk(self, root: str, cancel: Optional[threading.Event] = None) -> List[str]:
        out = []
        skip = os.path.normcase(self.quarantine.directory) if self.quarantine else None
        for base, dirs, names in os.walk(root):
            if cancel is not None and cancel.is_set():
                break
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS
                             and os.path.normcase(os.path.join(base, d)) != skip)
            out.extend(os.path.join(base, n) for n in sorted(names))
        return out

    @staticmethod
    def _ticker(progress: Optional[ProgressFn], done: int, total: int, rel: str):
        """Progress *inside* one file: a large file is not silent until it is
        finished. Reading / hashing it counts as the first tenth, the handler's
        own work (``ctx.tick``) as the rest. At most five updates a second."""
        if progress is None:
            return None
        last = [0.0, -1]

        def tick(fraction: float, reading=False) -> None:
            now = time.monotonic()
            if fraction < 0:                       # a member of this file: name it
                if now - last[0] >= 0.2:
                    last[0] = now
                    progress(done, total, str(reading))
                return
            fraction = min(max(fraction, 0.0), 1.0)
            tenths = int(1000 * (0.1 * fraction if reading else 0.1 + 0.9 * fraction))
            if now - last[0] >= 0.2 and tenths != last[1]:
                last[0], last[1] = now, tenths
                progress(done, total, "%s  (%.1f%%)" % (rel, tenths / 10.0))
        return tick

    @staticmethod
    def _sample(fh) -> bytes:
        fh.seek(0)
        return fh.read(65536)

    def _load(self, path: str, rel: str, tick=None) -> Optional[FileContext]:
        """Read + hash a file, or return None when nothing could want it."""
        if os.path.islink(path):
            return None
        with open(path, "rb") as fh:
            ext = os.path.splitext(rel)[1].lower()
            if (ext not in self._extensions and not self._match_everything
                    and not fh.read(8).startswith(self._magics)):
                # no reader takes it by name or first bytes. Text is still read (by what it
                # is: handlers/text.py), and so is a format nobody reads (it is said: its mark
                # can stand further in - an ISO image's at 32 KB); anything else is not
                # opened, and counts as unread
                fh.seek(0)
                if not sniff.unread_kind(fh.read(sniff.UNREAD_HEAD)) and (
                        fh.seek(0, 2) > text.MAX_TEXT or not text.is_text(self._sample(fh))):
                    return None
            total = fh.seek(0, 2)
            fh.seek(0)
            digest, chunks, kept, size = hashlib.sha256(), [], 0, 0
            while True:
                block = fh.read(1 << 20)
                if not block:
                    break
                digest.update(block)
                size += len(block)
                if tick is not None and total > _LARGE:
                    tick(size / total, True)
                if kept < self.max_bytes:
                    chunks.append(block)
                    kept += len(block)
        data = b"".join(chunks)[:self.max_bytes]
        return FileContext(path=path, relpath=rel, data=data, size=size,
                           sha256=digest.hexdigest(), truncated=size > len(data),
                           cancel=self._cancel, progress=tick if size > _LARGE else None)

    def _scan_ctx(self, ctx: FileContext, depth: int = 0) -> Optional[List[Finding]]:
        """Findings for one file (None = nothing applies to it). Every limit a format
        reader reached while this file was read (``unpack/limits.py``) is said: where
        the file has no "not read" note of that reader's kind yet, one is made."""
        with limits.watch() as reached:
            findings = self._scan_one(ctx, depth)
        if reached and findings is not None:
            findings = findings + self._limit_notes(ctx, reached, findings)
        return findings

    def _limit_notes(self, ctx: FileContext, reached, findings: List[Finding]) -> List[Finding]:
        """The "not read" notes for the limits in ``reached`` that nothing has said yet.
        None for a file that is, by its SHA-256, an official file of an engine or a known
        library (what is in it is known - as for SCRIPT-LIMIT-001)."""
        if ctx.baseline.startswith((engine_hashes.VERIFIED, library_hashes.VERIFIED)) \
                or engine_hashes.verified(ctx.sha256) or electron_official.verified(ctx.sha256):
            return []
        said ={f.rule_id for f in findings if f.file == ctx.relpath}
        out: List[Finding] = []
        for reader, what in reached:
            rule, title = limits.RULES[reader]
            if rule in said or len(out) >= 3:
                continue
            said.add(rule)
            note = Finding(rule_id=rule, title=title, category=Category.EVASION, severity=Severity.LOW,
                           file=ctx.relpath, line=None, snippet="", confidence=0.3, handler="scanner",
                           evidence="a limit of the reader was reached: %s" % what[:200],
                           reason=limits.REASON, sha256=ctx.sha256, path=ctx.path, chainable=False)
            self.context.evaluate(note, ctx)
            out.append(note)
        return out

    def _correlate(self, findings: List[Finding], ctx: FileContext) -> List[Finding]:
        """The chains of one file: of its active findings and - for a file trusted for its
        folder, its npm package or its official engine build - of what its suppressed
        signals add up to. A chain that stands where a CRITICAL stood (``chains.NO_FLOW``)
        is treated as the CRITICAL was: shown, and not lowered for trust."""
        chains = self.chains.correlate(findings, ctx)
        if ctx.baseline and not ctx.baseline.startswith(_SIGNED) and not self.context.strict:
            # A script is trusted here only because of the folder it sits in,
            # which a repack can imitate. Single signals stay suppressed, but a
            # complete CRITICAL chain inside such a file is reported anyway.
            in_baseline = lambda f: (f.line is not None and
                                     f.suppression_reason.startswith("Engine / library baseline"))
            seen = {c.rule_id for c in chains}
            # (a file of a published npm package keeps every chain, HIGH ones too: the registry
            # proves where the file comes from, not what it is used for - phageo, 2026-10-14)
            published = NPM_VERIFIED in ctx.baseline
            for chain in self.chains.correlate(findings, ctx, also=in_baseline):
                if (chain.severity is Severity.CRITICAL or chain.context.get(WAS_CRITICAL)
                        or (published and chain.severity >= Severity.HIGH)) and chain.rule_id not in seen:
                    chain.reason += (" It was found in a file of a published npm package: the "
                                     "single signals are lowered for that, what they add up to is not."
                                     if published else
                                     " It was found in a file that is otherwise trusted for "
                                     "sitting in an engine / library folder.")
                    chains.append(chain)
        if ctx.baseline.startswith(engine_hashes.VERIFIED) and not self.context.strict:
            # The file is, byte for byte, an official engine build. What its
            # (suppressed) signals add up to is still shown - as a note, since a
            # browser or runtime engine is expected to combine these functions.
            # A CRITICAL chain is reported unchanged.
            by_baseline = lambda f: f.suppression_reason.startswith("Engine / library baseline")
            seen = {c.rule_id for c in chains}
            for chain in self.chains.correlate(findings, ctx, also=by_baseline):
                if chain.rule_id in seen:
                    continue
                if chain.severity < Severity.CRITICAL and not chain.context.get(WAS_CRITICAL):
                    chain.severity = Severity.LOW
                    chain.reason += engine_hashes.CHAIN_NOTE
                chains.append(chain)
        return chains

    def _keeper(self, ctx: FileContext, handler):
        """For the builder of ``known_findings``: what a reading of a table file gives."""
        if self.known_record is None or ctx.size < known_findings.MIN_SIZE or not (
                npm_hashes.verified(ctx.sha256) or electron_official.verified(ctx.sha256)):
            return None

        def keep(found, pre, added):
            try:
                if added is None or ctx.truncated:
                    raise known_findings.Unstorable("not the whole file, or a note changed")
                row = known_findings.record(ctx, handler.name, found, pre, added)
            except known_findings.Unstorable as exc:
                row = {"unstorable": str(exc)}
            self.known_record.setdefault(ctx.sha256, []).append(row)
        return keep

    def _scan_one(self, ctx: FileContext, depth: int = 0) -> Optional[List[Finding]]:
        if ctx.sha256 in _own_files():
            return []       # the scanner's own rule definitions look like what it hunts
        if not ctx.truncated:
            localdrop.offer(ctx.relpath, ctx.data)     # (perhaps the file a script decodes: _join_local)
        self._note_engine_text(ctx)                    # (the version an engine says it is: ENGINE-008)
        if ctx.relpath.lower().endswith(self_update.KEPT) and ctx.size <= self_update.MAX_FILE \
                and self._app_kept < self_update.MAX_FILES and "node_modules" not in ctx.relpath.lower():
            app = electron_windows.app_root(ctx.relpath)
            if app is not None:                    # an Electron app's own settings (_join_updates)
                name = ctx.relpath.replace("\\", "/").rsplit("/", 1)[-1].rsplit("!", 1)[-1].lower()
                self._app_files.setdefault(app, {}).setdefault(name, []).append(
                    ctx.data[:self_update.MAX_FILE].decode("utf-8", "replace"))
                self._app_kept += 1
        package = self_update.crypto_package(ctx.relpath) if "node_modules" in ctx.relpath.lower() else ""
        app = electron_windows.app_root(ctx.relpath) if package else None
        if app is not None:                        # a file of the app's crypto library (_join_updates)
            counts = self._app_libraries.setdefault(app, {}).setdefault(package, [0, 0])
            counts[0 if (npm_hashes.verified(ctx.sha256) or "").startswith("npm package %s " % package) else 1] += 1
        if depth:
            self._note_engine(ctx.key)     # an engine can show only inside an archive / installer
        else:
            self._expanded = 0
        ctx.pe = self._parse_pe(ctx) if ctx.is_pe else None
        handler = next((h for h in self.handlers if h.can_handle(ctx)), None)
        if handler is None and self._text.takes(ctx):
            # no reader takes it by its name, and it is text: read by what it is (a script
            # of an engine the scanner does not know - handlers/text.py; phageo, 2026-10-12)
            handler = self._text
        known = self._known_malware(ctx)
        if handler is None and not self._match_everything and not known:
            return None
        name = handler.name if handler else "signatures"
        ctx.baseline = next(filter(None, (h.baseline_reason(ctx) for h in self.handlers)), "")
        # (... or of a published npm package, as the registry hands it out - gamescan/npm_hashes.py;
        # phageo, 2026-10-14. The same policy: the file's own pattern findings are lowered, a
        # CRITICAL chain is still shown, and the app's own scripts are read as ever.)
        library = library_hashes.verified(ctx.sha256) or npm_hashes.verified(ctx.sha256)
        if library and not ctx.baseline.startswith(engine_hashes.VERIFIED):
            # byte for byte a file of an official release of a library games bundle: proof
            # of origin, which a baseline resting on folder and name is not - it goes first
            ctx.baseline = "%s: %s" % (library_hashes.VERIFIED, library)
        packed_by = ctx.cache.get(PACKAGE_SIGNER)
        if packed_by and not ctx.baseline and not self.context.strict and self.context.publisher_trusted(packed_by):
            # a file of an embedded cabinet of a Windows Installer package whose signature Windows
            # accepts shares it, as a member of a signed installer does; a cabinet beside the package
            # by its own signature (phageo, 2026-10-19)
            ctx.baseline = "%s: %s" % (_SIGNED, packed_by)
        if not ctx.baseline and not self.context.strict:
            # a valid signature covers the whole file - also what is packed inside it
            ctx.baseline = ctx.cache.get("signed_container", "")
        # (a file of an official engine archive that also carries a trusted
        # publisher's valid signature - Microsoft's DirectX installer in a Ren'Py
        # SDK - keeps being judged by that signature, as before the hash table)
        by_hash = ctx.baseline.startswith(engine_hashes.VERIFIED)
        if by_hash and depth == 0:
            self._engine_verified = True           # (for the coverage note: Scanner._coverage)
        if ((not ctx.baseline or by_hash) and ctx.pe is not None and ctx.pe.has_signature
                and not self.context.strict and not ctx.cache.get("vendor_conflict")):
            signer = engine_files.signer(ctx)          # None = no valid signature
            if signer is not None:
                if self.context.publisher_trusted(signer):
                    ctx.baseline = "%s: %s" % (_SIGNED, signer)
                elif by_hash:
                    pass                               # the hash already vouches for the file
                else:
                    ctx.signer = signer                # known signer, not a trusted one
        kept = None
        if handler is not None and ctx.size >= known_findings.MIN_SIZE and (
                npm_hashes.verified(ctx.sha256) or electron_official.verified(ctx.sha256)):
            # a file of the official tables whose reading was kept when they were built
            # (phageo, 2026-10-14, forty-third message): given back, not read again
            row = known_findings.entry(ctx.sha256)
            if row is not None and known_findings.usable(row, ctx, handler.name) \
                    and self.known_record is None:
                kept = row
        findings = known + (handler.scan_file(ctx, self.rules, kept=kept, keep=self._keeper(ctx, handler))
                            if handler else [])
        cut = ctx.cache.get(TEXT_CUT)
        if cut:
            # the text was larger in memory than one text may be (models.MAX_DECODED): read up to there
            # (phageo, 2026-10-17, fifty-ninth message)
            findings.append(Finding(
                rule_id="ARC-002", title="Archive could not be fully inspected", category=Category.EVASION,
                severity=Severity.LOW, file=ctx.relpath, line=None, snippet="", confidence=0.3, handler=name,
                evidence="only the first %d of the %d characters of this text were read: it takes %d byte(s) "
                         "a character in memory, more than the %d MB one text may take [cause: memory]"
                         % (cut[0], cut[1], cut[2], cut[3] >> 20),
                reason=NOT_INSPECTED, chainable=False))
        names, imported = ctx.cache.get("shared_names"), ctx.cache.get("imported")
        if names or imported:
            tag = {"handler": handler, "path": ctx.path, "sha256": ctx.sha256,
                   "baseline": ctx.baseline, "state": handler.engine_state(ctx)}
        if names:                                      # what a script shares with other scripts
            if len(self._shared) < shared.MAX_FILES:
                self._shared.append(shared.Entry(
                    ctx.relpath, ctx.ext in handler.store_scripts, names["fills"], names["runs"], tag,
                    drops=names.get("drops"), starts=names.get("starts")))
            else:
                self._shared_cut = True
        for name, line in (imported or {}).items():    # ... and the modules it imports
            known = self._importers.get(name)
            if known is None:
                if len(self._importers) >= _MAX_IMPORT_NAMES:
                    self._shared_cut = True
                    continue
                known = self._importers[name] = []
            if len(known) < _MAX_IMPORTERS:
                known.append((ctx.relpath, line, tag))
        script = ctx.cache.get("electron_script")
        if script is not None and len(self._app_scripts) < electron_windows.MAX_SCRIPTS:
            self._app_scripts[ctx.relpath] = script    # an Electron app's windows and messages
        text = ctx.cache.pop("electron_text", None)    # (held here, not with the file's notes)
        if text is not None or ctx.cache.get("electron_big"):
            root = electron_windows.app_root(ctx.relpath) or ""
            if ctx.cache.get("electron_big"):
                self._app_cut.setdefault(root, "a script with message handlers is larger than %d MB"
                                         % (electron_ipc.MAX_SCRIPT >> 20))
            elif self._app_kept_text + len(text) > electron_ipc.MAX_TOTAL:
                self._app_cut.setdefault(root, "the app's scripts are more than %d MB" % (electron_ipc.MAX_TOTAL >> 20))
            else:
                self._app_texts[ctx.relpath] = text
                self._app_kept_text += len(text)
        if handler is not None and ctx.ext in stealer.SCRIPTS:
            app = electron_windows.app_root(ctx.relpath)
            named = self._app_stores.get(app) if app is not None else None
            if app is not None and (named is not None or len(self._app_stores) < stealer.MAX_APPS) \
                    and len(named or ()) < stealer.MAX_FILES:
                kinds = stealer.store_kinds(ctx.text())    # a browser's, Discord's or a wallet's store
                if kinds:
                    self._app_stores.setdefault(app, {})[ctx.relpath] = kinds
        loaded = ctx.cache.get("page_scripts")
        if loaded is not None and len(self._app_pages) < electron_windows.MAX_SCRIPTS:
            self._app_pages[ctx.relpath] = loaded      # ... and the scripts a page of it loads
        if ctx.pe is not None and electron_official.PROGRAM_VERIFIED in ctx.baseline or (
                ctx.pe is not None and ctx.name.lower().endswith(".exe") and electron_official.verified(ctx.sha256)):
            stated = _ELECTRON_VERSION.search(ctx.baseline) or _ELECTRON_VERSION.search(
                electron_official.verified(ctx.sha256) or "")
            if stated:                                 # the app's runtime, verified: its version
                self._app_versions[electron_windows.program_root(ctx.relpath)] = stated.group(1)
        managed = ctx.cache.get("managed")
        if managed is not None:                        # what a .NET library shares with the others
            if len(self._managed) < _MAX_MANAGED:
                self._managed.append((managed, {
                    "handler": handler, "path": ctx.path, "file": ctx.relpath, "sha256": ctx.sha256,
                    "baseline": ctx.baseline, "official": engine_hashes.verified(ctx.sha256)}))
            else:
                self._managed_cut = True
        findings += self.rules.scan_yara(ctx, name)
        if ctx.pe is not None:
            findings += sigblock.findings(ctx)         # data in / behind the signature block
            _injection_without_writer(ctx, findings)
        for f in findings:
            f.handler, f.sha256, f.path = name, ctx.sha256, ctx.path
            self.context.evaluate(f, ctx)
        # the data-flow reading read this script to its end and found no download that
        # reaches a run: a chain of nearness that says so is disproven (chains.NO_FLOW)
        self.chains.flowless = _flowless(ctx, findings)
        try:
            chains = self._correlate(findings, ctx)
        finally:
            self.chains.flowless = False
        for chain in chains:
            chain.handler, chain.sha256, chain.path = name, ctx.sha256, ctx.path
            if ctx.signer is not None and chain.severity < Severity.CRITICAL \
                    and not chain.context.get(WAS_CRITICAL):
                self.context.lower_for_signature(chain, ctx.signer)
            self.context.remember(chain, ctx)     # chains can be resolved by feedback too
            findings.append(chain)
        library_file = ctx.baseline.startswith(library_hashes.VERIFIED + ": ")
        if library_file and not self.context.strict:
            # A chain that starts and ends inside one verified file of a library - a published npm
            # package, or an official library release - is the library's own mechanism: MEDIUM,
            # tagged, still shown. HIGH since 2026-10-14; CRITICAL too since 2026-10-20 (phageo,
            # seventy-third message: rule 13's exception - jQuery's _evalUrl loads what it is given).
            # ADDON-DECRYPT-001 and chains that start in the app's code (an app script that hands
            # the loader a remote address; chains made after the scan, across files) are not touched.
            published = NPM_VERIFIED in ctx.baseline
            package = ctx.baseline.split(NPM_VERIFIED if published else library_hashes.VERIFIED + ": ", 1)[1]
            for f in findings:
                if f.rule_id.startswith("CHAIN-") and f.severity >= Severity.HIGH and not f.suppressed:
                    if f.severity is Severity.CRITICAL:
                        f.context["library_was_critical"] = True
                    f.severity = Severity.MEDIUM
                    f.context["library_mechanism"] = package
                    f.reason += LIBRARY_MECHANISM if published else LIBRARY_RELEASE_MECHANISM
                    if f.context.get("library_was_critical"):
                        f.reason += LIBRARY_WAS_CRITICAL
        own = ctx.cache.get(OWN_STARTS)
        if own and own[0] and own[1] and not self.context.strict and self.context.publisher_trusted(own[0]):
            self._own_starts(ctx, findings, own)
        findings = self.rules.prune(findings)     # per-rule limits, now that FPs are known
        if ctx.pe is not None and not ctx.pe.is_dotnet:
            self._note_sideload(ctx, name)         # (SIDELOAD-001: _join_local)
        if ctx.is_pe:
            self._note_engine_program(ctx, name)   # (ENGINE-008: _join_local)
            self._note_app_program(ctx, name)      # (ENGINE-009: _join_local)
        if ctx.is_pe and depth == 0:
            self._executables.append({"file": ctx.relpath, "path": ctx.path,
                                      "sha256": ctx.sha256, "baseline": bool(ctx.baseline)})
        if handler and depth < _MAX_DEPTH:
            for child in itertools.chain(handler.expand(ctx),
                                         sigblock.children(ctx) if ctx.pe is not None else ()):
                self._expanded += child.size
                ctx.cache["streamed"] = True       # an opened container is read from disk
                if self._expanded > _MAX_EXPANDED or (self._cancel is not None
                                                      and self._cancel.is_set()):
                    if self._expanded > _MAX_EXPANDED:    # nested-archive bomb guard
                        findings.append(Finding(
                            rule_id="ARC-002", title="Archive could not be fully inspected",
                            category=Category.EVASION, severity=Severity.LOW, file=ctx.relpath,
                            line=None, snippet="", confidence=0.3, handler=name,
                            evidence="more than %d MB unpacked from one file"
                                     % (_MAX_EXPANDED >> 20),
                            reason=NOT_INSPECTED,
                            sha256=ctx.sha256, path=ctx.path, chainable=False))
                    break
                child.cancel = self._cancel
                if ctx.baseline.startswith((_SIGNED, engine_hashes.VERIFIED)) and \
                        not child.cache.get("outside_signature"):
                    # what is packed inside a signed file - or inside a file that is,
                    # byte for byte, an official engine build - is part of that file
                    child.cache["signed_container"] = ctx.baseline
                if ctx.progress is not None and depth == 0:
                    ctx.progress(-1.0, child.relpath)     # which member is being looked at
                try:
                    found = self._scan_ctx(child, depth + 1) or []
                    if child.truncated and not child.cache.get("streamed"):
                        # a large member whose kind of file is not read in a stream
                        found.append(Finding(
                            rule_id="ARC-002", title="Archive could not be fully inspected",
                            category=Category.EVASION, severity=Severity.LOW, file=child.relpath,
                            line=None, snippet="", confidence=0.3, handler=name,
                            evidence="only the first %d MB of this %d MB member were inspected"
                                     % (len(child.data) >> 20, child.size >> 20),
                            reason=NOT_INSPECTED,
                            sha256=child.sha256, path=ctx.path, chainable=False))
                    findings.extend(found)
                finally:
                    containers.release(child)             # the temporary file of a large member
            for f in handler.after_expand(ctx):
                f.handler, f.sha256, f.path = name, ctx.sha256, ctx.path
                self.context.evaluate(f, ctx)
                findings.append(f)
        if official.exact(ctx.sha256):
            # byte for byte a file of an official distribution: its content is known, so it gets
            # no "could not be read" or packed-program note of its own (phageo, 2026-10-17,
            # fifty-ninth message). What its members say is theirs.
            findings = [f for f in findings if f.file != ctx.relpath or f.rule_id not in _UNREAD_NOTES]
        return findings

    @staticmethod
    def _own_starts(ctx: FileContext, findings: List[Finding], own) -> None:
        """The command lines of a Windows Installer package whose signature Windows accepts, from a
        trusted publisher (phageo, 2026-10-19): a HIGH finding on a line that starts a file of the same
        package and fetches or decodes nothing is MEDIUM, tagged, still shown - as a chain inside a
        published npm file is. A chain of the text is lowered only when every line is such a start.
        CRITICAL is never touched (rule 13); an unsigned package, or a line that fetches or
        decodes, keeps its level."""
        _signer, lines, count = own
        every = len(lines) >= count
        for f in findings:
            if f.file != ctx.relpath or f.severity is not Severity.HIGH or f.suppressed:
                continue
            chain = f.rule_id.startswith("CHAIN-")
            if (chain and every) or (not chain and f.line in lines):
                f.severity = Severity.MEDIUM
                f.context["package_start"] = True
                f.reason += PACKAGE_START

    def _note_engine(self, key: str) -> None:
        for h in self.handlers:
            name = h.engine_for(key)
            if name:
                self._engines[name] = True

    @staticmethod
    def _parse_pe(ctx: FileContext):
        """Headers, imports and exports. A program that is only partly loaded
        is mapped from disk for this, so tables that lie behind the loaded
        part (the import table of a 150 MB engine library) are read too."""
        if ctx.truncated and ctx.on_disk:
            try:
                with open(ctx.path, "rb") as fh, \
                        mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as view:
                    return parse_pe(view)
            except (OSError, ValueError):
                pass
        return parse_pe(ctx.data)

    def _known_malware(self, ctx: FileContext) -> List[Finding]:
        """Exact-match signatures: the EICAR test file and the SHA-256 blocklist."""
        name = builtin_match(ctx.data)
        source = "built-in signature"
        if name is None and self.signatures is not None and self._match_everything:
            name, source = self.signatures.lookup(ctx.sha256), "hash blocklist"
        if name is None:
            return []
        test = name == "EICAR-Test-File"
        return [Finding(
            rule_id="SIG-EICAR" if test else "SIG-001",
            title="Antivirus test file (EICAR)" if test else "Known malware",
            category=Category.SIGNATURE, severity=Severity.CRITICAL, file=ctx.relpath, line=None,
            snippet=ctx.sha256, evidence="%s (%s)" % (name, source), confidence=0.99,
            reason=("This is the harmless industry-standard file used to check that an "
                    "antivirus is working." if test else
                    "The file's SHA-256 is on the known-malware list: this exact file has "
                    "already been identified as malicious."), chainable=False)]

    def _open_amsi(self, report: ScanReport) -> Optional[Amsi]:
        """The AMSI session to use for this scan, or None (with an INFO note)."""
        if self._amsi is False or self._amsi is None:
            return self.rules.amsi if getattr(self.rules.amsi, "available", False) else None
        if self._amsi is True:
            self._amsi = Amsi()                   # opened once, reused by later scans
        if not self._amsi.available:
            self.rules.amsi = None
            report.notes.append("INFO: the Windows antimalware engine (AMSI) is not available "
                                "(%s); extracted content was not shown to it"
                                % (self._amsi.problem or "unknown reason"))
            return None
        self.rules.amsi = self._amsi
        return self._amsi

    def _defender_pass(self, report: ScanReport, targets: Optional[List[str]],
                       root: Optional[str], progress: Optional[ProgressFn],
                       on_findings: Optional[FindingsFn],
                       cancel: Optional[threading.Event]) -> None:
        """Optional second opinion: let Windows Defender scan the target itself
        (detection only - it is never allowed to remove anything)."""
        if not targets or len(targets) != 1:
            report.notes.append("INFO: the Windows Defender scan is only run for a single "
                                "game folder or file, not for PC-wide scans")
            return
        if progress:
            progress(0, 1, "Windows Defender · %s" % os.path.basename(targets[0]))
        result = self.defender.scan(targets[0], cancel)
        if result.status == "clean":
            report.notes.append("Windows Defender scan: no threats found")
            return
        if result.status != "threats":
            report.notes.append("INFO: the Windows Defender scan was not performed (%s)"
                                % result.detail)
            return
        found = []
        for threat, paths in result.threats:
            for path in paths or [targets[0]]:
                path = path.split("->")[0]        # "archive.zip->member" style resources
                inside = root and os.path.normcase(path).startswith(os.path.normcase(root))
                rel = (os.path.relpath(path, root) if inside else path).replace(os.sep, "/")
                f = Finding(
                    rule_id="DEFENDER-001", title="Windows Defender detects this file",
                    category=Category.SIGNATURE, severity=Severity.CRITICAL, file=rel, line=None,
                    snippet=threat, evidence=threat, confidence=0.97,
                    reason="Windows Defender scanned this file on request and identified it "
                           "as malware. Defender was told not to remove it.",
                    handler="defender", path=path, chainable=False)
                self.context.remember(f)
                found.append(f)
        report.findings.extend(found)
        report.notes.append("Windows Defender scan: %d threat(s) reported" % len(result.threats))
        if on_findings:
            on_findings(found)

    def _verify_executables(self, report: ScanReport, progress: Optional[ProgressFn],
                            on_findings: Optional[FindingsFn],
                            cancel: Optional[threading.Event]) -> None:
        """External verification of executables by SHA-256 (VirusTotal)."""
        flagged = {f.sha256 for f in report.active}
        seen, queue = set(), []
        # most interesting first: files with findings, then non-engine files
        for exe in sorted(self._executables,
                          key=lambda e: (e["sha256"] not in flagged, e["baseline"], e["file"])):
            if exe["sha256"] not in seen and exe["sha256"] not in self.context.allowlist:
                seen.add(exe["sha256"])
                queue.append(exe)
        if len(queue) > self.max_lookups:
            report.notes.append("VirusTotal: checked %d of %d executables (lookup limit)"
                                % (self.max_lookups, len(queue)))
            queue = queue[:self.max_lookups]
        clean = 0
        for done, exe in enumerate(queue, 1):
            if cancel is not None and cancel.is_set():
                report.cancelled = True
                return
            if progress:
                progress(done, len(queue), "VirusTotal · %s" % exe["file"])
            try:
                rep = self.reputation.lookup(exe["sha256"], cancel)
            except ReputationError as exc:
                report.notes.append("VirusTotal lookups stopped: %s" % exc)
                break
            if rep is None:
                report.cancelled = True
                return
            same = [f for f in report.findings if f.sha256 == exe["sha256"]]
            # an external verdict is evidence about our own rules: feed it back
            # at half weight (VirusTotal can be wrong in both directions)
            if rep.is_clean(self.context.vt_min_age_days):
                clean += 1
                exe["clean"] = True
                weak = [f for f in same if not f.suppressed and f.severity <= Severity.MEDIUM]
                self.context.apply_reputation(same, rep)
                for f in weak:
                    self.context.learn(f, True, "virustotal", 0.5)
            elif rep.malicious >= 5:
                for f in same:
                    if not f.suppressed and f.category is not Category.REPUTATION:
                        self.context.learn(f, False, "virustotal", 0.5)
            new = findings_for(rep, exe["file"], exe["path"], self.context.vt_min_age_days)
            report.findings.extend(new)
            if new and on_findings:
                on_findings(new)
        if queue:
            report.notes.append("VirusTotal: %d executable(s) checked, %d known clean"
                                % (len(queue), clean))

    def _isolate_threats(self, report: ScanReport) -> None:
        """Auto-quarantine: move files with HIGH / CRITICAL findings out of the game."""
        clean = {e["sha256"] for e in self._executables if e.get("clean")}
        by_path: Dict[str, List[Finding]] = {}
        for f in report.active:
            if f.severity >= Severity.HIGH and "!" not in f.file and f.path:
                by_path.setdefault(f.path, []).append(f)
        for path, found in sorted(by_path.items()):
            worst = max(f.severity for f in found)
            if _protected(path):
                report.notes.append("Not quarantined automatically (system or program "
                                    "location): %s" % found[0].file)
                continue
            if found[0].sha256 in clean and worst < Severity.CRITICAL:
                report.notes.append("Not quarantined (VirusTotal knows it as clean): %s"
                                    % found[0].file)
                continue
            try:
                entry = self.quarantine.isolate(path, (f.rule_id for f in found), worst.name)
            except QuarantineError as exc:
                report.errors.append({"file": found[0].file, "error": str(exc)})
                continue
            report.quarantined.append(entry)
            for f in report.findings:
                if f.path == path and "!" not in f.file:
                    f.quarantined = True


def neutral_scanner(strict: bool = False, rules: Optional[RuleEngine] = None,
                    signatures: Optional[SignatureDatabase] = None,
                    amsi: Union[bool, Amsi] = False) -> Scanner:
    """The scanner that judges a game the same way on every PC and every day:
    nothing of the user's profile can hide a finding - no memory center
    (memory=None: no feedback is applied; memory=False: no scan is recorded),
    an allow list without a file behind it, the built-in list of trusted
    publishers - and nothing is looked up on the network. The false-positive
    benchmark and the secure launcher both build their scanner here, so they
    cannot drift apart. What may be passed in only ever adds findings: YARA
    rules, the known-malware hashes, the Windows antimalware engine."""
    context = ContextEngine(HashAllowlist(None), strict=strict, memory=None)
    return Scanner(context=context, rules=rules, memory=False, signatures=signatures, amsi=amsi)


def scan_path(target: str, strict: bool = False,
              allowlist: Optional[HashAllowlist] = None) -> ScanReport:
    """One-call convenience wrapper."""
    return Scanner(strict=strict, allowlist=allowlist).scan(target)
