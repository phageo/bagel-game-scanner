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
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from . import (directx_official, electron_official, engine_hashes, inno_official, jsparse, known_findings, library_hashes,
               localdrop, npm_hashes, nsis_official, official, origin, program_resources, sideload, sigblock, stealer,
               models, reputation, staticonly, tiers, trust)
from .chains import ChainEngine
from .context import NPM_VERIFIED, SIGNED_BY_TRUSTED, TRUSTED_PUBLISHERS, ContextEngine, HashAllowlist
from .dataflow import decoderun, electron_ipc, electron_windows, exfil, exfil_cross, marshal_trace, remote, self_update, shared
from .defender import Amsi, DefenderScan
from .handlers import BaseHandler, containers, default_handlers, engine_files, renpy_engine
from .handlers import native_pe, text
from .handlers.electron import ASAR_HEADER
from .handlers.base import FLOW_CUT, FLOW_READ, LOCAL_DROP, LOCAL_DROP_PROVEN, PAYLOAD_SAID, TRACER_CUT
from .chains import WAS_CRITICAL
from .handlers.text import OWN_STARTS, PACKAGE_SIGNER, TextHandler
from .memory import MemoryCenter, fingerprint
from .models import NOT_INSPECTED, TEXT_CUT, UNREAD_CONTENT, Category, FileContext, Finding, ScanReport, Severity
from .pe import parse_pe, program_inside, resource_differences, resource_frame_key, resource_kinds, resources_of
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
# Ren'Py's icon tool pads the resource section with "RENPYVNE" up to this SDK (launcher/game/change_icon.py;
# from 7.4.0 on with zero bytes): Scanner._renpy_program
RENPY_PADDED_UNTIL = (7, 3, 5)


def _version_tuple(text: str) -> Tuple[int, ...]:
    """``"6.99.12.4"`` -> ``(6, 99, 12, 4)``; a part that is no number ends it."""
    out = []
    for part in text.split("."):
        if not part.isdigit():
            break
        out.append(int(part))
    return tuple(out)

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

    Not counted (2026-11-03): an empty file - its hash is every empty file's, so
    one empty ``__init__.py`` would hide every empty input - and the developer
    tools kept in a ``_tools`` folder (``tests/_tools``: compilers, Node.js with
    its own Python helpers; never shipped, not the scanner's own code).
    """
    global _own_hashes
    if _own_hashes is None:
        found = set()
        for base, dirs, names in os.walk(_OWN_DIR):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "_tools")]
            for name in names:
                if name.lower().endswith((".py", ".pyw", ".yar", ".yara")):
                    try:
                        with open(os.path.join(base, name), "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    if data:
                        found.add(hashlib.sha256(data).hexdigest())
        _own_hashes = frozenset(found)
    return _own_hashes
_MAX_DEPTH = 4                      # nesting: installer > game archive > script table > script
_MAX_SIGNED_MEMBER = 256 * 1024 * 1024   # an in-memory member whose signature is verified
# (phase D, session R2, B1 - phageo 2026-11-15) an error while one member of a container is read no longer ends the
# reading of the whole container: the member gets SCAN-ERR-001 (and a line in the report's errors, naming the member),
# the container's other members are read, and what was found before the error is kept. An error of the container's
# own member list (its reader failing between two members) is said on the container the same way. Off: as before
# (the error ends the container's reading; the top-level file gets SCAN-ERR-001 and loses its findings).
MEMBER_ERRORS_ISOLATED = True
SCAN_ERROR_TITLE = "File could not be analysed"
SCAN_ERROR_REASON = ("The scanner hit an error while analysing this file, so its "
                     "contents were not inspected. Malformed files are sometimes "
                     "crafted to break scanners.")
MEMBER_LIST_ERROR = "the reading of its members stopped here: "
# (phase D, session R2b-1, S03 - phageo 2026-11-17; a silent escape) a container that lies at the nesting limit
# (_MAX_DEPTH) is not opened - until now without a word. Now it is asked for its first member only (nothing of it is
# scanned or kept); when it holds one, the file gets ARC-002 (at least REVIEW). The limit itself is unchanged.
# Off: as before (nothing is said).
DEPTH_NOTE = True
DEPTH_EVIDENCE = "nested more than %d levels deep: what this file holds was not inspected"
# (phase D, session R2b-1 - phageo 2026-11-17; silent escapes, notes only)
# S08: a folder Windows refuses to list (access, a path over the length limit) was skipped with everything below it,
# and a file that could not be opened had only a line in the report's errors - now each gets ARC-002 (at least
# REVIEW) as well. Only in the scan of one folder or file (a game): a PC-wide scan of several places (quick / full)
# meets folders no user may list by design, and keeps the errors line only (R2b-1 review). Off: as before.
UNREADABLE_SAID = True
# S09: a single target (one file, or bytes scanned from memory) that no reader takes came out CLEAN - with the switch,
# ARC-002. Built off in R2b-1 (an existing test expects nothing for such a file); ON since R2b-2 by phageo's word
# (2026-11-17) - that test (YaraTests: "data/level.dat" without signatures) pins the switch off, its assertion unchanged.
UNTAKEN_TARGET_SAID = True
# (phase D, session R2b-2 - phageo 2026-11-17, answer to R2b-1) S04's notes (compiled Python that is not Python 2.7 and
# no official file) are folded to one note per folder on disk, or per archive (the part of the path before the last
# "!"), naming the number of files: a Ren'Py 8 game held 124-156 such notes. The verdict is the same (ARC-002 either
# way); the first file's note stays and says the count. Off: one note per file, as R2b-1 built it.
BYTECODE_NOTES_FOLDED = True
BYTECODE_FOLDED = ("%d compiled Python files that are not Python 2.7 and no official file (Python runs them without "
                   "their source) - %d bytes, not read - in %s: %s")
# S10: a file named like a Windows program that does not begin like one (no "MZ") was not loaded on disk and was no
# member of anything - now ARC-002, unless it begins like a program of another system (ELF, Mach-O also as a
# universal "fat" file: those stay unsaid, as decided 2026-10-12) or is an official file. Off: as before.
NOT_A_PROGRAM_SAID = True
_PROGRAM_ENDINGS = frozenset({".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx", ".node", ".pyd", ".drv",
                              ".efi"})
# (a Java class file also begins with CAFEBABE - but that one is taken by its own handler: here the handler is None)
_OTHER_SYSTEMS = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                  b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
S10_LOADED = "s10_loaded"           # FileContext.cache: loaded only for S10 (nothing is offered to localdrop)
# (item 8 - phageo 2026-11-17) the Electron window / page joins keep only the first electron_windows.MAX_SCRIPTS
# (4,000) scripts and pages of a scan; past that the app's picture is incomplete and nothing said so. Now one note per
# app (SCRIPT-LIMIT-001, information only: no level, verdict or launch change). Off: as before.
SCRIPT_CAP_SAID = True
SCRIPT_CAP_NOTE = "script_cap"      # Finding.context: the item-8 note (i18n.SCRIPT_CAP_NOTE: its own texts)
SCRIPT_CAP_EVIDENCE = ("more than %d scripts and pages in this scan: %d of this app's were not kept for the joins of "
                       "its windows and pages - a window made in such a script is not known when a page is judged")
SAID_UNREAD = "said_unread"         # FileContext.cache: the file's one finding says it was not read (S10)
UNTAKEN_EVIDENCE = "no reader takes this kind of file: its content was not inspected"
NOT_A_PROGRAM_EVIDENCE = ("named like a Windows program (%s) but it does not begin like one (an old DOS program, or "
                          "something else under a program's name): what it holds was not inspected")
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
        self._member_errors: List[Dict[str, str]] = []   # (B1) errors said on a member (_scan_error)
        self._engines: Dict[str, bool] = {}
        self._expanded = 0
        self._cancel: Optional[threading.Event] = None
        self._shared: List[shared.Entry] = []      # what the scripts of this scan share
        self._shared_cut = False
        self._importers: Dict[str, list] = {}      # module name -> the scripts that import it
        self._scripts = marshal_trace.Kept()       # the scripts' texts, for _join_stored_code
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
        # ... and the flows of the app's scripts from a call into a required module to the network (C1,
        # dataflow/exfil.py): (app, script, sha256, path, flow), joined with the decrypting add-ons
        self._app_exfil: List[tuple] = []
        # ... and each app script's cross-file summary (exports, sink imports) for C1 part 2b
        # (dataflow/exfil_cross.py): app -> {relpath: (exfil_cross.Summary, sha256, path)}
        self._app_summaries: Dict[str, Dict[str, tuple]] = {}
        # ... and the same for C3 (dataflow/decoderun.py): decoded data -> code across the app's files
        self._app_decode: Dict[str, Dict[str, tuple]] = {}
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
        staticonly.check_scanner(self)          # (a measurement runner: nothing but the scanner's own reading)
        targets = [os.path.abspath(target)] if isinstance(target, str) else \
            [os.path.abspath(t) for t in target]
        single = len(targets) == 1
        report = ScanReport(target=label or (targets[0] if single else "; ".join(targets)),
                            strict=self.context.strict)
        files: List[str] = []
        self._walk_errors = []                   # (S08) folders that could not be listed
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
        lone = single and os.path.isfile(targets[0])     # (S09) the scan of one file
        report.files_total = len(files)
        self._executables = []
        self._member_errors = []                 # (B1) errors said on a member, for report.errors
        self._shared, self._shared_cut, self._importers = [], False, {}
        self._scripts = marshal_trace.Kept()
        self._managed, self._managed_cut = [], False
        self._origin_of = {}                     # relpath -> origin.Origin of every file read (origin.stamp)
        self._app_cap = {}                       # (item 8) app root -> scripts / pages past the joins' cap
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
        for exc in self._walk_errors if single else ():
            # (S08) a folder that could not be listed: its files were never seen. Only in the scan of one folder: a
            # PC-wide scan of several places meets folders no user may list by design (R2b-1 review) - as before
            where = getattr(exc, "filename", None) or "?"
            rel = (os.path.relpath(where, root) if root else where).replace(os.sep, "/")
            report.errors.append({"file": rel, "error": "%s: %s" % (type(exc).__name__, exc)})
            self._said_unread(report, on_findings, rel, "this folder could not be listed (%s): the files in it were "
                                                        "not inspected" % type(exc).__name__)
        self._walk_errors = []
        for done, path in enumerate(files, 1):
            if cancel is not None and cancel.is_set():
                report.cancelled = True
                break
            # several roots (quick / system scan): show full paths
            rel = (os.path.relpath(path, root) if root else path).replace(os.sep, "/")
            self._note_engine(rel.lower())
            ctx = found = None
            failed = False
            tick = self._ticker(progress, done - 1, report.files_total, rel)
            try:
                ctx = self._load(path, rel, tick)
                found = self._scan_ctx(ctx) if ctx is not None else None
            except Exception as exc:              # one bad file must not end the scan
                failed = True
                report.errors.append({"file": rel, "error": "%s: %s" % (type(exc).__name__, exc)})
                if ctx is None and UNREADABLE_SAID and single:
                    # (S08) the file could not even be opened: said (found stays None - the counters as before)
                    self._said_unread(report, on_findings, rel, "the file could not be opened (%s): it was not "
                                                                "inspected" % type(exc).__name__)
                if ctx is not None:
                    # The file was read but analysing it failed. Say so in the
                    # results: a file built to break the scanner must not come
                    # out looking clean.
                    found = [Finding(
                        rule_id="SCAN-ERR-001", title=SCAN_ERROR_TITLE,
                        category=Category.EVASION, severity=Severity.LOW, file=rel, line=None,
                        snippet=str(exc)[:200], evidence=type(exc).__name__, confidence=0.3,
                        reason=SCAN_ERROR_REASON, handler="scanner",
                        sha256=ctx.sha256, path=ctx.path, chainable=False)]
            # (B1) the errors of members that were said on the member, the container read on
            report.errors.extend(self._member_errors)
            self._member_errors = []
            if found is not None and ctx.pe is not None and not ctx.truncated:
                programs[rel.lower()] = rel       # a program that was read to its end
            if ctx is not None and (ctx.ext in _PACKAGE_EXTS or ctx.cache.get("containers")):
                self._packages.add(rel)
            try:
                report.bytes_total += ctx.size if ctx is not None else os.path.getsize(path)
            except OSError:
                pass
            if found is not None and ctx is not None and ctx.cache.get(SAID_UNREAD):
                # (S10) its one finding says it was not read: counted as not read, as before the note
                report.findings.extend(found)
                if on_findings:
                    on_findings(found)
                found = None
            elif found is None and lone and not failed and UNTAKEN_TARGET_SAID:
                # (S09) the one file of this scan, and no reader takes it
                try:
                    size = ctx.size if ctx is not None else os.path.getsize(path)
                except OSError:
                    size = 0
                if size > 0:
                    self._said_unread(report, on_findings, rel, UNTAKEN_EVIDENCE, ctx)
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
            self._join_cross(report.findings)
            self._join_decode_cross(report.findings)
            self._join_stored_code(report.findings)
            found = self._join_local(report.findings)
            if found and on_findings:
                on_findings(found)
            found = self._cap_notes(report.findings)   # (item 8; after every join)
            if found and on_findings:
                on_findings(found)
        self._app_cap = {}
        self._forget_local()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_exfil = []
        self._app_summaries = {}
        self._app_decode = {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        self._shared, self._shared_cut, self._importers = [], False, {}
        self._scripts = marshal_trace.Kept()
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
        self._fold_bytecode_notes(report.findings)
        self._finish(report.findings)
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

    def _join_stored_code(self, findings: List[Finding]) -> None:
        """``PY-OBF-003`` whose value is a parameter nothing in its file calls (phageo, 2026-10-31):
        the callers in the other scripts of the same game decide (``dataflow/marshal_trace.py``). It
        runs for a scan from memory too: an archive is a whole game, and the finding was CRITICAL
        before the split."""
        games: Dict[str, List[Finding]] = {}
        for f in findings:
            if f.context.get(marshal_trace.EDGES):
                games.setdefault(self._game_root(f.file), []).append(f)
        for game in sorted(games):
            files = [file for file in self._scripts.files if self._game_root(file) == game]
            marshal_trace.join(games[game], self._scripts, files)

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
            # (a note of a silent-escape fix, R2b-1, is not counted here: it may set the verdict, nothing else)
            unread = next((f for f in findings if f.rule_id in UNREAD_CONTENT and not f.suppressed
                           and not f.context.get(limits.SILENT_ESCAPE)
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
        # (an S12 note says only that a payload reading failed: the script was read to its end for the update)
        cut = {f.file for f in findings if f.rule_id == TRACER_CUT and not f.context.get(PAYLOAD_SAID)}
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
        findings.extend(self._addon_flows(findings, addons))
        findings.extend(stealer.chains(findings, self._app_stores, electron_windows.app_root))

    def _addon_flows(self, findings: List[Finding], addons: List[Finding]) -> List[Finding]:
        """C1 (``dataflow/exfil.py``): a script's flow from a call into a required module to a network call
        becomes ``CHAIN-EXFIL`` (CRITICAL, MALICE) when that module is a decrypting add-on of the same app
        (``ADDON-DECRYPT-001`` on it: what Windows keeps for the user, decrypted and sent out). The script
        must be the app's own code (verified files are not read for flows at all)."""
        if not (exfil.ON and self._app_exfil):
            return []
        out: List[Finding] = []
        seen = {(f.file, f.line) for f in findings if f.rule_id == exfil.RULE}
        for app, script, sha256, path, flow in self._app_exfil:
            module = flow.kind.partition(":")[2]
            for a in addons:
                if (electron_windows.app_root(a.file) or "") != app or not exfil.matches_addon(module, a.file):
                    continue
                if (script, flow.line) in seen:
                    break
                seen.add((script, flow.line))
                f = Finding(
                    rule_id=exfil.RULE, title="Private data sent out", category=Category.CREDENTIALS,
                    severity=Severity.CRITICAL, file=script, line=flow.line, snippet="",
                    evidence=exfil.evidence(flow._replace(kind=exfil.DECRYPTED), addon=a.file),
                    confidence=0.9, reason=exfil.REASON, handler="scanner", sha256=sha256, path=path,
                    chainable=False, context={"exfil_kind": exfil.DECRYPTED, "addon": a.file})
                out.append(f)
                break
        return out

    def _join_cross(self, findings: List[Finding]) -> None:
        """C1 part 2b (``dataflow/exfil_cross.py``): a private-data flow split over the files of one app -
        one script reads a store (or captures the screen / clipboard) and exports it, another imports that
        export and sends it out. Each becomes ``CHAIN-EXFIL`` on the sending script: CRITICAL (MALICE) for
        a store, HIGH (CHAIN) for a capture. A flow whose source and sink both lie inside verified files is
        MEDIUM, the libraries' own mechanism (rule 13's exception); a flow that crosses into or out of the
        app's own code keeps its tier (phageo, 2026-11-04: origin proves origin, not intent)."""
        if not (exfil.ON and exfil_cross.ON and self._app_summaries):
            return
        seen = {(f.file, f.line) for f in findings if f.rule_id == exfil.RULE}
        for app, scripts in self._app_summaries.items():
            info = {rel: triple for rel, triple in scripts.items()}
            for flow in exfil_cross.join([triple[0] for triple in info.values()]):
                if (flow.sink_file, flow.sink_line) in seen:
                    continue
                seen.add((flow.sink_file, flow.sink_line))
                store = flow.kind in exfil.STORE_KINDS
                sha256, path = info[flow.sink_file][1], info[flow.sink_file][2]
                context = {"exfil_kind": flow.kind, "cross_file": flow.source_file}
                if flow.both_verified:                     # the libraries' own mechanism: MEDIUM, tagged
                    severity = Severity.MEDIUM
                    context["library_mechanism"] = "a verified library"
                    reason = exfil.REASON + LIBRARY_RELEASE_MECHANISM
                else:
                    severity = Severity.CRITICAL if store else Severity.HIGH
                    reason = exfil.REASON
                findings.append(Finding(
                    rule_id=exfil.RULE, title="Private data sent out",
                    category=Category.CREDENTIALS if store else Category.INPUT_CAPTURE,
                    severity=severity, file=flow.sink_file, line=flow.sink_line, snippet="",
                    evidence=exfil_cross.evidence(flow), confidence=0.9, reason=reason,
                    handler="scanner", sha256=sha256, path=path, chainable=False, context=context))

    def _join_decode_cross(self, findings: List[Finding]) -> None:
        """C3 (``dataflow/decoderun.py``) across the files of one app, on C1 part 2b's module graph: one
        script decodes, decompresses or decrypts data and exports it, another imports that export and
        runs it as code. ``CHAIN-DECODE-RUN`` HIGH (CHAIN) on the running script; a flow whose two ends lie
        inside verified files is MEDIUM, the libraries' own mechanism (rule 13's exception). A sink line
        that already has the finding, or ``JS-OBF-001`` / ``DF-EXEC-001`` (HIGH or more), gets none."""
        if not (decoderun.ON and decoderun.CROSS_ON and self._app_decode):
            return
        proven = BaseHandler._DECODE_RUN_PROVEN
        seen = {(f.file, f.line) for f in findings if f.rule_id == decoderun.RULE or (
            f.rule_id in proven and not f.suppressed and f.severity >= Severity.HIGH)}
        for app, scripts in self._app_decode.items():
            for flow in decoderun.join([triple[0] for triple in scripts.values()]):
                if (flow.sink_file, flow.sink_line) in seen:
                    continue
                seen.add((flow.sink_file, flow.sink_line))
                sha256, path = scripts[flow.sink_file][1], scripts[flow.sink_file][2]
                context = {decoderun.KIND: flow.kind, "cross_file": flow.source_file}
                severity, reason = Severity.HIGH, decoderun.REASON
                if flow.both_verified:                     # the libraries' own mechanism: MEDIUM, tagged
                    severity = Severity.MEDIUM
                    context["library_mechanism"] = "a verified library"
                    reason += LIBRARY_RELEASE_MECHANISM
                findings.append(Finding(
                    rule_id=decoderun.RULE, title=decoderun.TITLE, category=Category.OBFUSCATION,
                    severity=severity, file=flow.sink_file, line=flow.sink_line, snippet="",
                    evidence=decoderun.cross_evidence(flow), confidence=0.85, reason=reason,
                    handler="scanner", sha256=sha256, path=path, chainable=False, context=context))

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
        # ENGINE-011 (2026-10-27, answer c): integrity records of matched Electron runtimes inside an
        # installer or archive, and the checksums of the app archives of the scan (place -> SHA-256)
        self._runtime_integrity: List[dict] = []
        self._asar_headers: Dict[str, str] = {}
        # ENGINE-010 / ENGINE-011 (sixth fix session, answer b): resource differences of matched Ren'Py
        # start programs (the other engines' are the program handler's own findings)
        self._runtime_changes: List[dict] = []
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
                or ctx.baseline.startswith(_SIGNED)):
            return
        if self._renpy_program(ctx):
            changes = ctx.cache.get(native_pe.RUNTIME_CHANGES) if ctx.cache.get(native_pe.RUNTIME_NAME) == "Ren'Py" else None
            if changes and len(self._runtime_changes) < _MAX_ENGINE_PROGRAMS:
                self._runtime_changes.append({"file": ctx.relpath, "path": ctx.path, "sha256": sha,
                                              "baseline": ctx.baseline, "handler": handler, "reasons": list(changes)})
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
    def _place(relpath: str) -> str:
        return relpath.replace("\\", "/").lower()

    def _note_runtime_integrity(self, ctx: FileContext, handler: str) -> None:
        """For ENGINE-011 (``_join_local``; phageo, 2026-10-27, answer c): the checksum of every app
        archive of the scan by its place, and the integrity rows of a matched Electron runtime whose
        app archive is another member of the same installer or archive (``native_pe._electron``)."""
        header = ctx.cache.get(ASAR_HEADER)
        if header and len(self._asar_headers) < _MAX_ENGINE_PROGRAMS:
            self._asar_headers[self._place(ctx.relpath)] = header
        rows = ctx.cache.get(native_pe.INTEGRITY_LATER)
        if rows and len(self._runtime_integrity) < _MAX_ENGINE_PROGRAMS:
            cut = max(ctx.relpath.rfind("/"), ctx.relpath.rfind("!")) + 1
            self._runtime_integrity.append({"file": ctx.relpath, "folder": ctx.relpath[:cut], "rows": list(rows),
                                            "path": ctx.path, "sha256": ctx.sha256, "baseline": ctx.baseline,
                                            "handler": handler})

    def _runtime_integrity_notes(self) -> List[Finding]:
        """ENGINE-011 (MEDIUM, visible): an integrity record of a matched Electron runtime inside an
        installer or archive whose checksum is not the one of the app archive it names in the same
        installer or archive (the program's folder there), or which names one the scan did not read.
        A record whose every checksum is that archive's adds nothing: the difference is proven."""
        out: List[Finding] = []
        for tag in self._runtime_integrity:
            for name, value in tag["rows"]:
                actual = self._asar_headers.get(self._place(tag["folder"] + name))
                if actual == value:
                    continue
                reason = ("the integrity record's checksum is not the one of the app archive" if actual else
                          "the integrity record names an app archive that is not at hand")
                f = native_pe.runtime_change(tag["file"], "%s (%s, in the same installer or archive)" % (reason, name),
                                             tag["handler"])
                f.sha256, f.path = tag["sha256"], tag["path"]
                ctx = FileContext(path=tag["path"], relpath=tag["file"], data=b"", size=0, sha256=tag["sha256"],
                                  baseline=tag["baseline"])
                self.context.evaluate_joined(f, ctx)
                out.append(f)
        return out

    def _runtime_change_notes(self) -> List[Finding]:
        """ENGINE-010 / ENGINE-011 (MEDIUM, visible; sixth fix session, answer b): one finding for each
        resource difference of a renamed Ren'Py start program whose code is the SDK program's, that the
        one resource rule does not allow (kept by ``_note_engine_program``)."""
        out: List[Finding] = []
        for tag in self._runtime_changes:
            for reason in tag["reasons"]:
                f = native_pe.runtime_change(tag["file"], reason, tag["handler"], "Ren'Py")
                f.sha256, f.path = tag["sha256"], tag["path"]
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
        the note stays. A program larger than what is loaded is not compared (the note stays).

        Since 2026-10-27 (phageo: one resource rule for every renamed engine program) the
        resources are judged per kind (``pe.resource_differences``): icons, icon groups and the
        version may differ, the manifest only without elevation, any other kind not; bytes beside
        the tree only as Ren'Py's own icon tool writes them (``launcher/game/change_icon.py`` of
        the SDKs: a ``P`` before a resource's data, and up to Ren'Py 7.3.5 the word ``RENPYVNE``
        repeated up to the section's alignment). A program without a record in
        ``program_resources`` keeps the kinds rule above."""
        pe = ctx.pe
        if (pe is None or pe.is_dotnet or ctx.truncated or pe.has_signature or pe.overlay_size
                or pe.entry_point not in engine_hashes.RENPY_PROGRAM_ENTRY_POINTS):
            return None
        key = resource_frame_key(ctx.data, pe)
        official = engine_hashes.verified_renpy_program(key)
        kinds = resource_kinds(ctx.data, pe) if official else None
        if not kinds or program_inside(resources_of(ctx.data, pe)):
            return None
        record = program_resources.record("RENPY", key)
        if record is None:
            return official if set(kinds) <= engine_hashes.RENPY_PROGRAM_KINDS else None
        version = engine_hashes.ARCHIVES[engine_hashes.RENPY_PROGRAMS[key][1]][1]
        reasons = resource_differences(ctx.data, pe, record, renpy_padding=True,
                                       renpy_tail=_version_tuple(version) <= RENPY_PADDED_UNTIL)
        if reasons:
            # the decision in two (phageo, sixth fix session, answer b - one rule for every renamed
            # engine): the code is the SDK program's, the match stands; each such difference is a
            # visible ENGINE-010 / ENGINE-011 finding (_runtime_change_notes)
            ctx.cache[native_pe.RUNTIME_CHANGES], ctx.cache[native_pe.RUNTIME_NAME] = reasons, "Ren'Py"
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
        new += self._runtime_integrity_notes()
        new += self._runtime_change_notes()
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
        staticonly.check_scanner(self)
        ctx = FileContext(path=path or relpath, relpath=relpath.replace("\\", "/"),
                          data=data, size=len(data), sha256=hashlib.sha256(data).hexdigest())
        self._match_everything = bool(len(self.rules.yara)) or (
            self.signatures is not None and self.signatures.count() > 0)
        self._shared, self._shared_cut, self._importers = [], False, {}    # one file: nothing to join it with
        self._member_errors = []                 # (B1; no report here: the SCAN-ERR-001 note says it)
        self._scripts = marshal_trace.Kept()
        self._managed, self._managed_cut = [], False
        self._origin_of = {}
        self._app_cap = {}
        self._forget_local()
        localdrop.begin()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_exfil = []
        self._app_summaries = {}
        self._app_decode = {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        found = self._scan_ctx(ctx)
        if found is None and data and UNTAKEN_TARGET_SAID:
            # (S09) no reader takes it: said, never CLEAN
            found = [self._unread_note(ctx.relpath, UNTAKEN_EVIDENCE, ctx)]
            self.context.evaluate(found[0], ctx)
        found = found or []
        self._join_windows(found)          # (an installer or archive holds a whole app)
        self._join_updates(found)
        self._join_addons(found)
        self._join_cross(found)
        self._join_decode_cross(found)
        self._join_stored_code(found)
        self._join_local(found)
        self._cap_notes(found)             # (item 8; after every join)
        self._fold_bytecode_notes(found)
        self._forget_local()
        self._scripts = marshal_trace.Kept()
        self._app_scripts, self._app_versions, self._app_files, self._app_kept = {}, {}, {}, 0
        self._app_libraries, self._app_pages, self._app_stores = {}, {}, {}
        self._app_exfil = []
        self._app_summaries = {}
        self._app_decode = {}
        self._app_texts, self._app_cut, self._app_ipc, self._app_kept_text = {}, {}, {}, 0
        self._finish(found)
        return found

    def _finish(self, findings: List[Finding]) -> None:
        """The last step of every scan (``scan`` and ``scan_bytes``), after every chain and join: where
        each finding stands (gamescan/origin.py; information only), then the tier cap - the one place
        where a rule's level is capped by what it proves (gamescan/tiers.py; phase B, 2026-11-02)."""
        origin.stamp(findings, self._origin_of)
        self._origin_of = {}
        exfil.prove_stealers(findings, electron_windows.app_root)   # (C1: a proven flow -> MALICE)
        tiers.cap(findings)

    # -- internals -------------------------------------------------------------
    @staticmethod
    def _unread_note(file: str, evidence: str, ctx: Optional[FileContext] = None) -> Finding:
        """(R2b-1) ``ARC-002`` made by the scanner itself: content that was not read (rule 15: at least REVIEW).
        Marked as a note of a silent-escape fix (``limits.SILENT_ESCAPE``)."""
        return limits.mark(Finding(
            rule_id="ARC-002", title="Archive could not be fully inspected", category=Category.EVASION,
            severity=Severity.LOW, file=file, line=None, snippet="", confidence=0.3, handler="scanner",
            evidence=evidence, reason=NOT_INSPECTED, sha256=ctx.sha256 if ctx is not None else "",
            path=ctx.path if ctx is not None else "", chainable=False))

    def _said_unread(self, report: ScanReport, on_findings: Optional[FindingsFn], file: str, evidence: str,
                     ctx: Optional[FileContext] = None) -> None:
        """(S08 / S09) An ``ARC-002`` straight into the report, for a file or folder no reading came to. With the
        file's ``ctx`` it is judged like any note (the user's own allowlist); without, what past marks say."""
        note = self._unread_note(file, evidence, ctx)
        if ctx is not None:
            self.context.evaluate(note, ctx)
        else:
            self.context.remember(note)
        report.findings.append(note)
        if on_findings:
            on_findings([note])

    def _note_cap(self, relpath: str) -> None:
        """(item 8) A script or page of an Electron app that the window joins do not keep (the scan's cap)."""
        cap = self.__dict__.setdefault("_app_cap", {})
        root = electron_windows.app_root(relpath) or ""
        cap[root] = cap.get(root, 0) + 1

    def _cap_notes(self, findings: List[Finding]) -> List[Finding]:
        """(item 8) One information note per app whose scripts or pages passed the joins' cap - made after every
        join, so it changes nothing they decide. Appended to ``findings``; the new notes are returned."""
        cap, self._app_cap = self.__dict__.get("_app_cap") or {}, {}
        out = []
        for root in sorted(cap):
            note = Finding(rule_id=TRACER_CUT, title="App's windows judged from part of its scripts",
                           category=Category.OBFUSCATION, severity=Severity.LOW, file=root or ".", line=None,
                           snippet="", confidence=0.3, handler="scanner",
                           evidence=SCRIPT_CAP_EVIDENCE % (electron_windows.MAX_SCRIPTS, cap[root]),
                           reason="This app holds more scripts than the scanner joins to judge its windows and "
                                  "pages. Each script was read by the ordinary rules; only the picture of which "
                                  "window shows which page is incomplete. Information only: it sets no level.",
                           chainable=False, information=True)
            note.context[SCRIPT_CAP_NOTE] = True     # (its own texts: i18n._key)
            out.append(limits.mark(note))
        findings.extend(out)
        return out

    @staticmethod
    def _fold_bytecode_notes(findings: List[Finding]) -> None:
        """(S04, R2b-2) One note per folder / archive for the active S04 notes of a scan (``findings`` changed in
        place): the first one of each place stays and names how many files there were; places with one file keep
        their note as it is. Notes a user's own mark has hidden are left as they are."""
        if not BYTECODE_NOTES_FOLDED:
            return
        from .handlers.renpy import UNREAD_BYTECODE
        places: Dict[str, List[Finding]] = {}
        for f in findings:
            if f.rule_id == "ARC-002" and UNREAD_BYTECODE in f.context and not f.suppressed:
                name = f.file.replace("\\", "/")
                place = name.rsplit("!", 1)[0] if "!" in name else (posixpath.dirname(name) or ".")
                places.setdefault(place, []).append(f)
        dropped = set()
        for place, notes in places.items():
            if len(notes) < 2:
                continue
            names = [posixpath.basename(n.file.replace("\\", "/").rsplit("!", 1)[-1]) for n in notes]
            shown = ", ".join(names[:5]) + (" and %d more" % (len(names) - 5) if len(names) > 5 else "")
            first = notes[0]
            first.evidence = BYTECODE_FOLDED % (len(notes), sum(int(n.context[UNREAD_BYTECODE]) for n in notes),
                                                place, shown)
            dropped.update(id(n) for n in notes[1:])
        if dropped:
            findings[:] = [f for f in findings if id(f) not in dropped]

    def _walk(self, root: str, cancel: Optional[threading.Event] = None) -> List[str]:
        out = []
        skip = os.path.normcase(self.quarantine.directory) if self.quarantine else None
        errors = self.__dict__.setdefault("_walk_errors", [])
        for base, dirs, names in os.walk(root, onerror=errors.append if UNREADABLE_SAID else None):
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
        only_s10 = False
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
                    if not (NOT_A_PROGRAM_SAID and ext in _PROGRAM_ENDINGS):
                        return None
                    only_s10 = True                 # (S10: loaded only to be said - nothing else is done with it)
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
        ctx = FileContext(path=path, relpath=rel, data=data, size=size,
                          sha256=digest.hexdigest(), truncated=size > len(data),
                          cancel=self._cancel, progress=tick if size > _LARGE else None)
        if only_s10:
            ctx.cache[S10_LOADED] = True
        return ctx

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
        # (R2b-1) the notes of the silent-escape fixes come after, and never take the place of, the notes of before:
        # the limits of before are said exactly as before, as if no such note existed; then those of the fixes
        mine = [f for f in findings if f.file == ctx.relpath]
        said = {f.rule_id for f in mine if not f.context.get(limits.SILENT_ESCAPE)}
        out: List[Finding] = []
        for reader, what in reached:
            rule, title = limits.RULES[reader]
            if isinstance(what, limits.SaidNote) or rule in said or len(out) >= 3:
                continue
            said.add(rule)
            out.append(self._limit_note(ctx, rule, title, what))
        said |= {f.rule_id for f in mine}
        for reader, what in reached:
            rule, title = limits.RULES[reader]
            if isinstance(what, limits.SaidNote) and rule not in said:
                said.add(rule)
                out.append(limits.mark(self._limit_note(ctx, rule, title, what)))
        return out

    def _limit_note(self, ctx: FileContext, rule: str, title: str, what: str) -> Finding:
        note = Finding(rule_id=rule, title=title, category=Category.EVASION, severity=Severity.LOW,
                       file=ctx.relpath, line=None, snippet="", confidence=0.3, handler="scanner",
                       evidence="a limit of the reader was reached: %s" % what[:200],
                       reason=limits.REASON, sha256=ctx.sha256, path=ctx.path, chainable=False)
        self.context.evaluate(note, ctx)
        return note

    def _scan_error(self, ctx: FileContext, exc: BaseException, where: str = "") -> Finding:
        """(B1) ``SCAN-ERR-001`` on a member whose reading raised ``exc`` - or, with ``where``, on a container whose
        member list stopped - and the same line in the report's errors (``fp_benchmark``'s ``errors`` column)."""
        text = "%s%s" % (where, exc)
        self._member_errors.append({"file": ctx.relpath, "error": "%s: %s" % (type(exc).__name__, text)})
        return Finding(rule_id="SCAN-ERR-001", title=SCAN_ERROR_TITLE, category=Category.EVASION,
                       severity=Severity.LOW, file=ctx.relpath, line=None, snippet=text[:200],
                       evidence=type(exc).__name__, confidence=0.3, reason=SCAN_ERROR_REASON, handler="scanner",
                       sha256=ctx.sha256, path=ctx.path, chainable=False)

    def _members_said(self, ctx: FileContext, sources, findings: List[Finding]) -> Iterator[FileContext]:
        """(B1) The members of ``ctx`` from each of ``sources`` in turn. When a source raises between two members
        (its reader failed), that is said on ``ctx`` (:meth:`_scan_error`, into ``findings``) and the next source
        is read: what was found so far is kept. Only ``Exception``: the runners' guards (``BaseException``) pass."""
        for source in sources:
            members = iter(source)
            while True:
                try:
                    child = next(members)
                except StopIteration:
                    break
                except MemoryError:
                    raise                           # (as before: the runners say "not enough memory")
                except Exception as exc:
                    findings.append(self._scan_error(ctx, exc, MEMBER_LIST_ERROR))
                    break
                yield child

    def _holds_members(self, ctx: FileContext, handler) -> bool:
        """(S03) Does ``ctx`` - a file at the nesting limit, which is not opened - hold members? Each of its member
        sources is asked for its **first** member only; that member is let go unscanned, the source is closed, and
        nothing it offered on the way is kept (``localdrop.paused``). A source that fails counts as holding
        something (its reader did not get through it), and so does a container with no member a reader takes that
        has something to say of its own (``after_expand``). ``MemoryError`` and the runners' guards pass."""
        if (self._cancel is not None and self._cancel.is_set()) or self._expanded > _MAX_EXPANDED:
            return False                           # (the unpacked-size guard of the scan holds for the look too)
        held = False
        # (R2b-1 review) the look says nothing of its own: a reader limit reached while it looks is no limit of this
        # file's reading (limits.quiet), and what it unpacks counts toward the scan's unpacked-size guard
        with localdrop.paused(), limits.quiet():
            sources = [handler.expand]
            if ctx.pe is not None:
                sources.append(sigblock.children)
            for make in sources:
                members = None
                try:
                    members = iter(make(ctx))
                    first = next(members, None)
                except MemoryError:
                    raise
                except Exception:
                    first, held = None, True
                if first is not None:
                    held = True
                    self._expanded += first.size
                    containers.release(first)
                close = getattr(members, "close", None)
                if close is not None:
                    try:
                        close()
                    except MemoryError:
                        raise
                    except Exception:             # (as in the member loop: an error while it is let go is not raised)
                        pass
                if held:
                    break
            if not held:
                # no member a reader would take - but perhaps something the container itself would have said
                # (a member of a kind nobody reads, a part that could not be unpacked): that counts too
                try:
                    held = bool(handler.after_expand(ctx))
                except MemoryError:
                    raise
                except Exception:
                    held = True
        return held

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
        if ctx.cache.get(S10_LOADED):
            # (S10) a file on disk that was loaded only to be said: nothing else is done with it (no engine, app or
            # local-drop note sees it - as before, when it was not loaded); no reader takes it (_load: neither its
            # name, nor its first bytes, nor text)
            ctx.cache[SAID_UNREAD] = True
            if ctx.size <= 0 or bytes(ctx.data[:4]).startswith(_OTHER_SYSTEMS) or official.exact(ctx.sha256):
                return None
            note = self._unread_note(ctx.relpath, NOT_A_PROGRAM_EVIDENCE % ctx.ext, ctx)
            self.context.evaluate(note, ctx)
            return [note]
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
        not_a_program = handler is None and NOT_A_PROGRAM_SAID and ctx.size > 0 and ctx.ext in _PROGRAM_ENDINGS \
            and not bytes(ctx.data[:4]).startswith(_OTHER_SYSTEMS) and not official.exact(ctx.sha256)
        if handler is None and not self._match_everything and not known:
            if not_a_program:
                # (S10) named like a Windows program, and no reader takes it: said. A file of the scan itself still
                # counts as not read, as before the note (SAID_UNREAD; R2b-1 review, round 2)
                note = self._unread_note(ctx.relpath, NOT_A_PROGRAM_EVIDENCE % ctx.ext, ctx)
                self.context.evaluate(note, ctx)
                if depth == 0:
                    ctx.cache[SAID_UNREAD] = True
                return [note]
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
        if not_a_program:                              # (S10, when signatures read every file: said all the same)
            findings.append(self._unread_note(ctx.relpath, NOT_A_PROGRAM_EVIDENCE % ctx.ext, ctx))
        # where this file stands, from what the scan knows of it now (gamescan/origin.py; information only)
        self.__dict__.setdefault("_origin_of", {})[ctx.relpath] = origin.of_file(ctx, _SIGNED)
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
        script = ctx.cache.pop(marshal_trace.TEXT, None)
        if script is not None:                         # (held here, not with the file's notes)
            self._scripts.add(ctx.relpath, script, ctx.ext in handler.store_scripts)
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
        elif script is not None and SCRIPT_CAP_SAID:   # (item 8) not kept: counted for the app's note
            self._note_cap(ctx.relpath)
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
        flows = ctx.cache.get(exfil.CACHE)             # (C1: a module's result sent out - joined in _join_addons)
        if flows and handler is not None:
            app = electron_windows.app_root(ctx.relpath) or ""
            for flow in flows:
                if len(self._app_exfil) < exfil.MAX_KEPT:
                    self._app_exfil.append((app, ctx.relpath, ctx.sha256, ctx.path, flow))
        summary = ctx.cache.get(exfil.SUMMARY)         # (C1 part 2b: joined across files in _join_cross)
        if summary is not None and handler is not None and electron_windows.app_root(ctx.relpath) is not None:
            app = electron_windows.app_root(ctx.relpath)
            scripts = self._app_summaries.setdefault(app, {})
            if len(scripts) < exfil_cross.MAX_SCRIPTS:
                exports, sink_imports, verified = summary
                scripts[ctx.relpath] = (exfil_cross.Summary(ctx.relpath, exports, sink_imports, verified),
                                        ctx.sha256, ctx.path)
        summary = ctx.cache.get(decoderun.SUMMARY)     # (C3: joined across files in _join_decode_cross)
        if summary is not None and handler is not None and electron_windows.app_root(ctx.relpath) is not None:
            scripts = self._app_decode.setdefault(electron_windows.app_root(ctx.relpath), {})
            if len(scripts) < exfil_cross.MAX_SCRIPTS:
                exports, sink_imports, verified = summary
                scripts[ctx.relpath] = (exfil_cross.Summary(ctx.relpath, exports, sink_imports, verified),
                                        ctx.sha256, ctx.path)
        loaded = ctx.cache.get("page_scripts")
        if loaded is not None and len(self._app_pages) < electron_windows.MAX_SCRIPTS:
            self._app_pages[ctx.relpath] = loaded      # ... and the scripts a page of it loads
        elif loaded is not None and SCRIPT_CAP_SAID:
            self._note_cap(ctx.relpath)
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
        self._note_runtime_integrity(ctx, name)    # (ENGINE-011, integrity inside an archive: _join_local)
        if ctx.is_pe and depth == 0:
            self._executables.append({"file": ctx.relpath, "path": ctx.path,
                                      "sha256": ctx.sha256, "baseline": bool(ctx.baseline)})
        if handler and depth < _MAX_DEPTH:
            sources = [handler.expand(ctx), sigblock.children(ctx) if ctx.pe is not None else ()]
            members = self._members_said(ctx, sources, findings) if MEMBER_ERRORS_ISOLATED \
                else itertools.chain(*sources)
            for child in members:
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
                except Exception as exc:
                    if not MEMBER_ERRORS_ISOLATED or isinstance(exc, MemoryError):
                        raise
                    # (B1) this member could not be read: said on it; the container's other members are read
                    findings.append(self._scan_error(child, exc))
                finally:
                    containers.release(child)             # the temporary file of a large member
            # (R2 review) the member generators end here, before after_expand, as the unnamed iterator of before did
            # at a break: what a reader says in its ``finally`` (Ren'Py's unread .rpa members) reaches the notes
            for iterator in [members] + sources:
                close = getattr(iterator, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception:             # (as before: an error while a generator was let go was not raised)
                        pass
            for f in handler.after_expand(ctx):
                f.handler, f.sha256, f.path = name, ctx.sha256, ctx.path
                self.context.evaluate(f, ctx)
                findings.append(f)
        elif handler is not None and DEPTH_NOTE and self._holds_members(ctx, handler):
            # (S03) too deep to be opened, and it holds something: said
            note = Finding(
                rule_id="ARC-002", title="Archive could not be fully inspected", category=Category.EVASION,
                severity=Severity.LOW, file=ctx.relpath, line=None, snippet="", confidence=0.3, handler=name,
                evidence=DEPTH_EVIDENCE % _MAX_DEPTH, reason=NOT_INSPECTED,
                sha256=ctx.sha256, path=ctx.path, chainable=False)
            findings.append(limits.mark(note))     # (made like the unpacked-size note above)
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
        if models.STATIC_ONLY:                   # (check_scanner refused one already given)
            return None
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
                if reputation.CLEAN_HIDES_WEAK:      # (off since 2026-11-10: evidence, not proof)
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
            if reputation.CLEAN_SPARES_QUARANTINE and found[0].sha256 in clean and worst < Severity.CRITICAL:
                # (off since 2026-11-15, phageo: a clean VirusTotal result keeps no file out of quarantine)
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
