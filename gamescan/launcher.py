"""Secure launcher: scan a game, then start it, ask first, or refuse.

``gamescan --launch <executable> [-- arguments for the game]``

1. The executable's folder - the game - is scanned, sub-folders included,
   with the scanner the false-positive benchmark uses
   (:func:`gamescan.scanner.neutral_scanner`): no learning and no history
   (memory center off), no allowlist, no quarantine, no network look-ups.
   Temporary files are used as in an ordinary scan (large archive members,
   signature checks of programs inside archives), but in a folder made for
   this scan only, which is removed when the scan ends - also when it fails.
2. What happens next follows from the report (:func:`decide`):

   ========================  ===============================================
   CLEAN, LIKELY SAFE        the game is started
   REVIEW                    the findings are shown; one confirmation
   could not be inspected    the same: a part nobody looked at is not "clean"
   SUSPICIOUS                the main reasons are shown; the word ``launch``
                             has to be typed
   blocked without asking    any CRITICAL finding (so every DANGEROUS game),
                             an attack chain seen in a script, a known-malware
                             hash, a detection by Windows' own engine, a
                             program posing as an engine component
   ========================  ===============================================

   An attack chain inside a *program* rests on its import table - on what the
   program can do - so it is asked about, not blocked. So is a download-and-run
   chain in an engine script of a Ren'Py version whose official files are not
   in the scanner's table (HIGH): the typed word is needed, and the prompt
   says in its own words what was found and that the file could not be
   verified. The answer to every
   question defaults to "no", and when nobody is there to answer (no
   interactive terminal) the game is not started.
3. Just before starting, the executable is hashed again and compared with
   the hash taken before the scan, so that a file swapped in between is not
   run. It is started directly (no shell), with the game folder as working
   directory.

What this does not do: watch the game after it has started, or notice a
*data* file that is replaced between the scan and the moment the game reads
it. It is a gate, not a sandbox.

Exit codes: 0 = started; 1 = not started, MEDIUM findings; 2 = not started,
HIGH / CRITICAL findings or a finding that always blocks; 3 = not started for
another reason (scan incomplete, file changed, cannot be started).
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from typing import Callable, List, NamedTuple, Optional, Sequence

from . import cache, i18n
from .i18n import t
from .models import Category, Finding, ScanReport, Severity
from .unpack import spool

POPEN = subprocess.Popen                         # how the game is started
START, CONFIRM, TYPE_WORD, BLOCK = "start", "ask", "ask-word", "block"
# findings that mean "part of the game was not looked at" (CLAUDE.md, rule 15): a game is
# not started without a question on the strength of a scan that did not see all of it
NOT_INSPECTED = frozenset({"ARC-001", "ARC-002", "UNITY-FMT-001", "RPY-FMT-001", "RGSS-FMT-001",
                           "RGSS-FMT-002", "DN-META-001", "IL2CPP-META-001", "SCAN-ERR-001",
                           "PYO-FMT-001", "PY-JOIN-001", "INNO-CODE-001", "DN-IL-001",
                           "SCRIPT-LIMIT-001", "ENC-SCRIPT-001", "SCAN-COVERAGE-001",
                           "JSC-FMT-001", "EXEC-FMT-001", "RPY-CONTENT-001"})
# stop a launch whatever their severity: this exact file is known malware, or Windows'
# own engine detects it
ALWAYS_BLOCKED = frozenset({"SIG-001", "SIG-EICAR", "AMSI-001", "DEFENDER-001"})
FAKE_ENGINE_FILE = "ENGINE-001"                  # blocks when it is about a program (see _blocks)
UNVERIFIED_ENGINE = "engine_unverified"          # mark on a chain in an engine file of an unlisted version
WORDS = ("launch", "başlat", "baslat")           # what has to be typed for a SUSPICIOUS game
YES = ("y", "yes", "e", "evet")


class Decision(NamedTuple):
    action: str                  # START, CONFIRM, TYPE_WORD or BLOCK
    findings: List[Finding]      # what the decision rests on, worst first
    unseen: List[str]            # what was not inspected (empty: everything was)
    cancelled: bool = False


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _blocks(f: Finding) -> bool:
    if f.severity is Severity.CRITICAL or f.rule_id in ALWAYS_BLOCKED:
        return True
    # a program that poses as an engine component (MEDIUM). On a script the same rule is a
    # LOW note - a game that rewrote one of the engine's default scripts, which many do -
    # and the script is scanned like any other file: that goes by the verdict
    if f.rule_id == FAKE_ENGINE_FILE and f.severity >= Severity.MEDIUM:
        return True
    # a chain in a script: the calls were seen. In a program it is what the import table
    # allows - some games install a keyboard hook to switch off the Windows key.
    # A download-and-run chain in an engine script of a Ren'Py version that cannot be
    # compared (HIGH) is asked about too, with the typed word: the official updater has
    # that chain, and refusing it would refuse every game on an unlisted version
    return (f.category is Category.CHAIN and f.severity >= Severity.HIGH
            and not f.context.get("program") and not f.context.get(UNVERIFIED_ENGINE))


def _worst_first(findings) -> List[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, -f.confidence, f.file))


def blocking(report: ScanReport) -> List[Finding]:
    """The findings that stop a launch without a question, worst first."""
    return _worst_first(f for f in report.active if _blocks(f))


def decide(report: ScanReport) -> Decision:
    """What the launcher does with a scanned game (see the module text)."""
    active = report.active
    unseen = ["%s: %s" % (f.file, f.evidence) for f in active if f.rule_id in NOT_INSPECTED]
    unseen += ["%s: %s" % (e.get("file", "?"), e.get("error", "?")) for e in report.errors]
    stoppers = blocking(report)
    if stoppers or report.cancelled:
        return Decision(BLOCK, stoppers, unseen, report.cancelled)
    worst = report.max_severity
    if worst is not None and worst >= Severity.HIGH:           # SUSPICIOUS
        return Decision(TYPE_WORD, _worst_first(f for f in active if f.severity >= Severity.HIGH),
                        unseen)
    if worst is Severity.MEDIUM or unseen:                     # REVIEW, or not all of it was seen
        return Decision(CONFIRM, _worst_first(f for f in active if f.severity >= Severity.MEDIUM),
                        unseen)
    return Decision(START, [], unseen)


def scan_folder(scanner, folder: str, cancel=None, progress=None) -> ScanReport:
    """The launcher's scan of a game folder: temporary files go into a folder
    made for this scan, which is gone afterwards - also when the scan fails.
    (The benchmark repeats exactly this to check that both find the same.)
    The cache of unpacked and parsed files is never used here (``gamescan/cache.py``):
    a scan that decides whether a game is started rests on nothing in the profile.
    ``cancel`` / ``progress`` (the window's) only stop the scan or report how far it is."""
    extra = {k: v for k, v in (("cancel", cancel), ("progress", progress)) if v is not None}
    with spool.private_folder(), cache.suspended():
        return scanner.scan(folder, **extra)


# what a program carries that makes it an installer or a self-extracting archive (the kinds of
# ``handlers.containers.detect``); a zip behind a program is how NW.js / LÖVE games pack themselves
STANDALONE_KINDS = frozenset({"inno", "nsis", "7z", "rar", "cab"})
AS_IS, GAME_FOLDER, STANDALONE = "as-is", "game-folder", "standalone"


def scan_target(path: str, max_bytes: int = 64 * 1024 * 1024) -> tuple:
    """``(what to scan, why)`` for the right-click "Scan" (0.9-beta final polish, phageo
    2026-10-25): a program (``.exe``) stands for its game, so its folder is scanned - the folder
    :func:`secure_launch` scans (``GAME_FOLDER``) - unless it is an installer or a self-extracting
    archive on its own, a file that is not a Windows program, or stands at the top of a drive:
    then the file itself (``STANDALONE``). Anything else is scanned as it is (``AS_IS``)."""
    path = os.path.abspath(path)
    if not os.path.isfile(path) or not path.lower().endswith(".exe"):
        return path, AS_IS
    folder = os.path.dirname(path)
    if os.path.dirname(folder) == folder:
        return path, STANDALONE
    from .handlers import containers
    from .models import FileContext
    from .pe import parse_pe
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
            size = fh.seek(0, 2)
    except OSError:
        return path, AS_IS
    info = parse_pe(data) if data[:2] == b"MZ" else None
    if info is None:
        return path, STANDALONE
    ctx = FileContext(path=path, relpath=os.path.basename(path), data=data, size=size, pe=info,
                      truncated=size > len(data))
    try:
        kinds = {kind for kind, _offset, _size in containers.detect(ctx)}
    except Exception:                    # (a reading error: the file is scanned whole anyway)
        kinds = set()
    return (path, STANDALONE) if kinds & STANDALONE_KINDS else (folder, GAME_FOLDER)


def launch_scanner(cfg: dict, yara: Optional[str] = None, strict: bool = False,
                   amsi: bool = True, factory=None):
    """The launcher's scanner, for the command line and the window alike: the benchmark's
    (``factory`` = ``scanner.neutral_scanner``: no memory center, no allowlist, no network);
    YARA rules, the known-malware hashes (if they were downloaded before - the database is
    not created for the occasion) and the Windows antimalware engine can only add findings."""
    from .rules import RuleEngine
    from .scanner import neutral_scanner
    from .signatures import SignatureDatabase
    rules = RuleEngine()
    if yara and os.path.exists(yara):
        rules.load_yara(yara)
    known = os.path.join(os.path.expanduser("~"), ".game_safety_scanner", "signatures.db")
    return (factory or neutral_scanner)(
        strict=strict, rules=rules,
        signatures=SignatureDatabase(known) if os.path.isfile(known) else None,
        amsi=amsi and bool(cfg.get("amsi_enabled", True)))


def word_prompt() -> str:
    """The prompt of a question that needs the typed word (a SUSPICIOUS game)."""
    return t("To start the game anyway, type the word %s and press Enter. "
             "Anything else means no: ", t("launch"))


def console_ask(prompt: str) -> Optional[str]:
    """The user's answer, or None when nobody is there to give one."""
    try:
        if sys.stdin is None or not sys.stdin.isatty():
            return None
        return input(prompt)
    except (EOFError, KeyboardInterrupt, OSError, ValueError):
        return None


ASK = console_ask                                # who answers the launcher's questions


def _reasons(findings: List[Finding], limit: int = 3) -> List[Finding]:
    """The most important findings, one per rule."""
    out, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            out.append(f)
    return out[:limit]


def _question(name: str, decision: Decision, out: Callable[[str], None]) -> str:
    """Print why the launcher asks; returns the prompt."""
    out("")
    if decision.action == TYPE_WORD:
        out(t("WARNING  : high-risk behaviour was found in the folder of %s. This can be a "
              "false alarm, but it is what harmful programs do too. The main reasons:", name))
        # said first and in its own words, whatever else was found
        unverified = [f for f in decision.findings if f.context.get(UNVERIFIED_ENGINE)]
        for f in unverified[:3]:
            out("  - %s  (%s)" % (t("A download-and-run chain was found in an engine file that "
                                    "could not be verified"), f.file))
            out("      %s" % t("This file belongs to the game's engine (Ren'Py). It downloads "
                               "something and runs it. The engine's official updater does that "
                               "too, but this copy of the engine is a version the scanner has no "
                               "official files for, so nobody checked that the file is the "
                               "genuine one."))
        for f in _reasons([f for f in decision.findings if f not in unverified]):
            out("  - %s  (%s)" % (i18n.title(f), f.file))
            out("      %s" % i18n.reason(f))
    elif decision.findings:
        out(t("QUESTION : the scan found something in the folder of %s that deserves a look:", name))
        for f in _reasons(decision.findings, 5):
            out("  - %s  (%s)" % (i18n.title(f), f.file))
    if decision.unseen:
        out(t("NOT SEEN : %d part(s) of the game could not be inspected, so nobody knows what is "
              "inside. For example: %s", len(decision.unseen), decision.unseen[0]))
    if decision.action == TYPE_WORD:
        return word_prompt()
    return t("Start the game anyway? Type y for yes. Anything else means no [y/N]: ")


_LABEL = re.compile(r"^(\w+(?: \w+)?) +: ", re.MULTILINE)


def dialog_text(text: str) -> str:
    """The launcher's lines for a window: the labels are padded for a terminal's even letters
    ("SORU     : ..."), which a window's font shows as a gap - there they read "SORU: ..."
    (0.9-beta final polish, phageo 2026-10-25)."""
    return _LABEL.sub(lambda m: m.group(1) + ": " if m.group(1).isupper() else m.group(0), text)


def _confirmed(decision: Decision, answer: str) -> bool:
    answer = answer.strip().lower()
    return answer in (WORDS if decision.action == TYPE_WORD else YES)


def _code(report: ScanReport) -> int:
    worst = report.max_severity
    if worst is not None and worst >= Severity.HIGH:
        return 2
    return 1 if worst is Severity.MEDIUM else 3


def secure_launch(executable: str, scanner, arguments: Sequence[str] = (),
                  show: Optional[Callable[[ScanReport], None]] = None,
                  popen: Optional[Callable[..., object]] = None,
                  out: Callable[[str], None] = print,
                  ask: Optional[Callable[[str], Optional[str]]] = None,
                  cancel=None, progress=None) -> int:
    """Scan ``executable``'s folder with ``scanner`` and start the game if the
    result - and, where one is needed, the user's answer - allows it. ``ask``
    gets the prompt and returns the answer, or None when nobody can answer.
    (The window passes its own ``out`` / ``ask`` - dialogs - and ``cancel`` /
    ``progress``; the decision is the same.)
    Returns the exit code described in the module text."""
    path = os.path.abspath(executable)
    if not os.path.isfile(path):
        out(t("launch: not a file: %s", path))
        return 3
    folder, name = os.path.dirname(path), os.path.basename(path)
    if os.path.dirname(folder) == folder:
        out(t("launch: refusing to scan a whole drive as a game folder: %s", folder))
        return 3
    try:
        before = _sha256(path)
    except OSError as exc:
        out(t("launch: cannot read %s (%s)", path, exc))
        return 3
    report = scan_folder(scanner, folder, cancel, progress)
    if show is not None:
        show(report)
    decision = decide(report)
    if decision.cancelled:
        out("")
        out(t("BLOCKED  : %s was NOT started - the scan did not complete (%s)", name, t("cancelled")))
        return 3
    if decision.action == BLOCK:
        out("")
        out(t("BLOCKED  : %s was NOT started - %d finding(s) that always stop a launch:",
              name, len(decision.findings)))
        for f in decision.findings[:10]:
            out("  [%-8s] %s  %s  (%s)" % (i18n.severity(f.severity), f.rule_id, i18n.title(f), f.file))
        if len(decision.findings) > 10:
            out(t("  ... and %d more", len(decision.findings) - 10))
        return 2
    confirmed = False
    if decision.action != START:
        answer = (ask or ASK)(_question(name, decision, out))
        if answer is None:
            out("")
            out(t("BLOCKED  : %s was NOT started - this needs a confirmation and nobody is there "
                  "to give one (not an interactive terminal)", name))
            return _code(report)
        if not _confirmed(decision, answer):
            out("")
            out(t("BLOCKED  : %s was NOT started - not confirmed", name))
            return _code(report)
        confirmed = True
    try:
        after = _sha256(path)
    except OSError:
        after = ""
    if after != before:
        out("")
        out(t("BLOCKED  : %s changed while it was being scanned - not started", name))
        return 3
    try:
        process = (popen or POPEN)([path] + list(arguments), cwd=folder, close_fds=True)
    except OSError as exc:
        out(t("launch: %s could not be started (%s)", path, exc))
        return 3
    out("")
    pid = getattr(process, "pid", "?")
    if confirmed:
        out(t("LAUNCHED : %s (process %s) - started because you confirmed it", name, pid))
    else:
        out(t("LAUNCHED : %s (process %s) - the scan found nothing that needs a question", name, pid))
    return 0


def split_arguments(argv: Optional[List[str]]) -> tuple:
    """``(our arguments, the game's arguments)``: everything after a lone ``--``
    belongs to the game."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in argv:
        at = argv.index("--")
        return argv[:at], argv[at + 1:]
    return argv, []
