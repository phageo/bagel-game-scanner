"""Why a game is SUSPICIOUS or DANGEROUS, in plain words: the documented cause classes.

phageo, 2026-10-29 (criterion 3 for round 4): SUSPICIOUS means "could not be verified, and here
is why" - not "malicious". Every finding that sets a SUSPICIOUS-or-worse verdict (the active
findings at the report's highest level, HIGH or CRITICAL) is mapped to one cause class of
``CLASSES``; the report shows each class that applies with its reason. The classes are the ones
documented in ``docs/memory/limits.md`` ("Cause classes") - one id each, the same words.

A finding no class covers is never dropped: it is shown as "other signs", without a documented
cause (``None``). ``tools/explain_check.py`` lists such findings; in a clean round one of them
fails criterion 3c. A class says what the scanner could not prove - it lowers nothing, hides
nothing and changes no verdict.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/causes.py")

from typing import Dict, List, Optional, Tuple

from . import origin, tiers
from .models import Finding, ScanReport, Severity

# texts pulled out of a program's bytes (rules.STRINGS, rules.DOTNET)
_BINARY = frozenset({"strings", "dotnet"})

# id -> (title, the reason in plain words)
CLASSES: Dict[str, Tuple[str, str]] = {
    "KEYBOARD-HOOK": (
        "Keyboard hook in a program or library",
        "A program or library asks Windows to watch every key press. Games, game engines and "
        "libraries such as SDL2 do this for their controls; key loggers do it too. Only an exact "
        "official copy of the file could show which, and none is known for this one."),
    "PROGRAM-TEXTS": (
        "Names among the texts of an unverified program",
        "A program or library that no official table proves - most often an engine runtime or a "
        "bundled library - holds, among its texts or imports, names that malware uses too (a "
        "system tool, a function that writes into other programs, a password store). The names "
        "alone do not show what the program does with them."),
    "UNVERIFIED-LIBRARY": (
        "Unverified library beside the game's program",
        "A library with the name of a Windows library lies beside the game's program, and nothing "
        "proves it (no valid signature, no official table). Old games ship such runtime "
        "libraries; malware hides beside a program the same way."),
    "PACKED-PROGRAM": (
        "Packed program",
        "A program keeps its real code compressed or encrypted until it runs, so its code could "
        "not be read, and it also shows signs that would need that code to judge."),
    "SCRIPT-STARTS-PROGRAMS": (
        "A script can start programs",
        "A script - a plugin, a bundled library, an updater - can start other programs or "
        "commands. The scanner could not prove that what it starts is harmless."),
    "REMOTE-CODE": (
        "Code from the internet",
        "Code can fetch something from the internet and load it, run it or hand it to a program. "
        "Libraries do this to load parts of themselves from a web address; what the address will "
        "send cannot be seen in the files."),
    "DECODE-AND-RUN": (
        "Decodes data and runs it",
        "Code decodes or unpacks data and runs it as code in one step. Old engines do this with "
        "their own compiled code; malware hides its payload this way. This is never lowered for "
        "trust."),
    "RUNS-STORED-CODE": (
        "Runs stored compiled code",
        "A script turns stored compiled code back into code and runs it. No decoding, unpacking, "
        "decryption or download leads to it in that file. Old engines run their own compiled "
        "scripts this way; what is run here depends on what is handed in, and that was not "
        "proven harmless."),
    "HIDDEN-IN-MEDIA": (
        "Text hidden in a media file",
        "Text that reads like a script lies behind the sound or picture data of a media file, "
        "where a player never reads it."),
    "DELETES-OUTSIDE": (
        "Deletes files outside the game",
        "A script deletes files, and the place it deletes in is a user or system folder, not the "
        "game's own data."),
    "PRIVATE-DATA-NAMES": (
        "A script names private data",
        "A script names places where browsers, chat programs or wallets keep logins or passwords, "
        "or sends data out. The scanner could not prove what it does with them."),
    # (2026-11-03, phase C, C1: the flow itself, followed through the code)
    "PRIVATE-DATA-SENT": (
        "A script sends private data out",
        _IND[0]),
    # (2026-11-02, phase B: every rule of gamescan/tiers.py that can decide SUSPICIOUS or worse has a class)
    "HIDDEN-PAYLOAD-RUN": (
        "Hidden data decoded and started",
        "A script or an installer decodes, unpacks or reads hidden data, writes or loads what comes out, "
        "and starts it. Games do not hide their own programs this way; droppers do."),
    "DISGUISED-FILE": (
        "A file disguised as something else",
        "A program or script carries a name, an ending or a place that says it is something else - a "
        "picture, a document, a data file, a compiled script - or sits inside a program's signature "
        "block, where the signature still looks valid. Hiding what a file is has no use for a game."),
    "CONCEALED-CODE": (
        "Code carried in a hidden form",
        "A program or a command is carried in a form that only running it undoes - stored backwards, "
        "encoded inside a script, or inside a password archive - so no scanner can read it first."),
    "SECURITY-TAMPERING": (
        "Tampers with Windows' protection",
        "Code carries an instruction that switches off or bypasses Windows' protection - the antivirus, "
        "the firewall, recovery data or the event logs. Games have no reason to do this."),
    "STARTS-WITH-WINDOWS": (
        "Starts with Windows",
        "Something is set up to start by itself when Windows starts. Launchers and updaters do this; "
        "malware does it to stay on the PC."),
    "CHANGED-ENGINE-FILE": (
        "A changed engine file",
        "A compiled file of the game engine differs from the official one, although its source is the "
        "official one, or it does more than its source. A recompile or an edited source can explain it; "
        "a planted change looks the same."),
    "KNOWN-MALWARE": (
        "Named by an outside check",
        "An outside check names this exact file: the scanner's list of known bad files, Windows "
        "Defender, the antimalware engine or antivirus engines on VirusTotal."),
}
OTHER = ("Other signs (no documented cause)",
         "These findings are not covered by any documented cause: look at each of them.")

def cause_of(f: Finding) -> Optional[str]:
    """The cause class of the finding ``f`` (None: no documented class covers it). The classes come
    from the rule registry, ``gamescan/tiers.py`` - the single source since 2026-11-02 (phase B)."""
    return tiers.cause_of(f)


def deciding(report: ScanReport) -> List[Finding]:
    """The findings that set a SUSPICIOUS-or-worse verdict: the active ones at the report's
    highest level, when that level is HIGH or CRITICAL (none for a milder verdict)."""
    worst = report.max_severity
    if worst is None or worst < Severity.HIGH:
        return []
    return [f for f in report.active if f.severity is worst]


def explain(report: ScanReport) -> List[Tuple[Optional[str], List[Finding]]]:
    """``[(cause class or None, its deciding findings)]`` - the classes in the order of
    ``CLASSES``, the findings without a class last."""
    grouped: Dict[Optional[str], List[Finding]] = {}
    for f in deciding(report):
        grouped.setdefault(cause_of(f), []).append(f)
    order = [c for c in CLASSES if c in grouped] + ([None] if None in grouped else [])
    return [(c, grouped[c]) for c in order]


def as_dicts(report: ScanReport) -> List[dict]:
    """``explain`` for the JSON report (field ``verdict_causes``; English, as the other fields)."""
    out = []
    for cause, found in explain(report):
        title, reason = CLASSES[cause] if cause else OTHER
        out.append({"cause": cause, "title": title, "reason": reason, "findings": len(found),
                    "rules": sorted({f.rule_id for f in found}),
                    # where they stand (gamescan/origin.py; new field 2026-11-02, information only)
                    "origins": [{"kind": kind, "detail": detail, "verified": verified, "findings": count}
                                for kind, detail, verified, count in origin.summary(found)]})
    return out
