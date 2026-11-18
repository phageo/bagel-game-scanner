"""The rule registry and the tier cap (phageo, 2026-11-02; ``docs/memory/roadmap-1.0.md``, phase B).

**The single source** of what each rule proves, its tier and its cause class. A rule's severity is capped
by what it proves (rule 13 as amended on 2026-11-02): trust never lowers a finding, the tier only says how
high the evidence can reach.

========== ============= ============================================================================
Tier       Highest level What the rule must prove
========== ============= ============================================================================
CAPABILITY MEDIUM        a capability exists (imports, names, strings, packing, network, starting a
                         program), or findings that only stand near each other
CHAIN      HIGH          capabilities joined by data flow (a followed value, or a reference the
                         reader resolves)
EVASION    HIGH          an act whose purpose is hiding, bypassing protection or delivering
                         executable content past scanners (criterion: ``roadmap-1.0.md``)
MALICE     CRITICAL      no benign explanation: hidden payload decoded and run, remote code run
IDENTITY   CRITICAL      outside the model: a named outside verdict on the exact file (hash list,
                         antivirus); never capped
========== ============= ============================================================================

The tiers are those pre-registered in ``docs/memory/tiers-1.0.md`` (its table's SHA-256 stands in
``docs/memory/decisions.md``), with the amendments phageo recorded afterwards (``AMENDED``). A test keeps
this table equal to that one.

:func:`cap` is the one place where the tier acts: :meth:`Scanner._finish` calls it once on every finding of
a scan, after every chain and join has been formed (``CHAIN-LOCAL-DROP-PLUS`` needs a HIGH persistence
sign to form), so the readers and chains work on the levels the rules gave. A capped finding keeps its
old level in ``capped_from``; the cap never raises a level. Switch: ``ON``.

A rule id not in ``REGISTRY`` is a capability: ``BELOW_HIGH`` names the rules that never reach HIGH (a
test checks that every rule id of the package stands in one of the two), and a YARA rule not listed here
(the user's own) is strings, so CAPABILITY.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/tiers.py")

from typing import Dict, Iterable, NamedTuple, Optional

from .models import Finding, Severity

ON = True                      # the tier cap (phase B, 2026-11-02); off = the levels the rules give

CAPABILITY, CHAIN, EVASION, MALICE, IDENTITY = "CAPABILITY", "CHAIN", "EVASION", "MALICE", "IDENTITY"
TIERS = (CAPABILITY, CHAIN, EVASION, MALICE, IDENTITY)
CAP: Dict[str, Severity] = {CAPABILITY: Severity.MEDIUM, CHAIN: Severity.HIGH, EVASION: Severity.HIGH,
                            MALICE: Severity.CRITICAL, IDENTITY: Severity.CRITICAL}
EVIDENCE = frozenset({CHAIN, EVASION, MALICE})       # the tiers whose findings may decide SUSPICIOUS or worse

# texts pulled out of a program's bytes (rules.STRINGS, rules.DOTNET): a match there is a name, not an instruction
_BINARY = frozenset({"strings", "dotnet"})


class Entry(NamedTuple):
    tier: str
    cause: str                 # cause class id of gamescan/causes.py
    proves: str                # what a finding of the rule proves, in a few words
    at_high: str = ""          # tier of its HIGH form, when that proves less (two-level rules)
    in_program: str = ""       # tier when it matches among a program's texts (a name there, no instruction)
    program_cause: str = ""    # cause class there
    proven: str = ""           # tier when a reader proved the flow (Finding.context[PROVEN]; C1, 2026-11-03)
    proven_cause: str = ""     # cause class then


_E = Entry
REGISTRY: Dict[str, Entry] = {
    # -- MALICE: no benign explanation
    "PY-OBF-001": _E(MALICE, "DECODE-AND-RUN", "decoded payload run in one statement (Python)"),
    "JS-OBF-001": _E(MALICE, "DECODE-AND-RUN", "decoded payload run in one statement (JavaScript)"),
    "RB-OBF-001": _E(MALICE, "DECODE-AND-RUN", "decoded payload run in one statement (Ruby)"),
    "CS-OBF-001": _E(MALICE, "DECODE-AND-RUN", "assembly loaded from decoded bytes"),
    "SH-OBF-001": _E(MALICE, "DECODE-AND-RUN", "encoded command handed to PowerShell"),
    "CHAIN-REMOTE-CODE": _E(MALICE, "REMOTE-CODE", "a download followed into a code load or start", at_high=CHAIN),
    # (phase C, C1, 2026-11-03: tiers of diagnosis-evidence.md and phageo's answer 2 - store / decrypted data MALICE,
    # clipboard / screen CHAIN, its HIGH form)
    "CHAIN-EXFIL": _E(MALICE, "PRIVATE-DATA-SENT", "private data followed from where it is read into a network call",
                       at_high=CHAIN),
    "CHAIN-LOCAL-DROP": _E(MALICE, "HIDDEN-PAYLOAD-RUN", "decode -> write -> start; CRITICAL only with the program proven",
                           at_high=CHAIN),
    "CHAIN-LOCAL-DROP-PLUS": _E(MALICE, "HIDDEN-PAYLOAD-RUN", "that chain + a persistence / evasion sign in one game"),
    # -- CHAIN: joined by data flow
    "RB-OBF-002": _E(CHAIN, "DECODE-AND-RUN", "decompressed data run as code"),
    "DF-EXEC-001": _E(CHAIN, "DECODE-AND-RUN", "hidden code followed to exec / eval"),
    # (phase C, C3, part 3: CHAIN as pre-registered in diagnosis-evidence.md - code protectors decrypt their own code)
    "CHAIN-DECODE-RUN": _E(CHAIN, "DECODE-AND-RUN", "decoded / decrypted data followed, without its value, into code"),
    "CHAIN-REMOTE-LOAD": _E(CHAIN, "REMOTE-CODE", "code loaded from an address that arrives at run time"),
    "CHAIN-REMOTE-ARG": _E(CHAIN, "REMOTE-CODE", "a download followed into a program's argument"),
    "CHAIN-TEXT-RUN": _E(CHAIN, "SCRIPT-STARTS-PROGRAMS", "text written to a file that is then started"),
    "CHAIN-MSI-LOAD": _E(CHAIN, "HIDDEN-PAYLOAD-RUN", "unsigned package -> own program -> library -> near-random member"),
    "PAGE-REMOTE-SCRIPT": _E(CHAIN, "REMOTE-CODE", "remote script in a window not proven shut in"),
    # (amended 2026-11-02: CHAIN until a reader proves that app code reaches the add-on - C1 may raise it)
    "CHAIN-STEALER": _E(CHAIN, "PRIVATE-DATA-NAMES", "store names + network; across an app also a decrypting add-on",
                         proven=MALICE, proven_cause="PRIVATE-DATA-SENT"),
    # -- EVASION: an act of hiding, bypassing protection, or delivering executable content past scanners
    "EVADE-001": _E(EVASION, "SECURITY-TAMPERING", "security-tool tampering written as an instruction",
                    in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "OBF-REV-001": _E(EVASION, "CONCEALED-CODE", "a command or address stored backwards"),
    "OBF-PE-001": _E(EVASION, "CONCEALED-CODE", "a Windows program carried Base64-encoded inside a file"),
    "OBF-BLOB-001": _E(EVASION, "CONCEALED-CODE", "an encoded blob that is a program (HIGH only then)"),
    "NAME-001": _E(EVASION, "DISGUISED-FILE", "a double ending hides a program"),
    "NAME-002": _E(EVASION, "DISGUISED-FILE", "a program under a name no program has"),
    "MEDIA-002": _E(EVASION, "HIDDEN-IN-MEDIA", "program, archive or script behind media data"),
    "ARC-ENC-EXEC-001": _E(EVASION, "CONCEALED-CODE", "a password archive holding programs, scripts or archives"),
    "RPY-CONTENT-001": _E(EVASION, "DISGUISED-FILE", "a program kept under a compiled script's name (HIGH only then)"),
    "SIG-DATA-001": _E(EVASION, "DISGUISED-FILE", "a known kind of file inside the signature block"),
    "SIG-DATA-002": _E(EVASION, "DISGUISED-FILE", "a known kind of file behind the signature block"),
    # -- CAPABILITY: a capability, a name, or parts that only stand near each other
    "PY-OBF-003": _E(CAPABILITY, "RUNS-STORED-CODE", "stored compiled code run; the trace found no decoding"),
    "CHAIN-SPYWARE": _E(CAPABILITY, "KEYBOARD-HOOK", "input capture + network near each other"),
    "CHAIN-DOWNLOADER": _E(CAPABILITY, "REMOTE-CODE", "network + hidden data + execution near each other"),
    "CHAIN-BACKDOOR": _E(CAPABILITY, "STARTS-WITH-WINDOWS", "persistence + network / start near each other"),
    "CHAIN-FETCHRUN": _E(CAPABILITY, "REMOTE-CODE", "network + start near each other, no flow reading"),
    "CHAIN-LOADER": _E(CAPABILITY, "DECODE-AND-RUN", "decoding beside dynamic execution"),
    "CHAIN-PACKED": _E(CAPABILITY, "PACKED-PROGRAM", "packed program + a risky capability"),
    "CHAIN-EVASIVE": _E(CAPABILITY, "SECURITY-TAMPERING", "evasion sign + network / start near each other"),
    "CHAIN-NO-FLOW": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "parts near each other, the reading found no flow"),
    "INPUT-001": _E(CAPABILITY, "KEYBOARD-HOOK", "a key hook import, or key-log words (policy 8 withdrawn)"),
    "INPUT-002": _E(CAPABILITY, "KEYBOARD-HOOK", "screen or clipboard capture"),
    "INPUT-003": _E(CAPABILITY, "KEYBOARD-HOOK", "input capture note"),
    "CRED-001": _E(CAPABILITY, "PRIVATE-DATA-NAMES", "names a password / wallet / token store",
                   in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "NET-EXFIL-001": _E(CAPABILITY, "PRIVATE-DATA-NAMES", "names a service stealers send data to",
                        in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "URL-IP-001": _E(CAPABILITY, "REMOTE-CODE", "an address with a bare IP number",
                     in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "LOL-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "names a Windows system tool",
                  in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "INJ-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "names process-injection functions",
                  in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "PERSIST-001": _E(CAPABILITY, "STARTS-WITH-WINDOWS", "names a way to start with Windows"),
    "JS-PROC-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "JavaScript can start programs"),
    "JS-PROC-002": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "JavaScript drives Windows scripting objects"),
    "RB-PROC-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "Ruby starts a command"),
    "RB-NATIVE-002": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "Ruby reaches a Windows function that runs or downloads"),
    "SH-DL-001": _E(CAPABILITY, "REMOTE-CODE", "shell downloads", in_program=CAPABILITY, program_cause="PROGRAM-TEXTS"),
    "SH-EXEC-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "shell runs text as code"),
    "DF-CMD-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "a started command read back"),
    "DF-URL-001": _E(CAPABILITY, "REMOTE-CODE", "an address read back, bare IP number"),
    "DF-CALL-001": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "a risky function reached by a built name"),
    "JS-NET-002": _E(CAPABILITY, "REMOTE-CODE", "a setting: remote pages get Node.js"),
    "CHAIN-SELF-UPDATE": _E(CAPABILITY, "REMOTE-CODE", "an app's checked self-update"),
    "RENDERER-CODE-LOAD": _E(CAPABILITY, "REMOTE-CODE", "a window page loads code at run time"),
    "PE-PACK-001": _E(CAPABILITY, "PACKED-PROGRAM", "packed program (not UPX)"),
    "DN-PACK-001": _E(CAPABILITY, "PACKED-PROGRAM", ".NET protector seen more in malware"),
    "ADDON-DECRYPT-001": _E(CAPABILITY, "PRIVATE-DATA-NAMES", "native add-on imports secret decryption"),
    "IAT-001": _E(CAPABILITY, "PROGRAM-TEXTS", "IL2CPP imports process tampering"),
    "IAT-002": _E(CAPABILITY, "PROGRAM-TEXTS", "IL2CPP imports the native API"),
    "IAT-003": _E(CAPABILITY, "PROGRAM-TEXTS", "IL2CPP imports networking"),
    "IAT-004": _E(CAPABILITY, "PROGRAM-TEXTS", "IL2CPP imports cryptography"),
    "IAT-005": _E(CAPABILITY, "PROGRAM-TEXTS", "IL2CPP imports system control"),
    "PY-FS-001": _E(CAPABILITY, "DELETES-OUTSIDE", "deletes in a user or system folder (Python)"),
    "SH-FS-001": _E(CAPABILITY, "DELETES-OUTSIDE", "deletes in a user or system folder (shell)"),
    "RB-FS-001": _E(CAPABILITY, "DELETES-OUTSIDE", "deletes in a user or system folder (Ruby)"),
    "JS-FS-001": _E(CAPABILITY, "DELETES-OUTSIDE", "deletes in a user or system folder (JavaScript)"),
    "CS-FS-001": _E(CAPABILITY, "DELETES-OUTSIDE", "deletes in a user or system folder (C#)"),
    "SIDELOAD-001": _E(CAPABILITY, "UNVERIFIED-LIBRARY", "unverified library with a Windows name beside a program"),
    "ENGINE-004": _E(CAPABILITY, "CHANGED-ENGINE-FILE", "compiled engine file differs, source official"),
    "ENGINE-007": _E(CAPABILITY, "CHANGED-ENGINE-FILE", "compiled engine file calls what its source does not"),
    "DOC-002": _E(CAPABILITY, "SCRIPT-STARTS-PROGRAMS", "Office macro that starts itself and can launch code"),
    _IND[0]: _E(CAPABILITY, "PRIVATE-DATA-NAMES", "strings of a bundled signature"),
    "YARA:PowerShell_Download_Cradle": _E(CAPABILITY, "REMOTE-CODE", "strings of a bundled signature"),
    # -- IDENTITY: an outside verdict on the exact file; never capped
    "SIG-001": _E(IDENTITY, "KNOWN-MALWARE", "hash on the blocklist"),
    "SIG-EICAR": _E(IDENTITY, "KNOWN-MALWARE", "the antivirus test file"),
    "DEFENDER-001": _E(IDENTITY, "KNOWN-MALWARE", "Windows Defender names it"),
    "AMSI-001": _E(IDENTITY, "KNOWN-MALWARE", "antimalware engine flags unpacked content"),
    "VT-001": _E(IDENTITY, "KNOWN-MALWARE", "antivirus engines on VirusTotal"),
    "AUTORUN-002": _E(IDENTITY, "STARTS-WITH-WINDOWS", "PC check, not a game scan: hidden script at autostart"),
}

# every other rule of the package: it never reaches HIGH, so it is a capability (no cause class needed:
# a finding below HIGH never decides SUSPICIOUS or worse)
BELOW_HIGH = frozenset("""
ARC-001 ARC-002 AUTORUN-001 AUTORUN-003 CS-EXEC-001 CS-NET-001 CS-OBF-002 CS-PINV-001 CS-PROC-001 CS-REG-001
DF-PATH-001 DN-EXEC-001 DN-IL-001 DN-META-001 DN-NET-001 DN-OBF-001 DN-PACK-002 DN-PROC-001 DN-REG-001 DOC-001
ENC-SCRIPT-001 ENGINE-001 ENGINE-002 ENGINE-003 ENGINE-005 ENGINE-006 ENGINE-008 ENGINE-009 ENGINE-010 ENGINE-011
ENT-STR-001 EXEC-FMT-001 FS-SYS-001 IAT-006 IL2CPP-META-001 INNO-CODE-001 INST-REDIST-001 JS-ENV-001 JS-EXEC-001
JS-NET-001 JS-OBF-002 JS-OBF-003 JS-OBF-004 JS-OBF-005 JSC-FMT-001 MEDIA-001 MSI-PROG-001 NAME-003 NAME-004 NET-PE-001
NET-RECON-001 OBF-CAT-001 OBF-HEX-001 PE-ENT-001 PE-ENT-002 PE-ENT-003 PE-EP-001 PE-FMT-001 PE-PACK-002 PE-PACK-003
PE-PACK-004 PROC-LIST-001 PY-EXEC-001 PY-EXEC-002 PY-EXEC-003 PY-EXEC-004 PY-JOIN-001 PY-NET-001 PY-OBF-002
PY-PROC-001 PYO-FMT-001 RB-EXEC-001 RB-NATIVE-001 RB-NATIVE-003 RB-NET-001 RB-OBF-003 RB-PROC-002 RGSS-FMT-001
RGSS-FMT-002 RGSS-RT-001 RPY-FMT-001 SCAN-COVERAGE-001 SCAN-ERR-001 SCRIPT-LIMIT-001 SH-HIDE-001 SH-OBF-002
SH-OBF-003 SH-PROC-001 UNITY-FMT-001 UNITY-PE-001 URL-001 VT-002 VT-003 VT-004
YARA:Packed_UPX_Executable YARA:Embedded_PE_In_Non_Executable
""".split())

# the pre-registered tiers of docs/memory/tiers-1.0.md, as phageo amended them afterwards (decisions.md)
AMENDED = {"CHAIN-STEALER": (MALICE, CHAIN)}          # rule: (pre-registered, now) - 2026-11-02, phase B
# rules of the phase-C readers, registered after phase A with the tiers phase A gave their evidence
# (docs/memory/diagnosis-evidence.md, section 2) - not in the pre-registered table
PHASE_C = frozenset({"CHAIN-EXFIL", "CHAIN-DECODE-RUN"})
PROVEN = "flow_proven"          # Finding.context: a reader proved the flow the rule only names (Entry.proven)


def entry(rule_id: str) -> Optional[Entry]:
    return REGISTRY.get(rule_id)


def in_program(f: Finding) -> bool:
    """The finding matched among a program's texts or imports (a name there, no instruction)."""
    return f.context.get("language") in _BINARY


def tier_of(f: Finding, level: Optional[Severity] = None) -> str:
    """The tier of the finding ``f`` at ``level`` (its own level by default)."""
    e = REGISTRY.get(f.rule_id)
    if e is None:
        return CAPABILITY               # (BELOW_HIGH, or a YARA rule of the user's own: strings)
    if e.in_program and in_program(f):
        return e.in_program
    if e.proven and f.context.get(PROVEN):
        return e.proven
    if e.at_high and (level if level is not None else f.severity) == Severity.HIGH:
        return e.at_high
    return e.tier


def cause_of(f: Finding) -> Optional[str]:
    """The cause class of the finding (None: no class - a rule below HIGH)."""
    e = REGISTRY.get(f.rule_id)
    if e is None:
        return None
    if e.program_cause and in_program(f):
        return e.program_cause
    if e.proven_cause and f.context.get(PROVEN):
        return e.proven_cause
    return e.cause


def cap(findings: Iterable[Finding]) -> None:
    """Cap every finding at the highest level its tier allows (in place). The old level is kept in
    ``capped_from``; each finding gets its ``tier``. Never raises a level. Nothing when ``ON`` is off."""
    if not ON:
        return
    for f in findings:
        tier = tier_of(f)
        f.tier = tier
        limit = CAP[tier]
        if f.severity > limit:
            f.capped_from = f.severity.name
            f.severity = limit
            tier_after = tier_of(f)         # (a two-level rule's lower form may name another tier)
            if tier_after != tier:
                f.tier = tier_after
