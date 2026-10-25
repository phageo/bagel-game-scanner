"""The :class:`ContextEngine` - the single owner of false-positive decisions.

Rules and handlers only report what they see. Every decision to *suppress* a
finding (or to raise it because its context makes it worse) is taken here, and
a suppressed finding stays in the report together with the reason.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/context.py")

import ast
import base64
import binascii
import ipaddress
import json
import os
import re
import unicodedata
from typing import Dict, Iterable, Optional
from urllib.parse import urlsplit

from .engine_hashes import VERIFIED as VERIFIED_BUILD
from .library_hashes import VERIFIED as VERIFIED_LIBRARY
from .memory import fingerprint
from .models import Category, FileContext, Finding, Severity

RESOLVED_FP = "Resolved as a false positive earlier (memory center)"
TEXT_LITERAL = "Text, not code: the whole line is one string literal"
OWN_ATTRIBUTES = (" Here the function is SetFileAttributes, and every call of it in this script was "
                  "read: each one only hides or shows a folder or file of the game itself (shown in "
                  "the evidence), never a program. Games hide their save folder this way. It is "
                  "shown as a LOW note.")
OWN_LIBRARY = (" Here the function belongs to a library that lies in the game's own folder, named in "
               "full in the script. That file was read to the end in this scan, and nothing of "
               "MEDIUM or higher severity was found in it. It is shown as a LOW note; the library's "
               "own findings, if any, are listed under its file.")
# libraries of Windows itself: a file of that name in a game's folder is not "the game's own"
_SYSTEM_LIBRARIES = frozenset(
    "kernel32 kernelbase ntdll user32 gdi32 gdiplus shell32 shlwapi advapi32 ole32 oleaut32 comdlg32 "
    "comctl32 msvcrt winmm wininet urlmon winhttp ws2_32 wsock32 psapi version imm32 crypt32 "
    "secur32 netapi32 iphlpapi dbghelp setupapi userenv wtsapi32 dwmapi uxtheme mpr rpcrt4 "
    "bcrypt ncrypt powrprof dinput8 dsound d3d9 d3d11 opengl32 xinput1_3 xinput1_4 xinput9_1_0".split())
SAME_DECLARATION = _IND[0]
PROCESS_LIST_ONLY = "Only reads the list of running programs (reported as PROC-LIST-001)"
# a query for the running programs and nothing else: no other computer (/node), no output
# style sheet (/format - it can name a remote script), no "call", no second command
_PROCESS_QUERY = re.compile(r"(?:wmic(?:\.exe)?\s+process\s+get\s+[A-Za-z]+(?:\s*,\s*[A-Za-z]+){0,7}"
                            r"|tasklist(?:\.exe)?(?:\s+/(?:nh|v|fo\s+(?:csv|list|table)))*)", re.I)
DATA_WRITE = (" Here the script writes a data file into the game's own folder: the path starts from "
              "the game's folder, the file name ends in a data extension, and it is not a file the "
              "engine reads as code or configuration. It is shown as a LOW note.")
WRITTEN_TEXT = (" Here the text is only written, as it stands, into a file of the game that has no "
                "program or script extension; this script never decodes or executes text. It is "
                "shown as a LOW note.")
# open(config.basedir + "/name", "w").write(   <- the literal follows
_WRITES_TEXT = re.compile(r"""(?:^|[\s:;])open\(\s*config\.(?:basedir|gamedir)\s*\+\s*(["'])/((?:(?!\1)[^\\\n])+)\1"""
                          r"""\s*,\s*["'][wa]["']\s*\)\s*\.write\(\s*$""")
NATURAL_TEXT = "Natural-language text: a sentence in Japanese, Chinese or Korean writing, not encoded data"
# the writing such a sentence is made of (context._natural_text): ideographs of the basic
# block, kana, Hangul syllables, CJK punctuation, fullwidth forms - and nothing else but
# ASCII. An encoding that uses Unicode as its alphabet (base32768, base65536) spreads over
# other blocks, and one character from any of them is enough to leave the literal alone.
_IDEOGRAPH = (0x4E00, 0x9FFF)
_CJK_BLOCKS = (_IDEOGRAPH, (0x3040, 0x309F), (0x30A0, 0x30FF), (0xAC00, 0xD7AF), (0x3000, 0x303F),
               (0xFF00, 0xFFEF))
# what only written language has: kana and Hangul letters, and the punctuation of a sentence
_TEXT_MARKERS = ((0x3041, 0x3096), (0x30A1, 0x30FA), (0xAC00, 0xD7A3))
_TEXT_PUNCTUATION = frozenset("、。「」『』，！？：；（）")
NATURAL_SHARE = 0.9          # of the characters; the real sentences this was read from: 1.0
_MAX_ASCII_RUN = 15          # letters, digits, + / = _ - in a row (fullwidth ones count as ASCII)
_MAX_IDEOGRAPH_RUN = 40      # ideographs in a row without kana, Hangul or punctuation
_ASCII_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % (_MAX_ASCII_RUN + 1))
_TEXT_TAG = re.compile(r"\{/?[a-z_]{1,12}\}")           # Ren'Py text tags without a value: {b}, {/i}
# rules whose match can be a word in the name of a file an installer installs: a download
# word (DownloadFiles.iss), the name of a system tool (PowerShell.iss; phageo, 2026-10-11)
_NAME_RULES = frozenset({"SH-DL-001", "LOL-001"})
FILE_NAME_ONLY = "file_name"            # mark on such a finding (chains.py reads it)
FILE_NAME = (" Here the word stands in the name of a file this installer installs - file name, not an "
             "instruction: the installer's own code was read to its end and names nothing that "
             "downloads. It is shown as a LOW note.")
STANDARD_MESSAGE = (" Here the word stands in a standard installer message: a text of Inno Setup itself, "
                    "which every installer made with it carries, not an instruction of this installer. "
                    "It is shown as a LOW note.")
OWN_LOCK = "The script's own lock file in the temporary folder (one copy of the game at a time)"
_DELETES_NAME = re.compile(r"\bos\.(?:unlink|remove)\s*\(\s*([A-Za-z_][\w.]*)\s*\)")
_STRING_LITERAL = re.compile(r"""\"[^"\\\n]*(?:\\.[^"\\\n]*)*\"|'[^'\\\n]*(?:\\.[^'\\\n]*)*'""")   # (unrolled: rules._DQ)
SIGNED_BY_TRUSTED = "valid digital signature from trusted publisher"
# "The content could not be read" is never hidden by what the scanner concludes by itself -
# a signature, an official hash, a folder, a clean reputation, its own statistics. All of
# these speak about the file as a whole or about who made it; none of them has seen what is
# inside. (What the user decides - the allowlist, "this is a false positive" - still applies.)
_NEVER_HIDDEN = frozenset({"ARC-001", "ARC-ENC-EXEC-001", "ARC-002","UNITY-FMT-001", "RPY-FMT-001", "RGSS-FMT-001", "RGSS-FMT-002",
                           "DN-META-001", "IL2CPP-META-001", "SCAN-ERR-001", "PYO-FMT-001",
                           "PY-JOIN-001", "INNO-CODE-001", "DN-IL-001", "SCRIPT-LIMIT-001", "ENC-SCRIPT-001",
                           "SCAN-COVERAGE-001", "JSC-FMT-001", "EXEC-FMT-001",
                           # a "compiled script" that holds something else, not read (2026-10-18)
                           "RPY-CONTENT-001",
                           # an installer downloads and runs an official redistributable: what
                           # is downloaded is not in the package and was not seen either
                           "INST-REDIST-001",
                           # data in / behind a signature block: the signature does not cover it
                           "SIG-DATA-001", "SIG-DATA-002"})
# Windows functions that ordinary programs import all the time (see _import_table)
_EVERYDAY_IMPORTS = frozenset({("INPUT-001", _IND[1]), ("INPUT-001", "getkeyboardstate"),
                               ("INPUT-002", _IND[2])})
IN_IMPORT_TABLE = "in_import_table"
EVERYDAY_IMPORT = (" In a program this function is ordinary: games read the keyboard for their "
                   "controls, and anything with a text box can paste from the clipboard. It is "
                   "shown as a LOW note.")
# findings below CRITICAL that a baseline resting on folder and name does not silence ...
# (CHAIN-REMOTE-CODE is CRITICAL and never silenced anyway; listed for its HIGH form, a
# chain in an engine script of a Ren'Py version that cannot be verified)
# (ENGINE-003: the note that an engine script is not the official file of its version -
# the folder it sits in is exactly what it does not live up to; ENGINE-004 / ENGINE-005:
# the same for the engine's compiled Python)
_SHOWN_IN_NAMED_BASELINES = frozenset({"CHAIN-REMOTE-LOAD", "CHAIN-REMOTE-CODE", "ENGINE-003",
                                       "ENGINE-004", "ENGINE-005", "ENGINE-006", "ENGINE-007",
                                       # (2026-10-17: a decoded file of the game that is started, and a
                                       # library named like Windows' - a folder or a name proves nothing)
                                       "CHAIN-LOCAL-DROP", "SIDELOAD-001",
                                       # (2026-10-18: a program in the engine's folder that is not
                                       # the official file - the folder is what it does not live up to)
                                       "ENGINE-008",
                                       # (2026-10-20: a program beside a verified app runtime that
                                       # nothing verifies - the runtime is what it does not live up to)
                                       "ENGINE-009"})
# a file of a published npm package (gamescan/npm_hashes.py): the mark in its baseline, and
# the findings that say what a file can do, whoever published it
NPM_VERIFIED = ": npm package "
# JS-PROC-001 in a script whose process starts are made of written-out text and the app's own
# values only (remote.Start.local; phageo, 2026-10-14)
LOCAL_STARTS = (" Every program this script starts is made only of written-out text and of the app's own "
                "values - its folder, this PC's settings, environment variables -, nothing from the network, "
                "a file from elsewhere or a page of the app, and none is a script runtime - so the level is lowered.")
_CAPABILITIES = frozenset({"ADDON-DECRYPT-001"})
# ... and the baselines that rest on proof of origin instead (signature, official hash)
_PROVEN = (SIGNED_BY_TRUSTED, VERIFIED_BUILD, VERIFIED_LIBRARY)

# Publishers whose valid signature silences heuristics (editable in Settings).
# A name matches when the certificate subject starts with it, so "Microsoft"
# covers "Microsoft Corporation" and "Microsoft Windows".
TRUSTED_PUBLISHERS = (
    "Microsoft", "Unity Technologies", "Valve", "Python Software Foundation", "Epic Games",
    "NVIDIA Corporation", "Intel Corporation", "Advanced Micro Devices", "Google LLC",
    "Mozilla Corporation", "GOG",
)

BENIGN_DOMAINS = (
    # engines, stores, creator platforms
    "renpy.org", "rpgmakerweb.com", "rpgmaker.net", "unity3d.com", "unity.com",
    "steampowered.com", "steamcommunity.com", "itch.io", "patreon.com", "dlsite.com",
    "subscribestar.com", "gog.com", "epicgames.com", "yanfly.moe", "visustella.com",
    # dev infrastructure, standards, licences, docs
    # (no github.io / googleapis.com: anyone can host files under those)
    "github.com", "microsoft.com", "w3.org", "mozilla.org", "google.com",
    "fonts.googleapis.com", "gstatic.com", "python.org", "apache.org", "opensource.org",
    "creativecommons.org", "gnu.org", "wikipedia.org", "stackoverflow.com",
    # named in ordinary image / audio metadata (colour profiles, XMP, tool tags)
    "iec.ch", "color.org", "adobe.com", "purl.org", "xiph.org", "iptc.org", "goldwave.com",
    "gimp.org", "inkscape.org", "apple.com",
    "nwjs.io", "nodejs.org", "npmjs.com", "pixijs.com", "khronos.org", "libsdl.org",
    "freetype.org", "zlib.net", "openssl.org", "xmlsoap.org", "jquery.com",
    "mit-license.org", "unicode.org", "ietf.org", "example.com", "chromium.org",
    # certificate authorities (CRL / OCSP URLs inside signed binaries)
    "digicert.com", "verisign.com", "globalsign.com", "sectigo.com", "usertrust.com",
    "comodoca.com", "symantec.com", "symcb.com", "symcd.com", "thawte.com",
    "godaddy.com", "letsencrypt.org", "entrust.net",
    # social links
    "twitter.com", "x.com", "youtube.com", _IND[3], "facebook.com", "reddit.com",
)

_URL = re.compile(r"""https?://[^\s'"<>)\]\\}`,;]+""", re.I)
_API_LIKE = re.compile(r"^[A-Z][A-Za-z0-9]{5,}$")
_ASSET_MAGIC = (
    (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"),
    (b"OggS", "Ogg audio"), (b"RIFF", "RIFF audio/image"), (b"ID3", "MP3 audio"),
    (b"wOFF", "web font"), (b"wOF2", "web font"), (b"OTTO", "OpenType font"),
    (b"\x00\x01\x00\x00", "TrueType font"), (b"BM", "bitmap image"),
    (b"<svg", "SVG image"), (b"<?xml", "XML document"), (b'{"', "JSON document"),
)
# engine APIs that can only mean "the game's own data" - trusted anywhere nearby
_SAFE_DELETE_API = re.compile(
    _IND[4],
    re.I)
# ordinary words - only trusted inside the deleting statement itself
_SAFE_DELETE_WORD = re.compile(
    r"save|cache|te?mp\b|\.log\b|logs?[/\\]|persistent|screenshot|\.bak\b|thumbs", re.I)
_DANGER_DELETE = re.compile(
    r"%(?:userprofile|systemroot|windir|appdata|localappdata|homepath|systemdrive|programfiles)%"
    r"|\$(?:env:)?(?:HOME|USERPROFILE|APPDATA)\b|expanduser|os\.environ|process\.env|homedir"
    r"|[a-z]:[\\/]{1,2}(?:\*|users|windows|program)|[\\/]\*(?:\s|$|[\"'])|(?<![\w.\-])~(?:[/\\]|\s|$|[\"'])"
    r"|\s/(?:\*|\s|$)|system32|Documents|Desktop|--no-preserve-root|SpecialFolder",
    re.I)
_SAVE_CONTEXT = re.compile(
    r"save|persistent|StorageManager|DataManager|LZString|PlayerPrefs|localStorage"
    r"|json\.(?:loads|dumps)|JSON\.(?:parse|stringify)|pickle|checksum|achievement"
    r"|settings|config", re.I)
_CODE_SINK = re.compile(
    _IND[5], re.I)
_RGSS_HELPER = re.compile(
    _IND[6])
_RGSS_DANGER = re.compile(
    _IND[7])
_OPEN_URL = re.compile(
    _IND[8], re.I)
_BENIGN_SPAWN = re.compile(r"""['"](?:explorer(?:\.exe)?|xdg-open|open|notepad(?:\.exe)?)['"]""", re.I)
# Ruby: system("explorer.exe", SITE_URL) - the usual "visit our web site" title-menu entry
_RUBY_EXPLORER = re.compile(r"""\bsystem\s*\(?\s*["']explorer(?:\.exe)?["']\s*[,)]""", re.I)
_EXPLORER = re.compile(r"explorer(?:\.exe)?", re.I)
_LOCAL_LOAD = re.compile(
    r"overrideMimeType|['\"`](?:\.{0,2}/)?(?:data|img|audio|js|fonts|movies|icon|locales?)/"
    r"|\.(?:json|png|ogg|m4a|txt|csv|webm|ttf|woff2?)['\"`]", re.I)


class HashAllowlist:
    """SHA-256 allowlist persisted as JSON (``{"sha256": {hash: note}}``)."""

    def __init__(self, path: Optional[str] = None, hashes: Optional[Iterable[str]] = None) -> None:
        self.path = path
        self.entries: Dict[str, str] = {h.lower(): "" for h in (hashes or ())}
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh).get("sha256", {})
                self.entries.update({k.lower(): str(v) for k, v in loaded.items()})
            except (OSError, ValueError, AttributeError):
                pass                       # unreadable allowlist = empty allowlist

    @staticmethod
    def default_path() -> str:
        return os.path.join(os.path.expanduser("~"), ".game_safety_scanner", "allowlist.json")

    def __contains__(self, sha256: str) -> bool:
        return bool(sha256) and sha256.lower() in self.entries

    def add(self, sha256: str, note: str = "") -> None:
        self.entries[sha256.lower()] = note

    def save(self) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"sha256": self.entries}, fh, indent=2)


class ContextEngine:
    """Evaluates a raw finding in its context and suppresses / adjusts it.

    ``strict=True`` disables the engine/library *path* baselines (a file is no
    longer trusted just because it sits where engine files normally sit); all
    other checks still apply.
    """

    def __init__(self, allowlist: Optional[HashAllowlist] = None, strict: bool = False,
                 benign_domains: Iterable[str] = BENIGN_DOMAINS, memory=None,
                 trusted_publishers: Optional[Iterable[str]] = None,
                 vt_min_age_days: float = 30.0) -> None:
        self.allowlist = allowlist or HashAllowlist()
        self.strict = strict
        self.trusted_publishers = tuple(
            p.strip().lower() for p in (TRUSTED_PUBLISHERS if trusted_publishers is None
                                        else trusted_publishers) if p and p.strip())
        self.vt_min_age_days = vt_min_age_days
        self.benign_domains = tuple(d.lower() for d in benign_domains)
        self.memory = memory                 # MemoryCenter, or None = no learning
        self._resolved: Dict[str, str] = {}
        self._stats: Dict = {}
        # first check that suppresses wins; memory and the baseline go last so
        # that they see the confidence the specific checks arrived at, and so
        # context escalations to CRITICAL are not hidden by the baseline
        self._checks = (
            self._hash_allowlist, self._comment, self._same_declaration, self._text_literal,
            self._process_list, self._installed_name, self._standard_message,
            self._import_table,
            self._benign_domain, self._embedded_asset, self._natural_text, self._written_text,
            self._own_lock_file,
            self._data_write,
            self._deletion_target,
            self._save_encoding, self._benign_spawn, self._local_load, self._rgss_api,
            self._by_flow,
            self._signature, self.remember, self._baseline,
        )
        self.refresh_memory()

    # -- feedback loop -----------------------------------------------------------
    PRIOR_STRENGTH = 4.0      # a rule's own confidence counts like 4 pieces of feedback
    LEARNED_FLOOR = 0.15      # below this, with enough evidence, a weak finding is dropped
    MIN_EVIDENCE = 5

    @classmethod
    def learned_confidence(cls, base: float, fp: float, tp: float) -> float:
        """Bayesian update of a rule's confidence from its track record.

        The rule's built-in confidence is the prior (worth PRIOR_STRENGTH
        observations); every confirmed threat pulls the estimate up, every
        false positive pulls it down. With no feedback the result is ``base``.
        """
        k = cls.PRIOR_STRENGTH
        return min(0.99, max(0.02, (tp + base * k) / (tp + fp + k)))

    def refresh_memory(self) -> None:
        """Reload resolutions and rule statistics (call before a scan / after feedback)."""
        if self.memory is None:
            self._resolved, self._stats = {}, {}
        else:
            self._resolved, self._stats = self.memory.resolutions(), self.memory.rule_stats()

    def learn(self, finding: Finding, false_positive: bool, source: str = "user",
              weight: float = 1.0) -> None:
        """Feed a resolution back into the memory center.

        ``source`` says who decided: ``user`` (explicit click), ``allowlist`` /
        ``quarantine`` (implied by the user's action) or ``virustotal``
        (external verdict). The scanner never feeds its *own* conclusions back
        in - that would only reinforce whatever it already believes.
        """
        if self.memory is None:
            return
        self.memory.add_feedback(finding, false_positive, source, weight)
        self.refresh_memory()

    def unlearn(self, finding: Finding, source: str = "user") -> None:
        if self.memory is not None:
            self.memory.remove_feedback(finding, source)
            self.refresh_memory()

    def remember(self, f: Finding, ctx: Optional[FileContext] = None) -> bool:
        """Apply what past resolutions say about this finding."""
        if self.memory is None:
            return False
        resolved = self._resolved.get(fingerprint(f))
        if resolved == "fp":
            return f.suppress(RESOLVED_FP)
        if resolved == "tp":
            f.base_confidence = f.confidence
            f.confidence = max(f.confidence, 0.9)
            f.learned = "confirmed"
            return False
        stats = self._stats.get((f.rule_id, f.handler))
        if stats is None or f.rule_id in _NEVER_HIDDEN:
            return False
        f.base_confidence = f.confidence
        f.confidence = self.learned_confidence(f.confidence, stats.fp, stats.tp)
        f.learned = "%d/%d" % (stats.fp_count, stats.tp_count)
        # statistics alone may only drop weak signals, never HIGH / CRITICAL
        if (f.severity <= Severity.MEDIUM and stats.fp_count >= self.MIN_EVIDENCE
                and stats.tp_count == 0 and f.confidence < self.LEARNED_FLOOR):
            return f.suppress("Learned: this rule was a false positive %d times for this engine"
                              % stats.fp_count)
        return False

    def evaluate(self, finding: Finding, ctx: FileContext) -> Finding:
        for check in self._checks:
            if check(finding, ctx):
                break
        return finding

    def evaluate_joined(self, finding: Finding, ctx: FileContext) -> Finding:
        """The same for a chain that was put together after the files were scanned
        (download-and-run across two files; ``ctx`` has no content any more): the
        user's allowlist, what past resolutions say, and the baseline."""
        for check in (self._hash_allowlist, self.remember, self._baseline):
            if finding.suppressed or check(finding, ctx):
                break
        return finding

    def apply_reputation(self, findings: Iterable[Finding], reputation) -> int:
        """External verification: a file that dozens of antivirus engines have
        known for a while and none flags does not need its weak local signals.

        "For a while" matters: brand-new malware is routinely 0/70 in its
        first days, so a clean result only counts once the file has been on
        VirusTotal for ``vt_min_age_days``. Any detection at all rules it out.
        HIGH and CRITICAL findings are always kept - a clean reputation is
        evidence, not proof. Returns how many findings were suppressed."""
        if not reputation.is_clean(self.vt_min_age_days):
            return 0
        count = 0
        for f in findings:
            if not f.suppressed and f.severity <= Severity.MEDIUM and f.rule_id[:3] != "VT-" \
                    and f.rule_id not in _NEVER_HIDDEN:
                f.suppress("VirusTotal: 0 of %d engines flag this file (known for %d days)"
                           % (reputation.total, reputation.age_days()))
                count += 1
        return count

    # -- a script that calls a library of the game ---------------------------------
    @staticmethod
    def library_file(f: Finding) -> str:
        """The file name of the library a ``Win32API.new`` declaration names -
        empty when this finding is not one that :meth:`own_library` may lower
        (not such a declaration, already judged, or a library of Windows)."""
        name = (f.context.get("library") or "").strip().lower()
        if f.rule_id != "RB-NATIVE-001" or f.suppressed or f.severity != Severity.MEDIUM or not name \
                or f.context.get("own_attributes") or name.strip(". ") != name:
            return ""
        if "." not in name:
            name += ".dll"                        # what Windows adds
        if not name.endswith(".dll") or name[:-4] in _SYSTEM_LIBRARIES:
            return ""
        return name

    def own_library(self, f: Finding, shown: str, inside: Iterable[Finding]) -> bool:
        """``Win32API.new("Name.dll", ...)`` where ``Name.dll`` lies in the
        game's folder: the call leads into a file this scan has read. Called
        by the scanner once the whole folder was scanned, with every finding
        ``inside`` that library (and what is packed in it) - so the answer
        does not depend on which of the two files was scanned first. Nothing
        is hidden: the declaration becomes a LOW note, and only when the
        library was read in full (the caller's part) and holds no "could not
        be read" note and no active finding of MEDIUM or higher."""
        if self.strict:
            return False
        for other in inside:
            if other.rule_id in _NEVER_HIDDEN or (not other.suppressed and other.severity >= Severity.MEDIUM):
                return False
        f.severity, f.confidence = Severity.LOW, min(f.confidence, 0.3)
        f.chainable = False
        f.reason += OWN_LIBRARY
        f.evidence += "  [calls the game's own library %s, read in full]" % shown[:80]
        return True

    # -- digital signatures --------------------------------------------------------
    def publisher_trusted(self, signer: str) -> bool:
        """Is this certificate subject on the trusted-publisher list?"""
        name = (signer or "").strip().lower()
        for trusted in self.trusted_publishers:
            if name == trusted or (name.startswith(trusted)
                                   and not name[len(trusted)].isalnum()):
                return True
        return False

    def lower_for_signature(self, f: Finding, signer: str) -> None:
        """A valid signature from a publisher that is NOT on the trusted list
        proves who signed the file, not that it is safe (certificates are
        bought and stolen). It earns one severity level, nothing more, and
        never touches CRITICAL findings, signature hits or reputation."""
        if self.strict or f.category in (Category.SIGNATURE, Category.REPUTATION):
            return
        who = signer or "an unnamed publisher"
        if f.severity in (Severity.HIGH, Severity.MEDIUM):
            f.severity = Severity(f.severity - 1)
            f.reason += (' The file has a valid signature from "%s", which is not on the '
                         'trusted-publisher list, so the severity was lowered one level.' % who)
        else:
            f.reason += ' The file has a valid signature from "%s".' % who

    def _signature(self, f: Finding, ctx: FileContext) -> bool:
        # (data in / behind the signature block is exactly what the signature does not
        # cover: a valid signature earns such a finding nothing)
        if ctx.signer is not None and not ctx.baseline and not f.rule_id.startswith("SIG-DATA-"):
            self.lower_for_signature(f, ctx.signer)
        return False

    # -- individual decisions (return True once the finding is suppressed) ----
    def _hash_allowlist(self, f: Finding, ctx: FileContext) -> bool:
        if ctx.sha256 in self.allowlist:
            return f.suppress("File SHA-256 is on the allowlist")
        return False

    @staticmethod
    def _comment(f: Finding, ctx: FileContext) -> bool:
        # CRITICAL patterns are reported even inside a comment: comment
        # detection is a lexer heuristic, and being wrong there must not be
        # able to hide the most dangerous findings
        if f.context.get("in_comment") and f.severity < Severity.CRITICAL:
            return f.suppress("Match is inside a comment / docstring, not executable code")
        # ... and a word inside a string literal or the text of a template of a JavaScript
        # file is no call site (rules.QuotedText; phageo, 2026-10-13). CRITICAL: as above.
        if f.context.get("in_text") and f.severity < Severity.CRITICAL:
            return f.suppress("Match is inside a quoted text of the script, not a call")
        return False

    @staticmethod
    def _same_declaration(f: Finding, ctx: FileContext) -> bool:
        """``Win32API.new(`` on a ``ShellExecute`` declaration whose calls were
        all read and lowered to ``RB-NATIVE-003`` (``RgssHandler._shell_execute``
        marks it): one declaration, one finding."""
        if f.rule_id == "RB-NATIVE-001" and f.context.get("same_declaration") == "RB-NATIVE-003":
            return f.suppress(SAME_DECLARATION)
        return False

    @staticmethod
    def _text_literal(f: Finding, ctx: FileContext) -> bool:
        """A call pattern on a line that is, as a whole, one string literal is
        text, not a call: a game that shows ``"os.remove(...)"`` on a fake
        console deletes nothing. As a statement such a line does nothing, and
        as an expression of a compiled Ren'Py script it is a piece of text.
        Not when the literal is part of something larger (an argument on its
        own line, a continued expression), not in a file that executes text
        at all (``exec`` / ``eval`` / ``compile`` ... - the text could be
        handed to it), and never for HIGH or CRITICAL findings."""
        if (f.severity > Severity.MEDIUM or f.context.get("language") != "python"
                or not f.context.get("whole_line") or f.context.get("resolved")
                or ctx.cache.get("runs_text", True)):
            return False
        line = f.context.get("code_line", "").strip()
        if len(line) < 2 or line[-1] not in "\"'" or line.lstrip("uUbBrR")[:1] not in ("\"", "'"):
            return False
        try:
            node = ast.parse(line, mode="eval").body
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False
        if not (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))):
            return False
        # nothing before it may still be open: brackets, a line continuation, an operator
        before = f.context.get("code_window", "")[:max(0, f.context.get("line_at", 0))]
        bare = _STRING_LITERAL.sub('""', before)
        if sum(bare.count(c) for c in "([{") != sum(bare.count(c) for c in ")]}"):
            return False
        previous = bare.rstrip()
        if previous and (previous[-1] in "\\,+-*/%=(<>[{.&|^"
                         or re.search(r"\b(?:and|or|not|in|is|return|yield|lambda|else|if)$", previous)):
            return False
        return f.suppress(TEXT_LITERAL)

    @staticmethod
    def _process_list(f: Finding, ctx: FileContext) -> bool:
        """``wmic process get Description`` / ``tasklist``: the script reads the
        names of the running programs. That is worth a note (games do it to
        notice recording software), not what ``wmic`` usually stands for.
        Decided on the command the payload resolver read at that line - every
        command there has to be exactly such a query, written out in full -
        and only in a file without any network call: a process list that could
        be sent somewhere keeps its level."""
        if f.rule_id not in ("LOL-001", "PY-PROC-001") or not f.line or f.context.get("in_comment"):
            return False
        flow = ctx.cache.get("dataflow")
        if not flow or flow.get("opaque") or ctx.cache.get("uses_network", True):
            return False
        commands = [value for line, value in flow["commands"] if line == f.line]
        if not commands or not all(_PROCESS_QUERY.fullmatch(c.strip()) for c in commands):
            return False
        if f.rule_id == "PY-PROC-001":
            return f.suppress(PROCESS_LIST_ONLY)
        f.rule_id, f.title = "PROC-LIST-001", "Reads the list of running programs"
        f.severity, f.confidence, f.chainable = Severity.LOW, 0.5, False
        f.reason = ("The script asks Windows for the names of the programs that are running "
                    "(a fixed query that only reads; the file makes no network call). Games do "
                    "this to notice recording or streaming software. Nothing is started or "
                    "changed, but it is information about your PC that a game does not need.")
        f.evidence = commands[0].strip()[:120]
        return False

    @staticmethod
    def _installed_name(f: Finding, ctx: FileContext) -> bool:
        """A download word or the name of a system tool in the texts of an Inno
        Setup installer, on a line that is, as a whole, the name of a file the
        installer installs
        (``{app}\\Examples\\DownloadFiles.iss``) is a file name, not an
        instruction: a LOW note. Only when the installer's ``[Code]`` was read to
        its end and names nothing that downloads - ``BaseHandler.installer_code``
        sets the names then, and never when the code could not be read. The same
        for an NSIS installer (phageo, 2026-10-17, fifty-ninth message): its
        instructions read to their end, nothing in them downloads, and the line is
        the name a ``File`` instruction writes (``nsis.installed_texts``)."""
        names = ctx.cache.get("installed_names")
        if not names or f.rule_id not in _NAME_RULES or f.severity >= Severity.CRITICAL \
                or not f.context.get("whole_line") or f.context.get("line_text", "").strip() not in names:
            return False
        f.severity, f.confidence = Severity.LOW, min(f.confidence, 0.3)
        f.context[FILE_NAME_ONLY] = True
        f.reason += FILE_NAME
        f.evidence += "  [file name, not an instruction]"
        return False

    @staticmethod
    def _standard_message(f: Finding, ctx: FileContext) -> bool:
        """The name of a system tool on a line of an Inno Setup installer's texts
        that is exactly a standard message of Inno Setup (``RegSvr32 failed with
        exit code %1``, in the installer's languages) is a LOW note: the text is
        Inno Setup's, in every installer made with it. ``BaseHandler.installer_code``
        sets the lines - those that come from the stored messages and from
        nowhere else; a custom message, a ``[Run]`` row or a text of the
        ``[Code]`` with the same word is never among them."""
        lines = ctx.cache.get("standard_messages")
        if not lines or f.rule_id != "LOL-001" or not f.context.get("whole_line") \
                or f.context.get("line_text", "").strip("\r\n") not in lines:
            return False
        f.severity, f.confidence, f.chainable = Severity.LOW, min(f.confidence, 0.3), False
        f.reason += STANDARD_MESSAGE
        f.evidence += "  [standard installer message]"
        return False

    @staticmethod
    def _code(f: Finding, key: str) -> str:
        """Context text with comments blanked (falls back to the raw text)."""
        return f.context.get("code_" + key) or f.context.get(
            {"line": "line_text", "window": "window"}[key], "")

    @staticmethod
    def _import_table(f: Finding, ctx: FileContext) -> bool:
        """An API name in a native binary only counts if it is really imported."""
        pe = ctx.pe
        match = f.context.get("match", "")
        if (pe is None or pe.is_dotnet or "api" not in f.tags
                or f.context.get("language") != "strings" or not _API_LIKE.match(match)):
            return False
        if (f.rule_id, match.lower()) in _EVERYDAY_IMPORTS:
            # games read the keyboard state, and every program with a text box imports
            # the clipboard: in an import table these say next to nothing
            f.severity = min(f.severity, Severity.LOW)
            f.reason += EVERYDAY_IMPORT
        if match in pe.import_names:
            f.confidence = max(f.confidence, 0.8)
            f.evidence += "  [confirmed in import table]"
            f.context[IN_IMPORT_TABLE] = True       # (more than a text among the strings)
            return False
        if ctx.cache.get("resolves_by_name"):
            # IL2CPP: C# "DllImport" functions are looked up by name at run time, so
            # the names of the Windows functions a game calls are strings, not imports
            f.confidence = min(f.confidence, 0.45)
            f.reason += (" (Not in the import table: an IL2CPP program finds the functions "
                         "its C# code calls by name, at run time.)")
            return False
        if pe.packed or ctx.truncated or not pe.has_import_dir:
            f.confidence = min(f.confidence, 0.35)
            f.reason += " (Not in the import table, but the table cannot be trusted for this binary.)"
            return False
        return f.suppress("API name appears only as a string; it is not in the PE import table")

    def _benign_domain(self, f: Finding, ctx: FileContext) -> bool:
        if "url" not in f.tags:
            return False
        # Judge the host the URL really goes to. "http://127.0.0.1:80@evil.net/"
        # and "https://github.com:443@evil.net/" both go to evil.net: everything
        # before the "@" is just a user name.
        match, line = f.context.get("match", ""), f.context.get("line_text", "")
        at = line.find(match) if match else -1
        full = _URL.match(line, at) if at != -1 else None
        url = full.group(0) if full else match
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            return False
        if not host:
            return False
        if "@" in parts.netloc:
            f.reason += " The address hides its real destination behind a user-name part."
            f.confidence = max(f.confidence, 0.7)
            return False
        if host == "localhost":
            return f.suppress("Loopback address (localhost)")
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_unspecified:
                return f.suppress("Loopback / private-network address")
            return False
        except ValueError:
            pass
        host = host.rstrip("0123456789")   # binary strings run into the next byte
        labels = host.split(".")
        if f.context.get("language") == "strings" and (
                len(labels) < 2 or (labels[0] == "www" and len(labels) < 3)):
            # "http://whether", "http://www.years": word lists inside a binary (every
            # program that contains the Brotli dictionary has hundreds of them)
            return f.suppress("Not an address: there is no domain name in it")
        for dom in self.benign_domains:
            if host == dom or host.endswith("." + dom):
                return f.suppress("Domain is on the benign allowlist (%s)" % dom)
        return False

    @staticmethod
    def _embedded_asset(f: Finding, ctx: FileContext) -> bool:
        if "blob" not in f.tags:
            return False
        raw = f.context.get("match", "").strip("'\"`")
        try:
            if re.fullmatch(r"[0-9a-fA-F]+", raw):
                head = bytes.fromhex(raw[:64])
            else:
                head = base64.b64decode(raw[:64])
        except (ValueError, binascii.Error):
            return False
        for magic, kind in _ASSET_MAGIC:
            if head.startswith(magic):
                return f.suppress("Blob decodes to an embedded asset (%s)" % kind)
        if head[:2] == b"MZ":
            f.severity = Severity.HIGH
            f.confidence = 0.9
            f.title = "Embedded Windows executable (encoded blob)"
            f.reason = "The encoded string decodes to a Windows program (MZ header)."
        return False

    @staticmethod
    def _data_write(f: Finding, ctx: FileContext) -> bool:
        """A Node.js write that only puts a data file into the game's own
        folder (:mod:`gamescan.dataflow.jswrites` read the place, the kind and
        the name from the script) is a LOW note. Never a file the engine reads
        as code or configuration - ``package.json``, ``plugins.js``, RPG Maker's
        data files - and never a deletion, a rename or a copy."""
        if f.rule_id != "JS-FS-001" or not f.line or f.context.get("in_comment"):
            return False
        name = (ctx.cache.get("js_data_writes") or {}).get(f.line)
        if not name or not re.match(r"fs\.(?:writeFile|appendFile)", f.context.get("match", "")):
            return False
        f.severity, f.confidence = Severity.LOW, min(f.confidence, 0.3)
        f.tags = tuple(t for t in f.tags if t != "delete")
        f.chainable = False
        f.reason += DATA_WRITE
        f.evidence += "  [writes the data file %s in the game's own folder]" % name[:60]
        return False

    @staticmethod
    def _written_text(f: Finding, ctx: FileContext) -> bool:
        """A dense string that the script does nothing with but write it into a
        file of the game - ``open(config.basedir + "/name", "w").write("...")``,
        the literal standing right in the call - is a LOW note: a puzzle text
        for the player, in games that leave files behind. Only for a file name
        without an extension or with ``.txt``, directly in the game's folders;
        and not in a script that executes text at all, which could read the
        file back."""
        if f.rule_id != "ENT-STR-001" or f.context.get("language") != "python" \
                or ctx.cache.get("runs_text", True):
            return False
        if not f.context.get("line_from_start"):
            return False
        opened = _WRITES_TEXT.search(f.context.get("before", ""))
        if not opened or not re.fullmatch(r"\s*\)\s*", f.context.get("after", "x")):
            return False
        name = opened.group(2)
        leaf = name.rsplit("/", 1)[-1]
        if ".." in name or not leaf or ("." in leaf and not leaf.lower().endswith(".txt")):
            return False
        f.severity, f.confidence, f.chainable = Severity.LOW, min(f.confidence, 0.3), False
        f.reason += WRITTEN_TEXT
        return False

    @staticmethod
    def natural_text(body: str) -> bool:
        """Is the literal a sentence in Japanese, Chinese or Korean writing?
        Such prose measures like random data - thousands of different
        characters - and is not. All of this has to hold: every character is
        from the blocks of that writing or is ASCII (text tags like ``{b}``
        are not counted); ``NATURAL_SHARE`` of them are from those blocks,
        fullwidth letters and digits counting as the ASCII they stand for; no
        long run of letters and digits (a Base64 piece inside the sentence);
        it has what written language has - kana, Hangul or sentence
        punctuation - and no long run of ideographs without any of it."""
        bare = "".join(_TEXT_TAG.sub("", body).split())
        if not bare:
            return False
        folded = unicodedata.normalize("NFKC", bare)
        if _ASCII_RUN.search(folded):
            return False
        native = run = 0
        marked = False
        for char in bare:
            code = ord(char)
            if 0x21 <= code <= 0x7E:
                run = 0
                continue
            if not any(low <= code <= high for low, high in _CJK_BLOCKS):
                return False                     # a character of any other block
            if unicodedata.normalize("NFKC", char).isascii() and unicodedata.category(char)[0] in "LN":
                run = 0
                continue                         # a fullwidth letter or digit
            native += 1
            if char in _TEXT_PUNCTUATION or any(low <= code <= high for low, high in _TEXT_MARKERS):
                marked, run = True, 0
            elif _IDEOGRAPH[0] <= code <= _IDEOGRAPH[1]:
                run += 1
                if run > _MAX_IDEOGRAPH_RUN:
                    return False
        return marked and native >= NATURAL_SHARE * len(bare)

    @staticmethod
    def _natural_text(f: Finding, ctx: FileContext) -> bool:
        """A dense string literal that is a sentence in Japanese, Chinese or
        Korean writing (a game's translation file is full of them) is text,
        not a payload. ``ENT-STR-001`` only, never above MEDIUM, and only in
        a script that executes no text and names no decoder anywhere - a file
        nobody looked at for those two is left alone."""
        if (f.rule_id != "ENT-STR-001" or f.severity > Severity.MEDIUM
                or f.context.get("language") != "python"
                or ctx.cache.get("runs_text", True) or ctx.cache.get("decodes_text", True)):
            return False
        literal = f.context.get("match", "")
        if len(literal) < 2 or not ContextEngine.natural_text(literal[1:-1]):
            return False
        return f.suppress(NATURAL_TEXT)

    @staticmethod
    def _own_lock_file(f: Finding, ctx: FileContext) -> bool:
        """The "only one copy of the game at a time" helper: it creates
        ``%TEMP%/<program>.lock``, and removes that file again. Decided on the
        path the payload resolver worked out, never on a variable's name."""
        if f.context.get("language") not in ("python", "renpy"):
            return False
        if f.rule_id == "DF-PATH-001" and "delete" not in f.tags:
            from .handlers.base import OWN_LOCK_PATH
            if OWN_LOCK_PATH.fullmatch(f.context.get("match", "")) and "[decoded]" not in f.evidence:
                return f.suppress(OWN_LOCK)
            return False
        if f.rule_id != "PY-FS-001":
            return False
        locks = (ctx.cache.get("dataflow") or {}).get("own_locks")
        deleted = _DELETES_NAME.search(ContextEngine._code(f, "line"))
        if locks and deleted and deleted.group(1) in locks:
            return f.suppress(OWN_LOCK)
        return False

    @staticmethod
    def _deletion_target(f: Finding, ctx: FileContext) -> bool:
        if "delete" not in f.tags:
            return False
        # all of these look at code only - a comment saying "cache" proves nothing
        line, window = ContextEngine._code(f, "line"), ContextEngine._code(f, "window")
        if _DANGER_DELETE.search(line):
            f.severity = max(f.severity, Severity.HIGH)
            f.confidence = max(f.confidence, 0.8)
            f.reason += " The target resolves to a user-profile or system location outside the game."
            return False
        if f.rule_id == "RB-FS-001" and f.context.get("own_delete") and not _DANGER_DELETE.search(window):
            # every path this call can delete was read (remote_rb.own_deletes): files in a
            # folder of the game itself, none of them a program or part of the engine
            f.evidence += "  [deletes only: %s]" % "; ".join(f.context["own_delete"])[:160]
            return f.suppress("Target resolves to the game's own save / cache / temp data")
        if (_SAFE_DELETE_API.search(window) or _SAFE_DELETE_WORD.search(line)) \
                and not _DANGER_DELETE.search(window):
            return f.suppress("Target resolves to the game's own save / cache / temp data")
        return False

    @staticmethod
    def _save_encoding(f: Finding, ctx: FileContext) -> bool:
        if "decode" not in f.tags:
            return False
        window = ContextEngine._code(f, "window")
        if _SAVE_CONTEXT.search(window) and not _CODE_SINK.search(window):
            return f.suppress("Decoding is used for save / settings data (legitimate save encoding)")
        return False

    @staticmethod
    def _benign_spawn(f: Finding, ctx: FileContext) -> bool:
        line = ContextEngine._code(f, "line")
        if ("spawn" in f.tags and _BENIGN_SPAWN.search(line)) or (
                f.rule_id == "RB-PROC-001" and _RUBY_EXPLORER.search(line)) or (
                f.rule_id == "DF-CMD-001" and f.context.get("language") == "ruby"
                and _EXPLORER.fullmatch(f.context.get("match", "").strip())):
            return f.suppress("Only opens a folder / document with the system file manager")
        # The usual way an NW.js game opens a web page: it hands an address to
        # the system's URL handler. This is decided on the commands the payload
        # resolver reconstructed, never on what the surrounding text looks like:
        # every process launch in the file must have been read, and every one
        # must be nothing but "open this address".
        flow = ctx.cache.get("dataflow")
        if not flow or f.rule_id not in ("LOL-001", "JS-PROC-001", "DF-CMD-001"):
            return False
        if f.rule_id == "DF-CMD-001":
            commands = [f.context.get("match", "")]
        elif f.rule_id == "LOL-001":
            commands = [value for line, value in flow["commands"] if line and line == f.line]
        else:
            commands = [] if flow["opaque"] else [value for _line, value in flow["commands"]]
        if commands and all(_OPEN_URL.fullmatch(c.strip()) for c in commands):
            return f.suppress("Only opens a web address with the default browser")
        return False

    @staticmethod
    def _local_load(f: Finding, ctx: FileContext) -> bool:
        if "netload" not in f.tags:
            return False
        window = ContextEngine._code(f, "window")
        if _LOCAL_LOAD.search(window) and not re.search(r"https?://|wss?://", window, re.I):
            return f.suppress("Request loads a local game data file, not a remote resource")
        return False

    @staticmethod
    def _rgss_api(f: Finding, ctx: FileContext) -> bool:
        """RPG Maker XP/VX/Ace scripts call a small set of Windows functions all
        the time (window size, key state, .ini settings). Those are not threats."""
        if f.context.get("language") != "ruby":
            return False
        line = ContextEngine._code(f, "line")
        if f.rule_id == "RB-NATIVE-001" and f.context.get("own_attributes") and f.severity <= Severity.MEDIUM:
            # SetFileAttributes, every call read (remote_rb.own_attributes): shown, as a note
            f.severity, f.confidence = Severity.LOW, min(f.confidence, 0.3)
            f.chainable = False
            f.reason += OWN_ATTRIBUTES
            f.evidence += "  [hides or shows only: %s]" % "; ".join(f.context["own_attributes"])[:160]
            return False
        if ("rgss-api" in f.tags and "RtlMoveMemory" in line
                and not _RGSS_DANGER.search(line.replace("RtlMoveMemory", ""))):
            # Copying bytes (the widespread "save a Bitmap" snippet) is reported,
            # but it runs nothing by itself: a loader also needs executable
            # memory or a thread, and those calls still form chains.
            f.chainable = False
        if "rgss-api" in f.tags and _RGSS_HELPER.search(line) and not _RGSS_DANGER.search(line):
            return f.suppress("Common RPG Maker helper API (window, input or settings)")
        if f.rule_id == "INPUT-001" and f.context.get("match", "").lower() in (
                _IND[1], "getkeyboardstate"):
            return f.suppress("Keyboard state is read for in-game input (RPG Maker script)")
        return False

    @staticmethod
    def _by_flow(f: Finding, ctx: FileContext) -> bool:
        """Severity by flow, not mention (phageo, 2026-10-14) - in a JavaScript file, by what the
        data-flow reading knows about the file's process starts (``remote.starts``):

        * ``LOL-001`` - the name of a system tool in a text - stays HIGH when the name reaches
          a process start: it stands in a command the file starts, or the file has a start
          whose command is not written out (the text may be what is started). In a file whose
          starts are all written out and do not name it - or that starts nothing - it is a
          word: MEDIUM.
        * ``JS-PROC-001`` - the script can start programs - stays HIGH unless every start of
          the file is a constant program with constant arguments and no shell: then MEDIUM.
          A script runtime as the program (``cmd``, ``powershell``, ``node`` ...), a shell, or
          an argument that is not written out keep it HIGH; so does a file that asks for
          ``child_process``, keeps it, and shows no start. (A file that asks for it in a
          statement of its own and throws the result away starts nothing: MEDIUM.)

        Lowered, never hidden; the chains are made as before (they do not look at levels).
        Nothing is lowered when the reading failed or stopped at a limit."""
        if f.rule_id not in ("LOL-001", "JS-PROC-001") or f.severity is not Severity.HIGH or not f.line \
                or f.context.get("language") != "js" or ctx.ext not in (".js", ".mjs", ".cjs") \
                or f.context.get("in_comment") or f.context.get("in_text"):
            return False
        found, flow = ctx.cache.get("js_starts"), ctx.cache.get("dataflow")
        # (the script asks for child_process in a statement of its own and throws the result
        # away - what a bundler leaves behind -, and starts nothing: it cannot start anything)
        unused = bool(ctx.cache.get("js_asks_only")) and found == []
        if found is None or flow is None or ctx.cache.get("tracer_cut") or (flow.get("opaque") and not unused):
            return False                                 # not known: stays as it is
        if f.rule_id == "JS-PROC-001":
            match = f.context.get("match", "")
            if "binding" in match or "mainModule" in match:
                return False
            if unused:
                f.severity = Severity.MEDIUM
                f.reason += (" This script asks for the module and does not use it: it starts "
                             "no program, so the level is lowered.")
                return False
            if not found or any(start.kind != "constant" and not start.local for start in found):
                return False
            f.severity = Severity.MEDIUM
            if all(start.kind == "constant" for start in found):
                f.reason += (" Every program this script starts is written out in it - a fixed program "
                             "with fixed arguments, without a shell - so the level is lowered.")
            else:
                # (phageo, 2026-10-14: what is not written out comes from the app itself - its
                # folder, this PC's settings, environment variables -, not from outside)
                f.reason += LOCAL_STARTS
            return False
        name = re.split(r"[\s./]", f.context.get("match", "").strip().lower())[0]
        if not name or any(not start.known and not start.local for start in found):
            return False
        commands = [value.lower() for _line, value in flow.get("commands", ())] + [start.text for start in found]
        if any(name in command for command in commands):
            return False                                 # the name is in something that is started
        f.severity = Severity.MEDIUM
        f.reason += (" In this script the name stands in a text that reaches no place where a "
                     "program is started, so the level is lowered.")
        return False

    def _baseline(self, f: Finding, ctx: FileContext) -> bool:
        if f.rule_id in _NEVER_HIDDEN:
            return False
        if NPM_VERIFIED in ctx.baseline and (f.rule_id.startswith("CHAIN-") or f.rule_id in _CAPABILITIES):
            # A file of a published npm package: that proves where it comes from, not what
            # it is used for (phageo, 2026-10-14 - real samples are built from published
            # packages, the dangerous parts included). Its single pattern findings are
            # lowered; what the file adds up to - a chain - and what it is able to do - an
            # add-on that decrypts stored secrets - stay as they are.
            return False
        if f.context.get("unverified_part"):
            # found in the part of a file that its acceptance does not cover (the resources
            # of a launcher compared without them, data appended to it)
            return False
        if ctx.baseline and not self.strict and f.severity < Severity.CRITICAL:
            # A file trusted for the folder it sits in and the name it carries
            # (js/libs/effekseer.min.js) is trusted for something a repack can
            # imitate. Like a CRITICAL finding, a loader of code from an address
            # that is not shown stays visible there. A valid trusted signature or
            # the hash of an official build is proof of origin and still covers it.
            if f.rule_id in _SHOWN_IN_NAMED_BASELINES and not ctx.baseline.startswith(_PROVEN):
                return False
            return f.suppress("Engine / library baseline: %s" % ctx.baseline)
        return False
