"""Data model: severities, categories, findings, per-file context, the report."""
from __future__ import annotations

import enum
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import advice

TOOL_NAME = "Bagel"
# the one place of the version: window, reports, the CLI and tools/build_package.py read it
TOOL_VERSION = "0.9.0-beta"
# the "Protection" window and real-time protection (protection.py, monitor.py): never tested -
# hidden in 0.9-beta and left out of its package (phageo, 2026-10-24); the code stays, off
EXPERIMENTAL_PROTECTION = False


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Category(str, enum.Enum):
    EXECUTION = "EXECUTION"          # dynamic code execution / injection
    OBFUSCATION = "OBFUSCATION"      # encoded or hidden payloads
    PROCESS = "PROCESS"              # subprocess / interpreter spawning
    NETWORK = "NETWORK"              # sockets, HTTP, exfiltration endpoints
    FILESYSTEM = "FILESYSTEM"        # deletion / tampering
    PERSISTENCE = "PERSISTENCE"      # autoruns, services, scheduled tasks
    CREDENTIALS = "CREDENTIALS"      # browser / wallet / token stores
    INPUT_CAPTURE = "INPUT_CAPTURE"  # keylogging, screen, clipboard
    PACKING = "PACKING"              # packers / protectors
    EVASION = "EVASION"              # AV tampering, disguise, anti-analysis
    SIGNATURE = "SIGNATURE"          # YARA signature match
    REPUTATION = "REPUTATION"        # external verdict (VirusTotal)
    CHAIN = "CHAIN"                  # cross-signal attack chain


@dataclass
class Finding:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    file: str                 # path relative to the scan root
    line: Optional[int]       # None for binary / file-level findings
    snippet: str
    evidence: str
    confidence: float         # 0.0 - 1.0
    reason: str
    handler: str = ""
    sha256: str = ""
    path: str = ""            # absolute path on disk
    suppressed: bool = False
    suppression_reason: str = ""
    quarantined: bool = False  # the file was moved to quarantine
    is_new: bool = False       # not present in the previous scan of this target
    base_confidence: Optional[float] = None   # confidence before learning adjusted it
    learned: str = ""          # "confirmed", or "<false positives>/<confirmed>" for the rule
    chainable: bool = True
    tags: tuple = ()
    context: Dict[str, Any] = field(default_factory=dict, repr=False)

    def suppress(self, reason: str) -> bool:
        self.suppressed = True
        self.suppression_reason = reason
        return True

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        try:
            category = Category(d.get("category", "SIGNATURE"))
        except ValueError:
            category = Category.SIGNATURE
        return cls(
            rule_id=str(d.get("rule_id", "?")), title=str(d.get("title", "")),
            category=category, severity=Severity[d.get("severity", "LOW")],
            file=str(d.get("file", "")), line=d.get("line"), snippet=str(d.get("snippet", "")),
            evidence=str(d.get("evidence", "")), confidence=float(d.get("confidence", 0.5)),
            reason=str(d.get("reason", "")), handler=str(d.get("handler", "")),
            sha256=str(d.get("sha256", "")), path=str(d.get("path", "")),
            suppressed=bool(d.get("suppressed")),
            suppression_reason=str(d.get("suppression_reason", "")),
            quarantined=bool(d.get("quarantined")), is_new=bool(d.get("new")),
            base_confidence=d.get("base_confidence"), learned=str(d.get("learned", "")),
            chainable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.name,
            "confidence": round(self.confidence, 2),
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "evidence": self.evidence,
            "reason": self.reason,
            "handler": self.handler,
            "sha256": self.sha256,
            "path": self.path,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "quarantined": self.quarantined,
            "advice": advice.for_finding(self.rule_id, self.category.value),
            "new": self.is_new,
            "base_confidence": (None if self.base_confidence is None
                                else round(self.base_confidence, 2)),
            "learned": self.learned,
        }


@dataclass
class FileContext:
    """Everything a handler / the ContextEngine may need to know about a file."""

    path: str                 # absolute path on disk (the archive, for members)
    relpath: str              # display path, forward slashes
    data: bytes
    size: int = 0
    sha256: str = ""
    pe: Any = None            # pe.PEInfo when the file is a parsable PE
    truncated: bool = False   # only the first Scanner.max_bytes were loaded
    baseline: str = ""        # non-empty => known engine/library file (why)
    signer: Optional[str] = None   # publisher of a valid signature NOT on the trusted list
    cache: Dict[str, Any] = field(default_factory=dict, repr=False)  # handler scratch
    cancel: Any = field(default=None, repr=False)   # threading.Event: stop long work early
    progress: Any = field(default=None, repr=False)  # callable(fraction): work on this file
    _text: Optional[str] = field(default=None, repr=False)

    @property
    def key(self) -> str:
        return self.relpath.lower()

    @property
    def name(self) -> str:
        return self.key.replace("!", "/").rsplit("/", 1)[-1]

    @property
    def ext(self) -> str:
        return os.path.splitext(self.name)[1]

    @property
    def is_pe(self) -> bool:
        return self.data[:2] == b"MZ"

    @property
    def on_disk(self) -> bool:
        """Can the whole content be read from ``path``? True for a file of the
        scan target and for an archive member that was unpacked to a temporary
        file; False for a member that only exists in memory."""
        return ("!" not in self.relpath or bool(self.cache.get("spooled"))) \
            and os.path.isfile(self.path)

    def tick(self, fraction: float) -> None:
        """Report how far the work on this (large) file has got, 0.0 - 1.0."""
        if self.progress is not None:
            self.progress(fraction)

    @property
    def cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def text(self) -> str:
        if self._text is None:
            raw = self.data
            sample = raw[:4096]
            if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                txt = raw.decode("utf-16", "replace")
            elif len(sample) >= 8 and sample[1::2].count(0) > len(sample) * 0.3:
                txt = raw.decode("utf-16-le", "replace")     # UTF-16 without a BOM
            elif len(sample) >= 8 and sample[0::2].count(0) > len(sample) * 0.3:
                txt = raw.decode("utf-16-be", "replace")
            else:
                try:
                    txt = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    txt = raw.decode("latin-1")
            txt = txt.replace("\r\n", "\n").replace("\r", "\n")
            if len(txt) > MAX_DECODED // 4:
                # Python keeps a text in 1, 2 or 4 bytes a character, by its widest one (an emoji
                # makes it 4), and the readings hold several copies of it at once: a text of more
                # than MAX_DECODED bytes is read up to there, and the scan says so (TEXT_CUT;
                # phageo, 2026-10-17, fifty-ninth message)
                widest = ord(max(txt))
                width = 1 if widest < 0x100 else 2 if widest < 0x10000 else 4
                if len(txt) * width > MAX_DECODED:
                    keep = MAX_DECODED // width
                    self.cache[TEXT_CUT] = (keep, len(txt), width, MAX_DECODED)
                    txt = txt[:keep]
            self._text = txt
        return self._text


# what one decoded text may take in memory (FileContext.text): with the copies the readings make
# of it, a scan stays under 2 GB (measured on 2026-10-17: a script of 94 MB decoded - 47 million
# characters at 2 bytes - took 1.5 GB in all)
MAX_DECODED = 128 << 20
TEXT_CUT = "text_cut"           # FileContext.cache: (characters read, in all, bytes a character, the bound)


# ARC-002: said wherever an archive or installer (or a part of one) could not be read
NOT_INSPECTED = ("Part of this archive could not be unpacked, so what is inside was not "
                 "inspected. A file whose content was not read is never reported as clean - "
                 "also not when it carries a valid signature: a signature says who made the "
                 "file, not what is in it.")

_VERDICTS = {
    None: ("CLEAN", "No suspicious behaviour found"),
    Severity.LOW: ("LIKELY SAFE", "Only low-severity signals"),
    Severity.MEDIUM: ("REVIEW", "Some behaviour deserves a manual look"),
    Severity.HIGH: ("SUSPICIOUS", "High-risk behaviour detected"),
    Severity.CRITICAL: ("DANGEROUS", "Malware-like behaviour detected"),
}
# Content that could not be read - a password archive, a part that was not unpacked, an asar
# that was not read, compiled JavaScript - never gives LIKELY SAFE or CLEAN: the verdict is at
# least REVIEW (phageo, 2026-10-12). The notes themselves stay LOW; it is the verdict that says
# "this was not all seen".
UNREAD_CONTENT = frozenset({"ARC-001", "ARC-002", "JSC-FMT-001", "EXEC-FMT-001"})
UNREAD_DETAIL = "Part of the content could not be read"
# packed code (rules.py cuts it into statements, chains.py asks for the same statement)
PACKED = "packed_lines"            # FileContext.cache: the numbers of the lines that are packed code
STATEMENT = "statement"            # Finding.context: which statement of the file a finding stands in
_WEIGHT = {Severity.LOW: 1, Severity.MEDIUM: 4, Severity.HIGH: 12, Severity.CRITICAL: 30}


@dataclass
class ScanReport:
    target: str
    strict: bool = False
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    bytes_total: int = 0      # of every file in the scan, read or not (since 2026-10-12)
    cancelled: bool = False
    engines: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    quarantined: List[Dict[str, Any]] = field(default_factory=list)
    loaded: bool = False      # rebuilt from a JSON file: its paths and hashes are unverified
    _duration: Optional[float] = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, doc: Dict[str, Any]) -> "ScanReport":
        """Rebuild a report from its JSON form (see :meth:`to_dict`)."""
        if not isinstance(doc, dict) or "findings" not in doc:
            raise ValueError("not a Bagel report")

        def stamp(key: str) -> float:
            try:
                return time.mktime(time.strptime(doc.get(key, ""), "%Y-%m-%dT%H:%M:%S"))
            except (ValueError, TypeError):
                return 0.0

        stats = doc.get("stats", {})
        report = cls(
            target=str(doc.get("target", "")), strict=bool(doc.get("strict")),
            started_at=stamp("started_at"), finished_at=stamp("finished_at"),
            files_total=int(stats.get("files_total", 0)),
            files_scanned=int(stats.get("files_scanned", 0)),
            files_skipped=int(stats.get("files_skipped", 0)),
            bytes_scanned=int(stats.get("bytes_scanned", 0)),
            bytes_total=int(stats.get("bytes_total", 0)),
            cancelled=bool(doc.get("cancelled")), engines=list(doc.get("engines", [])),
            errors=list(doc.get("errors", [])), notes=list(doc.get("notes", [])),
            quarantined=list(doc.get("quarantined", [])), loaded=True,
            _duration=float(doc.get("duration_seconds", 0.0)))
        for item in list(doc.get("findings", [])) + list(doc.get("suppressed", [])):
            report.findings.append(Finding.from_dict(item))
        return report

    @classmethod
    def load(cls, path: str) -> "ScanReport":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @property
    def active(self) -> List[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed(self) -> List[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.active), default=None)

    @property
    def coverage(self) -> float:
        """The share of the scanned folder's bytes that lie in files a reader opened
        (1.0 when nothing was counted - a report from before 2026-10-12, a single text)."""
        if self.bytes_total <= 0:
            return 1.0
        return min(1.0, self.bytes_scanned / self.bytes_total)

    @property
    def unread_only(self) -> bool:
        """Nothing above LOW was found, but content could not be read (`UNREAD_CONTENT`):
        the verdict is REVIEW for that reason alone."""
        worst = self.max_severity
        return (worst is None or worst is Severity.LOW) and any(
            f.rule_id in UNREAD_CONTENT for f in self.active)

    @property
    def verdict(self) -> str:
        return "REVIEW" if self.unread_only else _VERDICTS[self.max_severity][0]

    @property
    def verdict_detail(self) -> str:
        return UNREAD_DETAIL if self.unread_only else _VERDICTS[self.max_severity][1]

    def plain_verdict_parts(self) -> Tuple[str, int]:
        """``(kind, files)`` behind the one-sentence verdict: kind is ``safe``,
        ``unusual``, ``caution`` or ``danger``; files is how many distinct
        files have findings at that level or above."""
        worst = self.max_severity
        if self.unread_only:
            return "unread", len({f.file for f in self.active if f.rule_id in UNREAD_CONTENT})
        if worst is None or worst is Severity.LOW:
            return "safe", 0
        files = len({f.file for f in self.active if f.severity >= worst})
        kind = {Severity.MEDIUM: "unusual", Severity.HIGH: "caution",
                Severity.CRITICAL: "danger"}[worst]
        return kind, files

    @property
    def is_pc_scan(self) -> bool:
        """Quick / full / system scans have a label, not a path, as their target."""
        return not os.path.isabs(self.target)

    @property
    def plain_verdict(self) -> str:
        """One sentence a non-technical user can act on."""
        kind, files = self.plain_verdict_parts()
        if kind == "unread":
            return ("Not fully checked: %d file(s) could not be read - run it only if you trust "
                    "where it came from" % files)
        if kind == "safe":
            return "No clear signs of danger found"
        if kind == "unusual":
            return ("Probably fine: %d file(s) do something unusual - worth a quick look"
                    % files)
        if kind == "caution":
            return "Caution: %d suspicious file(s) - review before running" % files
        if self.is_pc_scan:
            return "Do not run the %d flagged file(s)" % files
        return "Do not run this game"

    @property
    def risk_score(self) -> int:
        return min(100, round(sum(_WEIGHT[f.severity] * f.confidence for f in self.active)))

    @property
    def duration(self) -> float:
        if self._duration is not None:
            return self._duration
        return max(0.0, (self.finished_at or time.time()) - self.started_at)

    def counts(self) -> Dict[str, int]:
        out = {s.name: 0 for s in reversed(Severity)}
        for f in self.active:
            out[f.severity.name] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        for f in self.active:
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
        order = lambda f: (-f.severity, -f.confidence, f.file, f.line or 0)
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))
        mx = self.max_severity
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "target": self.target,
            "strict": self.strict,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at or time.time()),
            "duration_seconds": round(self.duration, 3),
            "cancelled": self.cancelled,
            "verdict": self.verdict,
            "verdict_detail": self.verdict_detail,
            "verdict_plain": self.plain_verdict,
            "max_severity": mx.name if mx else None,
            "risk_score": self.risk_score,
            "engines": self.engines,
            "stats": {
                "files_total": self.files_total,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "bytes_scanned": self.bytes_scanned,
                "bytes_total": self.bytes_total,
                "coverage": round(self.coverage, 4),
                "findings": len(self.active),
                "suppressed": len(self.suppressed),
                "by_severity": self.counts(),
                "by_category": by_cat,
            },
            "findings": [f.to_dict() for f in sorted(self.active, key=order)],
            "suppressed": [f.to_dict() for f in sorted(self.suppressed, key=order)],
            "errors": self.errors,
            "notes": self.notes,
            "quarantined": self.quarantined,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
