"""The memory center: a local SQLite database of what the scanner has seen
and what it was told about it.

Three tables:

``scans``         one row per finished scan (target, verdict, risk, ...)
``observations``  every finding of those scans: the code snippet, the engine
                  context (handler), severity, and how it was decided
``feedback``      resolutions - "this was a false positive" / "this was a real
                  threat" - from the user or from an external verdict

Everything stays on this machine. The :class:`~gamescan.context.ContextEngine`
reads the feedback to adjust rule confidence; nothing here executes or
changes a rule by itself.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
from contextlib import closing
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding, ScanReport

_SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY, time REAL NOT NULL, target TEXT NOT NULL, verdict TEXT,
    risk INTEGER, files INTEGER, findings INTEGER, suppressed INTEGER, duration REAL,
    engines TEXT, strict INTEGER);
CREATE TABLE IF NOT EXISTS observations(
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL, engine TEXT, category TEXT,
    severity TEXT, confidence REAL, file TEXT, line INTEGER, snippet TEXT, evidence TEXT,
    sha256 TEXT, suppressed INTEGER, suppression_reason TEXT);
CREATE INDEX IF NOT EXISTS obs_fingerprint ON observations(fingerprint);
CREATE INDEX IF NOT EXISTS obs_scan ON observations(scan_id);
CREATE TABLE IF NOT EXISTS feedback(
    id INTEGER PRIMARY KEY, time REAL NOT NULL, fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL, engine TEXT, label TEXT NOT NULL CHECK(label IN ('fp', 'tp')),
    source TEXT NOT NULL, weight REAL NOT NULL, file TEXT, snippet TEXT);
CREATE INDEX IF NOT EXISTS fb_fingerprint ON feedback(fingerprint);
CREATE INDEX IF NOT EXISTS fb_rule ON feedback(rule_id, engine);
"""
_KEEP_SCANS = 300
_MAX_OBSERVATIONS = 5000
_SPACE = re.compile(r"\s+")

RuleKey = Tuple[str, str]                       # (rule id, engine / handler)


def fingerprint(finding: Finding) -> str:
    """Identity of a finding independent of where it was found: the rule plus
    the whitespace-normalised code it matched. The same line in another file
    or another game has the same fingerprint."""
    body = _SPACE.sub(" ", (finding.snippet or finding.evidence).strip())
    return hashlib.sha256(("%s\0%s" % (finding.rule_id, body)).encode("utf-8", "replace")).hexdigest()[:32]


class RuleStats:
    """Feedback totals for one (rule, engine)."""

    __slots__ = ("fp", "tp", "fp_count", "tp_count")

    def __init__(self) -> None:
        self.fp = self.tp = 0.0          # time-decayed, source-weighted
        self.fp_count = self.tp_count = 0


class MemoryCenter:
    half_life_days = 180.0               # old feedback counts for less

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or self.default_path()
        folder = os.path.dirname(self.path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.executescript(_SCHEMA)
            con.execute("PRAGMA user_version = %d" % _SCHEMA_VERSION)

    @staticmethod
    def default_path() -> str:
        return os.path.join(os.path.expanduser("~"), ".game_safety_scanner", "memory.db")

    def _connect(self) -> sqlite3.Connection:
        # one short-lived connection per operation: safe from any thread
        con = sqlite3.connect(self.path, timeout=10)
        con.execute("PRAGMA foreign_keys = ON")
        return con

    # -- scans and observations --------------------------------------------------
    def record_scan(self, report: ScanReport) -> int:
        """Store a finished scan with all of its findings; returns the scan id."""
        rows = [(fingerprint(f), f.rule_id, f.handler, f.category.value, f.severity.name,
                 f.confidence, f.file, f.line, f.snippet[:500], f.evidence[:300], f.sha256,
                 int(f.suppressed), f.suppression_reason)
                for f in report.findings[:_MAX_OBSERVATIONS]]
        with closing(self._connect()) as con, con:
            cur = con.execute(
                "INSERT INTO scans(time, target, verdict, risk, files, findings, suppressed,"
                " duration, engines, strict) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (report.finished_at or time.time(), report.target, report.verdict,
                 report.risk_score, report.files_scanned, len(report.active),
                 len(report.suppressed), report.duration, ", ".join(report.engines),
                 int(report.strict)))
            scan_id = cur.lastrowid
            con.executemany(
                "INSERT INTO observations(scan_id, fingerprint, rule_id, engine, category,"
                " severity, confidence, file, line, snippet, evidence, sha256, suppressed,"
                " suppression_reason) VALUES (%d,?,?,?,?,?,?,?,?,?,?,?,?,?)" % scan_id, rows)
            con.execute("DELETE FROM scans WHERE id NOT IN "
                        "(SELECT id FROM scans ORDER BY id DESC LIMIT %d)" % _KEEP_SCANS)
        return scan_id

    def previous_fingerprints(self, target: str) -> Optional[Set[str]]:
        """Fingerprints seen in the last scan of ``target`` (None = never scanned)."""
        with closing(self._connect()) as con:
            row = con.execute("SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1",
                              (target,)).fetchone()
            if row is None:
                return None
            return {r[0] for r in con.execute(
                "SELECT fingerprint FROM observations WHERE scan_id = ?", (row[0],))}

    def times_seen(self, fp: str) -> Tuple[int, int]:
        """``(occurrences, distinct scans)`` in which a fingerprint was observed."""
        with closing(self._connect()) as con:
            return con.execute("SELECT COUNT(*), COUNT(DISTINCT scan_id) FROM observations "
                               "WHERE fingerprint = ?", (fp,)).fetchone()

    def history(self, limit: int = 100) -> List[Dict[str, object]]:
        with closing(self._connect()) as con:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]

    # -- feedback ----------------------------------------------------------------
    def add_feedback(self, finding: Finding, false_positive: bool, source: str = "user",
                     weight: float = 1.0) -> None:
        """Record a resolution. A newer one from the same source replaces the old."""
        fp = fingerprint(finding)
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM feedback WHERE fingerprint = ? AND source = ?", (fp, source))
            con.execute(
                "INSERT INTO feedback(time, fingerprint, rule_id, engine, label, source, weight,"
                " file, snippet) VALUES (?,?,?,?,?,?,?,?,?)",
                (time.time(), fp, finding.rule_id, finding.handler,
                 "fp" if false_positive else "tp", source, weight, finding.file,
                 (finding.snippet or finding.evidence)[:500]))

    def remove_feedback(self, finding: Finding, source: str = "user") -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM feedback WHERE fingerprint = ? AND source = ?",
                        (fingerprint(finding), source))

    def resolutions(self) -> Dict[str, str]:
        """Explicit user decisions: fingerprint -> ``'fp'`` or ``'tp'``."""
        with closing(self._connect()) as con:
            return dict(con.execute("SELECT fingerprint, label FROM feedback "
                                    "WHERE source = 'user' ORDER BY time"))

    def rule_stats(self, now: Optional[float] = None) -> Dict[RuleKey, RuleStats]:
        """Feedback aggregated per (rule, engine), with exponential time decay."""
        now = now or time.time()
        out: Dict[RuleKey, RuleStats] = {}
        with closing(self._connect()) as con:
            rows = con.execute("SELECT rule_id, engine, label, weight, time FROM feedback").fetchall()
        for rule_id, engine, label, weight, when in rows:
            stats = out.setdefault((rule_id, engine or ""), RuleStats())
            decayed = weight * 0.5 ** (max(0.0, now - when) / 86400.0 / self.half_life_days)
            if label == "fp":
                stats.fp += decayed
                stats.fp_count += 1
            else:
                stats.tp += decayed
                stats.tp_count += 1
        return out

    # -- housekeeping ------------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        with closing(self._connect()) as con:
            count = lambda table: con.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
            return {"scans": count("scans"), "observations": count("observations"),
                    "feedback": count("feedback")}

    def clear_feedback(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM feedback")

    def clear_history(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM observations")
            con.execute("DELETE FROM scans")
