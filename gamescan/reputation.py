"""VirusTotal hash lookups for executables.

Only the SHA-256 of a file is sent - never the file itself. Results are
cached on disk so repeated scans do not spend the API quota again, and
requests are spaced to respect the public API limit (4 per minute).
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .models import Category, Finding, Severity

API_URL = "https://www.virustotal.com/api/v3/files/%s"
GUI_URL = "https://www.virustotal.com/gui/file/%s"
Fetch = Callable[[str, Dict[str, str]], Tuple[int, bytes]]


class ReputationError(Exception):
    """Lookups cannot continue (bad key, quota used up, no network)."""


@dataclass
class Reputation:
    sha256: str
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    label: str = ""              # suggested threat label, if any
    checked_at: float = field(default_factory=time.time)
    first_seen: float = 0.0      # first_submission_date (epoch seconds); 0 = unknown

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    def age_days(self, now: Optional[float] = None) -> int:
        """Days since VirusTotal first saw the file (-1 if unknown)."""
        if not self.first_seen:
            return -1
        return max(0, int(((now or time.time()) - self.first_seen) // 86400))

    @property
    def undetected_by_all(self) -> bool:
        return self.found and self.malicious == 0 and self.suspicious == 0 and self.total >= 30

    def is_clean(self, min_age_days: float = 30.0, now: Optional[float] = None) -> bool:
        """Flagged by nobody AND known long enough for that to mean something.

        New malware is often 0/70 for its first days, so "no detections" on a
        file VirusTotal has only just met is not evidence of anything.
        """
        return self.undetected_by_all and self.age_days(now) >= min_age_days

    @property
    def clean(self) -> bool:
        """``is_clean()`` with the default 30-day age (kept for existing callers)."""
        return self.is_clean()

    @property
    def link(self) -> str:
        return GUI_URL % self.sha256


def _http_get(url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


class VirusTotalClient:
    def __init__(self, api_key: str, cache_path: Optional[str] = None,
                 min_interval: float = 15.5, ttl: float = 7 * 86400,
                 fetch: Optional[Fetch] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.api_key, self.cache_path = api_key.strip(), cache_path
        self.min_interval, self.ttl = min_interval, ttl
        self._fetch, self._sleep = fetch or _http_get, sleep
        self._last = 0.0
        self._cache: Dict[str, dict] = {}
        if cache_path and os.path.isfile(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as fh:
                    self._cache = json.load(fh)
            except (OSError, ValueError):
                self._cache = {}

    def cached(self, sha256: str) -> Optional[Reputation]:
        entry = self._cache.get(sha256.lower())
        try:
            if entry and time.time() - entry.get("checked_at", 0) < self.ttl:
                return Reputation(**entry)
        except (TypeError, AttributeError):      # damaged cache entry: look it up again
            pass
        return None

    def lookup(self, sha256: str, cancel: Optional[threading.Event] = None) -> Optional[Reputation]:
        """Reputation of a hash (None if cancelled). Raises ReputationError."""
        sha256 = sha256.lower()
        hit = self.cached(sha256)
        if hit is not None:
            return hit
        while time.time() - self._last < self.min_interval:      # rate limit
            if cancel is not None and cancel.is_set():
                return None
            self._sleep(0.25)
        self._last = time.time()
        try:
            status, body = self._fetch(API_URL % sha256, {"x-apikey": self.api_key,
                                                          "accept": "application/json"})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ReputationError("network error: %s" % exc)
        if status == 404:
            rep = Reputation(sha256, found=False)
        elif status == 200:
            try:
                attrs = json.loads(body)["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                label = (attrs.get("popular_threat_classification") or {}).get(
                    "suggested_threat_label", "")
                rep = Reputation(sha256, True, int(stats.get("malicious", 0)),
                                 int(stats.get("suspicious", 0)), int(stats.get("harmless", 0)),
                                 int(stats.get("undetected", 0)), str(label),
                                 first_seen=float(attrs.get("first_submission_date") or 0))
            except (ValueError, KeyError, TypeError) as exc:
                raise ReputationError("unexpected response: %s" % exc)
        elif status in (401, 403):
            raise ReputationError("the API key was rejected (HTTP %d)" % status)
        elif status == 429:
            raise ReputationError("the API quota is used up (HTTP 429)")
        else:
            raise ReputationError("HTTP %d" % status)
        self._cache[sha256] = asdict(rep)
        self._save()
        return rep

    def _save(self) -> None:
        if not self.cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
        except OSError:
            pass


def findings_for(rep: Reputation, relpath: str, path: str,
                 min_age_days: float = 30.0) -> List[Finding]:
    """Findings that a reputation result adds to a file (none when clean)."""
    age = rep.age_days()
    seen = "first seen on VirusTotal %d day(s) ago" % age if age >= 0 else \
        "first-seen date unknown"
    def make(rule_id, title, severity, confidence, reason, evidence):
        return Finding(rule_id=rule_id, title=title, category=Category.REPUTATION,
                       severity=severity, file=relpath, line=None, snippet=rep.link,
                       evidence=evidence, confidence=confidence, reason=reason,
                       handler="virustotal", sha256=rep.sha256, path=path, chainable=False)

    if not rep.found:
        return [make("VT-003", "Unknown to VirusTotal", Severity.LOW, 0.3,
                     "No antivirus vendor has ever seen this exact program, so nothing "
                     "vouches for it. Normal for small indie games, but also for fresh "
                     "malware.", "hash not found")]
    ratio = "%d/%d" % (rep.malicious, rep.total)
    evidence = ratio + (" - " + rep.label if rep.label else "") + "; " + seen
    if rep.malicious >= 5:
        return [make("VT-001", "Flagged as malicious by antivirus engines", Severity.CRITICAL,
                     0.95, "Several independent antivirus engines on VirusTotal detect this "
                     "exact file as malware.", evidence)]
    if rep.malicious >= 2:
        return [make("VT-001", "Flagged as malicious by antivirus engines", Severity.HIGH, 0.7,
                     "More than one antivirus engine on VirusTotal detects this exact file "
                     "as malware.", evidence)]
    if rep.malicious or rep.suspicious:
        return [make("VT-002", "Flagged by a single antivirus engine", Severity.MEDIUM, 0.4,
                     "One engine on VirusTotal flags this file. Single detections are "
                     "often false alarms, but worth a look.",
                     "%s malicious, %d suspicious; %s" % (ratio, rep.suspicious, seen))]
    if rep.undetected_by_all and not rep.is_clean(min_age_days):
        return [make("VT-004", "No detections yet, but too new on VirusTotal to trust",
                     Severity.LOW, 0.3,
                     "No antivirus engine flags this file, but VirusTotal has only known it "
                     "for a short time. New malware often goes undetected for its first days, "
                     "so this result was not used to dismiss other findings.",
                     "%s; %s (needs %d)" % (ratio, seen, min_age_days))]
    return []
