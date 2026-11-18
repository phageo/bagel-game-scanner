"""Where the pre-freeze fixes changed a scan (phase D, session R2b-2; phageo, 2026-11-17) - for the gate only.

The gate ``phaseD_3`` judges its result files by rules, not by a list of rows: a clean game may move only from CLEAN /
LIKELY SAFE to REVIEW by one of the R2b notes, a malicious sample may only rise or stay, and any other change fails -
named by the game's code and by the switch that caused it. The notes say themselves (``limits.SILENT_ESCAPE``, the
"could not be read" notes of ``models.UNREAD_NOTES``); what a fix changed without a note of its own - a tag no longer
counted (B1), a response tied to another request (B2), a start read as an argument (B3), a match a rule's fixed form
refused (B4-B7), a member read inside an archive (S07), a zip read on past a broken member (S01) - is counted here, per
switch, while it happens. ``gamescan/fixreport.py`` makes the runners' ``r2b`` column of one scan (kept apart:
this module imports nothing, so a reader that counts here depends on nothing more - gamescan/cache.py).

Counts only - no names, no content (rule 19). Information: nothing in a scan reads these counts.
"""
from __future__ import annotations

import collections
import threading
from typing import Dict

_lock = threading.Lock()
_counts: Dict[str, int] = collections.Counter()


def note(fix: str, times: int = 1) -> None:
    """The fix ``fix`` (its audit name: "B1", "S07" ...) changed what this scan reads, ``times`` times."""
    if times > 0:
        with _lock:
            _counts[fix] += times


def take() -> Dict[str, int]:
    """The counts since the last :func:`take` - and they start again from nothing."""
    with _lock:
        out = dict(_counts)
        _counts.clear()
    return out

