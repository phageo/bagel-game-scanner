"""The runners' ``r2b`` column (phase D, session R2b-2; for the gate ``phaseD_3``): the notes of the pre-freeze fixes
and the counts of :mod:`gamescan.fixlog` of one scan. Rule ids, levels and counts only (rule 19)."""
from __future__ import annotations

import collections
from typing import Dict, Iterable

from .models import UNREAD_NOTES, UNREAD_NOTES_REVIEW
from .unpack.limits import SILENT_ESCAPE


def column(findings: Iterable, fixes: Dict[str, int]) -> str:
    """The ``r2b`` column of one scan: ``"notes ARC-002 LOW x3 | review PE-FMT-001 x1 | fixes B1 x2"`` - the active
    notes of the silent-escape fixes by rule and level, the active "could not be read" notes that now give at least
    REVIEW (item 4), the counts of :func:`take`. Empty parts are left out."""
    from .handlers.base import PAYLOAD_SAID
    from .handlers.renpy import UNREAD_BYTECODE
    from .scanner import SCRIPT_CAP_NOTE, UNTAKEN_EVIDENCE
    notes: Dict[str, int] = collections.Counter()
    review: Dict[str, int] = collections.Counter()
    made: Dict[str, int] = collections.Counter()           # which fix made each note, where the note can tell
    for f in findings:
        if f.suppressed:
            continue
        if f.context.get(SILENT_ESCAPE):
            notes["%s %s" % (f.rule_id, f.severity.name)] += 1
            made["S04" if UNREAD_BYTECODE in f.context else "S12" if f.context.get(PAYLOAD_SAID)
                 else "item8" if f.context.get(SCRIPT_CAP_NOTE) else "S09" if f.evidence == UNTAKEN_EVIDENCE
                 else "other"] += 1
        elif UNREAD_NOTES_REVIEW and f.rule_id in UNREAD_NOTES:
            review[f.rule_id] += 1
    parts = []
    for label, counted in (("notes", notes), ("review", review), ("fixes", fixes), ("from", made)):
        if counted:
            parts.append("%s %s" % (label, ", ".join("%s x%d" % kv for kv in sorted(counted.items()))))
    return " | ".join(parts)
