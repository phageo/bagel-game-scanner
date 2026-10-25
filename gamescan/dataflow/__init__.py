"""Payload resolution: what really reaches ``exec``, the shell or the network.

Malicious scripts rarely write ``os.system("powershell ...")`` in one piece;
they build the string from fragments, decode it, or look the function up by
an assembled name. The resolvers in this package undo that statically and
report the final value:

``pyflow``    Python / Ren'Py - an abstract interpreter over the ``ast`` tree
``textflow``  JavaScript, Ruby, PowerShell - backward variable tracing from
              each sensitive call; batch files - ``%variable%`` expansion

Scanned code is never run or imported. Everything is modelled on the
scanner's own values, inside step, time, size and depth limits.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/__init__.py")

import re
from dataclasses import dataclass, field
from typing import List, Tuple

from . import pyflow, textflow
from .values import MAX_DEPTH, Clock, Resolved, powershell_encoded

__all__ = ["Analysis", "Resolved", "analyse", "LANGUAGES"]

LANGUAGES = ("python", "renpy", "js", "ruby", "powershell", "batch")

_RISKY_COMMAND = re.compile(
    _IND[0])
_RISKY_TARGET = re.compile(
    r"(?i)\.(?:exe|dll|bat|cmd|ps1|vbs|vbe|js|scr|lnk|hta|pyd|com)\b|start(?:up| menu)"
    r"|%(?:appdata|localappdata|temp|tmp|userprofile|programdata|windir|systemroot)%"
    r"|system32|[\\/]windows[\\/]")
_POWERSHELL_LINE = re.compile(r"(?im)^[^\n]*\b(?:powershell|pwsh)\b[^\n]*$")


@dataclass
class Analysis:
    resolved: List[Resolved] = field(default_factory=list)       # worth reporting
    payloads: List[Tuple[int, str, str]] = field(default_factory=list)   # (line, language, code)
    commands: List[Tuple[int, str]] = field(default_factory=list)        # every command seen
    # ... and those inside decoded code as well (for the shell download-and-execute chain)
    command_lines: List[Tuple[int, str]] = field(default_factory=list)
    opaque: int = 0                 # process launches whose command could not be read
    error: str = ""                  # internal failure of the resolver (never of the scan)
    cut: str = ""                    # the limit this reading stopped at ("": it read to the end)


def _reportable(hit: Resolved) -> bool:
    if hit.trivial:
        return False
    if hit.kind == "exec":
        # eval("config." + name) is everyday game code: only code that was decoded, or
        # that sits inside decoded code, is reported. What an assembled payload *does*
        # is still reported through the calls found inside it.
        return hit.hidden or hit.layer > 0
    if hit.kind == "path" and not hit.delete:
        return _RISKY_TARGET.search(hit.value) is not None
    return True


def _encoded_powershell(out: Analysis, hits: List[Resolved], clock: Clock) -> None:
    """``powershell -enc <base64>`` anywhere in a command: decode the script."""
    for hit in list(hits):
        if hit.kind != "command" or hit.layer >= MAX_DEPTH:
            continue
        script = powershell_encoded(hit.value)
        if script is None:
            continue
        out.resolved.append(Resolved(
            kind="exec", line=hit.line, sink=_IND[1], value=script[:4000],
            hidden=True, layer=hit.layer + 1, trace=hit.trace))
        out.payloads.append((hit.line or 0, "powershell", script))
        inner = textflow.TextFlow(script, "powershell", clock, hit.layer + 1, hit.line)
        inner.run()
        out.resolved.extend(h for h in inner.hits if _reportable(h))
        out.payloads.extend(inner.payloads)


def analyse(text: str, language: str) -> Analysis:
    """Resolve the values that reach sensitive calls in ``text``. Never raises."""
    out = Analysis()
    clock = Clock()
    try:
        hits: List[Resolved] = []
        started: List[Tuple[int, str]] = []      # commands written out in full (Ruby backticks, %x)
        if language in ("python", "renpy"):
            hits, payloads = pyflow.analyse(text, language == "renpy", clock)
            out.payloads = [(line, "python", code) for line, code in payloads]
        elif language in ("js", "ruby", "powershell"):
            flow = textflow.analyse(text, language, clock)
            hits, out.payloads, out.opaque = flow.hits, list(flow.payloads), flow.opaque
            started = flow.started
        elif language == "batch":
            lines = text.split("\n")
            # what batch_expand does not look at: said (silent until 2026-10-12)
            if len(text) > textflow.MAX_SOURCE:
                clock.stopped = "larger than %d MB" % (textflow.MAX_SOURCE >> 20)
            elif len(lines) > textflow.MAX_BATCH_LINES:
                clock.stopped = "more than %d lines" % textflow.MAX_BATCH_LINES
            for number, expanded in textflow.batch_expand(text):
                original = lines[number - 1] if number <= len(lines) else ""
                if re.match(r"\s*@?\s*[%!]", original) or (
                        _RISKY_COMMAND.search(expanded) and not _RISKY_COMMAND.search(original)):
                    hits.append(Resolved(kind="command", line=number, sink="%variable%",
                                         value=expanded[:4000]))
                    out.payloads.append((number, "batch", expanded))
        if language in ("powershell", "batch"):
            for m in _POWERSHELL_LINE.finditer(text[:textflow.MAX_SOURCE]):
                if powershell_encoded(m.group(0)):
                    hits.append(Resolved(kind="command", line=text.count("\n", 0, m.start()) + 1,
                                         sink="powershell", value=m.group(0).strip()[:4000],
                                         trivial=True))
        out.resolved = [h for h in hits if _reportable(h)]
        out.commands = [(h.line or 0, h.value) for h in hits if h.kind == "command" and h.layer == 0]
        out.command_lines = ([(h.line or 0, h.value) for h in hits if h.kind == "command"] + started)[:400]
        _encoded_powershell(out, hits, clock)
    except Exception as exc:     # an analysis aid must never break the scan itself
        out.error = "%s: %s" % (type(exc).__name__, exc)
    # the steps are the limit (a count: the same file, the same answer), the clock is an
    # emergency brake; whichever stopped the reading, it is said (SCRIPT-LIMIT-001)
    out.cut = clock.stopped
    del out.resolved[200:]
    del out.payloads[40:]
    return out
