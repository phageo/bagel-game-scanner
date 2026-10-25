"""Measure a "sink-first" reading of large JavaScript bundles against the full reading.

A measurement, not a rule (phageo, 2026-10-14, forty-first message: "measure only, propose,
do not build"). While the scanner reads a sample the usual way, every text the JavaScript
download-and-run reading (``remote.study``) is given is also read a second way:

1. **Full reading** - what the scan does today: its time, its hits, where it stopped.
2. **Sinks** - the places where code is run (``eval``, ``new Function``, ``vm``) or a
   program is started (``child_process``, the Windows Script Host, ``require`` of a file,
   the shell's open), found by the same patterns the reading uses.
3. **Backward trace** - from each sink, the names in what it is handed are followed back
   to where they are given a value, name by name (``TextFlow._definitions``), until a
   source is met (a request, a file read, a page's message), a parameter (a caller hands
   it in: the trace would have to go to the callers), or nothing more. Each name looked up
   and each place it is given a value is one step. Capped at ``CAP`` steps per sink.

Numbers only: no name, no path, no content of a sample is printed.

    python tools/sink_count.py <folder of one clean sample> [...]

Real samples: ``tools/positive_benchmark.py <folders> --sinks``.
"""
from __future__ import annotations

import os
import re
import sys
import time
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CAP = 2000                     # steps of one backward trace
BIG = 1 << 20                  # texts of at least 1 MB are listed one by one
# what a source looks like in an expression (a request, a file read, a page's message)
SOURCE = re.compile(r"(?<![\w$.])fetch\s*\(|XMLHttpRequest|\.\s*(?:responseText|response|responseBody)\b"
                    r"|(?<![\w$.])(?:https?|http2|net|tls|dgram)\s*\.\s*(?:get|request|connect)\s*\("
                    r"|(?<![\w$.])axios\b|\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\(|new\s+(?:WebSocket|EventSource)\b"
                    r"""|\.\s*readFile(?:Sync)?\s*\(|ipc(?:Main|Renderer)\b|\.\s*on\s*\(\s*["']message""")


def sinks(flow) -> List[tuple]:
    """``(position, "(" position, kind)`` of every place ``flow`` (a ``remote.RemoteFlow``)
    runs code or starts a program."""
    from gamescan.dataflow import remote as R
    bare, code = flow.bare, flow.code
    out = [(m.start(), m.end() - 1, "code") for m in R._CODE_SINK.finditer(bare)]
    out += [(m.start(), m.end() - 1, "code") for m in R._NAMED_SINK.finditer(code) if flow._real(m.start())]
    flow._find_functions()
    if "child_process" in code:
        out += [(a, b, "start") for a, b, _label in flow._launches()]
    if "ActiveXObject" in code or "CreateObject" in code:
        out += [(a, b, "start") for a, b, _label in flow._wsh_launches()]
    out += [(a, b, "load") for a, b, _label in flow._loads()]
    return sorted(set(out))


def trace(flow, opener: int) -> Dict[str, int]:
    """Follow the names handed to the sink whose argument list opens at ``opener`` back to
    where they are given a value. ``steps``; ``source``: 1 when a source was met;
    ``parameter``: names that are parameters (the trace would go on in the callers)."""
    from gamescan.dataflow import remote as R
    close = flow._close(opener)
    out = {"steps": 0, "source": 0, "parameter": 0, "capped": 0}
    if close < 0:
        return out
    first = flow.code[opener + 1:close]
    if SOURCE.search(first):
        out["source"] = 1
        return out
    params = flow.flow._parameters()
    todo = [m.group(1).split(".")[0] for m in R._CHAIN.finditer(R._code_parts(first))]
    seen = set()
    while todo:
        name = re.sub(r"\s+", "", todo.pop())
        if name in seen or name in R._NOT_VALUES or not R._NAME_ONLY.match(name):
            continue
        seen.add(name)
        out["steps"] += 1
        if out["steps"] >= CAP:
            out["capped"] = 1
            break
        if name in params:
            out["parameter"] += 1
        for _start, _kind, end in flow.flow._definitions(name)[:8]:
            out["steps"] += 1
            expr = flow.code[end:flow._expr_end(end)][:4000]
            if SOURCE.search(expr):
                out["source"] = 1
                return out
            todo += [m.group(1).split(".")[0] for m in R._CHAIN.finditer(R._code_parts(expr))]
    return out


def measure(text: str, full_seconds: float, hits, cut: str) -> Dict[str, float]:
    """The numbers of one text: the full reading (as the scan did it) and the sink-first
    reading (done here)."""
    from gamescan.dataflow import remote as R
    row: Dict[str, float] = {"size": len(text), "full_seconds": full_seconds, "full_hits": len(hits),
                             "full_cut": 1 if cut else 0}
    began = time.perf_counter()
    flow = R.RemoteFlow(text)
    flow.clock.steps = 10 ** 12                       # (this measurement has its own cap per sink)
    found = sinks(flow)
    row["sinks"] = len(found)
    row["code_sinks"] = sum(1 for s in found if s[2] == "code")
    row["start_sinks"] = sum(1 for s in found if s[2] != "code")
    steps: List[int] = []
    for key in ("source", "parameter", "capped"):
        row["sinks_" + key] = 0
    for _pos, opener, _kind in found:
        t = trace(flow, opener)
        steps.append(t["steps"])
        row["sinks_source"] += t["source"]
        row["sinks_parameter"] += 1 if t["parameter"] else 0
        row["sinks_capped"] += t["capped"]
    row["trace_steps"] = sum(steps)
    row["trace_max"] = max(steps) if steps else 0
    row["sink_seconds"] = time.perf_counter() - began
    return row


class Recorder:
    """Wraps ``remote.study`` while a scan runs: its time and answer are kept, and the text
    is read sink-first as well (``measure``, timed apart) - the scan goes on with the real
    reading's answer. The other readings of a JavaScript text are timed too (``OTHERS``)."""

    OTHERS = (("remote", "written_and_started"), ("remote", "starts"), ("remote", "wsh_commands"),
              ("dataflow", "analyse"))

    def __init__(self) -> None:
        import gamescan.dataflow as D
        from gamescan.dataflow import remote as R
        from gamescan.handlers import base
        self.remote, self.real, self.rows, self.measuring = R, R.study, [], 0.0
        self.places = {"remote": R, "dataflow": base.dataflow if hasattr(base, "dataflow") else D}
        self.saved: List[tuple] = []
        self.seconds: Dict[str, float] = {}

    def __enter__(self) -> "Recorder":
        R = self.remote

        def study(text, failed=None):
            began = time.perf_counter()
            hits, cut = self.real(text, failed)
            spent = time.perf_counter() - began
            self.seconds["study"] = self.seconds.get("study", 0.0) + spent
            if text and (len(text) >= BIG or (R._NET_HINT.search(text) and len(text) >= 4096)):
                began = time.perf_counter()
                self.rows.append(measure(text, spent, hits, cut))
                self.measuring += time.perf_counter() - began
            return hits, cut
        R.study = study
        for module, name in self.OTHERS:
            place = self.places[module]
            real = getattr(place, name)
            self.saved.append((place, name, real))

            def timed(*args, _real=real, _name=name, **kw):
                began = time.perf_counter()
                try:
                    return _real(*args, **kw)
                finally:
                    self.seconds[_name] = self.seconds.get(_name, 0.0) + time.perf_counter() - began
            setattr(place, name, timed)
        return self

    def __exit__(self, *_exc) -> None:
        self.remote.study = self.real
        for place, name, real in self.saved:
            setattr(place, name, real)

    def lines(self) -> List[str]:
        rows = self.rows
        out = ["readings of JavaScript, seconds: " + ", ".join(
            "%s %.1f" % item for item in sorted(self.seconds.items(), key=lambda item: -item[1]))]
        out.append("texts measured: %d, of them >= 1 MB: %d" % (len(rows), sum(1 for r in rows if r["size"] >= BIG)))
        total = lambda key, rs=rows: sum(r[key] for r in rs)
        out.append("all texts: full reading %.1f s, %d hit(s), %d cut | sink-first %.1f s, %d sink(s), "
                   "%d trace step(s), %d sink(s) reach a source, %d end at a parameter, %d capped" % (
                       total("full_seconds"), total("full_hits"), total("full_cut"), total("sink_seconds"),
                       total("sinks"), total("trace_steps"), total("sinks_source"), total("sinks_parameter"),
                       total("sinks_capped")))
        for r in sorted((r for r in rows if r["size"] >= BIG), key=lambda r: -r["size"]):
            out.append("  %5.1f MB: full %6.1f s, %d hit(s)%s | sinks %d (code %d, start/load %d), steps %d (max %d), "
                       "source %d, parameter %d, capped %d, %.2f s" % (
                           r["size"] / (1 << 20), r["full_seconds"], r["full_hits"], ", CUT" if r["full_cut"] else "",
                           r["sinks"], r["code_sinks"], r["start_sinks"], r["trace_steps"], r["trace_max"],
                           r["sinks_source"], r["sinks_parameter"], r["sinks_capped"], r["sink_seconds"]))
        return out


def main(argv: List[str]) -> int:
    from gamescan.scanner import neutral_scanner
    for folder in argv:
        with Recorder() as recorder:
            began = time.perf_counter()
            neutral_scanner().scan(folder)
            seconds = time.perf_counter() - began
        print("== %s: scan %.0f s without the measurement (%.0f s with it)" % (
            os.path.basename(os.path.normpath(folder)), seconds - recorder.measuring, seconds))
        for line in recorder.lines():
            print("   " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
