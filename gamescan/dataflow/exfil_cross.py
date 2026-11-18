"""C1, part 2b: a private-data -> network flow split over the files of one Electron app (phageo,
2026-11-04). Per-file C1 (:mod:`gamescan.dataflow.exfil`) proves a flow only inside one script. Real
stealers spread it: one module reads the browser / Discord / wallet store and exports it, another
imports that export and sends it out. This module joins the two **without running anything** (rule 2),
on the summaries the per-file reader already built on the syntax tree:

* each script's **exports** (an exported name -> the labels its value carries: store / capture kinds,
  and ``mod:<spec>::<name>`` when the export forwards another module's export), and
* each script's **sink imports** (a value imported from a relative module that reaches a network sink).

The app's scripts form a module graph by their **relative** ``require`` / ``import`` specs (and the
entry points ``package.json`` names - its handling stays in :mod:`gamescan.scanner`). A sink that
consumes ``require("./a").getData`` is joined to the store ``./a`` reads, following re-exports **at
most** :data:`MAX_HOPS` module boundaries. A proven cross-file store flow is ``CHAIN-EXFIL`` (CRITICAL,
MALICE); a capture flow is HIGH (CHAIN); the same rule and cause class as per-file C1.

Decision of phageo (2026-11-04): verified files (npm packages / official library releases) **are** read
for flows now. A flow whose source and sink both lie inside one verified file is MEDIUM (rule 13's
exception); a flow that crosses into or out of the app's own code gets its tier's full level - origin
proves origin, not intent. A flow wholly between two different verified files is also MEDIUM (it is the
libraries' own mechanism; the app did not join them).

Bounds (rule 3; counts): :data:`MAX_SCRIPTS` scripts per app, :data:`MAX_HOPS` boundaries per flow,
:data:`MAX_WORK` graph steps per app, :data:`MAX_FLOWS` flows reported per app.
"""
from __future__ import annotations

import posixpath
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from . import exfil

ON = True                       # the cross-file switch (its own switch; off -> nothing is joined)

MAX_SCRIPTS = 4000              # scripts of one app whose summaries are joined
MAX_HOPS = 4                    # module boundaries a flow may cross (phageo, 2026-11-04)
MAX_WORK = 2_000_000            # graph steps per app (then the join stops for that app)
MAX_FLOWS = 16                  # cross-file flows reported per app
C1_KINDS = frozenset(exfil.MALICE_KINDS | frozenset(exfil.CAPTURE_KINDS))   # what C1's join counts


class Summary(NamedTuple):
    relpath: str
    exports: Dict[str, frozenset]              # export name -> labels (store / capture / mod:spec::name)
    sink_imports: List[Tuple[str, str, int, str]]   # (relative spec, name, sink line, sink)
    verified: bool                             # the file is a verified npm / library file


class CrossFlow(NamedTuple):
    sink_file: str
    sink_line: int
    sink: str
    kind: str                                  # the private data: a store kind, "clipboard" or "screen"
    source_file: str                           # where the store is read / the capture is taken
    hops: int
    both_verified: bool                        # source and sink both verified -> MEDIUM (rule-13 exception)


def _key(name: str) -> str:
    return name.replace("\\", "/").replace("!", "/").lower()


class _Graph:
    def __init__(self, summaries: List[Summary]):
        self.by_rel = {s.relpath: s for s in summaries}
        self.by_key = {_key(s.relpath): s for s in summaries}
        self.work = 0

    def tick(self) -> None:
        self.work += 1
        if self.work > MAX_WORK:
            raise StopIteration

    def resolve(self, near: str, spec: str) -> Optional[Summary]:
        """The app script a relative ``spec`` names, resolved against ``near`` (both app-internal)."""
        if not spec.startswith((".", "/")):
            return None
        base = posixpath.dirname(_key(near))
        target = posixpath.normpath(posixpath.join(base, spec.lower()))
        for candidate in (target, target + ".js", target + ".cjs", target + ".mjs",
                          target + "/index.js", target + "/index.cjs", target + "/index.mjs"):
            got = self.by_key.get(candidate)
            if got is not None:
                return got
        return None

    def source(self, start: Summary, name: str, start_hop: int,
               kinds: frozenset = frozenset()) -> List[Tuple[str, str, int]]:
        """Follow the export ``name`` of module ``start`` to the stores / captures it carries (or,
        for C3, the ``kinds`` its reader counts), resolving ``mod:`` re-exports up to
        :data:`MAX_HOPS` boundaries. Each result is ``(kind, the file that reads it, hops)``."""
        kinds = kinds or C1_KINDS
        out: List[Tuple[str, str, int]] = []
        seen: Set[Tuple[str, str]] = set()
        stack: List[Tuple[Summary, str, int]] = [(start, name, start_hop)]
        while stack:
            self.tick()
            mod, want, hop = stack.pop()
            if (mod.relpath, want) in seen or hop > MAX_HOPS:
                continue
            seen.add((mod.relpath, want))
            labels = mod.exports.get(want) or (mod.exports.get("*") if want == "*" else None) or frozenset()
            for label in labels:
                if label in kinds:
                    out.append((label, mod.relpath, hop))
                elif label.startswith(exfil.MOD) and hop < MAX_HOPS:
                    spec, _, nxt = label[len(exfil.MOD):].partition("::")
                    other = self.resolve(mod.relpath, spec)
                    if other is not None:
                        stack.append((other, nxt, hop + 1))
        return out


def join(summaries: List[Summary]) -> List[CrossFlow]:
    """Every cross-file private-data flow of one app: a sink in one script fed by an import whose module
    (through re-exports, at most :data:`MAX_HOPS` hops) reads a store or captures the screen / clipboard
    in another script. Deterministic; never raises (a step limit ends the app's join quietly)."""
    if not ON:
        return []
    return join_kinds(summaries, C1_KINDS)


def join_kinds(summaries: List[Summary], kinds: frozenset) -> List[CrossFlow]:
    """The same join for the labels ``kinds`` a reader's summaries carry - C1's private-data kinds
    (:func:`join`), or C3's decoded-data kinds (``decoderun.py``, behind its own switch)."""
    if len(summaries) < 2:
        return []
    graph = _Graph(summaries[:MAX_SCRIPTS])
    out: List[CrossFlow] = []
    seen: Set[Tuple[str, int, str, str]] = set()
    try:
        for s in graph.by_rel.values():
            for spec, name, line, sink in s.sink_imports:
                target = graph.resolve(s.relpath, spec)
                if target is None:
                    continue
                for kind, src_file, hops in graph.source(target, name, 1, kinds):
                    if src_file == s.relpath and hops <= 1:
                        continue                       # wholly in one file: per-file C1 already has it
                    key = (s.relpath, line, kind, src_file)
                    if key in seen or len(out) >= MAX_FLOWS:
                        continue
                    seen.add(key)
                    both = s.verified and graph.by_rel[src_file].verified
                    out.append(CrossFlow(s.relpath, line, sink, kind, src_file, hops, both))
    except StopIteration:
        pass
    return sorted(out, key=lambda f: (f.sink_file, f.sink_line, f.kind, f.source_file))


def evidence(flow: CrossFlow) -> str:
    """One line for a cross-file flow, by the scanner's own words - the source script's file name
    (its leaf only) of the app and the sink's line."""
    said = exfil._KIND_WORDS.get(flow.kind, "private data")
    sink = flow.sink if len(flow.sink) <= 80 else "a network call"
    where = flow.source_file.replace("\\", "/").split("!")[-1].rsplit("/", 1)[-1] or "another script"
    return ("%s, read in %s, reaches %s on line %d of this script (%d file hop(s))"
            % (said, where, sink, flow.sink_line, flow.hops))
