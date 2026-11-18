"""The JavaScript syntax-tree front door (phase C, JS group; phageo, 2026-11-03).

``docs/memory/roadmap-1.0.md`` phase C adopts tree-sitter and its JavaScript grammar for the
JS group (C2 string-array resolver, C1 private-data -> network flow, C3 decode -> run flow).
This module is the one place that loads the parser and turns a script's bytes into a syntax
tree, behind a switch and inside bounded, **deterministic** limits. The readers of C2 / C1 / C3
call :func:`parse`; nothing here finds anything on its own.

**The parser is never run as code** (rule 2): tree-sitter only builds a tree of where things
are, exactly as ``ast.parse`` does for Python. Scanned bytes are never executed, imported,
compiled or evaluated.

Why a front door and not an ``import`` in each reader:

* **One switch.** ``ON`` and :func:`available` decide together whether the group reads through
  the tree; off, or the parser not installed, every reader uses today's name-based tracer and
  nothing changes. A reader that falls back says so with a "could not be read to the tree" note
  (:data:`FALLBACK_NOTE`), as the tracers say ``SCRIPT-LIMIT-001``.
* **One set of limits, and they are counts, not a clock** (the rule since 2026-10-13: a reading
  is bounded by counts so the same file gives the same answer on every PC; the clock is only a
  far safety cap). The deterministic limits are the **byte size** of the file (:data:`MAX_BYTES`;
  it bounds the tree's memory - the spike measured about 40-70 bytes of tree per input byte) and,
  after a parse, the **node count** (:data:`MAX_NODES`). A file that is not text-like is not
  handed to the parser at all. The **parse time** (:data:`PARSE_SECONDS`) is a far safety cap
  only, like ``values.SAFETY_SECONDS``: on a real script it never fires (the largest real JS file
  the spike saw, 47.2 MB, parsed in about 4 s), and a file that somehow reaches it falls back -
  the one non-deterministic edge, documented in ``docs/memory/limits.md``.

Memory guard: tree-sitter allocates the whole tree natively, and the safe way to cap that is the
input size (:data:`MAX_BYTES`), because the native allocation cannot be stopped mid-parse except
by the time cap. The spike's hostile inputs (random bytes, a 50 MB one-liner) are what the size
cap and the time cap are for.

A tree is **always walked with a cursor** (:func:`walk`), never by recursion: a one-million-deep
input makes a one-million-deep tree, and Python would overflow its stack on it (the spike).

The loader finds the parser by a plain ``import`` first (so the built package, which carries the
pinned wheels in its ``python/`` folder, needs nothing more), then, for running from source, by
the site folder named in ``GSS_TS_SITE`` (the unpacked wheels of ``tools/manifest_spike.json``,
kept outside the project). No path of a particular PC stands in this file (rule 11).
"""
from __future__ import annotations

import os
import sys
import warnings
from typing import Iterator, NamedTuple, Optional

ON = True                       # the JS group may read through the syntax tree (each reader also
                                # checks available(); until a reader of C2 / C1 / C3 calls parse(),
                                # this changes nothing - the fallback is today's tracer)

# -- deterministic limits (counts, not a clock) --------------------------------------------------
MAX_BYTES = 48 * 1024 * 1024    # the largest file handed to the parser (the largest real JS file
                                # the spike saw was 47.2 MB); also the memory guard - the tree's
                                # memory scales with the input size
MAX_NODES = 12_000_000          # the most nodes a tree may have (checked after the parse; a count,
                                # so the same file is kept or dropped on every PC)
PARSE_SECONDS = 30              # a FAR safety cap only (PC-dependent, like values.SAFETY_SECONDS);
                                # the byte size is the real limit. A parse that reaches it falls back.
_SAMPLE = 65536                 # bytes of the start looked at for the text-like test
_MAX_CONTROL = 0.02             # at most this share of them may be NUL / stray control bytes

# the note a reader adds when a file could not be read to a tree and it fell back to the tracer
# (a "could not be read" reason, phrased so values.cause() files it by its kind - SIZE for the
# size cap, a count for the node cap / not-text, a clock for the far time cap)
FALLBACK_NOTE = "read with the name-based tracer, not the syntax tree: %s"

_state = {"tried": False, "ok": False, "lang": None, "err": ""}


def _add_site() -> None:
    """Put the site folder of ``GSS_TS_SITE`` (the unpacked spike wheels, outside the project) on
    the path, when running from source and the parser is not already importable. The built package
    carries the wheels in ``python/`` and needs none of this."""
    site = os.environ.get("GSS_TS_SITE")
    if site and os.path.isdir(site) and site not in sys.path:
        sys.path.insert(0, site)


def _load() -> None:
    """Import tree-sitter and the JavaScript grammar once; keep the Language, or the reason it is
    not available. Called at import time (before the positive runner's guard is on) and cached."""
    if _state["tried"]:
        return
    _state["tried"] = True
    try:
        import tree_sitter            # noqa: F401  (a compiled extension, imported - never run as code)
    except ImportError:
        _add_site()
    try:
        import tree_sitter as ts
        import tree_sitter_javascript as tsj
        _state["lang"] = ts.Language(tsj.language())
        _state["ok"] = True
    except Exception as exc:          # noqa: BLE001  (any failure: the group falls back, never crashes)
        _state["ok"] = False
        _state["err"] = "%s: %s" % (type(exc).__name__, exc)


_load()


def _timeout_micros() -> int:
    """The far safety cap in microseconds (0 would mean "no cap" to tree-sitter, so never 0)."""
    return max(1, PARSE_SECONDS) * 1_000_000


def available() -> bool:
    """Is the syntax-tree parser loaded? When not (the switch, a missing or broken parser), every
    reader of the JS group uses today's name-based tracer and nothing changes."""
    return ON and _state["ok"]


def unavailable_reason() -> str:
    return _state["err"] or ("switched off (jsparse.ON)" if not ON else "")


def text_like(data: bytes) -> bool:
    """Is ``data`` text a JavaScript parser should see? A quick, deterministic look at a fixed
    prefix: JavaScript source is text, so more than a little NUL / stray control content (compiled
    V8 bytecode, a binary mislabelled ``.js``) means do not parse it."""
    head = data[:_SAMPLE]
    if not head:
        return True
    control = sum(1 for b in head if b == 0 or (b < 0x09) or (0x0E <= b < 0x20 and b not in (0x1B,)))
    return control <= _MAX_CONTROL * len(head)


class Parsed(NamedTuple):
    tree: object                      # a tree-sitter Tree, or None when it fell back
    limit: str                        # "" when parsed; else why a reader must fall back (one line)
    nodes: int                        # the tree's node count (0 when it fell back)

    @property
    def ok(self) -> bool:
        return self.tree is not None


def parse(data: bytes) -> Parsed:
    """The syntax tree of ``data`` (UTF-8 JavaScript), or a fall-back with the reason. The reason
    is empty only when a usable tree came back; otherwise the caller reads the file with today's
    tracer and adds :data:`FALLBACK_NOTE` % reason. Never raises, never runs the bytes."""
    if not available():
        return Parsed(None, "the syntax-tree parser is not available", 0)
    if len(data) > MAX_BYTES:
        return Parsed(None, "the file is larger than %d MB" % (MAX_BYTES >> 20), 0)
    if not text_like(data):
        return Parsed(None, "the file is not text (too many control bytes for a script)", 0)
    import tree_sitter as ts
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")              # timeout_micros is deprecated but the progress
        # callback crashes this build's native code; the clock here is only a far safety cap anyway
        parser = ts.Parser(_state["lang"], timeout_micros=_timeout_micros())
        try:
            tree = parser.parse(data)
        except ValueError:
            # the far time cap fired (a hostile file); PC-dependent, so documented as a limit
            return Parsed(None, "the parse did not finish within %d seconds" % PARSE_SECONDS, 0)
        except Exception as exc:                      # noqa: BLE001
            return Parsed(None, "the file could not be parsed (%s)" % type(exc).__name__, 0)
    nodes = tree.root_node.descendant_count
    if nodes > MAX_NODES:
        return Parsed(None, "the syntax tree has more than %d nodes" % MAX_NODES, nodes)
    return Parsed(tree, "", nodes)


def walk(tree, *, max_nodes: Optional[int] = None) -> Iterator[object]:
    """Every node of ``tree`` - a tree, or one node and what lies under it - in reading order, with a
    cursor - never by recursion (a deep input makes a deep tree; recursion would overflow the stack).
    Stops after ``max_nodes`` nodes."""
    if tree is None:
        return
    cursor = tree.walk()
    seen = 0
    limit = max_nodes if max_nodes is not None else MAX_NODES + 1
    while True:
        yield cursor.node
        seen += 1
        if seen >= limit:
            return
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def node_text(node, data: bytes) -> bytes:
    """The bytes of the file that ``node`` covers."""
    return data[node.start_byte:node.end_byte]
