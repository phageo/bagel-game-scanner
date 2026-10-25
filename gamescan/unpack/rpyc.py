"""Ren'Py ``.rpyc`` decompiler.

A compiled script is a zlib-compressed pickle of the script's syntax tree.
The tree is rebuilt with inert stand-in objects (no Ren'Py or game class is
ever imported or called), then every Python block and expression is emitted
at its original line number.
"""
from __future__ import annotations

import io
import pickle
import re
import struct
import zlib
from typing import Dict, List, Optional, Tuple

from . import limits

_PRINTABLE = re.compile(rb"[\t\x20-\x7e]{4,}")
# the path of the source file, as the compiler wrote it into the compiled script: the
# folder of whoever compiled it ("D:\...\renpy/common/00start.rpy"). A plain path - no
# quote, bracket, semicolon or equals sign - cannot be a statement that does anything.
_SOURCE_PATH = re.compile(r"[\w .:\\/\-~+,@#&]{0,400}[\\/][\w .\-]{1,120}\.rpym?")
_MAX_NODES = 2_000_000
_MAX_INFLATED = 256 * 1024 * 1024      # a script that inflates beyond this is a bomb
_MAX_CLASSES = 4000                    # distinct class names in one pickle


def inflate(blob: bytes, limit: int = _MAX_INFLATED) -> Optional[bytes]:
    """zlib-decompress with a hard output limit (None if invalid or too large)."""
    try:
        engine = zlib.decompressobj()
        out = engine.decompress(blob, limit)
        if engine.unconsumed_tail:         # more output was waiting: over the limit
            # (`limit`: _MAX_INFLATED unless the caller has a smaller one)
            limits.hit("rpyc", "compressed data that unpacks to more than %d MB" % (limit >> 20))
            return None
        return out
    except zlib.error:
        return None


def no_alloc(kind):
    """``bytes(10**12)`` in a pickle would allocate a terabyte of zeros; allow
    the type as a container only, never as a sized allocation."""
    def make(*args):
        if args and isinstance(args[0], int):
            raise pickle.UnpicklingError("sized allocation refused")
        return kind(*args)
    return make


_SAFE_BUILTINS = {
    "set": set, "frozenset": frozenset, "list": list, "dict": dict, "tuple": tuple,
    "bytes": no_alloc(bytes), "bytearray": no_alloc(bytearray), "str": str, "unicode": str,
    "int": int, "long": int, "float": float, "bool": bool, "complex": complex,
    "object": object,
}


class _Stub:
    """Inert stand-in for any pickled class: records data, runs nothing."""

    def __new__(cls, *args, **kwargs):
        obj = object.__new__(cls)
        obj.s_args, obj.s_items, obj.s_state = args, [], None
        return obj

    def __init__(self, *args, **kwargs):
        pass

    def __setstate__(self, state):
        self.s_state = state

    def append(self, item):
        self.s_items.append(item)

    add = append

    def extend(self, items):
        self.s_items.extend(items)

    def __setitem__(self, key, value):
        self.s_items.append(key)
        self.s_items.append(value)


def _reconstruct(cls, base, state):
    """Stand-in for ``copyreg._reconstructor`` (Python 2 style instances)."""
    if isinstance(cls, type) and issubclass(cls, _Stub):
        return cls.__new__(cls, state)
    return _Stub.__new__(_Stub, state)


class _StubUnpickler(pickle.Unpickler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._classes: Dict[Tuple[str, str], type] = {}   # per file, so it cannot grow forever

    def find_class(self, module, name):
        if len(self._classes) >= _MAX_CLASSES:
            raise pickle.UnpicklingError(limits.hit("rpyc", "more than %d distinct classes" % _MAX_CLASSES))
        if module in ("builtins", "__builtin__") and name in _SAFE_BUILTINS:
            return _SAFE_BUILTINS[name]
        if (module, name) in (("copy_reg", "_reconstructor"), ("copyreg", "_reconstructor")):
            return _reconstruct
        if (module, name) == ("_codecs", "encode"):
            import _codecs
            return _codecs.encode
        key = (module, name)
        if key not in self._classes:
            self._classes[key] = type(str(name), (_Stub,), {})
        return self._classes[key]


def slab(data: bytes) -> Optional[bytes]:
    """The decompressed pickle inside an ``.rpyc`` file, or None."""
    blob = data
    if data.startswith(b"RENPY RPC2"):
        pos, slabs = 10, {}
        while pos + 12 <= len(data):
            slot, start, length = struct.unpack_from("<III", data, pos)
            pos += 12
            if slot == 0:
                break
            slabs[slot] = data[start:start + length]
        blob = slabs.get(1, b"")
    return inflate(blob)


def _text(value) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, _Stub) and value.s_args and isinstance(value.s_args[0], str):
        return value.s_args[0]                   # PyExpr(text, filename, line)
    return None


def _collect(root) -> Tuple[List[Tuple[int, str]], List[str]]:
    """Walk the stub tree: ``[(line, code)]`` and loose strings."""
    located: List[Tuple[int, str]] = []
    loose: List[str] = []
    stack, seen, budget = [root], set(), _MAX_NODES
    while stack and budget:
        budget -= 1
        node = stack.pop()
        if isinstance(node, (int, float, bool, bytes, type(None))):
            continue
        if isinstance(node, str):
            if len(node) >= 4:
                loose.append(node)
            continue
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, _Stub):
            kind = type(node).__name__
            state = node.s_state
            if kind == "PyCode" and isinstance(state, tuple) and len(state) >= 3:
                source, where = _text(state[1]), state[2]
                if source is not None and isinstance(where, tuple) and len(where) >= 2 \
                        and isinstance(where[1], int):
                    located.append((where[1], source))
                    seen.add(id(state[1]))
                    continue
            if kind == "PyExpr" and len(node.s_args) >= 3 and isinstance(node.s_args[2], int) \
                    and isinstance(node.s_args[0], str):
                located.append((node.s_args[2], node.s_args[0]))
                continue
            stack.extend(node.s_args)
            stack.extend(node.s_items)
            stack.append(state)
        elif isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, (list, tuple, set, frozenset)):
            stack.extend(node)
    if stack and not budget:
        limits.hit("rpyc", "more than %d parts in one compiled script: the rest was not read" % _MAX_NODES)
    return located, loose


def _unindented(source: str) -> str:
    """A Python block without the indentation it had inside the script. Ren'Py
    8.4 and later store the block of an ``init python:`` as it stood in the
    file - indented - and indented code is not Python by itself."""
    lines = source.split("\n")
    first = next((line for line in lines if line.strip()), "")
    margin = len(first.expandtabs(4)) - len(first.expandtabs(4).lstrip())
    if not margin:
        return source
    out = []
    for line in lines:
        wide = line.expandtabs(4)
        out.append(wide[margin:] if len(wide) - len(wide.lstrip()) >= margin else wide.lstrip())
    return "\n".join(out)


def decompile(data: bytes, unindent: bool = False) -> Optional[Tuple[str, str, bool]]:
    """``(code, strings, exact)`` for a compiled script, or None if unreadable.

    ``code`` holds the Python blocks and expressions placed at their original
    line numbers (``exact`` is True); ``strings`` holds everything else, one
    per line. If the tree cannot be rebuilt, ``code`` is empty and ``strings``
    falls back to the printable strings of the raw pickle. ``unindent``: every
    block starts at the left margin, as code has to for the analysis (the
    lines stay where they are); ``content_key`` compares the blocks as stored.
    """
    raw = slab(data)
    if raw is None:
        return None
    try:
        tree = _StubUnpickler(io.BytesIO(raw), encoding="latin-1").load()
        located, loose = _collect(tree)
    except Exception:        # hostile or unknown pickle: fall back to plain strings
        strings = dict.fromkeys(s.decode("ascii") for s in _PRINTABLE.findall(raw))
        return "", "\n".join(strings), False
    lines: List[str] = []
    for line, source in sorted(set(located)):
        if len(lines) < line - 1:
            lines.extend([""] * (line - 1 - len(lines)))
        lines.extend((_unindented(source) if unindent else source).split("\n"))
    return "\n".join(lines), "\n".join(dict.fromkeys(loose)), True


def content_key(data: bytes) -> Optional[str]:
    """SHA-256 over what a compiled script contains - its code at its line
    numbers, and the set of its other strings. Two things are left out because
    they differ from one compilation to the next: the path of the source file
    the compiler recorded (the folder on the PC that compiled it), and the
    order of the other strings (names kept in an unordered collection come out
    in another order). Nothing can be added to a script, and no line of code
    changed or moved, without changing the key. None: the script could not be
    rebuilt, so nothing is said about it."""
    import hashlib
    result = decompile(data)
    if result is None or not result[2]:
        return None
    code, strings, _exact = result
    kept = sorted({line for line in strings.split("\n") if not _SOURCE_PATH.fullmatch(line)})
    return hashlib.sha256((code + "\0" + "\n".join(kept)).encode("utf-8", "replace")).hexdigest()
