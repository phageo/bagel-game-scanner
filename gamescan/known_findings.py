"""What the readers find in the larger files of the official tables - kept when the tables are
built, so that a scan does not read those files again (phageo, 2026-10-14, forty-third message:
"precompute pattern findings of verified npm / Electron files when the tables are built; skip
those files at scan time, still show their findings"; outputs byte-identical).

A file of a published npm package (``npm_hashes``) or of an official Electron release
(``electron_official``), by its exact SHA-256 and at least ``MIN_SIZE`` bytes, is read once by
``tools/build_known_findings.py``: what the file's reader returns (``handler.scan`` - its
findings, before they are judged) and the notes the reading leaves for the later steps
(``ctx.cache``) are kept in ``known_findings.json.gz``. A scan that meets the same file gives
that back instead of reading it (``Scanner._scan_one``); everything after the reading - the
checks of the file's name, the judging of each finding, the chains, the joins after the scan -
runs as for any file, so the findings are the same ones, shown the same way.

Kept only when it cannot differ from a reading:

* the data is tied to the code it came from: ``fingerprint()`` (SHA-256 over every source file
  of the package) must equal the one it was built with - any change of the code, a rule or a
  table makes it unused until it is built again (a test says when it is out of date);
* the builder reads every file twice, under two unrelated paths, and keeps it only when both
  readings give the same (so nothing of it depends on where the file lies);
* a scan uses it only for the same reader, the same file ending, the same baseline, the whole
  file read (not cut at the size limit) and the same notes present before the reading;
* only plain values are kept (text, numbers, lists, sets, the scanner's own small records);
  a file whose reading leaves anything else is not kept.

It is no cache in the user's profile (phageo, 2026-10-13: a cache any program can write to could
make a scan skip a file): the data is part of the package, made from official files only, and
nothing in it is ever learned from a scanned file.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import fields
from typing import Any, Dict, List, Optional, Tuple

from .models import Category, Finding, Severity

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_findings.json.gz")
MIN_SIZE = 128 * 1024               # smaller files are read again (quick enough)
FORMAT = 2                          # 2: texts of the file kept as places in it (packaging session 3)
# Texts the reading took from the file (snippets, evidence, context, notes) are not kept as text
# but as places in the file's own text - ``[start, length]`` - with our own words between them,
# and a hash of the whole text (phageo, packaging session 3: "ship no excerpts"). A scan meets the
# same file (same SHA-256) and puts the texts together again from it; a hash that does not match
# means the file is read as usual (``Mismatch``). Pieces under ``MIN_PIECE`` characters stay words.
MIN_PIECE = 6
# fields of a finding that may hold text of the file (the others are the scanner's own words)
_FILE_FIELDS = frozenset({"snippet", "evidence", "context"})
# the views of the file's bytes a text is looked for in: UTF-8 (also every ASCII text), UTF-16
_VIEWS = (("u", "utf-8"), ("w", "utf-16-le"))


class Mismatch(Exception):
    """A text put together from the file is not the kept one: read the file instead."""


class Places:
    """Texts of one file as places in it (``encode_text``) and back (``decode_text``)."""

    def __init__(self, data: bytes) -> None:
        self.data, self._views = data, {}

    def view(self, key: str) -> str:
        if key not in self._views:
            self._views[key] = self.data.decode(dict(_VIEWS)[key], "replace")
        return self._views[key]

    def _longest(self, s: str, pos: int):
        """``(view, start, length)`` of the longest piece of ``s`` from ``pos`` in a view."""
        best = None
        for key, _codec in _VIEWS:
            text = self.view(key)
            if text.find(s[pos:pos + MIN_PIECE]) < 0:
                continue
            lo, hi = MIN_PIECE, len(s) - pos
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if s[pos:pos + mid] in text:
                    lo = mid
                else:
                    hi = mid - 1
            if best is None or lo > best[2]:
                best = (key, text.find(s[pos:pos + lo]), lo)
            if lo == len(s) - pos:
                break
        return best

    def encode_text(self, s: str) -> Any:
        """``{"r": [parts], "h": hash}``; a part is ``[view, start, length]`` or own words."""
        if len(s) < MIN_PIECE:
            return s
        parts: List[Any] = []
        words, pos = "", 0
        while pos < len(s):
            piece = self._longest(s, pos) if len(s) - pos >= MIN_PIECE else None
            if piece is None:
                words += s[pos]
                pos += 1
                continue
            if words:
                parts.append(words)
                words = ""
            parts.append(list(piece))
            pos += piece[2]
        if words:
            parts.append(words)
        if all(isinstance(p, str) for p in parts):
            return s                                   # nothing of the file in it
        return {"r": parts, "h": hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16]}

    def decode_text(self, value: dict) -> str:
        s = "".join(p if isinstance(p, str) else self.view(p[0])[p[1]:p[1] + p[2]] for p in value["r"])
        if hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16] != value["h"]:
            raise Mismatch(value["h"])
        return s

    def encode(self, value: Any) -> Any:
        """``value`` (already ``encode``-d) with every text of it as places."""
        if isinstance(value, str):
            return self.encode_text(value)
        if isinstance(value, list):
            return [self.encode(v) for v in value]
        if isinstance(value, dict):
            if set(value) in ({"S"}, {"C"}):
                return value
            if set(value) == {"r", "h"}:
                raise Unstorable("a value that looks like places")
            return {k: self.encode(v) for k, v in value.items()}
        return value

    def decode(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self.decode(v) for v in value]
        if isinstance(value, dict):
            if set(value) == {"r", "h"}:
                return self.decode_text(value)
            return {k: self.decode(v) for k, v in value.items()}
        return value
# notes a container leaves on a member before it is read that only decide its baseline
# (Scanner._scan_one), not what its reader finds
_PARENT_NOTES = frozenset({"signed_container"})
_FILE = "\x00file"                  # a finding's file that is the file itself

_data: Optional[dict] = None
_print: Optional[str] = None


class Unstorable(Exception):
    """A value of a reading that this file does not keep."""


# the experimental "Protection" window and real-time protection: they never take part in a scan
# and are left out of the 0.9-beta package, which must give the same fingerprint (phageo, 2026-10-24)
NOT_SCAN_CODE = frozenset({"monitor.py", "protection.py"})
# data that is part of the code: the strings moved out of the modules' text (``indicators.py``;
# phageo, 2026-10-24, antivirus false positives) - a change in it is a change of the code
CODE_DATA = frozenset({"indicators.bin"})
# the user package ships its modules without comments and docstrings (tools/source_form.py, the
# same code by syntax tree; phageo, 2026-10-24): its builder writes the project's fingerprint here
SHIPPED_PRINT = "shipped_fingerprint.txt"


def fingerprint() -> str:
    """SHA-256 over every source file of the package (name and content, in name order),
    except the experimental modules of ``NOT_SCAN_CODE``, and over ``CODE_DATA`` - or, in the
    user package, the one its builder wrote into ``SHIPPED_PRINT``."""
    global _print
    if _print is None:
        root = os.path.dirname(os.path.abspath(__file__))
        try:
            with open(os.path.join(root, SHIPPED_PRINT), "rb") as fh:
                shipped = fh.read(200).decode("ascii").strip()
        except (OSError, UnicodeDecodeError):
            shipped = ""
        if len(shipped) == 64 and all(c in "0123456789abcdef" for c in shipped):
            _print = shipped
            return _print
        digest = hashlib.sha256()
        names = []
        for base, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            names += [os.path.join(base, n) for n in files if (n.endswith(".py") or n in CODE_DATA)
                      and not (base == root and n in NOT_SCAN_CODE)]
        for path in sorted(names, key=lambda p: os.path.relpath(p, root).replace("\\", "/")):
            digest.update(os.path.relpath(path, root).replace("\\", "/").encode() + b"\x00")
            with open(path, "rb") as fh:
                digest.update(hashlib.sha256(fh.read()).digest())
        _print = digest.hexdigest()
    return _print


# -- plain values -------------------------------------------------------------------------------
def _records() -> Dict[str, type]:
    from .dataflow import electron_windows, remote
    return {"remote.Start": remote.Start, "electron_windows.Script": electron_windows.Script,
            "electron_windows.Window": electron_windows.Window}


def encode(value: Any, records: Optional[Dict[type, str]] = None) -> Any:
    if records is None:
        records = {cls: name for name, cls in _records().items()}
    if isinstance(value, Severity):
        return {"S": value.name}
    if isinstance(value, Category):                 # (a str too: before the plain texts)
        return {"C": value.value}
    if value is None or type(value) in (bool, str):
        return value
    if isinstance(value, (int, float)) and type(value) in (int, float):
        return value
    name = records.get(type(value))
    if name is not None:
        return {"n": name, "v": [encode(v, records) for v in value]}
    if type(value) is list:
        return [encode(v, records) for v in value]
    if type(value) is tuple:
        return {"t": [encode(v, records) for v in value]}
    if type(value) in (set, frozenset):
        items = sorted((encode(v, records) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        return {"f" if type(value) is frozenset else "s": items}
    if type(value) is dict:
        if all(type(k) is str for k in value):
            return {"d": {k: encode(v, records) for k, v in value.items()}}
        return {"D": [[encode(k, records), encode(v, records)] for k, v in value.items()]}
    raise Unstorable(type(value).__name__)


def decode(value: Any, records: Optional[Dict[str, type]] = None) -> Any:
    if not isinstance(value, (dict, list)):
        return value
    if records is None:
        records = _records()
    if isinstance(value, list):
        return [decode(v, records) for v in value]
    if "n" in value:
        return records[value["n"]](*(decode(v, records) for v in value["v"]))
    (tag, inner), = value.items()
    if tag == "S":
        return Severity[inner]
    if tag == "C":
        return Category(inner)
    if tag == "t":
        return tuple(decode(v, records) for v in inner)
    if tag == "s":
        return {decode(v, records) for v in inner}
    if tag == "f":
        return frozenset(decode(v, records) for v in inner)
    if tag == "d":
        return {k: decode(v, records) for k, v in inner.items()}
    if tag == "D":
        return {decode(k, records): decode(v, records) for k, v in inner}
    raise ValueError("unknown tag %r" % tag)


def encode_finding(f: Finding, relpath: str) -> dict:
    out = {}
    for spec in fields(Finding):
        value = getattr(f, spec.name)
        if spec.name == "file" and value == relpath:
            value = _FILE
        out[spec.name] = encode(value)
    return out


def decode_finding(row: dict, relpath: str) -> Finding:
    values = {k: decode(v) for k, v in row.items()}
    if values.get("file") == _FILE:
        values["file"] = relpath
    return Finding(**values)


# -- what a scan asks ---------------------------------------------------------------------------
def entry(sha256: str) -> Optional[dict]:
    """The kept reading of the file with this SHA-256 (None: none, or not of this code)."""
    global _data
    if _data is None:
        _data = {}
        try:
            with gzip.open(DATA, "rt", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if loaded.get("format") == FORMAT and loaded.get("code") == fingerprint():
                _data = loaded.get("files", {})
        except (OSError, ValueError, EOFError):
            _data = {}
    return _data.get(sha256)


def before(cache: Dict[str, Any]) -> List[str]:
    """The notes a file carries before its reading that a kept reading must match."""
    return sorted(k for k in cache if k not in _PARENT_NOTES)


def usable(row: dict, ctx, handler: str) -> bool:
    return (row["handler"] == handler and row["ext"] == ctx.ext and row["baseline"] == ctx.baseline
            and row["size"] == ctx.size and not ctx.truncated and row["before"] == before(ctx.cache))


def _texts(row: dict, change) -> dict:
    """``row`` (an encoded finding) with ``change`` applied to the fields that may hold file text."""
    return {k: change(v) if k in _FILE_FIELDS else v for k, v in row.items()}


def replay(row: dict, ctx) -> List[Finding]:
    """The kept reading of ``ctx``'s file: its findings, and its notes put into ``ctx.cache``.
    Raises ``Mismatch`` (nothing changed) when a text cannot be put together from the file."""
    places = Places(ctx.data)
    found = [decode_finding(_texts(f, places.decode), ctx.relpath) for f in row["findings"]]
    notes = {key: decode(places.decode(value)) for key, value in row["cache"].items()}
    ctx.cache.update(notes)
    return found


def record(ctx, handler: str, found: List[Finding], pre: List[str], added: Dict[str, Any]) -> dict:
    """What the builder keeps of one reading (raises Unstorable): texts of the file as places,
    kept only when putting them together again gives exactly the reading."""
    places = Places(ctx.data)
    plain = [encode_finding(f, ctx.relpath) for f in found]
    notes = {k: encode(v) for k, v in sorted(added.items())}
    findings = [_texts(f, places.encode) for f in plain]
    cache = {k: places.encode(v) for k, v in notes.items()}
    try:
        again = ([_texts(f, places.decode) for f in findings], {k: places.decode(v) for k, v in cache.items()})
    except Mismatch:
        raise Unstorable("places")
    if json.dumps(again, sort_keys=True) != json.dumps((plain, notes), sort_keys=True):
        raise Unstorable("places")
    return {"handler": handler, "ext": ctx.ext, "baseline": ctx.baseline, "size": ctx.size,
            "before": pre, "findings": findings, "cache": cache}
