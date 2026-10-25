"""A cache on disk for work that depends on a file's bytes alone.

Unpacking a file, listing what a .NET library refers to, reading its methods:
none of that depends on the rules, on the folder the file lies in or on what
was scanned before. Its result is kept here and found again the next time the
same file is scanned - the same bytes, read by the same code.

The key of an entry is the file's SHA-256, the kind of work, and the *source
hash* of the module that does the work: the SHA-256 over that module's own
file and over every module of this package it imports, directly or through
others (:func:`source_hash`). A change to that code - and only to that code -
makes its entries unreachable; a change to a rule does not touch them.

What it is not:

* It is a developer's tool (phageo, 2026-10-13), and off for every user: the
  command line, the window and the secure launcher never switch it on and
  have no switch for it. The reason: the place it lies in can be written by
  any program of the user, and a planted entry could make a scan skip a
  file. Only the false-positive benchmark uses it, and only when asked
  (``tools/fp_benchmark.py --cache``), to measure time on clean samples.
* The positive benchmark never uses it and locks it for its whole process
  (:func:`forbid`): text taken from a real sample must not reach the disk.
* It is never inside the application's own folder (so it cannot get into a
  package that is handed on): the benchmark's default is the developer's
  local application data, ``GameSafetyScanner\\cache``.
* It holds no file name and no path - only results, by SHA-256.
* It is no proof of anything. An entry is checked against its own SHA-256
  when it is read (a damaged one is deleted and the work is done again), but
  whoever can write to the user's profile can write an entry - which is why
  no scan a verdict is taken from ever reads one.

Size: all entries together stay under ``MAX_BYTES`` (the least recently used
ones are deleted first); a result larger than ``MAX_ENTRY`` is not kept.
Entries are plain data (JSON, zlib) - nothing is ever unpickled or run.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import tempfile
import zlib
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .unpack import limits

MAGIC = b"GSSC1\n"
MAX_BYTES = 1024 * 1024 * 1024      # all entries together
MAX_ENTRY = 48 * 1024 * 1024        # one entry, as stored (compressed)
_KEEP = 0.8                         # pruning stops at this share of MAX_BYTES
_PACKAGE = os.path.dirname(os.path.abspath(__file__))
_OWN_DIR = os.path.dirname(_PACKAGE)                 # the application's folder
ENV_DIR = "GSS_CACHE_DIR"

_state: Dict[str, Any] = {"dir": None, "bytes": None, "max": MAX_BYTES}
STATS = {"hits": 0, "misses": 0, "stored": 0}
_sources: Dict[str, str] = {}


def default_directory() -> str:
    """Where the cache lies unless told otherwise: ``%LOCALAPPDATA%\\GameSafetyScanner\\cache``
    (``GSS_CACHE_DIR`` names another place)."""
    named = os.environ.get(ENV_DIR)
    if named:
        return os.path.abspath(named)
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "GameSafetyScanner", "cache")


def _inside_application(directory: str) -> bool:
    try:
        return os.path.commonpath([os.path.normcase(os.path.abspath(directory)),
                                   os.path.normcase(_OWN_DIR)]) == os.path.normcase(_OWN_DIR)
    except ValueError:                                  # (another drive)
        return False


def configure(directory: Optional[str] = None, enabled: bool = True, max_bytes: Optional[int] = None) -> Optional[str]:
    """Switch the cache on, in ``directory`` - a developer's tool names the folder itself;
    without a folder the cache is off. Returns the folder in use, or None when it is off -
    also when the process has forbidden it (:func:`forbid`), when the folder lies inside
    the application's own folder or cannot be made: then the scan simply works without."""
    _state.update(dir=None, bytes=None, max=MAX_BYTES if max_bytes is None else max_bytes)
    if not enabled or not directory or _state.get("forbidden"):
        return None
    directory = os.path.abspath(directory)
    if _inside_application(directory):
        return None
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        return None
    _state["dir"] = directory
    return directory


def off() -> None:
    configure(enabled=False)


def forbid() -> None:
    """Off for the rest of this process, whatever is configured later (the positive
    benchmark: nothing taken from a real sample is written to disk)."""
    _state["forbidden"] = True
    off()


@contextlib.contextmanager
def suspended() -> Iterator[None]:
    """Inside the block the cache is off, whatever was configured (the secure launcher's
    scan: every file is read anew)."""
    held = dict(_state)
    _state["dir"] = None
    try:
        yield
    finally:
        _state.update(held)


def directory() -> Optional[str]:
    """The folder in use (None: the cache is off)."""
    return _state["dir"]


# -- the source hash of a module --------------------------------------------------------------
def _module_file(name: str) -> Optional[str]:
    """The file of the module ``gamescan.x.y`` of this package (None: not one of ours)."""
    parts = name.split(".")
    if parts[0] != os.path.basename(_PACKAGE):
        return None
    base = os.path.join(_PACKAGE, *parts[1:])
    for path in (base + ".py", os.path.join(base, "__init__.py")):
        if os.path.isfile(path):
            return path
    return None


def _imports(name: str, path: str, source: bytes) -> List[str]:
    """The modules of this package that the module ``name`` imports, anywhere in its file."""
    package = name if os.path.basename(path) == "__init__.py" else name.rpartition(".")[0]
    found: List[str] = []
    for node in ast.walk(ast.parse(source)):            # (read as a syntax tree: nothing is run)
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package.split(".")
            if node.level:
                base = base[:len(base) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            found.append(target)
            found += ["%s.%s" % (target, alias.name) for alias in node.names]
    return found


def source_hash(module: str) -> str:
    """SHA-256 over the source of ``module`` (``"gamescan.pe"``) and of every module of this
    package it imports, directly or through others - what the result of its work can
    depend on, as far as the code goes."""
    known = _sources.get(module)
    if known is not None:
        return known
    digest = hashlib.sha256()
    for name, own in sorted(sources(module).items()):
        digest.update(("%s %s\n" % (name, own)).encode())
    known = _sources[module] = digest.hexdigest()
    return known


def sources(module: str) -> Dict[str, str]:
    """The modules :func:`source_hash` counts for ``module``, each with the SHA-256 of its file."""
    seen: Dict[str, str] = {}
    todo = [module]
    while todo:
        name = todo.pop()
        path = _module_file(name)
        if path is None or name in seen:
            continue
        with open(path, "rb") as fh:
            source = fh.read()
        digest = hashlib.sha256(source)
        if path == os.path.join(_PACKAGE, "indicators.py"):
            # the strings the modules use stand beside it as data (antivirus false positives,
            # phageo 2026-10-24): a change in them is a change of the code
            with open(os.path.join(_PACKAGE, "indicators.bin"), "rb") as fh:
                digest.update(fh.read())
        seen[name] = digest.hexdigest()
        # (what the module names itself; a package's ``__init__`` counts only where it is imported)
        todo += _imports(name, path, source)
    return seen


# -- entries --------------------------------------------------------------------------------------
def _path(kind: str, sha256: str, module: str, extra: str) -> str:
    key = hashlib.sha256(("%s|%s|%s|%s" % (kind, sha256, source_hash(module), extra)).encode()).hexdigest()
    return os.path.join(_state["dir"], key[:2], key[2:42] + ".gssc")


def get(kind: str, sha256: str, module: str, extra: str = "") -> Optional[bytes]:
    """The kept result (bytes), or None."""
    if _state["dir"] is None or not sha256:
        return None
    path = _path(kind, sha256, module, extra)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        STATS["misses"] += 1
        return None
    head = len(MAGIC) + 32
    if raw[:len(MAGIC)] != MAGIC or hashlib.sha256(raw[head:]).digest() != raw[len(MAGIC):head]:
        _remove(path)                                   # damaged or of another form: done again
        STATS["misses"] += 1
        return None
    try:
        payload = zlib.decompress(raw[head:])
    except zlib.error:
        _remove(path)
        STATS["misses"] += 1
        return None
    try:
        os.utime(path, None)                            # used now: pruned last
    except OSError:
        pass
    STATS["hits"] += 1
    return payload


def put(kind: str, sha256: str, module: str, payload: bytes, extra: str = "") -> bool:
    """Keep a result. False: the cache is off, the result is too large, or the disk refused."""
    if _state["dir"] is None or not sha256:
        return False
    packed = zlib.compress(payload, 3)
    if len(packed) > MAX_ENTRY or len(packed) > _state["max"] // 4:
        return False
    path = _path(kind, sha256, module, extra)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # (written beside its place and moved there: another scan never reads half an entry)
        handle, temporary = tempfile.mkstemp(prefix="put-", suffix=".tmp", dir=os.path.dirname(path))
        with os.fdopen(handle, "wb") as fh:
            fh.write(MAGIC + hashlib.sha256(packed).digest() + packed)
        os.replace(temporary, path)
    except OSError:
        return False
    STATS["stored"] += 1
    if _state["bytes"] is None:
        _state["bytes"] = _size()
    else:
        _state["bytes"] += len(packed) + len(MAGIC) + 32
    if _state["bytes"] > _state["max"]:
        prune()
    return True


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _entries() -> List[Tuple[float, int, str]]:
    out: List[Tuple[float, int, str]] = []
    root = _state["dir"]
    if root is None:
        return out
    for base, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith((".gssc", ".tmp")):
                path = os.path.join(base, name)
                try:
                    info = os.stat(path)
                except OSError:
                    continue
                out.append((info.st_mtime, info.st_size, path))
    return out


def _size() -> int:
    return sum(size for _used, size, _path in _entries())


def prune(limit: Optional[int] = None) -> int:
    """Delete the entries used longest ago until all together are under ``_KEEP`` of the
    limit. Returns the bytes that are left."""
    limit = _state["max"] if limit is None else limit
    entries = sorted(_entries())
    total = sum(size for _used, size, _path in entries)
    for _used, size, path in entries:
        if total <= limit * _KEEP:
            break
        _remove(path)
        total -= size
    _state["bytes"] = total
    return total


def clear() -> None:
    """Delete every entry (the folder stays)."""
    for _used, _size_, path in _entries():
        _remove(path)
    _state["bytes"] = 0


# -- the one way work is kept ---------------------------------------------------------------------
def kept(kind: str, sha256: str, module: str, work: Callable[[], Any], extra: str = "",
         encode: Callable[[Any], Any] = lambda value: value,
         decode: Callable[[Any], Any] = lambda value: value) -> Any:
    """``work()`` - from the cache when the same file was read by the same code before.
    ``encode`` turns the result into plain data (what JSON holds), ``decode`` back; an
    entry that does not decode is thrown away and the work is done. A limit a format
    reader reached during the work (``unpack/limits.py``) is kept with the result and said
    again when the result is taken from the cache: the "not read" note does not depend on
    where the result came from. Work that ends in an error is not kept."""
    if _state["dir"] is None or not sha256:
        return work()
    raw = get(kind, sha256, module, extra)
    if raw is not None:
        try:
            entry = json.loads(raw.decode("ascii"))
            value, reached = decode(entry["value"]), [(str(reader), str(what)) for reader, what in entry["limits"]]
        except Exception:                               # an entry of a form this code does not expect
            _remove(_path(kind, sha256, module, extra))
            STATS["hits"] -= 1
            STATS["misses"] += 1
        else:
            for reader, what in reached:
                limits.hit(reader, what)
            return value
    with limits.watch() as reached:
        value = work()
    for reader, what in reached:                        # (to whoever watches the file itself)
        limits.hit(reader, what)
    try:
        put(kind, sha256, module, json.dumps({"value": encode(value), "limits": reached},
                                             separators=(",", ":")).encode("ascii"), extra)
    except (TypeError, ValueError, UnicodeError, MemoryError):
        pass                                            # not plain data after all: simply not kept
    return value
