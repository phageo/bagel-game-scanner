"""Values and safe primitives shared by the payload resolvers.

Nothing here runs scanned code. The resolvers *model* what a script would
compute, using only the pure, bounded helpers below on plain strings, bytes
and numbers that the scanner built itself.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import lzma
import re
import time
import zlib
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple
from urllib.parse import unquote, unquote_plus

OPEN, CLOSE = "‹", "›"           # ‹name› marks a part that is only known at runtime
MAX_TEXT = 1 << 20                          # longest string / bytes value that is modelled
MAX_ITEMS = 1 << 16                         # longest list that is modelled
MAX_STEPS = 250_000                         # the limit: the same file is always cut at the same place
# The clock decides nothing (phageo, 2026-10-13): a verdict must not depend on how fast the PC is.
# Every reading is bounded by counts - steps, sites, sizes. The seconds are a far safety cap
# for the case nobody foresaw (ten minutes; five seconds until 2026-10-13, which a busy PC
# reached before the count in a large packed script); when it fires that is said, always.
SAFETY_SECONDS = 600.0
MAX_SECONDS = SAFETY_SECONDS                # the safety cap only; when it fires that is said too
MAX_DEPTH = 3                               # exec-inside-exec layers that are followed

_HOLE = re.compile(OPEN + "[^" + CLOSE + "]*" + CLOSE)


@dataclass
class Resolved:
    """What really reaches a sensitive call once the code's string building is undone."""

    kind: str                     # exec | command | url | path | call
    line: Optional[int]
    sink: str                     # the function that receives the value (os.system, eval ...)
    value: str                    # the resolved text; ‹name› marks runtime-only parts
    hidden: bool = False          # the value went through a decoder (base64, chr, XOR ...)
    partial: bool = False         # some parts are only known at runtime
    delete: bool = False          # path kind: the target is deleted
    dynamic: bool = False         # the function itself was looked up by a built-up name
    trivial: bool = False         # a plain literal at the call: the ordinary rules see it
    layer: int = 0                # 0 = the file itself, 1+ = inside decoded code
    trace: Tuple[str, ...] = ()   # variables the value came from


class Budget(Exception):
    """A limit was reached; the analysis stops and keeps what it has."""


TOO_LARGE = "a value larger than the scanner models"
TOO_DEEP = "nested too deeply"


SIZE, STEP_LIMIT, SAFETY_CAP = "size", "step limit", "safety cap"
_SIZE_WORDS = re.compile(r"larger than \d+ MB|too large to be read")
_CAP_WORDS = re.compile(r"-?\d+ seconds\b")


def cause(limit: str) -> str:
    """Which of the three kinds of limit ``limit`` names (phageo, 2026-10-13: a limit note
    says its cause): ``SIZE`` - the script is larger than what is read of a script;
    ``SAFETY_CAP`` - the far cap by the clock (``SAFETY_SECONDS``), which is not meant to be
    reached and depends on the PC; ``STEP_LIMIT`` - every limit that is a count (steps,
    lines, statements, classes, depth), the same for the same file on every PC."""
    if _CAP_WORDS.search(limit):
        return SAFETY_CAP
    if _SIZE_WORDS.search(limit):
        return SIZE
    return STEP_LIMIT


def also(told: str, limit: str) -> str:
    """``told`` (the limits a reading has named so far, "; " between them) with ``limit``
    added when its cause is not named yet. Until 2026-10-13 the first limit won and a
    second one was dropped: a script cut for its size hid that its reading had stopped at
    a step limit or at the clock as well."""
    if not limit or not told:
        return told or limit
    named = {cause(part) for part in told.split("; ")}
    for part in limit.split("; "):
        if cause(part) not in named:
            named.add(cause(part))
            told += "; " + part
    return told


class Clock:
    """Step budget of one analysis (shared by nested layers). The steps are the
    limit - a count, so the same file is always cut at the same place; the
    seconds are an emergency brake for a PC so slow that the steps take too
    long. ``stopped`` names the limit that ended the analysis ("": none did),
    so that whoever asked can say so (SCRIPT-LIMIT-001; phageo, 2026-10-12)."""

    def __init__(self, steps: Optional[int] = None, seconds: Optional[float] = None) -> None:
        self.steps = self.limit = MAX_STEPS if steps is None else steps
        self.seconds = MAX_SECONDS if seconds is None else seconds
        self.deadline = time.monotonic() + self.seconds
        self.stopped = ""

    def tick(self, cost: int = 1) -> None:
        before = self.steps
        self.steps = left = before - cost
        if left <= 0:
            self.stopped = self.stopped or "more than %d steps" % self.limit
            raise Budget()
        # (the clock is looked at once per 256 steps, whatever the single costs are)
        if before >> 8 != left >> 8 and time.monotonic() > self.deadline:
            self.stopped = self.stopped or "%.0f seconds" % self.seconds
            raise Budget()

    def ended(self, error: BaseException) -> None:
        """An analysis that shares this clock gave up because of ``error``."""
        if not self.stopped:
            self.stopped = TOO_DEEP if isinstance(error, RecursionError) else TOO_LARGE


class Sym:
    """A value that is not (fully) known: text with ‹holes› in it."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text[:MAX_TEXT]

    def __repr__(self) -> str:
        return "Sym(%r)" % self.text


class Ref:
    """A module, class or function referred to by its dotted name. ``dynamic``
    is set when the name was assembled at runtime (getattr, __import__ ...)."""

    __slots__ = ("name", "dynamic")

    def __init__(self, name: str, dynamic: bool = False) -> None:
        self.name, self.dynamic = name, dynamic

    def __repr__(self) -> str:
        return "Ref(%r)" % self.name


def hole(name: str) -> Sym:
    return Sym(OPEN + str(name)[:60].replace(CLOSE, "") + CLOSE)


def is_plain(value: Any, depth: int = 0) -> bool:
    """Fully known data made of ordinary immutable-ish Python values."""
    if value is None or isinstance(value, (str, bytes, bool, int, float)):
        return True
    if depth < 6 and isinstance(value, (list, tuple)):
        return all(is_plain(v, depth + 1) for v in value)
    if depth < 6 and isinstance(value, dict):
        return all(is_plain(k, depth + 1) and is_plain(v, depth + 1) for k, v in value.items())
    return False


def text_of(data: bytes) -> str:
    """Bytes as the text they most plausibly are."""
    for encoding in ("utf-8", "utf-16-le" if data[1:2] == b"\0" else "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def show(value: Any) -> str:
    """Readable form of a resolved value (argument lists become a command line)."""
    if isinstance(value, Sym):
        return value.text
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return text_of(bytes(value))
    if isinstance(value, Ref):
        return OPEN + value.name + CLOSE
    if isinstance(value, bool) or value is None:
        return str(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return " ".join(show(v) for v in value[:64])
    return OPEN + "?" + CLOSE


def known_part(text: str) -> str:
    """The text without its ‹holes›."""
    return _HOLE.sub("", text)


def is_partial(text: str) -> bool:
    return _HOLE.search(text) is not None


def stringish(value: Any) -> bool:
    return isinstance(value, (str, Sym))


def concat(a: Any, b: Any) -> Any:
    """``a + b`` for strings where either side may have holes."""
    if isinstance(a, str) and isinstance(b, str):
        return cap(a + b)
    if isinstance(a, bytes) and isinstance(b, bytes):
        return cap(a + b)
    if isinstance(a, (str, bytes, Sym, Ref)) and isinstance(b, (str, bytes, Sym, Ref)):
        return Sym(show(a) + show(b))
    return None


def cap(value: Any) -> Any:
    if isinstance(value, (str, bytes, list, tuple)) and len(value) > (
            MAX_TEXT if isinstance(value, (str, bytes)) else MAX_ITEMS):
        raise Budget()
    return value


# -- decoders -------------------------------------------------------------------
def _raw(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1", "ignore") if len(value) <= MAX_TEXT else b""
    raise ValueError("not data")


def inflate(data: bytes, wbits: int = 15) -> bytes:
    """zlib / gzip / raw deflate with a hard output limit."""
    try:
        engine = zlib.decompressobj(wbits)
        out = engine.decompress(data, MAX_TEXT)
    except zlib.error as exc:
        raise ValueError(str(exc))
    if engine.unconsumed_tail:
        raise ValueError("decompressed data too large")
    return out


def _bounded(engine, data: bytes) -> bytes:
    try:
        out = engine.decompress(data, MAX_TEXT)
    except (OSError, ValueError, EOFError, lzma.LZMAError) as exc:
        raise ValueError(str(exc))
    if not engine.eof:
        raise ValueError("decompressed data too large or incomplete")
    return out


def b64(value: Any, altchars: Optional[bytes] = None) -> bytes:
    data = _raw(value)
    if altchars:
        data = data.translate(bytes.maketrans(altchars, b"+/"))
    data = re.sub(rb"[^A-Za-z0-9+/]", b"", data)
    try:
        return base64.b64decode(data + b"=" * (-len(data) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ValueError(str(exc))


def unhex(value: Any) -> bytes:
    try:
        return bytes.fromhex(show(value) if not isinstance(value, bytes) else value.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(str(exc))


def rot13(value: Any) -> str:
    return codecs.decode(show(value), "rot_13")


_CODECS = {
    "utf8": "utf-8", "utf-8": "utf-8", "utf_8": "utf-8", "ascii": "ascii", "latin1": "latin-1",
    "latin-1": "latin-1", "latin_1": "latin-1", "iso-8859-1": "latin-1", "cp1252": "cp1252",
    "utf16": "utf-16", "utf-16": "utf-16", "utf-16le": "utf-16-le", "utf-16-le": "utf-16-le",
    "utf_16_le": "utf-16-le", "utf-16-be": "utf-16-be", "unicode": "utf-16-le",
    "binary": "latin-1", "ucs2": "utf-16-le",
}
_TRANSFORMS = {
    "base64": b64, "base_64": b64, "base64_codec": b64,
    "hex": unhex, "hex_codec": unhex,
    "zlib": lambda v: inflate(_raw(v)), "zip": lambda v: inflate(_raw(v)),
    "zlib_codec": lambda v: inflate(_raw(v)),
    "bz2": lambda v: _bounded(bz2.BZ2Decompressor(), _raw(v)),
    "rot13": rot13, "rot_13": rot13, "rot-13": rot13,
}


def decode(value: Any, encoding: Any = "utf-8"):
    """``value.decode(encoding)`` / ``codecs.decode`` for the codecs malware uses.
    Returns ``(result, hidden)``; hidden means the codec is an obfuscating one."""
    name = show(encoding).lower().strip() or "utf-8"
    if name in _TRANSFORMS:
        return _TRANSFORMS[name](value), True
    if name in _CODECS:
        if isinstance(value, str):
            return value, False
        return _raw(value).decode(_CODECS[name], "replace"), False
    raise ValueError("unsupported codec")


def encode(value: Any, encoding: Any = "utf-8"):
    name = show(encoding).lower().strip() or "utf-8"
    if name in ("rot13", "rot_13", "rot-13"):
        return rot13(value), True
    if name in _CODECS:
        if isinstance(value, bytes):
            return value, False
        return str(value).encode(_CODECS[name], "replace"), False
    raise ValueError("unsupported codec")


def decompress(kind: str, value: Any) -> bytes:
    data = _raw(value)
    if kind == "zlib":
        return inflate(data, 15 if data[:1] == b"\x78" else -15)
    if kind == "gzip":
        return inflate(data, 47)
    if kind == "bz2":
        return _bounded(bz2.BZ2Decompressor(), data)
    if kind == "lzma":
        return _bounded(lzma.LZMADecompressor(), data)
    raise ValueError(kind)


def b_decode(kind: str, value: Any) -> bytes:
    data = _raw(value)
    if len(data) > MAX_TEXT:
        raise ValueError("too large")
    try:
        if kind == "b64":
            return b64(data)
        if kind == "urlsafe":
            return b64(data, b"-_")
        if kind == "b32":
            return base64.b32decode(data + b"=" * (-len(data) % 8), casefold=True)
        if kind == "b16":
            return base64.b16decode(data, casefold=True)
        if kind == "b85":
            return base64.b85decode(data)
        if kind == "a85":
            return base64.a85decode(data)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(str(exc))
    raise ValueError(kind)


def url_unquote(value: Any, plus: bool = False) -> str:
    return (unquote_plus if plus else unquote)(show(value))


def js_unescape(text: str) -> str:
    """JavaScript ``unescape``: %XX and %uXXXX."""
    return re.sub(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})",
                  lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


# -- formatting -------------------------------------------------------------------
_WIDE = re.compile(r"\d{4,}|\*")


def percent(fmt: Any, args: Any) -> Any:
    """``fmt % args`` with no way to ask for a gigantic field width."""
    text = show(fmt)
    if _WIDE.search(text):
        return hole("format")
    values = args if isinstance(args, tuple) else (args,)
    partial = isinstance(fmt, Sym) or any(isinstance(v, (Sym, Ref)) for v in values)
    shown = tuple(show(v) if isinstance(v, (Sym, Ref, bytes)) else v for v in values)
    try:
        if isinstance(args, dict) and is_plain(args):
            out = text % args
        else:
            out = text % shown
    except (TypeError, ValueError, KeyError):
        # a runtime-only value where a number is expected: fill what can be filled
        pieces = iter(shown)
        out = re.sub(r"%(?:\([^)]*\))?[-+ #0]*\d*(?:\.\d+)?[a-zA-Z]",
                     lambda m: str(next(pieces, OPEN + "?" + CLOSE)), text)
        partial = True
    return Sym(out) if partial or is_partial(out) else cap(out)


def brace_format(fmt: Any, args: List[Any], kwargs: dict) -> Any:
    """``fmt.format(...)`` for plain ``{}``, ``{0}`` and ``{name}`` fields only."""
    text = show(fmt)
    auto = iter(range(len(args)))
    partial = [isinstance(fmt, Sym)]

    def field(m: "re.Match[str]") -> str:
        if m.group(0) in ("{{", "}}"):
            return m.group(0)[0]
        key = m.group(1)
        try:
            if key == "":
                value = args[next(auto)]
            elif key.isdigit():
                value = args[int(key)]
            else:
                value = kwargs[key]
        except (StopIteration, IndexError, KeyError):
            partial[0] = True
            return OPEN + (key or "?") + CLOSE
        if isinstance(value, (Sym, Ref)):
            partial[0] = True
        return show(value)

    # conversions and format specs ({!r}, {:>10}) are dropped: they cannot hide text
    out = re.sub(r"\{\{|\}\}|\{([\w]*)(?:![rsa])?(?::[^{}]{0,12})?\}", field, text)
    return Sym(out) if partial[0] or is_partial(out) else cap(out)


def join_path(parts: List[Any]) -> Any:
    out = ""
    for part in parts:
        piece = show(part)
        if re.match(r"[A-Za-z]:[\\/]|[\\/]", piece) or not out:
            out = piece
        else:
            out = out.rstrip("\\/") + "\\" + piece
    return Sym(out) if any(isinstance(p, (Sym, Ref)) for p in parts) or is_partial(out) else out


def powershell_encoded(command: str) -> Optional[str]:
    """The script hidden in a ``powershell -EncodedCommand <base64>`` call."""
    m = re.search(r"(?i)(?:^|[\s\"'/])-e(?:nc(?:odedcommand)?|c)?\s+[\"']?([A-Za-z0-9+/]{16,}={0,2})",
                  command)
    if not m:
        return None
    try:
        raw = b64(m.group(1))
    except ValueError:
        return None
    text = raw.decode("utf-16-le", "replace")
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return text if text and printable >= len(text) * 0.9 else None
