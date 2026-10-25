"""CHAIN-LOCAL-DROP made CRITICAL by proof (phageo, 2026-10-17).

A script reads a file of the game, decodes it, writes or unpacks the result and starts
it (``dataflow/remote_py.local_drops``): HIGH. CRITICAL only when the decoded result is
shown to be a program, or an archive that holds one. To show it the script's own decoding
steps are applied to that file - the encoded file of the same scan, found by its name -
**in memory only**: nothing is written to disk, and the input and every step's output are
capped. Only the head of the result is looked at: ``MZ`` with a PE header, or a zip whose
own list of entries names a program. Nothing is run, imported or unpacked to disk; a zip's
list is read, no member is opened.

Steps that can be applied again: Base64 (also URL-safe, Base32, Base85 / Ascii85), hex,
zlib, gzip, bz2, lzma, XOR with a key written out in the script, a part cut out with
numbers written out (``data[16:]``). Any other step (a decompressor of its own, ``translate``,
other byte-wise arithmetic, a key that is not written out) leaves the chain HIGH.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import io
import lzma
import struct
import threading
import zipfile
import zlib
from typing import Optional, Sequence, Tuple

MAX_INPUT = 64 * 1024 * 1024        # an encoded file larger than this is not decoded
MAX_OUTPUT = 128 * 1024 * 1024      # ... and no step may give more than this
MAX_CANDIDATES = 4                  # files of the same name tried for one chain
PROGRAM_ENDINGS = (".exe", ".dll", ".scr", ".com", ".msi", ".node", ".sys", ".cpl", ".ocx", ".pif", ".pyd")
PROGRAM, ARCHIVE = "a Windows program", "an archive holding a program"
LIBRARY = "a Windows library (DLL)"     # a program whose header marks it as a library (phageo, 2026-10-18)


class _TooLarge(Exception):
    pass


def provable(steps: Sequence[Tuple]) -> bool:
    """Can every step be applied again here?"""
    return bool(steps) and all(_known(step) for step in steps)


def _known(step: Tuple) -> bool:
    kind = step[0] if step else ""
    if kind == "xor":
        return len(step) > 1 and isinstance(step[1], str) and bool(step[1])
    if kind == "slice":
        return all(one is None or isinstance(one, int) for one in step[1:3])
    return kind in _STEPS


def _decompress(make, data: bytes) -> bytes:
    engine = make()
    out = engine.decompress(data, MAX_OUTPUT + 1)
    if len(out) > MAX_OUTPUT:
        raise _TooLarge()
    return out


def _b64(data: bytes, altchars: Optional[bytes] = None) -> bytes:
    cleaned = bytes(data).translate(None, b" \t\r\n")
    cleaned += b"=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned, altchars=altchars) if altchars else base64.b64decode(cleaned)


_STEPS = {
    "base64": _b64,
    "base64-url": lambda data: _b64(data, b"-_"),
    "base32": lambda data: base64.b32decode(bytes(data).translate(None, b" \t\r\n"), casefold=True),
    "base85": lambda data: base64.b85decode(bytes(data).translate(None, b" \t\r\n")),
    "ascii85": lambda data: base64.a85decode(bytes(data).translate(None, b" \t\r\n")),
    "hex": lambda data: binascii.unhexlify(bytes(data).translate(None, b" \t\r\n")),
    "zlib": lambda data: _decompress(zlib.decompressobj, data),
    "gzip": lambda data: _decompress(lambda: zlib.decompressobj(16 + zlib.MAX_WBITS), data),
    "bz2": lambda data: _bounded(bz2.BZ2Decompressor().decompress(data, MAX_OUTPUT + 1)),
    "lzma": lambda data: _bounded(lzma.LZMADecompressor().decompress(data, MAX_OUTPUT + 1)),
}


def _bounded(out: bytes) -> bytes:
    if len(out) > MAX_OUTPUT:
        raise _TooLarge()
    return out


def decode(data: bytes, steps: Sequence[Tuple]) -> Optional[bytes]:
    """``data`` with ``steps`` applied, in memory (None: a step cannot be applied, fails,
    or would give more than ``MAX_OUTPUT``)."""
    if not provable(steps) or len(data) > MAX_INPUT:
        return None
    try:
        for step in steps:
            kind = step[0]
            if kind == "slice":
                data = bytes(data[step[1]:step[2]])
            elif kind == "xor":
                key, source = bytes.fromhex(step[1]), bytes(data)
                out = bytearray(len(source))
                for at, value in enumerate(key):          # every len(key)-th byte with one key byte
                    out[at::len(key)] = source[at::len(key)].translate(bytes(b ^ value for b in range(256)))
                data = bytes(out)
            else:
                data = _STEPS[kind](data)
            if len(data) > MAX_OUTPUT:
                return None
        return bytes(data)
    except (_TooLarge, ValueError, TypeError, binascii.Error, zlib.error, OSError, EOFError, lzma.LZMAError,
            MemoryError, OverflowError):
        return None


def proof(decoded: Optional[bytes]) -> str:
    """What the decoded result is shown to be - ``PROGRAM``, ``LIBRARY``, ``ARCHIVE`` - by its
    head only: "" when none (or nothing to look at)."""
    if not decoded or len(decoded) < 64:
        return ""
    if decoded[:2] == b"MZ":
        at = struct.unpack_from("<I", decoded, 0x3C)[0]
        if 0x40 <= at <= len(decoded) - 4 and at < 0x10000 and decoded[at:at + 4] == b"PE\0\0":
            # the file header's characteristics: 0x2000 marks a library
            flags = struct.unpack_from("<H", decoded, at + 22)[0] if at + 24 <= len(decoded) else 0
            return LIBRARY if flags & 0x2000 else PROGRAM
        return ""
    if decoded[:4] == b"PK\x03\x04":
        try:
            names = zipfile.ZipFile(io.BytesIO(decoded)).namelist()[:10000]
        except (zipfile.BadZipFile, ValueError, OSError, struct.error, NotImplementedError, EOFError):
            return ""
        if any(name.lower().rstrip("/").endswith(PROGRAM_ENDINGS) for name in names):
            return ARCHIVE
    return ""


def shown(steps: Sequence[Tuple]) -> str:
    """The steps in words, for the evidence: "Base64, then zlib"."""
    words = []
    for step in steps:
        kind = step[0] if step else "?"
        if kind == "xor":
            words.append("XOR with the key %s" % step[1][:32] if len(step) > 1 and step[1] else "XOR")
        elif kind == "slice":
            words.append("a part cut out" + (" (%s:%s)" % ("" if step[1] is None else step[1],
                                                         "" if step[2] is None else step[2])
                                             if _known(step) else ""))
        elif kind == "custom":
            words.append("a decoding of its own")
        else:
            words.append({"base64-url": "Base64 (URL form)", "base64": "Base64", "base32": "Base32",
                          "base85": "Base85", "ascii85": "Ascii85", "hex": "hex"}.get(kind, kind))
    return ", then ".join(words)


# -- the files a proof may need, kept while one scan runs (in memory only) -------------------
# A script that decodes a file of the game names it; the file itself may come before or after
# the script in the scan, and may be of a kind no reader takes (a member the archive readers do
# not hand on). So while a scan runs, files that could be such a file are kept by their name -
# bounded - and looked at once the scan has seen everything (Scanner._join_local). Never on disk.
MAX_KEPT_FILE = 16 * 1024 * 1024
MAX_KEPT = 64 * 1024 * 1024
# what is plainly no encoded file: programs, archives, pictures, sound, fonts - by their first bytes
_PLAIN = (b"MZ", b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"OggS",
          b"RIFF", b"ID3", b"fLaC", b"%PDF", b"RPA-", b"RENPY RP", b"UnityFS", b"\x00\x01\x00\x00", b"OTTO",
          b"wOFF", b"wOF2", b"\x1a\x45\xdf\xa3", b"BM")
# ... and the scripts a scan reads anyway (a decoded text the script itself holds is read there)
_SCRIPTS = (".rpy", ".rpyc", ".rpym", ".rpymc", ".py", ".pyc", ".pyo", ".js", ".mjs", ".cjs", ".json", ".html",
            ".htm", ".css", ".xml", ".rb", ".rxdata", ".rvdata", ".rvdata2")
_COMPILED = (".rpyc", ".rpymc")
_kept = threading.local()


def begin() -> None:
    """Start keeping (a new scan)."""
    _kept.files, _kept.size = {}, 0


def end() -> None:
    """Forget what was kept."""
    _kept.files, _kept.size = None, 0


def keeping() -> bool:
    """Is a scan keeping files now (and is there room left)?"""
    return getattr(_kept, "files", None) is not None and _kept.size < MAX_KEPT


# members of these endings are not read out of an archive for a proof: pictures, sound, video, fonts
MEDIA = (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".avif", ".svg", ".ogg", ".opus", ".mp3", ".wav",
         ".flac", ".m4a", ".webm", ".mp4", ".mkv", ".avi", ".ogv", ".mpg", ".mpeg", ".ttf", ".otf", ".ttc",
         ".woff", ".woff2")


def wanted(name: str, size: int) -> bool:
    """Should an archive reader read out a member it does not hand on, to offer it
    (:func:`offer`)? Only while a scan keeps files, only what fits, never media."""
    low = name.lower()
    return keeping() and 16 <= size <= MAX_KEPT_FILE and _kept.size + size <= MAX_KEPT \
        and not low.endswith(MEDIA) and not low.endswith(_SCRIPTS)


def offer(relpath: str, data) -> None:
    """A file of the scan that may be the encoded file a script decodes: kept by its name
    while it fits the limits and is not plainly something else."""
    files = getattr(_kept, "files", None)
    if files is None or not isinstance(data, (bytes, bytearray, memoryview)):
        return
    size = len(data)
    name = leaf(relpath.rsplit("!", 1)[-1])
    # (a "compiled script" without Ren'Py's header is no script: it may be the encoded file -
    # phageo, 2026-10-18)
    script = name.endswith(_SCRIPTS) and not (name.endswith(_COMPILED) and not bytes(data[:5]) == b"RENPY")
    if not name or size < 16 or size > MAX_KEPT_FILE or _kept.size + size > MAX_KEPT \
            or script or bytes(data[:8]).startswith(_PLAIN):
        return
    held = files.setdefault(name, [])
    if len(held) < MAX_CANDIDATES:
        held.append(bytes(data))
        _kept.size += size


def kept(name: str) -> list:
    """The files of that name kept in this scan."""
    files = getattr(_kept, "files", None)
    return list(files.get(name, ())) if files else []


def leaf(path: str) -> str:
    """The file name a path as written in the script ends in ("" when that part is only
    known when the script runs)."""
    tail = path.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return "" if not tail or "‹" in tail or "›" in tail else tail
