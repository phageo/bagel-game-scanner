"""Positive benchmark: what the scanner says about real malicious samples.

Development tool only - never shipped (CLAUDE.md, open item 19). The samples
are not part of the project: they lie outside it, each in a password-protected
zip as MalwareBazaar hands them out (AES, password "infected").

    python tools/positive_benchmark.py "C:\\samples\\renpy" "C:\\samples\\electron" --out docs/benchmark/positive.csv

The rules of this tool (phageo, 2026-10-12):

- **Nothing of a sample is ever written to disk.** A zip is read into memory,
  its members are decrypted and unpacked in memory and handed to the scanner as
  bytes. The scanner runs in its memory-only mode (``spool.DISK = False``): a
  nested member too large for memory is skipped with a note. A member of the
  zip itself that is over ``MEMBER_LIMIT`` is skipped with a note too.
- **Nothing is ever run.** The scanner only reads. On top of that a guard
  (:func:`install_guard`, an audit hook of Python itself) is installed before
  the first sample is opened; it stops the run when this process tries to start
  a program (``subprocess``, ``os.system``, ``os.startfile``, ``os.exec*`` /
  ``os.spawn*``), when code of this project calls ``exec`` / ``eval`` /
  ``compile``, or when a Windows library other than ``bcrypt.dll`` is loaded
  through ``ctypes``. The scanner's own helpers that would do such a thing are
  switched off first (signature checks, the worker processes for LZ4, the
  antimalware interface; Windows' cabinet library is used by nobody since
  2026-10-19, 7-Zip / tar by nobody since 2026-10-20).
- **The result is a CSV and nothing else:** per sample its SHA-256, the folder
  it came from, the verdict, the rules that fired (with their level and how
  often) and the "not read" notes (their rule numbers only). No file name of a
  sample, no evidence text, no content.

AES is not in Python's standard library. The zip's key and check value are
derived with ``hashlib`` / ``hmac``; the AES block cipher is Windows' own (CNG,
``bcrypt.dll``) through ``ctypes``. So this tool runs on Windows only.
"""
from __future__ import annotations

import argparse
import collections
import csv
import ctypes
import hashlib
import hmac
import io
import os
import re
import struct
import sys
import zipfile
import zlib
from typing import Dict, Iterator, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
_STARTED_IN = os.getcwd()
sys.path.insert(0, PROJECT)

PASSWORD = b"infected"                      # MalwareBazaar's public standard, not a secret
# One unpacked member - of the zip, and of any archive inside the sample - is held in memory up
# to this size (1 GiB since 2026-10-12, phageo: this is a development tool on a developer's PC);
# a larger one is skipped with a note. Never written to disk, whatever its size.
MEMBER_LIMIT = 1024 * 1024 * 1024
ZIP_LIMIT = 2 * 1024 * 1024 * 1024          # one zip file, read into memory
MAX_MEMBERS = 64                            # members of one zip that are scanned
COLUMNS = ["folder", "sha256", "verdict", "rules", "notes", "official"]   # official: see ORIGINS
VERDICTS = ["DANGEROUS", "SUSPICIOUS", "REVIEW", "LIKELY SAFE", "CLEAN"]     # (DANGEROUS: a CRITICAL finding)
NOT_READ = "not read"
# a sample whose zip could not be opened in this run (held by another program, no memory): not a
# result about the sample. It is reported as MISSING, never as a verdict change (phageo, 2026-10-14) -
# but it fails the gate: a sample without its verdict is a lost verdict (phageo, 2026-10-15, forty-ninth
# message; a sample had been absent from three runs that were reported as "every row as before")
MISSING = "MISSING"
GATE_FAILED = 4                                   # the exit code of a run whose gate failed
# samples that lie in a folder they do not belong to (by what the inventory showed): their
# rows get this label instead of the folder's. 7d68ff23...: a small Java archive that lies
# among the Electron samples (phageo, 2026-10-12).
RELABEL = {"7d68ff23ba4173e1cfe98e2b1e43c96ade9ebc3a960a72a09b52f3e3c25f309e": "other"}


class Abort(BaseException):
    """The guard stopped the run. (Not an ``Exception``: nothing in the scanner
    that says "one bad file must not end the scan" may swallow it.)"""


# -- the guard -----------------------------------------------------------------------------
GUARD_HITS: List[str] = []
_guard = {"on": False}
_STARTS = frozenset({"subprocess.Popen", "os.system", "os.startfile", "os.startfile/2", "os.exec", "os.spawn",
                     "os.posix_spawn", "os.fork", "os.forkpty", "_winapi.CreateProcess"})
_ALLOWED_LIBRARIES = frozenset({"bcrypt", "bcrypt.dll"})


def _project_code(filename: str) -> bool:
    # ("<frozen importlib._bootstrap>", "<string>" ... are no files: Python's own machinery)
    if filename.startswith("<"):
        return False
    if not os.path.isabs(filename):             # (this script, started with a relative path)
        filename = os.path.join(_STARTED_IN, filename)
    try:
        return os.path.commonpath([os.path.normpath(filename), PROJECT]) == PROJECT
    except ValueError:
        return False


def _hook(event: str, args) -> None:
    if not _guard["on"]:
        return
    why = ""
    if event in _STARTS:
        why = "a program was about to be started (%s)" % event
    elif event == "ctypes.dlopen":
        name = os.path.basename(str(args[0] if args else "")).lower()
        if name not in _ALLOWED_LIBRARIES:
            why = "a Windows library other than bcrypt.dll was about to be loaded (%s)" % (name or "?")
    elif event in ("exec", "compile"):
        # Python itself compiles and runs code all the time (every import). What must never
        # happen is that code of this project hands something to exec / eval / compile: the
        # scanner reads samples, it runs nothing. ``ast.parse`` (the standard library's,
        # which only builds a syntax tree) is how the scanner reads Python, and is allowed.
        caller = sys._getframe(1)
        if _project_code(caller.f_code.co_filename):
            why = "code of the project called %s (%s, line %d)" % (
                "exec / eval" if event == "exec" else "compile",
                os.path.basename(caller.f_code.co_filename), caller.f_lineno)
    if why:
        GUARD_HITS.append(why)
        raise Abort("GUARD: the run was stopped - " + why)


def install_guard() -> None:
    """Install the guard and switch it on. It cannot be removed again in this
    process (that is how Python's audit hooks are)."""
    if not _guard.get("installed"):
        sys.addaudithook(_hook)
        _guard["installed"] = True
    _guard["on"] = True


# -- AES (Windows CNG) ----------------------------------------------------------------------
class AesError(OSError):
    pass


class Aes:
    """The AES block cipher with one key, from Windows itself (``bcrypt.dll``).
    Only single blocks in ECB mode are asked for; the counter mode a zip uses is
    built on that in :func:`ctr`."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise AesError("not an AES key length: %d" % len(key))
        self._lib = lib = ctypes.WinDLL("bcrypt")
        for name, types in (
                ("BCryptOpenAlgorithmProvider", [ctypes.POINTER(ctypes.c_void_p), ctypes.c_wchar_p,
                                                 ctypes.c_wchar_p, ctypes.c_ulong]),
                ("BCryptSetProperty", [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.c_ulong]),
                ("BCryptGenerateSymmetricKey", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                                ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong]),
                ("BCryptEncrypt", [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ulong,
                                   ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]),
                ("BCryptDestroyKey", [ctypes.c_void_p]),
                ("BCryptCloseAlgorithmProvider", [ctypes.c_void_p, ctypes.c_ulong])):
            function = getattr(lib, name)
            function.argtypes, function.restype = types, ctypes.c_long
        self._algorithm, self._key = ctypes.c_void_p(), ctypes.c_void_p()
        self._check(lib.BCryptOpenAlgorithmProvider(ctypes.byref(self._algorithm), "AES", None, 0), "open")
        mode = ctypes.create_unicode_buffer("ChainingModeECB")
        self._check(lib.BCryptSetProperty(self._algorithm, "ChainingMode", mode, ctypes.sizeof(mode), 0), "mode")
        self._check(lib.BCryptGenerateSymmetricKey(self._algorithm, ctypes.byref(self._key), None, 0,
                                                   key, len(key), 0), "key")

    @staticmethod
    def _check(status: int, what: str) -> None:
        if status != 0:
            raise AesError("Windows' AES refused (%s): 0x%08x" % (what, status & 0xFFFFFFFF))

    def blocks(self, data: bytes) -> bytes:
        """``data`` (a whole number of 16-byte blocks), each block encrypted by itself."""
        if len(data) % 16:
            raise AesError("not a whole number of blocks")
        out = ctypes.create_string_buffer(len(data))
        done = ctypes.c_ulong()
        self._check(self._lib.BCryptEncrypt(self._key, data, len(data), None, None, 0, out, len(data),
                                            ctypes.byref(done), 0), "encrypt")
        return out.raw[:done.value]

    def close(self) -> None:
        if self._key:
            self._lib.BCryptDestroyKey(self._key)
            self._key = ctypes.c_void_p()
        if self._algorithm:
            self._lib.BCryptCloseAlgorithmProvider(self._algorithm, 0)
            self._algorithm = ctypes.c_void_p()

    def __enter__(self) -> "Aes":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def ctr(aes: Aes, data: bytes, piece: int = 1 << 20) -> bytes:
    """``data`` in the counter mode of an AES zip (WinZip's): block number n,
    counted from 1 and written as 16 little-endian bytes, is encrypted and
    XOR-ed onto the n-th block. The same call decrypts and encrypts."""
    out, number = [], 1
    for at in range(0, len(data), piece):
        part = data[at:at + piece]
        count = (len(part) + 15) // 16
        stream = aes.blocks(b"".join(n.to_bytes(16, "little") for n in range(number, number + count)))
        number += count
        mixed = int.from_bytes(part, "big") ^ int.from_bytes(stream[:len(part)], "big")
        out.append(mixed.to_bytes(len(part), "big"))
    return b"".join(out)


# -- zips, read in memory ---------------------------------------------------------------------
class ZipProblem(ValueError):
    """Why a member (or a zip) was not read; becomes a note in the CSV."""


_KEY_BYTES = {1: 16, 2: 24, 3: 32}
_AES_EXTRA = 0x9901


def _aes_extra(extra: bytes) -> Optional[Tuple[int, int, int]]:
    """``(version, strength, real compression method)`` of the AES field in a member's extra data."""
    at = 0
    while at + 4 <= len(extra):
        kind, size = struct.unpack_from("<HH", extra, at)
        if kind == _AES_EXTRA and size >= 7:
            version, vendor, strength, method = struct.unpack_from("<H2sBH", extra, at + 4)
            if vendor == b"AE":
                return version, strength, method
        at += 4 + size
    return None


def _member(data: bytes, info: zipfile.ZipInfo, password: bytes, limit: int) -> bytes:
    """The unpacked content of one member of the zip ``data``. Raises
    :class:`ZipProblem` for anything that is not read."""
    if info.file_size > limit:
        raise ZipProblem("a member of %d MB: over the limit of %d MB, not unpacked" % (
            info.file_size >> 20, limit >> 20))
    at = info.header_offset
    if data[at:at + 4] != b"PK\x03\x04" or at + 30 > len(data):
        raise ZipProblem("damaged zip (no member where the list says)")
    name_length, extra_length = struct.unpack_from("<HH", data, at + 26)
    start = at + 30 + name_length + extra_length
    packed = data[start:start + info.compress_size]
    if len(packed) != info.compress_size:
        raise ZipProblem("damaged zip (a member is cut short)")
    method = info.compress_type
    if info.flag_bits & 1:
        field = _aes_extra(info.extra)
        if method != 99 or field is None:
            raise ZipProblem("encrypted, but not with AES (the old zip encryption is not read here)")
        _version, strength, method = field
        size = _KEY_BYTES.get(strength)
        if size is None:
            raise ZipProblem("unknown AES strength")
        salt_size = size // 2
        if len(packed) < salt_size + 2 + 10:
            raise ZipProblem("damaged zip (an encrypted member is too short)")
        salt, check = packed[:salt_size], packed[salt_size:salt_size + 2]
        body, code = packed[salt_size + 2:-10], packed[-10:]
        keys = hashlib.pbkdf2_hmac("sha1", password, salt, 1000, 2 * size + 2)
        if keys[2 * size:] != check:
            raise ZipProblem("wrong password")
        if not hmac.compare_digest(hmac.new(keys[size:2 * size], body, hashlib.sha1).digest()[:10], code):
            raise ZipProblem("damaged zip (the check value of a member does not fit)")
        with Aes(keys[:size]) as aes:
            packed = ctr(aes, body)
    if method == 0:
        content = packed
    elif method == 8:
        engine = zlib.decompressobj(-15)
        try:
            content = engine.decompress(packed, limit + 1)
        except zlib.error as exc:
            raise ZipProblem("damaged zip (%s)" % exc)
        if len(content) > limit or engine.unconsumed_tail:
            raise ZipProblem("a member that unpacks to more than %d MB: not unpacked" % (limit >> 20))
    else:
        raise ZipProblem("a compression method this tool does not read (%d)" % method)
    if len(content) != info.file_size:
        raise ZipProblem("damaged zip (a member has another size than listed)")
    return content


def read_zip(data: bytes, password: bytes = PASSWORD, limit: int = MEMBER_LIMIT) -> Iterator[Tuple[str, object]]:
    """``(name, content)`` for every file in the zip ``data`` - ``content`` is
    the unpacked bytes, or the :class:`ZipProblem` that says why it was not
    read. Everything happens in memory."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = [info for info in archive.infolist() if not info.is_dir()]
    except (zipfile.BadZipFile, ValueError, OSError, struct.error) as exc:
        raise ZipProblem("not a zip that can be read (%s)" % type(exc).__name__)
    for info in infos[:MAX_MEMBERS]:
        try:
            yield info.filename, _member(data, info, password, limit)
        except ZipProblem as problem:
            yield info.filename, problem
        except (AesError, struct.error, OverflowError, MemoryError) as exc:
            yield info.filename, ZipProblem("could not be unpacked (%s)" % type(exc).__name__)
    if len(infos) > MAX_MEMBERS:
        yield "", ZipProblem("more than %d members: the rest was not read" % MAX_MEMBERS)


# -- the scanner, in its memory-only form ------------------------------------------------------
def memory_only_scanner():
    """The scanner the false-positive benchmark and the launcher use
    (``neutral_scanner``), with everything switched off that would write a
    sample to disk, start a program or load a Windows library."""
    import gamescan
    from gamescan import cache
    from gamescan.unpack import lz4block, spool
    cache.forbid()                                      # nothing of a sample is kept on disk, in any form
    spool.DISK = False                                  # nothing is spooled to a temporary file
    spool.MEMORY = MEMBER_LIMIT                         # ... and a member up to 1 GiB stays in memory
    lz4block.default_workers = lambda: 1                # no worker processes
    return gamescan.neutral_scanner(strict=False, amsi=False)


class _Counters(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


class MemoryWatch:
    """``--memory FILE`` (phageo, 2026-10-15, forty-ninth message): the highest working set of this
    process while one sample is scanned, read every ``every`` seconds by a thread of its own.
    Windows keeps only the peak of the whole process, so a sample's peak is sampled: a rise shorter
    than ``every`` can be missed. The one Windows function is bound when the watch is made - before
    the guard is switched on, which lets no library be loaded after it. ``read`` can be replaced
    (tests)."""

    def __init__(self, every: float = 0.02, read=None, where: bool = False):
        import threading
        # --memory-where (phageo, 2026-10-17, fifty-ninth message): which of the scanner's functions
        # run when a sample's memory is highest, and the largest text a script was decoded to -
        # names of the scanner's functions and numbers only
        self.wheres: Optional[List[dict]] = [] if where else None
        self._main = threading.main_thread().ident
        self._stack: List[str] = []
        self._most: Dict[str, int] = {}
        if read is None:
            kernel32 = ctypes.WinDLL("kernel32")
            info = kernel32.K32GetProcessMemoryInfo
            info.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Counters), ctypes.c_ulong]
            info.restype = ctypes.c_int
            me = ctypes.c_void_p(kernel32.GetCurrentProcess())

            def read():
                counters = _Counters()
                counters.cb = ctypes.sizeof(counters)
                return counters.WorkingSetSize if info(me, ctypes.byref(counters), counters.cb) else 0
        self.read, self.every, self.peak = read, every, 0
        self._busy, self._stop = threading.Event(), threading.Event()
        self._thread = threading.Thread(target=self._watch, name="memory-watch", daemon=True)
        self._thread.start()

    def _watch(self) -> None:
        while not self._stop.wait(self.every):
            if self._busy.is_set():
                now = self.read()
                if self.wheres is not None:
                    names = self._names()
                    if names:
                        self._most[names[0]] = max(self._most.get(names[0], 0), now)
                    if now > self.peak:
                        self._stack = names
                self.peak = max(self.peak, now)

    def _names(self) -> List[str]:
        """The scanner's own functions on the scanning thread's stack, innermost first."""
        frame, names = sys._current_frames().get(self._main), []
        while frame is not None and len(names) < 40:
            code = frame.f_code
            if os.sep + "gamescan" + os.sep in code.co_filename:
                names.append("%s.%s" % (os.path.splitext(os.path.basename(code.co_filename))[0], code.co_name))
            frame = frame.f_back
        return names

    def begin(self) -> None:
        self.peak = self.read()
        self._stack, self._most = [], {}
        LARGEST_TEXT[:] = [0, 0]
        self._busy.set()

    def end(self) -> int:
        """The peak since ``begin``, in bytes."""
        self._busy.clear()
        self.peak = max(self.peak, self.read())
        if self.wheres is not None:
            self.wheres.append({"stack": self._stack[:12], "most": sorted(self._most.items(), key=lambda kv: -kv[1])[:12],
                                "text": tuple(LARGEST_TEXT)})
        return self.peak

    def close(self) -> None:
        self._stop.set()
        self._thread.join()


LARGEST_TEXT = [0, 0]           # --memory-where: the largest decoded text of a sample (characters, bytes each)


def watch_texts() -> None:
    """--memory-where: keep the length of the largest text a file of a sample is decoded to, and how many
    bytes each character takes in it (1, 2 or 4 - Python's choice by the widest character)."""
    from gamescan import models
    decode = models.FileContext.text

    def text(self):
        found = decode(self)
        if len(found) > LARGEST_TEXT[0]:
            widest = ord(max(found)) if found else 0
            LARGEST_TEXT[:] = [len(found), 1 if widest < 0x100 else 2 if widest < 0x10000 else 4]
        return found
    models.FileContext.text = text


MEMORY_COLUMNS = ["folder", "sha256", "peak_mb"]


def write_memory(path: str, peaks: List[Tuple[str, str, int]]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(MEMORY_COLUMNS)
        for folder, sha, peak in peaks:
            writer.writerow([folder, sha, "%.0f" % (peak / (1 << 20))])


SITES: Dict[str, object] = {"rule": "", "lines": []}      # for --sites: see scan_member
_PROGRAM_KINDS = frozenset(("node", "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "reg", "schtasks",
                            "taskkill", "tasklist", "start", "explorer", "curl", "bitsadmin", "certutil", "wmic", "attrib",
                            "icacls", "python", "rundll32", "regsvr32", "sc", "net", "wget"))
QUOTED = "QUOTED"       # --sites QUOTED: what "quoted text is not code" hid (rules.QuotedText)


# -- which findings stand in an official file (the gate rule of phageo, 2026-10-17) --------------
# A malicious verdict may drop only when every finding that went away came from a file that is,
# byte for byte, a file of an official table - by SHA-256, or a compiled script by its content
# (fifty-ninth message; checked by the gate since the sixtieth). So each run records, per
# finding, whether the file it stands in is such a file: the column ``official`` holds the part
# of ``rules`` that does (same form). Recorded by the runner itself, apart from what the scanner
# makes of the file - a later scanner that does recognise the file cannot hide an earlier miss.
ORIGINS: Dict[str, str] = {}        # file of the sample being scanned -> the official file it is ("": none)
OFFICIAL = {"last": ""}             # the ``official`` column of the last sample scan_member read


def official_origin(ctx) -> str:
    """What official file ``ctx`` is ("" none): any table of ``gamescan.official``, a Ren'Py
    engine script by SHA-256, or a compiled engine script by its content key. Reads the file,
    writes nothing into it (a cache entry would make later readings depend on the path)."""
    from gamescan import compiled_hashes, engine_hashes, official
    from gamescan.unpack import pyo, rpyc
    try:
        found = official.exact(ctx.sha256)
        if found:
            return found
        key = None
        if not ctx.truncated and ctx.key.endswith((".rpyc", ".rpymc")):
            key = rpyc.content_key(ctx.data)
        found = engine_hashes.verified_script(ctx.sha256, key)
        if found:
            return found
        if ctx.key.endswith((".pyo", ".pyc")):
            key = pyo.content_key(ctx.data) if not ctx.truncated and pyo.is_python2(ctx.data) else None
            if compiled_hashes.versions(ctx.sha256, key):
                return "official compiled Ren'Py script"
    except Exception:                       # (a file that cannot be judged is no official file)
        return ""
    return ""


def watch_origins() -> None:
    """Every file the scanner reads (``Scanner._scan_ctx``) goes into ``ORIGINS`` with what
    :func:`official_origin` says about it. Names stay in memory only."""
    from gamescan.scanner import Scanner
    if getattr(Scanner, "_origins_watched", False):
        return
    real = Scanner._scan_ctx

    def scan_ctx(self, ctx, depth=0):
        ORIGINS.setdefault(ctx.relpath, official_origin(ctx))
        return real(self, ctx, depth)

    Scanner._scan_ctx = scan_ctx
    Scanner._origins_watched = True


def counts(rules: str) -> collections.Counter:
    """``"RULE LEVEL xN; ..."`` (the form of ``rules`` and ``official``) as a Counter."""
    out: collections.Counter = collections.Counter()
    for part in (rules or "").split("; "):
        head, _, n = part.rpartition(" x")
        if head and n.isdigit():
            out[head] += int(n)
    return out


def _counted(findings) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    active = collections.Counter((f.rule_id, f.severity.name) for f in findings)
    return "; ".join("%s %s x%d" % (rule, level, count) for (rule, level), count in
                     sorted(active.items(), key=lambda item: (order.get(item[0][1], 9), item[0][0])))


def scan_member(scanner, name: str, content: bytes) -> Tuple[str, str, str]:
    """``(verdict, rules, notes)`` for one sample, scanned from memory. With ``--sites RULE``
    one line per active finding of that rule goes into ``SITES["lines"]``: the number of the
    file it stands in (files are numbered in the order they come up), its line, and short
    marks of its place and of its evidence text - two findings with the same marks are the
    same site said twice. Marks and numbers only: no name, no content. Several rules joined by
    ``+`` (``--sites CHAIN-LOCAL-DROP+EVADE-001``) share one numbering of the files, and each
    line then begins with its rule - whether two rules stand in the same file (2026-10-18)."""
    from gamescan import context
    from gamescan.models import ScanReport
    # (a path that cannot exist: nothing may take the sample for a file on disk)
    leaf = os.path.basename(name.replace("\\", "/")) or "sample"
    ORIGINS.clear()
    found = scanner.scan_bytes(leaf, content, path="<memory>|" + hashlib.sha256(content).hexdigest())
    report = ScanReport(target="memory", findings=list(found))
    rules = _counted(report.active)
    OFFICIAL["last"] = _counted(f for f in report.active if ORIGINS.get(f.file))
    ORIGINS.clear()
    if SITES["rule"]:
        files: Dict[str, int] = {}
        mark = lambda text: hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:8]
        wanted = str(SITES["rule"]).split("+")
        SITES["lines"] = [
            "%sfile #%d (%s) | line %s | place %s | evidence %s" % (
                "%s | " % f.rule_id if len(wanted) > 1 else "",
                files.setdefault(f.file, len(files) + 1), os.path.splitext(f.file)[1] or "no ending", f.line or "-",
                mark("%s|%s" % (f.file, f.line)), mark(f.evidence))
            for f in report.active if f.rule_id in wanted]
        if SITES["rule"] == "WRITTEN":
            from gamescan.dataflow import remote
            SITES["lines"] = list(remote.WRITTEN_TRACE or [])
            del (remote.WRITTEN_TRACE or [])[:]
        if SITES["rule"] == QUOTED:
            # which matches "quoted text is not code" hid, file by file - and what else stands
            # in those files: the active call-site findings and the chains (rule names, lines)
            hidden: Dict[str, collections.Counter] = {}
            for f in found:
                if f.suppressed and f.context.get("in_text"):
                    hidden.setdefault(f.file, collections.Counter())["%s line %s" % (f.rule_id, f.line or "-")] += 1
            for name, counts in hidden.items():
                others = collections.Counter(
                    "%s line %s" % (f.rule_id, f.line or "-") for f in report.active
                    if f.file == name and (f.rule_id.startswith(("CHAIN", "JS-", "DF-")) or f.rule_id == "SCRIPT-LIMIT-001"))
                SITES["lines"].append("file #%d (%s) | hidden as quoted text: %s | active in that file: %s" % (
                    files.setdefault(name, len(files) + 1), os.path.splitext(name)[1] or "no ending",
                    ", ".join("%s x%d" % item for item in sorted(counts.items())[:12]),
                    ", ".join("%s x%d" % item for item in sorted(others.items())[:16]) or "nothing"))
                # ... and which calls those are: the name of the function only, and for a command
                # that was resolved the kind of program it starts (from a fixed list) and its size
                calls = []
                for f in report.active:
                    if f.file != name or f.rule_id not in ("JS-FS-001", "DF-CMD-001", "DF-PATH-001", "DF-EXEC-001"):
                        continue
                    sink, _, value = f.evidence.partition(" receives: ")
                    said = "%s line %s: %s" % (f.rule_id, f.line or "-", "".join(re.findall(r"[\w.$]+", sink[:60])[:1]))
                    if f.rule_id == "DF-CMD-001":
                        first = os.path.splitext(re.split(r"[\s\"']+", value.strip() + " ")[0].replace("\\", "/").split("/")[-1])[0].lower()
                        said += " -> %s, %d characters, %d line break(s)" % (
                            first if first in _PROGRAM_KINDS else "another program", len(value), value.count("\n"))
                    calls.append(said)
                SITES["lines"].append("      calls: " + "; ".join(calls[:16]))
    unread = sorted({f.rule_id for f in report.active if f.rule_id in context._NEVER_HIDDEN})
    notes = "; ".join("%s: %s" % (NOT_READ, rule) for rule in unread)
    return str(report.verdict), rules, notes


# -- inventory: what a sample is made of (names, sizes, kinds - no content) ---------------------
_MAGICS = (
    (0, b"MZ", "Windows program"), (0, b"PK\x03\x04", "zip"), (0, b"PK\x05\x06", "zip (empty)"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"), (0, b"Rar!\x1a\x07", "RAR"), (0, b"MSCF", "cabinet"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE file (msi / old Office)"), (0, b"\x7fELF", "Linux program"),
    (0, b"\x89PNG", "PNG"), (0, b"\xff\xd8\xff", "JPEG"), (0, b"GIF8", "GIF"), (0, b"RIFF", "RIFF (wav / webp / avi)"),
    (0, b"OggS", "Ogg"), (0, b"%PDF", "PDF"), (0, b"\x1f\x8b", "gzip"), (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"), (0, b"\x28\xb5\x2f\xfd", "zstd"), (0, b"UnityFS\0", "Unity bundle"),
    (0, b"RGSSAD\0", "RPG Maker archive"), (0, b"RPA-", "Ren'Py archive"), (0, b"RENPY RP", "compiled Ren'Py script"),
    (0, b"SQLite format 3", "SQLite"), (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O / Java class"), (0, b"\xcf\xfa\xed\xfe", "macOS program"),
    (0, b"hsqs", "squashfs"), (0, b"\x03\xf3\r\n", "compiled Python 2.7"), (0, b"ISc(", "InstallShield cabinet"),
    (0, b"MSWIM\0\0\0", "WIM image"), (0, b"\xc0\xde", "V8 compiled JavaScript (maybe)"),
    (257, b"ustar", "tar"), (0x8001, b"CD001", "ISO disc image"), (0, b"koly", "macOS disk image"),
)


def kind_of(head: bytes) -> str:
    """What some content is, by its first bytes - or its first 16 bytes in hex
    when nothing here knows it (the only bytes of a sample this tool ever shows)."""
    for at, magic, name in _MAGICS:
        if head[at:at + len(magic)] == magic:
            return name
    from gamescan.handlers import text
    from gamescan.unpack import asar, sniff
    if asar.looks_like(head[:16]):
        return "asar (Electron)"
    if text.is_text(head[:65536]):
        ending = sniff.extension(head[:65536])
        return "text" + (" (reads like %s)" % ending if ending else "")
    return "unknown: " + head[:16].hex()


def inventory(scanner, name: str, content: bytes) -> List[str]:
    """Lines that say what the sample is made of, as far as the scanner goes
    into it: every file and member it meets - its name, size, kind by its
    first bytes, which reader took it - and the "not read" notes with their
    reason. Metadata only: no content of a member, no evidence of a finding."""
    from gamescan import context
    records: List[Tuple[int, str, int, str, str, List[str]]] = []
    real = scanner._scan_one

    def watched(ctx, depth: int = 0):
        index = len(records)
        records.append((depth, ctx.relpath, ctx.size, kind_of(bytes(ctx.data[:0x8010])), "", []))
        found = real(ctx, depth)
        handler = next((h.name for h in scanner.handlers if h.can_handle(ctx)), None)
        if handler is None and scanner._text.takes(ctx):
            handler = "text"
        holds = ", ".join(sorted({kind for kind, _at, _size in ctx.cache.get("containers", ())}))
        notes = ["%s (%s)" % (f.rule_id, " ".join(f.evidence.split())[:150]) for f in (found or [])
                 if f.file == ctx.relpath and not f.suppressed
                 and (f.rule_id in context._NEVER_HIDDEN or f.rule_id == "ARC-001")]
        # which rules about credentials, the network and chains fired in this file, how often
        # and on which lines (numbers only - what a plan for a chain rule needs to know)
        # (since 2026-10-13 also every other shown rule of MEDIUM or more, and for a program
        # what it was taken for - "what is left in a sample once the runtime is verified")
        fired: Dict[str, List[int]] = {}
        for f in found or []:
            if f.file == ctx.relpath and not f.suppressed and (f.severity.name in ("MEDIUM", "HIGH", "CRITICAL")
                                                                or f.category.name in (
                    "CREDENTIALS", "NETWORK", "CHAIN", "INPUT_CAPTURE")):
                fired.setdefault("%s %s" % (f.rule_id, f.severity.name), []).append(f.line or 0)
        if ctx.is_pe:
            hidden = sum(1 for f in found or [] if f.file == ctx.relpath and f.suppressed)
            notes.append("RULES taken for: %s; hidden findings: %d" % (ctx.baseline or "an unknown program", hidden))
        # what a Windows Installer package holds (names and sizes, unpack/msi.inventory)
        notes.extend("MSI " + line for line in ctx.cache.get("msi_inventory", ()))
        if "msi_inventory" in ctx.cache:
            # ... and what of it could not be read, by kind - counts only (part 2, 2026-10-19)
            kinds = {"LZX": "compressed with LZX", "Quantum": "compressed with Quantum",
                     "cabinet missing": "is missing", "cabinet damaged": "could not be read (",
                     "cabinet beside": "should lie beside", "cabinet needs more": " needs ",
                     "storages": "storage(s) inside", "script set while installing": "set only while installing",
                     "over memory": "larger than", "database": "its database", "changes another package": "changes another"}
            said = [f.evidence for f in found or [] if f.file == ctx.relpath and f.rule_id == "ARC-002"]
            counts = {kind: sum(text in e for e in said) for kind, text in kinds.items()}
            notes.append("MSI not read, by kind: " + ", ".join("%s %d" % item for item in counts.items() if item[1])
                         + (" (none)" if not any(counts.values()) else "") + "; notes %d" % len(said))
        if fired:
            notes.append("RULES " + "; ".join(
                "%s x%d (lines %d-%d)" % (rule, len(lines), min(lines), max(lines)) for rule, lines in sorted(fired.items())))
        records[index] = (depth, ctx.relpath, ctx.size, records[index][3],
                          (handler or "NOBODY") + (" [holds: %s]" % holds if holds else ""), notes)
        return found

    scanner._scan_one = watched
    try:
        leaf = os.path.basename(name.replace("\\", "/")) or "sample"
        scanner.scan_bytes(leaf, content, path="<memory>|" + hashlib.sha256(content).hexdigest())
    finally:
        del scanner._scan_one                     # (back to the class's own)
    out = []
    members = [r for r in records if r[0] == 1]
    read = sum(r[2] for r in members if not r[4].startswith("NOBODY"))
    total = sum(r[2] for r in members)
    out.append("%d file(s) / member(s) met; direct members: %d, %.1f MB, of which a reader took %.1f MB (%.0f %%)" % (
        len(records), len(members), total / 1048576.0, read / 1048576.0, 100.0 * read / total if total else 0.0))
    # (the first 400, and behind them every one that has a note: none of those is left out)
    shown = records if len(records) <= 400 else records[:400] + [r for r in records[400:] if r[5]]
    met = {path for _depth, path, _size, _kind, _reader, _notes in records}
    for depth, path, size, kind, reader, notes in shown:
        out.append("%s%s | %d bytes | %s | reader: %s" % ("  " * depth, path[-110:], size, kind, reader))
        for note in notes:
            out.append("%s    %s" % ("  " * depth, note if note.startswith(("RULES ", "MSI ")) else "NOT READ: " + note))
        if depth == 0 and kind.startswith("zip"):
            # what the zip lists and the scanner did not take: names and sizes out of the
            # zip's own list, the kind by the first bytes (unpacked in memory, at most 64 KB)
            try:
                archive = zipfile.ZipFile(io.BytesIO(content))
                for info in archive.infolist()[:200]:
                    if info.is_dir() or "%s!%s" % (path, info.filename.lstrip("/")) in met:
                        continue
                    if info.flag_bits & 1:
                        what = "encrypted"
                    else:
                        try:
                            with archive.open(info) as member:
                                what = kind_of(member.read(0x8010))
                        except Exception as exc:
                            what = "could not be unpacked (%s)" % type(exc).__name__
                    out.append("  %s | %d bytes | %s | reader: NOBODY (not handed on by the zip reader)"
                               % (info.filename[-110:], info.file_size, what))
            except (zipfile.BadZipFile, ValueError, OSError):
                out.append("  (the zip's own list could not be read)")
    if len(records) > len(shown):
        out.append("... and %d more" % (len(records) - len(shown)))
        kinds = collections.Counter((r[3].split(":")[0], r[4].split(" [")[0]) for r in records[400:])
        out.extend("    %d x %s, reader: %s" % (count, kind, reader) for (kind, reader), count in kinds.most_common(12))
    return out


_ELECTRON = re.compile(rb"Chrome/\d+\.\d+\.\d+\.\d+ Electron/(\d+\.\d+\.\d+(?:-[a-z]+\.\d+)?)[\0 ]")
_UNPACKED = ("Windows program", "zip", "7z", "RAR", "cabinet")
_MACHINES = {0x8664: "x64", 0x14C: "ia32", 0xAA64: "arm64"}


_FUSES = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"     # Electron's marker in front of its switches ("fuses")


def named_resources(data, info) -> List[str]:
    """One line for every resource of a program whose kind has a name of its own (the
    standard kinds have numbers): the kind's name, the entry's name, its size and how it
    begins - the first 96 bytes, everything that is not plain ASCII shown as a dot (phageo,
    2026-10-13: to see whether it is Electron's integrity record of the app archive)."""
    from gamescan import pe
    entries = pe.resource_entries(data, info)
    if entries is None:
        return ["resources: the tree is not a plain one (not walked)"]
    out = []
    for kind, name, offset, size in entries:
        if isinstance(kind, str):
            begins = "".join(chr(b) if 32 <= b < 127 else "." for b in bytes(data[offset:offset + 96]))
            out.append("resource of a named kind: kind %r, entry %r, %d bytes, begins: %s" % (kind, name, size, begins))
    return out


def why_not_official(data, info, archives: str, version: str, machine: str) -> List[str]:
    """Why a program that states an Electron version is, or is not, the official program of
    that version apart from its resources - in numbers only: the checks of the scanner one
    by one, and, with the official zip at hand, which sections differ from the official
    ``electron.exe`` and in how many bytes. Nothing of the sample's content is shown."""
    from gamescan import electron_official, pe
    out = []
    kinds = pe.resource_kinds(data, info)
    key = pe.resource_frame_key(data, info, signature=True)
    out.append("appended data is only a signature (or nothing): %s; signature: %s; resource kinds: %s; "
               "frame key: %s" % (
                   pe.signature_is_all_appended(data, info), "yes" if info.has_signature else "no",
                   "unreadable" if kinds is None else [pe.RESOURCE_KINDS.get(k, "named" if k < 0 else k) for k in kinds],
                   "no plain layout" if key is None else
                   "in the table" if electron_official.verified_program(key) else "NOT in the table"))
    out.extend(named_resources(data, info))
    path = os.path.join(archives or "", "electron-v%s-win32-%s.zip" % (version, machine))
    if not archives or not os.path.isfile(path):
        return out
    with zipfile.ZipFile(path) as archive:
        official = archive.read("electron.exe")
    theirs = pe.parse_pe(official)
    if [s.name for s in theirs.sections] != [s.name for s in info.sections]:
        return out + ["sections: other names or another number than the official program (%d / %d)" % (
            len(info.sections), len(theirs.sections))]
    for mine, other in zip(info.sections, theirs.sections):
        a = bytes(data[mine.raw_ptr:mine.raw_ptr + mine.raw_size])
        b = official[other.raw_ptr:other.raw_ptr + other.raw_size]
        if a == b or mine.name == pe.RESOURCES:
            continue
        if len(a) != len(b):
            out.append("section %s: another size (%d / %d)" % (mine.name, len(a), len(b)))
            continue
        places = [i for i in range(len(a)) if a[i] != b[i]] if a != b else []
        wire = b.find(_FUSES)
        inside = wire >= 0 and all(wire + len(_FUSES) <= i < wire + len(_FUSES) + 64 for i in places)
        out.append("section %s: %d byte(s) differ, in a span of %d%s" % (
            mine.name, len(places), places[-1] - places[0] + 1,
            " - all of them among Electron's switches (\"fuses\"), right behind their marker" if inside else ""))
    first = min(s.raw_ptr for s in info.sections if s.raw_size)
    head = sum(1 for i in range(min(first, len(official))) if data[i] != official[i])
    out.append("headers: %d byte(s) differ" % head)
    return out


def electron_versions(scanner, name: str, content: bytes, archives: str = "") -> List[str]:
    """Which Electron runtime a sample carries: for every program in it (the sample itself,
    or a member of its archives and installers) that states "Chrome/... Electron/<version>"
    the way the Electron program does, one line - version, processor kind, size in bytes.
    Version metadata only (phageo, 2026-10-13): no name, no hash, no other content; nothing
    but archives, installers and programs is opened, and no rule reads anything."""
    from gamescan.pe import parse_pe
    out: List[str] = []
    real = scanner._scan_one

    def watched(ctx, depth: int = 0):
        kind = kind_of(bytes(ctx.data[:0x8010]))
        if not kind.startswith(_UNPACKED):
            return None
        if kind == "Windows program":
            stated = _ELECTRON.search(ctx.data)
            if stated:
                info = parse_pe(ctx.data)
                out.append("ELECTRON %s %s | %d bytes%s" % (
                    stated.group(1).decode(), _MACHINES.get(info.machine if info else 0, "?"), ctx.size,
                    " (only the first %d MB were at hand)" % (len(ctx.data) >> 20) if ctx.truncated else ""))
                if info is not None and not ctx.truncated:
                    out.extend("    " + line for line in why_not_official(
                        ctx.data, info, archives, stated.group(1).decode(), _MACHINES.get(info.machine, "?")))
                return None
        return real(ctx, depth)

    scanner._scan_one = watched
    try:
        leaf = os.path.basename(name.replace("\\", "/")) or "sample"
        scanner.scan_bytes(leaf, content, path="<memory>|" + hashlib.sha256(content).hexdigest())
    finally:
        del scanner._scan_one                     # (back to the class's own)
    return out or ["no program that states an Electron version"]


_PACKAGE = re.compile(r"\A(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z")
_VERSION = re.compile(r"\A\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?\Z")


def packages(scanner, name: str, content: bytes) -> List[str]:
    """For ``--packages``: the npm packages a sample carries - the ``name`` and ``version``
    of every ``package.json`` under a ``node_modules`` folder, when both are plain (phageo,
    2026-10-14: names and versions only) -, and in numbers how much of ``node_modules`` the
    npm table (``gamescan/npm_hashes.py``) verifies: files of the kinds it keeps, native
    add-ons (``.node``), and add-ons that import the function that decrypts stored secrets."""
    import json
    try:
        from gamescan import npm_hashes
    except ImportError:
        npm_hashes = None
    kept = (".js", ".cjs", ".mjs", ".node", ".json", ".html", ".htm", ".wasm")
    found, real = set(), scanner._scan_one
    count = collections.Counter()

    def watched(ctx, depth: int = 0):
        result = real(ctx, depth)                 # (first: the scan reads the program's import table)
        low = ctx.relpath.replace("\\", "/").lower()
        if "node_modules/" in low:
            if low.endswith("/package.json"):
                try:
                    data = json.loads(ctx.text())
                    package, version = data.get("name"), data.get("version")
                    if isinstance(package, str) and isinstance(version, str) and _PACKAGE.match(package) \
                            and _VERSION.match(version) and len(package) <= 100:
                        found.add("%s@%s" % (package, version))
                except Exception:
                    pass
            elif low.endswith(kept) and ctx.size >= 24:
                known = npm_hashes is not None and npm_hashes.verified(ctx.sha256) is not None
                count["files"] += 1
                count["files verified"] += known
                if low.endswith(".node"):
                    count["add-ons"] += 1
                    count["add-ons verified"] += known
                    imports = {n.lower() for names in (ctx.pe.imports.values() if ctx.pe else ()) for n in names}
                    if "cryptunprotectdata" in imports:
                        count["add-ons importing the decrypt function"] += 1
                        count["... of them verified"] += known
        elif low.endswith(".node"):
            count["add-ons outside node_modules"] += 1
        return result

    scanner._scan_one = watched
    try:
        leaf = os.path.basename(name.replace("\\", "/")) or "sample"
        findings = scanner.scan_bytes(leaf, content, path="<memory>|" + hashlib.sha256(content).hexdigest())
    finally:
        del scanner._scan_one
    keys = ("files", "files verified", "add-ons", "add-ons verified", "add-ons importing the decrypt function",
            "... of them verified", "add-ons outside node_modules")
    out = ["PKG " + item for item in sorted(found)]
    if npm_hashes is not None:
        # which listed packages are not in the table (the registry does not have them), and which
        # published packages hold a chain or an add-on that decrypts - package names only
        listed = {item.replace(" ", "@", 1) for item in npm_hashes.PACKAGES}
        out += ["NOT ON THE REGISTRY " + item for item in sorted(found - listed)]
        held = collections.Counter()
        for f in findings:
            package = npm_hashes.verified(f.sha256) if not f.suppressed else None
            if package and (f.rule_id.startswith("CHAIN-") or f.rule_id == "ADDON-DECRYPT-001"):
                held[(package, f.rule_id)] += 1
        out += ["PUBLISHED %s: %s x%d" % (package, rule, n) for (package, rule), n in sorted(held.items())]
    return out + ["in node_modules: " + "; ".join("%s %d" % (key, count[key]) for key in keys)]


READINGS: List[str] = []


def watch_readings() -> None:
    """For ``--readings``: every download-and-run reading of a JavaScript text writes one
    line into ``READINGS`` - the size of the text, the seconds and the counted steps of each
    part of the reading, the limit it stopped at and the kinds of what it found. Numbers and
    the scanner's own words only; nothing of the text itself."""
    import time
    import gamescan.dataflow as dataflow
    from gamescan.dataflow import remote
    if getattr(remote.RemoteFlow, "_watched", False):
        return
    parts = ("_find_functions", "_sources", "_propagate", "_sinks")

    def timed(name):
        real = getattr(remote.RemoteFlow, name)

        def inner(self, *args, **kwargs):
            started, before = time.perf_counter(), self.clock.steps
            try:
                return real(self, *args, **kwargs)
            finally:
                self.__dict__.setdefault("_parts", []).append("%s %.2f s / %d steps" % (
                    name.strip("_"), time.perf_counter() - started, before - self.clock.steps))
        return inner

    for name in parts:
        setattr(remote.RemoteFlow, name, timed(name))
    real_run, real_analyse = remote.RemoteFlow.run, dataflow.analyse

    def run_flow(self):
        started = time.perf_counter()
        hits = real_run(self)
        READINGS.append("chain reading | %d characters | %.2f s | %s | stopped: %s | found: %s" % (
            self.size, time.perf_counter() - started, "; ".join(self.__dict__.get("_parts", [])) or "not begun",
            self.cut or "no", ", ".join(sorted(h.how + (" (weak)" if h.weak else "") for h in hits)) or "nothing"))
        return hits

    def analyse(text, language):
        started = time.perf_counter()
        out = real_analyse(text, language)
        if language == "js" and (out.cut or time.perf_counter() - started >= 0.5):
            READINGS.append("payload reading | %d characters | %.2f s | stopped: %s | resolved: %d, decoded: %d" % (
                len(text), time.perf_counter() - started, out.cut or "no", len(out.resolved), len(out.payloads)))
        return out

    remote.RemoteFlow.run, dataflow.analyse = run_flow, analyse
    remote.RemoteFlow._watched = True


def samples_in(folder: str) -> List[str]:
    out = []
    for base, dirs, files in os.walk(folder):
        dirs.sort()
        out.extend(os.path.join(base, name) for name in sorted(files))
    return out


def run(folders: List[str], password: bytes = PASSWORD, say=print, only=None,
        listing: bool = False, archives: str = "", memory: Optional[MemoryWatch] = None) -> List[Dict[str, str]]:
    """One row per sample of every folder (see ``COLUMNS``). The guard is
    installed first; a guard hit ends the run (:class:`Abort`). ``only``: a
    set of SHA-256 - only these samples are scanned (the others are unpacked
    to learn their SHA-256, and left out). ``memory``: each scanned sample's
    peak goes into ``memory.rows`` as (folder, SHA-256, bytes)."""
    if memory is not None:
        memory.rows = []
    scanner = memory_only_scanner()
    watch_origins()
    if listing == "readings":
        watch_readings()
    if listing in ("stealer", "sinks", "downloads", "encrypted", "sideload", "diagnose"):
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import encrypted_count
        import sideload_count
        import stealer_count
        import sink_count
        import download_runs
        import renpy_diagnosis
    # everything the scanner imports late is imported now, before the guard looks at who
    # compiles what: one harmless script through the whole path
    scanner.scan_bytes("warm-up.rpy", b'label start:\n    "Hi"\n')
    install_guard()
    rows: List[Dict[str, str]] = []
    for folder in folders:
        label = os.path.basename(os.path.normpath(folder)) or folder
        files = samples_in(folder)
        say("%s: %d file(s)" % (label, len(files)))
        for number, path in enumerate(files, 1):
            row = {"folder": label, "sha256": "", "verdict": "", "rules": "", "notes": "", "official": ""}
            try:
                if os.path.getsize(path) > ZIP_LIMIT:
                    raise ZipProblem("a zip of more than %d MB: not read" % (ZIP_LIMIT >> 20))
                with open(path, "rb") as fh:
                    data = fh.read()
                if data[:4] != b"PK\x03\x04":
                    raise ZipProblem("not a zip: not read (samples are read only out of password zips)")
                members = list(read_zip(data, password))
                del data
            except (ZipProblem, OSError, MemoryError) as problem:
                # (the SHA-256 of the zip file itself, so that the row can be found again). A zip
                # that is what it is (another password, not a zip) is NOT READ; one that could not
                # be opened at all in this run is MISSING - nothing is known about it
                if isinstance(problem, ZipProblem):
                    row.update(sha256="zip:" + _file_sha256(path), verdict=NOT_READ.upper(), notes=str(problem))
                else:
                    row.update(sha256="zip:" + _file_sha256(path), verdict=MISSING,
                               notes="the zip could not be opened in this run (%s)" % type(problem).__name__)
                rows.append(row)
                continue
            for name, content in members:
                row = {"folder": label, "sha256": "", "verdict": "", "rules": "", "notes": "", "official": ""}
                if isinstance(content, ZipProblem) and only is not None:
                    continue
                if isinstance(content, ZipProblem):
                    row.update(sha256="zip:" + _file_sha256(path), verdict=NOT_READ.upper(), notes=str(content))
                else:
                    row["sha256"] = hashlib.sha256(content).hexdigest()
                    row["folder"] = RELABEL.get(row["sha256"], label)
                    if only is not None and row["sha256"] not in only:
                        continue
                    try:
                        if listing == "versions":         # which Electron runtime: one line each
                            say("== %s %s" % (label, row["sha256"]))
                            for line in electron_versions(scanner, name, content, archives):
                                say("   " + line)
                            rows.append(row)
                            continue
                        if listing == "packages":         # npm package names and versions; coverage in numbers
                            say("== %s %s" % (label, row["sha256"][:16]))
                            for line in packages(scanner, name, content):
                                say("   " + line)
                            rows.append(row)
                            continue
                        if listing == "stealer":          # count only: what a stealer chain would rest on
                            numbers = stealer_count.count(scanner, lambda: scan_member(scanner, name, content))
                            say("== %s %s | %s" % (label, row["sha256"][:16], stealer_count.line(numbers)))
                            rows.append(row)
                            continue
                        if listing == "sideload":         # count only: what SIDELOAD-001 rests on
                            numbers = sideload_count.count(scanner, lambda: scan_member(scanner, name, content))
                            say("== %s %s | %s" % (label, row["sha256"][:16], sideload_count.line(numbers)))
                            rows.append(row)
                            continue
                        if listing == "encrypted":        # count only: what a password zip's entry list shows
                            numbers = encrypted_count.count(scanner, lambda: scan_member(scanner, name, content))
                            say("== %s %s | %s" % (label, row["sha256"][:16], encrypted_count.line(numbers)))
                            rows.append(row)
                            continue
                        if listing == "sinks":            # full reading against sink-first: numbers only
                            import time
                            with sink_count.Recorder() as recorder:
                                began = time.perf_counter()
                                row["verdict"], row["rules"], row["notes"] = scan_member(scanner, name, content)
                                seconds = time.perf_counter() - began
                            say("== %s %s | %s | scan %.0f s without the measurement" % (
                                label, row["sha256"][:16], row["verdict"], seconds - recorder.measuring))
                            for line in recorder.lines():
                                say("   " + line)
                            rows.append(row)
                            continue
                        if listing == "downloads":        # what a self-update policy would rest on: words only
                            with download_runs.Recorder() as recorder:
                                row["verdict"], row["rules"], row["notes"] = scan_member(scanner, name, content)
                            say("== %s %s | %s" % (label, row["sha256"][:16], row["verdict"]))
                            for line in recorder.lines():
                                say("   " + line)
                            rows.append(row)
                            continue
                        if listing == "diagnose":         # where the findings stand: numbers, endings, rule ids
                            with renpy_diagnosis.Recorder(official_origin) as recorder:
                                row["verdict"], row["rules"], row["notes"] = scan_member(scanner, name, content)
                            say("== %s %s | %s" % (label, row["sha256"][:16], row["verdict"]))
                            for line in recorder.lines():
                                say("   " + line)
                            rows.append(row)
                            continue
                        if listing == "readings":         # how long each reading took: printed below
                            del READINGS[:]
                        elif listing:                     # inventory mode: metadata, printed, not kept
                            say("== %s %s" % (label, row["sha256"]))
                            for line in inventory(scanner, name, content):
                                say("   " + line)
                        if memory is not None:
                            memory.begin()
                        try:
                            row["verdict"], row["rules"], row["notes"] = scan_member(scanner, name, content)
                            row["official"] = OFFICIAL["last"]
                        finally:
                            if memory is not None:
                                memory.rows.append((row["folder"], row["sha256"], memory.end()))
                        if SITES["rule"]:
                            say("== %s %s | %s: %d active finding(s)" % (label, row["sha256"][:16], SITES["rule"],
                                                                        len(SITES["lines"])))
                            for line in SITES["lines"]:
                                say("   " + line)
                            say("   verdict: %s | chains and CRITICAL: %s" % (row["verdict"], "; ".join(
                                part for part in row["rules"].split("; ") if "CHAIN" in part or "CRITICAL" in part) or "none"))
                        if listing == "readings":
                            say("== %s %s" % (label, row["sha256"]))
                            for line in READINGS:
                                if float(line.split(" | ")[2].split()[0]) >= 0.5 or "stopped: no" not in line \
                                        or not line.endswith("nothing"):
                                    say("   " + line)
                            say("   rules: " + "; ".join(part for part in row["rules"].split("; ")
                                                         if "CRITICAL" in part or "LIMIT" in part))
                    except Abort:
                        raise
                    except MemoryError:
                        row.update(verdict=NOT_READ.upper(), notes="not enough memory to scan this sample")
                    except Exception as exc:              # the scan of one sample failed: said, and on
                        row.update(verdict=NOT_READ.upper(), notes="the scan failed (%s)" % type(exc).__name__)
                rows.append(row)
                del content
            say("  %d / %d" % (number, len(files)), flush=True)
    return rows


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return "?"
    return digest.hexdigest()


def summary(rows: List[Dict[str, str]]) -> List[str]:
    """What the report gives per folder: verdict counts, the most common rules,
    and every sample that came out LIKELY SAFE or CLEAN (by SHA-256, with its notes)."""
    out: List[str] = []
    for folder in dict.fromkeys(row["folder"] for row in rows):
        mine = [row for row in rows if row["folder"] == folder]
        counts = collections.Counter(row["verdict"] for row in mine)
        out.append("%s: %d sample(s) - %s" % (folder, len(mine), ", ".join(
            "%s %d" % (verdict, counts[verdict]) for verdict in VERDICTS + [NOT_READ.upper(), MISSING]
            if counts[verdict])))
        rules = collections.Counter()
        for row in mine:
            rules.update({part.rsplit(" x", 1)[0] for part in row["rules"].split("; ") if part})
        out.append("  most common rules (samples they fired in): " + (", ".join(
            "%s %d" % item for item in rules.most_common(8)) or "none"))
        for row in mine:
            if row["verdict"] in ("LIKELY SAFE", "CLEAN", NOT_READ.upper(), MISSING):
                out.append("  %s  %s  rules: %s  notes: %s" % (row["verdict"], row["sha256"][:20],
                                                              row["rules"] or "none", row["notes"] or "none"))
    return out


def compare(before: List[Dict[str, str]], rows: List[Dict[str, str]]) -> List[str]:
    """What changed against an earlier result (``--compare``), by SHA-256: every verdict that
    moved, and every sample that is MISSING - one this run could not open, or one of the
    earlier result that this run has no row for. A MISSING sample is never a verdict change."""
    old = {row["sha256"]: row for row in before if row["sha256"] and not row["sha256"].startswith("zip:")}
    new = {row["sha256"]: row for row in rows if row["sha256"] and not row["sha256"].startswith("zip:")}
    out: List[str] = []
    for sha, row in new.items():
        if sha in old and old[sha]["verdict"] != row["verdict"]:
            out.append("changed  %s %s: %s -> %s" % (row["folder"], sha[:16], old[sha]["verdict"], row["verdict"]))
        elif sha not in old:
            out.append("new      %s %s: %s" % (row["folder"], sha[:16], row["verdict"]))
    for sha, row in old.items():
        if sha not in new:
            out.append("%s  %s %s (was %s): no row in this run" % (MISSING, row["folder"], sha[:16], row["verdict"]))
    for row in rows:
        if row["verdict"] == MISSING:
            out.append("%s  %s %s: %s" % (MISSING, row["folder"], row["sha256"][:20], row["notes"]))
    return out or ["no verdict changed, nothing missing"]


def official_drop(old: Dict[str, str], now: Dict[str, str]) -> Optional[str]:
    """Whether a lower verdict of one sample is the drop phageo accepts (2026-10-17): every
    finding the earlier run had and this one has not - by rule and level - stood, in the earlier
    run, in a file that is byte for byte an official one (its ``official`` column). The words
    for the report when it is; None when it is not, or when the earlier run did not record it
    (a result written before the column existed)."""
    if old.get("official") is None:
        return None
    removed = counts(old.get("rules", "")) - counts(now.get("rules", ""))
    if not removed or removed - counts(old.get("official", "")):
        return None
    return "removed, all from official files: " + "; ".join("%s x%d" % item for item in sorted(removed.items()))


def gate(before: Optional[List[Dict[str, str]]], rows: List[Dict[str, str]],
         accepted: Optional[List[str]] = None) -> List[str]:
    """Why this run fails the gate "no verdict is lost" (empty: it passes). A lost verdict is a
    sample that is MISSING in this run, a sample of the earlier result (``before``) that has no
    row in this run, or a verdict lower than the earlier one (NOT READ is lower than any) -
    unless every finding it lost came from an official file (:func:`official_drop`); such a
    drop goes into ``accepted`` (to be reported) instead."""
    rank = {verdict: len(VERDICTS) - at for at, verdict in enumerate(VERDICTS)}     # DANGEROUS 5 ... CLEAN 1
    out = ["%s %s: MISSING in this run" % (row["folder"], row["sha256"][:20]) for row in rows
           if row["verdict"] == MISSING]
    if before is not None:
        new = {row["sha256"]: row for row in rows if row["sha256"]}
        for row in before:
            sha = row["sha256"]
            if not sha or row["verdict"] == MISSING:
                continue
            now = new.get(sha)
            if now is None:
                out.append("%s %s (was %s): no row in this run" % (row["folder"], sha[:20], row["verdict"]))
            elif now["verdict"] != MISSING and rank.get(now["verdict"], 0) < rank.get(row["verdict"], 0):
                line = "%s %s: %s -> %s" % (row["folder"], sha[:20], row["verdict"], now["verdict"])
                why = official_drop(row, now)
                if why is None:
                    out.append(line)
                elif accepted is not None:
                    accepted.append("%s (%s)" % (line, why))
    return out


def read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: str, rows: List[Dict[str, str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _guard_case(name: str) -> None:
    """For the tests: switch the guard on and do the one thing ``name`` names.
    Each of them must end in :class:`Abort` before anything happens."""
    install_guard()
    if name == "popen":
        import subprocess
        subprocess.Popen(["cmd.exe", "/c", "echo", "must never run"])
    elif name == "system":
        os.system("echo must never run")
    elif name == "startfile":
        os.startfile("must-never-open.txt")
    elif name == "execv":
        os.execv(sys.executable, [sys.executable, "-c", "print('must never run')"])
    elif name == "spawnv":
        os.spawnv(os.P_NOWAIT, sys.executable, [sys.executable, "-c", "print('must never run')"])
    elif name == "exec":
        exec("print('must never run')")
    elif name == "eval":
        eval("print('must never run')")
    elif name == "compile":
        compile("print('must never run')", "<sample>", "exec")
    elif name == "library":
        ctypes.WinDLL("kernel32")
    elif name == "allowed":
        import ast
        ast.parse("print('only read, never run')")                # how the scanner reads Python
        with Aes(bytes(16)) as aes:                               # bcrypt.dll is the one library
            aes.blocks(bytes(16))
        print("allowed: nothing was stopped")
    else:
        raise SystemExit("no such case: " + name)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folders", nargs="*", help="folders of password zips (each row is labelled by its folder)")
    parser.add_argument("--out", help="the result CSV (never inside a sample folder)")
    parser.add_argument("--only", metavar="FILE", help="scan only the samples whose SHA-256 stands in FILE "
                        "(one per line; a result CSV of this tool works too)")
    parser.add_argument("--inventory", action="store_true",
                        help="print what each sample is made of (names, sizes, kinds by first bytes, which "
                             "reader took what, the not-read notes) - metadata only; no CSV is written")
    parser.add_argument("--electron-versions", action="store_true",
                        help="print which Electron version each sample's program states - version metadata "
                             "only; nothing is scanned and no CSV is written")
    parser.add_argument("--archives", metavar="FOLDER",
                        help="with --electron-versions: the folder of official archives - a program is then "
                             "compared with the official electron.exe of its version, section by section "
                             "(numbers only)")
    parser.add_argument("--readings", action="store_true",
                        help="print how long each download-and-run reading of a JavaScript text took, its "
                             "counted steps and where it stopped - numbers only; no CSV is written")
    parser.add_argument("--sites", metavar="RULE",
                        help="print, per sample, where each active finding of RULE stands (file number, "
                             "line, short marks of place and evidence) - to tell several sites from one "
                             "site said twice; numbers and marks only. RULE 'QUOTED': per file, which "
                             "matches were hidden as quoted text of a script, and what is active beside them")
    parser.add_argument("--packages", action="store_true",
                        help="print the npm packages each sample carries (name@version from the package.json "
                             "files under node_modules - names and versions only) and, in numbers, how much "
                             "of node_modules the npm table verifies; no CSV is written")
    parser.add_argument("--stealer-count", action="store_true",
                        help="print, per sample, how many add-ons import the function that decrypts stored "
                             "secrets, how many scripts name a browser / chat / wallet store, and how many "
                             "have a network call (tools/stealer_count.py) - numbers only; no CSV is written")
    parser.add_argument("--encrypted-count", action="store_true",
                        help="print, per sample, how many entries of its password zips (encrypted members) are "
                             "programs, scripts, archives or other, by the endings in the zip's own list "
                             "(tools/encrypted_count.py) - numbers only; no CSV is written")
    parser.add_argument("--sideload-count", action="store_true",
                        help="print, per sample, how many libraries named like a part of Windows lie beside a "
                             "program that imports or loads them, and what clears them - an official table, "
                             "a signature naming Microsoft (not checked in memory), nothing "
                             "(tools/sideload_count.py) - numbers only; no CSV is written")
    parser.add_argument("--sinks", action="store_true",
                        help="measure, per sample, the JavaScript download-and-run reading against a sink-first "
                             "reading (tools/sink_count.py): times, sinks, trace steps - numbers only; no CSV "
                             "is written")
    parser.add_argument("--download-runs", action="store_true",
                        help="print, per sample, every JavaScript download-and-run chain with four answers - "
                             "address constant / from the app's settings / runtime, HTTPS, same server as the "
                             "app, a signature check on the way (tools/download_runs.py) - words only; no CSV "
                             "is written")
    parser.add_argument("--diagnose", action="store_true",
                        help="print, per sample, where its HIGH / CRITICAL findings stand (endings of the "
                             "containers and the file, official or not), what its scripts that are not "
                             "official name (network / decode / run / write words, counted), which compiled "
                             "scripts could not be read and why, and what the resolved command lines start "
                             "(tools/renpy_diagnosis.py) - numbers, endings and rule ids only; no CSV is written")
    parser.add_argument("--profile", metavar="FILE",
                        help="measure where the time of the run goes (Python's cProfile) and write the "
                             "costliest functions to FILE - names of the scanner's own functions and "
                             "numbers only, nothing of a sample; never inside a sample folder")
    parser.add_argument("--compare", metavar="CSV",
                        help="an earlier result of this tool: print every verdict that changed against it, "
                             "and every sample that is MISSING (could not be opened, or has no row) - a "
                             "missing sample is never counted as a verdict change")
    parser.add_argument("--memory", metavar="FILE",
                        help="write each sample's peak memory (the process's working set, read every 20 ms "
                             "while the sample is scanned) to FILE: folder, SHA-256, MB - a file of its own, "
                             "so that the result CSV stays comparable byte for byte; never inside a sample folder")
    parser.add_argument("--memory-where", action="store_true",
                        help="print, per sample, its peak memory, which of the scanner's functions were running "
                             "at the peak and which had the highest memory, and the largest text a file was "
                             "decoded to (characters, bytes per character) - names of the scanner's functions "
                             "and numbers only; no CSV is written")
    parser.add_argument("--guard-case", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    profiler = None
    try:
        if args.guard_case:
            _guard_case(args.guard_case)
            return 0
        if not args.folders or not (args.out or args.inventory or args.electron_versions or args.readings
                                    or args.stealer_count or args.sites or args.packages or args.sinks
                                    or args.download_runs or args.encrypted_count or args.sideload_count
                                    or args.memory_where or args.diagnose):
            parser.error("folders and --out are needed")
        out = os.path.abspath(args.out or os.path.join(HERE, "unused.csv"))
        for folder in args.folders:
            if not os.path.isdir(folder):
                parser.error("not a folder: %s" % folder)
            for written in [out] + [os.path.abspath(extra) for extra in (args.profile, args.memory) if extra]:
                try:
                    inside = os.path.commonpath([written, os.path.abspath(folder)]) == os.path.abspath(folder)
                except ValueError:                          # (another drive)
                    inside = False
                if inside:
                    parser.error("the result may not be written into a sample folder")
        SITES["rule"] = args.sites or ""
        if args.sites == "WRITTEN":                 # numbers of the "written and started" reading
            from gamescan.dataflow import remote
            remote.WRITTEN_TRACE = []
        only = None
        if args.only:
            import re
            with open(args.only, encoding="utf-8-sig") as fh:
                only = set(re.findall(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", fh.read().lower()))
        if args.profile:
            import cProfile
            import pstats
            profiler = cProfile.Profile()
            profiler.enable()
        # (made before the guard is switched on)
        watch = MemoryWatch(where=args.memory_where) if args.memory or args.memory_where else None
        if args.memory_where:
            watch_texts()
        try:
            rows = run(args.folders, only=only, listing="versions" if args.electron_versions else "readings" if args.readings
                       else "stealer" if args.stealer_count else "encrypted" if args.encrypted_count
                       else "sideload" if args.sideload_count
                       else "packages" if args.packages
                       else "sinks" if args.sinks else "downloads" if args.download_runs
                       else "diagnose" if args.diagnose else args.inventory,
                       archives=args.archives or "", memory=watch)
        finally:
            if watch is not None:
                watch.close()
            if profiler is not None:
                profiler.disable()
                with open(os.path.abspath(args.profile), "w", encoding="utf-8") as handle:
                    stats = pstats.Stats(profiler, stream=handle)
                    stats.sort_stats("tottime").print_stats(45)
                    stats.sort_stats("cumulative").print_stats(70)
    except Abort as stop:
        print(str(stop))
        print("Nothing was written. Guard hits: %d" % len(GUARD_HITS))
        return 3
    if watch is not None and args.memory:
        write_memory(os.path.abspath(args.memory), watch.rows)
        print("peak memory of %d sample(s) -> %s" % (len(watch.rows), os.path.abspath(args.memory)))
    if args.memory_where:
        for (folder, sha, peak), where in zip(watch.rows, watch.wheres):
            print("%s %s: peak %d MB; largest text %d characters, %d byte(s) each" % (
                folder, sha[:16], peak >> 20, where["text"][0], where["text"][1]))
            print("   at the peak: %s" % " < ".join(where["stack"]))
            for name, most in where["most"]:
                print("   %6d MB  %s" % (most >> 20, name))
        print("guard hits: %d" % len(GUARD_HITS))
        return 0
    if args.electron_versions or args.readings or args.stealer_count or args.encrypted_count or args.sites or args.packages or args.sinks \
            or args.download_runs or args.sideload_count or args.diagnose:
        print("guard hits: %d" % len(GUARD_HITS))
        return 0
    if args.inventory:
        if args.out:                           # (the CSV as well, when one was asked for)
            write_csv(out, rows)
        for row in rows:
            print("%s %s: %s | %s" % (row["folder"], row["sha256"][:16], row["verdict"], row["notes"] or "no not-read note"))
        print("guard hits: %d" % len(GUARD_HITS))
        return 0
    write_csv(out, rows)
    for line in summary(rows):
        print(line)
    before = read_csv(args.compare) if args.compare else None
    if before is not None:
        print("against %s:" % os.path.basename(args.compare))
        for line in compare(before, rows):
            print("  " + line)
    print("%d row(s) -> %s; guard hits: %d" % (len(rows), out, len(GUARD_HITS)))
    accepted: List[str] = []
    failed = gate(before, rows, accepted)
    for line in accepted:
        print("accepted drop (gate rule of 2026-10-17): " + line)
    if failed:
        print("GATE FAILED - %d verdict(s) lost:" % len(failed))
        for line in failed:
            print("  " + line)
        return GATE_FAILED
    print("gate: no verdict lost" + ("" if before is not None else " (no --compare: only MISSING rows checked)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
