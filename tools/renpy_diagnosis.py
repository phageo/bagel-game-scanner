"""Where a Ren'Py sample's findings stand, and what its own files hold - in numbers only.

A measurement, not a rule (phageo, 2026-10-17, sixtieth message: for the Ren'Py samples that left
DANGEROUS, "per group, rule IDs, file types and counts only: remaining HIGH findings and where;
which file holds the attacker's logic (official vs not; .rpy, .rpyc, .rpa member, other); is
there a real download-or-decode -> run chain the tracers miss, and why"). While the scanner reads
a sample the usual way, every file it reads is described by:

``place``      the endings of the containers it lies in and its own (``zip > .rpa > .rpyc``)
``official``   whether it is, byte for byte, a file of an official table (the runner's own check)
``engine``     whether it lies where Ren'Py's engine files lie (``renpy/``, ``lib/python*``)
``words``      for a script that is not official (a compiled script: what the scanner decompiles
               out of it): how many places name the network, a decoding, something that runs
               code or starts a program, a file write - counted by fixed word lists
``unread``     for a compiled script the scanner could not read: what kind of header it has

and every command line the scanner resolved (``DF-CMD-001``) by the kind of program it starts
and whether it names an address, a download, a start, Defender or an encoded command.

Since 2026-10-18 (phageo, sixty-second message; decisions 2 and 3, diagnosis only):

``proof``      why ``CHAIN-LOCAL-DROP`` stays HIGH: per decoding step of each chain, could it be
               applied again and, if not, why (where its key or bounds come from); was the file it
               decodes found in the scan and kept for the proof (or why not); are the files decoded
               one by one or joined first; each of the script's own steps that can be applied again
               applied in memory to the kept files, as the scanner's proof does - its result's size
               and header class (:func:`header_class`). Never anything else: no guessed key, bounds
               or order, no files joined (phageo, 2026-10-18: the two trials of that kind are removed)
``old form``   a compiled script without Ren'Py's header, checked for the old form (a zlib stream
               from the first byte); a stream is inflated in memory (capped) and only the header
               class of the result is counted - never unpickled (rule 2)

Numbers, endings, rule numbers and these words only: no name, path, address or text of a sample
is printed. Real samples only through ``tools/positive_benchmark.py <folders> --diagnose``.
"""
from __future__ import annotations

import collections
import math
import os
import re
import sys
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_SCRIPTS = (".py", ".pyw", ".rpy", ".rpym", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".txt")
_COMPILED = (".rpyc", ".rpymc")
_MAX_TEXT = 8 << 20
WORDS = {
    "network": re.compile(r"\b(?:urlopen|urllib\d?|urlretrieve|requests\s*\.\s*(?:get|post|Session)|http\.client|httplib"
                          r"|socket\s*\.\s*(?:socket|create_connection)|renpy\s*\.\s*fetch|WinHttp|URLDownloadToFile"
                          r"|Invoke-WebRequest|DownloadFile|DownloadString|XMLHttpRequest|fetch\s*\()", re.I),
    "decode": re.compile(r"\b(?:b64decode|b32decode|b85decode|a85decode|base64|zlib\s*\.\s*decompress|marshal\s*\.\s*loads"
                         r"|pickle\s*\.\s*loads|codecs\s*\.\s*decode|fromhex|unhexlify|rot_?13|lzma|bz2\s*\.\s*decompress"
                         r"|Fernet|AES|FromBase64String|\^\s*0x[0-9a-f]{2})", re.I),
    "run": re.compile(r"\b(?:exec|eval|compile|subprocess|Popen|os\s*\.\s*system|os\s*\.\s*startfile|os\s*\.\s*popen"
                      r"|ShellExecute\w*|__import__|importlib|runpy|ctypes|CreateProcess\w*|Start-Process|Invoke-Expression)\b"),
    "write": re.compile(r"""\bopen\s*\([^)\n]{0,200}?["'](?:w|a|wb|ab|w\+|wb\+)["']|\.\s*write(?:_bytes)?\s*\(|shutil\s*\.\s*copy"""),
}
_COMMAND = {
    "address": re.compile(r"https?://|ftp://|\\\\[\w.-]+\\", re.I),
    "download": re.compile(r"Invoke-WebRequest|\biwr\b|\bcurl\b|\bwget\b|bitsadmin|certutil|DownloadFile|DownloadString"
                           r"|Net\.WebClient|Start-BitsTransfer|Invoke-RestMethod", re.I),
    "start": re.compile(r"Start-Process|\bstart\b|Invoke-Expression|\biex\b|rundll32|regsvr32|mshta|wscript|cscript", re.I),
    "defender": re.compile(r"MpPreference|Exclusion|Defender|DisableRealtime", re.I),
    "encoded": re.compile(r"-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String", re.I),
}
_PROGRAMS = ("powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "reg", "schtasks", "taskkill", "tasklist",
             "start", "explorer", "curl", "bitsadmin", "certutil", "wmic", "attrib", "icacls", "python", "rundll32",
             "regsvr32", "sc", "net", "netsh", "wget", "timeout", "ping", "msiexec")


def place(relpath: str) -> str:
    """``zip > .rpa > .rpyc``: the endings of the containers and of the file itself."""
    parts = relpath.replace("\\", "/").split("!")
    return " > ".join((os.path.splitext(part)[1].lower() or "(none)").lstrip(".") if at == 0 else
                      (os.path.splitext(part)[1].lower() or "(none)") for at, part in enumerate(parts))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


def unread_kind(data: bytes) -> str:
    """Why a compiled Ren'Py script may not be readable - by its header only."""
    from gamescan.unpack import rpyc
    head = data[:10]
    if head == b"RENPY RPC2":
        kind = "RPC2 header"
    elif head.startswith(b"RENPY RPC"):
        kind = "RPC header of another number"
    elif head.startswith(b"RENPY"):
        kind = "RENPY header of another kind"
    elif data[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        kind = "no header, zlib data"
    else:
        kind = "no Ren'Py header"
    inflated = rpyc.slab(data) is not None
    return "%s, %s, entropy %.1f" % (kind, "inflates" if inflated else "does not inflate", _entropy(data[10:4096]))


# -- header classes (phageo, 2026-10-18, sixty-second message) -----------------------------------
_B64 = re.compile(rb"[A-Za-z0-9+/=\s_-]+\Z")
_HEX = re.compile(rb"[0-9A-Fa-f\s]+\Z")
_ARCHIVE_HEADS = (b"7z\xbc\xaf\x27\x1c", b"Rar!", b"MSCF", b"\x1f\x8b", b"BZh", b"\xfd7zXZ")
_MAX_OLD_FORM = 16 << 20           # what an old-form compiled script is inflated to, at most


def header_class(data) -> str:
    """What ``data`` is by its head: program, DLL, archive with program, archive, zlib, pickle,
    random, text (Base64 / hex alphabet named), other. Nothing is unpacked but a zip's own list."""
    from gamescan import localdrop
    if data is None:
        return "nothing"
    data = bytes(data[:1 << 20]) if len(data) > 1 << 20 and data[:4] != b"PK\x03\x04" else bytes(data)
    if not data:
        return "empty"
    shown = localdrop.proof(data)
    if shown == localdrop.PROGRAM:
        return "program"
    if shown == localdrop.LIBRARY:
        return "DLL"
    if shown == localdrop.ARCHIVE:
        return "archive with program"
    if data[:2] == b"MZ":
        return "other (MZ without a PE header)"
    if data[:4] == b"PK\x03\x04" or data.startswith(_ARCHIVE_HEADS):
        return "archive"
    if len(data) > 2 and data[0] & 0x0F == 8 and data[0] >> 4 <= 7 and (data[0] << 8 | data[1]) % 31 == 0:
        import zlib
        try:
            if zlib.decompressobj().decompress(data[:65536], 64):    # (a head that only looks like one: no)
                return "zlib"
        except zlib.error:
            pass
    if data[:1] == b"\x80" and data[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return "pickle"
    head = data[:4096]
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if printable >= 0.95 * len(head):
        if _HEX.match(head):
            return "text (hex alphabet)"
        if _B64.match(head):
            return "text (Base64 alphabet)"
        return "text"
    if _entropy(data[:65536]) >= 7.5:
        return "random"
    return "other"


def size_class(n: int) -> str:
    for limit, label in ((1024, "under 1 KB"), (64 << 10, "1-64 KB"), (1 << 20, "64 KB-1 MB"), (16 << 20, "1-16 MB")):
        if n < limit:
            return label
    return "16 MB or more"


def old_form(data: bytes) -> str:
    """Decision 3: is a compiled script without Ren'Py's header in the old form - a zlib stream
    from its first byte? Inflated in memory up to ``_MAX_OLD_FORM``; only the header class of the
    result is said. Never unpickled."""
    import zlib
    try:
        engine = zlib.decompressobj()
        out = engine.decompress(bytes(data), _MAX_OLD_FORM)
    except zlib.error:
        return "not a zlib stream (content: %s)" % header_class(data)
    if engine.unconsumed_tail:
        return "a zlib stream of more than %d MB (not inflated to its end)" % (_MAX_OLD_FORM >> 20)
    if not engine.eof:
        return "a zlib stream that ends early (result: %s)" % header_class(out)
    return "a zlib stream (old form); result: %s%s" % (header_class(out), ", data behind it" if engine.unused_data else "")


def _step_label(step) -> str:
    kind = step[0] if step else "?"
    if kind == "xor":
        return "XOR (key written out)" if len(step) > 1 and step[1] else "XOR (key not written out)"
    if kind == "slice":
        return "cut (bounds written out)" if all(one is None or isinstance(one, int) for one in step[1:3]) \
            else "cut (bounds not written out)"
    return {"custom": "a decoding of its own"}.get(kind, kind)


class Recorder:
    """Wraps ``Scanner._scan_one`` and ``Scanner.scan_bytes`` while a sample is scanned."""

    def __init__(self, origin: Callable) -> None:
        from gamescan import scanner as S
        from gamescan.dataflow import remote_py as P
        self.S, self.P, self.origin = S, P, origin
        self.real_scan, self.real_bytes = S.Scanner._scan_one, S.Scanner.scan_bytes
        self.real_local, self.real_call, self.real_drop, self.real_sinks, self.real_hit = (
            P.local_drops, P._Flow._local_call, P._Flow._drop, P._Flow.sinks, P._Flow._local_hit)
        # (2026-10-18: the proof of CHAIN-LOCAL-DROP and where its steps come from)
        from gamescan import localdrop
        self.localdrop = localdrop
        self.real_join, self.real_offer = S.Scanner._join_local, localdrop.offer
        self.real_key, self.real_operation, self.real_statement, self.real_flow_call = (
            P._Flow._key, P._Flow._local_operation, P._Flow.statement, P._Flow.call)
        self.files: Dict[str, dict] = {}
        self.found: List = []
        self.current: List[str] = []
        # what the local reading (CHAIN-LOCAL-DROP) saw in each file: counts by kind
        self.local: Dict[str, collections.Counter] = {}
        # file name (as kept) -> what happened when it was offered for the proof: counts
        self.offers: Dict[str, collections.Counter] = {}
        self.proof: collections.Counter = collections.Counter()      # what the proof met, counted
        self.keys_asked = 0
        self.old: collections.Counter = collections.Counter()        # decision 3: the old form

    def _count(self, what: str, n: int = 1) -> None:
        if self.current:
            self.local.setdefault(self.current[-1], collections.Counter())[what] += n

    def __enter__(self) -> "Recorder":
        recorder, P = self, self.P

        def scan_one(scanner, ctx, depth=0):
            if ctx.relpath not in recorder.files:
                recorder.files[ctx.relpath] = recorder.describe(ctx)
            recorder.current.append(ctx.relpath)
            try:
                return recorder.real_scan(scanner, ctx, depth)
            finally:
                recorder.current.pop()

        def scan_bytes(scanner, *args, **kwargs):
            out = recorder.real_bytes(scanner, *args, **kwargs)
            recorder.found = list(out)
            return out

        def local_drops(text, renpy=False):
            gates = [bool(p.search(text or "")) for p in (P._LOCAL_HINT, P._READ_HINT, P._SINK_HINT)]
            recorder._count("local reading asked")
            for name, open_ in zip(("decoder named", "file read named", "sink named"), gates):
                recorder._count(name + (" yes" if open_ else " no"))
            found, cut = recorder.real_local(text, renpy)
            recorder._count("local chains", len(found))
            if cut:
                recorder._count("local reading cut")
            return found, cut

        def local_call(flow, node, name, line):
            out = recorder.real_call(flow, node, name, line)
            if isinstance(out, P._Local):
                recorder._count("decoded value of a game file" if out.decoded else "game file read")
                if out.steps:
                    recorder._count("step " + str(out.steps[-1][0]))
                    if out.steps[-1] == ("custom",):
                        func = node.func
                        recorder._count("decoding of its own: " + (
                            ".translate()" if isinstance(func, P.ast.Attribute) and func.attr == "translate" else
                            "a decompressor object" if isinstance(func, P.ast.Attribute) and func.attr == "decompress"
                            else "marshal" if name == "marshal.loads" else "a codec (rot13 / uu)"))
            return out

        def key(flow, node):
            recorder.keys_asked += 1
            out = recorder.real_key(flow, node)
            if out is None:
                recorder._count("XOR key not written out: " + recorder._key_source(flow, node))
            return out

        def operation(flow, node):
            asked = recorder.keys_asked
            out = recorder.real_operation(flow, node)
            if isinstance(out, P._Local) and out.steps:
                last = out.steps[-1]
                # (both sides carry a game file's content: the tracer gives ("xor", None) without asking
                # for a key - or joins two texts with +)
                if last == ("xor", None) and recorder.keys_asked == asked and isinstance(node.op, P.ast.BitXor):
                    recorder._count("XOR key not written out: the content of a game file (or derived from one)")
                elif isinstance(node.op, P.ast.Add) and not isinstance(node.left, P.ast.Constant) \
                        and not isinstance(node.right, P.ast.Constant) and last != ("custom",) \
                        and isinstance(flow.lookup(flow.key_of(node.left)) if isinstance(node.left, (P.ast.Name, P.ast.Attribute))
                                       else None, P._Local) \
                        and isinstance(flow.lookup(flow.key_of(node.right)) if isinstance(node.right, (P.ast.Name, P.ast.Attribute))
                                       else None, P._Local):
                    recorder._count("two game-file contents joined with + (%s)" % (
                        "after decoding" if out.decoded else "before decoding"))
                elif last == ("custom",):
                    recorder._count("decoding of its own: arithmetic " + type(node.op).__name__)
            return out

        def statement(flow, node, scope):
            before = None
            if flow.local and isinstance(node, P.ast.AugAssign) and isinstance(node.op, P.ast.Add):
                try:
                    before = flow.lookup(flow._target_key(node.target))
                except Exception:
                    before = None
            out = recorder.real_statement(flow, node, scope)
            if isinstance(before, P._Local):
                recorder._count("a game-file content extended with += (%s)" % (
                    "after decoding" if before.decoded else "before decoding"))
            if flow.local and isinstance(node, (P.ast.For, P.ast.While)):
                recorder._count("loops in a file with a local reading")
            return out

        def flow_call(flow, node):
            out = recorder.real_flow_call(flow, node)
            if flow.local and isinstance(out, P._Local) and isinstance(node.func, P.ast.Attribute) \
                    and node.func.attr == "join":
                recorder._count("game-file contents joined with join() (%s)" % (
                    "after decoding" if out.decoded else "before decoding"))
            return out

        def offer(relpath, data):
            files = getattr(recorder.localdrop._kept, "files", None)
            name = recorder.localdrop.leaf(relpath.rsplit("!", 1)[-1])
            before = len(files.get(name, ())) if files is not None else 0
            recorder.real_offer(relpath, data)
            if files is None or not name or not isinstance(data, (bytes, bytearray, memoryview)):
                return
            held = recorder.offers.setdefault(name, collections.Counter())
            if len(files.get(name, ())) > before:
                held["kept"] += 1
            else:
                size = len(data)
                held["not kept: " + (
                    "under 16 bytes" if size < 16 else "over 16 MB" if size > recorder.localdrop.MAX_KEPT_FILE
                    else "no room left (64 MB kept)" if recorder.localdrop._kept.size + size > recorder.localdrop.MAX_KEPT
                    else "plainly no encoded file (first bytes: %s)" % header_class(bytes(data[:4096]))
                    if bytes(data[:8]).startswith(recorder.localdrop._PLAIN)
                    else "four of that name kept already" if len(files.get(name, ())) >= recorder.localdrop.MAX_CANDIDATES
                    else "a script (read by the scan itself)")] += 1

        def join_local(scanner, findings):
            try:
                recorder._prove(scanner, findings)
            except Exception as exc:            # (a measurement must never break the scan)
                recorder.proof["measurement failed: %s" % type(exc).__name__] += 1
            return recorder.real_join(scanner, findings)

        def drop(flow, path, source, extracted=False):
            if flow.local and source is not None:
                if path is None:
                    recorder._count("write: path not known")
                elif not (isinstance(source, P._Local) and source.decoded):
                    recorder._count("write of data that is no decoded game file")
                else:
                    recorder._count("write of a decoded game file")
            return recorder.real_drop(flow, path, source, extracted)

        def sinks(flow, node):
            if flow.local:
                name = flow.canon(node.func) or ""
                arguments = list(node.args) + [k.value for k in node.keywords]
                if name in P._CODE:
                    source = flow._any(arguments[:1])
                    recorder._count("code run of a decoded game file (in memory)" if isinstance(source, P._Local)
                                    and source.decoded else "code run of something else")
                if name in P._COMMAND or name in P._RUNS_FILE:
                    started = arguments if name not in P._COMMAND else list(node.args) + [
                        k.value for k in node.keywords if k.arg in ("args", "executable", "cmd", "command", "file", "path")]
                    hit = any(flow._dropped(argument, deep=True) is not None for argument in started)
                    other = any(flow._dropped(argument, deep=True) is not None for argument in arguments)
                    recorder._count("start of a written decoded file" if hit else
                                    "start whose other keyword names a written decoded file" if other else
                                    "start of something else")
                    recorder._count("starter " + name.rsplit(".", 1)[-1])
                    for at, argument in enumerate(node.args):
                        if flow._dropped(argument, deep=True) is not None:
                            recorder._count("matched through argument %d (%s)" % (at, type(argument).__name__))
                    for keyword in node.keywords:
                        if flow._dropped(keyword.value, deep=True) is not None:
                            recorder._count("matched through keyword %s" % keyword.arg)
                    recorder._count("first argument " + (type(node.args[0]).__name__ if node.args else "none"))
            return recorder.real_sinks(flow, node)

        def local_hit(flow, drop_, sink, line, via="", others=()):
            before = len(flow.local_hits)
            recorder.real_hit(flow, drop_, sink, line, via, others)
            recorder._count(("local chain kept" if len(flow.local_hits) > before else "local chain offered, not kept")
                            + (" (through the %s)" % via if via else ""))

        self.S.Scanner._scan_one, self.S.Scanner.scan_bytes = scan_one, scan_bytes
        self.S.Scanner._join_local, self.localdrop.offer = join_local, offer
        P._Flow._local_hit = local_hit
        P.local_drops, P._Flow._local_call, P._Flow._drop, P._Flow.sinks = local_drops, local_call, drop, sinks
        P._Flow._key, P._Flow._local_operation, P._Flow.statement, P._Flow.call = key, operation, statement, flow_call
        return self

    def __exit__(self, *_exc) -> None:
        self.S.Scanner._scan_one, self.S.Scanner.scan_bytes = self.real_scan, self.real_bytes
        self.S.Scanner._join_local, self.localdrop.offer = self.real_join, self.real_offer
        P = self.P
        P._Flow._local_hit = self.real_hit
        P.local_drops, P._Flow._local_call, P._Flow._drop, P._Flow.sinks = (
            self.real_local, self.real_call, self.real_drop, self.real_sinks)
        P._Flow._key, P._Flow._local_operation, P._Flow.statement, P._Flow.call = (
            self.real_key, self.real_operation, self.real_statement, self.real_flow_call)

    # -- decision 2: where the steps come from, and what the proof meets ----------------------
    def _key_source(self, flow, node, depth: int = 0) -> str:
        """Where an XOR key that is not written out comes from - a class only."""
        P = self.P
        try:
            if isinstance(node, P.ast.Subscript):
                return "an indexed value: " + self._key_source(flow, node.value, depth + 1)
            if isinstance(node, P.ast.Constant):
                return "a written-out value that is no byte (%s)" % type(node.value).__name__
            if isinstance(node, (P.ast.Name, P.ast.Attribute)):
                held = flow.lookup(flow.key_of(node))
                if isinstance(held, P._Local):
                    return "the content of a game file" + (" (decoded)" if held.decoded else "")
                if isinstance(node, P.ast.Attribute):
                    return "a field or attribute"
                values = flow.assigned.get(flow.key(node.id), [])
                if not values:
                    return "a name never assigned in this scope (a parameter, a loop name or another file's)"
                if len(values) > 1:
                    return "a name assigned %s times" % ("2-3" if len(values) <= 3 else "4 or more")
                if depth < 3:
                    return "a name given " + self._key_source(flow, values[0], depth + 1)
                return "a name given another name"
            if isinstance(node, P.ast.Call):
                name = flow.canon(node.func) or ""
                return "the result of a call" + (" (%s)" % name if name in (
                    "ord", "len", "int", "bytes", "bytearray", "hash", "sum", "hashlib.md5", "hashlib.sha256",
                    "hashlib.sha1", "random.randint", "random.Random", "str.encode") else "")
            if isinstance(node, P.ast.BinOp):
                return "arithmetic (%s)" % type(node.op).__name__
            return "an expression (%s)" % type(node).__name__
        except Exception:
            return "not classified"

    def _prove(self, scanner, findings) -> None:
        """What ``Scanner._join_local`` will try for each CHAIN-LOCAL-DROP, measured before it
        runs: classes and numbers only."""
        from gamescan import scanner as S
        localdrop, count = self.localdrop, self.proof
        chains = [f for f in findings if f.rule_id == S.LOCAL_DROP and f.context.get("local_drop")]
        count["chains"] += len(chains)
        seen_names = {localdrop.leaf(name.rsplit("!", 1)[-1]) for name in self.files}
        for f in chains:
            wanted = f.context["local_drop"]
            items = [wanted] + list(wanted.get("also") or ())
            count["files the chain names: %s" % ("1" if len(items) == 1 else "2-8" if len(items) <= 8 else "9-16")] += 1
            count["started through its folder" if f.context.get("in_folder") else "started directly"] += 1
            for one in items:
                name, steps = one.get("file") or "", tuple(one.get("steps") or ())
                count["named file: " + ("name resolved" if name else "name not resolved (known at run time)")] += 1
                count["steps: %d" % len(steps)] += 1
                for at, step in enumerate(steps, 1):
                    count["step %d: %s - %s" % (at, _step_label(step), "can be applied again"
                                                if localdrop._known(step) else "cannot be applied again")] += 1
                if not name:
                    continue
                kept = localdrop.kept(name)
                disk = scanner._local_disk.get(name, ())
                count["named file taken by a reader of the scan: %s" % ("yes" if name in seen_names else "no")] += 1
                count["named file kept for the proof: %s" % (
                    "%d cop%s" % (len(kept), "y" if len(kept) == 1 else "ies") if kept else
                    "no (%s)" % ", ".join(sorted(self.offers.get(name, {"never offered": 1})))) + (
                    "; on disk %d" % len(disk) if disk else "")] += 1
                for data in kept[:2]:
                    count["input: %s, %s" % (header_class(data), size_class(len(data)))] += 1
                    current = data
                    for at, step in enumerate(steps, 1):
                        if not localdrop._known(step):
                            count["applied: stops at step %d (%s)" % (at, _step_label(step))] += 1
                            break
                        out = localdrop.decode(current, [step])
                        if out is None:
                            count["applied: step %d (%s) fails on %s" % (at, _step_label(step), header_class(current))] += 1
                            break
                        current = out
                        count["applied: after step %d (%s): %s, %s" % (
                            at, _step_label(step), header_class(current), size_class(len(current)))] += 1
                    else:
                        count["applied: result %s, %s%s" % (header_class(current), size_class(len(current)),
                                                            " - the proof shows it" if localdrop.proof(current) else "")] += 1

    def lines_proof(self) -> List[str]:
        out = ["CHAIN-LOCAL-DROP proof (decision 2): %d chain(s)" % self.proof["chains"]]
        out += ["  %s x%d" % item for item in sorted(self.proof.items()) if item[0] != "chains"]
        offered = collections.Counter()
        for counts in self.offers.values():
            for what, n in counts.items():
                offered[what] += n
        out.append("files offered for the proof: %d name(s); %s" % (
            len(self.offers), ", ".join("%s %d" % item for item in sorted(offered.items())) or "none"))
        out.append("compiled scripts without Ren'Py's header, the old form (decision 3): %d" % sum(self.old.values()))
        out += ["  %s x%d" % item for item in sorted(self.old.items())]
        return out

    def describe(self, ctx) -> dict:
        from gamescan.handlers import renpy_engine
        from gamescan.unpack import rpyc
        info = {"place": place(ctx.relpath), "size": ctx.size, "official": bool(self.origin(ctx)),
                "engine": renpy_engine.is_engine_path(ctx.key) if "!" not in ctx.key else
                bool(renpy_engine._ENGINE_PLACE.search(ctx.key)), "words": None, "unread": ""}
        if info["official"] or ctx.truncated or ctx.size > _MAX_TEXT:
            return info
        try:
            text = None
            if ctx.key.endswith(_SCRIPTS):
                text = ctx.text()
            elif ctx.key.endswith(_COMPILED):
                if bytes(ctx.data[:5]) != b"RENPY":              # (decision 3: the old form?)
                    self.old["%s%s" % (old_form(ctx.data), " [engine place]" if info["engine"] else "")] += 1
                result = rpyc.decompile(ctx.data, unindent=True)
                if result is None:
                    info["unread"] = unread_kind(ctx.data)
                else:
                    text = result[0]
            if text is not None:
                info["words"] = {name: len(pattern.findall(text)) for name, pattern in WORDS.items()}
        except Exception:                   # (a measurement must never break the scan)
            pass
        return info

    # -- what is printed ---------------------------------------------------------------------
    def lines(self) -> List[str]:
        from gamescan.models import Severity
        files, number = self.files, {}
        num = lambda name: number.setdefault(name, len(number) + 1)
        kinds = collections.Counter(info["place"] for info in files.values())
        out = ["files read: %d; official: %d; by place: %s" % (
            len(files), sum(info["official"] for info in files.values()),
            ", ".join("%s %d" % item for item in sorted(kinds.items(), key=lambda i: (-i[1], i[0]))[:14]))]
        active = [f for f in self.found if not f.suppressed]
        high = [f for f in active if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        where = collections.Counter(
            "%s %s in %s%s" % (f.rule_id, f.severity.name, files.get(f.file, {}).get("place", "?"),
                               " [official]" if files.get(f.file, {}).get("official") else "")
            for f in high)
        out.append("HIGH / CRITICAL findings (active): %d" % len(high))
        out += ["  %s x%d" % item for item in sorted(where.items())]
        hidden = collections.Counter("%s %s in %s%s" % (f.rule_id, f.severity.name, files.get(f.file, {}).get("place", "?"),
                                                        " [official]" if files.get(f.file, {}).get("official") else "")
                                     for f in self.found if f.suppressed and f.rule_id.startswith("CHAIN"))
        out.append("chains hidden: %s" % (", ".join("%s x%d" % item for item in sorted(hidden.items())) or "none"))
        # every file with a HIGH finding, and every script that is not official and names words
        shown = sorted({f.file for f in high} | {name for name, info in files.items() if info["words"]
                                                  and (info["words"]["run"] or info["words"]["network"]
                                                       or info["words"]["decode"])},
                       key=lambda name: (files.get(name, {}).get("place", ""), name))
        out.append("files with HIGH findings or naming network / decode / run words (not official): %d" % len(shown))
        for name in shown[:60]:
            info = files.get(name, {"place": "?", "size": 0, "official": False, "engine": False, "words": None})
            mine = collections.Counter("%s %s" % (f.rule_id, f.severity.name) for f in active if f.file == name)
            chains = sorted("%s%s" % (f.rule_id, " (hidden)" if f.suppressed else "") for f in self.found
                            if f.file == name and (f.rule_id.startswith("CHAIN") or f.rule_id in (
                                "SCRIPT-LIMIT-001", "PY-JOIN-001", "RPY-FMT-001", "PYO-FMT-001")))
            words = info["words"]
            out.append("  #%d %s, %d KB, official %s, engine place %s | words: %s | active: %s | chains / limits: %s" % (
                num(name), info["place"], (info["size"] + 1023) // 1024, "yes" if info["official"] else "no",
                "yes" if info["engine"] else "no",
                ", ".join("%s %d" % item for item in words.items()) if words else "not counted",
                ", ".join("%s x%d" % item for item in sorted(mine.items())) or "none", ", ".join(chains) or "none"))
            seen_local = self.local.get(name)
            if seen_local:
                out.append("       local reading (CHAIN-LOCAL-DROP): " + ", ".join(
                    "%s %d" % item for item in sorted(seen_local.items())))
        unread = collections.Counter("%s: %s%s" % (info["place"], info["unread"], " [engine place]" if info["engine"] else "")
                                     for info in files.values() if info["unread"])
        out.append("compiled scripts the scanner could not read: %d" % sum(unread.values()))
        out += ["  %s x%d" % item for item in sorted(unread.items())]
        commands = [f for f in active if f.rule_id == "DF-CMD-001"]
        out.append("resolved command lines (DF-CMD-001): %d" % len(commands))
        seen = collections.Counter()
        for f in commands:
            value = f.evidence.partition(" receives: ")[2] or f.evidence
            first = os.path.splitext(re.split(r"[\s\"']+", value.strip() + " ")[0].replace("\\", "/").split("/")[-1])[0].lower()
            seen["%s %s in %s: starts %s; %s" % (f.rule_id, f.severity.name, files.get(f.file, {}).get("place", "?"),
                                                 first if first in _PROGRAMS else "another program",
                                                 ", ".join("%s %s" % (k, "yes" if p.search(value) else "no")
                                                           for k, p in _COMMAND.items()))] += 1
        out += ["  %s x%d" % item for item in sorted(seen.items())]
        return out + self.lines_proof()
