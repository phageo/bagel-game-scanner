"""C3: decoded or decrypted data -> code, in JavaScript (phase C, JS group, part 3; phageo, 2026-11-02 / 11-04).

A loader keeps its payload hidden - Base64 or hex text, compressed bytes, an encrypted file - and turns it
back into code only while it runs. The older findings name the parts: a decoding primitive
(``JS-OBF-002``), dynamic code (``JS-EXEC-001``), the two near each other (``CHAIN-LOADER``, a capability
since phase B), or both in one statement (``JS-OBF-001``). This module follows the decoded data itself,
on the syntax tree (:mod:`gamescan.jsparse`), **without its value** and without running anything (rule 2):

``source``  what a decoding call gives: a decipher of ``crypto`` (``createDecipheriv`` / ``createDecipher``
            and what its ``update`` / ``final`` return, ``privateDecrypt`` / ``publicDecrypt``), WebCrypto's
            ``subtle.decrypt``, the ``decrypt`` of crypto-js / aes-js / node-forge; Base64 or hex
            (``atob``, ``Buffer.from(x, "base64" | "base64url" | "hex")``, js-base64, base64-js,
            crypto-js's ``enc.Base64.parse``); decompression (``zlib``'s inflate / gunzip / unzip /
            brotli, synchronous, with a callback or as a stream; pako; fflate; lz-string)
``flow``    C1's reader (:mod:`gamescan.dataflow.exfil`): variables, objects and arrays, texts built with
            ``+`` and templates, the file's own functions (parameters and returns), callbacks and promises,
            collectors, any unknown call (its result carries what went in). One thing is read more
            closely here: a member read ``o.k`` / ``this.k`` takes only what was written into that key
            (C1 is field-blind) - a class that decodes a picture into one field and runs a plugin's text
            from another is no flow
``sink``    code: ``eval``, ``new Function`` / ``Function``, a timer given code text, ``vm``'s
            ``runInThisContext`` / ``runInNewContext`` / ``runInContext`` / ``compileFunction`` /
            ``new vm.Script`` / ``new vm.SourceTextModule``, a module's ``_compile``, a page's
            ``executeJavaScript``; a file written from the data (``writeFile*`` / ``appendFile*`` /
            fs-extra's ``outputFile*``, a write stream it is written or piped into) that is then loaded
            by ``require`` / ``import()`` / ``process.dlopen`` or started; ``child_process`` given the data
            (command, arguments, options) or such a file

Decoding data for display, for a save or for the game's own files reaches none of these, so it never
counts. Names are bound by scope and the arms of an ``if`` / ``?:`` are kept apart (C1's reader). The
text read is the script with its string table put back (C2, :mod:`gamescan.dataflow.jsstrings`). A
decoder in one file and the code sink in another file of the same Electron app are joined through the
module graph of C1 part 2b (:mod:`gamescan.dataflow.exfil_cross`): this reader's summaries (exports,
imports used at a sink), the same relative ``require`` / ``import`` specs, at most four hops.

Tier (pre-registered, ``roadmap-1.0.md`` / ``diagnosis-evidence.md``): **CHAIN** - ``CHAIN-DECODE-RUN``
HIGH, cause class ``DECODE-AND-RUN``. Not MALICE: code protectors decrypt their own code the same way. A
flow wholly inside one verified npm / library file is MEDIUM (the scanner's rule-13 exception for every
``CHAIN-*`` finding there); one that crosses into or out of the app's code keeps HIGH. Nothing is lowered
by this module. Switches: :data:`ON` (all of C3), :data:`CROSS_ON` (its cross-file join).

Limits (rule 3; counts): the parser's own, :data:`MAX_BYTES` per script, :data:`MAX_STEPS` steps per
file, C1's bounds per value (nesting, texts, labels), :data:`MAX_FLOWS` flows per file,
:data:`MAX_WRITES` written files per file, :data:`MAX_ARG_NODES` nodes looked at in one start's
arguments. A reading that stops at a bound adds nothing and gives no note (``Result.limit``, diagnosis
only). Not read: home-made decoders that call none of the sources above (a loop of ``charCodeAt`` /
``String.fromCharCode`` / XOR), ``decodeURIComponent`` / ``unescape`` (character escapes, not
payloads), a ``Worker`` started from code text, a written file opened by ``shell.openPath``, HTML pages.
"""
from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .. import jsparse
from . import exfil, exfil_cross, jsstrings
from .exfil import ANY, MOD, Flow, OutOfSteps, Result, _FUNCTIONS, _REQUIRES, _last, _root

ON = True                       # C3: decoded / decrypted data -> code (CHAIN)
CROSS_ON = True                 # its cross-file join (the module graph of C1 part 2b)

RULE = "CHAIN-DECODE-RUN"
TITLE = "Decoded data run as code"
SUMMARY = "decoderun_summary"   # FileContext.cache: (exports, sink_imports, verified) for the cross-file join
LIMIT = "decoderun_limit"       # FileContext.cache: why the reading stopped early (diagnosis only)
KIND = "decoded_kind"           # Finding.context: what the data was (one of KINDS)

DECRYPTED, DECODED, DECOMPRESSED = "decrypted", "decoded", "decompressed"
KINDS = frozenset({DECRYPTED, DECODED, DECOMPRESSED})

MAX_BYTES = 8 * 1024 * 1024     # the largest script read (as C1)
MAX_STEPS = 3_000_000           # evaluation steps per file
MAX_FLOWS = 8                   # flows reported per file
MAX_WRITES = 64                 # files written from decoded data kept per file
MAX_ARG_NODES = 200             # nodes looked at in one start's arguments for a written file's name
MIN_KNOWN = 4                   # known characters a written file's name needs to be matched by its text

# -- a cheap look before the parse (on the text with its string table put back) ------------------------
_DECODE_HINT = re.compile(r"atob|base64|['\"`]hex['\"`]|decipher|decrypt|inflate|gunzip|unzip|brotli|"
                          r"decompress|ungzip|unzlib|toByteArray", re.I)
_CODE_HINT = re.compile(r"(?<![\w$])eval\b|(?<![\w$])Function\s*\(|runIn(?:This|New)?Context|compileFunction|"
                        r"(?<![\w$])Script\s*\(|SourceTextModule|_compile|executeJavaScript|setTimeout|setInterval|"
                        r"child_process|(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(")
_WRITE_HINT = re.compile(r"writeFile|appendFile|outputFile|createWriteStream")
_LOAD_HINT = re.compile(r"(?<![\w$])(?:require|import)\s*\(|dlopen")

# -- sources -------------------------------------------------------------------------------------------
_DECIPHER = frozenset("""crypto.createDecipheriv crypto.createDecipher crypto.privateDecrypt crypto.publicDecrypt
crypto.subtle.decrypt crypto.webcrypto.subtle.decrypt window.crypto.subtle.decrypt self.crypto.subtle.decrypt
globalThis.crypto.subtle.decrypt""".split())
_CRYPTO_LIBS = ("crypto-js", "CryptoJS", "aes-js", "aesjs", "node-forge", "forge")
_LIB_DECRYPT = frozenset({"decrypt", "createDecipher", "createDecipheriv"})
_BASE64_CALLS = frozenset("atob window.atob self.atob globalThis.atob global.atob".split())
_BASE64_LIBS = {"js-base64": frozenset({"decode", "atob", "toUint8Array", "fromBase64"}),
                "Base64": frozenset({"decode", "atob", "toUint8Array", "fromBase64"}),
                "base64-js": frozenset({"toByteArray"})}
_ENCODINGS = frozenset({"base64", "base64url", "hex"})
_INFLATE = {"zlib": frozenset("""inflateSync inflateRawSync gunzipSync unzipSync brotliDecompressSync inflate inflateRaw
gunzip unzip brotliDecompress createInflate createInflateRaw createGunzip createUnzip createBrotliDecompress""".split()),
            "pako": frozenset({"inflate", "inflateRaw", "ungzip"}),
            "fflate": frozenset("""inflateSync gunzipSync unzlibSync decompressSync inflate gunzip unzlib
decompress""".split())}
_LZ = ("LZString", "lz-string")
_WASM = frozenset({"WebAssembly"})
_GLOBAL_OBJECTS = frozenset({"window", "self", "globalThis", "global"})
_ENC_PARSE = re.compile(r"\.enc\.(?:Base64|Base64url|Hex)\.parse\Z")       # crypto-js's own decoders

# -- sinks ---------------------------------------------------------------------------------------------
_GLOBAL = ("", "window.", "self.", "globalThis.", "global.")
_EVAL = frozenset(g + "eval" for g in _GLOBAL)
_FUNCTION = frozenset(g + "Function" for g in _GLOBAL)
_TIMERS = frozenset(g + t for g in _GLOBAL for t in ("setTimeout", "setInterval"))
_VM = frozenset({"runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script",
                 "SourceTextModule"})
_CODE_METHODS = {"_compile": "module._compile", "executeJavaScript": "executeJavaScript"}
_STARTS = frozenset({"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"})
_WRITES = frozenset({"writeFileSync", "writeFile", "appendFileSync", "appendFile", "outputFileSync", "outputFile",
                     "writeFileAsync", "appendFileAsync"})
_FS_ROOTS = frozenset({"fs", "fs/promises", "fs-extra", "original-fs", "graceful-fs"})
WRITTEN = " (a file written from it)"


def candidate(text: str, cross: bool = True) -> bool:
    """A quick, deterministic look: is this script worth parsing? Per file: it names a decoding call and
    a code sink (or a file write and a load). Cross-file (:data:`CROSS_ON`, and ``cross``: the script is
    one of an Electron app's own files): also a script that only decodes (it may export what it decodes)
    or that has a code sink and a relative import."""
    decodes = bool(_DECODE_HINT.search(text))
    runs = bool(_CODE_HINT.search(text)) or (bool(_WRITE_HINT.search(text)) and bool(_LOAD_HINT.search(text)))
    if decodes and runs:
        return True
    if CROSS_ON and cross:
        if decodes:
            return True                                # it may export what it decodes
        if exfil._REL_IMPORT_HINT.search(text) and (runs or exfil._EXPORT_HINT.search(text)):
            return True                                # a sink that imports, or a module that re-exports
    return False


def analyse(text: str, trees: Optional[dict] = None, cross: bool = True) -> Optional[Result]:
    """The decoded-data -> code flows of a JavaScript text (``Result.flows``, kinds of :data:`KINDS`;
    imports used at a sink in ``Result.sink_imports``, exports in ``Result.exports``), or None when there
    is nothing to read (the switch is off, the parser is not available, the text names no decoding and
    no code). Never raises. ``trees``: :func:`exfil.parse_shared` (C1 and C3 parse a script once);
    ``cross``: the script is one of an Electron app's files (only there the cross-file join is made)."""
    if not ON or not jsparse.available() or not candidate(text, cross):
        return None
    out = Result()
    if len(text) > MAX_BYTES:
        out.limit = "the script is larger than %d MB" % (MAX_BYTES >> 20)
        return out
    data = text.encode("utf-8", "surrogatepass")
    parsed = exfil.parse_shared(data, trees)
    if not parsed.ok:
        out.limit = parsed.limit
        return out
    reader = _Reader(data, parsed.tree, cross)
    try:
        reader.read()
        reader.run(out)
    except OutOfSteps:
        out.limit = "the reading stopped at its limit of %d steps" % MAX_STEPS
    except (RecursionError, ValueError, IndexError, KeyError, AttributeError, TypeError) as exc:
        out.limit = "the reading stopped (%s)" % type(exc).__name__
    return out


def _known(text: str) -> int:
    return len(text.replace(ANY, ""))


class _Reader(exfil._Reader):
    """C1's reader with C3's sources and sinks, keyed member reads, and the files written from decoded
    data (by the binding of their name and by its texts)."""

    def __init__(self, data: bytes, tree, cross: bool = True):
        super().__init__(data, tree)
        self.collect_imports = bool(CROSS_ON and cross)
        self.written: Dict[int, Set[Tuple[str, int]]] = {}          # binding id -> labels of what was written
        self.written_texts: Dict[str, Set[Tuple[str, int]]] = {}    # a file name's text -> the same
        self.write_count = 0

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise OutOfSteps()

    @staticmethod
    def _exported(label: str) -> bool:
        return label in KINDS or label.startswith(MOD)

    # ---- sources ----
    def source(self, call, depth: int) -> FrozenSet[Tuple[str, int]]:
        """The label a decoding call itself brings in (one of :data:`KINDS`), or nothing."""
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is None:
            return frozenset()
        names = self.api(callee, depth)
        method = ""
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            method = self.text(prop) if prop is not None else ""
        kind = self._decoding(call, callee, names, method, depth)
        return frozenset({(kind, self.line(call))}) if kind else frozenset()

    def _decoding(self, call, callee, names, method: str, depth: int) -> str:
        if names & _DECIPHER:
            return DECRYPTED
        for n in names:
            root, last = _root(n), _last(n)
            if last in _LIB_DECRYPT and (root in _CRYPTO_LIBS or root.startswith("crypto-js")):
                return DECRYPTED
            if root in _INFLATE and last in _INFLATE[root]:
                return DECOMPRESSED
            if root in _LZ and last.startswith("decompress"):
                return DECOMPRESSED
            if root in _BASE64_LIBS and last in _BASE64_LIBS[root]:
                return DECODED
            if (root == "CryptoJS" or root.startswith("crypto-js")) and _ENC_PARSE.search(n):
                return DECODED
        if names & _BASE64_CALLS or (callee.type == "identifier" and not names and self.text(callee) == "atob"):
            return DECODED
        if any(n in ("Buffer", "buffer.Buffer", "Buffer.from") or n.endswith(".Buffer.from") for n in names):
            args = call.child_by_field_name("arguments")
            items = list(args.named_children) if args is not None and args.type == "arguments" else []
            if len(items) >= 2:
                encodings = self.strings(items[1], depth)
                if encodings and all(e.lower() in _ENCODINGS for e in encodings):
                    return DECODED
        return ""

    # ---- member reads: only what was written into that key ----
    @staticmethod
    def _key_of(node, text) -> Optional[str]:
        """The key of ``o.k`` / ``o['k']`` (None: computed)."""
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            return text(prop) if prop is not None else None
        if node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            if index is not None and index.type == "string":
                return jsstrings.js_string(text(index))
        return None

    def _def_key(self, d) -> Optional[str]:
        """The first-level key a ``member`` def writes (``o.k = v``, ``this.k.l = v``, ``this.k.push(v)``);
        None: the whole object (``o.push(v)``, ``Object.assign(o, v)``, ``o[x] = v``)."""
        at = d.at
        if at.type in ("assignment_expression", "augmented_assignment_expression"):
            left = at.child_by_field_name("left")
        elif at.type == "call_expression":
            callee = at.child_by_field_name("function")
            if callee is None or callee.type != "member_expression":
                return None
            left = callee.child_by_field_name("object")
        else:
            return None
        n = left
        steps = 0
        while n is not None and n.type in ("member_expression", "subscript_expression") and steps < 64:
            steps += 1
            obj = n.child_by_field_name("object")
            if obj is not None and obj.type in ("this", "identifier"):
                return self._key_of(n, self.text)
            n = obj
        return None

    def _keyed(self, node, depth: int) -> Optional[FrozenSet]:
        """``o.k`` / ``this.k`` with a written key: the taint of what was written into ``k`` (and of
        whole-object writes); None when the read is not of that form (C1's field-blind reading then)."""
        key = self._key_of(node, self.text)
        obj = node.child_by_field_name("object")
        if key is None or obj is None:
            return None
        if obj.type == "this":
            b = self._this(obj)
        elif obj.type == "identifier":
            b = self.lookup(obj)
            if b is None:
                return None
        else:
            return None
        out: Set = set()
        for d in b.defs:
            self.tick()
            if d.kind in ("function", "import", "catch", "class") or self.apart(d.at, node):
                continue
            if d.kind == "member":
                k = self._def_key(d)
                if (k is None or k == key) and d.value is not None:
                    out |= self.taint(d.value, depth)
            elif d.kind in ("var", "assign") and d.value is not None:
                v = d.value
                while v.type == "parenthesized_expression" and v.named_child_count:
                    v = v.named_children[0]
                if v.type == "object":
                    for pair in v.named_children:
                        self.tick()
                        if pair.type == "pair":
                            k = pair.child_by_field_name("key")
                            val = pair.child_by_field_name("value")
                            if k is not None and val is not None and (
                                    k.type == "computed_property_name" or self._key(k) == key):
                                out |= self.taint(val, depth)
                        elif pair.type == "shorthand_property_identifier" and self.text(pair) == key:
                            out |= self.taint(pair, depth)
                        elif pair.type == "spread_element":
                            out |= self.taint(pair, depth)
                else:
                    out |= self.taint(v, depth)
            elif d.kind in ("part", "each") and d.value is not None:
                out |= self.taint(d.value, depth)
            elif d.kind == "param":
                out |= self._param_taint(d, depth)
        return frozenset(out)

    def _call_taint(self, call, depth: int) -> FrozenSet:
        # a WebAssembly compile / instantiate ends the flow: decoded bytes become a compiled module, which is not
        # one of C3's sinks, and what its exports return is the program's output, not the decoded data (an
        # emscripten build decodes its own wasm from Base64 - found on a clean game's bundled library, 2026-11-08)
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is not None and any(_root(n) in _WASM or n.split(".", 1)[0] in _GLOBAL_OBJECTS
                                      and _root(n.split(".", 1)[-1]) in _WASM for n in self.api(callee, depth)):
            return frozenset()
        return super()._call_taint(call, depth)

    def _function_value(self, node) -> bool:
        """Is ``node`` a function rather than text - a function written there, ``f.bind(...)``, or a name bound
        only to functions? A function handed to a timer / ``eval`` / ``child_process`` is not code text."""
        while node.type == "parenthesized_expression" and node.named_child_count:
            node = node.named_children[0]
        if node.type in _FUNCTIONS:
            return True
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None and callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                return prop is not None and self.text(prop) == "bind"
            return False
        if node.type == "identifier":
            b = self.lookup(node)
            if b is None or not b.defs:
                return False
            return all(d.kind == "function" or (d.kind in ("var", "assign") and d.value is not None
                                                and d.value.type != "identifier" and self._function_value(d.value))
                       for d in b.defs)
        return False

    def _taint(self, node, depth: int) -> FrozenSet:
        if node.type in ("member_expression", "subscript_expression"):
            self.tick()
            ref = self.import_ref(node)
            if ref is not None:                    # one export of a relative module (as C1)
                return frozenset({(MOD + "%s::%s" % ref, self.line(node))})
            got = self._keyed(node, depth)
            if got is not None:
                return got
        return super()._taint(node, depth)

    # ---- files written from decoded data ----
    def _labels(self, node) -> Set[Tuple[str, int]]:
        return {lbl for lbl in self.taint(node) if lbl[0] in KINDS or lbl[0].startswith(MOD)}

    def _stream_path(self, node, depth: int = 0):
        """The file name a write stream was opened on (``fs.createWriteStream(p)``, through names)."""
        while node is not None and node.type in ("parenthesized_expression", "await_expression") \
                and node.named_child_count:
            node = node.named_children[-1]
        if node is None or depth > 4:
            return None
        self.tick()
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is None:
                return None
            opens = any(_last(n) == "createWriteStream" for n in self.api(callee))
            if not opens and callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                opens = prop is not None and self.text(prop) == "createWriteStream"
            if opens:
                args = node.child_by_field_name("arguments")
                return args.named_children[0] if args is not None and args.named_child_count else None
            return None
        if node.type == "identifier":
            b = self.lookup(node)
            for d in (b.defs if b is not None else ()):
                if d.kind in ("var", "assign") and d.value is not None:
                    got = self._stream_path(d.value, depth + 1)
                    if got is not None:
                        return got
        return None

    def _record(self, path, labels: Set[Tuple[str, int]]) -> None:
        if not labels or path is None or self.write_count >= MAX_WRITES:
            return
        self.write_count += 1
        if path.type == "identifier":
            b = self.lookup(path)
            if b is not None:
                self.written.setdefault(id(b), set()).update(labels)
        for t in self.strings(path):
            if _known(t) >= MIN_KNOWN:
                self.written_texts.setdefault(t, set()).update(labels)

    def writes(self) -> None:
        """Note every file written from decoded data: its name's binding and texts."""
        for call in self.calls:
            self.tick()
            if call.type != "call_expression":
                continue
            callee = call.child_by_field_name("function")
            args = call.child_by_field_name("arguments")
            if callee is None or args is None or args.type != "arguments":
                continue
            items = list(args.named_children)
            names = self.api(callee)
            method = ""
            obj = None
            if callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                method = self.text(prop) if prop is not None else ""
                obj = callee.child_by_field_name("object")
            lasts = {_last(n) for n in names} | ({method} if method else set())
            if lasts & _WRITES and len(items) >= 2 and (not names or any(_root(n) in _FS_ROOTS for n in names)):
                self._record(items[0], self._labels(items[1]))
            elif method in ("write", "end") and items and obj is not None:
                path = self._stream_path(obj)
                if path is not None:
                    self._record(path, self._labels(items[0]))
            elif method == "pipe" and items and obj is not None:
                path = self._stream_path(items[0])
                if path is not None:
                    self._record(path, self._labels(obj))

    def written_labels(self, node) -> Set[Tuple[str, int]]:
        """What a file name at a load / start stands for, when it is a file written from decoded data:
        a name bound to such a file anywhere in the argument, or a text that holds such a file's name."""
        if not (self.written or self.written_texts):
            return set()
        out: Set[Tuple[str, int]] = set()
        texts = self.strings(node)
        for t in texts:
            for w, labels in self.written_texts.items():
                self.tick()
                if w == t or (w in t):
                    out |= labels
        stack, seen = [node], 0
        while stack and seen < MAX_ARG_NODES:
            n = stack.pop()
            seen += 1
            self.tick()
            if n.type == "identifier":
                b = self.lookup(n)
                if b is not None:
                    out |= self.written.get(id(b), set())
            elif n.type in _FUNCTIONS:
                continue
            stack.extend(n.named_children)
        return out

    # ---- sinks ----
    def _cached_data(self, options) -> List[object]:
        """The ``cachedData`` values of ``vm`` options written as object literals (directly or through a name)."""
        out: List[object] = []
        for o in options:
            for lit in self.objects(o):
                if lit.type != "object":
                    continue
                for pair in lit.named_children:
                    self.tick()
                    if pair.type == "pair":
                        k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                        if k is not None and v is not None and self._key(k) == "cachedData":
                            out.append(v)
                    elif pair.type == "shorthand_property_identifier" and self.text(pair) == "cachedData":
                        out.append(pair)
        return out

    def code_sink(self, call) -> Tuple[str, List[object], List[object]]:
        """(the sink's name in the scanner's own words, the values run as code, the values that name a
        file loaded or started) - or ("", [], []) when the call is no code sink."""
        new = call.type == "new_expression"
        callee = call.child_by_field_name("constructor" if new else "function")
        if callee is None:
            return "", [], []
        args = call.child_by_field_name("arguments")
        raw = list(args.named_children) if args is not None and args.type == "arguments" else []
        items = [a for a in raw if not self._function_value(a)]
        # (by position: a timer's delay or a callback's neighbour is never the code; a function is no code text)
        first = raw[:1] if raw and not self._function_value(raw[0]) else []
        names = self.api(callee)
        method = ""
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            method = self.text(prop) if prop is not None else ""
        if not new and (names & _EVAL or (callee.type == "identifier" and not names and self.text(callee) == "eval")):
            return "eval", first, []
        if names & _FUNCTION:
            return "new Function" if new else "Function", items, []
        if not new and names & _TIMERS:
            return "a timer given code text", first, []
        for n in sorted(names):
            if _root(n) == "vm" and _last(n) in _VM:
                # (the options' cachedData is compiled code V8 runs as it is: a code argument too)
                return ("new vm." if new else "vm.") + _last(n), first + self._cached_data(raw[1:]), []
        if not new and method in _CODE_METHODS:
            return _CODE_METHODS[method], first, []
        if not new:
            for n in sorted(names):
                if _root(n) == "child_process" and _last(n) in _STARTS:
                    return "child_process." + _last(n), items, items
            if names & _REQUIRES:
                return "require", [], first
            if callee.type == "import":
                return "import()", [], first
            if names & {"process.dlopen", "global.process.dlopen"}:
                return "process.dlopen", [], raw[1:2]
        return "", [], []

    def run(self, out: Result) -> None:
        self.writes()
        sinks = []
        for call in self.calls:
            self.tick()
            name, sent, paths = self.code_sink(call)
            if name:
                sinks.append((call, name, sent, paths))
        out.sinks = len(sinks)
        if self.collect_imports:
            out.exports = self.exports()          # a decoder-only module still exports what it decodes
        if not sinks:
            return
        found: Dict[Tuple, Flow] = {}
        last = None
        for _ in range(exfil.ROUNDS):
            self.prev, self.memo = self.memo, {}
            now: Dict[Tuple, Flow] = {}
            for call, name, sent, paths in sinks:
                labels = {lbl for lbl in self._union(sent, 0) if lbl[0] in KINDS or lbl[0].startswith(MOD)}
                via = set()
                for p in paths:
                    via |= self.written_labels(p)
                for kind, source_line in sorted(labels):
                    key = (kind, self.line(call))
                    if key not in now:
                        now[key] = Flow(kind, source_line, name, self.line(call))
                for kind, source_line in sorted(via - labels):
                    key = (kind, self.line(call))
                    if key not in now:
                        now[key] = Flow(kind, source_line, name + WRITTEN, self.line(call))
            if now == last:
                break
            last = now
            found = now
        seen_imports: Set[Tuple[str, str, int]] = set()
        for flow in sorted(found.values(), key=lambda f: (f.line, f.kind)):
            if flow.kind.startswith(MOD):                   # a value imported from a relative module (cross-file)
                spec, _, name = flow.kind[len(MOD):].partition("::")
                key = (spec, name, flow.line)
                if spec and key not in seen_imports and len(out.sink_imports) < exfil.MAX_IMPORT_SINKS:
                    seen_imports.add(key)
                    out.sink_imports.append((spec, name, flow.line, flow.sink))
            elif flow.kind in KINDS and len(out.flows) < MAX_FLOWS:
                if any(f.line == flow.line for f in out.flows):
                    continue                                # one finding per sink
                out.flows.append(flow)


def join(summaries: List[exfil_cross.Summary]) -> List[exfil_cross.CrossFlow]:
    """The cross-file decoded-data -> code flows of one app (C1 part 2b's module graph, C3's kinds)."""
    if not (ON and CROSS_ON):
        return []
    return exfil_cross.join_kinds(summaries, KINDS)


_KIND_WORDS = {DECRYPTED: "Data decrypted", DECODED: "Base64- or hex-decoded data",
               DECOMPRESSED: "Decompressed data"}
_SINKS_SAID = re.compile(r"[\w$.() ]{1,80}")


def _sink_words(sink: str) -> str:
    return sink if _SINKS_SAID.fullmatch(sink) else "code"


def evidence(flow: Flow) -> str:
    """One line for a flow, by the scanner's own words (the kind of data, the sink of its own lists)."""
    return "%s, made on line %d, reaches %s on line %d" % (
        _KIND_WORDS.get(flow.kind, "Decoded data"), flow.source_line, _sink_words(flow.sink), flow.line)


def cross_evidence(flow: exfil_cross.CrossFlow) -> str:
    where = flow.source_file.replace("\\", "/").split("!")[-1].rsplit("/", 1)[-1] or "another script"
    return ("%s, made in %s, reaches %s on line %d of this script (%d file hop(s))"
            % (_KIND_WORDS.get(flow.kind, "Decoded data"), where, _sink_words(flow.sink), flow.sink_line,
               flow.hops))


REASON = ("Data that this script decodes, decompresses or decrypts while it runs was followed through its "
          "code into a place where it runs as code - eval, new Function, the vm module, a file it writes "
          "and then loads, or a program it starts. What that code does cannot be seen in the files. "
          "Hidden payloads are run this way; code protectors decrypt their own code the same way, so this "
          "is a chain, not proof of malice.")
