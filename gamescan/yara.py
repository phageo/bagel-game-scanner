"""A dependency-free YARA engine covering the commonly used subset.

Supported
  strings    text ("..." with nocase / wide / ascii / fullword, and the
             obfuscation modifiers xor, xor(min-max), base64, base64wide,
             base64("custom alphabet")), hex ({ 4D 5A ?? [2-4] ( 01 | 02 ) })
             and regular expressions (/.../is)
  condition  and / or / not, parentheses, $a, #a, "$a at N", "$a in (A..B)",
             "any|all|none|N of them", "N of ($a*, $b)", filesize, uintN(off),
             uintNbe(off), integer arithmetic and comparisons, KB / MB
  meta       description, severity (LOW..CRITICAL) or score (0-100), category,
             confidence

Not supported: modules (pe., math., ...), "for" loops, rule references,
includes. A rule using any of these is skipped and listed in
:attr:`YaraRuleSet.skipped` - it never silently "passes".

``xor`` finds a text string under every single-byte XOR key (0x00 - 0xFF, or
the given range). It is done in one pass, not 256: XOR-ing each byte with its
neighbour cancels the key, so the same "difference" string is searched in the
difference of the data, and the key is read off - and range-checked - at
each hit. ``base64`` / ``base64wide`` find the string inside base64 text: the
three encodings it can have, depending on where it starts in the encoded
data, are searched without the characters that depend on its neighbours.
"""
from __future__ import annotations

import base64
import itertools
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

_MAX_HITS = 1000
_COMMENTS = re.compile(r'''("(?:\\.|[^"\\\n])*"|/(?![/*])(?:\\.|[^/\\\n])+/|//[^\n]*|/\*[\s\S]*?\*/)''')
_HEADER = re.compile(r"\b((?:(?:private|global)\s+)*)rule\s+(\w+)\s*(?::\s*[\w \t]+?)?\s*\{")
_SECTION = re.compile(r"\s*(meta|strings|condition)\s*:")
_META = re.compile(r'\s*(\w+)\s*=\s*("(?:\\.|[^"\\])*"|-?\d+|true|false)')
_STRING = re.compile(
    r'\s*\$(\w*)\s*=\s*(?:"((?:\\.|[^"\\\n])*)"|\{([^}]*)\}|/((?:\\.|[^/\\\n])+)/([is]*))'
    r"((?:\s+(?:nocase|wide|ascii|fullword|private|xor|base64wide|base64)\b(?:\([^)]*\))?)*)")
_TOKEN = re.compile(
    r"\s*(?:(0x[0-9a-fA-F]+|\d+)(KB|MB)?|(\$\w*\*?)|(#\w*)|([A-Za-z_][\w.]*)"
    r"|(==|!=|<=|>=|\.\.|[<>()+\-*\\%,]))")
_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", '"': b'"'}
_UINT = {"uint8": "<B", "uint16": "<H", "uint32": "<I", "int8": "<b", "int16": "<h",
         "int32": "<i", "uint16be": ">H", "uint32be": ">I", "int16be": ">h", "int32be": ">i",
         "uint8be": ">B", "int8be": ">b"}


class YaraError(ValueError):
    pass


@dataclass
class YaraMatch:
    rule: "YaraRule"
    strings: List[Tuple[str, int]]            # (identifier, first offset)


@dataclass
class YaraRule:
    name: str
    meta: Dict[str, object]
    patterns: Dict[str, "re.Pattern[bytes]"]
    condition: Callable[["_Scan"], object]
    private: bool = False
    source: str = ""


class _Scan:
    """One rule evaluated against one buffer; string searches are lazy."""

    def __init__(self, rule: YaraRule, data: bytes) -> None:
        self.rule, self.data = rule, data
        self._hits: Dict[str, List[int]] = {}

    def hits(self, ident: str) -> List[int]:
        if ident not in self._hits:
            rx = self.rule.patterns[ident]
            self._hits[ident] = [m.start() for m in
                                 itertools.islice(rx.finditer(self.data), _MAX_HITS)]
        return self._hits[ident]


# -- string compilation ---------------------------------------------------------
def _unescape(text: str) -> bytes:
    out, i = bytearray(), 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "x" and i + 3 < len(text):
                out.append(int(text[i + 2:i + 4], 16))
                i += 4
                continue
            out += _ESCAPES.get(nxt, nxt.encode("latin-1", "replace"))
            i += 2
            continue
        out += ch.encode("utf-8")
        i += 1
    return bytes(out)


def _text_pattern(raw: bytes, mods: set) -> "re.Pattern[bytes]":
    variants = []
    if "ascii" in mods or "wide" not in mods:
        body = re.escape(raw)
        if "fullword" in mods:
            body = rb"(?<![A-Za-z0-9_])" + body + rb"(?![A-Za-z0-9_])"
        variants.append(body)
    if "wide" in mods:
        body = re.escape(b"".join(bytes((b, 0)) for b in raw))
        if "fullword" in mods:
            body = rb"(?<![A-Za-z0-9_]\x00)" + body + rb"(?![A-Za-z0-9_]\x00)"
        variants.append(body)
    return re.compile(b"|".join(variants), re.DOTALL | (re.IGNORECASE if "nocase" in mods else 0))


def _hex_pattern(body: str) -> "re.Pattern[bytes]":
    out, pos = [], 0
    body = re.sub(r"\s+", " ", body.strip())
    token = re.compile(r" ?(?:([0-9a-fA-F?]{2})|\[ ?(\d*) ?(-)? ?(\d*) ?\]|([(|)]))")
    while pos < len(body):
        m = token.match(body, pos)
        if not m:
            raise YaraError("bad hex string near %r" % body[pos:pos + 12])
        pos = m.end()
        byte, low, dash, high, punct = m.groups()
        if byte:
            hi, lo = byte[0], byte[1]
            if hi == "?" and lo == "?":
                out.append(b".")
            elif lo == "?":
                base = int(hi, 16) << 4
                out.append(b"[" + re.escape(bytes([base])) + b"-" + re.escape(bytes([base | 15])) + b"]")
            elif hi == "?":
                out.append(b"[" + b"".join(re.escape(bytes([h << 4 | int(lo, 16)]))
                                           for h in range(16)) + b"]")
            else:
                out.append(re.escape(bytes([int(byte, 16)])))
        elif punct:
            out.append({"(": b"(?:", "|": b"|", ")": b")"}[punct])
        elif dash:
            out.append(b".{%s,%s}" % (low.encode() or b"0", high.encode()))
        else:
            out.append(b".{%s}" % low.encode())
    return re.compile(b"".join(out), re.DOTALL)


# -- xor / base64 modifiers --------------------------------------------------------------
_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_delta_cache: List[object] = [None, b""]          # the last buffer and its neighbour-XOR


def _delta(data: bytes) -> bytes:
    """``data[i] ^ data[i + 1]`` for every i (one big-integer XOR)."""
    if _delta_cache[0] is not data:
        if len(data) < 2:
            _delta_cache[:] = [data, b""]
        else:
            n = len(data) - 1
            value = int.from_bytes(data[:-1], "little") ^ int.from_bytes(data[1:], "little")
            _delta_cache[:] = [data, value.to_bytes(n, "little")]
    return _delta_cache[1]


class _Hit:
    __slots__ = ("_start",)

    def __init__(self, start: int) -> None:
        self._start = start

    def start(self) -> int:
        return self._start


class _XorPattern:
    """A text string under a single-byte XOR key (``finditer`` like a regex)."""

    def __init__(self, variants: List[bytes], low: int, high: int, fullword: bool) -> None:
        self.variants, self.low, self.high, self.fullword = variants, low, high, fullword

    def finditer(self, data: bytes):
        for raw in self.variants:
            if len(raw) < 2:                       # no neighbour to cancel the key with
                for key in range(self.low, self.high + 1):
                    pos = data.find(bytes([raw[0] ^ key]))
                    while pos >= 0:
                        yield _Hit(pos)
                        pos = data.find(bytes([raw[0] ^ key]), pos + 1)
                continue
            needle = bytes(a ^ b for a, b in zip(raw, raw[1:]))
            delta = _delta(data)
            pos = delta.find(needle)
            while pos >= 0:
                key = data[pos] ^ raw[0]
                if self.low <= key <= self.high and self._whole(data, pos, len(raw), key):
                    yield _Hit(pos)
                pos = delta.find(needle, pos + 1)

    def _whole(self, data: bytes, pos: int, length: int, key: int) -> bool:
        if not self.fullword:
            return True
        for at in (pos - 1, pos + length):
            if 0 <= at < len(data) and (chr(data[at] ^ key).isalnum() or data[at] ^ key == 0x5F):
                return False
        return True


def _wide(raw: bytes) -> bytes:
    return b"".join(bytes((b, 0)) for b in raw)


def _base64_variants(raw: bytes, alphabet: bytes) -> List[bytes]:
    """The stable part of ``raw``'s base64 text for each of the three
    positions it can start at inside the encoded data."""
    out = []
    table = bytes.maketrans(_B64, alphabet)
    for shift in range(3):
        text = base64.b64encode(b"\0" * shift + raw).rstrip(b"=")
        text = text[(0, 2, 3)[shift]:]             # characters that mix in what comes before
        rest = (shift + len(raw)) % 3
        if rest:                                   # the last character mixes in what follows
            text = text[:-1]
        if text:
            out.append(text.translate(table))
    return out


def _modifiers(text: str) -> Dict[str, str]:
    """``{modifier: argument}`` from the text after a string definition."""
    return {m.group(1): (m.group(2) or "") for m in
            re.finditer(r"(nocase|wide|ascii|fullword|private|xor|base64wide|base64)\b"
                        r"(?:\(([^)]*)\))?", text or "")}


def _obfuscated_pattern(raw: bytes, mods: Dict[str, str]):
    """Matcher for a text string with ``xor`` or ``base64`` / ``base64wide``."""
    if "nocase" in mods:
        raise YaraError("nocase cannot be combined with xor / base64")
    forms = []
    if "ascii" in mods or "wide" not in mods:
        forms.append(raw)
    if "wide" in mods:
        forms.append(_wide(raw))
    if "xor" in mods:
        if "base64" in mods or "base64wide" in mods:
            raise YaraError("xor cannot be combined with base64")
        low, high = 0, 255
        if mods["xor"].strip():
            try:
                parts = [int(p.strip(), 0) for p in mods["xor"].split("-")]
            except ValueError:
                raise YaraError("bad xor range: %s" % mods["xor"])
            low, high = (parts[0], parts[-1]) if len(parts) in (1, 2) else (256, 0)
            if not 0 <= low <= high <= 255:
                raise YaraError("bad xor range: %s" % mods["xor"])
        if not raw:
            raise YaraError("empty string")
        return _XorPattern(forms, low, high, "fullword" in mods)
    if "fullword" in mods:
        raise YaraError("fullword cannot be combined with base64")
    if len(raw) < 3:
        raise YaraError("a base64 string needs at least 3 characters")
    variants = []
    for name in ("base64", "base64wide"):
        if name not in mods:
            continue
        alphabet = _B64
        if mods[name].strip():
            alphabet = _unescape(mods[name].strip().strip('"'))
            if len(alphabet) != 64 or len(set(alphabet)) != 64:
                raise YaraError("a base64 alphabet needs 64 different characters")
        for form in forms:
            for text in _base64_variants(form, alphabet):
                variants.append(re.escape(_wide(text) if name == "base64wide" else text))
    return re.compile(b"|".join(dict.fromkeys(variants)), re.DOTALL)


# -- condition parser (recursive descent, compiled to closures) -----------------
class _Parser:
    def __init__(self, text: str, idents: List[str]) -> None:
        self.idents, self.tokens, pos = idents, [], 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if not m:
                raise YaraError("unsupported syntax near %r" % text[pos:pos + 16])
            pos = m.end()
            num, unit, ref, cnt, word, op = m.groups()
            if num:
                value = int(num, 0) * {"KB": 1024, "MB": 1 << 20, None: 1}[unit]
                self.tokens.append(("num", value))
            elif ref:
                self.tokens.append(("ref", ref[1:]))
            elif cnt:
                self.tokens.append(("cnt", cnt[1:]))
            elif word:
                self.tokens.append(("word", word))
            else:
                self.tokens.append(("op", op))
        self.i = 0

    def peek(self, kind=None, value=None) -> bool:
        if self.i >= len(self.tokens):
            return False
        k, v = self.tokens[self.i]
        return (kind is None or k == kind) and (value is None or v == value)

    def take(self, kind=None, value=None):
        if not self.peek(kind, value):
            got = self.tokens[self.i][1] if self.i < len(self.tokens) else "end of condition"
            raise YaraError("unexpected %r" % (got,))
        self.i += 1
        return self.tokens[self.i - 1][1]

    def parse(self):
        fn = self.p_or()
        if self.i != len(self.tokens):
            raise YaraError("unexpected %r" % (self.tokens[self.i][1],))
        return fn

    def p_or(self):
        left = self.p_and()
        while self.peek("word", "or"):
            self.take()
            a, b = left, self.p_and()
            left = lambda s, a=a, b=b: bool(a(s)) or bool(b(s))
        return left

    def p_and(self):
        left = self.p_not()
        while self.peek("word", "and"):
            self.take()
            a, b = left, self.p_not()
            left = lambda s, a=a, b=b: bool(a(s)) and bool(b(s))
        return left

    def p_not(self):
        if self.peek("word", "not"):
            self.take()
            a = self.p_not()
            return lambda s, a=a: not a(s)
        return self.p_cmp()

    def p_cmp(self):
        left = self.p_sum()
        ops = {"==": lambda x, y: x == y, "!=": lambda x, y: x != y, "<": lambda x, y: x < y,
               ">": lambda x, y: x > y, "<=": lambda x, y: x <= y, ">=": lambda x, y: x >= y}
        if self.peek("op") and self.tokens[self.i][1] in ops:
            fn = ops[self.take()]
            a, b = left, self.p_sum()
            return lambda s, a=a, b=b, fn=fn: fn(a(s), b(s))
        return left

    def p_sum(self):
        left = self.p_mul()
        while self.peek("op", "+") or self.peek("op", "-"):
            sign = 1 if self.take() == "+" else -1
            a, b = left, self.p_mul()
            left = lambda s, a=a, b=b, sign=sign: a(s) + sign * b(s)
        return left

    def p_mul(self):
        left = self.p_atom()
        while self.peek("op", "*") or self.peek("op", "\\") or self.peek("op", "%"):
            op = self.take()
            a, b = left, self.p_atom()
            if op == "*":
                left = lambda s, a=a, b=b: a(s) * b(s)
            elif op == "\\":
                left = lambda s, a=a, b=b: a(s) // (b(s) or 1)
            else:
                left = lambda s, a=a, b=b: a(s) % (b(s) or 1)
        return left

    def _known(self, ident: str) -> str:
        if ident not in self.idents:
            raise YaraError("undefined string $%s" % ident)
        return ident

    def _set(self) -> List[str]:
        if self.peek("word", "them"):
            self.take()
            return list(self.idents)
        self.take("op", "(")
        chosen: List[str] = []
        while True:
            ref = self.take("ref")
            if ref.endswith("*"):
                chosen += [i for i in self.idents if i.startswith(ref[:-1])]
            else:
                chosen.append(self._known(ref))
            if self.peek("op", ","):
                self.take()
                continue
            break
        self.take("op", ")")
        if not chosen:
            raise YaraError("empty string set")
        return chosen

    def _of(self, quantity):
        self.take("word", "of")
        chosen = self._set()

        def run(s, chosen=chosen, quantity=quantity):
            found = sum(1 for i in chosen if s.hits(i))
            need = quantity(s) if callable(quantity) else {"any": 1, "all": len(chosen), "none": 0}[quantity]
            return found == 0 if quantity == "none" else found >= need
        return run

    def p_atom(self):
        if self.peek("op", "("):
            self.take()
            inner = self.p_or()
            self.take("op", ")")
            return inner
        if self.peek("num"):
            value = self.take()
            if self.peek("word", "of"):
                return self._of(lambda s, value=value: value)
            return lambda s, value=value: value
        if self.peek("cnt"):
            ident = self._known(self.take())
            return lambda s, ident=ident: len(s.hits(ident))
        if self.peek("ref"):
            ident = self._known(self.take())
            if self.peek("word", "at"):
                self.take()
                at = self.p_sum()
                return lambda s, ident=ident, at=at: at(s) in s.hits(ident)
            if self.peek("word", "in"):
                self.take()
                self.take("op", "(")
                low = self.p_sum()
                self.take("op", "..")
                high = self.p_sum()
                self.take("op", ")")
                return lambda s, ident=ident, low=low, high=high: any(
                    low(s) <= h <= high(s) for h in s.hits(ident))
            return lambda s, ident=ident: bool(s.hits(ident))
        word = self.take("word")
        if word in ("true", "false"):
            return lambda s, v=(word == "true"): v
        if word == "filesize":
            return lambda s: len(s.data)
        if word in ("any", "all", "none"):
            return self._of(word)
        if word in _UINT:
            self.take("op", "(")
            off = self.p_sum()
            self.take("op", ")")
            fmt = _UINT[word]

            def read(s, off=off, fmt=fmt):
                try:
                    return struct.unpack_from(fmt, s.data, off(s))[0]
                except struct.error:
                    return -1                 # YARA "undefined": never equals anything
            return read
        raise YaraError("unsupported keyword %r" % word)


# -- rule files -----------------------------------------------------------------
def _strip_comments(text: str) -> str:
    return _COMMENTS.sub(lambda m: m.group(0) if m.group(0)[0] in '"/' and
                         not m.group(0).startswith(("//", "/*")) else " ", text)


def parse_rules(text: str, source: str = "") -> Tuple[List[YaraRule], List[Tuple[str, str]]]:
    """``(rules, skipped)`` where skipped is ``[(rule name, reason)]``."""
    text = _strip_comments(text)
    rules: List[YaraRule] = []
    skipped: List[Tuple[str, str]] = []
    pos = 0
    while True:
        head = _HEADER.search(text, pos)
        if not head:
            break
        name, pos = head.group(2), head.end()
        try:
            meta: Dict[str, object] = {}
            defs: List[Tuple[str, "re.Pattern[bytes]"]] = []
            cond_text = None
            while cond_text is None:
                sec = _SECTION.match(text, pos)
                if not sec:
                    raise YaraError("expected meta/strings/condition")
                pos = sec.end()
                if sec.group(1) == "meta":
                    while True:
                        m = _META.match(text, pos)
                        if not m:
                            break
                        value = m.group(2)
                        meta[m.group(1)] = (value[1:-1] if value[0] == '"' else
                                            value == "true" if value in ("true", "false") else int(value))
                        pos = m.end()
                elif sec.group(1) == "strings":
                    while True:
                        m = _STRING.match(text, pos)
                        if not m:
                            break
                        pos = m.end()
                        ident, txt, hexa, rgx, rflags, mods = m.groups()
                        arguments = _modifiers(mods)
                        mods = set(arguments)
                        obfuscated = mods & {"xor", "base64", "base64wide"}
                        if obfuscated and txt is None:
                            raise YaraError("%s only applies to text strings"
                                            % ", ".join(sorted(obfuscated)))
                        if obfuscated:
                            rx = _obfuscated_pattern(_unescape(txt), arguments)
                        elif txt is not None:
                            rx = _text_pattern(_unescape(txt), mods)
                        elif hexa is not None:
                            rx = _hex_pattern(hexa)
                        else:
                            flags = re.DOTALL if "s" in rflags else 0
                            if "i" in rflags or "nocase" in mods:
                                flags |= re.IGNORECASE
                            try:
                                rx = re.compile(rgx.replace("\\/", "/").encode("latin-1"), flags)
                            except (re.error, UnicodeEncodeError) as exc:
                                raise YaraError("regex not supported: %s" % exc)
                        defs.append((ident or "anon%d" % len(defs), rx))
                else:
                    end = text.find("}", pos)
                    if end == -1:
                        raise YaraError("missing closing brace")
                    cond_text, pos = text[pos:end], end + 1
            patterns = dict(defs)
            condition = _Parser(cond_text, list(patterns)).parse()
            rules.append(YaraRule(name, meta, patterns, condition,
                                  "private" in head.group(1), source))
        except YaraError as exc:
            skipped.append((name, str(exc)))
            nxt = _HEADER.search(text, pos)
            pos = nxt.start() if nxt else len(text)
    return rules, skipped


@dataclass
class YaraRuleSet:
    rules: List[YaraRule] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def add_source(self, text: str, source: str = "") -> None:
        rules, skipped = parse_rules(text, source)
        self.rules += rules
        self.skipped += [("%s (%s)" % (n, source) if source else n, why) for n, why in skipped]

    def load(self, path: str) -> int:
        """Load a ``.yar`` / ``.yara`` file or every such file under a folder."""
        before = len(self.rules)
        files: List[str] = []
        if os.path.isdir(path):
            for base, _dirs, names in os.walk(path):
                files += [os.path.join(base, n) for n in sorted(names)
                          if n.lower().endswith((".yar", ".yara"))]
        elif os.path.isfile(path):
            files.append(path)
        for name in files:
            try:
                with open(name, "r", encoding="utf-8", errors="replace") as fh:
                    self.add_source(fh.read(), os.path.basename(name))
            except OSError as exc:
                self.skipped.append((os.path.basename(name), str(exc)))
        return len(self.rules) - before

    def match(self, data: bytes) -> List[YaraMatch]:
        out = []
        for rule in self.rules:
            if rule.private:
                continue
            scan = _Scan(rule, data)
            try:
                if not rule.condition(scan):
                    continue
            except (TypeError, ValueError, ZeroDivisionError):
                continue
            out.append(YaraMatch(rule, [(i, h[0]) for i, h in scan._hits.items() if h]))
        return out
