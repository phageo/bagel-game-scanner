"""C2: the JavaScript string-table resolver (phase C, JS group, part 1; phageo, 2026-11-02 / 11-03).

Obfuscators such as javascript-obfuscator move every text of a script into one table and replace
each text by a call - ``_0x3c00(0x1a5)`` instead of ``'https'`` - to a small decoder that reads the
table at run time: by an index with an offset, after a rotation loop has turned the table, and in
the encoded forms after Base64 or RC4 with a key written next to the call. A reader that looks for
``require("child_process")`` or an address then sees only numbers. This module rebuilds those texts
**without running anything**: it reads the syntax tree (:mod:`gamescan.jsparse`), recognises the
table, its decoder, the aliases and wrapper functions around it and the rotation loop **by their
shape**, and works the arithmetic out with a small evaluator of its own that knows literals,
arithmetic, ``parseInt``, member reads of object literals and the calls into the table - nothing
else. Base64 and RC4 are undone by this module's own code, not by the script's. Scanned content is
never executed, imported or evaluated (CLAUDE.md, rule 2).

The result is the script's text with every resolved call replaced by the text it stands for (a
quoted literal; ``obj[call]`` becomes ``obj.name``), lines kept where they were. The handler reads
that text with the ordinary rules and tracers as well and adds what only it shows, marked
``resolved`` (:data:`MARK`, :data:`RESOLVED`); what the original text gave stays as it was. The
resolver finds nothing on its own (roadmap-1.0, C2: an enabler).

What stays unresolved is said, never guessed: a call whose arguments are not plain literals (a key
known only at run time), a decoder or rotation loop of a form this module does not read, a decoder
reassigned elsewhere, a name declared twice. Then the handler adds a note (:data:`NOTE_RULE`).

Limits (rule 3; counts, so the same file gives the same answer on every PC): the parser's own
(``jsparse``: size, nodes, a far time cap - a file it refuses falls back to the tracer with
``jsparse.FALLBACK_NOTE``), and here :data:`MAX_STEPS` evaluation steps per file, :data:`MAX_DEPTH`
nesting, :data:`MAX_TABLE` texts per table, :data:`MAX_SITES` calls, :data:`MAX_FUNCTION` bytes for a
function read as a decoder or wrapper, :data:`MAX_TEXT` characters for a built text.
"""
from __future__ import annotations

import math
import re
from bisect import bisect_right
from typing import Dict, List, Optional, Tuple

from .. import jsparse

ON = True                       # the C2 switch: off -> nothing is resolved and nothing changes
PROXIES_ON = True               # helper objects of the "high" preset put back (part 2, 2026-11-03; C2's gap)
# a table recognised but read by no decoder of a form this module knows (an older count rotation, an XOR decoder,
# the index offset written inline) is said too (phageo, 2026-11-08: before, such a script got no note at all)
UNREAD_TABLE_NOTE_ON = True
UNREAD_TABLE = "a string table that no decoder of a form it reads uses (another kind of decoder or rotation)"
UNREAD_TABLE_STOPPED = "a string table whose decoder the reading did not reach"
MAX_ROTATION_WORK = 4 << 20    # bytes of calls-made-at-once searched for a rotation loop per file
# a rotation loop moves one name's items: X.push(X.shift()) or X['push'](X['shift']())
_ROTATE = re.compile(rb"(?<![\w$])([\w$]++)\s*(?:\.\s*push|\[\s*[\x22\x27]push[\x22\x27]\s*\])\s*\(\s*\1\s*"
                     rb"(?:\.\s*shift|\[\s*[\x22\x27]shift[\x22\x27]\s*\])\s*\(\s*\)\s*\)")
_TABLE_REPLACED = "its string table is replaced elsewhere in the script"
MAX_PROXY_WORK = 5_000_000      # spans and text the helper step may go through per file (then it stops)

MAX_STEPS = 3_000_000           # evaluation steps per file (each node evaluated, each decoded text)
MAX_DEPTH = 150                 # nesting of one evaluation (expressions, wrapper calls)
MAX_TABLE = 200_000             # texts in one table
MAX_SITES = 400_000             # calls into the table read in one file
MAX_FUNCTION = 64 * 1024        # bytes of a function read as a decoder or a wrapper
MAX_TEXT = 1 << 20              # characters of a text built by "+"
MAX_UP = 4000                   # parent steps when the scope of a node is looked for

NOTE_RULE = "JS-OBF-005"        # the note: a string table that was not fully resolved
MARK = "  [resolved from the script's string table]"   # appended to the evidence of what only the
RESOLVED = "resolved_string_table"                    # resolved text shows (and Finding.context key)
CACHE = "js_string_table"       # FileContext.cache: the Resolution, for the readers of C1 / C3

# a quick look before the parse: an obfuscator's table - a function that declares an array of
# texts (and, in the usual form, overwrites itself), or an array of texts with an obfuscator's
# rotation (``['push']``) or a hexadecimal index offset (``i = i - 0x1a4``)
_TABLE_FUNCTION = re.compile(r"function\s*[\w$]+\s*\(\s*\)\s*\{\s*(?:var|let|const)\s+[\w$]+\s*=\s*\[\s*['\"]")
_TEXT_ARRAY = re.compile(r"=\s*\[\s*(?:'[^'\\\n]{0,300}'|\"[^\"\\\n]{0,300}\")\s*,\s*['\"]")
# (a name starts where no name character stands before it and is never given back: the unanchored form
# tried every start and every length inside a long run of name characters - quadratic; one malicious
# script with a large encoded blob did not finish in hours. Found in part 2, 2026-11-04.)
_OBF_SHAPE = re.compile(r"\[\s*['\"]push['\"]\s*\]|(?<![\w$])([\w$]++)\s*=\s*\1\s*-\s*0x[0-9a-fA-F]+")

_SCOPES = frozenset({"program", "function_declaration", "function_expression", "function", "arrow_function",
                     "method_definition", "generator_function_declaration", "generator_function",
                     "catch_clause", "class_static_block"})
_FUNCTIONS = frozenset({"function_declaration", "function_expression", "function", "arrow_function",
                        "generator_function_declaration", "generator_function", "method_definition"})
_PATTERNS = frozenset({"identifier", "object_pattern", "array_pattern", "pair_pattern", "assignment_pattern",
                       "rest_pattern", "shorthand_property_identifier_pattern"})
_LOOPS = frozenset({"for_statement", "for_in_statement", "while_statement", "do_statement"})
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*\Z")
_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_JS_SPACE = " \t\n\r\x0b\x0c\xa0\ufeff\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009" \
            "\u200a\u2028\u2029\u202f\u205f\u3000"
_DECIMAL = re.compile(r"[+-]?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)\Z")
_NUMBERS_ONLY = re.compile(r"[-+*0-9a-fA-FxX()\s]{3,200}\Z")


class Unsupported(Exception):
    """A form the evaluator does not read: the value stays unknown (never guessed)."""


class Thrown(Exception):
    """What the script itself would throw at run time (the rotation loop catches it and turns on)."""


class OutOfSteps(Exception):
    """The file's step budget is used up: the reading stops."""


class _Undefined:
    def __repr__(self):
        return "undefined"


UNDEF = _Undefined()


class _Array:
    """An array literal with no items (``!![]`` is how obfuscators write ``true``)."""


_ARRAY = _Array()


class _Func:
    __slots__ = ("binding",)

    def __init__(self, binding):
        self.binding = binding


class _Object:
    __slots__ = ("node", "binding")

    def __init__(self, node, binding):
        self.node, self.binding = node, binding


class Binding:
    __slots__ = ("name", "kind", "node", "value", "scope", "writes", "ambiguous")

    def __init__(self, name, kind, node, value, scope):
        self.name, self.kind, self.node, self.value, self.scope = name, kind, node, value, scope
        self.writes: List[int] = []           # where the name is assigned (byte offsets)
        self.ambiguous = False


class Table:
    def __init__(self, binding, texts):
        self.binding, self.texts = binding, texts
        self.rotation: Optional[int] = None   # settled turn of the table (None: not yet)
        self.trial: Optional[int] = None      # the turn being tried by the rotation loop
        self.problem = ""

    def get(self, index: int, owner: "_Reader"):
        if self.trial is None and self.rotation is None:
            owner.settle(self)
        turn = self.trial if self.trial is not None else self.rotation
        n = len(self.texts)
        if 0 <= index < n:
            return self.texts[(index + turn) % n]
        return UNDEF


class Decoder:
    def __init__(self, table, param, key, offset, encoding, alphabet):
        self.table, self.param, self.key, self.offset = table, param, key, offset
        self.encoding, self.alphabet = encoding, alphabet


class Wrapper:
    def __init__(self, params, call):
        self.params, self.call = params, call


class Resolution:
    """What the resolver made of one script."""

    def __init__(self):
        self.text: Optional[str] = None        # the script with every resolved call replaced (None: none)
        self.limit = ""                        # why the parser fell back ("" when it read the file)
        self.tables = 0                        # string tables recognised that a decoder reads
        self.texts = 0                         # texts in them
        self.unread_tables = 0                 # tables recognised that no decoder it knows reads (said, not read)
        self.unread_texts = 0                  # texts in those
        # the note is there only because of such tables: information - it changes no verdict and no launch
        # (phageo, 2026-11-08; models.Finding.information)
        self.information = False
        self.calls = 0                         # calls into a table outside its own machinery
        self.resolved = 0                      # ... of which resolved
        self.problems: List[str] = []          # why parts stayed unresolved (plain words, for the note)
        self.values: List[Tuple[int, int, str]] = []   # (start byte, end byte, text) per resolved span

    @property
    def unresolved(self) -> int:
        return self.calls - self.resolved

    @property
    def needs_note(self) -> bool:
        return (self.tables > 0 or self.unread_tables > 0) and (self.unresolved > 0 or bool(self.problems))

    def evidence(self) -> str:
        said = "; ".join(self.problems) if self.problems else "%d calls with arguments it does not read" % self.unresolved
        if not self.tables:
            return ("string table of %d texts; no call into it was read; not resolved: %s"
                    % (self.unread_texts, said))[:600]
        return ("string table of %d texts; %d of %d calls resolved; not resolved: %s"
                % (self.texts + self.unread_texts, self.resolved, self.calls, said))[:600]


# -- JavaScript values, as the evaluator models them ----------------------------------------------

def _units(s: str) -> List[int]:
    raw = s.encode("utf-16-le", "surrogatepass")
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2)]


def _from_units(units) -> str:
    return b"".join(u.to_bytes(2, "little") for u in units).decode("utf-16-le", "surrogatepass")


def js_string(raw: str) -> str:
    """The value of a JavaScript string literal (quotes included in ``raw``)."""
    body = raw[1:-1]
    if "\\" not in body:
        return body
    units: List[int] = []
    i, n = 0, len(body)
    simple = {"n": 10, "r": 13, "t": 9, "b": 8, "f": 12, "v": 11}
    while i < n:
        c = body[i]
        if c != "\\":
            units.extend(_units(c))
            i += 1
            continue
        i += 1
        if i >= n:
            raise Unsupported("a string ends in a backslash")
        c = body[i]
        if c in simple:
            units.append(simple[c])
            i += 1
        elif c == "x":
            units.append(int(body[i + 1:i + 3], 16))
            i += 3
        elif c == "u":
            if body[i + 1:i + 2] == "{":
                end = body.index("}", i)
                cp = int(body[i + 2:end], 16)
                units.extend(_units(chr(cp)) if cp < 0xD800 or cp > 0xDFFF else [cp])
                i = end + 1
            else:
                units.append(int(body[i + 1:i + 5], 16))
                i += 5
        elif c in "\n\u2028\u2029":
            i += 1                                       # a line continuation
        elif c == "\r":
            i += 2 if body[i + 1:i + 2] == "\n" else 1
        elif c in "01234567":
            j = i
            while j < n and j - i < 3 and body[j] in "01234567" and int(body[i:j + 1], 8) <= 255:
                j += 1
            units.append(int(body[i:j], 8))
            i = j
        else:
            units.extend(_units(c))
            i += 1
    return _from_units(units)


def js_number(raw: str) -> float:
    t = raw.replace("_", "")
    if t.endswith("n"):
        raise Unsupported("a BigInt literal")
    low = t.lower()
    try:
        if low.startswith("0x"):
            return float(int(low[2:], 16))
        if low.startswith("0o"):
            return float(int(low[2:], 8))
        if low.startswith("0b"):
            return float(int(low[2:], 2))
        if len(t) > 1 and t[0] == "0" and t.isdigit():
            return float(int(t, 8)) if all(ch in "01234567" for ch in t) else float(t)
        return float(t)
    except ValueError:
        raise Unsupported("a number literal")


def to_number(v) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, float):
        return v
    if v is UNDEF:
        return math.nan
    if v is None:
        return 0.0
    if isinstance(v, str):
        s = v.strip(_JS_SPACE)
        if not s:
            return 0.0
        low = s.lower()
        try:
            if low.startswith("0x"):
                return float(int(low[2:], 16))
            if low.startswith("0o"):
                return float(int(low[2:], 8))
            if low.startswith("0b"):
                return float(int(low[2:], 2))
        except ValueError:
            return math.nan
        if s in ("Infinity", "+Infinity"):
            return math.inf
        if s == "-Infinity":
            return -math.inf
        return float(s) if _DECIMAL.match(s) else math.nan
    raise Unsupported("a number from an object")


def to_string(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        if v == int(v) and abs(v) < 1e21:
            return str(int(v))
        s = repr(v)
        if "e" in s or "E" in s:
            raise Unsupported("a number in exponent form")
        return s
    if v is _ARRAY:
        return ""
    raise Unsupported("a text from an object")


def truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, float):
        return not (v == 0 or math.isnan(v))
    if isinstance(v, str):
        return v != ""
    return v is not UNDEF and v is not None


def _int32(x: float) -> int:
    if math.isnan(x) or math.isinf(x):
        return 0
    n = int(x) & 0xFFFFFFFF
    return n - (1 << 32) if n & 0x80000000 else n


def js_parse_int(value, radix=UNDEF) -> float:
    s = to_string(value).lstrip(_JS_SPACE)
    sign = 1
    if s[:1] in "+-" and s:
        sign = -1 if s[0] == "-" else 1
        s = s[1:]
    r = _int32(to_number(radix)) if radix is not UNDEF else 0
    strip = True
    if r != 0:
        if r < 2 or r > 36:
            return math.nan
        if r != 16:
            strip = False
    else:
        r = 10
    if strip and s[:2].lower() == "0x":
        s, r = s[2:], 16
    digits = 0
    for ch in s:
        d = int(ch, 36) if ch.isascii() and ch.isalnum() else 99
        if d >= r:
            break
        digits += 1
    if not digits:
        return math.nan
    return float(sign * int(s[:digits], r))


def _strict_equal(a, b) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, (str, bool)):
        return a == b
    return a is b


def _b64(text: str, alphabet: str) -> str:
    """javascript-obfuscator's Base64 loop, step for step (its alphabet read from the decoder), then
    ``decodeURIComponent`` of the bytes (UTF-8; what the script would throw on is thrown here)."""
    out = bytearray()
    bc = bs = 0
    for u in _units(text):
        b = alphabet.find(chr(u))
        if b == -1:
            continue
        bs = bs * 64 + b if bc % 4 else b
        old = bc % 4
        bc += 1
        if old:
            out.append(255 & (bs >> ((-2 * bc) & 6)))
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise Thrown("URIError")


def _rc4(text: str, key: str, boxes: Dict[str, List[int]]) -> str:
    ku = _units(key)
    if not ku:
        raise Unsupported("an empty RC4 key")
    if key not in boxes:
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + ku[i % len(ku)]) % 256
            s[i], s[j] = s[j], s[i]
        boxes[key] = s
    s = list(boxes[key])
    i = j = 0
    out = []
    for c in _units(text):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return _from_units(out)


def literal(value: str) -> str:
    """``value`` as a double-quoted JavaScript literal on one line."""
    out = ['"']
    for ch in value:
        o = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F or o in (0x2028, 0x2029) or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# -- the reader -----------------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes, tree):
        self.data, self.tree = data, tree
        self.steps = 0
        self.scopes: Dict[int, Tuple[Optional[int], Dict[str, Binding]]] = {}
        self.scope_node: Dict[int, object] = {}
        self.calls: List[Tuple[object, int]] = []       # (call node, scope id) with a named callee
        self.iifes: List[Tuple[object, int]] = []       # (call node, scope id): a function called at once
        self.writes: List[Tuple[str, int, int]] = []    # (name, scope id, byte offset)
        self.uses: Dict[str, int] = {}                  # name -> uses other than a member read / a call
        self.member_writes: Dict[str, int] = {}
        self.kinds: Dict[int, tuple] = {}
        self.busy: set = set()
        self.tables: Dict[int, Table] = {}
        self.machinery: List[Tuple[int, int]] = []
        self.memo: Dict[tuple, object] = {}
        self.boxes: Dict[str, List[int]] = {}
        self.consts: Dict[int, object] = {}
        self.problems: Dict[str, None] = {}
        self.table_names: set = set()             # names of the tables (bytes), for a cheap first look
        self.used: Dict[int, Table] = {}          # tables a decoder reads (what the note counts)
        # binding id -> (table, texts, a plain array, overwrites itself from inside) - for unread_tables
        self.recognised: Dict[int, Tuple[Binding, int, bool, bool]] = {}
        self.node_scope: Dict[int, int] = {}      # node id -> innermost scope id (every name, from the walk)

    # ---- budget and text ----
    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise OutOfSteps()

    def text(self, node) -> str:
        return self.data[node.start_byte:node.end_byte].decode("utf-8", "surrogatepass")

    # ---- one walk: scopes, declarations, writes, calls ----
    def read(self) -> None:
        cursor = self.tree.walk()
        path: List[Tuple[str, Optional[str], Optional[str]]] = []   # (type, field, role) per depth
        stack: List[Tuple[int, int]] = []                           # (depth, scope id)
        depth = 0
        while True:
            node = cursor.node
            field = cursor.field_name
            t = node.type
            del path[depth:]
            while stack and stack[-1][0] >= depth:
                stack.pop()
            parent = path[-1] if path else None
            role = self._role(t, field, parent)
            path.append((t, field, role))
            if t in _SCOPES:
                sid = node.id
                self.scopes[sid] = (stack[-1][1] if stack else None, {})
                self.scope_node[sid] = node
                stack.append((depth, sid))
            if t in ("identifier", "shorthand_property_identifier_pattern"):
                self._identifier(node, field, role, path, stack)
            elif t == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None:
                    inner = fn
                    if inner.type == "parenthesized_expression" and inner.named_child_count == 1:
                        inner = inner.named_children[0]
                    if fn.type == "identifier":
                        self.calls.append((node, stack[-1][1]))
                    elif inner.type in ("function_expression", "function"):
                        self.iifes.append((node, stack[-1][1]))
            if cursor.goto_first_child():
                depth += 1
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    self._settle_writes()
                    return
                depth -= 1

    @staticmethod
    def _role(t, field, parent) -> Optional[str]:
        if parent is None:
            return None
        ptype, _, prole = parent
        if t == "formal_parameters":
            return "param"
        if ptype == "variable_declarator" and field == "name":
            return "var"
        if ptype == "catch_clause" and field == "parameter":
            return "catch"
        if ptype == "arrow_function" and field == "parameter":
            return "param"
        if ptype in ("import_clause", "import_specifier", "namespace_import", "named_imports") or t == "import_clause":
            return "import"
        if prole and t in _PATTERNS and field != "right" and not (ptype == "pair_pattern" and field == "key"):
            return prole
        if prole == "param" and ptype == "formal_parameters":
            return "param" if t in _PATTERNS else None
        if prole == "import":
            return "import"
        return None

    def _declare(self, sid: int, name: str, binding: Binding) -> None:
        names = self.scopes[sid][1]
        old = names.get(name)
        if old is None:
            names[name] = binding
        elif not (old.kind == "var" and binding.kind == "var" and binding.value is None):
            old.ambiguous = True               # declared twice in one scope: never trusted

    def _function_scope(self, stack) -> int:
        for _, sid in reversed(stack):
            if self.scope_node[sid].type != "catch_clause":
                return sid
        return stack[0][1]

    def _identifier(self, node, field, role, path, stack) -> None:
        self.node_scope[node.id] = stack[-1][1]
        name = self.text(node)
        ptype = path[-2][0] if len(path) > 1 else ""
        if role in ("param", "catch"):
            self._declare(stack[-1][1], name, Binding(name, role, node, None, stack[-1][1]))
            return
        if role == "var":
            declarator = node.parent if ptype == "variable_declarator" else None
            value = declarator.child_by_field_name("value") if declarator is not None else None
            sid = self._function_scope(stack)
            self._declare(sid, name, Binding(name, "var", declarator, value, sid))
            return
        if role == "import":
            sid = stack[0][1]
            self._declare(sid, name, Binding(name, "import", node, None, sid))
            return
        if field == "name" and ptype in ("function_declaration", "generator_function_declaration", "class_declaration"):
            own = ptype != "class_declaration"
            outer = stack[-2][1] if own and len(stack) > 1 else stack[-1][1]
            self._declare(outer, name, Binding(name, "function" if own else "class", node.parent, None, outer))
            return
        if field == "name" and ptype in ("function_expression", "function", "generator_function"):
            self._declare(stack[-1][1], name, Binding(name, "function", node.parent, None, stack[-1][1]))
            return
        if node.type != "identifier":
            return
        # a reference: assigned, a member written, a member read, called, or any other use
        if ptype in ("assignment_expression", "augmented_assignment_expression") and field == "left" \
                or ptype == "update_expression":
            self.writes.append((name, stack[-1][1], node.start_byte))
            return
        if ptype in ("member_expression", "subscript_expression") and field == "object":
            gtype, gfield = (path[-3][0], path[-2][1]) if len(path) > 2 else ("", None)
            if gtype in ("assignment_expression", "augmented_assignment_expression") and gfield == "left" \
                    or gtype == "update_expression":
                self.member_writes[name] = self.member_writes.get(name, 0) + 1
            elif gtype == "call_expression" and gfield == "function":
                self.uses[name] = self.uses.get(name, 0) + 1          # a method call may change it
            return
        if ptype == "call_expression" and field == "function":
            return
        self.uses[name] = self.uses.get(name, 0) + 1

    def _settle_writes(self) -> None:
        for name, sid, at in self.writes:
            try:
                b = self.lookup(name, sid)
            except Unsupported:
                continue
            if b is not None:
                b.writes.append(at)

    # ---- names ----
    def lookup(self, name: str, sid: Optional[int]) -> Optional[Binding]:
        steps = 0
        while sid is not None:
            parent, names = self.scopes[sid]
            b = names.get(name)
            if b is not None:
                if b.ambiguous:
                    raise Unsupported("a name declared twice")
                return b
            sid = parent
            steps += 1
            if steps > MAX_UP:
                raise Unsupported("scopes nested too deep")
        return None

    def scope_of(self, node) -> int:
        """The innermost scope around ``node``. Every name's scope is noted during the one walk (``read``);
        another node walks up once and notes what it passed. (tree-sitter finds a node's parent from the
        root each time: walking up from every name made a deep 1 MB script take hours - part 2, 2026-11-03.)"""
        got = self.node_scope.get(node.id)
        if got is not None:
            return got
        path = []
        n = node
        for _ in range(MAX_UP):
            if n is None:
                break
            got = self.node_scope.get(n.id)
            if got is None and n.id in self.scopes:
                got = n.id
            if got is not None:
                for i in path:
                    self.node_scope[i] = got
                return got
            path.append(n.id)
            n = n.parent
        raise Unsupported("scopes nested too deep")

    def binding_at(self, node) -> Optional[Binding]:
        return self.lookup(self.text(node), self.scope_of(node))

    # ---- what a function is: a table, a decoder, a wrapper, an alias, or nothing of these ----
    @staticmethod
    def _function_node(b: Binding):
        if b.kind == "function":
            return b.node
        if b.kind == "var" and b.value is not None and b.value.type in ("function_expression", "function", "arrow_function"):
            return b.value
        return None

    @staticmethod
    def _params(fn) -> Optional[List[str]]:
        ps = fn.child_by_field_name("parameters")
        if ps is None:
            p = fn.child_by_field_name("parameter")
            return [p.text.decode("utf-8", "surrogatepass")] if p is not None and p.type == "identifier" else None
        out = []
        for p in ps.named_children:
            if p.type != "identifier":
                return None
            out.append(p.text.decode("utf-8", "surrogatepass"))
        return out

    def _own_writes_only(self, b: Binding, fn) -> bool:
        return all(fn.start_byte <= at < fn.end_byte for at in b.writes)

    def kind(self, b: Binding) -> tuple:
        key = id(b)
        if key in self.kinds:
            return self.kinds[key]
        if key in self.busy:
            return ("none",)
        self.busy.add(key)
        try:
            found = self._kind(b)
        except Unsupported as exc:
            found = ("none", str(exc))
        finally:
            self.busy.discard(key)
        self.kinds[key] = found
        return found

    def _kind(self, b: Binding) -> tuple:
        if b.ambiguous:
            return ("none",)
        if b.kind == "var" and b.value is not None and b.value.type == "identifier":
            if b.writes:
                return ("none",)
            target = self.binding_at(b.value)
            if target is None:
                return ("none",)
            k = self.kind(target)
            return ("alias", target) if k[0] in ("decoder", "wrapper", "alias", "bad") else ("none",)
        fn = self._function_node(b)
        if fn is None:
            return ("none",)
        params = self._params(fn)
        if params is None:
            return ("none",)
        if not params:
            texts = self._table_texts(fn, b)
            if texts is not None:
                own = self._own_writes_only(b, fn)
                self.recognised[id(b)] = (b, len(texts), False, own and bool(b.writes))   # (whatever comes of it)
                if not own:
                    return ("bad", _TABLE_REPLACED)
                self.machinery.append((fn.start_byte, fn.end_byte))
                return ("table", texts)
            return ("none",)
        if fn.end_byte - fn.start_byte > MAX_FUNCTION:
            return ("none",)
        wrapper = self._wrapper(fn, params)
        if wrapper is None and not any(self.data.find(name, fn.start_byte, fn.end_byte) >= 0 for name in self.table_names):
            return ("none",)                         # (a decoder names its table: cheap before its walk)
        if wrapper is not None:
            if b.writes:
                return ("none",)
            self.machinery.append((fn.start_byte, fn.end_byte))
            return ("wrapper", wrapper)
        decoder = self._decoder(fn, b)
        if decoder is None:
            return ("none",)
        self.machinery.append((fn.start_byte, fn.end_byte))
        if isinstance(decoder, str):
            return ("bad", decoder)
        if not self._own_writes_only(b, fn):
            return ("bad", "its string decoder is reassigned elsewhere in the script")
        return ("decoder", decoder)

    def _text_array(self, node) -> Optional[List[str]]:
        if node is None or node.type != "array":
            return None
        items = node.named_children
        if not items or len(items) > MAX_TABLE or any(i.type != "string" for i in items):
            return None
        self.tick(len(items) // 64 + 1)
        return [js_string(self.text(i)) for i in items]

    def _table_texts(self, fn, b: Binding) -> Optional[List[str]]:
        """A function with no parameters that declares an array of texts and calls nothing but
        itself (javascript-obfuscator's table: it returns the array and overwrites itself)."""
        body = fn.child_by_field_name("body")
        if body is None or body.type != "statement_block":
            return None
        found = None
        rest = []                                    # everything but the array itself is looked at
        for stmt in body.named_children:
            if stmt.type in ("variable_declaration", "lexical_declaration"):
                for d in stmt.named_children:
                    value = d.child_by_field_name("value") if d.type == "variable_declarator" else None
                    texts = self._text_array(value)
                    if texts is not None:
                        if found is not None:
                            return None
                        found = texts
                    elif value is not None:
                        rest.append(value)
            else:
                rest.append(stmt)
        if found is None:
            return None
        for part in rest:
            seen = 0
            for n in jsparse.walk(part, max_nodes=4097):
                seen += 1
                if seen > 4096 or n.type in _LOOPS:
                    return None
                if n.type == "call_expression":
                    callee = n.child_by_field_name("function")
                    if callee is None or callee.type != "identifier" or self.text(callee) != b.name:
                        return None
        return found

    def _wrapper(self, fn, params) -> Optional[Wrapper]:
        """``function w(a, b, ...) { [var o = {literal members};] return f(<arithmetic of a, b, o.x>); }``
        where ``f`` is a decoder, an alias or another wrapper."""
        body = fn.child_by_field_name("body")
        if body is None:
            return None
        if body.type != "statement_block":
            call = body
        else:
            call = None
            for stmt in body.named_children:
                if stmt.type == "return_statement":
                    if call is not None or stmt.named_child_count != 1:
                        return None
                    call = stmt.named_children[0]
                elif stmt.type in ("variable_declaration", "lexical_declaration"):
                    for d in stmt.named_children:
                        v = d.child_by_field_name("value") if d.type == "variable_declarator" else None
                        if v is None or v.type not in ("object", "number", "string", "unary_expression"):
                            return None
                elif stmt.type != "comment":
                    return None
        if call is None or call.type != "call_expression":
            return None
        callee = call.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            return None
        target = self.binding_at(callee)
        if target is None or self.kind(target)[0] not in ("decoder", "wrapper", "alias", "bad"):
            return None
        return Wrapper(params, call)

    def _decoder(self, fn, b: Binding):
        """A function that reads one table by its first parameter, after an offset (``i = i - 0x1a4``),
        plain or after Base64 / RC4 (the key: its second parameter). Returns a :class:`Decoder`, a
        problem (plain words) for a decoder of a form not read, or None for anything else."""
        reads = []
        alphabet = ""
        uri = xor = has256 = False
        loops = 0
        calls = []
        for n in jsparse.walk(fn, max_nodes=20_000):
            t = n.type
            if t == "subscript_expression":
                obj, index = n.child_by_field_name("object"), n.child_by_field_name("index")
                if obj is not None and index is not None and obj.type == "identifier" and index.type == "identifier":
                    reads.append(n)
            elif t == "string":
                if 64 <= n.end_byte - n.start_byte - 2 <= 6 * 70:          # (also written with escapes)
                    v = js_string(self.text(n))
                    if len(v) in (64, 65) and len(set(v)) == len(v) and set(v) <= _B64:
                        alphabet = v
            elif t == "binary_expression":
                op = n.child_by_field_name("operator")
                xor = xor or (op is not None and op.type == "^")
                if not has256 and _NUMBERS_ONLY.match(self.text(n)):
                    try:                                  # 256 written as arithmetic (numbersToExpressions)
                        has256 = self.ev(n, {}, 0, const=True) == 256.0
                    except Unsupported:
                        pass
            elif t == "number":
                has256 = has256 or self.text(n).lower() in ("0x100", "256")
            elif t in _LOOPS:
                loops += 1
            elif t == "call_expression":
                calls.append(n)
            elif t == "identifier":
                uri = uri or self.text(n) == "decodeURIComponent"
        table = None
        logic = param = key = None
        for r in reads:
            obj = r.child_by_field_name("object")
            source = self.binding_at(obj)
            t = self._table_of(source)
            if t is None:
                continue
            owner = self.scope_node.get(self.scope_of(r))
            if owner is None or owner.type not in _FUNCTIONS:
                continue
            ps = self._params(owner)
            if not ps or self.text(r.child_by_field_name("index")) != ps[0]:
                continue
            if table is not None and (t is not table or owner.id != logic.id):
                return None
            table, logic, param, key = t, owner, ps[0], (ps[1] if len(ps) > 1 else None)
        if table is None:
            return None
        self.used[id(table)] = table
        if logic.id != fn.id:
            # the decoder's logic in a function it assigns to its own name (an older form)
            up = logic.parent
            if up is None or up.type != "assignment_expression" or self.text(up.child_by_field_name("left")) != b.name:
                return None
        offset = self._offset(logic, param)
        if offset == "twice":
            return "its string decoder changes the index more than once"
        encoded = bool(alphabet)
        if not encoded and offset is None and table.binding.kind == "var" and not self._rotated(table):
            return None                    # an ordinary array read by index: no obfuscator's table
        if alphabet and uri and xor and has256 and key:
            return Decoder(table, param, key, offset, "rc4", alphabet)
        if alphabet and uri and not xor:
            return Decoder(table, param, key, offset, "base64", alphabet)
        if not alphabet and not uri and not loops:
            for c in calls:
                callee = c.child_by_field_name("function")
                if callee is None or callee.type != "identifier":
                    return "its string decoder calls something it does not read"
                name = self.text(callee)
                if name != b.name and self._table_of(self.binding_at(callee)) is not table:
                    return "its string decoder calls something it does not read"
            return Decoder(table, param, key, offset, "plain", "")
        return "its string decoder is of a kind it does not read"

    def _offset(self, logic, param):
        """The assignment that shifts the index (``i = i - 0x1a4``, ``i -= 4``) in the decoder's logic:
        (operator, expression), None when there is none, "twice" when there is more than one."""
        found = None
        body = logic.child_by_field_name("body")
        for n in jsparse.walk(body, max_nodes=20_000) if body is not None else ():
            if n.type in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                if left is not None and left.type == "identifier" and self.text(left) == param:
                    if self.scope_of(n) != logic.id:
                        continue                     # another function's own variable of that name
                    if found is not None:
                        return "twice"
                    op = n.child_by_field_name("operator")
                    found = (op.type if op is not None else "=", n.child_by_field_name("right"))
            elif n.type == "update_expression" and self.text(n).strip("+- ") == param and self.scope_of(n) == logic.id:
                return "twice"
        return found

    def _table_of(self, source: Optional[Binding]) -> Optional[Table]:
        """The table a name stands for: the table function itself, a variable holding its result
        (``var t = _0x37b2();``), or a variable that is an array of texts (older obfuscators)."""
        if source is None:
            return None
        if source.kind == "function":
            k = self.kind(source)
            return self._table(source, k[1]) if k[0] == "table" else None
        if source.kind != "var" or source.value is None:
            return None
        v = source.value
        if v.type == "call_expression" and v.child_by_field_name("arguments").named_child_count == 0:
            callee = v.child_by_field_name("function")
            if callee is not None and callee.type == "identifier":
                return self._table_of(self.binding_at(callee))
            return None
        if v.type == "array" and not source.writes and not self.member_writes.get(source.name):
            texts = self._text_array(v)
            if texts is not None and len(texts) >= 2:
                return self._table(source, texts)
        return None

    def _table(self, binding: Binding, texts) -> Table:
        t = self.tables.get(id(binding))
        if t is None:
            t = self.tables[id(binding)] = Table(binding, texts)
        return t

    def _rotated(self, table: Table) -> bool:
        return bool(self._rotations(table))

    # ---- the rotation loop ----
    def _rotations(self, table: Table) -> list:
        found = []
        for call, sid in self.iifes:
            args = call.child_by_field_name("arguments")
            first = args.named_children[0] if args is not None and args.named_child_count else None
            if first is None or first.type != "identifier":
                continue
            try:
                if self.lookup(self.text(first), sid) is table.binding:
                    found.append(call)
            except Unsupported:
                continue
        return found

    def settle(self, table: Table) -> None:
        """Turn the table the way its rotation loop does: the loop computes an expression of
        ``parseInt`` over decoded texts, compares it with a number and turns the table by one
        (``push(shift())``) until they are equal. Tried for every turn of one full round."""
        if table.problem:
            raise Unsupported(table.problem)
        loops = self._rotations(table)
        if not loops:
            table.rotation = 0
            return
        if len(loops) > 1:
            table.problem = "its string table is turned by more than one loop"
            raise Unsupported(table.problem)
        call = loops[0]
        fn = call.child_by_field_name("function")
        if fn.type == "parenthesized_expression":
            fn = fn.named_children[0]
        self.machinery.append((call.start_byte, call.end_byte))
        params = self._params(fn)
        args = call.child_by_field_name("arguments").named_children
        shape = None
        if params and len(params) >= 2 and len(args) >= 2:
            shape = self._loop_shape(fn, params[1])
        if shape is None:
            table.problem = "its string table is turned by a loop of a form it does not read"
            raise Unsupported(table.problem)
        target = to_number(self.ev(args[1], {}, 0))
        n = len(table.texts)
        try:
            for turn in range(n):
                table.trial = turn
                try:
                    value = self.ev(shape, {}, 0)
                except Thrown:
                    continue
                if isinstance(value, float) and value == target:
                    table.rotation = turn
                    return
        except Unsupported as exc:
            table.problem = "its string table's rotation loop uses %s" % exc
            raise Unsupported(table.problem)
        finally:
            table.trial = None
        table.problem = "its string table's rotation loop does not settle within one full turn"
        raise Unsupported(table.problem)

    def _loop_shape(self, fn, target_param: str):
        """The expression the loop compares with its second parameter, when the function also turns
        an array (``push`` / ``shift``)."""
        compared = None
        words = set()
        declared = {}
        for n in jsparse.walk(fn, max_nodes=50_000):
            t = n.type
            if t == "binary_expression":
                op = n.child_by_field_name("operator")
                if op is not None and op.type in ("===", "=="):
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    for a, c in ((left, right), (right, left)):
                        if a is not None and c is not None and a.type == "identifier" and c.type == "identifier" \
                                and self.text(c) == target_param:
                            compared = self.text(a)
            elif t == "string":
                words.add(js_string(self.text(n)))
            elif t == "property_identifier":
                words.add(self.text(n))
            elif t == "variable_declarator":
                name = n.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    declared.setdefault(self.text(name), []).append(n.child_by_field_name("value"))
        if compared is None or not {"push", "shift"} <= words:
            return None
        values = declared.get(compared, [])
        return values[0] if len(values) == 1 and values[0] is not None else None

    # ---- the evaluator: literals, arithmetic, parseInt, member reads, calls into the table ----
    def ev(self, node, env: dict, depth: int, const: bool = False):
        self.tick()
        if depth > MAX_DEPTH:
            raise Unsupported("expressions nested too deep")
        t = node.type
        if t == "number":
            return js_number(self.text(node))
        if t == "string":
            return js_string(self.text(node))
        if t == "template_string":
            if any(c.type == "template_substitution" for c in node.named_children):
                raise Unsupported("a template with values")
            return js_string("`" + self.text(node)[1:-1].replace("\\`", "`") + "`")
        if t == "parenthesized_expression":
            if node.named_child_count != 1:
                raise Unsupported("a list in parentheses")
            return self.ev(node.named_children[0], env, depth + 1, const)
        if t == "true":
            return True
        if t == "false":
            return False
        if t == "null":
            return None
        if t == "array":
            if node.named_child_count:
                raise Unsupported("an array")
            return _ARRAY
        if t == "unary_expression":
            return self._unary(node, env, depth, const)
        if t == "binary_expression":
            return self._binary(node, env, depth, const)
        if t == "identifier":
            return self._name(node, env, depth)
        if t in ("member_expression", "subscript_expression"):
            obj = self.ev(node.child_by_field_name("object"), env, depth + 1, const)
            if t == "member_expression":
                prop = node.child_by_field_name("property")
                if prop is None or prop.type != "property_identifier":
                    raise Unsupported("a member")
                key = self.text(prop)
            else:
                key = to_string(self.ev(node.child_by_field_name("index"), env, depth + 1, const))
            return self._member(obj, key, depth)
        if t == "call_expression":
            if const:
                raise Unsupported("a call in a constant")
            return self._call(node, env, depth)
        raise Unsupported("a %s" % t.replace("_", " "))

    def _unary(self, node, env, depth, const):
        op = node.child_by_field_name("operator")
        v = self.ev(node.child_by_field_name("argument"), env, depth + 1, const)
        o = op.type if op is not None else ""
        if o == "-":
            return -to_number(v)
        if o == "+":
            return to_number(v)
        if o == "!":
            return not truthy(v)
        if o == "~":
            return float(~_int32(to_number(v)))
        raise Unsupported("the operator %s" % o)

    def _binary(self, node, env, depth, const):
        op = node.child_by_field_name("operator").type
        a = self.ev(node.child_by_field_name("left"), env, depth + 1, const)
        if op == "&&":
            return self.ev(node.child_by_field_name("right"), env, depth + 1, const) if truthy(a) else a
        if op == "||":
            return a if truthy(a) else self.ev(node.child_by_field_name("right"), env, depth + 1, const)
        b = self.ev(node.child_by_field_name("right"), env, depth + 1, const)
        if op == "+":
            if isinstance(a, str) or isinstance(b, str) or a is _ARRAY or b is _ARRAY:
                s = to_string(a) + to_string(b)
                if len(s) > MAX_TEXT:
                    raise Unsupported("a text too long")
                self.tick(len(s) // 256)
                return s
            return to_number(a) + to_number(b)
        if op in ("===", "!=="):
            return _strict_equal(a, b) == (op == "===")
        if op in ("==", "!="):
            if type(a) is type(b) or {type(a), type(b)} <= {str, float}:
                same = _strict_equal(a, b) if type(a) is type(b) else to_number(a) == to_number(b)
                return same == (op == "==")
            raise Unsupported("a loose comparison")
        if op in ("<", ">", "<=", ">="):
            if isinstance(a, str) and isinstance(b, str):
                x, y = _units(a), _units(b)
            else:
                x, y = to_number(a), to_number(b)
                if math.isnan(x) or math.isnan(y):
                    return False
            return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
        x, y = to_number(a), to_number(b)
        if op == "-":
            return x - y
        if op == "*":
            return x * y
        if op == "/":
            if y == 0:
                if x == 0 or math.isnan(x):
                    return math.nan
                return math.copysign(math.inf, x) * math.copysign(1.0, y)
            return x / y
        if op == "%":
            if y == 0 or math.isinf(x) or math.isnan(x) or math.isnan(y):
                return math.nan
            return x if math.isinf(y) else math.fmod(x, y)
        if op == "**":
            try:
                return math.pow(x, y)
            except (OverflowError, ValueError):
                return math.nan
        i, j = _int32(x), _int32(y)
        if op == "&":
            return float(i & j)
        if op == "|":
            return float(_int32(float(i | j)))
        if op == "^":
            return float(_int32(float(i ^ j)))
        if op == "<<":
            return float(_int32(float((i << (j & 31)) & 0xFFFFFFFF)))
        if op == ">>":
            return float(i >> (j & 31))
        if op == ">>>":
            return float((i & 0xFFFFFFFF) >> (j & 31))
        raise Unsupported("the operator %s" % op)

    def _name(self, node, env, depth):
        name = self.text(node)
        if name in env:
            return env[name]
        b = self.binding_at(node)
        if b is None:
            if name == "undefined":
                return UNDEF
            if name == "NaN":
                return math.nan
            if name == "Infinity":
                return math.inf
            raise Unsupported("a value known only at run time")
        if b.kind == "function":
            return _Func(b)
        if b.kind != "var" or b.value is None or b.writes or b.ambiguous:
            raise Unsupported("a value known only at run time")
        v = b.value
        if v.type in ("function_expression", "function", "arrow_function"):
            return _Func(b)
        if v.type == "identifier":
            k = self.kind(b)
            if k[0] == "alias":
                return _Func(b)
            raise Unsupported("a value known only at run time")
        if v.type == "object":
            if self.uses.get(name) or self.member_writes.get(name):
                raise Unsupported("an object that is changed or handed on")
            return _Object(v, b)
        key = id(b)
        if key not in self.consts:
            self.consts[key] = Unsupported("a constant that refers to itself")
            try:
                self.consts[key] = self.ev(v, {}, depth + 1, const=True)
            except Unsupported as exc:
                self.consts[key] = exc
        found = self.consts[key]
        if isinstance(found, Unsupported):
            raise Unsupported(str(found))
        return found

    def _member(self, obj, key: str, depth: int):
        if isinstance(obj, _Object):
            for pair in obj.node.named_children:
                if pair.type != "pair":
                    raise Unsupported("an object with more than plain members")
                k = pair.child_by_field_name("key")
                if k.type in ("property_identifier", "number"):
                    name = self.text(k) if k.type == "property_identifier" else to_string(js_number(self.text(k)))
                elif k.type == "string":
                    name = js_string(self.text(k))
                else:
                    raise Unsupported("an object with computed members")
                if name == key:
                    return self.ev(pair.child_by_field_name("value"), {}, depth + 1, const=True)
            return UNDEF
        if isinstance(obj, str) and key == "length":
            return float(len(_units(obj)))
        raise Unsupported("a member of a value it does not model")

    def _call(self, node, env, depth):
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        items = args.named_children if args is not None else []
        if any(a.type == "spread_element" for a in items):
            raise Unsupported("spread arguments")
        if fn.type == "identifier" and self.text(fn) not in env and self.binding_at(fn) is None:
            if self.text(fn) == "parseInt":
                vals = [self.ev(a, env, depth + 1) for a in items[:2]]
                return js_parse_int(vals[0] if vals else UNDEF, vals[1] if len(vals) > 1 else UNDEF)
            raise Unsupported("a call to %s" % self.text(fn)[:40])
        f = self.ev(fn, env, depth + 1)
        if not isinstance(f, _Func):
            raise Unsupported("a call to a value it does not model")
        values = [self.ev(a, env, depth + 1) for a in items]
        return self.apply(f.binding, values, depth + 1)

    def apply(self, b: Binding, values: list, depth: int):
        if depth > MAX_DEPTH:
            raise Unsupported("calls nested too deep")
        k = self.kind(b)
        if k[0] == "alias":
            return self.apply(k[1], values, depth + 1)
        if k[0] == "wrapper":
            w = k[1]
            env = {p: (values[i] if i < len(values) else UNDEF) for i, p in enumerate(w.params)}
            return self.ev(w.call, env, depth + 1)
        if k[0] == "decoder":
            return self.decode(k[1], values)
        if k[0] == "bad":
            raise Unsupported(k[1])
        raise Unsupported("a call it does not model")

    def decode(self, d: Decoder, values: list):
        index = values[0] if values else UNDEF
        key = values[1] if len(values) > 1 else UNDEF
        if d.offset is not None:
            op, expr = d.offset
            env = {d.param: index}
            if d.key:
                env[d.key] = key
            shift = self.ev(expr, env, 1)
            if op == "=":
                index = shift
            elif op == "-=":
                index = to_number(index) - to_number(shift)
            elif op == "+=":
                index = (to_string(index) + to_string(shift)) if isinstance(index, str) or isinstance(shift, str) \
                    else to_number(index) + to_number(shift)
            else:
                raise Unsupported("an index changed by %s" % op)
        if isinstance(index, str):
            raise Unsupported("a table read by a text")
        i = to_number(index)
        if math.isnan(i) or i != int(i):
            item = UNDEF
        else:
            item = d.table.get(int(i), self)
        turn = d.table.trial if d.table.trial is not None else d.table.rotation
        memo = (id(d), i, key if isinstance(key, str) else None, turn)
        if memo in self.memo:
            return self.memo[memo]
        if d.encoding == "plain":
            value = item
        else:
            if not isinstance(item, str):
                raise Thrown("TypeError")
            self.tick(len(item) // 16 + 1)
            value = _b64(item, d.alphabet)
            if d.encoding == "rc4":
                if not isinstance(key, str):
                    raise Unsupported("an RC4 key that is not a text")
                self.tick(len(value) // 16 + 16)
                value = _rc4(value, key, self.boxes)
        self.memo[memo] = value
        return value

    # ---- the calls ----
    def find_tables(self) -> None:
        """Every table before any decoder is looked for: table functions (no parameters, an array of
        texts) and arrays of texts held by a variable; their names bound the decoder search."""
        self.table_names = set()
        functions = []
        for _, names in self.scopes.values():
            for name, b in names.items():
                if b.ambiguous:
                    continue
                if b.kind == "function" or (b.kind == "var" and self._function_node(b) is not None):
                    if b.kind == "function" and self._params(b.node) == [] and self.kind(b)[0] == "table":
                        self.table_names.add(name.encode("utf-8", "surrogatepass"))
                    else:
                        functions.append(b)
                elif b.kind == "var" and b.value is not None and b.value.type == "array" \
                        and b.value.named_child_count >= 2 and b.value.named_children[0].type == "string":
                    self.table_names.add(name.encode("utf-8", "surrogatepass"))
                    # (an array of texts is a table only when a rotation loop turns it: see unread_tables)
                    self.recognised[id(b)] = (b, b.value.named_child_count, True, False)
        if self.table_names:
            # every function read once - a wrapper the obfuscator made but nothing calls is machinery too
            for b in functions:
                self.kind(b)

    def unread_tables(self) -> Tuple[int, int]:
        """``(tables, texts)`` this reader recognised as an obfuscator's string table but that no decoder of
        a form it knows reads. Counted: a table function (no parameters, an array of texts) that overwrites
        itself from inside, as the obfuscator's does; or any recognised table - function or array of texts -
        that a rotation loop turns. A rotation loop is a function called at once, at most ``MAX_FUNCTION``
        bytes, given the table (or a call of the table function) and a number, that moves one name's items
        with ``X.push(X.shift())`` (or ``X['push'](X['shift']())``). A game's own function that returns a
        list, or an array of texts nothing turns, is data: not counted. Cheap checks first; the text searched
        is bounded by ``MAX_ROTATION_WORK`` bytes per file (then the rest counts as not turned)."""
        if not self.recognised:
            return 0, 0
        used = {id(t.binding) for t in self.used.values()}
        turned, work = set(), 0
        for call, sid in self.iifes:
            size = call.end_byte - call.start_byte
            if size > MAX_FUNCTION:
                continue
            args = call.child_by_field_name("arguments")
            if args is None or args.named_child_count < 2 or args.named_children[1].type != "number":
                continue
            first = args.named_children[0]
            if first.type == "call_expression":
                inner = first.child_by_field_name("arguments")
                first = first.child_by_field_name("function") \
                    if inner is not None and inner.named_child_count == 0 else None
            if first is None or first.type != "identifier":
                continue
            try:
                b = self.lookup(self.text(first), sid)
            except Unsupported:
                continue
            if b is None or id(b) not in self.recognised or id(b) in used or id(b) in turned:
                continue
            work += size
            if work > MAX_ROTATION_WORK:
                break
            if _ROTATE.search(self.data, call.start_byte, call.end_byte):
                turned.add(id(b))
        tables = texts = 0
        for key, (_b, count, array, overwrites) in self.recognised.items():
            if key in used or not (key in turned or (overwrites and not array)):
                continue
            tables += 1
            texts += count
        return tables, texts

    def run(self, res: Resolution) -> List[Tuple[int, int, str]]:
        self.find_tables()
        string_calls = []
        if not self.table_names:
            return []
        for call, sid in self.calls:
            fn = call.child_by_field_name("function")
            try:
                b = self.lookup(self.text(fn), sid)
            except Unsupported:
                continue
            if b is None:
                continue
            k = self.kind(b)
            if k[0] in ("decoder", "wrapper", "alias", "bad"):
                string_calls.append((call, b))
            if len(string_calls) > MAX_SITES:
                self.problems["more than %d calls into the table" % MAX_SITES] = None
                break
        for t in self.used.values():                    # every rotation loop counts as machinery
            for loop in self._rotations(t):
                self.machinery.append((loop.start_byte, loop.end_byte))
        spans = sorted(self.machinery)
        starts = [s for s, _ in spans]
        ends_max = []
        best = -1
        for _, e in spans:
            best = max(best, e)
            ends_max.append(best)

        def inside(node) -> bool:
            i = bisect_right(starts, node.start_byte) - 1
            return i >= 0 and ends_max[i] >= node.end_byte

        sites = []
        for call, b in string_calls:
            if inside(call):
                continue
            res.calls += 1
            try:
                value = self.apply_call(call)
            except (Unsupported, Thrown) as exc:
                self.problems[_problem(exc)] = None
                continue
            if not isinstance(value, str):
                self.problems["calls that read outside the string table" if value is UNDEF
                              else "calls whose value is not a text"] = None
                continue
            res.resolved += 1
            sites.append((call, value))
        for t in self.used.values():
            if t.problem:
                self.problems[t.problem] = None
        spans = self._spans(sites)
        if PROXIES_ON and spans:
            # the helper step counts its own steps: what the table gave is never lost to it (2026-11-04:
            # counted on the table's budget, a 31,000-text table resolved in full was then thrown away)
            used, self.steps = self.steps, 0
            found: List[tuple] = []
            try:
                self._proxies(sites, spans, found)
            except OutOfSteps:
                pass                               # (the helpers put back so far stay; the rest as they are)
            finally:
                self.steps = used
            spans += found
        return spans

    def apply_call(self, call):
        return self.ev(call, {}, 0)

    # ---- helper objects (control-flow flattening of the "high" preset; part 2, 2026-11-03) ----
    def _key_of(self, node, resolved: Dict[int, str]) -> Optional[str]:
        """The text a property key or index stands for: a written text, a name, or a resolved call."""
        if node is None:
            return None
        if node.type == "string":
            return js_string(self.text(node))
        if node.type == "property_identifier":         # (a key of a pair, a member's name)
            return self.text(node)
        if node.type == "computed_property_name" and node.named_child_count == 1:
            return self._key_of(node.named_children[0], resolved)
        if node.type == "call_expression" and node.id in resolved:
            return resolved[node.id]
        if node.type in ("call_expression", "binary_expression", "parenthesized_expression"):
            return self._text_value(node)
        return None

    def _proxy_shape(self, fn) -> Optional[tuple]:
        """``function(a, b, c) { return a(b, c); }`` -> ("call", 2); ``function(a, b) { return a + b; }`` ->
        ("op", "+"); anything else -> None."""
        if fn.end_byte - fn.start_byte > MAX_FUNCTION:
            return None
        params = self._params(fn)
        if not params or len(set(params)) != len(params):
            return None
        body = fn.child_by_field_name("body")
        if body is None:
            return None
        if body.type == "statement_block":
            stmts = [c for c in body.named_children if c.type != "comment"]
            if len(stmts) != 1 or stmts[0].type != "return_statement" or stmts[0].named_child_count != 1:
                return None
            e = stmts[0].named_children[0]
        else:
            e = body
        if e.type == "call_expression":
            f, args = e.child_by_field_name("function"), e.child_by_field_name("arguments")
            if f is not None and f.type == "identifier" and self.text(f) == params[0] and args is not None \
                    and args.type == "arguments" and [self.text(a) for a in args.named_children] == params[1:] \
                    and all(a.type == "identifier" for a in args.named_children):
                return ("call", len(params) - 1)
            return None
        if e.type == "binary_expression" and len(params) == 2:
            left, right, op = e.child_by_field_name("left"), e.child_by_field_name("right"), \
                e.child_by_field_name("operator")
            if left is not None and right is not None and op is not None and left.type == right.type == "identifier" \
                    and [self.text(left), self.text(right)] == params:
                return ("op", self.text(op))
        return None

    def _entry(self, value, resolved: Dict[int, str]) -> Optional[tuple]:
        """What one member of a helper object is: a text, a call helper or an operator helper (else None)."""
        if value.type == "string":
            return ("text", js_string(self.text(value)))
        if value.type == "call_expression" and value.id in resolved:
            return ("text", resolved[value.id])
        if value.type in ("function_expression", "function", "arrow_function"):
            return self._proxy_shape(value)
        if value.type in ("binary_expression", "parenthesized_expression", "call_expression", "template_string"):
            text = self._text_value(value)               # (texts joined by "+", table calls: the evaluator)
            return ("text", text) if text is not None else None
        return None

    def _text_value(self, node) -> Optional[str]:
        try:
            value = self.ev(node, {}, 0)
        except (Unsupported, Thrown):
            return None
        return value if isinstance(value, str) else None

    def _proxy_object(self, b: Binding, resolved: Dict[int, str], written) -> Optional[Dict[str, tuple]]:
        """The entries of a helper object: a name bound once to an object literal and never assigned again,
        each entry a text, a call helper or an operator helper - from the literal and from writes of the
        form ``obj['k'] = ...`` (the obfuscator's "object keys" step), when those are all the writes of its
        members and no key is written twice."""
        key = ("proxy", id(b))
        if key in self.memo:
            return self.memo[key]
        out: Optional[Dict[str, tuple]] = None
        writes = written.get(id(b), [])
        if b.kind == "var" and not b.ambiguous and b.value is not None and b.value.type == "object"                 and not b.writes and len(writes) == self.member_writes.get(b.name, 0):
            entries: Dict[str, tuple] = {}
            seen: set = set()
            for pair in b.value.named_children:
                self.tick()
                if pair.type != "pair":
                    continue
                name = self._key_of(pair.child_by_field_name("key"), resolved)
                value = pair.child_by_field_name("value")
                if name is None or value is None:
                    continue
                seen.add(name)
                entry = self._entry(value, resolved)
                if entry is not None:
                    entries[name] = entry
            twice = False
            for name, value in writes:
                self.tick()
                if name is None or name in seen:
                    twice = True
                    break
                seen.add(name)
                entry = self._entry(value, resolved)
                if entry is not None:
                    entries[name] = entry
            out = None if twice else (entries or None)
        self.memo[key] = out
        return out

    def _proxies(self, sites, spans, out: List[tuple]) -> None:
        """Each use of a helper object put back: ``obj.k(f, x)`` -> ``f(x)``, ``obj.k(a, b)`` -> ``(a + b)``,
        ``obj.k`` (a text) -> the text - built from the arguments with every replacement inside them made
        first (innermost first), so ``obj.k(require, obj.m)`` reads ``require('fs')``. Nothing is run."""
        resolved = {call.id: value for call, value in sites}
        uses = []                                  # member reads on a name: (node, its object, its parent)
        written: Dict[int, list] = {}             # binding -> [(key, value node)] of obj['k'] = value
        cursor = self.tree.walk()
        parents: List[object] = []                # the nodes above the cursor (no parent lookups: see scope_of)
        while True:
            node = cursor.node
            self.tick()
            parent = parents[-1] if parents else None
            if node.type in ("member_expression", "subscript_expression"):
                obj = node.child_by_field_name("object")
                if obj is not None and obj.type == "identifier":
                    left = parent.child_by_field_name("left") if parent is not None and \
                        parent.type == "assignment_expression" else None
                    if left is not None and left.id == node.id:
                        try:
                            b = self.binding_at(obj)
                        except Unsupported:
                            b = None
                        if b is not None:
                            written.setdefault(id(b), []).append((self._member_key(node, resolved),
                                                                  parent.child_by_field_name("right")))
                    elif len(uses) < MAX_SITES:
                        uses.append((node, obj, parent))
            if cursor.goto_first_child():
                parents.append(node)
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    break
                parents.pop()
            else:
                continue
            break
        found = []                                 # (node to replace, entry)
        for node, obj, parent in uses:
            self.tick()
            key = self._member_key(node, resolved)
            if key is None:
                continue
            try:
                b = self.binding_at(obj)
            except Unsupported:
                continue
            entries = self._proxy_object(b, resolved, written) if b is not None else None
            entry = entries.get(key) if entries else None
            if entry is None:
                continue
            callee = parent.child_by_field_name("function") if parent is not None and \
                parent.type == "call_expression" else None
            is_callee = callee is not None and callee.id == node.id
            if is_callee and entry[0] in ("call", "op"):
                found.append((parent, entry))
            elif not is_callee and entry[0] == "text" and not (
                    parent is not None and parent.type in ("augmented_assignment_expression", "update_expression")):
                found.append((node, entry))
        if not found:
            return
        base = sorted(spans, key=lambda s: (s[0], -s[1]))       # the texts put back (fixed)
        lists = (base, [(s[0], -s[1]) for s in base], [], [])    # + the helpers put back (grows)
        self.proxy_work = 0
        # (each helper put back is added to ``out`` at once: a stop at the bound keeps them)
        for node, entry in sorted(found, key=lambda f: (f[0].end_byte - f[0].start_byte, f[0].start_byte)):
            if self.proxy_work > MAX_PROXY_WORK:
                break                              # (a bound of its own: the texts already put back stay)
            if entry[0] == "text":
                text = literal(entry[1])
            else:
                args = node.child_by_field_name("arguments")
                items = list(args.named_children) if args is not None and args.type == "arguments" else []
                if entry[0] == "call":
                    if len(items) != entry[1] + 1:
                        continue
                    callee = self._render(items[0], lists)
                    if items[0].type not in ("identifier", "member_expression", "subscript_expression",
                                             "call_expression", "parenthesized_expression", "this"):
                        callee = "(" + callee + ")"
                    text = "%s(%s)" % (callee, ", ".join(self._render(a, lists) for a in items[1:]))
                else:
                    if len(items) != 2:
                        continue
                    text = "(%s %s %s)" % (self._render(items[0], lists), entry[1], self._render(items[1], lists))
            text = text.replace("\r", " ").replace("\n", " ")
            if len(text) > MAX_TEXT:
                continue
            span = (node.start_byte, node.end_byte, text, text)
            at = bisect_right(lists[3], (span[0], -span[1]))
            lists[2].insert(at, span)
            lists[3].insert(at, (span[0], -span[1]))
            out.append(span)
        return

    def _member_key(self, member, resolved: Dict[int, str]) -> Optional[str]:
        if member.type == "member_expression":
            return self._key_of(member.child_by_field_name("property"), resolved)
        return self._key_of(member.child_by_field_name("index"), resolved)

    def _render(self, node, lists) -> str:
        """The text of ``node`` with every replacement inside it made (the outermost of nested ones): the
        texts put back and the helpers already put back, merged in order. Counted in ``proxy_work``."""
        start, end = node.start_byte, node.end_byte
        inside = []
        for spans, keys in ((lists[0], lists[1]), (lists[2], lists[3])):
            i = bisect_right(keys, (start, -(1 << 62)))
            while i < len(spans) and spans[i][0] < end:
                self.proxy_work += 1
                if spans[i][1] <= end:
                    inside.append(spans[i])
                i += 1
        inside.sort(key=lambda s: (s[0], -s[1]))
        out, at = [], start
        for s in inside:
            if s[0] < at:
                continue
            out.append(self.data[at:s[0]].decode("utf-8", "surrogatepass"))
            out.append(s[2])
            at = s[1]
        out.append(self.data[at:end].decode("utf-8", "surrogatepass"))
        self.proxy_work += 1 + (end - start) // 64
        return "".join(out)

    def _ev_text(self, node) -> Optional[str]:
        try:
            v = self.ev(node, {}, 0)
        except (Unsupported, Thrown):
            return None
        return v if isinstance(v, str) else None

    def _fold(self, node, known: Dict[int, Optional[str]]) -> Optional[str]:
        """The text of a ``+`` / parenthesised expression from its parts' texts (known ones first), each node
        once, without recursion; a part that is not plainly a text goes to the evaluator (numbers ...)."""
        stack = [(node, False)]
        while stack:
            n, ready = stack.pop()
            if n.id in known:
                continue
            t = n.type
            if t == "string":
                known[n.id] = js_string(self.text(n))
                continue
            if t == "parenthesized_expression" and n.named_child_count == 1:
                kids = [n.named_children[0]]
            elif t == "binary_expression" and n.child_by_field_name("operator").type == "+":
                kids = [n.child_by_field_name("left"), n.child_by_field_name("right")]
            else:
                known[n.id] = self._ev_text(n)
                continue
            if not ready:
                stack.append((n, True))
                stack.extend((k, False) for k in kids if k is not None)
                continue
            self.tick()
            parts = [known.get(k.id) if k is not None else None for k in kids]
            joined = "".join(parts) if all(isinstance(p, str) for p in parts) else None
            known[n.id] = joined if joined is not None and len(joined) <= MAX_TEXT else self._ev_text(n)
        return known.get(node.id)

    def _spans(self, sites) -> List[Tuple[int, int, str]]:
        """Each resolved call as (start, end, replacement): a quoted literal; ``obj[call]`` as
        ``obj.name``; a ``+`` of texts around it folded into one literal."""
        out = []
        # (each "+" node is valued once and each chain climbed once: evaluating the whole chain above every
        # call in it was quadratic - the long "a" + "b" + ... chains of split texts used up the reading's
        # budget after every call had been resolved; part 2, 2026-11-04)
        known: Dict[int, Optional[str]] = {call.id: value for call, value in sites}
        tops: Dict[int, tuple] = {}                  # "+" node -> (outermost text node above it, its text)
        emitted: set = set()                         # nodes whose span is made
        for call, value in sites:
            node, text = call, value
            up = node.parent
            climbed = []
            while up is not None and up.type in ("binary_expression", "parenthesized_expression"):
                if up.id in tops:
                    node, text = tops[up.id]
                    break
                if up.type == "binary_expression" and up.child_by_field_name("operator").type != "+":
                    break
                v = known[up.id] if up.id in known else self._fold(up, known)
                if not isinstance(v, str):
                    break
                climbed.append(up.id)
                node, text = up, v
                up = up.parent
            for i in climbed:
                tops[i] = (node, text)
            if node.id in emitted:
                continue                           # (one span per chain: the others were skipped by the rebuild)
            emitted.add(node.id)
            parent = node.parent
            if parent is not None and parent.type == "subscript_expression" and _IDENTIFIER.match(text) \
                    and parent.child_by_field_name("index") is not None \
                    and parent.child_by_field_name("index").id == node.id:
                obj = parent.child_by_field_name("object")
                optional = parent.child_by_field_name("optional_chain") is not None
                out.append((obj.end_byte, parent.end_byte, ("?." if optional else ".") + text, text))
            else:
                out.append((node.start_byte, node.end_byte, literal(text), text))
        return out


def _problem(exc: Exception) -> str:
    if isinstance(exc, Thrown):
        return "calls whose decoding would fail when the script runs"
    said = str(exc) or "a form it does not read"
    if said.startswith("its "):
        return said
    return "calls that use %s" % said


def candidate(text: str) -> bool:
    """A quick, deterministic look: could this script hold an obfuscator's string table?"""
    if _TABLE_FUNCTION.search(text):
        return True
    return bool(_TEXT_ARRAY.search(text) and _OBF_SHAPE.search(text))


def resolve(text: str) -> Optional[Resolution]:
    """The string-table reading of a JavaScript text, or None when there is nothing to say (the switch
    is off, the parser is not available, or the text holds no obfuscator's table). Never raises,
    never runs the script."""
    if not (ON and jsparse.available()) or not candidate(text):
        return None
    res = Resolution()
    data = text.encode("utf-8", "surrogatepass")
    parsed = jsparse.parse(data)
    if not parsed.ok:
        res.limit = parsed.limit
        return res
    reader = _Reader(data, parsed.tree)
    stopped = True
    try:
        reader.read()
        spans = reader.run(res)
        stopped = False
    except OutOfSteps:
        res.problems.append("the reading stopped at its limit of %d steps" % MAX_STEPS)
    except (Unsupported, Thrown, RecursionError, ValueError, IndexError) as exc:   # never take the scan down
        res.problems.append("the reading stopped (%s)" % type(exc).__name__)
    else:
        res.problems.extend(reader.problems)
        if spans:
            res.text = _rebuild(data, spans, res)
    res.tables = len(reader.used)
    res.texts = sum(len(t.texts) for t in reader.used.values())
    noted_before = res.needs_note                  # (what the note was until 2026-11-08)
    if UNREAD_TABLE_NOTE_ON:
        # a table recognised but read by no decoder this module knows is said, never guessed (2026-11-08)
        try:
            res.unread_tables, res.unread_texts = reader.unread_tables()
        except (OutOfSteps, RecursionError, ValueError, IndexError):
            res.unread_tables = res.unread_texts = 0
        if res.unread_tables:
            res.problems.append(UNREAD_TABLE_STOPPED if stopped else UNREAD_TABLE)
        res.information = res.needs_note and not noted_before
    if not res.tables and not res.unread_tables:
        return None
    if res.text is None:
        res.values = []
    return res


def _rebuild(data: bytes, spans, res: Resolution) -> str:
    """The text with each span replaced, outermost first; a replaced span's line breaks are kept
    after it, so every line stays where it was."""
    spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    out = []
    at = 0
    for start, end, replacement, value in spans:
        if start < at:
            continue                                   # inside a span already replaced
        out.append(data[at:start])
        out.append(replacement.encode("utf-8", "surrogatepass"))
        out.append(b"\n" * data.count(b"\n", start, end))
        res.values.append((start, end, value))
        at = end
    out.append(data[at:])
    return b"".join(out).decode("utf-8", "surrogatepass")
