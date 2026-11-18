"""C1: private data -> network flow in JavaScript (phase C, JS group, part 2; phageo, 2026-11-02 / 11-03).

A stealer reads what the user's browsers, Discord or crypto wallets keep (or what an add-on decrypts for
it) and sends it out. The older findings name the parts - a store named in a text (``CRED-001``), a
network call (``JS-NET-001``), a decrypting add-on (``ADDON-DECRYPT-001``), the three across one app
(``CHAIN-STEALER``) - but nothing proves that the data travels from one to the other. This module
follows it, on the syntax tree (:mod:`gamescan.jsparse`), without running anything (rule 2):

``source``  a read of a file whose path - joined from its pieces, through variables, loops over arrays
            of paths, function parameters - is a browser's, Discord's or a wallet's store
            (:data:`gamescan.stealer.STORES`), also a database opened on such a path or on a copy of
            it; the result of a call into an add-on reached by ``require`` (the scanner then checks
            that the add-on is a decrypting one, ``ADDON_FLOWS``); behind their own switch
            (:data:`CAPTURE_ON`), the clipboard and the screen
``flow``    through variables, object and array literals, texts built with ``+`` and templates,
            function parameters and return values, callbacks and promise chains, member writes,
            any call that is not known (its result carries what went in)
``sink``    a network call: ``fetch``, ``XMLHttpRequest``, ``http`` / ``https`` requests and what is
            written into them, sockets, WebSockets, socket.io, axios / got / request / superagent /
            needle / node-fetch / undici, ``navigator.sendBeacon``, form uploads, mail

Names are bound by scope (``var`` to its function, ``let`` / ``const`` / ``class`` to their block),
so two variables of the same name are never mixed. **Branches are kept apart:** a value written in
one arm of an ``if`` or ``?:`` does not reach a use in the other arm. The text read is the script
with its string table put back (:mod:`gamescan.dataflow.jsstrings`, C2) when it has one.

Tiers (``roadmap-1.0.md``; phageo, 2026-11-03): a flow from a browser / Discord / wallet store or from
a decrypting add-on is MALICE (``CHAIN-EXFIL`` CRITICAL, and ``CHAIN-STEALER`` of the same app keeps
CRITICAL - :data:`RAISE_ON`); a flow from the clipboard or the screen is CHAIN only (HIGH). Nothing is
lowered by this module; without a proven flow everything stays as it was.

Limits (rule 3; counts, so the same file gives the same answer on every PC): the parser's own
(``jsparse``), :data:`MAX_STEPS` evaluation steps per file, :data:`MAX_DEPTH` nesting of one
evaluation, :data:`MAX_VARIANTS` texts per value, :data:`MAX_TEXT` characters per text,
:data:`MAX_LABELS` labels per value, :data:`MAX_FLOWS` flows reported per file. A reading that
reaches a limit adds nothing (it never takes the scan down and never lowers anything); the reason is
kept for the diagnosis tools (``Result.limit``).
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/exfil.py")

import re
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple

from .. import jsparse, stealer, tiers
from . import jsstrings

ON = True                       # C1: store / decrypted-data sources -> network (MALICE)
CAPTURE_ON = True               # clipboard and screen sources (CHAIN only; phageo, 2026-11-03)
RAISE_ON = True                 # a proven flow keeps CHAIN-STEALER of the same app CRITICAL (MALICE)

RULE = "CHAIN-EXFIL"
CACHE = "exfil_addon_flows"     # FileContext.cache: flows from an add-on call, for the scanner's join
SUMMARY = "exfil_summary"       # FileContext.cache: (exports, sink_imports, verified) for the cross-file join
LIMIT = "exfil_limit"           # FileContext.cache: why the reading stopped early (diagnosis only)
PROVEN = tiers.PROVEN           # Finding.context key of a CHAIN-STEALER whose app has a proven flow
STORE_KINDS = ("browser", _IND[0], "wallet")
DECRYPTED = "decrypted"         # the kind of a flow from a decrypting add-on (after the join)
MALICE_KINDS = frozenset(STORE_KINDS + (DECRYPTED,))
CAPTURE_KINDS = ("clipboard", "screen")

MAX_BYTES = 8 * 1024 * 1024     # the largest script read for flows (a larger one adds nothing; the parse
                                # and the reading grow with it - the app scripts phase A names are under 2 MB)
MAX_STEPS = 3_000_000           # evaluation steps per file
MAX_DEPTH = 120                 # nesting of one evaluation
MAX_VARIANTS = 24               # texts one value may stand for (more -> unknown)
MAX_TEXT = 4096                 # characters of one text
MAX_LABELS = 24                 # labels one value may carry
MAX_FLOWS = 8                   # flows reported per file
MAX_ADDONS = 16                 # add-on modules followed per file
MAX_UP = 4000                   # parent steps when a node's scope or branch is looked for
MAX_SITES = 400                 # call sites / callback sites read per function
ROUNDS = 3                      # passes over the sinks (values that depend on each other in a loop)
MAX_IMPORT_SINKS = 16           # (cross-file) imports used at a sink kept per file
MAX_EXPORT_POINTS = 400         # (cross-file) export points read per file

ANY = "\x00"                    # an unknown part of a text

# a value imported from a relative module of the same app (``require("./a")`` / ``import ... from
# "./a"``): a label ``mod:<spec>::<name>`` carried through the flow exactly as a store label is, so
# the cross-file join (``exfil_cross.py``, C1 part 2b) can tell which export of which module a sink
# consumes, and whether that export reads a store in another file. Collected only when the cross-file
# switch is on (``exfil_cross.ON``); off -> not emitted and the per-file reading is byte-identical.
MOD = "mod:"


def _collect_imports() -> bool:
    from . import exfil_cross
    return bool(exfil_cross.ON)


def _rank(label: str) -> int:
    """Order for the :data:`MAX_LABELS` cut: private data first, then an add-on call, then an import
    reference (so a store label is never pushed out by the cross-file ``mod:`` labels)."""
    if label.startswith("addon:"):
        return 1
    if label.startswith(MOD):
        return 2
    return 0

# a cheap look before the parse: a source and a sink must both be named somewhere
# (reads only - writing to the clipboard or a word "screenshot" is no source; an add-on by its file or loader)
_CAPTURE_HINT = re.compile(r"clipboard\s*\.\s*read|desktopcapturer|getdisplaymedia|screenshot-desktop|capturepage|"
                           r"clipboardy|copy-paste|node-screenshots|robotjs", re.I)
_ADDON_HINT = re.compile(r"\.node['\"`]|unprotect|dpapi|\bbindings\s*\(|node-gyp-build", re.I)
_SINK_HINT = re.compile(_IND[1], re.I)
# (cross-file) a relative require / import / dynamic import of the app's own files
_REL_IMPORT_HINT = re.compile(r"require\s*\(\s*['\"`]\.|import\s*\(\s*['\"`]\.|from\s*['\"`]\.|import\s+['\"`]\.", re.I)
# (cross-file) a module that exports something (it may forward another module's export)
_EXPORT_HINT = re.compile(r"module\s*\.\s*exports|(?<![\w$.])exports\s*[.\[]|(?<![\w$.])export\s+", re.I)

# -- what the names stand for --------------------------------------------------------------------
_REQUIRES = frozenset({"require", "window.require", "nw.require", "module.require", "__non_webpack_require__",
                       "globalThis.require", "global.require"})
_READS = frozenset({"readFileSync", "readFile", "createReadStream", "readFileAsync", "readJson", "readJsonSync",
                    "readJSON", "Database", "Level", "ClassicLevel", "level", "open", "openSync", "verbose"})
_COPIES = frozenset({"copyFileSync", "copyFile", "cpSync", "cp", "copy", "copySync", "copyFileAsync"})
_BUILTINS = frozenset("""assert buffer child_process cluster console constants crypto dgram dns domain events fs
fs/promises http http2 https inspector module net os path perf_hooks process punycode querystring readline repl
stream string_decoder sys timers tls tty url util v8 vm worker_threads zlib electron original-fs""".split())
# network: modules whose every call goes out, builtins / globals whose named calls or objects do
_NET_MODULES = frozenset(_IND[2].split())
_NET_CALLS = frozenset("""fetch window.fetch self.fetch globalThis.fetch http.request https.request http.get https.get
http2.connect net.connect net.createConnection tls.connect electron.net.request navigator.sendBeacon
window.navigator.sendBeacon $.ajax $.post $.get $.getJSON jQuery.ajax jQuery.post jQuery.get""".split())
_NET_OBJECTS = frozenset("""XMLHttpRequest() window.XMLHttpRequest() WebSocket() window.WebSocket() net.Socket()
http.ClientRequest() http.request() https.request() http.get() https.get() http2.connect() net.connect()
net.createConnection() tls.connect() electron.net.request() dgram.createSocket()""".split())
_SENDS = frozenset({"write", "end", "send", "emit", "submit", "pipe", "sendUTF", "sendBytes", "field", "attach",
                    "form", "json", "post", "put", "patch", "request", "sendMail", "setRequestHeader", "open"})
# when nothing says what the receiver is: these names go out only with a written address
_ADDRESS_CALLS = frozenset({"post", "put", "patch", "request", "get", "send", "sendBeacon", "fetch"})
_CLIPBOARD = frozenset("""electron.clipboard.readText electron.clipboard.readImage electron.clipboard.readHTML
electron.clipboard.readRTF electron.clipboard.readBuffer electron.clipboard.read electron.remote.clipboard.readText
navigator.clipboard.readText navigator.clipboard.read window.navigator.clipboard.readText clipboardy.read
clipboardy.readSync clipboardy.default.read clipboardy.default.readSync copy-paste.paste
nw.Clipboard.get().get""".split())
_SCREEN = frozenset("""electron.desktopCapturer.getSources navigator.mediaDevices.getDisplayMedia
window.navigator.mediaDevices.getDisplayMedia screenshot-desktop screenshot-desktop.listDisplays
screenshot-desktop.all node-screenshots robotjs.screen.capture""".split())
_SCREEN_METHODS = frozenset({"capturePage"})        # webContents / BrowserWindow capture (any receiver)
_ELEMENTS = frozenset({"forEach", "map", "filter", "find", "some", "every", "flatMap", "findLast", "reduce"})
_COLLECT = frozenset({"append", "push", "unshift", "set", "add", "splice", "write", "writeSync"})
_THROUGH = frozenset({"then", "catch", "finally"})
_SCOPES = frozenset({"program", "function_declaration", "function_expression", "function", "arrow_function",
                     "method_definition", "generator_function_declaration", "generator_function", "catch_clause",
                     "class_static_block", "statement_block", "for_statement", "for_in_statement", "class_body"})
_FUNCTIONS = frozenset({"function_declaration", "function_expression", "function", "arrow_function",
                        "method_definition", "generator_function_declaration", "generator_function"})
_FUNCTION_SCOPES = _FUNCTIONS | {"program", "class_static_block"}
_PATTERNS = frozenset({"object_pattern", "array_pattern", "assignment_pattern", "rest_pattern", "pair_pattern",
                       "object_assignment_pattern", "shorthand_property_identifier_pattern", "identifier"})


class OutOfSteps(Exception):
    pass


class Def(NamedTuple):
    kind: str           # var, part, param, each, assign, member, function, import, catch, class
    at: object          # the node that defines (for the branch test)
    value: object       # the value node (or the function node, the iterable ...)
    extra: object       # param index, import (module, name), key of a destructured part


class Binding:
    __slots__ = ("name", "defs")

    def __init__(self, name: str):
        self.name = name
        self.defs: List[Def] = []


class Flow(NamedTuple):
    kind: str           # browser / Discord / wallet / clipboard / screen / "addon:<module>"
    source_line: int
    sink: str           # the network call, by its name
    line: int           # the sink's line


class Result:
    def __init__(self):
        self.flows: List[Flow] = []           # store and capture flows, ready to be findings
        self.addon_flows: List[Flow] = []     # flows from a call into a required module (joined later)
        self.limit = ""                       # why the reading stopped early ("" = it read the file)
        self.sinks = 0                        # network calls looked at
        # C1 part 2b (cross-file, exfil_cross.py): what this script exports and the imports its sinks use
        self.exports: Dict[str, FrozenSet[str]] = {}       # export name -> labels its value carries
        self.sink_imports: List[Tuple[str, str, int, str]] = []   # (relative spec, name, sink line, sink)


def _names_source(text: str, low: str) -> bool:
    return (any(word in low for word in stealer._ANCHORS) or bool(_ADDON_HINT.search(text))
            or (CAPTURE_ON and bool(_CAPTURE_HINT.search(text))))


def candidate(text: str) -> bool:
    """A quick, deterministic look: is this script worth parsing? Per file: it names a private-data
    source and a network sink. Cross-file (``exfil_cross.ON``): also a script that only names a source
    (it may export it) or that has a sink and a relative import (it may consume another file's export)."""
    low = text.lower()
    if _collect_imports():
        if _names_source(text, low):
            return True                                # a source: it may export what it reads
        if _REL_IMPORT_HINT.search(text) and (_SINK_HINT.search(text) or _EXPORT_HINT.search(text)):
            return True                                # a sink that imports, or a module that re-exports
    if not _SINK_HINT.search(text):
        return False
    return _names_source(text, low)


def parse_shared(data: bytes, trees: Optional[dict] = None):
    """``jsparse.parse(data)``, once per text for the readers of one script (C1 and C3 read the same
    text): ``trees`` is a dict the caller keeps only while it hands one script to its readers."""
    if trees is not None:
        got = trees.get("parsed")
        if got is not None and got[0] == data:
            return got[1]
    parsed = jsparse.parse(data)
    if trees is not None:
        trees["parsed"] = (data, parsed)
    return parsed


def analyse(text: str, trees: Optional[dict] = None) -> Optional[Result]:
    """The private-data flows of a JavaScript text, or None when there is nothing to read (the switch
    is off, the parser is not available, or the text names no source or no sink). Never raises.
    ``trees``: see :func:`parse_shared`."""
    if not ON or not jsparse.available() or not candidate(text):
        return None
    out = Result()
    if len(text) > MAX_BYTES:
        out.limit = "the script is larger than %d MB" % (MAX_BYTES >> 20)
        return out
    data = text.encode("utf-8", "surrogatepass")
    parsed = parse_shared(data, trees)
    if not parsed.ok:
        out.limit = parsed.limit
        return out
    reader = _Reader(data, parsed.tree)
    try:
        reader.read()
        reader.run(out)
    except OutOfSteps:
        out.limit = "the reading stopped at its limit of %d steps" % MAX_STEPS
    except (RecursionError, ValueError, IndexError, KeyError, AttributeError, TypeError) as exc:
        out.limit = "the reading stopped (%s)" % type(exc).__name__
    return out


def store_kinds(texts) -> List[str]:
    """The store kinds the texts (unknown parts as :data:`ANY`) name."""
    found: Set[str] = set()
    for t in texts:
        if t == ANY or not t.strip(ANY):
            continue
        found.update(stealer.store_kinds(t.replace(ANY, "*")))
    return [k for k in STORE_KINDS if k in found]


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _root(name: str) -> str:
    """The module or global a dotted name begins with (``@scope/pkg.fn`` -> ``@scope/pkg``)."""
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        return scope + "/" + rest.split(".", 1)[0]
    return name.split(".", 1)[0]


def _module(text: str) -> str:
    text = text.strip()
    return text[5:] if text.startswith("node:") else text


class _Reader:
    def __init__(self, data: bytes, tree):
        self.data, self.tree = data, tree
        self.steps = 0
        self.scopes: Dict[int, Dict[str, Binding]] = {}
        self.calls: List[object] = []
        self.returns: Dict[int, List[object]] = {}
        self.functions: Dict[int, object] = {}
        self.methods: Dict[str, List[object]] = {}
        self.pending: List[Tuple[object, object, object]] = []    # (left identifier or root, value, at)
        self.call_sites: Dict[int, List[object]] = {}
        self.callbacks: Dict[int, List[Tuple[object, int]]] = {}
        self.copied: Dict[int, Set[str]] = {}                       # binding id -> store kinds of a copy
        self.copied_texts: Dict[str, Set[str]] = {}
        self.memo: Dict[int, FrozenSet] = {}
        self.prev: Dict[int, FrozenSet] = {}
        self.busy: Set[int] = set()
        self.texts: Dict[int, FrozenSet[str]] = {}
        self.text_busy: Set[int] = set()
        self.apis: Dict[int, FrozenSet[str]] = {}
        self.api_busy: Set[int] = set()
        self.branches: Dict[int, Dict[int, int]] = {}
        self.addons: Set[str] = set()
        self.bound: Dict[int, Optional[Binding]] = {}             # identifier node -> its binding (memo)
        self.where: Dict[int, Tuple[int, tuple]] = {}               # node -> (scope id, arms of if / ?:)
        self.scope_parent: Dict[int, Optional[int]] = {}            # scope id -> the scope around it
        self.this_owner: Dict[int, int] = {}                        # `this` node -> its class / function
        self.imp: Dict[int, object] = {}                            # node -> its relative-import (spec, name) or None (memo)
        self.collect_imports = _collect_imports()                   # cross-file: emit mod: labels (exfil_cross.ON)

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise OutOfSteps()

    def text(self, node) -> str:
        return self.data[node.start_byte:node.end_byte].decode("utf-8", "surrogatepass")

    @staticmethod
    def line(node) -> int:
        return node.start_point[0] + 1

    # ---- one walk: scopes, declarations, writes, calls, returns ----
    # (tree-sitter finds a node's parent by walking down from the root, so nothing here walks up: the
    # walk notes for every name and every place a value is written its scope and its arms of if / ?:)
    _NOTED = frozenset({"identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern",
                        "this", "variable_declarator", "assignment_expression", "augmented_assignment_expression",
                        "call_expression", "new_expression", "for_in_statement", "catch_clause", "import_specifier",
                        "class_declaration"}) | _FUNCTIONS
    _THIS_OWNERS = frozenset({"class_body", "function_declaration", "function_expression", "function",
                              "generator_function", "generator_function_declaration", "program"})

    def read(self) -> None:
        cursor = self.tree.walk()
        depth = 0
        nodes: List[object] = []                  # the node at each depth above the cursor
        scopes: List[Tuple[int, object]] = []      # (depth, scope node) around the cursor
        arms: List[Tuple[int, tuple]] = []         # (depth, arms so far) - the if / ?: arms around
        while True:
            node = cursor.node
            field = cursor.field_name
            self.tick()
            del nodes[depth:]
            while scopes and scopes[-1][0] >= depth:
                scopes.pop()
            while arms and arms[-1][0] >= depth:
                arms.pop()
            parent = nodes[-1] if nodes else None
            if parent is not None and parent.type in ("if_statement", "ternary_expression") \
                    and field in ("consequence", "alternative"):
                arms.append((depth, (arms[-1][1] if arms else ()) + ((parent.id, 0 if field == "consequence" else 1),)))
            t = node.type
            outer = scopes[-1][1] if scopes else node
            if t in _SCOPES:
                self.scope_parent[node.id] = outer.id if scopes else None
                self.scopes.setdefault(node.id, {})
                scopes.append((depth, node))
            if t in self._NOTED:
                self.where[node.id] = (scopes[-1][1].id if scopes else node.id, arms[-1][1] if arms else ())
            if t in _FUNCTIONS:
                self.functions[node.id] = node
                self._function(node, outer)
            elif t == "variable_declarator":
                lexical = parent is not None and parent.type == "lexical_declaration"
                self._declarator(node, scopes[-1][1] if lexical else self._function_scope(scopes))
            elif t == "for_in_statement":
                self._for_in(node, self._function_scope(scopes))
            elif t == "catch_clause":
                p = node.child_by_field_name("parameter")
                if p is not None:
                    for ident, key in self._pattern(p):
                        self._declare(node, ident, Def("catch", node, None, None))
            elif t == "class_declaration":
                n = node.child_by_field_name("name")
                if n is not None:
                    self._declare(outer, n, Def("class", node, node, None))
            elif t == "import_statement":
                self._import(node)
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                if left is not None and right is not None:
                    self.pending.append((left, right, node))
            elif t in ("call_expression", "new_expression"):
                self.calls.append(node)
            elif t == "return_statement":
                fn = next((n for _d, n in reversed(scopes) if n.type in _FUNCTIONS or n.type == "program"), None)
                if fn is not None and fn.type != "program" and node.named_child_count:
                    self.returns.setdefault(fn.id, []).append(node.named_children[0])
            elif t == "this":
                owner = next((n for _d, n in reversed(scopes) if n.type in self._THIS_OWNERS), None)
                if owner is not None:
                    self.this_owner[node.id] = owner.id
            elif t == "pair":
                key, value = node.child_by_field_name("key"), node.child_by_field_name("value")
                if key is not None and value is not None and value.type in _FUNCTIONS:
                    self.methods.setdefault(self._key(key), []).append(value)
            if cursor.goto_first_child():
                nodes.append(node)
                depth += 1
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    self._settle()
                    return
                depth -= 1

    @staticmethod
    def _function_scope(scopes):
        for _d, n in reversed(scopes):
            if n.type in _FUNCTION_SCOPES:
                return n
        return scopes[0][1]

    def _key(self, key) -> str:
        if key.type == "string":
            return jsstrings.js_string(self.text(key))
        return self.text(key)

    def _function(self, fn, outer) -> None:
        t = fn.type
        name = fn.child_by_field_name("name")
        if name is not None:
            if t in ("function_declaration", "generator_function_declaration"):
                self._declare(outer, name, Def("function", fn, fn, None))
            elif t == "method_definition":
                self.methods.setdefault(self.text(name), []).append(fn)
            elif name.type == "identifier":
                self._declare(fn, name, Def("function", fn, fn, None))
        params = fn.child_by_field_name("parameters")
        if params is None:
            p = fn.child_by_field_name("parameter")
            if p is not None:
                self._declare(fn, p, Def("param", p, fn, (0, None)))
            if t == "arrow_function":
                body = fn.child_by_field_name("body")
                if body is not None and body.type != "statement_block":
                    self.returns.setdefault(fn.id, []).append(body)
            return
        for index, p in enumerate(params.named_children):
            for ident, key in self._pattern(p):
                self._declare(fn, ident, Def("param", ident, fn, (index, key)))
        if t == "arrow_function":
            body = fn.child_by_field_name("body")
            if body is not None and body.type != "statement_block":
                self.returns.setdefault(fn.id, []).append(body)

    def _pattern(self, node, key=None) -> List[Tuple[object, Optional[str]]]:
        """The names a declaration pattern binds, each with the key it takes (None: the whole value)."""
        out = []
        stack = [(node, key)]
        while stack:
            self.tick()
            n, k = stack.pop()
            t = n.type
            if t in ("identifier", "shorthand_property_identifier_pattern"):
                out.append((n, k if k is not None else (self.text(n) if t != "identifier" else None)))
            elif t == "object_pattern":
                for c in n.named_children:
                    stack.append((c, None))
            elif t == "pair_pattern":
                kk, v = n.child_by_field_name("key"), n.child_by_field_name("value")
                if v is not None:
                    stack.append((v, self._key(kk) if kk is not None else None))
            elif t in ("object_assignment_pattern", "assignment_pattern"):
                left = n.child_by_field_name("left")
                if left is not None:
                    stack.append((left, k))
            elif t == "array_pattern":
                for c in n.named_children:
                    stack.append((c, None))
            elif t == "rest_pattern":
                for c in n.named_children:
                    stack.append((c, None))
        return out

    def _declarator(self, node, where) -> None:
        name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        if name is None:
            return
        for ident, key in self._pattern(name):
            self._declare(where, ident, Def("var" if ident.id == name.id else "part", node, value, key))
        if value is not None and value.type in _FUNCTIONS and name.type == "identifier":
            self.methods.setdefault(self.text(name), []).append(value)

    def _for_in(self, node, function_scope) -> None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return
        kind = node.child_by_field_name("kind")
        op = node.child_by_field_name("operator")
        of = op is not None and self.text(op) == "of"
        names = self._pattern(left)
        if kind is None:                                   # (an existing name, assigned each round)
            for ident, _key in names:
                self.pending.append((ident, ("each", right, of), node))
            return
        where = node if self.text(kind) in ("let", "const") else function_scope
        for ident, key in names:
            self._declare(where, ident, Def("each", node, right, (of, key)))

    def _import(self, node) -> None:
        source = node.child_by_field_name("source")
        if source is None:
            return
        module = _module(jsstrings.js_string(self.text(source)))
        top = self._program()
        for clause in node.named_children:
            if clause.type != "import_clause":
                continue
            for c in clause.named_children:
                if c.type == "identifier":
                    self._declare(top, c, Def("import", c, None, (module, "default")))
                elif c.type == "namespace_import":
                    for i in c.named_children:
                        if i.type == "identifier":
                            self._declare(top, i, Def("import", i, None, (module, "*")))
                elif c.type == "named_imports":
                    for spec in c.named_children:
                        n, alias = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                        if n is not None:
                            self._declare(top, alias or n, Def("import", spec, None, (module, self._key(n))))

    def _program(self):
        return self.tree.root_node

    def _declare(self, scope_node, ident, d: Def) -> None:
        names = self.scopes.setdefault(scope_node.id, {})
        name = self.text(ident)
        b = names.get(name)
        if b is None:
            b = names[name] = Binding(name)
        b.defs.append(d)

    def lookup(self, ident) -> Optional[Binding]:
        """The binding a name stands for: its scope (noted by the walk), then the scopes around it."""
        got = self.bound.get(ident.id, self)
        if got is not self:
            return got
        name = self.text(ident)
        noted = self.where.get(ident.id)
        sid = noted[0] if noted is not None else None
        found = None
        steps = 0
        while sid is not None and steps < MAX_UP:
            steps += 1
            names = self.scopes.get(sid)
            if names is not None:
                b = names.get(name)
                if b is not None:
                    found = b
                    break
            sid = self.scope_parent.get(sid)
        self.tick()
        self.bound[ident.id] = found
        return found

    def _this(self, node) -> Binding:
        """``this`` of the class (or the plain function) around ``node``: one name for its fields."""
        owner = self.this_owner.get(node.id)
        if owner is None:
            return Binding("this")
        names = self.scopes.setdefault(owner, {})
        b = names.get("this")
        if b is None:
            b = names["this"] = Binding("this")
        return b

    def _settle(self) -> None:
        """Assignments, now that every declaration is known; call and callback sites; copies of stores."""
        for left, right, at in self.pending:
            self.tick()
            if isinstance(right, tuple):                   # (for-in / for-of into an existing name)
                b = self.lookup(left) if left.type == "identifier" else None
                if b is not None:
                    b.defs.append(Def("each", at, right[1], (right[2], None)))
                continue
            root = left
            member = False
            while root.type in ("member_expression", "subscript_expression", "parenthesized_expression"):
                member = True
                inner = root.child_by_field_name("object") if root.type != "parenthesized_expression" else (
                    root.named_children[0] if root.named_child_count else None)
                if inner is None:
                    break
                root = inner
            if root.type == "this":
                self._this(root).defs.append(Def("member", at, right, None))
            elif root.type == "identifier":
                b = self.lookup(root)
                if b is None and not member:               # (a name never declared: a global of the script)
                    names = self.scopes.setdefault(self.tree.root_node.id, {})
                    b = names.setdefault(self.text(root), Binding(self.text(root)))
                if b is not None:
                    b.defs.append(Def("member" if member else "assign", at, right, self._member_key(left)))
                    if not member and right.type in _FUNCTIONS:
                        self.methods.setdefault(b.name, []).append(right)
            elif left.type in ("object_pattern", "array_pattern"):
                for ident, key in self._pattern(left):
                    b = self.lookup(ident)
                    if b is not None:
                        b.defs.append(Def("part", at, right, key))
            if member and left.type == "member_expression" and right.type in _FUNCTIONS:
                prop = left.child_by_field_name("property")
                if prop is not None:
                    self.methods.setdefault(self.text(prop), []).append(right)
        for call in self.calls:
            self.tick()
            for fn in self.targets(call):
                sites = self.call_sites.setdefault(fn.id, [])
                if len(sites) < MAX_SITES:
                    sites.append(call)
            args = call.child_by_field_name("arguments")
            if args is None or args.type != "arguments":
                continue
            callee = call.child_by_field_name("function")
            if call.type == "call_expression" and callee is not None and args.named_child_count:
                # what a collector takes in, its object carries: form.append(k, v), list.push(v),
                # map.set(k, v), Object.assign(target, v)
                target = None
                if callee.type == "member_expression":
                    prop = callee.child_by_field_name("property")
                    if prop is not None and self.text(prop) in _COLLECT:
                        target = callee.child_by_field_name("object")
                    elif self.text(callee) == "Object.assign":
                        target = args.named_children[0]
                while target is not None and target.type in ("member_expression", "subscript_expression"):
                    target = target.child_by_field_name("object")
                if target is not None and target.type == "this":
                    self._this(target).defs.append(Def("member", call, args, None))
                elif target is not None and target.type == "identifier":
                    b = self.lookup(target)
                    if b is not None:
                        b.defs.append(Def("member", call, args, None))
            for i, a in enumerate(args.named_children):
                for fn in self._functions_of(a):
                    sites = self.callbacks.setdefault(fn.id, [])
                    if len(sites) < MAX_SITES:
                        sites.append((call, i))

    def _member_key(self, left) -> Optional[str]:
        """The key of ``o.k = v`` / ``o['k'] = v`` (one level on a name); None for anything else."""
        if left.type == "member_expression":
            obj, prop = left.child_by_field_name("object"), left.child_by_field_name("property")
            if obj is not None and obj.type == "identifier" and prop is not None:
                return self.text(prop)
        elif left.type == "subscript_expression":
            obj, index = left.child_by_field_name("object"), left.child_by_field_name("index")
            if obj is not None and obj.type == "identifier" and index is not None and index.type == "string":
                return jsstrings.js_string(self.text(index))
        return None

    def _functions_of(self, node) -> List[object]:
        """The functions ``node`` stands for: a function written there, or a name bound to one."""
        while node.type == "parenthesized_expression" and node.named_child_count:
            node = node.named_children[0]
        if node.type in _FUNCTIONS:
            return [node]
        if node.type == "identifier":
            b = self.lookup(node)
            if b is None:
                return []
            out = []
            for d in b.defs:
                if d.kind == "function":
                    out.append(d.value)
                elif d.kind in ("var", "assign") and d.value is not None and d.value.type in _FUNCTIONS:
                    out.append(d.value)
            return out
        return []

    def targets(self, call) -> List[object]:
        """The functions of this file a call reaches: by its bound name, or a method name defined once."""
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is None:
            return []
        found = self._functions_of(callee)
        if found:
            return found
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            if prop is not None:
                fns = self.methods.get(self.text(prop), ())
                if len(fns) == 1:
                    return list(fns)
        return []

    # ---- branches ----
    def branch(self, node) -> Dict[int, int]:
        """The arms of ``if`` / ``?:`` that ``node`` stands in: {conditional id: 0 (then) or 1 (else)}."""
        got = self.branches.get(node.id)
        if got is None:
            noted = self.where.get(node.id)
            got = self.branches[node.id] = dict(noted[1]) if noted is not None else {}
        return got

    def apart(self, a, b) -> bool:
        """Do ``a`` and ``b`` stand in different arms of one ``if`` / ``?:`` (never both run)?"""
        ba, bb = self.branch(a), self.branch(b)
        if len(ba) > len(bb):
            ba, bb = bb, ba
        return any(k in bb and bb[k] != v for k, v in ba.items())

    # ---- what a name or a call stands for: dotted names of modules and globals ----
    def api(self, node, depth: int = 0) -> FrozenSet[str]:
        got = self.apis.get(node.id)
        if got is not None:
            return got
        if node.id in self.api_busy or depth > MAX_DEPTH:
            return frozenset()
        self.api_busy.add(node.id)
        try:
            found = self._api(node, depth + 1)
        finally:
            self.api_busy.discard(node.id)
        if len(found) > MAX_VARIANTS:
            found = frozenset()
        self.apis[node.id] = found
        return found

    def _api(self, node, depth: int) -> FrozenSet[str]:
        self.tick()
        t = node.type
        if t in ("parenthesized_expression", "await_expression") and node.named_child_count:
            return self.api(node.named_children[-1], depth)
        if t == "sequence_expression" and node.named_child_count:
            return self.api(node.named_children[-1], depth)
        if t == "identifier":
            b = self.lookup(node)
            if b is None:
                return frozenset({self.text(node)})
            out: Set[str] = set()
            for d in b.defs:
                self.tick()
                if d.kind == "import":
                    module, name = d.extra
                    out.add(module if name in ("default", "*") else module + "." + name)
                elif d.kind in ("var", "assign") and d.value is not None:
                    out |= self.api(d.value, depth)
                elif d.kind == "part" and d.value is not None and d.extra is not None:
                    out |= {a + "." + d.extra for a in self.api(d.value, depth)}
            return frozenset(out)
        if t == "member_expression":
            obj, prop = node.child_by_field_name("object"), node.child_by_field_name("property")
            if obj is None or prop is None:
                return frozenset()
            name = self.text(prop)
            return frozenset(a + "." + name for a in self.api(obj, depth))
        if t == "subscript_expression":
            obj, index = node.child_by_field_name("object"), node.child_by_field_name("index")
            if obj is None or index is None or index.type != "string":
                return frozenset()
            name = jsstrings.js_string(self.text(index))
            return frozenset(a + "." + name for a in self.api(obj, depth))
        if t == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is None:
                return frozenset()
            names = self.api(callee, depth)
            args = node.child_by_field_name("arguments")
            if names & _REQUIRES and args is not None and args.named_child_count:
                return frozenset(_module(s) for s in self.strings(args.named_children[0], depth)
                                 if ANY not in s and s)
            if callee.type == "import":
                if args is not None and args.named_child_count:
                    return frozenset(_module(s) for s in self.strings(args.named_children[0], depth) if ANY not in s)
            return frozenset(a + "()" for a in names)
        if t == "new_expression":
            ctor = node.child_by_field_name("constructor")
            return frozenset(a + "()" for a in self.api(ctor, depth)) if ctor is not None else frozenset()
        return frozenset()

    # ---- what texts a value can be (paths, addresses) ----
    def strings(self, node, depth: int = 0) -> FrozenSet[str]:
        got = self.texts.get(node.id)
        if got is not None:
            return got
        if node.id in self.text_busy or depth > MAX_DEPTH:
            return frozenset({ANY})
        self.text_busy.add(node.id)
        try:
            found = self._strings(node, depth + 1)
        finally:
            self.text_busy.discard(node.id)
        if not found or len(found) > MAX_VARIANTS:
            found = frozenset({ANY})
        self.texts[node.id] = found
        return found

    @staticmethod
    def _join(parts: List[FrozenSet[str]], sep: str = "") -> FrozenSet[str]:
        out = {""}
        for p in parts:
            out = {(a + sep + b if a and sep else a + b)[:MAX_TEXT] for a in out for b in p}
            if len(out) > MAX_VARIANTS:
                return frozenset({ANY})
        return frozenset(out)

    def _strings(self, node, depth: int) -> FrozenSet[str]:
        self.tick()
        t = node.type
        if t == "string":
            return frozenset({jsstrings.js_string(self.text(node))})
        if t == "template_string":
            parts = []
            for c in node.named_children:
                if c.type == "template_substitution":
                    parts.append(self.strings(c.named_children[0], depth) if c.named_child_count else frozenset({ANY}))
                elif c.type in ("string_fragment", "escape_sequence"):
                    raw = self.text(c)
                    parts.append(frozenset({jsstrings.js_string('"' + raw + '"') if c.type == "escape_sequence" else raw}))
            return self._join(parts)
        if t in ("parenthesized_expression", "await_expression") and node.named_child_count:
            return self.strings(node.named_children[-1], depth)
        if t == "binary_expression":
            op = node.child_by_field_name("operator")
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op is not None and self.text(op) == "+" and left is not None and right is not None:
                return self._join([self.strings(left, depth), self.strings(right, depth)])
            if op is not None and self.text(op) in ("||", "??") and left is not None and right is not None:
                return self.strings(left, depth) | self.strings(right, depth)
            return frozenset({ANY})
        if t == "ternary_expression":
            a, b = node.child_by_field_name("consequence"), node.child_by_field_name("alternative")
            return (self.strings(a, depth) if a is not None else frozenset()) | (
                self.strings(b, depth) if b is not None else frozenset())
        if t == "identifier":
            b = self.lookup(node)
            if b is None:
                return frozenset({ANY})
            out: Set[str] = set()
            for d in b.defs:
                self.tick()
                if self.apart(d.at, node):
                    continue
                out |= self._def_strings(d, depth)
                if len(out) > MAX_VARIANTS:
                    return frozenset({ANY})
            return frozenset(out) or frozenset({ANY})
        if t in ("member_expression", "subscript_expression"):
            obj = node.child_by_field_name("object")
            if obj is None:
                return frozenset({ANY})
            if t == "member_expression":
                prop = node.child_by_field_name("property")
                key = self.text(prop) if prop is not None else None
            else:
                index = node.child_by_field_name("index")
                key = jsstrings.js_string(self.text(index)) if index is not None and index.type == "string" else None
            names = self.api(obj, depth)
            if any(n in ("process.env", "global.process.env") for n in names) and key:
                return frozenset({"%" + key + "%"})
            out = set()
            for o in self.objects(obj, depth):
                if o.type == "object" and key is not None:
                    for pair in o.named_children:
                        if pair.type == "pair":
                            k = pair.child_by_field_name("key")
                            v = pair.child_by_field_name("value")
                            if k is not None and v is not None and self._key(k) == key:
                                out |= self.strings(v, depth)
                elif o.type == "array" and t == "subscript_expression":
                    for item in o.named_children:
                        out |= self.strings(item, depth)
            if obj.type == "identifier" and key is not None:      # (an object filled by o['k'] = 'text')
                b = self.lookup(obj)
                for d in (b.defs if b is not None else ()):
                    self.tick()
                    if d.kind == "member" and d.extra == key and d.value is not None:
                        out |= self.strings(d.value, depth)
            return frozenset(out) or frozenset({ANY})
        if t == "call_expression":
            callee = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if callee is None:
                return frozenset({ANY})
            names = self.api(callee, depth)
            last = {_last(n) for n in names}
            items = list(args.named_children) if args is not None and args.type == "arguments" else []
            if last & {"join", "resolve", "normalize"} and any(_root(n) == "path" for n in names):
                return self._join([self.strings(a, depth) for a in items], "/") if items else frozenset({ANY})
            if names & {"os.homedir", "os.tmpdir", "process.cwd"}:
                return frozenset({"%" + _last(next(iter(names))) + "%"})
            if any(_last(n) == "getPath" for n in names) and items:
                return frozenset("%" + s + "%" for s in self.strings(items[0], depth))
            if callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                obj = callee.child_by_field_name("object")
                method = self.text(prop) if prop is not None else ""
                if method == "join" and obj is not None:
                    sep = self.strings(items[0], depth) if items else frozenset({","})
                    if len(sep) == 1 and ANY not in next(iter(sep)):
                        elems = [self.strings(e, depth) for o in self.objects(obj, depth) if o.type == "array"
                                 for e in o.named_children]
                        if elems:
                            return self._join(elems, next(iter(sep)))
                if method == "concat" and obj is not None:
                    return self._join([self.strings(obj, depth)] + [self.strings(a, depth) for a in items])
            return frozenset({ANY})
        return frozenset({ANY})

    def _def_strings(self, d: Def, depth: int) -> FrozenSet[str]:
        if d.kind in ("var", "assign") and d.value is not None:
            return self.strings(d.value, depth)
        if d.kind == "each" and d.value is not None:
            out: Set[str] = set()
            of, key = d.extra
            for o in self.objects(d.value, depth):
                if of and o.type == "array":
                    for item in o.named_children:
                        out |= self._keyed(item, key, depth)
                elif not of and o.type == "object":
                    for pair in o.named_children:
                        k = pair.child_by_field_name("key") if pair.type == "pair" else None
                        if k is not None:
                            out.add(self._key(k))
            return frozenset(out) or frozenset({ANY})
        if d.kind == "part" and d.value is not None:
            out = set()
            for o in self.objects(d.value, depth):
                if o.type == "object" and d.extra is not None:
                    out |= self._keyed(o, d.extra, depth)
            return frozenset(out) or frozenset({ANY})
        if d.kind == "param":
            index, key = d.extra
            fn = d.value
            out = set()
            for call in self.call_sites.get(fn.id, ()):
                args = call.child_by_field_name("arguments")
                if args is not None and args.type == "arguments" and index < args.named_child_count:
                    out |= self._keyed(args.named_children[index], key, depth)
            for call, at in self.callbacks.get(fn.id, ()):
                callee = call.child_by_field_name("function")
                if index == 0 and callee is not None and callee.type == "member_expression":
                    prop = callee.child_by_field_name("property")
                    if prop is not None and self.text(prop) in _ELEMENTS:
                        obj = callee.child_by_field_name("object")
                        for o in self.objects(obj, depth):
                            if o.type == "array":
                                for item in o.named_children:
                                    out |= self._keyed(item, key, depth)
            return frozenset(out) or frozenset({ANY})
        return frozenset({ANY})

    def _keyed(self, node, key, depth: int) -> FrozenSet[str]:
        if key is None:
            return self.strings(node, depth)
        out: Set[str] = set()
        for o in self.objects(node, depth):
            if o.type == "object":
                for pair in o.named_children:
                    if pair.type == "pair":
                        k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                        if k is not None and v is not None and self._key(k) == key:
                            out |= self.strings(v, depth)
        return frozenset(out) or frozenset({ANY})

    def objects(self, node, depth: int = 0) -> List[object]:
        """The array and object literals a value can be (through names, a little)."""
        out: List[object] = []
        if node is None or depth > MAX_DEPTH:
            return out
        stack = [(node, 0)]
        seen: Set[int] = set()
        while stack and len(out) < MAX_VARIANTS:
            self.tick()
            n, d = stack.pop()
            if n is None or n.id in seen or d > 8:
                continue
            seen.add(n.id)
            if n.type in ("array", "object"):
                out.append(n)
            elif n.type == "parenthesized_expression" and n.named_child_count:
                stack.append((n.named_children[0], d))
            elif n.type == "identifier":
                b = self.lookup(n)
                for df in (b.defs if b is not None else ()):
                    self.tick()
                    if df.kind in ("var", "assign") and df.value is not None:
                        stack.append((df.value, d + 1))
                    elif df.kind == "each" and df.value is not None and df.extra[0]:
                        for o in self.objects(df.value, depth + 1):
                            if o.type == "array":
                                stack.extend((item, d + 1) for item in o.named_children)
                    elif df.kind == "param":
                        index, key = df.extra
                        if key is not None:
                            continue
                        for call, _at in self.callbacks.get(df.value.id, ()):
                            callee = call.child_by_field_name("function")
                            if index == 0 and callee is not None and callee.type == "member_expression":
                                prop = callee.child_by_field_name("property")
                                if prop is not None and self.text(prop) in _ELEMENTS:
                                    for o in self.objects(callee.child_by_field_name("object"), depth + 1):
                                        if o.type == "array":
                                            stack.extend((item, d + 1) for item in o.named_children)
                        for call in self.call_sites.get(df.value.id, ()):
                            args = call.child_by_field_name("arguments")
                            if args is not None and args.type == "arguments" and index < args.named_child_count:
                                stack.append((args.named_children[index], d + 1))
            elif n.type == "call_expression":
                callee = n.child_by_field_name("function")
                names = self.api(callee, depth) if callee is not None else frozenset()
                if names & {"Object.values", "Object.keys", "Object.entries"}:
                    args = n.child_by_field_name("arguments")
                    for o in (self.objects(args.named_children[0], depth + 1)
                              if args is not None and args.named_child_count else []):
                        if o.type == "object":
                            if "Object.values" in names:
                                vals = [p.child_by_field_name("value") for p in o.named_children if p.type == "pair"]
                                arr = [v for v in vals if v is not None]
                                stack.extend((v, d + 1) for v in arr)
                        # (keys / entries: the values are not paths)
        return out

    # ---- sources ----
    def source(self, call, depth: int) -> FrozenSet[Tuple[str, int]]:
        """The labels a call itself brings in: a store read, an add-on call, the clipboard, the screen."""
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is None:
            return frozenset()
        names = self.api(callee, depth)
        args = call.child_by_field_name("arguments")
        items = list(args.named_children) if args is not None and args.type == "arguments" else []
        line = self.line(call)
        out: Set[Tuple[str, int]] = set()
        method = ""
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            method = self.text(prop) if prop is not None else ""
        lasts = {_last(n) for n in names} | ({method} if method else set())
        if callee.type == "identifier" and not names:
            lasts.add(self.text(callee))
        if items and (lasts & _READS or call.type == "new_expression"):
            for kind in self.store_of(items[0], depth):
                out.add((kind, line))
        if CAPTURE_ON:
            if names & _CLIPBOARD:
                out.add(("clipboard", line))
            if names & _SCREEN or (method in _SCREEN_METHODS) or any(n in _SCREEN for n in
                                                                       {a[:-2] for a in names if a.endswith("()")}):
                out.add(("screen", line))
        for n in names:
            root = _root(n)
            if root in _BUILTINS or root in _NET_MODULES or root in ("require", "window", "document", "JSON",
                                                                       "Buffer", "Object", "Array", "Math", "Promise"):
                continue
            if n == root and call.type == "call_expression" and callee.type == "identifier" and \
                    self.lookup(callee) is None:
                continue                                    # (a global function, not a module)
            if self._required(n, callee, depth):
                if len(self.addons) < MAX_ADDONS or root in self.addons:
                    self.addons.add(root)
                    out.add(("addon:" + root, line))
        return frozenset(out)

    def _required(self, name: str, callee, depth: int) -> bool:
        """Does ``name`` come from a ``require`` / ``import`` of a module (not a global)?"""
        root = callee
        while root.type in ("member_expression", "subscript_expression"):
            root = root.child_by_field_name("object")
            if root is None:
                return False
        if root.type == "call_expression":
            inner = root.child_by_field_name("function")
            return inner is not None and bool(self.api(inner, depth) & _REQUIRES)
        if root.type != "identifier":
            return False
        b = self.lookup(root)
        if b is None:
            return False
        for d in b.defs:
            self.tick()
            if d.kind == "import":
                return True
            if d.kind in ("var", "assign", "part") and d.value is not None:
                v = d.value
                while v.type in ("member_expression", "subscript_expression", "await_expression") and (
                        v.child_by_field_name("object") is not None or v.named_child_count):
                    v = v.child_by_field_name("object") if v.type != "await_expression" else v.named_children[0]
                if v.type == "call_expression":
                    inner = v.child_by_field_name("function")
                    if inner is not None and (self.api(inner, depth) & _REQUIRES or inner.type == "import"):
                        return True
        return False

    # ---- a value imported from a relative module of the same app (C1 part 2b, exfil_cross.py) ----
    def _require_spec(self, call) -> Optional[str]:
        """The module spec of ``require("...")`` / ``import("...")`` - only when it is a relative
        path of the app (``./`` / ``../`` / ``/``); None otherwise."""
        if call.type != "call_expression":
            return None
        callee = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        if callee is None or args is None or not args.named_child_count:
            return None
        if not (self.api(callee) & _REQUIRES or callee.type == "import"):
            return None
        specs = {_module(s) for s in self.strings(args.named_children[0]) if ANY not in s and s}
        if len(specs) != 1:
            return None
        spec = next(iter(specs))
        return spec if spec.startswith((".", "/")) else None

    def import_ref(self, node, depth: int = 0) -> Optional[Tuple[str, str]]:
        """``(spec, name)`` when ``node`` is a value taken from a relative module of the same app
        (``name`` = the export used, ``"*"`` = the whole module object); None otherwise. Memoised."""
        if not self.collect_imports or depth > 12:
            return None
        if node.id in self.imp:
            got = self.imp[node.id]
            return got if got is not None else None
        self.imp[node.id] = None
        self.tick()
        ref = self._import_ref(node, depth)
        self.imp[node.id] = ref
        return ref

    def _import_ref(self, node, depth: int) -> Optional[Tuple[str, str]]:
        t = node.type
        if t in ("parenthesized_expression", "await_expression") and node.named_child_count:
            return self.import_ref(node.named_children[-1], depth + 1)
        if t == "call_expression":
            spec = self._require_spec(node)
            if spec is not None:
                return (spec, "*")
            callee = node.child_by_field_name("function")
            # calling an imported export (``require("./a").getData()``) yields that export's result
            return self.import_ref(callee, depth + 1) if callee is not None else None
        if t in ("member_expression", "subscript_expression"):
            obj = node.child_by_field_name("object")
            if obj is None:
                return None
            base = self.import_ref(obj, depth + 1)
            if base is None:
                return None
            if t == "member_expression":
                prop = node.child_by_field_name("property")
                key = self.text(prop) if prop is not None else None
            else:
                index = node.child_by_field_name("index")
                key = jsstrings.js_string(self.text(index)) if index is not None and index.type == "string" else None
            if key is None:
                return None
            return (base[0], key) if base[1] == "*" else base
        if t == "identifier":
            b = self.lookup(node)
            if b is None:
                return None
            for d in b.defs:
                self.tick()
                if d.kind == "import":
                    module, name = d.extra
                    if isinstance(module, str) and module.startswith((".", "/")):
                        return (module, name if name != "default" else "default")
                elif d.kind in ("var", "assign") and d.value is not None:
                    ref = self.import_ref(d.value, depth + 1)
                    if ref is not None:
                        return ref
                elif d.kind == "part" and d.value is not None:
                    spec = self._require_spec(d.value) if d.value.type == "call_expression" else None
                    if spec is not None and isinstance(d.extra, str):
                        return (spec, d.extra)
                    base = self.import_ref(d.value, depth + 1) if d.value.type != "call_expression" else None
                    if base is not None and isinstance(d.extra, str):
                        return (base[0], d.extra) if base[1] == "*" else base
            return None
        return None

    def store_of(self, node, depth: int) -> List[str]:
        """The store kinds a path value names (or a copy of a store made into it)."""
        texts = self.strings(node, depth)
        kinds = set(store_kinds(texts))
        if node.type == "identifier":
            b = self.lookup(node)
            if b is not None:
                kinds |= self.copied.get(id(b), set())
        for t in texts:
            kinds |= self.copied_texts.get(t, set())
        if node.type == "object":                       # (sqlite's open({filename: path}))
            for pair in node.named_children:
                if pair.type == "pair":
                    k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                    if k is not None and v is not None and self._key(k) in ("filename", "path", "file"):
                        kinds |= set(self.store_of(v, depth))
        return [k for k in STORE_KINDS if k in kinds]

    def copies(self) -> None:
        for call in self.calls:
            self.tick()
            callee = call.child_by_field_name("function")
            if callee is None or call.type != "call_expression":
                continue
            names = self.api(callee)
            method = ""
            if callee.type == "member_expression":
                prop = callee.child_by_field_name("property")
                method = self.text(prop) if prop is not None else ""
            if not ({_last(n) for n in names} | {method}) & _COPIES:
                continue
            args = call.child_by_field_name("arguments")
            if args is None or args.type != "arguments" or args.named_child_count < 2:
                continue
            kinds = set(self.store_of(args.named_children[0], 0))
            if not kinds:
                continue
            dst = args.named_children[1]
            if dst.type == "identifier":
                b = self.lookup(dst)
                if b is not None:
                    self.copied.setdefault(id(b), set()).update(kinds)
            for t in self.strings(dst):
                if t.strip(ANY):
                    self.copied_texts.setdefault(t, set()).update(kinds)

    # ---- taint: which private data a value carries ----
    def taint(self, node, depth: int = 0) -> FrozenSet[Tuple[str, int]]:
        got = self.memo.get(node.id)
        if got is not None:
            return got
        if node.id in self.busy or depth > MAX_DEPTH:
            return self.prev.get(node.id, frozenset())
        self.busy.add(node.id)
        try:
            found = self._taint(node, depth + 1)
        finally:
            self.busy.discard(node.id)
        if len(found) > MAX_LABELS:                  # (private data first, then add-on calls, then imports)
            found = frozenset(sorted(found, key=lambda l: (_rank(l[0]), l))[:MAX_LABELS])
        self.memo[node.id] = found
        return found

    def _union(self, nodes, depth: int) -> FrozenSet:
        out: Set = set()
        for n in nodes:
            if n is not None:
                out |= self.taint(n, depth)
        return frozenset(out)

    def _taint(self, node, depth: int) -> FrozenSet:
        self.tick()
        t = node.type
        if t in ("string", "number", "true", "false", "null", "undefined", "regex", "comment", "this_type") \
                or t in _FUNCTIONS or t == "class":
            return frozenset()
        if t in ("identifier", "shorthand_property_identifier"):
            b = self.lookup(node)
            base = self._binding_taint(b, node, depth) if b is not None else frozenset()
            ref = self.import_ref(node)
            if ref is not None:                        # a value taken whole from a relative module
                return base | {(MOD + "%s::%s" % ref, self.line(node))}
            return base
        if t == "this":
            return self._binding_taint(self._this(node), node, depth)
        if t in ("member_expression", "subscript_expression"):
            ref = self.import_ref(node)
            if ref is not None:                        # one export of a relative module (not the whole object)
                return frozenset({(MOD + "%s::%s" % ref, self.line(node))})
            obj = node.child_by_field_name("object")
            return self.taint(obj, depth) if obj is not None else frozenset()
        if t in ("call_expression", "new_expression"):
            return self._call_taint(node, depth)
        if t == "ternary_expression":
            return self._union([node.child_by_field_name("consequence"), node.child_by_field_name("alternative")], depth)
        if t in ("assignment_expression", "augmented_assignment_expression"):
            right = node.child_by_field_name("right")
            return self.taint(right, depth) if right is not None else frozenset()
        if t == "sequence_expression":
            return self.taint(node.named_children[-1], depth) if node.named_child_count else frozenset()
        if t == "pair":
            v = node.child_by_field_name("value")
            return self.taint(v, depth) if v is not None else frozenset()
        if t in ("object", "array", "template_string", "template_substitution", "binary_expression",
                 "parenthesized_expression", "await_expression", "spread_element", "unary_expression",
                 "arguments", "yield_expression", "as_expression"):
            return self._union(node.named_children, depth)
        return frozenset()

    def _binding_taint(self, b: Binding, use, depth: int) -> FrozenSet:
        out: Set = set()
        for d in b.defs:
            self.tick()
            if d.kind in ("function", "import", "catch", "class"):
                continue
            if self.apart(d.at, use):
                continue
            if d.kind in ("var", "assign", "part", "member", "each"):
                if d.value is not None:
                    out |= self.taint(d.value, depth)
            elif d.kind == "param":
                out |= self._param_taint(d, depth)
        return frozenset(out)

    def _param_taint(self, d: Def, depth: int) -> FrozenSet:
        index, _key = d.extra
        fn = d.value
        out: Set = set()
        for call in self.call_sites.get(fn.id, ()):
            args = call.child_by_field_name("arguments")
            if args is not None and args.type == "arguments" and index < args.named_child_count:
                out |= self.taint(args.named_children[index], depth)
        for call, at in self.callbacks.get(fn.id, ()):
            out |= self._delivered(call, at, depth)
        return frozenset(out)

    def _delivered(self, call, at: int, depth: int) -> FrozenSet:
        """What a call hands to the callback it was given (argument ``at``): what the call itself brings
        in, what its receiver carries (``promise.then(cb)``, ``list.forEach(cb)``), its other arguments."""
        out: Set = set(self.source(call, depth))
        callee = call.child_by_field_name("function")
        if callee is not None and callee.type == "member_expression":
            obj = callee.child_by_field_name("object")
            if obj is not None:
                out |= self.taint(obj, depth)
        args = call.child_by_field_name("arguments")
        if args is not None and args.type == "arguments":
            for i, a in enumerate(args.named_children):
                if i != at and a.type not in _FUNCTIONS:
                    out |= self.taint(a, depth)
        return frozenset(out)

    def _call_taint(self, call, depth: int) -> FrozenSet:
        out: Set = set(self.source(call, depth))
        ref = self.import_ref(call)
        if ref is not None:
            # the result of calling an export of a relative module (``require("./a").getData()``):
            # exactly that export, nothing of the caller's receiver
            out.add((MOD + "%s::%s" % ref, self.line(call)))
            return frozenset(out)
        fns = self.targets(call)
        args = call.child_by_field_name("arguments")
        items = [a for a in (args.named_children if args is not None and args.type == "arguments" else [])]
        if fns:
            for fn in fns:
                out |= self._union(self.returns.get(fn.id, ()), depth)
            return frozenset(out)
        out |= self._union([a for a in items if a.type not in _FUNCTIONS], depth)
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is not None and callee.type in ("member_expression", "subscript_expression"):
            obj = callee.child_by_field_name("object")
            if obj is not None:
                out |= self.taint(obj, depth)
        return frozenset(out)

    # ---- sinks ----
    def sink(self, call) -> Tuple[str, List[object]]:
        """(the network call's name, the values it sends) - or ("", []) when the call is no sink."""
        callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
        if callee is None:
            return "", []
        args = call.child_by_field_name("arguments")
        items = [a for a in (args.named_children if args is not None and args.type == "arguments" else [])
                 if a.type not in _FUNCTIONS]
        names = self.api(callee)
        for n in sorted(names):
            if n in _NET_CALLS or _root(n) in _NET_MODULES or (n.endswith("()") and n in _NET_OBJECTS):
                return n, items
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            obj = callee.child_by_field_name("object")
            method = self.text(prop) if prop is not None else ""
            if obj is None:
                return "", []
            receiver = self.api(obj)
            net = any(r in _NET_OBJECTS or _root(r) in _NET_MODULES or r in _NET_CALLS
                      or (r.endswith("()") and r[:-2] in _NET_CALLS) for r in receiver)
            if net and method in _SENDS:
                return "%s.%s" % (sorted(receiver)[0], method), items + ([obj] if method in ("submit", "pipe") else [])
            if method == "pipe" and items and any(_root(r) in _NET_MODULES or r in _NET_OBJECTS
                                                  for r in self.api(items[0])):
                return "pipe into a request", [obj]
            if method in ("sendBeacon", "fetch") and not receiver:
                return method, items
            if method in _ADDRESS_CALLS and not receiver and items and any(
                    s.lower().startswith(("http://", "https://")) for s in self.strings(items[0])):
                return method + " (to a written address)", items
        elif callee.type == "identifier" and not names - {self.text(callee)} and self.lookup(callee) is None:
            if self.text(callee) == "fetch":
                return "fetch", items
        return "", []

    def run(self, out: Result) -> None:
        self.copies()
        sinks = []
        for call in self.calls:
            self.tick()
            name, sent = self.sink(call)
            if name:
                sinks.append((call, name, sent))
        out.sinks = len(sinks)
        if self.collect_imports:
            out.exports = self.exports()          # a source-only module (no sink) still exports its reads
        if not sinks:
            return
        found: Dict[Tuple, Flow] = {}
        last = None
        for _ in range(ROUNDS):
            self.prev, self.memo = self.memo, {}
            now = {}
            for call, name, sent in sinks:
                labels = self._union(sent, 0)
                for kind, source_line in sorted(labels):
                    key = (kind, self.line(call))
                    if key not in now:
                        now[key] = Flow(kind, source_line, name, self.line(call))
            if now == last:
                break
            last = now
            found = now
        seen_imports: Set[Tuple[str, str, int]] = set()
        for flow in sorted(found.values(), key=lambda f: (f.line, f.kind)):
            if flow.kind.startswith("addon:"):
                if len(out.addon_flows) < MAX_FLOWS:
                    out.addon_flows.append(flow)
            elif flow.kind.startswith(MOD):                 # a value imported from a relative module (cross-file)
                spec, _, name = flow.kind[len(MOD):].partition("::")
                key = (spec, name, flow.line)
                if spec and key not in seen_imports and len(out.sink_imports) < MAX_IMPORT_SINKS:
                    seen_imports.add(key)
                    out.sink_imports.append((spec, name, flow.line, flow.sink))
            elif flow.kind in STORE_KINDS or (CAPTURE_ON and flow.kind in CAPTURE_KINDS):
                if len(out.flows) < MAX_FLOWS:
                    out.flows.append(flow)

    # ---- what this script exports (for the cross-file join, exfil_cross.py) ----
    def exports(self) -> Dict[str, FrozenSet[str]]:
        """Each exported name -> the labels its value carries (store / capture kinds and ``mod:`` import
        references), so another module's sink can be joined to a store this module reads. ``"*"`` is the
        whole exports object (``module.exports = obj`` / the union of the parts)."""
        out: Dict[str, Set[str]] = {}
        work = [0]

        def add(name: str, value) -> None:
            if value is None or work[0] > MAX_EXPORT_POINTS:
                return
            work[0] += 1
            labels = {lbl for lbl, _line in self._export_taint(value, 0)}
            labels = {lbl for lbl in labels if self._exported(lbl)}
            if labels:
                out.setdefault(name, set()).update(labels)
                out.setdefault("*", set()).update(labels)

        cursor = self.tree.walk()
        depth, nodes = 0, []
        while True:
            node = cursor.node
            self.tick()
            del nodes[depth:]
            if node.type == "export_statement":
                self._export_statement(node, add)
            elif node.type in ("assignment_expression", "augmented_assignment_expression"):
                self._export_assignment(node, add)
            elif node.type == "call_expression":
                self._define_property(node, add)
            if work[0] > MAX_EXPORT_POINTS:
                break
            if cursor.goto_first_child():
                nodes.append(node)
                depth += 1
                continue
            while not cursor.goto_next_sibling():
                if not cursor.goto_parent():
                    return {k: frozenset(v) for k, v in out.items()}
                depth -= 1

    @staticmethod
    def _exported(label: str) -> bool:
        """The labels an export summary keeps (C3's reader keeps its own kinds)."""
        return label in MALICE_KINDS or label in CAPTURE_KINDS or label.startswith(MOD)

    def _export_taint(self, value, depth: int) -> FrozenSet[Tuple[str, int]]:
        """The labels an exported value carries - a function's returns, not the function node."""
        if value.type in _FUNCTIONS:
            return self._union(self.returns.get(value.id, ()), depth)
        return self.taint(value, depth)

    def _export_statement(self, node, add) -> None:
        decl = node.child_by_field_name("declaration")
        value = node.child_by_field_name("value")
        if value is not None:                              # export default <value>
            add("default", value)
        if decl is not None:
            if decl.type in ("function_declaration", "generator_function_declaration", "class_declaration"):
                name = decl.child_by_field_name("name")
                if name is not None:
                    add(self.text(name), decl)
            elif decl.type in ("lexical_declaration", "variable_declaration"):
                for d in decl.named_children:
                    if d.type == "variable_declarator":
                        n, v = d.child_by_field_name("name"), d.child_by_field_name("value")
                        if n is not None and n.type == "identifier" and v is not None:
                            add(self.text(n), v)
        for clause in node.named_children:                 # export { a, b as c }
            if clause.type == "export_clause":
                for spec in clause.named_children:
                    n = spec.child_by_field_name("name")
                    alias = spec.child_by_field_name("alias")
                    if n is not None and n.type == "identifier":
                        add(self.text(alias) if alias is not None else self.text(n), n)

    def _export_assignment(self, node, add) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        name = self._export_target(left)
        if name is not None:
            add(name, right)

    @staticmethod
    def _export_target(left) -> Optional[str]:
        """``module.exports`` / ``module.exports.X`` / ``exports.X`` as the export name, else None
        (``"*"`` = the whole exports object)."""
        if left.type != "member_expression":
            return None
        obj, prop = left.child_by_field_name("object"), left.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        key = prop.text.decode("utf-8", "surrogatepass") if prop is not None else ""
        if obj.type == "identifier" and obj.text == b"exports":
            return key or "*"
        if obj.type == "member_expression":
            inner, iprop = obj.child_by_field_name("object"), obj.child_by_field_name("property")
            if inner is not None and inner.type == "identifier" and inner.text == b"module" \
                    and iprop is not None and iprop.text == b"exports":
                return key                                 # module.exports.X
        if obj.type == "identifier" and obj.text == b"module" and key == "exports":
            return "*"                                     # module.exports = ...
        return None

    def _define_property(self, node, add) -> None:
        """``Object.defineProperty(exports, "k", { get() { ... } })``."""
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "member_expression" or self.text(callee) != "Object.defineProperty":
            return
        args = node.child_by_field_name("arguments")
        if args is None or args.named_child_count < 3:
            return
        target, key, desc = args.named_children[0], args.named_children[1], args.named_children[2]
        base = self._export_target(target) if target.type == "member_expression" else (
            "*" if target.type == "identifier" and target.text == b"exports" else None)
        if base is None or key.type != "string" or desc.type != "object":
            return
        name = jsstrings.js_string(self.text(key))
        for pair in desc.named_children:
            if pair.type == "pair":
                k, v = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                if k is not None and v is not None and self.text(k).strip("'\"") in ("get", "value"):
                    add(name, v)


_KIND_WORDS = {"browser": "a browser's store", _IND[0]: _IND[3], "wallet": "a wallet's files",
               "clipboard": "the clipboard", "screen": "the screen", DECRYPTED: "what a decrypting add-on returns"}


def evidence(flow: Flow, addon: str = "") -> str:
    """One line for a flow: the kind of data, where it is read, the network call, where it is sent. The
    call is named by the scanner's own words (a module or global name of the lists above)."""
    sink = flow.sink if re.fullmatch(r"[\w$.@/()\- ]{1,80}", flow.sink) else "a network call"
    said = _KIND_WORDS.get(flow.kind, "private data")
    if addon:
        said += " (%s)" % addon
    return "%s, read on line %d, reaches %s on line %d" % (said, flow.source_line, sink, flow.line)


REASON = (_IND[4])


def prove_stealers(findings, app_root) -> int:
    """``CHAIN-STEALER`` names the parts of a stealer; when C1 proved, in the app's own code, that private
    data of a store (or decrypted by the app's add-on) reaches a network call - a ``CHAIN-EXFIL`` of a
    MALICE kind in the same app (or, for the chain inside one script, in the same file) - the chain is
    marked proven (:data:`PROVEN`) and keeps its CRITICAL level (tier MALICE). Without such a flow it stays
    CHAIN (HIGH). A flow lowered to MEDIUM inside a verified library is the library's own mechanism, not
    proof the app exfiltrates: it does not count (its severity is below CRITICAL). Returns how many were
    marked. Switch: :data:`RAISE_ON`."""
    if not (ON and RAISE_ON):
        return 0
    from ..models import Severity
    by_app: Dict[str, str] = {}
    by_file: Dict[str, str] = {}
    for f in findings:
        if f.rule_id == RULE and not f.suppressed and f.context.get("exfil_kind") in MALICE_KINDS \
                and f.severity >= Severity.CRITICAL:
            by_file.setdefault(f.file, "%s line %s" % (f.file, f.line or "-"))
            root = app_root(f.file)
            if root is not None:
                by_app.setdefault(root, by_file[f.file])
    if not by_file:
        return 0
    marked = 0
    for f in findings:
        if f.rule_id != "CHAIN-STEALER" or f.context.get(PROVEN):
            continue
        root = app_root(f.file) if f.context.get("across_app") else None
        where = by_app.get(root) if root is not None else by_file.get(f.file)
        if where:
            f.context[PROVEN] = where
            f.evidence += "; the flow is proven: %s" % where
            marked += 1
    return marked


MAX_KEPT = 256                  # add-on flows a scan keeps for the join (Scanner._app_exfil)


def matches_addon(module: str, addon_file: str) -> bool:
    """Is ``addon_file`` (a native add-on of the app) what ``require(module)`` reaches?"""
    path = addon_file.replace("\\", "/").lower()
    module = module.replace("\\", "/").lower().strip()
    if not module:
        return False
    if module.endswith(".node"):
        leaf = module.rsplit("/", 1)[-1].replace("*", "")
        return bool(leaf) and path.rsplit("/", 1)[-1] == leaf
    if module.startswith((".", "/")):
        return False
    return ("node_modules/%s/" % module) in path
