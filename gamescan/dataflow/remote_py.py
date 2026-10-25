"""Remote code execution in Python and Ren'Py: does what runs come from the network?

The Python counterpart of :mod:`gamescan.dataflow.remote`. The 60-line attack
chains need an obfuscation signal to call a downloader CRITICAL, and a plain
``exec(urlopen(address).read())`` has none. This module follows the data:

``source``  a network request - ``urllib`` / ``urllib2``, ``requests``,
            ``http.client`` / ``httplib``, a ``socket``, ``ftplib``,
            ``renpy.fetch``
``flow``    the response travels through variables, attributes, function
            arguments and return values, decoders and containers
``sink``    ... and is executed: ``exec`` / ``eval`` / ``compile``,
            ``marshal.loads`` / ``pickle.loads`` (both rebuild code objects),
            a command line, native code through ``ctypes`` - or it is written
            to a file that is then started, imported or executed (a dropper)

What decides is the address the request goes to, as in JavaScript: remote or
decoded - reported; not resolvable - reported; this PC (``localhost``, a
``file:`` address) - not a download, nothing is reported. Reading and running
a file of the game itself is not a network request at all.

The source is parsed with ``ast`` (which never runs it). Names are followed
per function, so a ``data`` in one function is not the ``data`` of another;
inside one function a value only counts from the line that assigns it. It is
a tracer, not an interpreter: both branches of a condition are followed, a
reassignment does not clear a name, and objects are told apart by name only.

Inside one file the data is also followed (2026-10-10) through objects - a
name made from a class of the file is an object of that class: its methods
are that class's (and its base classes' in the file), ``Class(data)`` hands
``data`` to ``__init__``, and a field (``self.x``, ``obj.x``) belongs to the
class and the classes it is related to in the file, not to every class at
once - and through functions handed on as values: a function given to a
parameter, a name, a field or a container and called there, a ``lambda``,
``functools.partial`` / ``renpy.curry``, and what starts a function in a
thread (``threading.Thread(target=f, args=...)``, ``Timer``,
``start_new_thread``, ``renpy.invoke_in_thread``; ``start()`` of a class of
the file with a ``run`` method is ``run()``). Limits: a function is followed
through ``_MAX_HANDOVER`` hand-overs, ``_MAX_CLASSES`` classes and
``_MAX_FIELDS`` fields per file. Not followed: a queue between threads, an
executor's ``submit``, another file.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_py.py")

import ast
import builtins
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from . import pyflow
from . import values as V
from .remote import _INTERPRETERS, HIDDEN, LOCAL, REMOTE, UNRESOLVED, Hit
from .values import Budget, Clock

MAX_STEPS = 400_000             # syntax-tree nodes visited per file (all passes together)
MAX_SECONDS = V.SAFETY_SECONDS  # a far safety cap only (the nodes are the limit); it makes the note too
_MAX_PASSES = 8                 # rounds of "what is tainted now" until nothing changes
_MAX_HITS = 8
_MAX_HANDOVER = 4               # hand-overs a function is followed through as a value (and nested lambdas)
_MAX_CLASSES = 200              # classes of one file whose objects are told apart
_MAX_FIELDS = 2000              # fields of one file that can carry a download
_MAX_REFS = 2000                # names of one file that hold a function
_MAX_HELD = 16                  # functions one name can hold
_MAX_HANDED = 16                # arguments kept per parameter (what a start's command can be)

# calls that hand a function on to be called later: where the function stands (position,
# keyword) and where its arguments do - as a tuple and a dict (positions), or as the rest
# of the call
_AS_TUPLE, _AS_REST = "tuple", "rest"
_STARTS = {
    "threading.Thread": (1, "target", _AS_TUPLE, 3, 4),
    "multiprocessing.Process": (1, "target", _AS_TUPLE, 3, 4),
    "threading.Timer": (1, "function", _AS_TUPLE, 2, 3),
    "thread.start_new_thread": (0, "function", _AS_TUPLE, 1, 2),
    "_thread.start_new_thread": (0, "function", _AS_TUPLE, 1, 2),
    "renpy.invoke_in_thread": (0, "fn", _AS_REST, 0, 0),
    "renpy.exports.invoke_in_thread": (0, "fn", _AS_REST, 0, 0),
    "functools.partial": (0, "", _AS_REST, 0, 0),
    "renpy.partial": (0, "", _AS_REST, 0, 0),
    "renpy.exports.partial": (0, "", _AS_REST, 0, 0),
    "renpy.curry": (0, "", _AS_REST, 0, 0),
    "renpy.exports.curry": (0, "", _AS_REST, 0, 0),
}
# ... and those whose result is the function itself, to be called with (more) arguments
_BINDS = frozenset(name for name in _STARTS if name.endswith(("partial", "curry")))
# pools of threads or processes, and their methods that hand a function on
_POOLS = frozenset("""concurrent.futures.ThreadPoolExecutor concurrent.futures.ProcessPoolExecutor
concurrent.futures.thread.ThreadPoolExecutor concurrent.futures.process.ProcessPoolExecutor
multiprocessing.Pool multiprocessing.pool.Pool multiprocessing.pool.ThreadPool
multiprocessing.dummy.Pool""".split())
_POOL_CALLS = dict.fromkeys(("submit", "map", "imap", "imap_unordered", "starmap", "map_async",
                             "starmap_async"), (0, "fn", _AS_REST, 0, 0))
_POOL_CALLS.update(dict.fromkeys(("apply", "apply_async"), (0, "func", _AS_TUPLE, 1, 2)))

# Across files (step 2 of the same work): a file is read a second time with the names it
# shares with other files as if they were downloads. What reaches something that runs
# is what the file "runs"; what a real download is stored under is what it "fills".
SHARED = "shared"               # the kind of such a stand-in source
_MAX_SHARED = 64                # shared names one file can fill, and can run
SHARED_STEPS = 400_000          # syntax-tree nodes the second reading visits: its limit
SHARED_SECONDS = V.SAFETY_SECONDS   # ... and a far safety cap by the clock (the step limit comes first)
STEPS, SECONDS = "steps", "seconds"         # which of the two cut a second reading short
_IDENT = re.compile(r"[A-Za-z_]\w*\Z")
_BUILTIN = frozenset(dir(builtins)) | frozenset(
    "execfile unicode file raw_input xrange basestring long unichr reduce cmp reload".split())
_MAX_STARTED = 256              # files one script starts, as another file can know them
_NOT_SHARED = frozenset({"store", "renpy", "config", "persistent", "self", "cls"}) | _BUILTIN
# Ren'Py's ``persistent``: one object for every script of the game (and kept between
# runs of it). Its fields are shared names like the names of the store
_PERSISTENT = ("persistent.", "store.persistent.", "renpy.store.persistent.", "renpy.game.persistent.")
# A module written from the network and imported by another script. The path it is written
# to is put together as a text, parts that are only known when the script runs as ‹name›.
_MAX_IMPORTED = 256             # names one script imports, as kept for the join
_IMPORT = re.compile(r"^[ \t]*(?:\$[ \t]*)?(?:import[ \t]+([\w., \t]+)"
                     r"|from[ \t]+([\w.]+)[ \t]+import[ \t]+\(?([\w., \t*]+))", re.M)
_JOINS = frozenset({"os.path.join", "posixpath.join", "ntpath.join"})
_SAME_PATH = frozenset({"os.path.abspath", "os.path.normpath", "os.path.realpath", "str", "unicode",
                        "renpy.fsencode", "renpy.fsdecode", "renpy.exports.fsencode",
                        "renpy.exports.fsdecode"})
# folders that are not the game's: a module written there is not found by an import
_ELSEWHERE = ("tempfile.", "os.environ", "os.getenv", "os.path.expanduser", "config.savedir",
              "renpy.config.savedir")
_ABSOLUTE = re.compile(r"[A-Za-z]:|[/~%]")
_MODULE_FILE = re.compile(r"/?((?:[^/‹›]+/)*)([A-Za-z_]\w*)\.(py|pyc|pyo|pyd)")
# where Python looks from the game's folder: the folder itself, game/, python-packages,
# and the folders of the bundled Python under lib/
_MODULE_ROOT = re.compile(r"(?:lib/[^/]+/(?:site-packages/)?|(?:game/)?(?:python-packages/)?)")


def imported(text: str) -> Dict[str, int]:
    """The modules a script imports with a plain ``import a.b`` / ``from a import
    b`` (also Ren'Py's ``$ import a``), with the line: ``a``, ``a.b``. Read from the
    text, line by line - nothing is parsed. At most ``_MAX_IMPORTED`` names."""
    out: Dict[str, int] = {}
    if "import" not in text:
        return out
    line, at = 1, 0
    for match in _IMPORT.finditer(text):
        line += text.count("\n", at, match.start())
        at = match.start()
        names: List[str] = []
        if match.group(1):
            wanted = [part.split()[0] for part in match.group(1).split(",") if part.split()]
        else:
            base = match.group(2).strip(".")
            members = [part.split()[0] for part in match.group(3).split(",") if part.split()]
            wanted = [base] + [base + "." + member for member in members if member != "*"] if base else members
        for dotted in wanted:
            parts = [part for part in dotted.split(".") if part]
            names += [".".join(parts[:count]) for count in range(1, len(parts) + 1)]
        for name in names:
            if name not in out and len(out) < _MAX_IMPORTED:
                out[name] = line
    return out


def _persistent(name: str) -> Optional[str]:
    """``persistent.x`` - also written ``store.persistent.x.y`` ... - as ``persistent.x``
    (None: not a field of it)."""
    for prefix in _PERSISTENT:
        if name.startswith(prefix):
            field = name[len(prefix):].split(".")[0]
            return "persistent." + field if field else None
    return None


class Shared:
    """What one script shares with the other scripts of its folder (:func:`study`).
    ``cut``: the second reading reached a limit (``STEPS`` or ``SECONDS``; "" when it
    came to its end), so ``runs`` and ``starts`` may lack names. ``limit``: the first
    reading - the one that looks for a chain inside the file - stopped at its count of
    steps ("": it did not)."""

    __slots__ = ("fills", "runs", "drops", "starts", "cut", "limit")

    def __init__(self) -> None:
        self.fills: Dict[str, Tuple[str, int, str, str]] = {}
        self.runs: Dict[str, Tuple[str, str, int, str]] = {}
        self.drops: Dict[str, Tuple[str, int, str, str, str]] = {}
        self.starts: Dict[str, Tuple[str, int]] = {}
        self.cut = ""
        self.limit = ""

    def __bool__(self) -> bool:
        return bool(self.fills or self.runs or self.drops or self.starts)
_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset(
    _IND[0].split())

# cheap tests: is there a request at all, and anything that could run its answer?
_NET_HINT = re.compile(_IND[1])
_SINK_HINT = re.compile(_IND[2])

_REQUEST = frozenset(_IND[3].split())
_RETRIEVE = frozenset({_IND[4], _IND[5]})
# objects a request is made through: the answer comes out of their methods
_CLIENT = frozenset("""requests.Session requests.session http.client.HTTPConnection
http.client.HTTPSConnection httplib.HTTPConnection httplib.HTTPSConnection socket.socket
socket.create_connection socket.socketpair ftplib.FTP ftplib.FTP_TLS urllib.request.build_opener
urllib2.build_opener urllib3.PoolManager""".split())
_HOST_FIRST = {"HTTPConnection": "http://", "HTTPSConnection": "https://", "FTP": "ftp://",
               "FTP_TLS": "ftp://", "create_connection": ""}
_ASKS = frozenset(_IND[6].split())
_WRAPS_ADDRESS = frozenset({"urllib.request.Request", "urllib2.Request"})

_CODE = frozenset(_IND[7].split())
_COMMAND = frozenset(_IND[8].split())
# what starts, imports or executes a *file* (besides the command calls above)
_RUNS_FILE = frozenset("""execfile runpy.run_path imp.load_source imp.load_module imp.load_compiled
importlib.import_module __import__ importlib.machinery.SourceFileLoader
importlib.machinery.SourcelessFileLoader renpy.load_module renpy.exports.load_module
webbrowser.open""".split()) - {"webbrowser.open"}
_NATIVE = re.compile(r"(?:^|\.)(?:windll|cdll|oledll|WinDLL|CDLL|OleDLL)(?:\.|$)|^ctypes\.(?:memmove|memset"
                     r"|cast|CFUNCTYPE|WINFUNCTYPE|string_at)$")
_OPEN = frozenset({"open", "io.open", "codecs.open", "file", "os.fdopen"})
_WRITES = frozenset({"write", "writelines"})
_EXTRACTS = frozenset({"extractall", "extract"})
# functions whose result says nothing about the content of what they were given
_FACTS = frozenset("""len isinstance type id hash bool int float print repr callable hasattr range xrange
min max sum abs round sorted enumerate zip all any ord chr""".split()) - {"sorted", "enumerate", "zip"}
_REMOTE_AT = re.compile(r"\s*(?:https?|wss?|ftps?)://", re.I)
_LOCAL_AT = re.compile(r"\s*(?:file:|(?:https?|wss?|ftp)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)"
                       r"(?:[:/]|$)|(?:localhost|127\.\d+\.\d+\.\d+|::1)$)", re.I)
_HOSTLIKE = re.compile(r"[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:/|$)")


class _Source:
    """A request, or an object that requests are made through."""

    __slots__ = ("what", "line", "kind", "address", "client")

    def __init__(self, what: str, line: int, kind: str, address: str, client: bool = False) -> None:
        self.what, self.line, self.kind, self.address, self.client = what, line, kind, address, client


class _Drop:
    """A file that was written from the network (or, in the local reading, from a decoded
    file of the game). ``extracted``: an archive was unpacked there."""

    __slots__ = ("source", "line", "ids", "shown", "extracted", "folders")

    def __init__(self, source: _Source, line: int, ids: Set[str], shown: str, extracted: bool = False,
                 folders: Optional[Set[str]] = None) -> None:
        self.source, self.line, self.ids, self.shown = source, line, ids, shown
        self.extracted = extracted
        # ways to recognise the folder the file lies in (an archive unpacked: that folder itself)
        self.folders: Set[str] = folders or set()


# -- the local chain (CHAIN-LOCAL-DROP; phageo, 2026-10-15/17): a file of the game is read,
# decoded, written or unpacked, and what was written is started - no download at all. The
# same tracer, with one other source: the content of a local file, which counts once it went
# through a decoder (a file that is only copied and started is no chain).
LOCAL_FILE = "local file"       # the kind of such a source
_LOCAL_READS = frozenset("""renpy.file renpy.exports.file renpy.open_file renpy.exports.open_file
renpy.loader.load io.FileIO""".split())
# decoders by name -> the step they are (a step the scanner can apply again in memory:
# localdrop.decode; ("custom",) cannot be)
_DECODERS = {
    _IND[9]: ("base64",), "base64.standard_b64decode": ("base64",), "base64.decodestring": ("base64",),
    "base64.decodebytes": ("base64",), "base64.urlsafe_b64decode": ("base64-url",),
    "base64.b32decode": ("base32",), "base64.b16decode": ("hex",), "base64.b85decode": ("base85",),
    "base64.a85decode": ("ascii85",), "binascii.a2b_base64": ("base64",), "binascii.unhexlify": ("hex",),
    "binascii.a2b_hex": ("hex",), "bytes.fromhex": ("hex",), "bytearray.fromhex": ("hex",),
    "zlib.decompress": ("zlib",), "gzip.decompress": ("gzip",), "bz2.decompress": ("bz2",),
    "lzma.decompress": ("lzma",), _IND[10]: ("custom",),
}
_CODEC_STEPS = {"base64": ("base64",), "base_64": ("base64",), "base64_codec": ("base64",), "hex": ("hex",),
                "hex_codec": ("hex",), "zlib": ("zlib",), "zip": ("zlib",), "zlib_codec": ("zlib",),
                "bz2": ("bz2",), "bz2_codec": ("bz2",), "rot13": ("custom",), "rot_13": ("custom",),
                "uu": ("custom",), "uu_codec": ("custom",)}
_KEEPS = frozenset({"ord", "chr", "bytes", "bytearray", "str", "list", "memoryview", "iter"})
_ARCHIVES = frozenset({"zipfile.ZipFile", "tarfile.open", "tarfile.TarFile"})
_ELEMENTWISE = (ast.Add, ast.Sub, ast.Mult, ast.Mod, ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr)
_LOCAL_HINT = re.compile(r"b64decode|b32decode|b16decode|b85decode|a85decode|decodestring|decodebytes|a2b_"
                         r"|unhexlify|fromhex|decompress|codecs\.decode|\.decode\(\s*['\"](?:base64|hex|zlib|bz2)"
                         r"|[\w\])]\s*\^=?\s*[\w(]|\.translate\(")
_READ_HINT = re.compile(r"\bopen\s*\(|renpy\.(?:exports\.)?(?:file|open_file)\b|loader\.load|read_bytes|FileIO")


class _Local(_Source):
    """The content of a local file: where it was read (``path``, as far as it is written
    out), and the decoding steps it went through since (``steps``)."""

    __slots__ = ("path", "steps", "paths")

    def __init__(self, what: str, line: int, path: str, steps: Tuple[Tuple, ...] = (),
                 paths: Tuple[str, ...] = ()) -> None:
        super().__init__(what, line, LOCAL_FILE, "")
        self.path, self.steps = path, steps
        self.paths = paths              # the path for each text of a loop name in it (_loop_paths)

    def then(self, step: Tuple) -> "_Local":
        if len(self.steps) >= 16:
            return self
        return _Local(self.what, self.line, self.path, self.steps + (step,), self.paths)

    @property
    def decoded(self) -> bool:
        return any(step[0] != "slice" for step in self.steps)


class LocalDrop:
    """A file of the game read, decoded, written (or unpacked) and started
    (:func:`local_drops`). ``read``: the path read, as far as it is written out
    (``‹›`` for what is only known when the script runs); ``steps``: the decoding
    steps in order (``localdrop.decode`` applies them again). ``via``: "" when the written
    file itself is started; :data:`WORKING_FOLDER` / :data:`PROGRAM_FOLDER` when the start
    reaches it through its folder (phageo, 2026-10-18) - then ``others`` holds ``(read, steps)``
    of every decoded file written to that folder, for the proof."""

    __slots__ = ("read", "read_line", "steps", "written", "write_line", "extracted", "sink", "line", "via",
                 "others")

    def __init__(self, read: str, read_line: int, steps, written: str, write_line: int, extracted: bool,
                 sink: str, line: int, via: str = "", others=()) -> None:
        self.read, self.read_line, self.steps = read, read_line, tuple(steps)
        self.written, self.write_line, self.extracted = written, write_line, extracted
        self.sink, self.line = sink, line
        self.via, self.others = via, tuple(others)


# a start that reaches a written file through its folder (phageo, 2026-10-18): the folder it
# works in holds the file, or the program it starts lies in the folder the file was written to
WORKING_FOLDER, PROGRAM_FOLDER = "working folder", "program's folder"
_MAX_IN_FOLDER = 16             # written files of one folder handed on for the proof


def _dotted(node: ast.AST) -> Optional[str]:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):                  # requests.Session().get
        inner = _dotted(node.func)
        return None if inner is None or len(parts) > 4 else ".".join([inner + "()"] + parts[::-1])
    if isinstance(node, ast.Name) and len(parts) <= 5:
        return ".".join([node.id] + parts[::-1])
    return None


def _shown(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)[:120]
    except Exception:
        return ""


class _Flow:
    def __init__(self, tree: ast.Module, resolved, clock: Clock, shared: bool = False,
                 store: bool = False, local: bool = False) -> None:
        self.tree, self.clock = tree, clock
        # local: the reading for the local chain - the sources are the decoded contents of
        # local files, not requests; only a file written from them and started is found
        self.local = local
        self.local_hits: List[LocalDrop] = []
        # (the local reading keeps a name's value per line that gives it one: "data =
        # zlib.decompress(data)" reads the value of the line before and is read again in
        # every round - a name with one value for all lines would be decoded once a round)
        self.versions: Dict[Tuple[int, str], Dict[int, "_Local"]] = {}
        self.targets: Set[Tuple[int, str]] = set()      # names the statement being read assigns
        # (the local reading: a loop over written-out texts - "for name in ('a.dat', 'b.dat')" -
        # gives its name each of them, so the proof can try every file read that way)
        self.loops: Dict[Tuple[int, str], List[str]] = {}
        self.loop_value: Dict[Tuple[int, str], str] = {}  # the one value _path_text gives a loop name now
        # shared: the second reading - requests are not sources, names shared with other
        # files are. store: the file's own top-level names live in Ren'Py's store
        self.shared, self.store = shared, store
        self.stand_ins: Dict[str, _Source] = {}
        self.runs: Dict[str, Tuple[str, str, int, str]] = {}    # shared name -> how it is run
        self.starts: Dict[str, Tuple[str, int]] = {}    # file name / shared name of a path -> what starts it
        self.own: Set[str] = set()                      # top-level names the file gives a value itself
        self.pools: Set[Tuple[int, str]] = set()        # names that hold a pool of threads
        # addresses the payload resolver already worked out, by line
        self.urls: Dict[int, Any] = {}
        for hit in resolved or ():
            if getattr(hit, "kind", "") == "url" and hit.line and hit.layer == 0:
                self.urls.setdefault(hit.line, hit)
        self.alias: Dict[str, str] = {}                 # local name -> what was imported
        self.scope_of: Dict[int, int] = {}              # id(function node) -> scope number
        self.locals: List[Set[str]] = [set()]           # names assigned in each scope (0 = file)
        self.parent: List[int] = [0]
        self.functions: Dict[str, List[Tuple[int, ast.AST]]] = {}
        self.taint: Dict[Tuple[int, str], Tuple[_Source, int]] = {}
        self.handles: Dict[Tuple[int, str], ast.AST] = {}   # file handle -> the path it was opened with
        self.assigned: Dict[Tuple[int, str], List[ast.AST]] = {}
        # a parameter -> the arguments calls of the file hand it, with the scope of each call
        self.handed: Dict[Tuple[int, str], List[Tuple[int, ast.AST]]] = {}
        self.handed_more: Set[Tuple[int, str]] = set()  # ... handed more than _MAX_HANDED
        self.drops: List[_Drop] = []
        self.hits: List[Hit] = []
        self.changed = False
        self.scope, self.line = 0, 1
        self.final = False
        # classes of the file: name -> (method name -> [(scope, node)], base classes by name)
        self.classes: Dict[str, Tuple[Dict[str, List[Tuple[int, ast.AST]]], List[str]]] = {}
        self.owner: Dict[int, str] = {}                 # scope of a method -> its class
        self.root: Dict[str, str] = {}                  # class -> the family it shares fields with
        self.made: Dict[Tuple[int, str], str] = {}      # name of an object -> its class
        self.fields: Dict[str, List[Tuple[int, str]]] = {}   # field name -> where it carries a download
        self.field_count = 0
        # names that hold a function: key -> {id(node): (scope, node, hand-overs so far)}
        self.refs: Dict[Tuple[int, str], Dict[int, Tuple[int, ast.AST, int]]] = {}
        self.nesting = 0                                # lambdas entered inside one another

    # -- preparation ----------------------------------------------------------------
    def prepare(self) -> None:
        self._declare(self.tree.body, 0)
        # classes related by inheritance inside the file share their fields
        root = {name: name for name in self.classes}

        def find(name: str) -> str:
            while root[name] != name:
                name = root[name]
            return name

        for name, (_methods, bases) in self.classes.items():
            for base in bases:
                if base in root:
                    one, other = find(name), find(base)
                    if one != other:
                        root[max(one, other)] = min(one, other)
        self.root = {name: find(name) for name in root}
        if self.shared:
            # a top-level name this file computes itself is its own, whatever another file
            # stores under it; one it only declares (None, a number, a text) is not
            todo: List[ast.AST] = list(self.tree.body)
            while todo:
                node = todo.pop()
                self.clock.tick()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    value = node.value
                    if value is not None and not isinstance(value, ast.Constant):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        self.own.update(t.id for t in targets if isinstance(t, ast.Name))
                    continue
                todo.extend(child for child in ast.iter_child_nodes(node) if isinstance(child, ast.stmt))

    # -- names shared with other files (the second reading) -----------------------------
    def _stand_in(self, name: str) -> _Source:
        found = self.stand_ins.get(name)
        if found is None:
            found = self.stand_ins[name] = _Source(name, self.line, SHARED, "")
        return found

    def _shared_dotted(self, name: str) -> Optional[_Source]:
        """``store.x`` / ``module.x`` (as imported) as a shared name."""
        field = _persistent(name)
        if field is not None and not name.startswith("persistent."):
            return self._stand_in("store:" + field)       # store.persistent.x
        if name.startswith("renpy.store."):
            name = name[6:]
        if name.startswith("store."):
            rest = name[6:].split(".")[0]
            return self._stand_in("store:" + rest) if rest else None
        if name.split(".")[0] in _STDLIB:
            return None
        return self._stand_in("module:" + name)

    def _shared_name(self, name: str) -> Optional[_Source]:
        if self._is_local(name) or name in _NOT_SHARED:
            return None
        target = self.alias.get(name)
        if target is not None:                            # from module import name
            return self._shared_dotted(target) if "." in target else None
        if name in self.functions or name in self.classes or name in self.own:
            return None
        return self._stand_in("store:" + name) if self.store else None

    def _shared_attr(self, node: ast.Attribute) -> Optional[_Source]:
        raw, name = _dotted(node), self.canon(node)
        if raw is None or name is None or "()" in name:
            return None
        head = raw.split(".")[0]
        if self._is_local(head):
            return None
        field = _persistent(name)
        if field is not None and not (name.startswith("persistent.") and not self._bare_persistent()):
            return self._stand_in("store:" + field)
        if name.startswith(("store.", "renpy.store.")) or head in self.alias:
            return self._shared_dotted(name)
        return None

    def _bare_persistent(self) -> bool:
        """Is a plain ``persistent`` in this file Ren'Py's? (In a script of the store,
        unless the file imports or computes something of that name itself.)"""
        return self.store and "persistent" not in self.alias and "persistent" not in self.own

    def _shared_call(self, node: ast.Call, name: str) -> Optional[_Source]:
        """What a function of another file returns: ``module.get()``, or a function
        of Ren'Py's store called by its bare name."""
        if not self.shared or not name or "()" in name:
            return None
        func = node.func
        if isinstance(func, ast.Name):
            if (self._is_local(func.id) or func.id in _NOT_SHARED or func.id in self.functions
                    or func.id in self.classes):
                return None
            target = self.alias.get(func.id)
            if target is not None:
                return self._shared_dotted(target + "()") if "." in target else None
            return self._stand_in("store:%s()" % func.id) if self.store else None
        if isinstance(func, ast.Attribute):
            raw = _dotted(func)
            head = raw.split(".")[0] if raw else ""
            if not head or self._is_local(head):
                return None
            if name.startswith(("store.", "renpy.store.")) or head in self.alias:
                return self._shared_dotted(name + "()")
        return None

    def filled(self) -> Dict[str, Tuple[str, int, str, str]]:
        """The shared names this file stores a download under: ``store:x`` for a name
        written ``store.x``, ``global:x`` for a top-level name and ``global:f()`` for
        what a top-level function returns - ``(request, line, kind, address)`` each."""
        out: Dict[str, Tuple[str, int, str, str]] = {}
        tops = {number: name for name, items in self.functions.items() for number, _node in items
                if self.parent[number] == 0 and number not in self.owner}
        for (scope, name), (source, _line) in self.taint.items():
            if scope != 0 or source.kind == SHARED or source.client:
                continue
            if name.startswith("return of "):
                function = tops.get(int(name[10:]))
                shared = "global:%s()" % function if function else None
            else:
                shared = self._fill_name(name)
            if shared and shared not in out and len(out) < _MAX_SHARED:
                out[shared] = (source.what, source.line, source.kind, source.address)
        return out

    def _fill_name(self, name: str) -> Optional[str]:
        """A name of the file's top level as other files know it: ``store:x`` for
        ``store.x`` and for a field of ``persistent``, ``global:x`` for a plain name."""
        head = name.split(".")[0]
        full = self.alias[head] + name[len(head):] if head in self.alias else name
        field = _persistent(full)
        if field is not None:
            if full.startswith("persistent.") and (head in self.alias or not self.store):
                return None                               # a persistent of the file's own
            return "store:" + field
        if name.startswith(("store.", "renpy.store.")):
            rest = name.split("store.", 1)[1].split(".")[0]
            return "store:" + rest if rest else None
        return "global:" + name if _IDENT.match(name) else None

    def dropped(self) -> Dict[str, Tuple[str, int, str, str, str]]:
        """The files this file writes a download to, by what another file can know
        them by: ``file:<name>`` for a file name that is written out, and the shared
        name (as in :meth:`filled`) that holds the path - ``(request, line, kind,
        address, path as written)`` each. A path that is only an expression of the
        file's own names says nothing to another file."""
        out: Dict[str, Tuple[str, int, str, str, str]] = {}
        for drop in self.drops:
            source = drop.source
            if source.kind == SHARED:
                continue
            for one in sorted(drop.ids):
                shared = one if one.startswith(("file:", "import:")) else \
                    self._fill_name(one[7:]) if one.startswith("name:0:") else None
                if shared and shared not in out and len(out) < _MAX_SHARED:
                    out[shared] = (source.what, source.line, source.kind, source.address, drop.shown)
        return out

    def _declare(self, body: List[ast.stmt], scope: int) -> None:
        for node in body:
            self._declare_node(node, scope)

    def _declare_node(self, node: ast.AST, scope: int) -> None:
        self.clock.tick()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", None) or ""
            for item in node.names:
                if isinstance(node, ast.Import):
                    local = item.asname or item.name.split(".")[0]
                    self.alias[local] = item.name if item.asname else item.name.split(".")[0]
                elif item.name != "*":
                    self.alias[item.asname or item.name] = (module + "." + item.name).lstrip(".")
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            number = len(self.locals)
            self.scope_of[id(node)] = number
            args = node.args
            names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            names.update(a.arg for a in (args.vararg, args.kwarg) if a is not None)
            self.locals.append(names)
            self.parent.append(scope)
            self.functions.setdefault(node.name, []).append((number, node))
            declared: Set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Global, ast.Nonlocal)):
                    declared.update(sub.names)
            self._collect_targets(node.body, number)
            self.locals[number] -= declared
            self._declare(node.body, number)
            return
        if isinstance(node, ast.ClassDef):
            known = self.classes.get(node.name)
            if known is None and len(self.classes) < _MAX_CLASSES:
                known = self.classes[node.name] = ({}, [])
            if known is not None:
                known[1].extend(base.id for base in node.bases[:8] if isinstance(base, ast.Name))
            for child in node.body:
                self._declare_node(child, scope)
                if known is not None and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    number = self.scope_of[id(child)]
                    self.owner[number] = node.name
                    known[0].setdefault(child.name, []).append((number, child))
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.excepthandler)) or type(child).__name__ == "match_case":
                self._declare_node(child, scope)

    def _collect_targets(self, body: List[ast.stmt], scope: int) -> None:
        stack: List[ast.AST] = list(body)
        while stack:
            node = stack.pop()
            self.clock.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if not isinstance(node, ast.Lambda):
                    self.locals[scope].add(node.name)
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.locals[scope].add(node.id)
            stack.extend(ast.iter_child_nodes(node))

    # -- names ----------------------------------------------------------------------
    def canon(self, node: ast.AST) -> Optional[str]:
        name = _dotted(node)
        if name is None:
            return None
        head, _, rest = name.partition(".")
        bare = head[:-2] if head.endswith("()") else head
        if bare in self.alias and not self._is_local(bare):
            head = self.alias[bare] + ("()" if head.endswith("()") else "")
        name = head + ("." + rest if rest else "")
        for prefix in ("builtins.", "__builtin__.", "six.moves.", "six.moves.urllib."):
            if name.startswith(prefix):
                name = ("urllib." if prefix.endswith("urllib.") else "") + name[len(prefix):]
        return name

    def _is_local(self, name: str) -> bool:
        scope = self.scope
        while scope:
            if name in self.locals[scope]:
                return True
            scope = self.parent[scope]
        return False

    def key(self, name: str) -> Tuple[int, str]:
        """Where a plain name lives: the innermost function that assigns it, else the file."""
        scope = self.scope
        while scope:
            if name in self.locals[scope]:
                return scope, name
            scope = self.parent[scope]
        return 0, name

    def key_of(self, node: ast.AST) -> Optional[Tuple[int, str]]:
        if isinstance(node, ast.Name):
            return self.key(node.id)
        name = _dotted(node)
        if name is None or "()" in name:
            return None
        head, _, rest = name.partition(".")
        if head in ("self", "cls"):
            # a field: shared by the methods of the class and of the classes related to it
            # in the file ("?": the code is in no class the tracer knows)
            cls = self._owner()
            return -1, (self.root.get(cls, cls) if cls else "?") + "." + rest
        cls = self.made.get(self.key(head))
        if cls is not None and rest:                      # a field of an object of a known class
            return -1, self.root.get(cls, cls) + "." + rest
        return self.key(head)[0], name

    # -- objects and functions as values ----------------------------------------------
    def _owner(self) -> Optional[str]:
        """The class the code that is being read belongs to."""
        scope = self.scope
        while scope:
            cls = self.owner.get(scope)
            if cls is not None:
                return cls
            scope = self.parent[scope]
        return None

    def _class_called(self, func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name) and func.id in self.classes and func.id not in self.alias:
            return func.id
        return None

    def class_of(self, node: Optional[ast.AST]) -> Optional[str]:
        """The class of the file whose object ``node`` is, as far as its name tells."""
        if isinstance(node, ast.Call):
            return self._class_called(node.func)
        if isinstance(node, ast.Name):
            if node.id in ("self", "cls"):
                return self._owner()
            return self.made.get(self.key(node.id))
        if isinstance(node, ast.Attribute):
            key = self.key_of(node)
            return self.made.get(key) if key is not None else None
        return None

    def _methods(self, cls: str, name: str) -> List[Tuple[int, ast.AST]]:
        """The method ``name`` of a class: its own, else the nearest base class's in the file."""
        todo, seen = [cls], set()
        while todo and len(seen) < 16:
            one = todo.pop(0)
            if one in seen or one not in self.classes:
                continue
            seen.add(one)
            methods, bases = self.classes[one]
            if name in methods:
                return methods[name]
            todo.extend(bases)
        return []

    def _lambda_scope(self, node: ast.Lambda) -> int:
        number = self.scope_of.get(id(node))
        if number is None:
            args = node.args
            names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            names.update(a.arg for a in (args.vararg, args.kwarg) if a is not None)
            number = len(self.locals)
            self.locals.append(names)
            self.parent.append(self.scope)
            self.scope_of[id(node)] = number
        return number

    def _callable(self, node: Optional[ast.AST], depth: int = 0) -> List[Tuple[int, ast.AST, int]]:
        """The functions of the file ``node`` stands for: ``(scope, node, hand-overs so far)``."""
        if node is None or depth > _MAX_HANDOVER:
            return []
        self.clock.tick()
        if isinstance(node, ast.Lambda):
            return [(self._lambda_scope(node), node, 0)]
        if isinstance(node, ast.Call):                    # partial(f, ...), renpy.curry(f)(...)
            inner = node.func if isinstance(node.func, ast.Call) else node
            if self.canon(inner.func) in _BINDS and inner.args:
                return self._callable(inner.args[0], depth + 1)
            return []
        if isinstance(node, ast.Subscript):               # table["go"]
            holder = node.value
            key = self.key_of(holder) if isinstance(holder, (ast.Name, ast.Attribute)) else None
            return list(self.refs.get(key, {}).values()) if key is not None else []
        if isinstance(node, ast.Name):
            held = self.refs.get(self.key(node.id))
            if held:
                return list(held.values())
            if node.id in self.functions and node.id not in self.alias:
                return [(number, function, 0) for number, function in self.functions[node.id]]
            return []
        if isinstance(node, ast.Attribute):
            cls = self.class_of(node.value)
            if cls is not None:
                # start() of a class with a run() method (a thread) is run()
                found = self._methods(cls, node.attr) or (
                    self._methods(cls, "run") if node.attr == "start" else [])
                if found:
                    return [(number, function, 0) for number, function in found]
            key = self.key_of(node)
            held = self.refs.get(key) if key is not None else None
            if held:
                return list(held.values())
            if (isinstance(node.value, ast.Name) and node.value.id in ("self", "cls")
                    and node.attr in self.functions):
                return [(number, function, 0) for number, function in self.functions[node.attr]]
        return []

    def _refer(self, key: Optional[Tuple[int, str]], held: List[Tuple[int, ast.AST, int]]) -> None:
        """``key`` now holds these functions: one hand-over further than where they came from."""
        held = [one for one in held if one[2] < _MAX_HANDOVER]
        if key is None or not held:
            return
        slot = self.refs.get(key)
        if slot is None:
            if len(self.refs) >= _MAX_REFS:
                return
            slot = self.refs[key] = {}
        for number, function, depth in held:
            old = slot.get(id(function))
            if old is None and len(slot) >= _MAX_HELD:
                continue
            if old is None or old[2] > depth + 1:
                if old is None:
                    self.changed = True
                slot[id(function)] = (number, function, depth + 1)

    def _hand_on(self, key: Optional[Tuple[int, str]], value: Optional[ast.AST]) -> None:
        """A name, field or parameter is given ``value``: remember the class of an
        object and the functions it stands for."""
        if key is None or value is None:
            return
        cls = self.class_of(value)
        if cls is not None and key not in self.made:
            self.made[key] = cls
            self.changed = True
        held = self._callable(value)
        if not held and isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            members = value.values if isinstance(value, ast.Dict) else value.elts
            for member in members[:_MAX_HELD]:
                held = held + self._callable(member)
        self._refer(key, held)

    def _started(self, node: ast.Call, name: str):
        """``(function, arguments, keyword arguments)`` of a call that hands a
        function on to be called - in a thread, or bound to arguments (None: not one)."""
        spec = _STARTS.get(name)
        if spec is None and isinstance(node.func, ast.Attribute) and self._is_pool(node.func.value):
            spec = _POOL_CALLS.get(node.func.attr)        # executor.submit(f, ...), pool.map(f, ...)
        if spec is None:
            return None
        at, word, mode, args_at, kwargs_at = spec
        target = next((k.value for k in node.keywords if word and k.arg == word), None)
        rest = list(node.args)
        if target is None and len(node.args) > at:
            target, rest = node.args[at], list(node.args[at + 1:])
        if target is None:
            return None
        if mode == _AS_REST:
            return target, rest, [(k.arg, k.value) for k in node.keywords if k.arg and k.arg != word]
        given = next((k.value for k in node.keywords if k.arg == "args"), None)
        if given is None and len(node.args) > args_at:
            given = node.args[args_at]
        named = next((k.value for k in node.keywords if k.arg == "kwargs"), None)
        if named is None and len(node.args) > kwargs_at:
            named = node.args[kwargs_at]
        if isinstance(given, (ast.Tuple, ast.List)):
            positional = list(given.elts)
        else:                                             # a tuple made elsewhere: any of them
            positional = [given] * 8 if given is not None else []
        keywords = []
        if isinstance(named, ast.Dict):
            keywords = [(k.value, v) for k, v in zip(named.keys, named.values)
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        return target, positional, keywords

    def _is_pool(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            return self.canon(node.func) in _POOLS
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self.key_of(node) in self.pools
        return False

    def _start(self, node: ast.Call, name: str) -> Optional[_Source]:
        """Hand the arguments of such a call to the function it names. Returns what
        that function returns when the call gives it back (a pool's ``submit`` / ``map``)."""
        started = self._started(node, name)
        if started is None:
            return None
        target, positional, keywords = started
        bound = not (isinstance(target, ast.Name) and target.id in self.functions)
        returned = None
        for number, function, _depth in self._callable(target):
            self._invoke(number, function, positional, keywords, bound)
            returned = returned or self.lookup((0, "return of %d" % number))
        return returned if name not in _STARTS else None

    def _invoke(self, number: int, function: ast.AST, positional: List[ast.AST],
                keywords: List[Tuple[Optional[str], ast.AST]], bound: bool) -> None:
        """A function of the file is called with these arguments: what they carry
        (a download, an object's class, a function) arrives in its parameters."""
        args = function.args
        names = [a.arg for a in args.posonlyargs + args.args]
        if bound and names and names[0] in ("self", "cls"):
            names = names[1:]
        saved = self.line
        for index, argument in enumerate(positional):
            source = self.expr(argument)
            if index < len(names):
                self._arrive((number, names[index]), argument, source, function, saved)
        for word, argument in keywords:
            source = self.expr(argument)
            if word:
                self._arrive((number, word), argument, source, function, saved)
        self._enter(number, function)

    def _arrive(self, key: Tuple[int, str], argument: ast.AST, source: Optional[_Source],
                function: ast.AST, saved: int) -> None:
        if source is not None:
            self.line = getattr(function, "lineno", saved)
            self.mark(key, source)
            self.line = saved
        self._hand_on(key, argument)
        values = self.handed.setdefault(key, [])          # (what a start's command can be: _command_lists)
        if not any(value is argument for _scope, value in values):
            if len(values) < _MAX_HANDED:
                values.append((self.scope, argument))
            else:
                self.handed_more.add(key)

    def _enter(self, number: int, function: ast.AST) -> None:
        """A lambda has no statements the walk comes by: its body is read when it is called."""
        if not isinstance(function, ast.Lambda) or self.nesting >= _MAX_HANDOVER:
            return
        self.nesting += 1
        saved = (self.scope, self.line)
        try:
            self.scope, self.line = number, getattr(function, "lineno", self.line)
            source = self.expr(function.body)
            self._calls(function.body)
            if source is not None:
                self.scope, self.line = 0, 0
                self.mark((0, "return of %d" % number), source)
        finally:
            self.scope, self.line = saved
            self.nesting -= 1

    # -- taint ----------------------------------------------------------------------
    def mark(self, key: Optional[Tuple[int, str]], source: Optional[_Source]) -> None:
        if key is None or source is None:
            return
        if self.local and isinstance(source, _Local):
            held = self.versions.setdefault(key, {})
            old_value = held.get(self.line)
            if old_value is None or (old_value.path, old_value.steps) != (source.path, source.steps):
                if old_value is None and len(held) >= 64:
                    return
                held[self.line] = source
                self.changed = True
        old = self.taint.get(key)
        if old is None and key[0] == -1:
            if self.field_count >= _MAX_FIELDS:
                return
            self.field_count += 1
            self.fields.setdefault(key[1].partition(".")[2], []).append(key)
        if old is None or self.line < old[1]:
            if old is None:
                self.changed = True
            self.taint[key] = (source if old is None else old[0], self.line)

    def lookup(self, key: Optional[Tuple[int, str]]) -> Optional[_Source]:
        if key is None:
            return None
        held = self.versions.get(key) if self.local else None
        if held:
            # the value of the nearest line above (a name the statement assigns: strictly
            # above); none above in its own function - assigned further down; read from
            # elsewhere - the last one
            strict = key in self.targets
            above = [line for line in held if line < self.line or (line == self.line and not strict)]
            if above:
                return held[max(above)]
            if key[0] == self.scope:
                return None
            return held[max(held)]
        found = self.taint.get(key)
        if found is None and key[0] == -1:
            # code outside every known class ("?") reads any class's field of that name,
            # and a class reads what such code stored - as before classes were told apart
            bucket, _, rest = key[1].partition(".")
            if bucket == "?":
                found = next((self.taint[one] for one in self.fields.get(rest, ())), None)
            else:
                found = self.taint.get((-1, "?." + rest))
        if found is None:
            return None
        if key[0] == self.scope and found[1] > self.line:
            return None                                   # assigned further down in this function
        return found[0]

    def classify(self, node: Optional[ast.AST], line: int, prefix: str = "") -> Tuple[str, str]:
        """``(kind, address)`` of the address a request goes to."""
        if isinstance(node, ast.Call) and self.canon(node.func) in _WRAPS_ADDRESS and node.args:
            node = node.args[0]
        if isinstance(node, ast.Tuple) and node.elts:     # socket: (host, port)
            node = node.elts[0]
        hit = self.urls.get(line)
        if hit is not None:
            text = hit.value
            if hit.hidden:
                return HIDDEN, text[:200]
            known = V.known_part(text)
            if _LOCAL_AT.match(known):
                return LOCAL, text[:200]
            if _REMOTE_AT.match(known):
                return REMOTE, text[:200]
        text = self._literal(node)
        if text is not None:
            whole = text if "://" in text else prefix + text
            if _LOCAL_AT.match(whole) or _LOCAL_AT.match(text):
                return LOCAL, whole[:200]
            if _REMOTE_AT.match(whole) or (prefix == "" and _HOSTLIKE.match(text) and node is not None
                                           and isinstance(node, ast.Constant)):
                return REMOTE, whole[:200]
        return UNRESOLVED, _shown(node)

    def _literal(self, node: Optional[ast.AST]) -> Optional[str]:
        """The text of an address as far as it is written out (None: nothing is)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value = node.value
            return value if isinstance(value, str) else value.decode("latin-1")
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._literal(node.left)
        if isinstance(node, ast.JoinedStr) and node.values:
            return self._literal(node.values[0])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return self._literal(node.func.value)
        if isinstance(node, ast.Name):
            values = self.assigned.get(self.key(node.id), [])
            if len(values) == 1 and not isinstance(values[0], ast.Name):
                return self._literal(values[0])
        return None

    def _address_arg(self, call: ast.Call, name: str) -> Optional[ast.AST]:
        index = 1 if name.endswith(".request") and len(call.args) > 1 else 0
        for keyword in call.keywords:
            if keyword.arg in ("url", "fullurl", "host", "address"):
                return keyword.value
        return call.args[index] if len(call.args) > index else None

    def expr(self, node: Optional[ast.AST]) -> Optional[_Source]:
        """The request ``node``'s value comes from, or None."""
        if node is None:
            return None
        self.clock.tick()
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Name):
            found = self.lookup(self.key(node.id))
            return self._shared_name(node.id) if found is None and self.shared else found
        if isinstance(node, ast.Attribute):
            found = self.lookup(self.key_of(node))
            if found is None and self.shared:             # the whole name first: tools.net.payload
                found = self._shared_attr(node)
            return found or self.expr(node.value)
        if self.local and isinstance(node, ast.Subscript):
            source = self.expr(node.value)
            self.expr(node.slice)
            cut = node.slice
            if isinstance(source, _Local) and isinstance(cut, ast.Slice) and cut.step is None:
                # data[16:]: the part of the file that is decoded (a step the proof applies too)
                bounds = [None if one is None else one.value if isinstance(one, ast.Constant)
                          and isinstance(one.value, int) and not isinstance(one.value, bool) else "?"
                          for one in (cut.lower, cut.upper)]
                # (bounds that are not written out: a part the proof cannot cut - "?")
                return source.then(("slice",) + tuple(bounds) if "?" not in bounds else ("slice", "?", "?"))
            return source
        if isinstance(node, (ast.Subscript, ast.Starred, ast.Await, ast.UnaryOp, ast.FormattedValue)):
            return self.expr(getattr(node, "value", None) or getattr(node, "operand", None))
        if isinstance(node, ast.BinOp):
            if self.local:
                return self._local_operation(node)
            return self.expr(node.left) or self.expr(node.right)
        if isinstance(node, ast.BoolOp):
            return self._any(node.values)
        if isinstance(node, ast.IfExp):
            return self.expr(node.body) or self.expr(node.orelse)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._any(node.elts)
        if isinstance(node, ast.JoinedStr):
            return self._any(node.values)
        if isinstance(node, ast.Dict):
            return self._any([v for v in node.values if v is not None])
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for generator in node.generators:
                source = self.expr(generator.iter)
                if source is not None:
                    self.bind(generator.target, source)
            return self.expr(getattr(node, "elt", None) or getattr(node, "value", None)) or \
                self._any([g.iter for g in node.generators])
        if isinstance(node, ast.NamedExpr):
            source = self.expr(node.value)
            self.bind(node.target, source)
            return source
        return None

    def _any(self, nodes) -> Optional[_Source]:
        for node in nodes:
            source = self.expr(node)
            if source is not None:
                return source
        return None

    # -- the local reading: a file of the game, decoded ---------------------------------
    def _local_operation(self, node: ast.BinOp) -> Optional[_Source]:
        """``b ^ key`` and the like on the content of a local file: a decoding step. XOR
        with a key that is written out (a number, or a text indexed in turn) can be applied
        again; any other byte-wise arithmetic is a step of its own kind ("custom")."""
        left, right = self.expr(node.left), self.expr(node.right)
        mine = left if isinstance(left, _Local) else right if isinstance(right, _Local) else None
        if mine is None:
            return left or right
        if isinstance(left, _Local) and isinstance(right, _Local):
            return mine.then(("xor", None)) if isinstance(node.op, ast.BitXor) else mine
        other = node.right if mine is left else node.left
        if isinstance(node.op, ast.BitXor):
            return mine.then(("xor", self._key(other)))
        if isinstance(node.op, _ELEMENTWISE) and not (
                isinstance(other, ast.Constant) and isinstance(other.value, (str, bytes))):
            if isinstance(node.op, ast.Add) and isinstance(other, (ast.Name, ast.Attribute, ast.Subscript,
                                                                    ast.Call, ast.BinOp)):
                # data + other: perhaps two texts joined, not a byte decoded - only a number counts
                if not isinstance(self._constant(other), int):
                    return mine
            return mine.then(("custom",))
        return mine

    def _constant(self, node: Optional[ast.AST], depth: int = 0):
        """The value of a number or text written out - directly, or as the one value a
        name is given (None: not one)."""
        if depth > 4 or node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, str, bytes)) \
                and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name):
            values = self.assigned.get(self.key(node.id), [])
            return self._constant(values[0], depth + 1) if len(values) == 1 else None
        if isinstance(node, ast.Call) and self.canon(node.func) == "ord" and len(node.args) == 1:
            value = self._constant(node.args[0], depth + 1)
            return ord(value) if isinstance(value, str) and len(value) == 1 else None
        if isinstance(node, ast.Call) and self.canon(node.func) in ("bytes", "bytearray") and len(node.args) == 1 \
                and isinstance(node.args[0], (ast.List, ast.Tuple)):
            items = [self._constant(one, depth + 1) for one in node.args[0].elts[:256]]
            return bytes(items) if all(isinstance(i, int) and 0 <= i < 256 for i in items) else None
        return None

    def _key(self, node: ast.AST) -> Optional[str]:
        """The XOR key, in hex, when it is written out: a number (``b ^ 0x5A``), or a text
        or bytes taken in turn (``key[i % len(key)]``). None: not known here."""
        if isinstance(node, ast.Subscript):
            value = self._constant(node.value)
            if isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except UnicodeEncodeError:
                    return None
            return value.hex() if isinstance(value, bytes) and 0 < len(value) <= 4096 else None
        value = self._constant(node)
        return bytes([value]).hex() if isinstance(value, int) and 0 <= value < 256 else None

    def _local_call(self, node: ast.Call, name: str, line: int) -> Optional[_Source]:
        """The local reading: a file of the game that is read (``open`` for reading,
        ``renpy.file``, ``Path(...).read_bytes()``), and the decoders it goes through
        (Base64, hex, zlib / gzip / bz2 / lzma, ``codecs.decode``, a text's ``.decode("base64")``,
        ``.translate``). None: no such call - the ordinary reading goes on."""
        func = node.func
        if (name in _OPEN or name in _LOCAL_READS) and node.args:
            dropped = self._dropped(node.args[0])
            if dropped is not None:
                return dropped.source                     # reading back what was written
            if name in _LOCAL_READS or self._opened(node) is None:
                return _Local(_shown(node) or name, line, self._path_text(node.args[0]),
                              paths=self._loop_paths(node.args[0]))
            return None
        if isinstance(func, ast.Attribute) and func.attr in ("read_bytes", "read_text"):
            holder = func.value
            path = holder.args[0] if isinstance(holder, ast.Call) and holder.args else holder
            return _Local(_shown(node), line, self._path_text(path), paths=self._loop_paths(path))
        if name in _ARCHIVES and node.args:              # zipfile.ZipFile(the path a decoded file was written to)
            dropped = self._dropped(node.args[0])
            return dropped.source if dropped is not None else None
        step, given = _DECODERS.get(name), node.args[0] if node.args else None
        if step is None and name == "codecs.decode" and node.args:
            codec = node.args[1] if len(node.args) > 1 else next(
                (k.value for k in node.keywords if k.arg == "encoding"), None)
            if isinstance(codec, ast.Constant) and isinstance(codec.value, str):
                step = _CODEC_STEPS.get(codec.value.lower().replace("-", "_"))
        if step is None and isinstance(func, ast.Attribute):
            if func.attr == "decode" and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                step, given = _CODEC_STEPS.get(node.args[0].value.lower().replace("-", "_")), func.value
            elif func.attr == "translate":
                step, given = ("custom",), func.value
            elif func.attr == "decompress" and name not in _DECODERS and node.args:
                step = ("custom",)                        # a decompressor object of its own
            elif func.attr in ("append", "extend", "insert") and node.args:
                source = self._any(node.args)
                if isinstance(source, _Local):            # out.append(b ^ key): out carries it
                    self.bind(func.value, source)
                return None
        if step is not None and given is not None:
            source = self.expr(given)
            return source.then(step) if isinstance(source, _Local) else None
        if name in _KEEPS and node.args:                  # bytes(...), chr(ord(c) ^ k)
            source = self._any(node.args)
            return source if isinstance(source, _Local) else None
        return None

    def _local_hit(self, drop: _Drop, sink: str, line: int, via: str = "", others=()) -> None:
        source = drop.source
        if not isinstance(source, _Local) or len(self.local_hits) >= _MAX_HITS or any(
                h.read_line == source.line and h.line == line for h in self.local_hits):
            return
        also = []
        for other in [drop] + list(others):
            one = other.source
            if not isinstance(one, _Local):
                continue
            # (a file read in a loop over written-out names: each of them, for the proof)
            for path in (one.paths or (one.path,)):
                if (path, one.steps) not in also and len(also) < _MAX_IN_FOLDER:
                    also.append((path, one.steps))
        self.local_hits.append(LocalDrop(source.path, source.line, source.steps, drop.shown, drop.line,
                                         drop.extracted, sink, line, via, also))

    def call(self, node: ast.Call) -> Optional[_Source]:
        name = self.canon(node.func) or ""
        line = getattr(node, "lineno", self.line)
        arguments = list(node.args) + [k.value for k in node.keywords]
        if isinstance(node.func, ast.Call):               # partial(f, data)(): the inner call first
            self.expr(node.func)
        handed = self._start(node, name)                  # Thread(target=f, args=...), partial(f, ...)
        if handed is not None:                            # pool.submit(f): what f returns
            return handed
        if self.local:
            found = self._local_call(node, name, line)
            if found is not None:
                return found
        if self.shared and (name in _REQUEST or name in _CLIENT):
            return None                                   # the second reading: no request is a source
        made = self._class_called(node.func)
        if made is not None:                              # Class(data): data arrives in __init__
            for number, function in self._methods(made, "__init__"):
                self._invoke(number, function, list(node.args),
                             [(k.arg, k.value) for k in node.keywords], True)
        if name in _REQUEST:
            kind, address = self.classify(self._address_arg(node, name), line)
            if name in _RETRIEVE:
                self._retrieve(node, _Source(name, line, kind, address) if kind != LOCAL else None)
            return None if kind == LOCAL else _Source(name, line, kind, address)
        if name in _CLIENT:
            leaf = name.rsplit(".", 1)[-1]
            if leaf in _HOST_FIRST and arguments:
                kind, address = self.classify(arguments[0], line, _HOST_FIRST[leaf])
                return None if kind == LOCAL else _Source(name, line, kind, address)
            return _Source(name, line, UNRESOLVED, "", client=True)
        if name.rsplit(".", 1)[-1] in _FACTS and "." not in name:
            for argument in arguments:
                self.expr(argument)
            return None
        if isinstance(node.func, ast.Attribute):
            base = self.expr(node.func.value)
            if base is not None:
                if base.client and node.func.attr in _ASKS and arguments:
                    # the address is only known here: session.get(address), sock.connect((host, port))
                    kind, address = self.classify(self._address_arg(node, "." + node.func.attr), line)
                    if kind == LOCAL:
                        return None
                    refined = _Source(base.what + "." + node.func.attr, line, kind, address)
                    if node.func.attr in ("connect", "connect_ex"):
                        self.taint_replace(node.func.value, refined)
                    return refined
                for argument in arguments:
                    self.expr(argument)
                if base.client:                           # sock.recv(...): what came in
                    return _Source(base.what + "." + node.func.attr, base.line, base.kind, base.address)
                return base
        local = self._local_function(node.func)
        if local:
            for number, function in local:
                self._pass_arguments(node, number, function)
                self._wrapped_drops(node, number, function)
            # (kept per function, not per name: two classes may each have a get())
            returned = next(filter(None, (self.lookup((0, "return of %d" % number))
                                          for number, _function in local)), None)
            for argument in arguments:
                self.expr(argument)
            return returned
        if name in _OPEN and node.args:
            dropped = self._dropped(node.args[0])
            if dropped is not None:
                return dropped.source                     # reading back what was downloaded
        return self._any(arguments) or self._shared_call(node, name)

    def taint_replace(self, node: ast.AST, source: _Source) -> None:
        key = self.key_of(node)
        if key is not None and key in self.taint:
            self.taint[key] = (source, self.taint[key][1])

    def _local_function(self, func: ast.AST):
        """The functions of the file a call calls: by name, as a method of an object
        of a known class, or through a name that was handed a function."""
        return [(number, function) for number, function, _depth in self._callable(func)] or None

    def _pass_arguments(self, call: ast.Call, number: int, function) -> None:
        self._invoke(number, function, list(call.args), [(k.arg, k.value) for k in call.keywords],
                     isinstance(call.func, ast.Attribute))

    def _wrapped_drops(self, call: ast.Call, number: int, function) -> None:
        """A function of the script that writes a download to the path it is
        given (``def urlretrieve(url, fn)`` around ``requests.get``): the path
        the caller hands over is a file written from the network, too."""
        if not self.drops:
            return
        args = function.args
        names = [a.arg for a in args.posonlyargs + args.args]
        if names and names[0] in ("self", "cls") and isinstance(call.func, ast.Attribute):
            names = names[1:]
        given = list(zip(names, call.args)) + [(k.arg, k.value) for k in call.keywords if k.arg]
        for name, argument in given:
            wanted = "name:%d:%s" % (number, name)
            for drop in list(self.drops):
                if wanted in drop.ids:
                    self._drop(argument, drop.source)
                    break

    def bind(self, target: ast.AST, source: Optional[_Source]) -> None:
        if source is None:
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, source)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, source)
        elif isinstance(target, ast.Subscript):
            self.bind(target.value, source)               # box[key] = data: the container carries it
        else:
            self.mark(self.key_of(target), source)

    # -- files written from the network ------------------------------------------------
    def _ids(self, node: Optional[ast.AST]) -> Set[str]:
        """Ways to recognise the same path again: the variable, the text, the expression."""
        out: Set[str] = set()
        if node is None:
            return out
        key = self.key_of(node) if isinstance(node, (ast.Name, ast.Attribute)) else None
        if key is not None:
            out.add("name:%d:%s" % key)
            for value in self.assigned.get(key, [])[:4]:
                if not isinstance(value, (ast.Name, ast.Attribute)):
                    out |= self._ids(value)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
            leaf = re.split(r"[\\/]", text.strip())[-1].lower()
            if len(leaf) >= 3:
                out.add("file:" + leaf)
        elif not isinstance(node, (ast.Name, ast.Attribute)):
            try:
                out.add("expr:" + ast.dump(node)[:1500])
            except Exception:
                pass
            for child in ast.walk(node):                  # os.path.join(folder, "a.exe")
                if isinstance(child, ast.Constant) and isinstance(child.value, str) and \
                        re.search(r"\.\w{2,4}$", child.value.strip()):
                    out.add("file:" + re.split(r"[\\/]", child.value.strip())[-1].lower())
        return out

    def _drop(self, path: Optional[ast.AST], source: Optional[_Source], extracted: bool = False) -> None:
        if path is None or source is None:
            return
        if self.local and not (isinstance(source, _Local) and source.decoded):
            return                                        # (a file only copied is no local chain)
        ids = self._ids(path)
        module = self._module_of(path)
        if module:                                        # a module another script may import
            ids.add("import:" + module)
        if ids and len(self.drops) < 200 and not any(
                d.ids == ids and d.source.line == source.line for d in self.drops):
            self.drops.append(_Drop(source, self.line, ids, _shown(path), extracted,
                                    self._folder_ids(path if extracted else None, path)))
            self.changed = True

    # -- the folder a file lies in (phageo, 2026-10-18: a start whose working folder holds a
    # written file, or whose program lies beside it, reaches that file) ---------------------
    def _parents(self, node: ast.AST, depth: int = 0) -> List[ast.AST]:
        """The folder part of a path expression: ``os.path.join(d, n)`` -> ``d``
        (``os.path.join(a, b, n)`` -> ``os.path.join(a, b)``), ``d + "/" + n`` -> ``d``,
        ``d / n`` -> ``d``, a name -> the folders of what was assigned to it. [] when the
        expression shows no folder part."""
        if depth > 4:
            return []
        if isinstance(node, ast.Name):
            out: List[ast.AST] = []
            for value in self.assigned.get(self.key(node.id), [])[:4]:
                if not isinstance(value, ast.Name):
                    out += self._parents(value, depth + 1)
            return out
        if isinstance(node, ast.Call):
            name = self.canon(node.func) or ""
            if name in _JOINS and len(node.args) == 2:
                return [node.args[0]]
            if name in _JOINS and len(node.args) > 2:
                return [ast.Call(func=node.func, args=node.args[:-1], keywords=[])]
            if name in _SAME_PATH and node.args:
                return self._parents(node.args[0], depth + 1)
            return []
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):     # pathlib: d / "a.dll"
            return [node.left]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            parts: List[ast.AST] = []
            walk: ast.AST = node
            while isinstance(walk, ast.BinOp) and isinstance(walk.op, ast.Add) and len(parts) < 16:
                parts.append(walk.right)
                walk = walk.left
            parts.append(walk)
            parts.reverse()                                  # d, "/", n
            for at in range(len(parts) - 1, 0, -1):
                part = parts[at]
                if isinstance(part, ast.Constant) and isinstance(part.value, str) \
                        and re.search(r"[\\/]", part.value):
                    head = re.split(r"[\\/]", part.value)[0]
                    kept = parts[:at] + ([ast.Constant(value=head)] if head else [])
                    folder = kept[0]
                    for one in kept[1:]:
                        folder = ast.BinOp(left=folder, op=ast.Add(), right=one)
                    return [folder]
            return []
        return []

    def _folder_text(self, node: ast.AST) -> str:
        """A folder's text as far as it is written out, in one spelling - "" when nothing of it is."""
        text = self._path_text(node).replace("\\", "/").lower().rstrip("/")
        return text if len(re.sub(r"[‹›/.\s]", "", text)) >= 2 else ""

    def _folder_of(self, node: Optional[ast.AST]) -> Set[str]:
        """Ways to recognise the folder ``node`` stands for (its variable, its expression, its text)."""
        if node is None:
            return set()
        ids = {one for one in self._ids(node) if not one.startswith("file:")}
        text = self._folder_text(node)
        if text:
            ids.add("dir:" + text)
        return ids

    def _folder_ids(self, folder: Optional[ast.AST], path: Optional[ast.AST]) -> Set[str]:
        """The folder a written file lies in: ``folder`` itself (an archive unpacked there), else
        the folder part of ``path``."""
        if folder is not None:
            return self._folder_of(folder)
        out: Set[str] = set()
        if path is None:
            return out
        for parent in self._parents(path)[:4]:
            out |= self._folder_of(parent)
        text = self._path_text(path).replace("\\", "/").lower()
        if "/" in text:                                      # f"{d}/a.dll", "‹d›/a.dll"
            head = text.rsplit("/", 1)[0].rstrip("/")
            if len(re.sub(r"[‹›/.\s]", "", head)) >= 2:
                out.add("dir:" + head)
        return out

    def _in_folder(self, node: ast.Call, name: str) -> Tuple[Optional[_Drop], str, List[_Drop]]:
        """A process start that reaches a written file through its folder: the folder it is
        given to work in (``cwd=``) holds the file or is the folder an archive was unpacked to,
        or the program it starts lies in the folder the file was written to. ``(the first such
        file, how - WORKING_FOLDER / PROGRAM_FOLDER -, every written file of that folder)``."""
        if name not in _COMMAND or not self.drops:
            return None, "", []
        cwd = next((k.value for k in node.keywords if k.arg == "cwd"), None)
        if cwd is None and name in (_IND[11],) and len(node.args) > 8:
            cwd = node.args[8]                               # Popen(args, bufsize, ..., cwd)
        if cwd is not None:
            folder = self._folder_of(cwd)
            found = [d for d in self.drops if d.folders & folder or (d.extracted and d.ids & self._ids(cwd))]
            if found:
                return found[0], WORKING_FOLDER, found
        program = node.args[0] if node.args else next(
            (k.value for k in node.keywords if k.arg in ("args", "executable", "path", "file")), None)
        if isinstance(program, (ast.List, ast.Tuple)):
            program = program.elts[0] if program.elts else None
        if program is not None:
            folder = self._folder_ids(None, program)
            found = [d for d in self.drops if d.folders & folder] if folder else []
            if found:
                return found[0], PROGRAM_FOLDER, found
        return None, "", []

    def _path_text(self, node: Optional[ast.AST], depth: int = 0) -> str:
        """A path as far as it is written out; what is only known when the script
        runs stands as ``‹name›``."""
        self.clock.tick()
        if depth > 6 or node is None:
            return "‹›"
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value = node.value
            return value if isinstance(value, str) else value.decode("latin-1")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._path_text(node.left, depth + 1) + self._path_text(node.right, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return re.sub(r"%[-\d.]*[a-zA-Z]", "‹›", self._path_text(node.left, depth + 1))
        if isinstance(node, ast.JoinedStr):
            return "".join(self._path_text(value, depth + 1) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return "‹›"
        if isinstance(node, ast.Subscript):               # os.environ["TEMP"]
            return "‹%s›" % (self.canon(node.value) or "")
        if isinstance(node, ast.Call):
            name = self.canon(node.func) or ""
            if name in _JOINS:
                return "/".join(self._path_text(argument, depth + 1) for argument in node.args)
            if name in _SAME_PATH and node.args:
                return self._path_text(node.args[0], depth + 1)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return re.sub(r"\{[^{}]*\}", "‹›", self._path_text(node.func.value, depth + 1))
            return "‹%s›" % name
        if isinstance(node, ast.Name):
            if self.loop_value and self.key(node.id) in self.loop_value:
                return self.loop_value[self.key(node.id)]
            values = self.assigned.get(self.key(node.id), [])
            if len(values) == 1 and not isinstance(values[0], ast.Name):
                return self._path_text(values[0], depth + 1)
            return "‹%s›" % node.id
        if isinstance(node, ast.Attribute):
            return "‹%s›" % (self.canon(node) or "")
        return "‹›"

    def _module_of(self, path: ast.AST) -> str:
        """The name another script would import the file at ``path`` by -
        ``<dir>/name.py`` (``.pyc``, ``.pyo``, ``.pyd``) or the package ``<dir>/name/__init__.py``,
        where ``<dir>`` is the game's folder or one Python looks into from there. A
        folder that cannot be read from the script counts; one that is plainly
        elsewhere (the temporary folder, the user's folder, an absolute path) does
        not. "": no such file, or its name is not written out."""
        text = self._path_text(path).replace("\\", "/")
        head, _, tail = text.rpartition("›")
        if head:
            holes = re.findall(r"‹([^›]*)", head + "›")
            if not tail.startswith("/") or _ABSOLUTE.match(text) \
                    or any(hole.startswith(_ELSEWHERE) for hole in holes):
                return ""
        elif _ABSOLUTE.match(tail):
            return ""
        match = _MODULE_FILE.fullmatch(tail[2:] if tail.startswith("./") else tail)
        if match is None:
            return ""
        folders, name, kind = match.groups()
        folders = folders[_MODULE_ROOT.match(folders).end():]
        parts = [part for part in folders.split("/") if part and part != "."]
        if name != "__init__":
            parts.append(name)
        elif kind != "py":
            return ""
        return ".".join(parts) if parts and all(_IDENT.match(part) for part in parts) else ""

    def _retrieve(self, node: ast.Call, source: Optional[_Source]) -> None:
        path = node.args[1] if len(node.args) > 1 else None
        for keyword in node.keywords:
            if keyword.arg == "filename":
                path = keyword.value
        self._drop(path, source)

    def _dropped(self, node: ast.AST, deep: bool = False) -> Optional[_Drop]:
        if not self.drops:
            return None
        ids = self._deep_ids(node) if deep else self._ids(node)
        for drop in self.drops:
            if drop.ids & ids:
                return drop
        return None

    def _deep_ids(self, node: ast.AST) -> Set[str]:
        """:meth:`_ids` of what is started, with every name and text inside it."""
        ids = self._ids(node)
        for child in ast.walk(node):
            if isinstance(child, (ast.Name, ast.Attribute, ast.Constant)):
                ids |= self._ids(child)
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                for word in re.split(r"[\s\"']+", child.value)[:40]:      # "cmd /c a.exe"
                    leaf = re.split(r"[\\/]", word)[-1].lower()
                    if len(leaf) >= 3:
                        ids.add("file:" + leaf)
        return ids

    def _note_start(self, argument: ast.AST, sink: str, line: int) -> None:
        """The second reading: what a call starts, by what another file can know it
        by (see :meth:`dropped`) - the file names written out in it, and the shared
        name its path comes from."""
        ids = {one for one in self._deep_ids(argument) if one.startswith("file:")}
        if sink in ("__import__", "importlib.import_module") and isinstance(argument, ast.Constant) \
                and isinstance(argument.value, str):
            ids.add("file:" + argument.value.rsplit(".", 1)[-1].lower() + ".py")
        source = self.expr(argument)
        if source is not None and source.kind == SHARED:
            ids.add(source.what)
        for one in sorted(ids):
            if one not in self.starts and len(self.starts) < _MAX_STARTED:
                self.starts[one] = (sink, line)

    def _opened(self, value: ast.AST) -> Optional[ast.AST]:
        """The path of ``open(path, "w...")`` (None: not a file opened for writing)."""
        if not (isinstance(value, ast.Call) and self.canon(value.func) in _OPEN and value.args):
            return None
        mode = value.args[1] if len(value.args) > 1 else None
        for keyword in value.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and re.search(r"[wax+]", mode.value):
            return value.args[0]
        return None

    def _file_calls(self, node: ast.Call) -> None:
        """Writes of downloaded data to a file, and archives unpacked from it."""
        if not isinstance(node.func, ast.Attribute) or (
                self.local and self.canon(node.func) == "shutil.unpack_archive"):
            name = self.canon(node.func) or ""
            if name in ("shutil.copyfileobj",) and len(node.args) > 1:
                self._write(node.args[1], self.expr(node.args[0]))
            if name == "shutil.unpack_archive" and self.local and node.args:
                # (the local reading: an archive that was written from a decoded file, unpacked)
                dropped = self._dropped(node.args[0])
                where = node.args[1] if len(node.args) > 1 else next(
                    (k.value for k in node.keywords if k.arg == "extract_dir"), None)
                if dropped is not None:
                    self._drop(where, dropped.source, extracted=True)
            return
        method, target = node.func.attr, node.func.value
        if method in _WRITES and node.args:
            self._write(target, self.expr(node.args[0]))
        elif method in _EXTRACTS:
            source = self.expr(target)
            if source is not None:
                where = node.args[0] if node.args else None
                for keyword in node.keywords:
                    if keyword.arg == "path":
                        where = keyword.value
                self._drop(where, source, extracted=True)

    def _write(self, handle: ast.AST, source: Optional[_Source]) -> None:
        if source is None:
            return
        path = self._opened(handle)
        if path is None:
            key = self.key_of(handle) if isinstance(handle, (ast.Name, ast.Attribute)) else None
            path = self.handles.get(key) if key is not None else None
        self._drop(path, source)

    # -- sinks ----------------------------------------------------------------------
    def _hit(self, how: str, sink: str, source: _Source, line: int, detail: str = "", folder: str = "") -> None:
        if source.kind == SHARED:                         # a name shared with other files is run
            if source.what not in self.runs and len(self.runs) < _MAX_SHARED:
                self.runs[source.what] = (how, sink, line, detail)
            return
        if len(self.hits) >= _MAX_HITS or any(h.source_line == source.line and h.line == line
                                              for h in self.hits):
            return
        self.hits.append(Hit(how=how, line=line, sink=sink, source=source.what, source_line=source.line,
                             kind=source.kind, address=source.address, detail=detail, folder=folder))

    def _command_kind(self, node: ast.Call, name: str, source: _Source) -> str:
        """``"argument"`` for a start whose program is fixed and is not a shell or an
        interpreter, with no shell between, when what was downloaded reaches only its
        arguments: ``subprocess.run(["git", "clone", url])`` - data handed to a program, not
        a program (phageo, 2026-10-23; the JavaScript reading's ``CHAIN-REMOTE-ARG``, HIGH).
        ``"command"`` for every other start (``cmd``, ``powershell``, ``python`` ... with
        whatever they are given; a command text; a shell; a program that is not written
        out; a name shared with another file)."""
        if source.kind == SHARED or not name.startswith(_IND[12]) or \
                name in (_IND[13], _IND[14]) or len(node.args) != 1:
            return "command"
        for keyword in node.keywords:
            if keyword.arg == "executable" or keyword.arg is None or (
                    keyword.arg == "shell" and not (isinstance(keyword.value, ast.Constant) and not keyword.value.value)):
                return "command"
        commands = self._command_lists(node.args[0])
        if not commands:
            return "command"
        for command in commands:
            program = command.elts[0] if command.elts else None
            if not (isinstance(program, ast.Constant) and isinstance(program.value, str)):
                return "command"
            base = re.split(r"[\\/]", program.value.strip().strip("\"'"))[-1].lower()
            base = base[:-4] if base.endswith(".exe") else base
            if not base or base in _INTERPRETERS:
                return "command"
        return "argument"

    def _command_lists(self, node: ast.AST, depth: int = 0) -> Optional[List[ast.AST]]:
        """The written-out lists a start's command can be: the one at the call itself, or
        every value its name was assigned in its function or handed as an argument by a call
        of this file (phageo, 2026-10-24, HO2-01: ``self._execute(["git", "clone", url, target])``
        and ``subprocess.Popen(command, ...)`` inside ``_execute``). None when one of them is
        no such list, or when not every value is known (a name of the file, more values than
        are kept, a name handed on from a name of the file)."""
        if isinstance(node, (ast.List, ast.Tuple)):
            return [node]
        if not isinstance(node, ast.Name) or depth >= _MAX_HANDOVER:
            return None
        key = self.key(node.id)
        assigned = self.assigned.get(key, [])
        if key[0] == 0 or key in self.handed_more or len(assigned) >= 8:
            return None
        values = [(key[0], value) for value in assigned] + self.handed.get(key, [])
        if not values:
            return None
        out: List[ast.AST] = []
        saved = self.scope
        try:
            for scope, value in values:
                self.scope = scope                        # (a name is read where it was handed on)
                found = self._command_lists(value, depth + 1)
                if found is None:
                    return None
                out += found
        finally:
            self.scope = saved
        return out

    def sinks(self, node: ast.Call) -> None:
        name = self.canon(node.func) or ""
        line = getattr(node, "lineno", self.line)
        arguments = list(node.args) + [k.value for k in node.keywords]
        if self.local:
            pass                                          # (the local reading: only a written file that is started)
        elif name in _CODE:
            source = self._any(arguments[:2] if name in ("types.FunctionType", "types.CodeType")
                               else arguments[:1])
            if source is not None and not source.client:
                self._hit("code", name, source, line)
        if name in _COMMAND and not self.local:
            source = self._any(arguments[:1])
            if source is not None and not source.client:
                self._hit(self._command_kind(node, name, source), name, source, line)
        if _NATIVE.search(name) and not self.local:
            source = self._any(arguments)
            if source is not None and not source.client:
                self._hit("code", name + " (native code)", source, line)
        started = None if self.local else self._started(node, name)
        if started is not None:                           # Thread(target=os.system, args=(data,))
            called = self.canon(started[0]) or ""
            if called in _CODE or called in _COMMAND:
                source = self._any(started[1][:1])
                if source is not None and not source.client:
                    self._hit("code" if called in _CODE else "command", called, source, line)
        if name in _COMMAND or name in _RUNS_FILE or _NATIVE.search(name):
            started = arguments
            if name in _COMMAND:
                # what is started is the command - not the log file its output goes to
                # (stdout=...), its working folder or its environment
                started = list(node.args) + [k.value for k in node.keywords
                                             if k.arg in ("args", "executable", "cmd", "command", "file", "path")]
            if self.shared:
                for argument in started:
                    self._note_start(argument, name, line)
            for argument in started:
                drop = self._dropped(argument, deep=True)
                if drop is None and name in ("__import__", "importlib.import_module") and \
                        isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    wanted = "file:" + argument.value.rsplit(".", 1)[-1].lower() + ".py"
                    drop = next((d for d in self.drops if wanted in d.ids), None)
                if drop is not None:
                    if self.local:
                        self._local_hit(drop, name, line)
                    else:
                        self._hit("dropper", name, drop.source, line, drop.shown)
                    break
            else:
                # ... or through its folder (phageo, 2026-10-18): the start works in the folder a
                # written file lies in, or starts a program that lies there - a program finds
                # its libraries and files in its own folder and the one it works in
                drop, via, found = self._in_folder(node, name)
                if drop is not None and self.local:
                    self._local_hit(drop, name, line, via, found)
                elif drop is not None:
                    self._hit("dropper", name, drop.source, line, drop.shown, folder=via)

    # -- walking --------------------------------------------------------------------
    def run(self) -> List[Hit]:
        self.prepare()
        for _ in range(_MAX_PASSES):
            self.changed = False
            self.walk_body(self.tree.body, 0)
            if not self.changed:
                break
        self.final = True
        self.walk_body(self.tree.body, 0)
        return self.hits

    def walk_body(self, body: List[ast.stmt], scope: int) -> None:
        for node in body:
            self.statement(node, scope)

    def statement(self, node: ast.AST, scope: int) -> None:
        self.clock.tick()
        self.scope = scope
        self.line = getattr(node, "lineno", self.line)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = self.scope_of.get(id(node), scope)
            self.walk_body(node.body, inner)
            self.scope = scope
            return
        if isinstance(node, ast.ClassDef):
            self.walk_body(node.body, scope)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if self.final and self.drops:             # importing a module that was downloaded
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                for name in names:
                    wanted = "file:" + name.rsplit(".", 1)[-1].lower() + ".py"
                    drop = next((d for d in self.drops if name and wanted in d.ids), None)
                    if drop is not None and self.local:
                        self._local_hit(drop, "import " + name, self.line)
                    elif drop is not None:
                        self._hit("dropper", "import " + name, drop.source, self.line, drop.shown)
            return
        if isinstance(node, ast.Return):
            source = self.expr(node.value)
            self._calls(node)
            if source is not None and scope:
                saved, self.scope, self.line = (self.scope, self.line), 0, 0
                self.mark((0, "return of %d" % scope), source)
                self.scope, self.line = saved
            return
        if isinstance(node, ast.Assign):
            if self.local:
                self.targets = {key for key in map(self._target_key, node.targets) if key is not None}
            source = self.expr(node.value)
            self.targets = set()
            for target in node.targets:
                self._remember(target, node.value)
                self.bind(target, source)
            self._calls(node)
            return
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.value is not None:
                if self.local:
                    self.targets = {key for key in [self._target_key(node.target)] if key is not None}
                source = self.expr(node.value)
                if self.local and isinstance(node, ast.AugAssign):
                    # data ^= key, buf[i] ^= key: the name's own value goes through the step
                    mine = self.expr(node.target)
                    if isinstance(mine, _Local) and isinstance(node.op, ast.BitXor):
                        source = mine.then(("xor", self._key(node.value)))
                    elif isinstance(mine, _Local) and isinstance(node.op, _ELEMENTWISE[1:]):
                        source = mine.then(("custom",))     # (not +=: that joins texts)
                    elif isinstance(mine, _Local):
                        source = mine
                self.targets = set()
                self._remember(node.target, node.value)
                self.bind(node.target, source)
            self._calls(node)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                source = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self._remember(item.optional_vars, item.context_expr)
                    self.bind(item.optional_vars, source)
                self._calls(item.context_expr)
            self.walk_body(node.body, scope)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            if self.local:
                self._loop_texts(node.target, node.iter)
            self.bind(node.target, self.expr(node.iter))
            self._calls(node.iter)
            self.walk_body(node.body, scope)
            self.walk_body(node.orelse, scope)
            return
        for _field, value in ast.iter_fields(node):
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, (ast.stmt, ast.excepthandler)):
                    self.statement(item, scope)
                    self.scope, self.line = scope, getattr(node, "lineno", self.line)
                elif isinstance(item, ast.expr):
                    self.expr(item)
                    self._calls(item)
                elif isinstance(item, ast.AST):
                    for sub in ast.iter_child_nodes(item):
                        if isinstance(sub, (ast.stmt, ast.excepthandler)):
                            self.statement(sub, scope)
                        elif isinstance(sub, ast.expr):
                            self.expr(sub)
                            self._calls(sub)

    def _loop_texts(self, target: ast.AST, over: ast.AST) -> None:
        """``for name in ('a.dat', 'b.dat')`` (or a name given such a list once; or pairs, ``for
        src, dst in (('a', 'b'), ...)``): the texts each loop name takes, at most
        :data:`_MAX_IN_FOLDER`."""
        if isinstance(over, ast.Name):
            values = self.assigned.get(self.key(over.id), [])
            over = values[0] if len(values) == 1 else over
        if not isinstance(over, (ast.List, ast.Tuple, ast.Set)) or not over.elts:
            return
        names = target.elts if isinstance(target, (ast.Tuple, ast.List)) else [target]
        for at, name in enumerate(names):
            if not isinstance(name, ast.Name):
                continue
            texts = []
            for element in over.elts[:_MAX_IN_FOLDER]:
                one = element if len(names) == 1 else (
                    element.elts[at] if isinstance(element, (ast.Tuple, ast.List)) and len(element.elts) == len(names)
                    else None)
                if isinstance(one, ast.Constant) and isinstance(one.value, str):
                    texts.append(one.value)
            key = self.key(name.id)
            if texts and key is not None and self.loops.get(key) != texts:
                self.loops[key] = texts

    def _loop_paths(self, node: ast.AST) -> Tuple[str, ...]:
        """A path that names a loop name (:meth:`_loop_texts`): the path for each text it takes."""
        keys = [self.key(one.id) for one in ast.walk(node) if isinstance(one, ast.Name)]
        key = next((one for one in keys if one in self.loops), None)
        if key is None:
            return ()
        out = []
        for text in self.loops[key]:
            self.loop_value[key] = text
            try:
                out.append(self._path_text(node))
            finally:
                self.loop_value.pop(key, None)
        return tuple(out)

    def _target_key(self, target: ast.AST) -> Optional[Tuple[int, str]]:
        """The name an assignment gives a value to (``buf[i] = ...``: ``buf``)."""
        holder = target.value if isinstance(target, ast.Subscript) else target
        return self.key_of(holder) if isinstance(holder, (ast.Name, ast.Attribute)) else None

    def _remember(self, target: ast.AST, value: ast.AST) -> None:
        """What a name was assigned (for addresses and paths), and which file a handle is."""
        holder = target.value if isinstance(target, ast.Subscript) else target    # table["go"] = f
        if not isinstance(holder, (ast.Name, ast.Attribute)):
            return
        key = self.key_of(holder)
        if key is None:
            return
        self._hand_on(key, value)
        if holder is not target:
            return
        if isinstance(value, ast.Call) and self.canon(value.func) in _POOLS and key not in self.pools:
            self.pools.add(key)                           # pool = ThreadPoolExecutor()
            self.changed = True
        values = self.assigned.setdefault(key, [])
        if not any(v is value for v in values) and len(values) < 8:
            values.append(value)
        path = self._opened(value)
        if path is not None:
            self.handles[key] = path

    def _calls(self, node: ast.AST) -> None:
        """Every call inside an expression or simple statement: file writes always,
        sinks once the taint has settled."""
        for sub in ast.walk(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(sub, ast.Call):
                self.clock.tick()
                saved = self.line
                self.line = getattr(sub, "lineno", self.line)
                self._file_calls(sub)
                if self.final:
                    self.sinks(sub)
                self.line = saved


def analyse(text: str, renpy: bool = False, resolved=()) -> List[Hit]:
    """What ``text`` (Python, or a Ren'Py script) executes that came from the
    network. ``resolved``: what the payload resolver found in the same text
    (its addresses are used). Never raises."""
    return read(text, renpy, resolved)[0]


def read(text: str, renpy: bool = False, resolved=()) -> Tuple[List[Hit], str]:
    """:func:`analyse`, and the limit the reading stopped at ("": it read to
    the end) - steps, the emergency clock, the size of the text, its nesting.
    Until 2026-10-12 a reading that stopped here said nothing."""
    if not text or not _NET_HINT.search(text) or not _SINK_HINT.search(text):
        return [], ""
    try:
        tree = pyflow.parse(pyflow.renpy_python(text) if renpy else text)
        if tree is None and renpy:
            tree = pyflow.parse(text)
        if tree is None:
            return [], pyflow.unread(text)
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        flow = _Flow(tree, resolved, clock)
        try:
            return flow.run(), ""
        except (Budget, RecursionError) as exc:
            clock.ended(exc)
            return flow.hits, clock.stopped
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""


def local_drops(text: str, renpy: bool = False) -> Tuple[List[LocalDrop], str]:
    """CHAIN-LOCAL-DROP (phageo, 2026-10-15 / 2026-10-17): what ``text`` (Python, or a Ren'Py
    script) reads from a local file, decodes (Base64, hex, zlib / gzip / bz2 / lzma, XOR, any
    other byte-wise arithmetic, ``.translate``), writes to a file or unpacks as an archive, and
    then starts, imports or loads - with no download at all. The download-and-run reading with
    one other source: what was written from a request there is written from a decoded local
    file here, and joined to what is started the same way (the path, the text, the expression).
    A file that is read and written without a decoder is no chain (copying a bundled program is
    ordinary). Returns the chains (:class:`LocalDrop`) and the limit the reading stopped at
    ("": none). Never raises."""
    if not text or not _LOCAL_HINT.search(text) or not _READ_HINT.search(text) or not _SINK_HINT.search(text):
        return [], ""
    try:
        tree = pyflow.parse(pyflow.renpy_python(text) if renpy else text)
        if tree is None and renpy:
            tree = pyflow.parse(text)
        if tree is None:
            return [], pyflow.unread(text)
        clock = Clock(MAX_STEPS, MAX_SECONDS)
        flow = _Flow(tree, (), clock, store=renpy, local=True)
        try:
            flow.run()
            return flow.local_hits, ""
        except (Budget, RecursionError) as exc:
            clock.ended(exc)
            return flow.local_hits, clock.stopped
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""


_MAX_REBUILT_LINES = 200_000    # lines of a compiled file's calls, kept per function
_MAX_REBUILT_TRIED = 100_000    # lines that are tried (parsed one by one): the limit, a count
REBUILT_SECONDS = V.SAFETY_SECONDS  # a far safety cap only; when it fires that is said too


def rebuilt_text(root, cut: Optional[List[str]] = None) -> Tuple[str, List[int]]:
    """Python-like text for the calls rebuilt from a compiled file, every
    function kept apart (``root``: :class:`gamescan.unpack.pycalls.Function`):
    a ``def`` with its parameters for each code object, a ``class`` for the
    body of a class, the code objects defined inside it nested in it. Returns
    the text and, for each of its lines, the line number in the file's own
    line table. A rebuilt line that does not parse by itself is left out (the
    walk rebuilds approximately, and Python 2 allows names Python 3 does
    not). Nothing is compiled or run: ``ast`` only reads. ``cut``: a list
    that gets the limit the putting-together stopped at, if it did (a count
    of lines; the clock is an emergency brake - until 2026-10-12 a silent
    two-second clock was the limit)."""
    out: List[str] = []
    numbers: List[int] = []
    deadline = time.monotonic() + REBUILT_SECONDS
    tried = [0]

    def stopped() -> bool:
        tried[0] += 1
        why = ""
        if len(out) >= _MAX_REBUILT_LINES or tried[0] > _MAX_REBUILT_TRIED:
            why = "more than %d lines of rebuilt calls" % (
                _MAX_REBUILT_LINES if len(out) >= _MAX_REBUILT_LINES else _MAX_REBUILT_TRIED)
        elif tried[0] & 255 == 0 and time.monotonic() > deadline:
            why = "%.0f seconds" % REBUILT_SECONDS
        if why and cut is not None and not cut:
            cut.append(why)
        return bool(why)

    def parses(text: str, inside: bool) -> bool:
        try:
            ast.parse("def _():\n " + text if inside else text)
            return True
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False

    def render(function, depth: int, top: bool) -> None:
        pad = "    " * depth
        if not top:
            names: List[str] = []
            for arg in function.args:
                names.append(arg if arg not in names else "%s_%d" % (arg, len(names)))
            name = function.name if _IDENT.match(function.name) else "_code"
            header = "class %s:" % name if function.is_class else "def %s(%s):" % (name, ", ".join(names))
            if not parses(header + "\n pass", False):
                header = "def _code():"
            out.append(pad + header)
            numbers.append(function.first_line)
            pad += "    "
            depth += 1
        before = len(out)
        for inner in function.inner:
            render(inner, depth, False)
        for line, text in sorted(function.lines, key=lambda item: item[0]):
            if stopped():
                break
            if parses(text, not top and not function.is_class):
                out.append(pad + text)
                numbers.append(line)
        if not top and len(out) == before:
            out.append(pad + "pass")
            numbers.append(function.first_line)

    try:
        render(root, 0, True)
    except RecursionError:
        if cut is not None and not cut:
            cut.append("nested too deeply")
        return "", []
    return "\n".join(out), numbers


def analyse_rebuilt(root, flat: Optional[str] = None) -> List[Hit]:
    """:func:`analyse` for the calls rebuilt from a compiled Python file, per
    function. The lines of the hits are those of the compiled file's own line
    table. ``flat``: the same calls as one text, when at hand - a file that
    names no request or nothing that runs is not put together at all. Never
    raises."""
    return read_rebuilt(root, flat)[0]


def read_rebuilt(root, flat: Optional[str] = None) -> Tuple[List[Hit], str]:
    """:func:`analyse_rebuilt`, and the limit the reading stopped at ("": none)."""
    if root is None:
        return [], ""
    if flat is not None and not (_NET_HINT.search(flat) and _SINK_HINT.search(flat)):
        return [], ""
    try:
        cut: List[str] = []
        text, numbers = rebuilt_text(root, cut)
        hits, stopped = read(text)
        for hit in hits:
            hit.line = numbers[hit.line - 1] if 0 < hit.line <= len(numbers) else hit.line
            hit.source_line = (numbers[hit.source_line - 1] if 0 < hit.source_line <= len(numbers)
                               else hit.source_line)
        return hits, (cut[0] if cut else stopped)
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""


def study(text: str, renpy: bool = False, resolved=(), store: bool = False):
    """``(hits, shared)``: what :func:`analyse` gives, and what the file
    shares with other files (:class:`Shared`) - the shared names it stores a
    download under (``_Flow.filled``) and the shared names whose value it
    runs (``name -> (how, sink, line, detail)``; ``store:x`` and
    ``module:<name as imported>``, with ``()`` for what a function returns);
    the files it writes a download to (``_Flow.dropped``) and the files it
    starts (``file:<name>`` or the shared name of the path ``-> (sink,
    line)``). ``store``: the file's top-level names are names of Ren'Py's
    store (a ``.rpy`` / ``.rpyc`` script). ``shared.cut``: the second reading
    reached its limit. The caller joins the files of a folder
    (:mod:`gamescan.dataflow.shared`). Never raises."""
    hits: List[Hit] = []
    shared = Shared()
    if not text:
        return hits, shared
    net, sink = _NET_HINT.search(text) is not None, _SINK_HINT.search(text) is not None
    if not net and not sink:
        return hits, shared
    try:
        tree = pyflow.parse(pyflow.renpy_python(text) if renpy else text)
        if tree is None and renpy:
            tree = pyflow.parse(text)
        if tree is None:
            shared.limit = pyflow.unread(text)      # (too large or too deep: not read at all)
            return hits, shared
        if net:
            first = Clock(MAX_STEPS, MAX_SECONDS)
            flow = _Flow(tree, resolved, first, store=store or renpy)
            try:
                flow.run()
            except Budget:
                # (the count is the limit; the clock is an emergency brake and is named when it fires)
                shared.limit = "more than %d steps" % MAX_STEPS if first.steps <= 0 else "%.0f seconds" % MAX_SECONDS
            except RecursionError:
                shared.limit = "nested too deeply"
            if sink:
                hits = flow.hits
            shared.fills, shared.drops = flow.filled(), flow.dropped()
        if sink:
            clock = Clock(SHARED_STEPS, SHARED_SECONDS)
            second = _Flow(tree, (), clock, shared=True, store=store or renpy)
            try:
                second.run()
            except Budget:
                # the steps decide (the same file is always cut at the same place); the
                # clock is only a brake for a PC so slow that the steps take too long
                shared.cut = STEPS if clock.steps <= 0 else SECONDS
            except RecursionError:
                shared.cut = STEPS
            shared.runs, shared.starts = second.runs, second.starts
    except Exception:                    # an analysis aid must never break the scan itself
        pass
    return hits, shared
