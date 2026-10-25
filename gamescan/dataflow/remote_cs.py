"""Remote code execution in compiled C# (.NET method bodies): does what a managed
program loads or starts come from the network?

Read from the instructions of each method (:mod:`gamescan.unpack.dotnet_il`),
as data. A value is followed

* inside one method - over the evaluation stack, local variables and
  arguments;
* through the fields of one class together with the classes nested in it.
  That is where the compiler puts the steps of a coroutine
  (``IEnumerator`` with ``yield``) and of an ``async`` method, and the
  variables a lambda uses: small generated classes whose methods talk to
  each other through fields;
* between the methods of one program: as an argument into the method that
  is called and as what that method gives back - at most :data:`MAX_DEPTH`
  such hand-overs in a row;
* into a method that is handed on as a delegate (a lambda, a method group):
  ``Task.Run``, ``new Thread(...).Start(x)``, ``ThreadPool.QueueUserWorkItem``,
  ``ContinueWith``, ``Invoke`` - whatever call receives the delegate, the
  other things it receives are taken to reach the delegate's method, and
  what that method gives back to come out of the call;
* between two programs of one scan, one hop, by name (:class:`Shares`): each
  program says which of its methods give back a download, which run what
  they are handed, and which methods of *other* programs it relies on for
  either. :func:`join` puts those together.

A chain is

    download  ->  Assembly.Load / AppDomain.Load / Process.Start
    download  ->  written to a file  ->  that file is loaded or started

where "download" is what ``WebClient``, ``HttpClient``, ``WebRequest``,
``UnityWebRequest``, the old ``WWW`` or a socket hands back.

It is a model, not an interpreter: the instructions of a method are read
in the order they stand, branches are not taken, what a call into another
program gives back is taken to depend on what went in, and a method is
known by what *any* of its callers hands it (not caller by caller). So it
can report a chain a careful reading would not see as one - and it misses a
value that travels a way it does not model (reflection, a script engine,
a second hop between programs).
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote_cs.py")

import re
from typing import Dict, FrozenSet, Iterable, List, NamedTuple, Optional, Set, Tuple

from ..unpack import dotnet_il as il

READ, UNREAD = "read", "not read"
MAX_STEPS = 20_000_000              # instructions looked at in one program (all readings)
MAX_HITS = 50
MAX_DEPTH = 4                       # hand-overs between methods a value is followed over
MAX_SHARED = 4_000                  # names one program shares with the others, of each kind
MAX_LINKS = 50                      # chains across programs that are reported
_MAX_READINGS = 4                   # readings from nothing until the set of methods that are read stays
_MAX_ROUNDS = 12                    # times the methods whose inputs changed are read again
_MAX_TAGS = 24                      # what one value can carry
_MAX_TEXTS = 6                      # ... of which this many texts
_MAX_FNS = 4                        # ... and this many delegates
_MAX_TARGETS = 8                    # methods one call can stand for (an interface method's implementations)
_MAX_STACK = 4096

# -- names ---------------------------------------------------------------------------------
# a type that can download / start: a program that names none of them is not walked
_NET_TYPES = re.compile(
    _IND[0])
_RUN_TYPES = re.compile(r"^(?:System\.Reflection\.Assembly|System\.AppDomain|System\.Diagnostics\.Process"
                        r"|System\.Diagnostics\.ProcessStartInfo)$")
# what a call hands back is a download
_SOURCE = re.compile(
    _IND[1])
# ... a download that is written straight to the file its second argument names
_SOURCE_TO_FILE = re.compile(_IND[2])
# ... a download that is written into the buffer it is handed
_SOURCE_INTO = re.compile(r"^System\.Net\.Sockets\.Socket::(?:Receive\w*|EndReceive)$")
# every way in which a managed program loads code: Assembly.Load / LoadFrom / LoadFile /
# LoadModule / LoadWithPartialName / UnsafeLoadFrom / ReflectionOnlyLoad..., AppDomain.Load /
# ExecuteAssembly... / CreateInstance... (also ...From), Activator.CreateInstanceFrom
_LOAD = re.compile(r"^(?:System\.Reflection\.Assembly::(?:Load\w*|UnsafeLoadFrom|ReflectionOnlyLoad\w*)"
                   r"|System\.AppDomain::(?:Load|ExecuteAssembly\w*|CreateInstance\w*|CreateComInstanceFrom)"
                   r"|System\.Activator::(?:CreateInstanceFrom|CreateComInstanceFrom))$")
# the types whose methods the lists above and below name: a program that *defines* one of
# them is looked at method by method (_wanted)
_NAMED_TYPES = re.compile(
    _IND[3])
# ... and which of its arguments choose the code that is loaded (phageo, 2026-10-23): the
# assembly and the type name for the CreateInstance kind and LoadModule's raw module, the
# first argument for every other load. The rest (constructor arguments, the program's own
# arguments, evidence, the domain the call is made on) choose nothing.
_LOAD_TWO = re.compile(r"^(?:System\.Reflection\.Assembly::LoadModule"
                       r"|System\.AppDomain::(?:CreateInstance\w*|CreateComInstanceFrom)"
                       r"|System\.Activator::(?:CreateInstanceFrom|CreateComInstanceFrom))$")
_LOAD_BY_ADDRESS = re.compile(r"^System\.Reflection\.Assembly::(?:LoadFrom|UnsafeLoadFrom)$")
_START = re.compile(r"^System\.Diagnostics\.Process::Start$")
_START_NATIVE = re.compile(_IND[4])
_WRITE_ALL = re.compile(r"^System\.IO\.File::(?:WriteAll|AppendAll)\w+$")
_MOVE = re.compile(r"^System\.IO\.File::(?:Move|Copy|Replace)$")
_OPEN_FILE = re.compile(r"^System\.IO\.(?:File::(?:Create|OpenWrite|Open|AppendText|CreateText)"
                        r"|(?:FileStream|StreamWriter|BinaryWriter|BufferedStream)::\.ctor|FileInfo::\.ctor)$")
_FILLS = re.compile(r"^(?:System\.Array::Copy\w*|System\.Buffer::BlockCopy)$")
_METHOD = re.compile(r"::([^:]+)$")
_FILE_NAME = re.compile(r"\.[A-Za-z0-9]{1,8}[\"']?\s*$")
_LOCAL = re.compile(r"(?i)^(?:https?|ftp|wss?)://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])(?:[:/]|$)")
_REMOTE = re.compile(r"(?i)^(?:https?|ftp|wss?)://")

# what a value carries. DL, DROP, PARAM and EXT have a third part: the hand-overs between
# methods the mark has travelled over
DL, DROP, TEXT, ORIGIN, FILE_SLOT, FILE_TEXT, BOX = "dl", "drop", "s", "o", "po", "ps", "box"
FN = "fn"                           # a delegate: (FN, row of its method)
PARAM = "param"                     # came in as an argument of a method: (PARAM, (row, number), hops)
EXT = "ext"                         # came back from a method of another program: (EXT, name, hops)
_COUNTED = (DL, DROP, PARAM, EXT)
_CARRIED = (DL, DROP, FILE_SLOT, FILE_TEXT, BOX, TEXT, FN, PARAM, EXT)   # what a call's result takes over
EMPTY: FrozenSet[tuple] = frozenset()


class Hit(NamedTuple):
    how: str                # "loader" (the download is loaded / started) or "dropper" (written, then started)
    source: str             # "WebClient::DownloadData"
    sink: str               # "Assembly::Load"
    where: str              # "Game.Updater::Run" - the method that holds the sink
    address: str = ""       # a remote address the method names ("" = none seen)


class Shares(NamedTuple):
    """What one program leaves for the chain across programs (names are
    ``Namespace.Type::Method``)."""
    gives: Dict[str, str]                       # own method -> the download it gives back
    runs: Dict[str, str]                        # own method -> the load / start one of its arguments reaches
    # (assembly the call refers to - "" when the reference does not say -, method of another
    #  program) -> (load / start its result reaches here, where)
    wants_gives: Dict[Tuple[str, str], Tuple[str, str]]
    # ... -> (download it is handed here, where)
    wants_runs: Dict[Tuple[str, str], Tuple[str, str]]
    assembly: str = ""                          # the name this program gives itself
    forwarded: FrozenSet[str] = frozenset()     # types it only passes on to another assembly
    # the argument numbers (0 = ``this`` of an instance method) behind ``runs`` and
    # ``wants_runs``: a link needs one in both. A name without an entry is not narrowed.
    # Keys carry the overload's parameter types after the name (``il.Module.shape``:
    # ``"System.Activator::CreateInstance(Type,Object[])"``; the bare name = not known).
    run_args: Dict[str, Tuple[int, ...]] = {}
    wants_args: Dict[Tuple[str, str], Tuple[int, ...]] = {}

    def __bool__(self) -> bool:
        return bool(self.gives or self.runs or self.wants_gives or self.wants_runs)


NOTHING = Shares({}, {}, {}, {})


class Found(NamedTuple):
    hits: List[Hit]
    state: str              # READ, UNREAD
    problem: str = ""       # why not, or what was left out
    traced: int = 0         # methods whose instructions were followed
    shares: Shares = NOTHING


def as_plain(found: Found) -> list:
    """``found`` as plain data (lists, texts, numbers) - what the cache on disk holds."""
    shares = found.shares
    return [[list(hit) for hit in found.hits], found.state, found.problem, found.traced,
            [list(shares.gives.items()), list(shares.runs.items()),
             [[list(key), list(value)] for key, value in shares.wants_gives.items()],
             [[list(key), list(value)] for key, value in shares.wants_runs.items()],
             shares.assembly, sorted(shares.forwarded),
             [[key, list(value)] for key, value in shares.run_args.items()],
             [[list(key), list(value)] for key, value in shares.wants_args.items()]]]


def from_plain(plain: list) -> Found:
    """What :func:`as_plain` made, back as it was (anything else raises)."""
    hits, state, problem, traced, (gives, runs, wants_gives, wants_runs, assembly, forwarded, run_args,
                                   wants_args) = plain
    numbers = [n for _key, value in list(run_args) + list(wants_args) for n in value]
    if not all(isinstance(n, int) for n in numbers) or not all(isinstance(key, str) for key, _ in run_args) \
            or not all(isinstance(part, str) for key, _ in wants_args for part in key):
        raise ValueError("not a kept reading of a managed program")
    texts = [state, problem, assembly] + list(forwarded) + [part for hit in hits for part in hit]
    for pairs in (gives, runs):
        texts += [part for pair in pairs for part in pair]
    for pairs in (wants_gives, wants_runs):
        texts += [part for key, value in pairs for part in tuple(key) + tuple(value)]
    if state not in (READ, UNREAD) or not isinstance(traced, int) or not all(isinstance(text, str) for text in texts):
        raise ValueError("not a kept reading of a managed program")
    return Found([Hit(*hit) for hit in hits], state, problem, traced, Shares(
        dict((key, value) for key, value in gives), dict((key, value) for key, value in runs),
        dict((tuple(key), tuple(value)) for key, value in wants_gives),
        dict((tuple(key), tuple(value)) for key, value in wants_runs), assembly, frozenset(forwarded),
        dict((key, tuple(value)) for key, value in run_args),
        dict((tuple(key), tuple(value)) for key, value in wants_args)))


class Link(NamedTuple):
    """A chain across two programs."""
    runner: int             # index of the program that holds the load / start
    other: int              # ... and of the one on the other side of the call
    source: str
    sink: str
    through: str            # the method of one program the other one calls
    where: str              # the method of the calling program
    returned: bool          # True: ``through`` gives the download back; False: it is handed the download


def _short(name: str) -> str:
    owner, _, method = name.rpartition("::")
    return "%s::%s" % (owner.rsplit(".", 1)[-1], method)


class _Budget:
    def __init__(self) -> None:
        self.steps = 0

    def take(self, count: int) -> None:
        self.steps += count
        if self.steps > MAX_STEPS:
            raise il.IlError("more than %d instructions" % MAX_STEPS)


class _State:
    """What the methods of one program are known by while they are read: what each
    one gives back, which of its arguments reach a load or a start, what it
    writes where - and the fields of the classes."""

    def __init__(self, module: il.Module, bodies: Dict[int, tuple], by_name: Dict[Tuple[str, int], List[int]]) -> None:
        self.module, self.bodies, self.by_name = module, bodies, by_name
        self.fields: Dict[tuple, FrozenSet[tuple]] = {}
        self.locals: Dict[tuple, FrozenSet[tuple]] = {}     # local variables (and arguments that are assigned)
        self.returns: Dict[int, FrozenSet[tuple]] = {}      # method -> what it gives back
        self.runs: Dict[Tuple[int, int], Tuple[str, int]] = {}  # (method, argument) -> (load / start it reaches, hand-overs)
        self.writes: Dict[int, Set[tuple]] = {}     # method -> (argument that is written, "p" / "t", argument / text of the path)
        self.drops: Dict[Tuple[int, int], str] = {}  # (method, argument): a download is written to the path it names
        self.tainted: Dict[tuple, str] = {}         # slot -> the download written into it
        self.dropped: Dict[tuple, str] = {}         # slot that holds the path of a written download
        self.dropped_texts: Dict[str, str] = {}     # ... and the paths written out as text
        self.hits: Dict[tuple, Hit] = {}
        self.wants_gives: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.wants_runs: Dict[Tuple[str, str], Tuple[str, str]] = {}
        self.wants_args: Dict[Tuple[str, str], Set[int]] = {}   # ... which arguments carry the download
        self.traced: Set[int] = set()               # the methods that are read
        self.callers: Dict[int, Set[int]] = {}
        self.family_rows: Dict[int, List[int]] = {}
        self.dirty: Set[int] = set()                # methods to read (again): something they use has changed
        self._targets: Dict[int, Tuple[int, ...]] = {}

    def targets(self, callee: il.Callee) -> Tuple[int, ...]:
        """The methods with a body that a call of the own method ``callee`` can reach:
        itself - or, for a method without one (an interface's, an abstract one), the
        methods of that name and size."""
        row = callee.own
        known = self._targets.get(row)
        if known is None:
            if row in self.bodies:
                known = (row,)
            else:
                name = callee.name.rpartition("::")[2]
                known = tuple(self.by_name.get((name, callee.params), ())[:_MAX_TARGETS])
            self._targets[row] = known
        return known

    # -- what has changed: who has to be read again ------------------------------------------
    def want(self, rows: Iterable[int]) -> None:
        """Read these methods (again). A method that was not read so far comes in with
        the other methods of its class (they talk through its fields)."""
        for row in rows:
            if row in self.traced:
                self.dirty.add(row)
            elif row in self.bodies:
                mates = self.family_rows.get(self.module.family(self.bodies[row][0].type_row), (row,))
                self.traced.update(mates)
                self.dirty.update(mates)

    def changed_method(self, row: int, spread: bool = True) -> None:
        """What is known about a method has changed: what calls it is read (again) - this
        is how the reading spreads upwards from a download or a start, one call at a time.
        ``spread`` False: only the callers that are read anyway (the change carries
        nothing a caller that was not read could turn into a chain)."""
        callers = self.callers.get(row, ())
        if spread:
            self.want(callers)
        else:
            self.dirty.update(caller for caller in callers if caller in self.traced)

    def changed_slot(self, slot: tuple) -> None:
        if slot[0] == "F":
            self.want(self.family_rows.get(self.module.family(slot[1][0]), ()))
        else:
            self.want((slot[1],))


def _trim(tags: FrozenSet[tuple]) -> FrozenSet[tuple]:
    if len(tags) <= _MAX_TAGS:
        return tags
    texts = sorted(t for t in tags if t[0] in (TEXT, FILE_TEXT))
    rest = sorted((t for t in tags if t[0] not in (TEXT, FILE_TEXT)),
                  key=lambda t: (t[0] not in (DL, DROP), t[0] != PARAM, t[0] != FN, str(t)))
    return frozenset(rest[:_MAX_TAGS - _MAX_TEXTS] + texts[:_MAX_TEXTS])


def _has(tags: Iterable[tuple], kind: str) -> Optional[str]:
    """What the mark of ``kind`` in ``tags`` names (of several: the first by name, so that
    the answer does not depend on the order in which a set happens to be walked)."""
    found = [tag[1] for tag in tags if tag[0] == kind]
    return min(found) if found else None


def _youngest(tags: Iterable[tuple], kind: str) -> Optional[tuple]:
    """The mark of ``kind`` that has travelled over the fewest hand-overs."""
    found = None
    for tag in tags:
        if tag[0] == kind and (found is None or (tag[2], tag[1]) < (found[2], found[1])):
            found = tag
    return found


def _handed(tags: Iterable[tuple], steps: int = 1) -> FrozenSet[tuple]:
    """``tags`` after a hand-over between two methods: the counted marks are older, and
    those that have travelled more than :data:`MAX_DEPTH` hand-overs stay behind."""
    out = set()
    for tag in tags:
        if tag[0] in _COUNTED:
            if tag[2] + steps <= MAX_DEPTH:
                out.add((tag[0], tag[1], tag[2] + steps))
        elif tag[0] not in (ORIGIN, BOX):
            out.add(tag)
    return frozenset(out)


class _Trace:
    """One reading of one method."""

    def __init__(self, state: _State, method: il.Method, code: List[il.Instruction]) -> None:
        self.state, self.module, self.method, self.code = state, state.module, method, code
        self.family_row = self.module.family(method.type_row)
        self.stack: List[FrozenSet[tuple]] = []
        self.boxes: Dict[int, Set[tuple]] = {}
        owner = self.module.type_name(method.type_row)
        if self.family_row != method.type_row:          # a generated class: say whose it is
            owner = "%s/%s" % (self.module.type_name(self.family_row), owner)
        self.where = "%s::%s" % (owner, method.name)
        self.address = ""
        self.serial = 0

    # -- values ----------------------------------------------------------------------------
    def pop(self) -> FrozenSet[tuple]:
        return self.stack.pop() if self.stack else EMPTY

    def push(self, tags: FrozenSet[tuple]) -> None:
        if len(self.stack) < _MAX_STACK:
            self.stack.append(_trim(tags))

    def full(self, tags: FrozenSet[tuple]) -> FrozenSet[tuple]:
        """``tags`` with what was put into the arrays / objects they name."""
        out = set(tags)
        for tag in tags:
            if tag[0] == BOX:
                out |= self.boxes.get(tag[1], ())
        return frozenset(out)

    def slot(self, kind: str, number) -> tuple:
        return (kind, self.method.row, number) if kind != "F" else (kind, number)

    def load(self, slot: tuple, held: FrozenSet[tuple]) -> FrozenSet[tuple]:
        tags = set(held)
        tags.add((ORIGIN, slot))
        if slot in self.state.tainted:
            tags.add((DL, self.state.tainted[slot], 0))
        if slot in self.state.dropped:
            tags.add((DROP, self.state.dropped[slot], 0))
        return frozenset(tags)

    def kept(self, tags: FrozenSet[tuple]) -> FrozenSet[tuple]:
        """What is stored: without the marks of where a value was loaded from, and each
        counted mark once, at its youngest."""
        youngest: Dict[tuple, int] = {}
        out = set()
        for tag in self.full(tags):
            if tag[0] in _COUNTED:
                key = tag[:2]
                youngest[key] = min(youngest.get(key, tag[2]), tag[2])
            elif tag[0] not in (ORIGIN, BOX):
                out.add(tag)
        out.update(key + (hops,) for key, hops in youngest.items())
        return _trim(frozenset(out))

    def field_slot(self, token: int) -> Optional[tuple]:
        owner, name = self.module.field(token)
        if owner and self.module.family(owner) == self.family_row:
            return self.slot("F", (owner, name))
        return None

    def store(self, table: Dict, key, tags: FrozenSet[tuple]) -> bool:
        if tags:
            held = table.get(key, EMPTY)
            if not tags <= held:
                table[key] = self.kept(held | tags)
                return table[key] != held
        return False

    # -- marks -----------------------------------------------------------------------------
    def taint(self, tags: FrozenSet[tuple], source: str) -> None:
        """A download was written into what ``tags`` names (a buffer, an object)."""
        for tag in tags:
            if tag[0] == ORIGIN:
                if tag[1] not in self.state.tainted:
                    self.state.tainted[tag[1]] = source
                    self.state.changed_slot(tag[1])
            elif tag[0] == BOX:
                self.boxes.setdefault(tag[1], set()).add((DL, source, 0))

    def drop(self, path: FrozenSet[tuple], source: str) -> None:
        """A download was written to the file ``path`` names."""
        state = self.state
        for tag in self.full(path):
            if tag[0] in (ORIGIN, FILE_SLOT):
                if tag[1] not in state.dropped:
                    state.dropped[tag[1]] = source
                    state.changed_slot(tag[1])
            elif tag[0] in (TEXT, FILE_TEXT) and _FILE_NAME.search(tag[1]) and len(state.dropped_texts) < 256:
                if tag[1].lower() not in state.dropped_texts:
                    state.dropped_texts[tag[1].lower()] = source
                    state.dirty |= state.traced             # (rare: every method may name that file)
            elif tag[0] == BOX:
                self.boxes.setdefault(tag[1], set()).add((DROP, source, 0))
            elif tag[0] == PARAM and tag[1] not in state.drops:
                state.drops[tag[1]] = source                # the path is an argument: the caller's file
                state.changed_method(tag[1][0])

    def written(self, path: FrozenSet[tuple], data: Iterable[FrozenSet[tuple]]) -> None:
        """``data`` is written to the file ``path`` names: a download - or an argument of
        this method, which is then known as a method that writes what it is handed."""
        state = self.state
        for tags in data:
            source = _has(tags, DL)
            if source:
                self.drop(path, source)
            for tag in tags:
                if tag[0] != PARAM:
                    continue
                row, number = tag[1]
                for mark in self.full(path):
                    entry = (number, "p", mark[1][1]) if mark[0] == PARAM and mark[1][0] == row else \
                        (number, "t", mark[1]) if mark[0] in (TEXT, FILE_TEXT) and _FILE_NAME.search(mark[1]) else None
                    if entry and entry not in state.writes.setdefault(row, set()) and len(state.writes[row]) < 16:
                        state.writes[row].add(entry)
                        state.changed_method(row)

    def dropped(self, tags: FrozenSet[tuple]) -> Optional[str]:
        found = _has(tags, DROP)
        if found:
            return found
        for tag in tags:
            if tag[0] == ORIGIN and tag[1] in self.state.dropped:
                return self.state.dropped[tag[1]]
            if tag[0] == TEXT and tag[1].lower() in self.state.dropped_texts:
                return self.state.dropped_texts[tag[1].lower()]
        return None

    def hit(self, how: str, source: str, sink: str) -> None:
        key = (self.where, sink, how)
        if key not in self.state.hits and len(self.state.hits) < MAX_HITS:
            self.state.hits[key] = Hit(how, source, sink, self.where, self.address)

    def reaches(self, tags: FrozenSet[tuple], sink: str, depth: int) -> None:
        """``tags`` are handed to something that loads or starts them (``sink``), over
        ``depth`` hand-overs between methods from here on."""
        state = self.state
        download = _youngest(tags, DL)
        written = self.dropped(tags)
        if download is not None and download[2] + depth <= MAX_DEPTH:
            self.hit("loader", download[1], sink)
        elif written and depth <= MAX_DEPTH:
            self.hit("dropper", written, sink)
        for tag in tags:
            if tag[0] == PARAM:                         # an argument of a method reaches the start
                total = tag[2] + depth
                known = state.runs.get(tag[1])
                if total <= MAX_DEPTH and (known is None or (total, sink) < (known[1], known[0])):
                    state.runs[tag[1]] = (sink, total)
                    state.changed_method(tag[1][0])
            elif tag[0] == EXT and tag[2] + depth <= MAX_DEPTH and len(state.wants_gives) < MAX_SHARED:
                known = state.wants_gives.get(tag[1])
                if known is None or (sink, self.where) < known:
                    state.wants_gives[tag[1]] = (sink, self.where)

    # -- reading ---------------------------------------------------------------------------
    def run(self) -> None:
        module, state = self.module, self.state
        saved: Dict[int, List[FrozenSet[tuple]]] = {}
        dead = False
        row = self.method.row
        for ins in self.code:
            code = ins.code
            if dead:
                self.stack = list(saved.get(ins.offset, ()))
                dead = False
            elif ins.offset in saved and len(saved[ins.offset]) == len(self.stack):
                self.stack = [a | b for a, b in zip(self.stack, saved[ins.offset])]
            if code in il.LOAD_LOCAL or code in (0x11, 0x12, 0xFE0C, 0xFE0D):
                slot = self.slot("L", il.LOAD_LOCAL.get(code, ins.operand))
                self.push(self.load(slot, state.locals.get(slot, EMPTY)))
            elif code in il.STORE_LOCAL or code in (0x13, 0xFE0E):
                self.store(state.locals, self.slot("L", il.STORE_LOCAL.get(code, ins.operand)), self.kept(self.pop()))
            elif code in il.LOAD_ARG or code in (0x0E, 0x0F, 0xFE09, 0xFE0A):
                number = il.LOAD_ARG.get(code, ins.operand)
                slot = self.slot("A", number)
                self.push(self.load(slot, state.locals.get(slot, EMPTY)) | {(PARAM, (row, number), 0)})
            elif code in (0x10, 0xFE0B):
                self.store(state.locals, self.slot("A", ins.operand), self.kept(self.pop()))
            elif code == il.LDSTR:
                text = module.string(ins.operand)
                if _REMOTE.match(text) and not _LOCAL.match(text) and not self.address:
                    self.address = text[:200]
                self.push(frozenset({(TEXT, text[:200])}) if text else EMPTY)
            elif code in (0x7B, 0x7C, 0x7E, 0x7F):                  # ldfld ldflda ldsfld ldsflda
                held = self.pop() if code in (0x7B, 0x7C) else EMPTY
                slot = self.field_slot(ins.operand)
                carried = frozenset(t for t in self.full(held) if t[0] in (DL, DROP))
                self.push(carried | (self.load(slot, state.fields.get(slot, EMPTY)) if slot else EMPTY))
            elif code in (0x7D, 0x80):                              # stfld, stsfld
                value = self.pop()
                if code == 0x7D:
                    self.pop()
                slot = self.field_slot(ins.operand)
                if slot and self.store(state.fields, slot, self.kept(value)):
                    state.changed_slot(slot)
            elif code == 0x8D:                                      # newarr: something can be put into it
                self.pop()
                self.boxes[ins.offset] = set()
                self.push(frozenset({(BOX, ins.offset)}))
            elif code in (0xA4,) or 0x9B <= code <= 0xA2:           # stelem
                value, _index, array = self.pop(), self.pop(), self.pop()
                carried = {t for t in self.full(value) if t[0] in (DL, DROP, TEXT, FN, PARAM, EXT)}
                for tag in array:
                    if tag[0] == BOX:
                        self.boxes.setdefault(tag[1], set()).update(carried)
                    elif tag[0] == ORIGIN and _has(carried, DL):
                        self.taint(frozenset({tag}), _has(carried, DL))
            elif code in (0x8F, 0xA3) or 0x90 <= code <= 0x9A:      # ldelem
                self.pop()
                self.push(self.pop())
            elif code in (il.CALL, il.CALLVIRT, il.NEWOBJ):
                self.call(code, module.callee(ins.operand))
            elif code in (il.LDFTN, il.LDVIRTFTN):                  # a method as a value: a delegate to be
                if code == il.LDVIRTFTN:
                    self.pop()
                callee = module.callee(ins.operand)
                self.push(frozenset((FN, target) for target in state.targets(callee)[:_MAX_FNS]) if callee.own else EMPTY)
            elif code == il.CALLI:
                callee = module.callee(ins.operand)
                for _ in range(callee.params + 1 + callee.has_this):
                    self.pop()
                if callee.returns != il.VOID:
                    self.push(EMPTY)
            elif code == il.RET:
                if self.stack:                                      # what the method gives back
                    value = frozenset(t for t in self.kept(self.pop()) if t[0] != PARAM or t[1][0] == row)
                    if self.store(state.returns, row, value):
                        # (a method that gives a download back draws its callers in; one that
                        # only gives back what it was handed does not)
                        state.changed_method(row, any(t[0] in (DL, DROP) for t in value))
            elif code == il.SWITCH:
                self.pop()
            elif code == 0x8E:                                      # ldlen: a number
                self.pop()
                self.push(EMPTY)
            else:
                _size, pops, pushes = il.OPCODES[code]
                if pops == 1 and pushes == 1:
                    pass                                            # a conversion, a cast: the same value
                elif pops == 2 and pushes == 1 and (0x58 <= code <= 0x64 or 0xD6 <= code <= 0xDB):
                    second, first = self.full(self.pop()), self.full(self.pop())    # a ^ key: still that data
                    self.push(frozenset(t for t in first | second if t[0] in _COUNTED))
                elif pops == 1 and pushes == 2:
                    top = self.pop()
                    self.push(top)
                    self.push(top)
                else:
                    for _ in range(pops):
                        self.pop()
                    for _ in range(pushes):
                        self.push(EMPTY)
            goes = il.target(ins)
            if goes is not None and goes > ins.offset and goes not in saved:
                saved[goes] = list(self.stack)
            if code in il.ENDS:
                self.stack, dead = [], True

    def call(self, code: int, callee: il.Callee) -> None:
        state = self.state
        args = [self.pop() for _ in range(callee.params)][::-1]
        this = self.pop() if callee.has_this and code != il.NEWOBJ else None
        name = callee.name
        full = [self.full(a) for a in args]
        full_this = self.full(this) if this is not None else EMPTY
        everything = full + [full_this]
        method = _METHOD.search(name)
        method = method.group(1) if method else ""
        result: Set[tuple] = set()
        known = False                                   # a call this model knows by name

        # -- a start or a load: does what it is given come from the network? ------------------
        native = self.module.imported(callee.own) if callee.own else ""
        sink = _short(name) if _LOAD.match(name) or _START.match(name) else \
            native if native and _START_NATIVE.match(native) else ""
        if sink:
            known = True
            before = len(state.hits)
            loads = _LOAD.match(name) or sink.lower().startswith("loadlibrary")
            chooses = everything if not loads else full[:2] if _LOAD_TWO.match(name) else full[:1]
            for tags in chooses:
                self.reaches(tags, sink, 0)
            if len(state.hits) == before and _LOAD_BY_ADDRESS.match(name):
                remote = min((t[1] for tags in full[:1] for t in tags
                              if t[0] == TEXT and _REMOTE.match(t[1]) and not _LOCAL.match(t[1])), default=None)
                if remote:
                    self.address = self.address or remote
                    self.hit("loader", "the address it is given", sink)

        # -- a download ---------------------------------------------------------------------
        addresses = [t[1] for tags in full for t in tags if t[0] == TEXT and _REMOTE.match(t[1])]
        local = bool(addresses) and all(_LOCAL.match(a) for a in addresses)
        if _SOURCE.match(name):
            known = True
            if not local:
                result.add((DL, _short(name), 0))
        elif _SOURCE_TO_FILE.match(name):
            known = True
            if not local and len(args) > 1:
                self.drop(args[1], _short(name))
        elif _SOURCE_INTO.match(name):
            known = True
            for tags in args:
                self.taint(tags, _short(name))

        # -- a file that is written ---------------------------------------------------------
        if _WRITE_ALL.match(name) and len(args) > 1:
            known = True
            self.written(args[0], full[1:])
        elif _MOVE.match(name) and len(args) > 1:
            known = True
            source = _has(full[0], DL) or self.dropped(full[0])
            if source:
                self.drop(args[1], source)
        elif _OPEN_FILE.match(name) and args:
            known = True
            for tag in full[0]:                         # the stream / writer remembers its file
                if tag[0] == ORIGIN:
                    result.add((FILE_SLOT, tag[1]))
                elif tag[0] == TEXT:
                    result.add((FILE_TEXT, tag[1]))
        if this is not None and method.startswith(("Write", "CopyTo")):
            if method.startswith("Write"):              # writer.Write(downloaded)
                source = next((s for s in (_has(tags, DL) for tags in full) if s), None)
                if source:
                    self.drop(frozenset(t for t in full_this if t[0] in (FILE_SLOT, FILE_TEXT)), source)
            elif _has(full_this, DL):                   # downloaded.CopyTo(file)
                for tags in full:
                    self.drop(frozenset(t for t in tags if t[0] in (FILE_SLOT, FILE_TEXT)), _has(full_this, DL))

        # -- what a call writes into what it is handed --------------------------------------
        if this is not None and _has(full_this, DL) and method.startswith(("Read", "Receive", "CopyTo", "EndRead")):
            for tags in args:                           # stream.Read(buffer, ...)
                self.taint(tags, _has(full_this, DL))
        elif _FILLS.match(name) and args and _has(full[0], DL):
            for tags in args[1:]:
                self.taint(tags, _has(full[0], DL))
        elif this is not None and method.startswith(("set_", "Add", "Append", "Enqueue", "Push", "Insert")):
            carried = {t for tags in full for t in tags if t[0] in (DL, DROP)}
            if carried:                                 # info.FileName = downloaded
                for tag in this:
                    if tag[0] == ORIGIN:
                        if _has(carried, DL):
                            self.taint(frozenset({tag}), _has(carried, DL))
                        if _has(carried, DROP) and tag[1] not in state.dropped:
                            state.dropped[tag[1]] = _has(carried, DROP)
                            state.changed_slot(tag[1])
                    elif tag[0] == BOX:
                        self.boxes.setdefault(tag[1], set()).update(carried)

        # -- a method of this program that was read: what is known about it -------------------
        targets = tuple(t for t in state.targets(callee) if t in state.traced) if callee.own and not known else ()
        if targets:
            raw = ([this] if this is not None else [EMPTY] if callee.has_this else []) + args
            passed = ([full_this] if this is not None else [EMPTY] if callee.has_this else []) + full
            via = "%s via %s"
            for target in targets:
                for number, tags in enumerate(passed):
                    reached = state.runs.get((target, number))
                    if reached:                         # the method loads / starts what this argument is
                        self.reaches(tags, reached[0] if " via " in reached[0] else via % (reached[0], _short(name)),
                                     reached[1] + 1)
                    source = state.drops.get((target, number))
                    if source:                          # the method writes a download to the path it is handed
                        self.drop(raw[number], source)
                for number, kind, path in state.writes.get(target, ()):
                    if number < len(passed):            # the method writes this argument to a file
                        if kind == "p" and path < len(passed):
                            self.written(raw[path], [_handed(passed[number])])
                        elif kind == "t":
                            self.written(frozenset({(TEXT, path)}), [_handed(passed[number])])
                if code != il.NEWOBJ:
                    for tag in state.returns.get(target, EMPTY):
                        if tag[0] == PARAM:             # it gives back what it was handed
                            if tag[1][1] < len(passed):
                                result.update(_handed((t for t in passed[tag[1][1]] if t[0] in _CARRIED), tag[2] + 1))
                        else:
                            result.update(_handed((tag,)))

        # -- a delegate that is handed on: its method gets what travels with it ------------------
        fns = sorted({t[1] for tags in everything for t in tags if t[0] == FN})[:_MAX_FNS]
        if fns:
            travelling = frozenset(t for tags in everything for t in tags if t[0] in (DL, DROP, TEXT, PARAM, EXT))
            for target in fns:
                if target not in state.traced:
                    continue
                label = _short("%s::%s" % (self.module.type_name(state.bodies[target][0].type_row),
                                           state.bodies[target][0].name))
                for (owner, _number), reached in list(state.runs.items()):
                    if owner == target:
                        self.reaches(travelling, reached[0] if " via " in reached[0] else "%s via %s" % (reached[0], label),
                                     reached[1] + 1)
                for tag in state.returns.get(target, EMPTY):
                    if tag[0] == PARAM:
                        result.update(_handed((t for t in travelling if t[0] != TEXT), tag[2] + 1))
                    else:
                        result.update(_handed((tag,)))

        # -- a method of another program -------------------------------------------------------
        outside = not callee.own and not known and name != "?" and "::" in name
        if outside and len(state.wants_runs) < MAX_SHARED:
            source = next((s for s in (_has(tags, DL) for tags in everything) if s), None)
            if source:
                known = state.wants_runs.get((callee.scope, name))
                if known is None or (source, self.where) < known:
                    state.wants_runs[(callee.scope, name)] = (source, self.where)
                passed = ([full_this] if this is not None else [EMPTY] if callee.has_this else []) + full
                state.wants_args.setdefault((callee.scope, name + callee.shape), set()).update(
                    number for number, tags in enumerate(passed) if _has(tags, DL))

        # -- what the call gives back -------------------------------------------------------
        if code != il.NEWOBJ and callee.returns == il.VOID:
            return
        if code != il.NEWOBJ and callee.returns == il.PLAIN:
            self.push(EMPTY)
            return
        if not targets or code == il.NEWOBJ:            # (an own method that was read gives back what it was read to)
            for tags in everything:
                result.update(t for t in tags if t[0] in _CARRIED)
        else:
            for tags in everything:
                result.update(t for t in tags if t[0] == FN)
        if outside and not any(t[0] in (DL, DROP, EXT) for t in result):
            result.add((EXT, (callee.scope, name), 0))  # where the value first came from
        if this is not None and method.startswith("get_"):
            result.update(t for t in this if t[0] == ORIGIN)    # info = process.StartInfo
        if code == il.NEWOBJ:                                   # new X { Name = downloaded }: set on it later
            self.serial -= 1
            self.boxes[self.serial] = set()
            result.add((BOX, self.serial))
        self.push(frozenset(result))


def _named(name: str) -> bool:
    return bool(_SOURCE.match(name) or _SOURCE_TO_FILE.match(name) or _SOURCE_INTO.match(name) or _LOAD.match(name)
                or _START.match(name) or _WRITE_ALL.match(name) or _MOVE.match(name) or _OPEN_FILE.match(name))


def _wanted(module: il.Module, official: bool = False) -> bool:
    """Is there anything to follow in this program? (phageo, 2026-10-11.) By what is in it;
    what the file is called plays no part.

    * Yes when its own reference tables name a download, a load or a start, or a file
      write - the members of other programs it refers to and the Windows functions it
      imports.
    * Yes, too, when it *defines* such a method itself (the .NET base library defines
      ``Assembly.Load``): a helper beside it can hand a download straight to it, and no
      reference table shows that. Not when the file is, byte for byte, a file of an
      official engine package (``official``) - there the definition is the vendor's own."""
    for name in module.references():
        if _named(name) or _START_NATIVE.match(name):
            return True
    if not official:
        for name in module.defined(_NAMED_TYPES.match):
            if _named(name):
                return True
    return False


def analyse(data: bytes, pe, official: bool = False) -> Found:
    """The download-and-run chains in the methods of one managed program, and what
    it leaves for the chain across programs. ``official``: the file is verified to be
    a file of an official engine package (see :func:`_wanted`)."""
    try:
        module = il.Module(data, pe)
        identity = Shares({}, {}, {}, {}, module.assembly_name(), module.forwarded())
        if not _wanted(module, official):
            return Found([], READ, shares=identity)
        budget = _Budget()
        # every method's instructions; which methods name a download or a start
        bodies: Dict[int, Tuple[il.Method, List[il.Instruction]]] = {}
        by_name: Dict[Tuple[str, int], List[int]] = {}
        families: Dict[int, List[int]] = {}
        calls: Dict[int, Set[int]] = {}             # method -> the own methods it calls or hands on (tokens)
        net, run = set(), set()
        problems: List[str] = []
        for method in module.methods():
            if not method.rva:
                continue
            try:
                code = il.instructions(module.body(method.rva))
            except il.IlError as exc:
                if len(problems) < 3:
                    problems.append("%s::%s: %s" % (module.type_name(method.type_row), method.name, exc))
                elif len(problems) == 3:
                    problems.append("...")
                continue
            budget.take(len(code))
            bodies[method.row] = (method, code)
            families.setdefault(module.family(method.type_row), []).append(method.row)
            for ins in code:
                if ins.code not in (il.CALL, il.CALLVIRT, il.NEWOBJ, il.LDFTN, il.LDVIRTFTN):
                    continue
                callee = module.callee(ins.operand)
                name = callee.name
                if _SOURCE.match(name) or _SOURCE_TO_FILE.match(name) or _SOURCE_INTO.match(name):
                    net.add(method.row)
                elif _LOAD.match(name) or _START.match(name) or (
                        callee.own and _START_NATIVE.match(module.imported(callee.own))):
                    run.add(method.row)
                elif callee.own:
                    calls.setdefault(method.row, set()).add(ins.operand)
        if not net and not run:
            return Found([], UNREAD if problems else READ, "; ".join(problems), shares=identity)
        for row, (method, _code) in bodies.items():
            by_name.setdefault((method.name, module.callee(0x06000000 | row).params), []).append(row)
        first = _State(module, bodies, by_name)
        callers: Dict[int, Set[int]] = {}
        for row, tokens in sorted(calls.items()):
            for token in sorted(tokens):
                for target in first.targets(module.callee(token)):
                    callers.setdefault(target, set()).add(row)
        # The methods that can have a part in a chain. A download leaves the method that makes
        # it as what that method gives back (to its callers) or through a field (to the methods
        # of its class); an argument reaches a start from the methods above it. So the reading
        # begins with the methods that name a download or a start, and their classes - and
        # spreads to what calls a method only when something became known about that method
        # (_State.changed_method), never further than MAX_DEPTH hand-overs.
        #
        # What is known about a method depends on whether it was read (a method that was not
        # is taken to give back what went in). So that the result does not depend on the order
        # in which the reading spread, it is done again from nothing with the set of methods
        # the reading before it ended with - until that set stays as it is.
        reading: Set[int] = set()
        state = first
        for _attempt in range(_MAX_READINGS):
            state = _State(module, bodies, by_name)
            state.family_rows, state.callers, state._targets = families, callers, first._targets
            state.traced, state.dirty = set(reading), set(reading)
            state.want(sorted(net | run))
            for _round in range(_MAX_ROUNDS):
                todo = sorted(state.dirty & state.traced)
                if not todo:
                    break
                state.dirty = set()
                for row in todo:
                    method, code = bodies[row]
                    budget.take(len(code))
                    _Trace(state, method, code).run()
            if state.traced == reading:
                break
            reading = set(state.traced)

        def named(row: int) -> str:
            method = bodies[row][0]
            return "%s::%s" % (module.type_name(method.type_row), method.name)

        gives: Dict[str, str] = {}
        for row, tags in sorted(state.returns.items()):
            source = _has(tags, DL)
            if source and (named(row) in gives or len(gives) < MAX_SHARED):
                gives[named(row)] = min(source, gives.get(named(row), source))
        runs: Dict[str, str] = {}
        run_args: Dict[str, Set[int]] = {}
        for (row, number), (sink, _depth) in sorted(state.runs.items()):
            if row in bodies and (named(row) in runs or len(runs) < MAX_SHARED):
                runs[named(row)] = min(sink, runs.get(named(row), sink))
                run_args.setdefault(named(row) + module.method_shape(bodies[row][0].row), set()).add(number)
        wants_args = {(scope, overload): tuple(sorted(numbers))
                      for (scope, overload), numbers in state.wants_args.items()
                      if (scope, overload.split("(", 1)[0]) in state.wants_runs}
        shares = Shares(gives, runs, dict(sorted(state.wants_gives.items())), dict(sorted(state.wants_runs.items())),
                        identity.assembly, identity.forwarded,
                        {name: tuple(sorted(numbers)) for name, numbers in sorted(run_args.items())},
                        dict(sorted(wants_args.items())))
        hits = [state.hits[key] for key in sorted(state.hits)][:MAX_HITS]
        if problems:
            return Found(hits, UNREAD, "; ".join(problems), len(state.traced), shares)
        return Found(hits, READ, "", len(state.traced), shares)
    except il.IlError as exc:
        return Found([], UNREAD, str(exc))
    except (RecursionError, MemoryError) as exc:
        return Found([], UNREAD, type(exc).__name__)


def _overloads(entries: Iterable[Tuple[str, Tuple[int, ...]]], name: str) -> Dict[str, Set[int]]:
    """The argument numbers kept for ``name``, by overload: parameter types (``"(Type,Object[])"``)
    -> numbers; "" = the overload is not known (a kept reading of older code, a signature that
    was not read)."""
    out: Dict[str, Set[int]] = {}
    for key, numbers in entries:
        if key == name or (key.startswith(name + "(") and key.endswith(")")):
            out.setdefault(key[len(name):], set()).update(numbers)
    return out


def _meets(handed: Dict[str, Set[int]], reaching: Dict[str, Set[int]]) -> bool:
    """Whether a download handed to a method of another program goes in where that method
    loads or starts something - argument for argument, and overload for overload (phageo,
    2026-10-24, HO2-06 / HO2-07: ``Activator.CreateInstance(Type, object[])`` with a stream among
    the constructor arguments is not the ``(string, string)`` overload whose second argument
    names the type that is loaded). An overload not known on either side is compared with every
    overload of that name, as before."""
    every = set().union(*reaching.values())
    for shape, numbers in handed.items():
        if shape and shape in reaching:
            if numbers & reaching[shape]:
                return True
        elif not shape or "" in reaching:
            if numbers & every:
                return True
    return False


def join(programs: List[Shares]) -> List[Link]:
    """The chains across two of ``programs`` - one hop: a method of one program
    gives a download back to another program, which loads or starts it; or one
    program hands a download to a method of another, which loads or starts it.

    The call is resolved through the assembly its reference names (phageo,
    2026-10-11): only a program that gives itself that name is the one that is
    called - two programs may well have a method of the same name. When the
    reference names no assembly, or none of the scanned programs has that name,
    or the one that has it only passes the type on (a type forwarder), the call
    is not resolved: then every program with such a method is a candidate and
    each one is reported - none is picked."""
    gives: Dict[str, List[int]] = {}
    runs: Dict[str, List[int]] = {}
    named: Dict[str, List[int]] = {}
    for index, shares in enumerate(programs):
        for name in shares.gives:
            gives.setdefault(name, []).append(index)
        for name in shares.runs:
            runs.setdefault(name, []).append(index)
        if shares.assembly:
            named.setdefault(shares.assembly.lower(), []).append(index)

    def candidates(table: Dict[str, List[int]], scope: str, name: str) -> List[int]:
        having = table.get(name, ())
        referred = named.get(scope.lower(), ()) if scope else ()
        type_name = name.rpartition("::")[0]
        if referred and not any(type_name in programs[i].forwarded for i in referred):
            return [i for i in having if i in referred]
        return list(having)

    out: List[Link] = []
    seen = set()
    for index, shares in enumerate(programs):
        for (scope, name), (sink, where) in shares.wants_gives.items():
            for other in candidates(gives, scope, name):
                if other != index and (index, other, name, True) not in seen and len(out) < MAX_LINKS:
                    seen.add((index, other, name, True))
                    out.append(Link(index, other, programs[other].gives[name], sink, name, where, True))
        for (scope, name), (source, where) in shares.wants_runs.items():
            handed = _overloads(((key[1], numbers) for key, numbers in shares.wants_args.items() if key[0] == scope), name)
            for other in candidates(runs, scope, name):
                reaching = _overloads(programs[other].run_args.items(), name)
                if handed and reaching and not _meets(handed, reaching):
                    continue                            # the download goes in where nothing is loaded / started
                if other != index and (other, index, name, False) not in seen and len(out) < MAX_LINKS:
                    seen.add((other, index, name, False))
                    out.append(Link(other, index, source, programs[other].runs[name], name, where, False))
    return out