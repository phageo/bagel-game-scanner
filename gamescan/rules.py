"""Rule definitions and the shared :class:`RuleEngine`.

The engine only *matches*. It never decides whether a hit is a false positive;
it records what the :class:`~gamescan.context.ContextEngine` needs (whether the
hit sits inside a comment, the matched text, surrounding lines) and moves on.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/rules.py")

import bisect
import collections
import itertools
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from .models import PACKED, STATEMENT, Category as C, FileContext, Finding, Severity as S
from .yara import YaraRuleSet


# -- one reading per text (phageo, 2026-10-14, forty-second message) ---------------------------
# A JavaScript file is read by the rules and by five data-flow readings, and each of them
# masked its comments, found its quoted texts and cut it into functions again - for a bundle
# of megabytes a third of the scan. What depends on the text alone (nothing that counts steps)
# is kept for the last texts, by their content: the same text gives the same answer, whoever
# asks and in whatever order, so nothing found changes.
SHARED_ITEMS = 12                   # kept results (a few kinds for each of the last texts)
SHARED_FROM = 64 * 1024             # characters: a smaller text is read again (cheaper than keeping it)
_shared: "collections.OrderedDict[Tuple[str, Any], Any]" = collections.OrderedDict()
_shared_lock = threading.Lock()


def shared(kind: str, text: Any, make: Callable[[], Any]) -> Any:
    """``make()`` - a pure function of ``text`` named ``kind`` -, kept for the last texts."""
    if len(text) < SHARED_FROM:
        return make()
    key = (kind, text)
    with _shared_lock:
        found = _shared.get(key)
        if found is not None:
            _shared.move_to_end(key)
            return found
    value = make()
    with _shared_lock:
        _shared[key] = value
        while len(_shared) > SHARED_ITEMS:
            _shared.popitem(last=False)
    return value


def forget_shared() -> None:
    """Drop what is kept (the end of a scan: the texts are not needed any more)."""
    with _shared_lock:
        _shared.clear()


def _yara_severity(meta: dict) -> S:
    """``severity = "HIGH"`` wins; otherwise the conventional 0-100 ``score``."""
    name = str(meta.get("severity", "")).upper()
    if name in S.__members__:
        return S[name]
    score = meta.get("score", meta.get("threat_level"))
    if isinstance(score, int) and not isinstance(score, bool):
        return S.CRITICAL if score >= 90 else S.HIGH if score >= 70 else S.MEDIUM if score >= 40 else S.LOW
    return S.MEDIUM


# -- languages a rule can apply to -------------------------------------------
PY = frozenset({"python"})
JS = frozenset({"js"})
CS = frozenset({"csharp"})
SH = frozenset({"shell"})
DOTNET = frozenset({"dotnet"})     # strings pulled from a managed assembly
STRINGS = frozenset({"strings"})   # strings pulled from a native binary
RB = frozenset({"ruby"})
TEXT = PY | JS | CS | SH | RB
ALL = TEXT | DOTNET | STRINGS

_SEP = r"(?:\\{1,2}|/)"            # path separator as it appears in source or raw


def _names(names: str, windows: bool = False) -> str:
    """API and tool names as whole words only (phageo, 2026-10-17, fifty-ninth message): never a
    part of a longer name - ``pyHook`` is no hook library inside ``CopyHook``, ``KeyLog`` none
    inside ``SSLKeyLogger``. A letter, a digit or ``$`` beside it makes it part of a longer
    name; a dot, a quote or an underscore does not (``start_keylogger``, ``_winreg.SetValueEx``,
    ``_WriteProcessMemory@20``). (Round 2 made an underscore join parts for a few hours on
    2026-10-23; phageo took it back the same day: ``start_keylogger`` in a script must be found,
    and OpenSSL's ``nss_keylog_int`` among a library's strings is found too - HIGH.)
    ``windows``: a Windows function also stands with ``A`` / ``W`` at its end - its two forms
    (the import table check reads them the same: ``pe.import_names``). Longer functions of
    the same family are written out where they are meant (``CreateRemoteThreadEx``)."""
    return r"%s(?:%s)%s(?![A-Za-z0-9$])" % (_LEFT, names, "[AW]?" if windows else "")


# where a whole name may begin: no letter, digit or ``$`` before it. One plain look-behind,
# so that the rules' start texts are still found (start_texts).
_LEFT = r"(?<![A-Za-z0-9$])"
_MAX_MATCHES = 3000                # regex hits examined per rule, per file
PACKED_LINE = 1000                 # a line longer than this is packed code: read by statements
# Quoted texts, written "unrolled" (phageo, 2026-10-17, fifty-ninth message): ``"[^"\\]*(?:\\.[^"\\]*)*"``
# matches exactly what ``"(?:\\.|[^"\\])*"`` matches, but Python's regular expressions keep a record
# for every turn of a group - the old form one per character of the text, the new one per escape.
# A real sample's script with one string of tens of millions of characters took about 4 GB in
# the old form, for each of the patterns below that walked over it.
_DQ = r'"[^"\\\n]*(?:\\.[^"\\\n]*)*"'                  # "...", on one line
_SQ = r"'[^'\\\n]*(?:\\.[^'\\\n]*)*'"                  # '...', on one line
_BQ = r"`[^`\\]*(?:\\.[^`\\]*)*"                       # `... (a template may go over lines; its end not given)
_CUT = re.compile(_DQ + "|" + _SQ + "|" + _BQ + r"`|([;{}])")


def _packed_lines(starts: List[int], length: int) -> Dict[int, bool]:
    """The indexes (from 0) of the lines that are longer than `PACKED_LINE`."""
    ends = starts[1:] + [length]
    return {index: True for index, (a, b) in enumerate(zip(starts, ends)) if b - a > PACKED_LINE}


def _statement_cuts(code: str) -> List[int]:
    """Where the statements of `code` end: every `;`, `{` and `}` that is not inside a
    quoted text, in order. (Comments are already blanked. A text that holds a script - a
    command of a game's data file - stays in one piece.)"""
    return [m.start(1) for m in _CUT.finditer(code) if m.group(1)]
_KEEP = 300                        # findings handed to the ContextEngine per rule, per file
_KEEP_SUPPRESSED = 2               # suppressed findings reported per rule, per file


@dataclass
class Rule:
    id: str
    title: str
    category: C
    severity: S
    pattern: str
    reason: str
    confidence: float = 0.6
    languages: FrozenSet[str] = ALL
    ignore_case: bool = False
    tags: tuple = ()               # hints for ContextEngine checks
    min_hits: int = 1              # report only if the file has this many hits
    max_per_file: int = 5
    chainable: bool = True         # may contribute to an attack chain
    regex: "re.Pattern[str]" = field(init=False, repr=False)
    needles: Optional[FrozenSet[str]] = field(init=False, repr=False, default=None)
    starts: Optional[Tuple[str, ...]] = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        # "rest of the line" must be bounded: on a megabyte-long line an
        # unbounded [^\n]* makes every failed attempt rescan the whole line,
        # which a hostile file can use to stall the scan
        pattern = self.pattern.replace(r"[^\n]*", r"[^\n]{0,300}")
        self.regex = re.compile(pattern, re.IGNORECASE if self.ignore_case else 0)
        self.needles = required_literals(pattern)
        self.starts = start_texts(pattern, self.regex.flags)


# -- prefilter ------------------------------------------------------------------
# Running ~80 regexes over megabytes of game data is slow, and almost all of
# them cannot match. For each pattern we derive literal substrings of which at
# least one MUST occur in any match; a plain (very fast) substring test then
# decides whether the regex needs to run at all. The derivation is
# conservative: if no such set can be proven, the rule simply always runs.
try:                                    # Python 3.11+
    from re import _constants as _sre_c, _parser as _sre_p
except ImportError:                     # Python 3.9 / 3.10
    import sre_constants as _sre_c
    import sre_parse as _sre_p


def _required(sequence) -> Optional[set]:
    """A set of lower-case literals, one of which every match must contain."""
    candidates, run = [], []

    def flush() -> None:
        if len(run) >= 3:
            candidates.append({"".join(run).lower()})
        del run[:]

    for op, arg in sequence:
        if op is _sre_c.LITERAL:
            run.append(chr(arg))
            continue
        flush()
        if op is _sre_c.SUBPATTERN:
            inner = _required(arg[-1])
            if inner:
                candidates.append(inner)
        elif op is _sre_c.BRANCH:
            parts = [_required(branch) for branch in arg[1]]
            if all(parts):
                candidates.append(set().union(*parts))
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT) and arg[0] >= 1:
            inner = _required(arg[2])
            if inner:
                candidates.append(inner)
    flush()
    if not candidates:
        return None
    return max(candidates, key=lambda group: (min(len(x) for x in group), -len(group)))


def required_literals(pattern: str) -> Optional[FrozenSet[str]]:
    """Literals of which one must appear (case-insensitively) in any match of
    ``pattern``, or None when that cannot be established."""
    try:
        found = _required(_sre_p.parse(pattern))
    except Exception:                    # parser internals differ: just do not prefilter
        return None
    return frozenset(found) if found else None


# -- matches only where a match can begin -------------------------------------------
# A rule's pattern is mostly a list of alternatives - fourteen for PERSIST-001, eighteen for
# CRED-001 - and the search tries every one of them at every character of the text. Measured
# on 2026-10-13: that was more than half of the time of a scan of a game with large scripts.
# For most patterns it can be said how a match must *begin*: with one of a few written-out
# texts ("CurrentVersion", "schtasks", "reg" ...). Then the pattern is tried only at the places
# where one of those texts stands (found by a plain search, which is fast), in the order of
# the places and never inside a match already made - exactly what the search does, so the
# matches are the same ones (a test compares both ways; so did every text of four samples).
_ZERO_WIDTH = (_sre_c.AT, _sre_c.ASSERT, _sre_c.ASSERT_NOT)
_MAX_PLACES = 200_000              # places tried for one rule in one text; above: the plain search
_MAX_NEAR = 2_000                  # letter look-alikes in one text; above: the plain search


def _first_texts(sequence, at: int = 0) -> Optional[set]:
    """Lower-case texts of which one begins every match of ``sequence[at:]`` - or None when
    that cannot be said (the match may begin with a character class, a reference ...)."""
    sequence = list(sequence)
    while at < len(sequence) and sequence[at][0] in _ZERO_WIDTH:
        at += 1                                         # (\b, ^, a look-around: no character)
    if at >= len(sequence):
        return None
    op, arg = sequence[at]
    if op is _sre_c.LITERAL:
        run = []
        while at < len(sequence) and sequence[at][0] is _sre_c.LITERAL:
            run.append(chr(sequence[at][1]))
            at += 1
        return {"".join(run).lower()}
    if op is _sre_c.SUBPATTERN:
        return _first_texts(arg[-1])
    if op is _sre_c.BRANCH:
        parts = [_first_texts(branch) for branch in arg[1]]
        return None if any(part is None for part in parts) else set().union(*parts)
    if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
        low, _high, item = arg
        inner = _first_texts(item)
        if inner is None:
            return None
        if low >= 1:
            return inner
        rest = _first_texts(sequence, at + 1)           # (it may be left out: then what follows begins)
        return None if rest is None else inner | rest
    return None


def start_texts(pattern: str, flags: int = 0) -> Optional[Tuple[str, ...]]:
    """The texts of which one begins every match of ``pattern`` (lower case, plain ASCII, two
    characters or more each), or None when that cannot be established."""
    try:
        found = _first_texts(_sre_p.parse(pattern, flags))
    except Exception:                    # parser internals differ: the plain search then
        return None
    if not found or any(len(text) < 2 or not text.isascii() for text in found):
        return None
    return tuple(sorted(found))


_lookalike: List["re.Pattern[str]"] = []


def lookalikes() -> "re.Pattern[str]":
    """The characters outside ASCII that have an ASCII letter or digit among their upper,
    lower or folded forms (the Turkish dotless i, the long s, the Kelvin sign, ligatures ...):
    the only ones a pattern's written-out ASCII text can match, ignoring case, without the
    lower-cased text showing it."""
    if not _lookalike:
        odd = [chr(code) for code in range(128, 0x10000)
               if any(c.isascii() and c.isalnum() for form in (chr(code).lower(), chr(code).upper(), chr(code).casefold())
                      for c in form)]
        _lookalike.append(re.compile("[%s]" % "".join(map(re.escape, odd))))
    return _lookalike[0]


class _Places:
    """One text, and where in it each rule is tried (see above)."""

    def __init__(self, text: str, lowered: str) -> None:
        self.text, self.lowered = text, lowered
        self.usable: Optional[bool] = None
        self.odd: List[int] = []                        # where a letter look-alike stands
        # One index per text for all rules (phageo, 2026-10-14, forty-third message: "all text
        # rules in one pass per text"): each start text and each required literal is looked for
        # once, whichever rules share it.
        self.words: Dict[str, List[int]] = {}
        self.present: Dict[str, bool] = {}
        self.whole = lowered                            # the lower-cased text as it is (literals)

    def has(self, needles: FrozenSet[str]) -> bool:
        """Does one of ``needles`` stand in the text (lower case)?"""
        present, whole = self.present, self.whole
        for n in needles:
            known = present.get(n)
            if known is None:
                known = present[n] = n in whole
            if known:
                return True
        return False

    def _where(self, word: str) -> List[int]:
        found = self.words.get(word)
        if found is None:
            found, find = [], self.lowered.find
            at = find(word)
            while at != -1:
                found.append(at)
                if len(found) > _MAX_PLACES:
                    break
                at = find(word, at + 1)
            self.words[word] = found
        return found

    def matches(self, rule: "Rule") -> Optional[list]:
        """The first ``_MAX_MATCHES`` matches of ``rule`` in the text, as the search over the
        whole text gives them - or None: this text or this rule is searched plainly."""
        if not self._ready():
            return None
        places = set()
        for word in rule.starts:
            places.update(self._where(word))
            if len(places) > _MAX_PLACES:
                return None
        return self._tried(rule.regex, places, max(map(len, rule.starts)), _MAX_MATCHES)

    def find_all(self, regex: "re.Pattern[str]", starts: Tuple[str, ...],
                 searches: Tuple["re.Pattern[str]", ...]) -> Optional[list]:
        """Every match of ``regex``, as ``regex.finditer(text)`` gives them, tried only where
        one can begin: at the places of ``starts``, and where one of ``searches`` - the
        alternatives of the pattern that begin with a written-out character, which the search
        finds fast - matches (each of them at every place it matches, not only those that do
        not overlap). None: this text is searched plainly."""
        if not self._ready():
            return None
        places = set()
        for word in starts:
            places.update(self._where(word))
            if len(places) > _MAX_PLACES:
                return None
        for sub in searches:
            at, search = 0, sub.search
            while True:
                m = search(self.text, at)
                if m is None:
                    break
                places.add(m.start())
                if len(places) > _MAX_PLACES:
                    return None
                at = m.start() + 1
        return self._tried(regex, places, max(map(len, starts), default=1), 0)

    def _tried(self, regex: "re.Pattern[str]", places: set, longest: int, limit: int) -> list:
        """The matches of ``regex`` at ``places``, in their order and never inside a match
        already made - what the search over the whole text finds (``limit``: 0 = all)."""
        text = self.text
        if self.odd:
            # a look-alike may stand for a letter of a start text: every place from which a
            # start text would reach it is tried too
            places = set(places)
            for at in self.odd:
                places.update(range(max(0, at - longest + 1), at + 1))
        out, behind, match = [], 0, regex.match
        for place in sorted(places):
            if place < behind:
                continue                                # inside the match before
            m = match(text, place)
            if m is not None:
                out.append(m)
                if limit and len(out) >= limit:
                    break
                behind = m.end() if m.end() > place else place + 1
        return out

    def _ready(self) -> bool:
        text = self.text
        if self.usable is None:
            self.usable = True
            if len(self.lowered) != len(text):
                # A character whose lower case is two characters (the Turkish dotted capital I)
                # shifted every place behind it, and the whole text was searched plainly by every
                # rule - measured on 2026-10-14: 65 of ELE-01's 94 seconds of rules, for one such
                # character. Lowered with that character kept in place, the places stay where they
                # are; the character is a letter look-alike, so the places around it are tried too.
                # (in its place a character no start text holds)
                wide = "".join(sorted(c for c in set(text) if len(c.lower()) != 1))
                self.lowered = "\x00".join(part.lower() for part in re.split("[%s]" % re.escape(wide), text))
                if len(self.lowered) != len(text):     # (cannot happen; then as before)
                    self.usable = False
                    return False
            if not text.isascii():
                for m in lookalikes().finditer(text):
                    self.odd.append(m.start())
                    if len(self.odd) > _MAX_NEAR:
                        self.usable = False
                        break
        return bool(self.usable)


# -- the flow readings' searches, where a match can begin (phageo, 2026-10-15) --------------------
# The three readings of a JavaScript text that follow data - what reaches the shell or eval (the
# payload reading), a download that is run, the program starts - each searched the whole text
# for its sinks and sources, with patterns that begin with "not after a letter": the search
# tries those at every character. Measured on ELE-01's 19 MB bundle: 8.8 s for eval-like calls
# that matched 3 times, 7.6 s for fetch-like calls (1 match), 6.1 s for loaders (0). Now one
# index per text, shared by the three readings and the rules (the same `_Places`): each written
# start text is looked for once, and a pattern is tried only where one of its alternatives can
# begin - the same matches as the search over the whole text (a test compares both ways).
_finders: Dict[Tuple[str, int], Optional[tuple]] = {}


def _alternatives(pattern: str) -> List[str]:
    """The top-level alternatives of ``pattern`` (split at ``|`` outside brackets and classes)."""
    out, depth, start, i, klass = [], 0, 0, 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if klass:
            klass = ch != "]"
        elif ch == "[":
            klass = True
            if pattern[i + 1:i + 2] == "]" or pattern[i + 1:i + 3] == "^]":
                i += 2 if pattern[i + 1] == "]" else 3
                continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            out.append(pattern[start:i])
            start = i + 1
        i += 1
    out.append(pattern[start:])
    return out


def _finder(regex: "re.Pattern[str]") -> tuple:
    """``(needles, (starts, searches) or None)`` for ``regex`` (see ``find_all``); None: it is
    searched plainly where one of the needles stands."""
    key = (regex.pattern, regex.flags)
    found = _finders.get(key)
    if found is not None:
        return found
    needles = required_literals(regex.pattern)
    places: Optional[tuple] = None
    try:
        starts: set = set()
        searches = []
        for alternative in _alternatives(regex.pattern):
            texts = _first_texts(_sre_p.parse(alternative, regex.flags))
            if texts and all(t and t.isascii() for t in texts):
                starts |= texts
                continue
            parsed = list(_sre_p.parse(alternative, regex.flags))
            if parsed and parsed[0][0] in (_sre_c.LITERAL, _sre_c.IN):
                searches.append(re.compile(alternative, regex.flags))   # (begins with a character: fast)
                continue
            raise ValueError("no place to begin")
        places = (tuple(sorted(starts)), tuple(searches))
    except Exception:                    # (no place to begin, or parser internals differ: plainly)
        places = None
    found = (frozenset(n.lower() for n in needles) if needles else None, places)
    if len(_finders) >= 4096:            # (patterns made for a name of one text: bounded)
        _finders.clear()
    _finders[key] = found
    return found


def text_places(text: str) -> "_Places":
    """The shared index of a text (see ``find_all``)."""
    return shared("places", text, lambda: _Places(text, text.lower()))


def find_all(regex: "re.Pattern[str]", text: str) -> list:
    """``list(regex.finditer(text))`` - for a large text through the text's shared index
    (``_Places.find_all``): the same matches, in the same order."""
    if len(text) < SHARED_FROM:
        return list(regex.finditer(text))
    needles, spec = _finder(regex)
    places = text_places(text)
    if needles is not None and not places.has(needles):
        return []                        # a literal every match holds is not in the text
    out = places.find_all(regex, *spec) if spec is not None else None
    return list(regex.finditer(text)) if out is None else out


# -- comment masking ----------------------------------------------------------
# Block constructs also match up to end-of-file when unterminated, so a file
# full of unclosed openers costs one pass, not one pass per opener. An
# unterminated block is never treated as a comment (see mask_comments).
_NON_NL = re.compile(r"[^\n]")
# (quoted texts: _DQ, _SQ, _BQ - unrolled, see above _CUT)
_MASKS = {
    "python": re.compile(
        r'''("""[\s\S]*?(?:"""|\Z)|\'\'\'[\s\S]*?(?:\'\'\'|\Z)|''' + _DQ + "|" + _SQ + r'''|\#[^\n]*)'''),
    # the 4th alternative is a JavaScript regex literal: without it "/x/*1"
    # would be read as the start of a block comment and hide the code after it
    "c": re.compile(
        "(" + _DQ + "|" + _SQ + "|" + _BQ + r'''(?:`|\Z)'''
        r'''|(?<=[(,=:\[!&|?{};\n])[ \t]*/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/'''
        r'''|//[^\n]*|/\*[\s\S]*?(?:\*/|\Z))'''),
    "powershell": re.compile(r'''("[^"`\n]*(?:`.[^"`\n]*)*"|'[^'\n]*'|<\#[\s\S]*?(?:\#>|\Z)|\#[^\n]*)'''),
    "sh": re.compile("(" + _DQ + r'''|'[^'\n]*'|(?<![\w$])\#[^\n]*)'''),
    "ruby": re.compile(
        "(" + _DQ + "|" + _SQ + r'''|`[^`\\\n]*(?:\\.[^`\\\n]*)*`|(?m:^=begin\b[\s\S]*?(?:^=end\b[^\n]*|\Z))|\#[^\n]*)'''),
    "bat": re.compile(r"(?im)^[ \t]*@?(?:rem\b|::)[^\n]*"),
    "vbs": re.compile(r'''("[^"\n]*"|'[^\n]*|(?im:^[ \t]*rem\b[^\n]*))'''),
}
_COMMENT_PREFIX = {
    "python": ("#",), "c": ("//", "/*"), "powershell": ("<#", "#"),
    "sh": ("#",), "vbs": ("'", "rem", "REM", "Rem"), "ruby": ("#", "=begin"),
}


_DOC_OWNER = re.compile(r"\s*(?:async\s+def|def|class)\b")
_BLOCK_END = {"/*": "*/", "<#": "#>"}


def _is_docstring(text: str, start: int) -> bool:
    """Only a real docstring counts as documentation: a triple-quoted string
    that opens the module, or is the first statement after a ``def`` / ``class``
    line. Anything else may be a value that is used (and executed) later."""
    j = start - 1
    while j >= 0 and start - j <= 2 and text[j] in "rRuUbBfF":   # string prefix
        j -= 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    if j >= 0 and text[j] != "\n":
        return False                       # something precedes it on its line
    while True:                            # walk back over blank and comment lines
        while j >= 0 and text[j] in " \t\r\n":
            j -= 1
        if j < 0:
            return True                    # module docstring
        line_start = text.rfind("\n", 0, j) + 1
        line = text[line_start:j + 1]
        if line.lstrip().startswith("#"):
            j = line_start - 1
            continue
        return text[j] == ":" and bool(_DOC_OWNER.match(line))


def mask_comments(text: str, style: Optional[str]) -> str:
    """Return ``text`` with comments blanked out (same length, same newlines)."""
    rx = _MASKS.get(style or "")
    if rx is None:
        return text
    return shared("mask " + style, text, lambda: _mask(text, style, rx))


def _mask(text: str, style: str, rx: "re.Pattern[str]") -> str:
    if style == "bat":
        return rx.sub(lambda m: _NON_NL.sub(" ", m.group(0)), text)
    prefixes = _COMMENT_PREFIX[style]

    def blanked(m: "re.Match[str]") -> bool:
        tok = m.group(0)
        if tok.startswith(prefixes):
            closer = _BLOCK_END.get(tok[:2])
            if closer and not (tok.endswith(closer) and len(tok) >= 4):
                return False               # unterminated block: keep it as code
            if tok.startswith("=begin") and "\n=end" not in tok:
                return False
            return True
        return (style == "python" and tok[:3] in ('"""', "'''") and len(tok) >= 6
                and tok.endswith(tok[:3]) and _is_docstring(text, m.start()))

    # The text is cut only where a comment is blanked: every string literal the pattern meets
    # stays where it is. (Until 2026-10-17 ``re.sub`` was handed each literal and each gap as a
    # string of its own and joined them at the end - for a 47-million-character script of a
    # real sample tens of millions of small strings, about 4 GB; phageo, fifty-ninth message.
    # The result is the same text, character for character.)
    pieces: List[str] = []
    at = 0
    for m in rx.finditer(text):
        if blanked(m):
            pieces.append(text[at:m.start()])
            pieces.append(_NON_NL.sub(" ", m.group(0)))
            at = m.end()
    if not pieces:
        return text
    pieces.append(text[at:])
    return "".join(pieces)


# -- JavaScript: quoted text is not code ---------------------------------------------------
# phageo, 2026-10-13: a word inside a string literal, inside the text parts of a template or
# inside a comment is never a call site - `fetch(` in a description text a code editor
# carries is a word, not a download. What stays code: `${...}` inside a template, and every
# quoted text that stands inside the brackets of a call that runs text (eval, new Function,
# setTimeout ..., vm, document.write) - there the text is the program. A text that reaches
# such a call through names or decoding is found by the data-flow reading, which hands the
# rules what it resolved (handlers/base.py, resolve_payloads).
CALL = "call"                      # tag of a rule whose match is a call site (JavaScript)
IN_TEXT = "in_text"                # Finding.context: the match begins inside quoted text
_JS_TOKEN = (_DQ + "|" + _SQ + "|`"
             r"""|(?<=[(,=:\[!&|?{};\n])[ \t]*/(?![/*])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/"""
             r"""|//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)""")
_JS_TOP = re.compile(_JS_TOKEN)                     # outside every template: braces do not matter
_JS_INNER = re.compile(_JS_TOKEN + r"|[{}]")        # inside `${ ... }`: its braces are counted
_JS_TEMPLATE = re.compile(r"\\[\s\S]|\$\{|`")       # inside a template's text: what ends a part
_JS_RUNS_TEXT = re.compile(
    r"(?<![\w$])(?:eval|Function|setTimeout|setInterval|setImmediate|execScript|runInThisContext|runInNewContext"
    r"|runInContext|compileFunction|Script|SourceTextModule|write|writeln|insertAdjacentHTML|importScripts)\s*\(")
_JS_BRACKET = re.compile(r"[()]")
_MAX_RUN_CALL = 200_000            # characters of one call that runs text in which its end is looked for
_MAX_RUN_CALLS = 20_000            # such calls looked at in one file


class QuotedText:
    """The places of a JavaScript text that are quoted text - the inside of every string
    literal and the text parts of every template literal - except what stands inside a call
    that runs text. Read once per file, in one pass; nothing is run.

    Where the reading cannot be sure, the answer is "code" (a finding stays): a quote that
    is not closed on its line is no string, a template that is never closed is no text.
    Regular-expression literals are stepped over (a quote inside one opens nothing) and
    count as code."""

    def __init__(self, code: str) -> None:
        self.begins: List[int] = []
        self.ends: List[int] = []
        self._read(code)
        self._keep_what_is_run(code)

    def _read(self, code: str) -> None:
        begins, ends = self.begins, self.ends
        frames: List[List[int]] = []          # open templates: [brace depth inside its ${...}, spans before it]
        pos, in_text = 0, False               # in_text: inside the text of the innermost template
        while True:
            if in_text:
                m = _JS_TEMPLATE.search(code, pos)
                while m is not None and m.group(0)[0] == "\\":
                    m = _JS_TEMPLATE.search(code, m.end())
                if m is None:
                    break                     # never closed
                if m.start() > pos:
                    begins.append(pos)
                    ends.append(m.start())
                pos, in_text = m.end(), False
                if m.group(0) == "`":         # the template ends: code again (of the `${...}` around it, if any)
                    frames.pop()
                continue                      # (after `${`: code, until its closing brace)
            m = (_JS_INNER if frames else _JS_TOP).search(code, pos)
            if m is None:
                break
            first, pos = code[m.start()], m.end()
            if first in "\"'":
                begins.append(m.start() + 1)
                ends.append(m.end() - 1)
            elif first == "{":
                frames[-1][0] += 1
            elif first == "}":
                if frames[-1][0]:
                    frames[-1][0] -= 1
                else:
                    in_text = True            # the end of a `${...}`: the template's text goes on
            elif first == "`":
                frames.append([0, len(begins)])
                in_text = True
            # (else: a comment or a regular expression - stepped over)
        if frames:                            # a template that is never closed: nothing of it is taken for text
            del begins[frames[0][1]:], ends[frames[0][1]:]

    def _keep_what_is_run(self, code: str) -> None:
        """Quoted text inside the brackets of a call that runs text is code."""
        if not self.begins:
            return
        drop = set()
        for count, call in enumerate(_JS_RUNS_TEXT.finditer(code)):
            if count >= _MAX_RUN_CALLS:
                break
            if self.holds(call.start()):
                continue                      # the call's name is itself a word in a text
            depth, close = 1, min(len(code), call.end() + _MAX_RUN_CALL)
            for bracket in _JS_BRACKET.finditer(code, call.end(), close):
                if self.holds(bracket.start()):
                    continue
                depth += 1 if bracket.group(0) == "(" else -1
                if not depth:
                    close = bracket.start()
                    break
            a = bisect.bisect_left(self.begins, call.end())
            b = bisect.bisect_left(self.begins, close)
            drop.update(range(a, b))
        if drop:
            self.begins = [at for index, at in enumerate(self.begins) if index not in drop]
            self.ends = [at for index, at in enumerate(self.ends) if index not in drop]

    def holds(self, position: int) -> bool:
        """Does ``position`` lie inside quoted text?"""
        index = bisect.bisect_right(self.begins, position) - 1
        return index >= 0 and position < self.ends[index]


def quoted_text(code: str) -> QuotedText:
    """:class:`QuotedText` of ``code``, read once for everyone who asks (it is only read)."""
    return shared("quoted", code, lambda: QuotedText(code))


# -- rule set -----------------------------------------------------------------
def _R(*a, **k) -> Rule:
    return Rule(*a, **k)


DEFAULT_RULES: List[Rule] = [
    # ---- Python / Ren'Py -----------------------------------------------------
    _R("PY-EXEC-001", "Dynamic code execution (exec/eval)", C.EXECUTION, S.LOW,
       r"(?<![\w.])(?:exec|eval)\s*\(",
       "Runs code built at runtime. Common in game scripts, dangerous when the "
       "input is downloaded or decoded.", 0.3, PY),
    _R("PY-EXEC-002", "Dynamic import / code object construction", C.EXECUTION, S.LOW,
       r"""__import__\s*\(|importlib\.import_module\s*\(|(?<![\w.])compile\s*\([^\n]*['"]exec['"]|types\.(?:CodeType|FunctionType)\s*\(""",
       "Loads modules or builds code objects by name at runtime, which hides "
       "what is actually executed.", 0.35, PY),
    _R("PY-EXEC-003", "Native library loading via ctypes", C.EXECUTION, S.MEDIUM,
       r"ctypes\.(?:windll|WinDLL|CDLL|cdll|oledll|CFUNCTYPE|WINFUNCTYPE)",
       "Calls native OS APIs directly from script code, bypassing the engine "
       "sandbox.", 0.4, PY),
    _R("PY-EXEC-004", "Indirect call through a built-up attribute name", C.EXECUTION, S.MEDIUM,
       _IND[0],
       "A sensitive function is looked up by a name assembled from pieces, so "
       "the real call never appears in the file.", 0.55, PY),
    _R("PY-OBF-001", "Execution of decoded/decompressed payload", C.OBFUSCATION, S.CRITICAL,
       r"(?:exec|eval)\s*\([^\n]*(?:b(?:64|32|16|85)decode|decompress|fromhex|unhexlify|marshal\.loads|codecs\.decode|\[::-1\]|chr\s*\()",
       "Decodes a hidden payload and executes it in one step - the classic "
       "obfuscated-loader pattern.", 0.9, PY),
    _R("PY-OBF-002", "Payload decoding primitive", C.OBFUSCATION, S.MEDIUM,
       r"""base64\.[ab](?:64|32|16|85)decode|binascii\.(?:unhexlify|a2b_base64)|bytes\.fromhex|(?:zlib|lzma|bz2)\.decompress|marshal\.loads|codecs\.decode\s*\([^\n]*rot|\.decode\s*\(\s*['"](?:base64|hex|rot13|zlib)""",
       "Decodes or decompresses embedded data. Harmless for saves and assets, "
       "suspicious next to code execution.", 0.4, PY, tags=("decode",)),
    _R("PY-PROC-001", _IND[1], C.PROCESS, S.MEDIUM,
       _IND[2],
       "Starts an external program or shell command from game script.", 0.5, PY,
       tags=("spawn",)),
    _R("PY-NET-001", "Network client usage", C.NETWORK, S.MEDIUM,
       _IND[3],
       "Opens network connections from game script (HTTP, raw sockets, FTP or "
       "mail).", 0.5, PY),
    _R("PY-FS-001", "File / directory deletion", C.FILESYSTEM, S.MEDIUM,
       r"shutil\.rmtree\s*\(|os\.(?:remove|unlink|rmdir|removedirs)\s*\(",
       "Deletes files or directory trees.", 0.4, PY, tags=("delete",)),

    # ---- JavaScript / RPG Maker / NW.js -------------------------------------
    _R("JS-EXEC-001", "Dynamic code execution (eval / Function)", C.EXECUTION, S.LOW,
       r"""(?<![\w.$])eval\s*\(|new\s+Function\s*\(|(?:setTimeout|setInterval)\s*\(\s*['"`]""",
       "Runs code built at runtime. Plugins use this for note tags; it is "
       "dangerous when the input is fetched or decoded.", 0.3, JS, tags=(CALL,)),
    _R("JS-OBF-001", "Execution of decoded payload", C.OBFUSCATION, S.CRITICAL,
       r"(?:eval|Function)\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode|Buffer\.from|LZString\.decompress\w*)\s*\(",
       "Decodes a hidden string and executes it immediately - an obfuscated "
       "loader.", 0.9, JS),
    _R("JS-OBF-002", "String decoding primitive", C.OBFUSCATION, S.MEDIUM,
       r"""(?<![\w.$])atob\s*\(|String\.fromCharCode\s*\((?:\s*(?:0x[0-9a-fA-F]+|\d+)\s*,){6,}|unescape\s*\(\s*['"]%|Buffer\.from\s*\([^)\n]{0,200}['"](?:base64|hex)['"]""",
       "Rebuilds strings from encoded data, which hides URLs and commands "
       "from review.", 0.4, JS, tags=("decode", CALL)),
    _R("JS-OBF-003", "Obfuscator signature (_0x identifiers)", C.OBFUSCATION, S.MEDIUM,
       r"\b_0x[0-9a-fA-F]{3,6}\b",
       "The file was run through a JavaScript obfuscator, so its behaviour "
       "cannot be reviewed by reading it.", 0.6, JS, min_hits=25, max_per_file=1,
       chainable=False),
    _R("JS-OBF-004", "Unicode-escaped identifier", C.OBFUSCATION, S.MEDIUM,
       r"""(?<![\w\\'"`$])(?:[A-Za-z_$][\w$]*)?(?:\\u(?:00[0-9a-fA-F]{2}|\{[0-9a-fA-F]{1,4}\}))+[\w$]*\s*[(\[.]""",
       "A function or property name is written with \\u escapes (\\u0065val "
       "is eval), which hides it from anyone reading or scanning the code.",
       0.5, JS, max_per_file=3, tags=(CALL,)),
    _R("JS-PROC-001", "Child process spawning (Node.js)", C.PROCESS, S.HIGH,
       r"""require\s*\(\s*['"`](?:node:)?child_process['"`]\s*\)|process\.mainModule\.require|process\.binding\s*\(|\.(?:execSync|spawnSync|execFileSync)\s*\(""",
       "Gains the ability to start arbitrary programs on the PC. Game plugins "
       "almost never need this.", 0.7, JS, tags=(CALL,)),
    _R("JS-PROC-002", "Windows Script Host / ActiveX automation", C.PROCESS, S.HIGH,
       r"new\s+ActiveXObject\s*\(|WScript\.(?:Shell|CreateObject)",
       "Drives Windows scripting objects that can run commands and edit the "
       "registry.", 0.8, JS, tags=(CALL,)),
    _R("JS-NET-001", "Network request", C.NETWORK, S.LOW,
       r"""new\s+XMLHttpRequest|(?<![\w.$])fetch\s*\(|require\s*\(\s*['"](?:node:)?(?:https?|net|dgram|tls|request|axios|ws|node-fetch)['"]\s*\)|new\s+WebSocket\s*\(|\$\.(?:ajax|get|post)\s*\(|navigator\.sendBeacon""",
       "Performs a network or resource request.", 0.35, JS, tags=("netload", CALL)),
    _R("JS-NET-002", "NW.js node-remote enabled", C.NETWORK, S.HIGH,
       r'"node-remote"\s*:',
       "Gives pages loaded from the internet full Node.js access to this PC.",
       0.7, JS),
    _R("JS-FS-001", "Node.js filesystem write / delete", C.FILESYSTEM, S.MEDIUM,
       r"""fs\.(?:unlink|rmdir|rm|writeFile|appendFile|rename|copyFile)(?:Sync)?\s*\(|require\s*\(\s*['"]rimraf['"]\s*\)""",
       "Writes or deletes files through Node.js.", 0.4, JS, tags=("delete", CALL)),
    _R("JS-ENV-001", "User profile / environment access", C.FILESYSTEM, S.LOW,
       r"""process\.env\.(?:APPDATA|LOCALAPPDATA|USERPROFILE|HOME|TEMP)|os\.homedir\s*\(|require\s*\(\s*['"]os['"]\s*\)""",
       "Looks up the user's profile folders, which lie outside the game "
       "directory.", 0.3, JS, chainable=False, tags=(CALL,)),

    # ---- Ruby / RPG Maker XP, VX, VX Ace (RGSS) ------------------------------
    _R("RB-PROC-001", "Shell command execution (Ruby)", C.PROCESS, S.HIGH,
       _IND[4],
       "Runs a program or shell command on the PC. RPG Maker scripts have no "
       "ordinary reason to do this.", 0.7, RB),
    _R("RB-PROC-002", "Backtick command (Ruby)", C.PROCESS, S.MEDIUM,
       r"""(?<![\w"'`\\])`[^`\n]{3,200}`""",
       "Text between backticks is run as a shell command in Ruby.", 0.4, RB),
    _R("RB-EXEC-001", "Dynamic code execution (eval)", C.EXECUTION, S.LOW,
       r"""(?<![\w.])(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*[\w"'@$(\[]""",
       "Runs Ruby code built at runtime. The engine does this for event script "
       "commands; it is dangerous when the code is decoded or downloaded.", 0.3, RB),
    _R("RB-OBF-001", "Execution of decoded Ruby payload", C.OBFUSCATION, S.CRITICAL,
       r"""eval\s*\(?[^\n]{0,60}(?:unpack\s*\(?\s*["']m|decode64|\.pack\s*\(\s*["'][cCU]\*|\.reverse\b)""",
       "Decodes a hidden string and runs it as Ruby code in one step - an "
       "obfuscated loader.", 0.9, RB),
    _R("RB-OBF-002", "Execution of decompressed Ruby code", C.OBFUSCATION, S.HIGH,
       r"eval\s*\(?[^\n]{0,60}(?:Zlib::Inflate|Zlib\.inflate|\binflate\s*\()",
       "Decompresses data and runs it as code. Custom script loaders do this, "
       "and so do hidden payloads.", 0.6, RB),
    _R("RB-OBF-003", "Decoding primitive (Ruby)", C.OBFUSCATION, S.MEDIUM,
       r"""Base64\.decode64|\.unpack\s*\(?\s*["']m["']|Zlib::Inflate\.inflate""",
       "Decodes or decompresses embedded data. Normal for saves, suspicious "
       "next to code execution.", 0.4, RB, tags=("decode",)),
    _R("RB-NATIVE-001", "Native Windows API call (Win32API / Fiddle)", C.EXECUTION, S.MEDIUM,
       r"Win32API\.new\s*\(|\bFiddle::|\bFiddle\.dlopen|\bDL\.dlopen|\bDL::",
       "Calls Windows functions directly from a game script, outside the "
       "engine's sandbox.", 0.4, RB, tags=("rgss-api",)),
    _R("RB-NATIVE-002", "Native API that runs programs, downloads or injects", C.EXECUTION, S.HIGH,
       r"Win32API\.new\s*\([^\n]{0,80}"
       + _names(_IND[5], windows=True),
       "Reaches for a Windows function that starts programs, downloads files, "
       "changes the registry or runs injected code.", 0.75, RB),
    _R("RB-NET-001", "Network access (Ruby)", C.NETWORK, S.MEDIUM,
       r"""\bNet::(?:HTTP|FTP|SMTP)|\bTCPSocket\b|\bUDPSocket\b|\bOpenURI\b|\bURI\.open\b|require\s*\(?\s*["'](?:socket|net/http|net/ftp|net/smtp|open-uri)["']""",
       "Opens network connections from a game script.", 0.5, RB),
    _R("RB-FS-001", "File / directory deletion (Ruby)", C.FILESYSTEM, S.MEDIUM,
       r"\bFile\.(?:delete|unlink)\b|\bFileUtils\.(?:rm|rm_r|rm_rf|remove_dir|remove_entry\w*)\b|\bDir\.(?:rmdir|delete|unlink)\b",
       "Deletes files or directories.", 0.4, RB, tags=("delete",)),

    # ---- C# source -----------------------------------------------------------
    _R("CS-PROC-001", "Process spawning", C.PROCESS, S.MEDIUM,
       r"Process\.Start\s*\(|new\s+ProcessStartInfo",
       "Starts an external program.", 0.5, CS, tags=("spawn",)),
    _R("CS-NET-001", "Network client usage", C.NETWORK, S.MEDIUM,
       _IND[6],
       "Uses raw .NET networking instead of the engine's own web requests.",
       0.5, CS),
    _R("CS-EXEC-001", "Runtime assembly loading / code generation", C.EXECUTION, S.MEDIUM,
       r"Assembly\.Load(?:From|File)?\s*\(|CSharpCodeProvider|Reflection\.Emit",
       "Loads or generates code at runtime.", 0.45, CS),
    _R("CS-OBF-001", "Assembly loaded from decoded bytes", C.OBFUSCATION, S.CRITICAL,
       _IND[7],
       "Decodes a hidden assembly and loads it straight into memory.", 0.9, CS),
    _R("CS-OBF-002", "Base64 decoding", C.OBFUSCATION, S.LOW,
       _IND[8],
       "Decodes embedded Base64 data.", 0.3, CS, tags=("decode",), chainable=False),
    _R("CS-FS-001", "File / directory deletion", C.FILESYSTEM, S.MEDIUM,
       r"(?:File|Directory)\.Delete\s*\(",
       "Deletes files or directories.", 0.4, CS, tags=("delete",)),
    _R("CS-REG-001", "Registry access", C.PERSISTENCE, S.MEDIUM,
       r"Registry\.(?:CurrentUser|LocalMachine|ClassesRoot)|RegistryKey\b",
       "Reads or writes the Windows registry.", 0.4, CS),
    _R("CS-PINV-001", "P/Invoke into system DLL", C.EXECUTION, S.LOW,
       r'\[DllImport\s*\(\s*"(?:kernel32|ntdll|user32|advapi32)',
       "Calls raw Windows APIs from managed code.", 0.3, CS, chainable=False),

    # ---- managed (.NET) assembly metadata -----------------------------------
    _R("DN-PROC-001", "Process spawning (managed)", C.PROCESS, S.MEDIUM,
       _IND[9],
       "The assembly references the .NET process-launching API.", 0.5, DOTNET),
    _R("DN-NET-001", "Raw network client (managed)", C.NETWORK, S.MEDIUM,
       _IND[10],
       "The assembly references raw .NET networking instead of the engine's "
       "own web requests.", 0.5, DOTNET),
    _R("DN-EXEC-001", "Runtime code generation (managed)", C.EXECUTION, S.MEDIUM,
       r"(?m)(?<![\w])(?:DefineDynamicAssembly|CSharpCodeProvider|CompileAssemblyFromSource)$|System\.Reflection\.Emit$|System\.Reflection\.Assembly::Load(?:From|File)?$",
       "The assembly can generate or compile code at runtime.", 0.4, DOTNET),
    _R("DN-OBF-001", "Base64 decoding (managed)", C.OBFUSCATION, S.LOW,
       _IND[11],
       "The assembly decodes Base64 data.", 0.3, DOTNET, chainable=False),
    _R("DN-PACK-001", "Malware-associated .NET protector", C.PACKING, S.HIGH,
       r"ConfusedByAttribute|ConfuserEx|KoiVM|ObfuscatedByGoliath|ILProtector|YanoAttribute|NETGuard",
       "Protected with a tool that is far more common in malware than in "
       "shipped games.", 0.7, DOTNET),
    _R("DN-PACK-002", "Commercial .NET obfuscator", C.PACKING, S.MEDIUM,
       r"SmartAssembly\.|PoweredByAttribute|Eazfuscator|DotNetReactor|\.NET Reactor|BabelObfuscator|CryptoObfuscator|DotfuscatorAttribute|Agile\.NET",
       "The assembly is obfuscated, so its behaviour cannot be reviewed.",
       0.5, DOTNET),
    _R("DN-REG-001", "Registry access (managed)", C.PERSISTENCE, S.LOW,
       r"(?m)(?<![\w])RegistryKey$",
       "The assembly references the Windows registry API.", 0.3, DOTNET,
       chainable=False),

    # ---- shell / script droppers --------------------------------------------
    _R("SH-DL-001", "Remote download", C.NETWORK, S.HIGH,
       _names(_IND[12])
       + "|" + _names("URLDownloadToFile", windows=True)
       + _IND[13],
       "Downloads content from the internet.", 0.7, SH, ignore_case=True),
    _R("SH-EXEC-001", "Expression / pipe-to-shell execution", C.EXECUTION, S.HIGH,
       _IND[14],
       "Executes text as code - how downloaded payloads are run.", 0.6, SH,
       ignore_case=True),
    _R("SH-PROC-001", "Script-driven process launch", C.PROCESS, S.MEDIUM,
       _IND[15],
       "Launches other programs from a script.", 0.4, SH, ignore_case=True),
    _R("SH-OBF-001", "Encoded PowerShell command", C.OBFUSCATION, S.CRITICAL,
       r"""-e(?:nc(?:odedcommand)?)?\s+["']?[A-Za-z0-9+/]{40,}={0,2}""",
       "Passes a Base64-encoded command to PowerShell to hide what it does.",
       0.9, SH, ignore_case=True),
    _R("SH-OBF-002", "Execution-policy bypass / hidden window", C.EVASION, S.MEDIUM,
       r"-(?:ep|executionpolicy)\s+bypass|-w(?:indowstyle)?\s+h(?:idden)?\b|-nop(?:rofile)?\b|-noni\b",
       "Runs PowerShell hidden and with safety policies switched off.", 0.6, SH,
       ignore_case=True),
    _R("SH-OBF-003", "Decode primitive", C.OBFUSCATION, S.MEDIUM,
       _IND[16],
       "Decodes embedded data before using it.", 0.5, SH, ignore_case=True,
       tags=("decode",)),
    _R("SH-FS-001", "Recursive / forced deletion", C.FILESYSTEM, S.MEDIUM,
       r"\b(?:del|erase)\s+/[sfq]|\b(?:rd|rmdir)\s+/s|\brm\s+-[a-z]*[rf]|Remove-Item[^\n]*-(?:Recurse|Force)|\bformat\s+[a-z]:|\bcipher\s+/w|\bdd\s+if=[^\n]*of=/dev/|\bmkfs\.",
       "Deletes files recursively or without confirmation.", 0.5, SH,
       ignore_case=True, tags=("delete",)),
    _R("SH-HIDE-001", "Hides files", C.EVASION, S.LOW,
       r"attrib\s+\+[hs]", "Marks files as hidden/system.", 0.4, SH, ignore_case=True),

    # ---- every language, including strings from binaries --------------------
    _R("LOL-001", "System interpreter / LOLBin invocation", C.PROCESS, S.HIGH,
       _IND[17],
       "References a Windows system tool that malware uses to run commands "
       "and fetch payloads.", 0.6, ALL, ignore_case=True),
    _R("INJ-001", "Process injection API", C.EXECUTION, S.HIGH,
       _names(_IND[18], windows=True),
       "Writes code into another running process - used to hide inside "
       "trusted programs.", 0.6, ALL, tags=("api",)),
    _R("OBF-BLOB-001", "Large encoded blob literal", C.OBFUSCATION, S.MEDIUM,
       r"""['"`][A-Za-z0-9+/]{240,}={0,2}['"`]""",
       "A long encoded string is embedded in code; it may hide a payload.",
       0.4, TEXT, tags=("blob",), max_per_file=3),
    _R("OBF-HEX-001", "Escaped byte-string payload", C.OBFUSCATION, S.MEDIUM,
       r"(?:\\x[0-9a-fA-F]{2}){24,}|(?:\\u00[0-9a-fA-F]{2}){24,}",
       "A long run of escaped bytes hides readable content or shellcode.",
       0.5, TEXT, max_per_file=3),
    _R("OBF-CAT-001", "String assembled from tiny fragments", C.OBFUSCATION, S.MEDIUM,
       r"""(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){5,}|(?:String\.fromCharCode\s*\(\s*\d+\s*\)\s*\+\s*){5,}|(?:\[char\]\s*\d+\s*\+\s*){5,}|(?:['"][^'"\n]{1,3}['"]\s*\+\s*){7,}['"]""",
       "A word is built character by character so that it never appears in "
       "the file - a way to hide commands and URLs from scanners.", 0.5, TEXT,
       max_per_file=3),
    _R("OBF-REV-001", "Reversed command string", C.OBFUSCATION, S.HIGH,
       r"""['"`][^'"`\n]{0,80}(?:llehsrewop|exe\.dmc|//:s?ptth|metsys\.so|noisserpxE-ekovnI|edoced46b|gnirtSdaolnwoD)[^'"`\n]{0,80}['"`]""",
       "A command or URL is stored backwards and flipped at runtime to avoid "
       "detection.", 0.75, TEXT, ignore_case=True),
    _R("OBF-PE-001", "Embedded Windows executable (Base64)", C.OBFUSCATION, S.HIGH,
       r"TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA8A|TVoAAAAAAAAAAAAA",
       "A Base64 string that decodes to a Windows program is embedded in the "
       "file.", 0.9, ALL),
    _R("URL-001", "Hard-coded URL", C.NETWORK, S.LOW,
       r"""https?://(?!\d{1,3}(?:\.\d{1,3}){3})[^\s'"<>)\]\\}`,;]{4,}""",
       "Contacts or links to a web address that is not on the known-benign "
       "list.", 0.3, ALL, tags=("url",), chainable=False, max_per_file=10),
    _R("URL-IP-001", "URL with raw IP address", C.NETWORK, S.HIGH,
       r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?",
       "Talks to a bare IP address instead of a named site - typical of "
       "throwaway malware servers.", 0.7, ALL, tags=("url", "ip")),
    _R("NET-EXFIL-001", "Exfiltration / drop endpoint", C.NETWORK, S.HIGH,
       _IND[19],
       "Uses a service that stealers rely on to send stolen data out or to "
       "pull payloads in.", 0.8, ALL, ignore_case=True),
    _R("NET-RECON-001", "Public-IP lookup service", C.NETWORK, S.MEDIUM,
       r"api\.ipify\.org|ip-api\.com|checkip\.amazonaws\.com|ifconfig\.me|icanhazip\.com|ipinfo\.io",
       "Looks up the player's public IP address / location.", 0.6, ALL,
       ignore_case=True),
    _R("NET-PE-001", "Internet download API", C.NETWORK, S.MEDIUM,
       _names(r"URLDownloadToFile|InternetOpenUrl|InternetReadFile(?:Ex)?|WinHttpSendRequest|HttpSendRequest(?:Ex)?",
              windows=True),
       "Uses Windows internet APIs to fetch remote content.", 0.5, STRINGS,
       tags=("api",)),
    _R("FS-SYS-001", "Sensitive system path", C.FILESYSTEM, S.MEDIUM,
       r"windows" + _SEP + r"system32|/etc/(?:passwd|shadow)\b|drivers" + _SEP + r"etc" + _SEP + r"hosts|PhysicalDrive\d|/dev/sd[a-z]\b",
       "References operating-system locations a game has no reason to touch.",
       0.5, TEXT | DOTNET, ignore_case=True),
    _R("PERSIST-001", "Persistence mechanism", C.PERSISTENCE, S.HIGH,
       r"CurrentVersion" + _SEP + r"Run(?:Once)?\b|schtasks(?:\.exe)?\s+/create|Start Menu" + _SEP + r"Programs" + _SEP
       + r"Startup|shell:startup|crontab\s+-|/etc/(?:rc\.local|cron\.|systemd/system)|LaunchAgents|LaunchDaemons|\.config/autostart|\breg(?:\.exe)?\s+add\b|\bsc(?:\.exe)?\s+create\b|"
       + _names(r"New-ItemProperty|Register-ScheduledTask|winreg\.(?:SetValueEx|CreateKey(?:Ex)?)"),
       "Arranges for something to start automatically with the computer.",
       0.7, ALL, ignore_case=True),
    _R("CRED-001", "Credential / wallet / token store access", C.CREDENTIALS, S.HIGH,
       _IND[20] + _SEP + _IND[21]
       + _SEP + _IND[22] + _names(_IND[23]) + _IND[24] + _SEP + _IND[25]
       + _SEP + _IND[26],
       "Touches places where browsers, chat apps and wallets keep passwords "
       "and session tokens.", 0.8, ALL, ignore_case=True, tags=("api",)),
    _R("INPUT-001", "Keystroke capture", C.INPUT_CAPTURE, S.HIGH,
       _names(_IND[27]) + r"|" + _LEFT + r"keyboard\.(?:on_press|hook"
       r"|read_event|record)\s*\(|" + _names(_IND[28], windows=True),
       "Can record what the user types outside the game.", 0.7, ALL,
       ignore_case=True, tags=("api",)),
    _R("INPUT-002", "Screen / clipboard capture", C.INPUT_CAPTURE, S.MEDIUM,
       _names(_IND[29]) + r"|" + _LEFT + r"mss\.mss\s*\(",
       "Can capture the screen or read the clipboard.", 0.5, ALL, tags=("api",)),
    _R("EVADE-001", "Security-tool tampering / anti-analysis", C.EVASION, S.HIGH,
       _names("Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|DisableAntiSpyware")
       + r"|netsh\s+(?:adv)?firewall[^\n]*(?:off|disable)|vssadmin[^\n]*delete|bcdedit[^\n]*recoveryenabled|wevtutil\s+cl\b|taskkill[^\n]*(?:MsMpEng|avp\.exe|avast|defender)|\b(?:VBoxService|vmtoolsd|SbieDll|x64dbg|ollydbg)\b",
       "Tries to switch off protection, destroy recovery data, or detect "
       "analysis tools.", 0.7, ALL, ignore_case=True),
]


class RuleEngine:
    """Applies :class:`Rule` objects to text and produces raw findings."""

    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        self.rules: List[Rule] = list(DEFAULT_RULES if rules is None else rules)
        self._by_lang: Dict[str, List[Rule]] = {}
        self.yara = YaraRuleSet()
        self.amsi = None        # defender.Amsi, set by the Scanner when AMSI is enabled

    # -- YARA signatures ---------------------------------------------------------
    def load_yara(self, path: str) -> int:
        """Load YARA rules from a file or folder; returns how many were added."""
        return self.yara.load(path)

    def scan_yara(self, ctx: FileContext, handler: str = "") -> List[Finding]:
        """Match the loaded YARA rules against the raw bytes of a file."""
        out: List[Finding] = []
        for match in self.yara.match(ctx.data):
            meta = match.rule.meta
            severity = _yara_severity(meta)
            try:
                category = C(str(meta.get("category", "SIGNATURE")).upper())
            except ValueError:
                category = C.SIGNATURE
            hits = sorted(match.strings, key=lambda h: h[1])
            evidence = ", ".join("$%s @ 0x%x" % h for h in hits[:6]) or "condition matched"
            snippet = ""
            if hits:
                at = hits[0][1]
                chunk = ctx.data[max(0, at - 16):at + 96]
                snippet = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            try:
                confidence = min(1.0, max(0.0, float(meta.get("confidence", 0.8))))
            except (TypeError, ValueError):
                confidence = 0.8
            out.append(Finding(
                rule_id="YARA:" + match.rule.name,
                title=str(meta.get("description") or "YARA signature: " + match.rule.name),
                category=category, severity=severity, file=ctx.relpath, line=None,
                snippet=snippet, evidence=evidence, confidence=confidence,
                reason="Matched the YARA signature '%s'%s." % (
                    match.rule.name, " from " + match.rule.source if match.rule.source else ""),
                handler=handler, chainable=category is not C.SIGNATURE, tags=("yara",),
                context={"language": "yara"}))
        return out

    def add(self, rule: Rule) -> None:
        self.rules.append(rule)
        self._by_lang.clear()

    def rules_for(self, language: str) -> List[Rule]:
        if language not in self._by_lang:
            self._by_lang[language] = [r for r in self.rules if language in r.languages]
        return self._by_lang[language]

    def scan(self, text: str, language: str, ctx: FileContext, handler: str = "",
             comment_style: Optional[str] = None, numbered: bool = True,
             quoted: bool = False) -> List[Finding]:
        """Match every rule for ``language``.

        ``numbered=False`` is for strings extracted from binaries: no line
        numbers, and identical matches are reported once. ``quoted``: the text is
        JavaScript source - a match of a call-site rule (tag ``CALL``) that begins
        inside quoted text is marked (``IN_TEXT``; :class:`QuotedText`) and counted
        like a match inside a comment.
        """
        rules = self.rules_for(language)
        if not rules or not text:
            return []
        code = mask_comments(text, comment_style)
        starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        lowered = text.lower()                   # for the literal prefilter
        out: List[Finding] = []
        # Packed code (phageo, 2026-10-12): in a line of thousands of characters "the same line"
        # says nothing about what belongs together. Such a line is cut into its statements,
        # and a finding in it knows which statement it stands in (ChainEngine: PACKED).
        packed = _packed_lines(starts, len(text)) if numbered else {}
        cuts = _statement_cuts(code) if packed else []
        if packed:
            ctx.cache.setdefault(PACKED, set()).update(line + 1 for line in packed)
        places = _Places(text, lowered)
        texts: Optional[QuotedText] = None           # (read when the first call-site rule matches)
        for rule in rules:
            if rule.needles is not None and not places.has(rule.needles):
                continue                         # a required literal is absent: cannot match
            # (tried only where a match can begin, when that is known - the same matches)
            found = places.matches(rule) if rule.starts is not None else None
            if found is None:
                found = itertools.islice(rule.regex.finditer(text), _MAX_MATCHES)
            hits = [m for m in found if m.end() > m.start()]
            if len(hits) < rule.min_hits:
                continue
            # The per-file limit (rule.max_per_file) is NOT applied here. Which
            # hits are false positives is only known after the ContextEngine has
            # looked at them, so limiting first would let a few harmless-looking
            # matches use up the budget and hide a dangerous one behind them.
            # See prune(), which runs after evaluation.
            kept = kept_comment = 0
            seen = set()
            if quoted and texts is None and CALL in rule.tags:
                texts = quoted_text(code)
            for m in hits:
                matched = m.group(0)
                in_comment = code[m.start():m.end()] != matched
                in_text = (quoted and not in_comment and CALL in rule.tags
                           and rule.severity < S.CRITICAL and texts.holds(m.start()))
                if not numbered:
                    if matched.lower() in seen:
                        continue
                    seen.add(matched.lower())
                if in_comment or in_text:
                    if kept_comment >= _KEEP_SUPPRESSED:
                        continue
                    kept_comment += 1
                elif kept >= _KEEP:
                    break
                else:
                    kept += 1
                f = self._finding(rule, m, text, code, starts, language, ctx, handler,
                                  in_comment, numbered)
                if in_text:
                    f.context[IN_TEXT] = True
                if packed and f.line is not None and f.line - 1 in packed:
                    f.context[STATEMENT] = bisect.bisect_right(cuts, m.start())
                if rule.min_hits > 1:
                    f.evidence = "%d occurrences, e.g. %s" % (len(hits), f.evidence)
                out.append(f)
        return out

    @staticmethod
    def prune(findings: List[Finding]) -> List[Finding]:
        """Apply the per-rule report limits *after* false-positive evaluation.

        Per rule: at most ``max_per_file`` active findings and a couple of
        suppressed ones are kept; the first active one notes how many more
        there were. Findings without a limit (structural, chains) pass through.
        """
        active: Dict[str, int] = {}
        quiet: Dict[str, int] = {}
        first: Dict[str, Finding] = {}
        extra: Dict[str, int] = {}
        out: List[Finding] = []
        for f in findings:
            cap = f.context.get("cap")
            if cap is None:
                out.append(f)
            elif f.suppressed:
                if quiet.get(f.rule_id, 0) < _KEEP_SUPPRESSED:
                    quiet[f.rule_id] = quiet.get(f.rule_id, 0) + 1
                    out.append(f)
            elif active.get(f.rule_id, 0) < cap:
                active[f.rule_id] = active.get(f.rule_id, 0) + 1
                first.setdefault(f.rule_id, f)
                out.append(f)
            else:
                extra[f.rule_id] = extra.get(f.rule_id, 0) + 1
        for rule_id, count in extra.items():
            first[rule_id].evidence += "  (+%d more match(es) in this file)" % count
        return out

    @staticmethod
    def _finding(rule: Rule, m: "re.Match[str]", text: str, code: str, starts: List[int],
                 language: str, ctx: FileContext, handler: str, in_comment: bool,
                 numbered: bool) -> Finding:
        idx = bisect.bisect_right(starts, m.start()) - 1
        line_end = starts[idx + 1] - 1 if idx + 1 < len(starts) else len(text)
        # keep context bounded even on megabyte-long minified lines
        lo = max(starts[idx], m.start() - 300)
        hi = min(line_end, m.end() + 300)
        line_text = text[lo:hi]
        s_lo = max(starts[idx], m.start() - 90)
        s_hi = min(line_end, m.start() + 150)
        snippet = text[s_lo:s_hi].strip()
        if s_lo > starts[idx]:
            snippet = "..." + snippet
        if s_hi < line_end:
            snippet += "..."
        if numbered:
            w_lo = starts[max(0, idx - 3)]
            w_idx = min(len(starts) - 1, idx + 3)
            w_hi = starts[w_idx + 1] if w_idx + 1 < len(starts) else len(text)
            w_lo, w_hi = max(w_lo, m.start() - 600), min(w_hi, m.end() + 600)
        else:
            w_lo, w_hi = lo, hi
        window = text[w_lo:w_hi]
        matched = m.group(0)
        return Finding(
            rule_id=rule.id, title=rule.title, category=rule.category,
            severity=rule.severity, file=ctx.relpath,
            line=idx + 1 if numbered else None, snippet=snippet,
            evidence=matched if len(matched) <= 120 else matched[:117] + "...",
            confidence=rule.confidence, reason=rule.reason, handler=handler,
            chainable=rule.chainable, tags=rule.tags,
            # code_line / code_window are the same text with comments blanked:
            # false-positive decisions must not be steerable by comment text
            context={"in_comment": in_comment, "match": matched, "cap": rule.max_per_file,
                     "line_text": line_text, "window": window, "language": language,
                     "code_line": code[lo:hi], "code_window": code[w_lo:w_hi],
                     # is code_line the whole line, and where does it start in code_window
                     "whole_line": numbered and lo == starts[idx] and hi == line_end,
                     "line_at": lo - w_lo},
        )
