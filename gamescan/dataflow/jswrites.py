"""Node.js file writes that only put a data file into the game's own folder.

RPG Maker MV / MZ plugins write small data files next to the game - an index
of the cursor images, a settings file. ``fs.writeFile(...)`` alone says
nothing about that, so every such call is MEDIUM. :func:`data_writes` picks
out the calls of which three things can be read from the file itself:

``the place``  the path starts from the game's own folder
               (``process.mainModule.filename``, ``location.pathname``,
               ``__dirname``, ``localFileDirectoryPath()``) and nothing that
               leads elsewhere takes part in building it (the user's profile,
               the environment, a drive, ``..``)
``the kind``   the file name ends in a data extension, written out as text
``the name``   it is not - and cannot be the end of - a file the engine reads
               as code or configuration: ``package.json`` (NW.js takes its
               start-up settings from it), ``plugins.js``, and RPG Maker's
               data files, whose event commands, formulas and notes are run
               or evaluated (``Map001.json``, ``CommonEvents.json``,
               ``Troops.json``, ``Skills.json`` ...)

It reads text, not a syntax tree: names are followed by name through the
whole file, and *every* assignment to a name has to qualify - so a same-named
variable in another function can only make a call not qualify. Nothing is
executed.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

MAX_SOURCE = 32 * 1024 * 1024        # as textflow.JS_MAX_SOURCE (phageo, 2026-10-14)
_MAX_SITES = 400
_MAX_ARGUMENT = 600

# every file operation the JS-FS-001 rule reports
_SITE = re.compile(r"""fs\.(unlink|rmdir|rm|writeFile|appendFile|rename|copyFile)(Sync)?\s*\(|"""
                   r"""require\s*\(\s*['"]rimraf['"]\s*\)""")
_WRITES = frozenset({"writeFile", "appendFile"})
DATA_EXTENSIONS = (".json", ".txt", ".csv", ".log", ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".ogg",
                   ".m4a", ".wav")
# files the engine reads as code or configuration, whatever folder they are in
_ENGINE_FILES = ("package.json", "plugins.js", "actors.json", "classes.json", "skills.json", "items.json",
                 "weapons.json", "armors.json", "enemies.json", "troops.json", "states.json",
                 "animations.json", "tilesets.json", "commonevents.json", "system.json", "mapinfos.json",
                 "manifest.json", "config.json", "nw.json")
_MAP_FILE = re.compile(r"map\d+\.json")
_MAP_TAIL = re.compile(r"(?:(?:m?a)?p)?\d*\.json")       # how the name of a map file can end
_OWN_FOLDER = re.compile(r"process\.mainModule\.filename|(?<![\w$.])(?:window\.)?location\.pathname"
                         r"|(?<![\w$.])__dirname|localFileDirectoryPath\s*\(")
_LEADS_ELSEWHERE = re.compile(
    r"process\.env|homedir|tmpdir|\bos\.|\.\.|[A-Za-z]:[\\/]|argv|dataPath|getPath|USERPROFILE|APPDATA"
    r"|\bTEMP\b|\bHOME\b|require\s*\(|\\\\\\\\", re.I)
_REWRITE_WORDS = frozenset("decodeURIComponent decodeURI slice substring substr replace trim normalize "
                           "length".split())
_NAME = r"(?:this\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,3}"
_LITERAL = re.compile(r"""\s*(['"])((?:\\.|(?!\1)[^\\\n])*)\1\s*""")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _first_argument(text: str, start: int) -> Optional[str]:
    """The text of the first argument of the call whose ``(`` ends at ``start``."""
    depth, quote, i = 0, "", start
    end = min(len(text), start + _MAX_ARGUMENT)
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[start:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return text[start:i]
        i += 1
    return None


def _terms(expression: str) -> Optional[List[str]]:
    """The parts of ``a + b + c`` (None: something else than ``+`` joins them)."""
    out, depth, quote, current = [], 0, "", []
    for index, ch in enumerate(expression):
        if quote:
            current.append(ch)
            if ch == quote and expression[index - 1] != "\\":
                quote = ""
        elif ch in "\"'`":
            quote = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "+" and depth == 0:
            out.append("".join(current).strip())
            current = []
        elif ch in "?:|&<>=*/%-!~^" and depth == 0:
            return None                      # a condition or another operator: not followed
        else:
            current.append(ch)
    out.append("".join(current).strip())
    return out if all(out) and "`" not in expression else None


def _assignments(text: str, name: str) -> List[str]:
    """What ``name`` is set to anywhere in the file (a property is followed by
    its last name: ``$._indexFilename = ...`` sets ``this._indexFilename``)."""
    if "." in name:
        pattern = r"\." + re.escape(name.rsplit(".", 1)[-1]) + r"\s*=(?!=)\s*([^;]{1,400})"
    else:
        pattern = r"(?<![\w$.])" + re.escape(name) + r"\s*=(?!=)\s*([^;]{1,400})"
    return [m.group(1).strip() for m in re.finditer(pattern, text)][:40]


def _literal(term: str) -> Optional[str]:
    m = _LITERAL.fullmatch(term)
    return None if m is None or "\\" in m.group(2) else m.group(2)


def _file_name(text: str, term: str) -> Optional[str]:
    """The written-out text the path ends with (None: it is not written out)."""
    value = _literal(term)
    if value is not None:
        return value
    if not re.fullmatch(_NAME, term):
        return None
    values = [_literal(v) for v in _assignments(text, term)]
    if not values or any(v is None for v in values) or len(set(values)) != 1:
        return None
    return values[0]


def _in_own_folder(text: str, term: str, depth: int = 0) -> bool:
    """Does this part of a path start in the game's own folder, with nothing
    in it that leads elsewhere?"""
    if _LEADS_ELSEWHERE.search(term):
        return False
    if _OWN_FOLDER.search(term):
        return True
    if depth >= 3 or not re.fullmatch(_NAME, term):
        return False
    values = _assignments(text, term)
    rooted = False
    for value in values:
        if _LEADS_ELSEWHERE.search(value):
            return False
        if _OWN_FOLDER.search(value):
            rooted = True
        elif re.search(r"(?<![\w$.])" + re.escape(term) + r"(?![\w$])", value):
            others = set(re.findall(r"[A-Za-z_$][\w$]*", _LITERAL.sub(" ", value))) - {term.split(".")[-1]}
            if not others <= _REWRITE_WORDS | set(term.split(".")):
                return False                 # rewritten with something that was not followed
        elif not _in_own_folder(text, value, depth + 1):
            return False
        else:
            rooted = True
    return rooted


def engine_file(name: str) -> bool:
    """Is ``name`` (the written-out end of a path) a file the engine reads as
    code or configuration - or could it be the end of the name of one?"""
    name = name.replace("\\", "/").lower()
    leaf = name.rsplit("/", 1)[-1]
    if "/" in name:                          # the whole file name is known
        return leaf in _ENGINE_FILES or _MAP_FILE.fullmatch(leaf) is not None
    return (not leaf or any(known.endswith(leaf) for known in _ENGINE_FILES)
            or _MAP_TAIL.fullmatch(leaf) is not None)


def data_writes(text: str) -> Dict[int, str]:
    """``{line: file name}`` for the lines whose every file operation is a
    write of a data file into the game's own folder (see the module text).
    Never raises."""
    out: Dict[int, str] = {}
    refused = set()
    if not text or len(text) > MAX_SOURCE or "fs." not in text:
        return out
    try:
        for count, m in enumerate(_SITE.finditer(text)):
            line = _line(text, m.start())
            name = None
            if count < _MAX_SITES and m.group(1) in _WRITES:
                argument = _first_argument(text, m.end())
                terms = _terms(argument) if argument is not None else None
                if terms and len(terms) >= 2:
                    ending = _file_name(text, terms[-1])
                    if (ending is not None and ending.lower().endswith(DATA_EXTENSIONS)
                            and not _LEADS_ELSEWHERE.search(ending) and not engine_file(ending)
                            and _in_own_folder(text, terms[0])
                            and all(_literal(t) is not None and not _LEADS_ELSEWHERE.search(t)
                                    or _in_own_folder(text, t) for t in terms[1:-1])):
                        name = ending
            if name is None:
                refused.add(line)
            else:
                out[line] = name
    except (RecursionError, re.error, IndexError):
        return {}
    return {line: name for line, name in out.items() if line not in refused}
