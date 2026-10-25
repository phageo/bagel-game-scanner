"""Move the scanner's indicator strings out of its modules' text into ``gamescan/indicators.bin``.

    python tools/move_indicators.py                   move: every shipped module, then write the file
    python tools/move_indicators.py --check           plain indicator literals left (exit 1 if any)
    python tools/move_indicators.py --count ZIP       per file of app/ in a package zip: matches per kind
    python tools/move_indicators.py --show MODULE     a module's moved strings with their numbers
    python tools/move_indicators.py --select-from F   (once) store the selection patterns of F

(phageo, 2026-10-24, antivirus false positives; ``gamescan/indicators.py`` says why.) Development
tool only, never shipped.

- **Which strings:** a string or bytes literal of a shipped module (``build_package.app_files``)
  whose value or source text matches one of the selection patterns. The patterns themselves are
  kept in ``tools/indicator_select.bin`` (the same compressed form), by kind; ``--select-from``
  takes them once from a Python file that holds a dict ``KINDS = {kind: pattern}``.
- **Never moved:** docstrings, parts of f-strings, annotations, ``match`` patterns - they are
  counted as left by ``--check``.
- **How:** the literal's exact source text is replaced by ``_IND[n]``; two lines after the
  module's ``from __future__`` import (or its docstring) load ``_IND``. A module moved before
  keeps its numbers; new strings are appended. Nothing else of the file changes.
- **Proof, before anything is written:** the new module is compiled, and its syntax tree with
  every ``_IND[n]`` put back as the string ``n`` equals the old module's tree. One difference
  stops the tool and writes nothing.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
import zipfile
from typing import Dict, List, Optional, Tuple, Union

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import build_package                                     # noqa: E402
from gamescan import indicators                          # noqa: E402

SELECT = os.path.join(HERE, "indicator_select.bin")
# (``from ..indicators import strings``: a module imports the loader only - ``from .. import x``
# would count as importing the whole package for ``cache.source_hash``)
NAME, LOADER = "_IND", "_indicator_strings"
# the loader itself; lz4block.py also runs as a plain script (its worker processes), where a
# relative import cannot work - what it holds is counted by --count like any file
NOT_MOVED = ("app/gamescan/indicators.py", "app/gamescan/unpack/lz4block.py")
Value = Union[str, bytes]


class MoveError(Exception):
    pass


# -- the selection patterns ----------------------------------------------------------------------
def kinds() -> List[Tuple[str, "re.Pattern[bytes]"]]:
    """``[(kind, pattern)]`` from ``tools/indicator_select.bin``."""
    if not os.path.exists(SELECT):
        raise MoveError("no selection patterns yet: run once with --select-from <file>")
    with open(SELECT, "rb") as fh:
        rows = indicators.decode(fh.read()).get("select", ())
    out = []
    for row in rows:
        kind, _tab, pattern = str(row).partition("\t")
        out.append((kind, re.compile(pattern.encode("utf-8"), re.IGNORECASE)))
    return out


def store_selection(source: str) -> int:
    """Take ``KINDS = {kind: pattern}`` of a Python file (read as data, never run)."""
    with open(source, "rb") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "KINDS" for t in node.targets):
            table = ast.literal_eval(node.value)
            break
    else:
        raise MoveError("no KINDS = {...} in " + source)
    rows = tuple("%s\t%s" % (k, v) for k, v in table.items())
    for row in rows:
        re.compile(row.partition("\t")[2])
    with open(SELECT, "wb") as fh:
        fh.write(indicators.encode({"select": rows}))
    return len(rows)


def matches(data: bytes, patterns) -> Dict[str, int]:
    return {kind: len(p.findall(data)) for kind, p in patterns}


# -- what may be moved ---------------------------------------------------------------------------
def _docstrings(tree: ast.AST) -> set:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                out.add(id(first.value))
    return out


def _fixed(tree: ast.AST) -> set:
    """Literals that must stay literals: inside f-strings, annotations and match patterns."""
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            roots.append(node)
        elif isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
        elif hasattr(ast, "match_case") and isinstance(node, getattr(ast, "match_case")):
            roots.append(node.pattern)
    return {id(n) for root in roots for n in ast.walk(root)}


def literals(tree: ast.AST) -> Tuple[List[ast.Constant], List[ast.Constant]]:
    """``(movable, kept)``: the string / bytes literals of a module."""
    docs, fixed = _docstrings(tree), _fixed(tree)
    movable, kept = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            (kept if id(node) in docs or id(node) in fixed else movable).append(node)
    return movable, kept


# -- one module ----------------------------------------------------------------------------------
def module_key(package_name: str) -> str:
    """The name a module's strings are kept under: its name in the package below ``app/``."""
    return package_name[len("app/"):]


def _import_line(key: str) -> str:
    if not key.startswith("gamescan/"):
        raise MoveError("only modules of gamescan/ can load their strings: " + key)
    # (in a package's __init__.py "." is that package too: one dot per folder below gamescan/)
    return "from %sindicators import strings as %s" % ("." * key.count("/"), LOADER)


def _offsets(raw: bytes) -> List[int]:
    starts, at = [0], 0
    for line in raw.split(b"\n")[:-1]:
        at += len(line) + 1
        starts.append(at)
    return starts


def _ours(node: ast.stmt) -> bool:
    """Is ``node`` one of the two lines that load ``_IND``?"""
    if isinstance(node, ast.ImportFrom):
        return node.module == "indicators" and any(a.name == "strings" and a.asname == LOADER
                                                   for a in node.names)
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        call = node.value
        return node.targets[0].id == NAME and isinstance(call, ast.Call) \
            and isinstance(call.func, ast.Name) and call.func.id == LOADER
    return False


def selected(body: bytes, nodes: List[ast.Constant], patterns) -> List[Tuple[int, int, Value]]:
    """``(begin, end, value)`` of the literals whose value or source text matches a pattern."""
    starts = _offsets(body)
    out = []
    for node in nodes:
        begin = starts[node.lineno - 1] + node.col_offset
        end = starts[node.end_lineno - 1] + node.end_col_offset
        value = node.value
        text = value.encode("utf-8") if isinstance(value, str) else value
        if any(p.search(text) or p.search(body[begin:end]) for _k, p in patterns):
            out.append((begin, end, value))
    return out


def resolved(tree: ast.Module, table: Tuple[Value, ...]) -> str:
    """The dump of ``tree`` without the loading lines and with every ``_IND[n]`` as its string."""

    class Put(ast.NodeTransformer):
        def visit_Subscript(self, node):
            self.generic_visit(node)
            if isinstance(node.value, ast.Name) and node.value.id == NAME \
                    and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                return ast.Constant(value=table[node.slice.value])
            return node

    tree = Put().visit(tree)
    tree.body = [s for s in tree.body if not _ours(s)]
    return ast.dump(tree)


def move(raw: bytes, key: str, table: Tuple[Value, ...], patterns) -> Tuple[bytes, Tuple[Value, ...], int]:
    """``(new source, new table, strings moved now)`` of one module's source ``raw``."""
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    body = raw[len(bom):]
    tree = ast.parse(body)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    loaded = any(_ours(s) for s in tree.body)
    if not loaded and (NAME in names or LOADER in names):
        raise MoveError("%s already uses the name %s or %s" % (key, NAME, LOADER))
    chosen = selected(body, literals(tree)[0], patterns)
    if not chosen:
        return raw, table, 0
    values = list(table)
    index = {(type(v), v): i for i, v in enumerate(values)}
    pieces, at = [], 0
    for begin, end, value in sorted(chosen):
        slot = index.get((type(value), value))
        if slot is None:
            slot = index[(type(value), value)] = len(values)
            values.append(value)
        pieces += [body[at:begin], ("%s[%d]" % (NAME, slot)).encode("ascii")]
        at = end
    pieces.append(body[at:])
    new = b"".join(pieces)
    if not loaded:
        newline = b"\r\n" if b"\r\n" in body else b"\n"
        anchor = None
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__":
                anchor = stmt
        if anchor is None and tree.body and isinstance(tree.body[0], ast.Expr) \
                and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
            anchor = tree.body[0]
        cut = 0 if anchor is None else _offsets(new)[anchor.end_lineno]
        lines = (_import_line(key) + "   # strings as data: indicators.py\n" +
                 '%s = %s("%s")\n' % (NAME, LOADER, key)).encode("ascii").replace(b"\n", newline)
        new = new[:cut] + lines + new[cut:]
    table = tuple(values)
    compile(new, key, "exec")                               # (our own code, never a scanned file)
    if resolved(ast.parse(new), table) != resolved(tree, tuple(table)):
        raise MoveError("%s: the moved module is not the same code - nothing written" % key)
    return bom + new, table, len(chosen)


# -- the runs ------------------------------------------------------------------------------------
def shipped_modules() -> List[Tuple[str, str]]:
    return [(name, path) for name, path in build_package.app_files()
            if name.endswith((".py", ".pyw")) and name not in NOT_MOVED]


def current() -> Dict[str, Tuple[Value, ...]]:
    path = indicators.path()
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as fh:
        return indicators.decode(fh.read())


def run_move(say=print) -> int:
    patterns = kinds()
    tables = current()
    staged, moved = {}, 0
    for name, path in shipped_modules():
        key = module_key(name)
        with open(path, "rb") as fh:
            raw = fh.read()
        new, table, count = move(raw, key, tables.get(key, ()), patterns)
        if count:
            staged[path] = new
            tables[key] = table
            moved += count
            say("%-44s %4d literal(s) -> %d string(s)" % (key, count, len(table)))
    if not staged:
        say("nothing to move")
        return 0
    data = indicators.encode(dict(sorted(tables.items())))
    if indicators.decode(data) != dict(sorted(tables.items())):
        raise MoveError("the indicator file does not read back the same - nothing written")
    with open(indicators.path(), "wb") as fh:
        fh.write(data)
    for path, new in staged.items():
        with open(path, "wb") as fh:
            fh.write(new)
    say("moved %d literal(s) in %d module(s); %s: %d bytes, %d string(s)" % (
        moved, len(staged), indicators.FILE, len(data), sum(len(t) for t in tables.values())))
    return 0


def left_in(files: Dict[str, bytes], patterns=None) -> List[str]:
    """Package names of the modules among ``files`` (``{name: bytes}``) that still hold an
    indicator literal outside docstrings, f-strings and annotations (``build_package`` refuses)."""
    patterns = kinds() if patterns is None else patterns
    out = []
    for name, raw in sorted(files.items()):
        if name.startswith("app/") and name.endswith((".py", ".pyw")) and name not in NOT_MOVED:
            body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
            if selected(body, literals(ast.parse(body))[0], patterns):
                out.append(name)
    return out


def run_check(say=print) -> int:
    patterns = kinds()
    left = kept = 0
    for name, path in shipped_modules():
        with open(path, "rb") as fh:
            raw = fh.read()
        body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
        movable, fixed = literals(ast.parse(body))
        left += len(selected(body, movable, patterns))
        kept += len(selected(body, fixed, patterns))
    say("indicator literals left in the modules' text: %d; in docstrings / f-strings / annotations: %d"
        % (left, kept))
    return 1 if left else 0


def run_count(zip_path: str, say=print) -> int:
    patterns = kinds()
    totals = {k: 0 for k, _p in patterns}
    rows = []
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.split("/", 1)[-1]
            if not name.startswith("app/") or info.is_dir():
                continue
            found = matches(z.read(info.filename), patterns)
            for k, v in found.items():
                totals[k] += v
            if any(found.values()):
                rows.append((sum(found.values()), name, found))
    say("app files with a match: %d; matches per kind: %s" % (
        len(rows), ", ".join("%s %d" % kv for kv in totals.items())))
    for _total, name, found in sorted(rows, key=lambda r: (-r[0], r[1])):
        say("  %-46s %s" % (name[len("app/"):], " ".join("%s=%d" % kv for kv in found.items() if kv[1])))
    return 0


def run_show(module: str, say=print) -> int:
    for i, value in enumerate(current().get(module, ())):
        say("%4d  %r" % (i, value))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true")
    group.add_argument("--count", metavar="ZIP")
    group.add_argument("--show", metavar="MODULE")
    group.add_argument("--select-from", metavar="FILE")
    args = ap.parse_args(argv)
    try:
        if args.select_from:
            print("selection patterns stored: %d" % store_selection(args.select_from))
            return 0
        if args.check:
            return run_check()
        if args.count:
            return run_count(args.count)
        if args.show:
            return run_show(args.show)
        return run_move()
    except (MoveError, indicators.IndicatorError, OSError, SyntaxError) as exc:
        print("STOPPED: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
