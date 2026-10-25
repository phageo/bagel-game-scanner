"""The shipped form of a module: its source without comments and docstrings.

(phageo, 2026-10-24, antivirus false positives, second test build.) ``tools/build_package.py``
ships every ``.py`` file in this form; the project's source stays as it is. Comments are found
with ``tokenize``, docstrings with ``ast`` (both only read the text; nothing is run). A module
docstring is removed, a class or function docstring becomes ``pass``. A module that names
``__doc__`` keeps its docstrings (none does in 0.9).

The result is proven, not trusted: its syntax tree must equal the original's with the
docstrings taken out in the same way - otherwise :class:`FormError` and nothing is shipped.
The package's code is then not byte for byte the project's, so the builder writes the
project's ``known_findings.fingerprint`` into it (``known_findings.SHIPPED_PRINT``): the kept
readings stay current there. Development tool only, never shipped.
"""
from __future__ import annotations

import ast
import io
import tokenize
from typing import Dict, List, Tuple


class FormError(ValueError):
    """The stripped module would not be the same code."""


def _docstrings(tree: ast.Module) -> List[Tuple[ast.AST, ast.Expr]]:
    """``(owner, statement)`` of every docstring."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                out.append((node, first))
    return out


def _expected(text: str, keep: bool) -> str:
    """The dump of the original tree with its docstrings taken out as :func:`strip` does."""
    tree = ast.parse(text)
    if not keep:
        for owner, statement in _docstrings(tree):
            if isinstance(owner, ast.Module):
                owner.body.remove(statement)
            else:
                owner.body[0] = ast.Pass()
    return ast.dump(tree)


def strip(source: bytes) -> bytes:
    """``source`` (UTF-8) without comments and docstrings; line ends as they were."""
    bom = b"\xef\xbb\xbf" if source.startswith(b"\xef\xbb\xbf") else b""
    text = source[len(bom):].decode("utf-8")
    keep = "__doc__" in text
    lines = text.splitlines(True)
    # (line index, first char, end char, replacement); columns in characters
    edits: List[Tuple[int, int, int, str]] = []
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type == tokenize.COMMENT:
            row, col = token.start
            edits.append((row - 1, col, col + len(token.string), ""))
    if not keep:
        for owner, statement in _docstrings(ast.parse(text)):
            first, last = statement.lineno - 1, statement.end_lineno - 1
            start = len(lines[first].encode("utf-8")[:statement.col_offset].decode("utf-8"))
            end = len(lines[last].encode("utf-8")[:statement.end_col_offset].decode("utf-8"))
            word = "" if isinstance(owner, ast.Module) else "pass"
            if first == last:
                edits.append((first, start, end, word))
            else:
                edits.append((first, start, len(lines[first].rstrip("\r\n")), word))
                for row in range(first + 1, last):
                    edits.append((row, 0, len(lines[row].rstrip("\r\n")), ""))
                edits.append((last, 0, end, ""))
    touched: Dict[int, bool] = {}
    for row, start, end, word in sorted(edits, reverse=True):
        line = lines[row]
        lines[row] = line[:start] + word + line[end:]
        touched[row] = True
    out = []
    for row, line in enumerate(lines):
        if touched.get(row):
            body = line.rstrip("\r\n")
            ending = line[len(body):]
            body = body.rstrip()
            if not body.strip():
                continue                                # a line that held only a comment or doc
            line = body + ending
        out.append(line)
    result = "".join(out)
    if ast.dump(ast.parse(result)) != _expected(text, keep):
        raise FormError("the stripped module is not the same code")
    return bom + result.encode("utf-8")
