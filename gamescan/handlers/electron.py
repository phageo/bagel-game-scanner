"""Electron games: ``app.asar`` and compiled JavaScript (``.jsc``).

An Electron game is a browser engine plus the game's own code, and that code
sits in ``resources/app.asar`` (:mod:`gamescan.unpack.asar`). Until 2026-10-12
the scanner did not open it: the one file that holds what the game does came
out without a finding and without a note.

* ``app.asar`` is opened as the archive it is; its members are scanned like any
  other file - its JavaScript by the JavaScript reader, with the
  download-and-run chain, its programs (``.node`` libraries are programs) by
  the program reader. It makes no difference whether the archive lies in a
  folder or inside the ``app-64.7z`` of an installer.
* What cannot be read is said (CLAUDE.md, rule 15) - ``ARC-002``, never hidden,
  the launcher asks: an archive that is encrypted, of an unknown layout or
  damaged; a member that is cut short or over the size limit; a script member
  that is not text (encrypted by one of the tools that do that).
* A ``.jsc`` file is JavaScript compiled by V8 (the "bytenode" tool): machine
  code of V8's own, different for every version, which the scanner does not
  read. It gets ``JSC-FMT-001`` - in a folder and inside an archive alike.
"""
from __future__ import annotations

import io
from typing import Iterable, List

from .. import cache
from ..models import NOT_INSPECTED, Category, FileContext, Finding, Severity
from ..rules import RuleEngine
from ..unpack import asar, spool
from . import containers
from .base import BaseHandler
from .text import is_text

COMPILED = "JSC-FMT-001"
_SCRIPTS = frozenset({".js", ".mjs", ".cjs", ".json", ".html", ".htm"})
_MAX_NOTES = 5


class ElectronHandler(BaseHandler):
    name = "electron"
    engine = "Electron"
    extensions = frozenset({".asar", ".jsc"})
    streamed = frozenset({".asar"})
    markers = (r"(^|[/!])resources/(?:app|electron)\.asar$", r"(^|[/!])app\.asar$")

    @staticmethod
    def _stream(ctx: FileContext):
        # a large archive is only partly in memory: read it from disk instead
        return open(ctx.path, "rb") if ctx.truncated and ctx.on_disk else io.BytesIO(ctx.data)

    def _entries(self, ctx: FileContext):
        """The archive's files (cached), or the text that says why they cannot be read."""
        if "asar" not in ctx.cache:
            try:
                with self._stream(ctx) as stream:
                    # (the list of files, kept by the archive's SHA-256 - gamescan/cache.py)
                    ctx.cache["asar"] = cache.kept(
                        "asar-index", ctx.sha256, "gamescan.unpack.asar", lambda: asar.entries(stream),
                        extra=str(ctx.size), encode=lambda found: [list(entry) for entry in found],
                        decode=lambda plain: [asar.Entry(str(n), int(s), int(o), bool(u)) for n, s, o, u in plain])
            except (asar.AsarError, OSError) as exc:
                ctx.cache["asar"] = str(exc) or type(exc).__name__
        return ctx.cache["asar"]

    def _note(self, ctx: FileContext, what: str) -> Finding:
        note = self.make(ctx, "ARC-002", "Archive could not be fully inspected", Category.EVASION,
                         Severity.LOW, NOT_INSPECTED, what[:300], 0.3)
        note.chainable = False
        return note

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        if ctx.ext == ".jsc":
            note = self.make(
                ctx, COMPILED, "Compiled JavaScript could not be read", Category.OBFUSCATION, Severity.LOW,
                "This file is JavaScript compiled by the V8 engine (the form the \"bytenode\" tool writes): "
                "not text, but V8's own instructions, which differ from version to version. The scanner "
                "does not read them, so what this code does was not inspected. Games use it to hide "
                "their source; malware uses it for the same reason.",
                "%s: compiled JavaScript (V8), %d KB - not read" % (ctx.name, ctx.size // 1024), 0.3)
            note.chainable = False
            return [note]
        listed = self._entries(ctx)
        if isinstance(listed, str):
            return [self._note(ctx, "app.asar: %s - its files were not read" % listed)]
        return []                                       # the members are scanned through expand()

    def expand(self, ctx: FileContext) -> Iterable[FileContext]:
        if ctx.ext != ".asar":
            return
        listed = self._entries(ctx)
        if isinstance(listed, str):
            return
        notes: List[str] = ctx.cache.setdefault("asar_notes", [])
        policy = containers.Policy()
        scrambled = 0
        try:
            with self._stream(ctx) as stream:
                for entry in listed:
                    if entry.unpacked:                  # lies beside the archive: scanned there
                        continue
                    ending = containers.ext_of(entry.name)
                    if not policy.want(entry.name, entry.size):
                        continue
                    try:
                        data = asar.read(stream, entry)
                    except (asar.AsarError, spool.SpoolError, OSError) as exc:
                        notes.append("%s: %s" % (entry.name[-120:], exc))
                        continue
                    head = spool.head_of(data)
                    if ending not in _SCRIPTS and not policy.settle(entry.name, data):
                        if isinstance(data, spool.Blob):
                            data.release()
                        continue
                    if ending in _SCRIPTS and head and not is_text(head):
                        # a script that is not text: scrambled by a tool that encrypts the
                        # files of an asar. It is still handed on (what can be read is read).
                        scrambled += 1
                        if scrambled == 1:
                            notes.append("%s: a script that is not text (encrypted or compiled) - not read"
                                         % entry.name[-120:])
                    yield containers.child(ctx, entry.name, data)
        except OSError as exc:
            notes.append("the archive could not be read to its end (%s)" % type(exc).__name__)
        if scrambled > 1:
            notes.append("%d more scripts that are not text were not read" % (scrambled - 1))
        notes.extend(policy.problems())

    def after_expand(self, ctx: FileContext) -> List[Finding]:
        return [self._note(ctx, "app.asar: " + note) for note in ctx.cache.pop("asar_notes", [])[:_MAX_NOTES]]
