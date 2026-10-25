"""File isolation: move a threat out of the game and neutralise it.

A quarantined file is stored under ``~/.game_safety_scanner/quarantine`` with
its bytes XOR-scrambled and a ``.quar`` extension, so it cannot be run by
accident and is not re-detected in place. Nothing is ever deleted unless the
user asks; every entry can be restored to its original location.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Iterable, List, Optional

_KEY = 0xA5
_TABLE = bytes(b ^ _KEY for b in range(256))


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, directory: Optional[str] = None) -> None:
        self.directory = directory or os.path.join(
            os.path.expanduser("~"), ".game_safety_scanner", "quarantine")
        self._index = os.path.join(self.directory, "index.json")

    # -- manifest ----------------------------------------------------------------
    def list(self) -> List[Dict[str, Any]]:
        try:
            with open(self._index, "r", encoding="utf-8") as fh:
                return list(json.load(fh))
        except (OSError, ValueError):
            return []

    def _write(self, entries: List[Dict[str, Any]]) -> None:
        os.makedirs(self.directory, exist_ok=True)
        with open(self._index, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)

    def _entry(self, entry_id: str) -> Dict[str, Any]:
        for entry in self.list():
            if entry.get("id") == entry_id:
                # the index is a plain file: never follow a "stored" path that
                # points outside the quarantine folder (restore reads it,
                # delete removes it)
                stored = os.path.abspath(str(entry.get("stored", "")))
                inside = os.path.normcase(os.path.dirname(stored)) == \
                    os.path.normcase(os.path.abspath(self.directory))
                if not inside or not stored.lower().endswith(".quar") or not entry.get("original"):
                    raise QuarantineError("the quarantine index entry is damaged: %s" % entry_id)
                return entry
        raise QuarantineError("no such quarantine entry: %s" % entry_id)

    @staticmethod
    def _copy(src: str, dst: str) -> str:
        """Copy ``src`` to ``dst`` XOR-scrambled; returns the SHA-256 of the *input*."""
        digest = hashlib.sha256()
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                block = fin.read(1 << 20)
                if not block:
                    break
                digest.update(block)
                fout.write(block.translate(_TABLE))
        return digest.hexdigest()

    # -- operations --------------------------------------------------------------
    def isolate(self, path: str, reasons: Iterable[str] = (), severity: str = "") -> Dict[str, Any]:
        """Move ``path`` into quarantine and return its manifest entry."""
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise QuarantineError("not a file: %s" % path)
        os.makedirs(self.directory, exist_ok=True)
        entry_id = "%d-%s" % (time.time() * 1000, hashlib.sha256(path.encode("utf-8")).hexdigest()[:8])
        stored = os.path.join(self.directory, entry_id + ".quar")
        try:
            sha256 = self._copy(path, stored)
            os.remove(path)
        except OSError as exc:
            if os.path.exists(stored):
                os.remove(stored)                # all or nothing: leave the game untouched
            raise QuarantineError("could not isolate %s: %s" % (path, exc))
        entry = {"id": entry_id, "original": path, "stored": stored, "sha256": sha256,
                 "size": os.path.getsize(stored), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "severity": severity, "reasons": sorted(set(reasons))}
        self._write(self.list() + [entry])
        return entry

    def restore(self, entry_id: str, overwrite: bool = False) -> str:
        """Put a quarantined file back where it came from; returns that path."""
        entry = self._entry(entry_id)
        target = entry["original"]
        if os.path.exists(target) and not overwrite:
            raise QuarantineError("a file already exists at %s" % target)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            self._copy(entry["stored"], target)     # XOR twice = original bytes
            os.remove(entry["stored"])
        except OSError as exc:
            raise QuarantineError("could not restore %s: %s" % (target, exc))
        self._write([e for e in self.list() if e["id"] != entry_id])
        return target

    def delete(self, entry_id: str) -> None:
        """Permanently delete a quarantined file."""
        entry = self._entry(entry_id)
        try:
            if os.path.exists(entry["stored"]):
                os.remove(entry["stored"])
        except OSError as exc:
            raise QuarantineError("could not delete: %s" % exc)
        self._write([e for e in self.list() if e["id"] != entry_id])
