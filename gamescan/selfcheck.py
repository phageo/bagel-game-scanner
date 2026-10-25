"""The package's check of its own files at start (criterion 5; phageo, 2026-10-12 and 2026-10-24).

``tools/build_package.py`` writes ``app/package_files.json`` into the package: the SHA-256 of every
other file of the package. At start the window compares the files with that list; a changed, missing
or added file gives one clear warning, and scanning stays allowed.

It finds damage (a broken download, a half-copied folder, a file another program changed). It
cannot prove that nobody changed the package on purpose: whoever can change a file can also change
the list. Outside a package (no list beside the app) nothing is checked.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Dict, List, NamedTuple, Optional

LIST_NAME = "package_files.json"
_SKIP_DIRS = frozenset({"__pycache__"})       # Python writes compiled copies of the app's modules
# the installer's own uninstaller (tools/build_installer.py, UninstallFilesDir={app}\uninstall):
# written at install time, so it cannot be in the list - these exact names only
_INSTALLER_FILES = re.compile(r"uninstall/unins\d{3}\.(exe|dat|msg)", re.IGNORECASE)


class Result(NamedTuple):
    changed: List[str]
    missing: List[str]
    added: List[str]

    @property
    def ok(self) -> bool:
        return not (self.changed or self.missing or self.added)


def package_root(app_folder: Optional[str] = None) -> Optional[str]:
    """The top folder of the package the running app belongs to, or None outside a package."""
    app = app_folder or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isfile(os.path.join(app, LIST_NAME)):
        return os.path.dirname(app)
    return None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def listed(root: str) -> Dict[str, str]:
    """``{name: sha256}`` of the package's list (names with ``/``, below the top folder)."""
    with open(os.path.join(root, "app", LIST_NAME), encoding="utf-8") as fh:
        return dict(json.load(fh)["files"])


def check(root: str) -> Result:
    """Compare the files below ``root`` with the package's list."""
    want = listed(root)
    own = "app/" + LIST_NAME
    seen = {}
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            rel = os.path.relpath(os.path.join(base, name), root).replace("\\", "/")
            if rel != own and not rel.endswith(".pyc") and not _INSTALLER_FILES.fullmatch(rel):
                seen[rel.lower()] = rel
    changed, missing = [], []
    for name, digest in sorted(want.items()):
        found = seen.pop(name.lower(), None)
        if found is None:
            missing.append(name)
            continue
        try:
            if _sha256(os.path.join(root, found)) != digest:
                changed.append(name)
        except OSError:
            missing.append(name)
    return Result(changed, missing, sorted(seen.values()))
