"""Known-malware signatures: a local SHA-256 blocklist plus the EICAR test file.

The blocklist is an SQLite table that can be filled from any text / CSV file
containing SHA-256 hashes, or updated from abuse.ch MalwareBazaar's "recent
samples" export. That export needs a free Auth-Key (https://auth.abuse.ch/),
which is part of the URL. The export only covers the last 48 hours, so every
update is *merged* into the local table - nothing is ever replaced. A hash
match is exact: it identifies a file somebody already analysed, nothing more.
"""
from __future__ import annotations

import csv
import io
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import closing
from typing import Callable, NamedTuple, Optional, Tuple

DEFAULT_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
MIN_FETCH_INTERVAL = 300                 # abuse.ch: at most one fetch per 5 minutes
_MAX_DOWNLOAD = 300 * 1024 * 1024
_HASH = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
# the industry-standard harmless test file every antivirus must detect
# (kept in two pieces so this source file is not itself mistaken for it)
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()

Fetch = Callable[[str], Tuple[int, bytes]]     # url -> (HTTP status, body)

_MESSAGES = {
    "no_key": "an abuse.ch Auth-Key is required (free at https://auth.abuse.ch/)",
    "rejected": "abuse.ch rejected the Auth-Key",
    "rate_limit": "the list was fetched less than 5 minutes ago",
    "network": "the download failed",
    "empty": "the server did not return a hash list",
}


class SignatureError(Exception):
    """``code`` is one of: no_key, rejected, rate_limit, network, empty."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code, self.detail = code, detail
        super().__init__(_MESSAGES[code] + (": " + detail if detail else ""))


class UpdateResult(NamedTuple):
    listed: int          # hashes in the downloaded list
    added: int           # of those, new to the local database


def builtin_match(data: bytes) -> Optional[str]:
    """Name of a built-in signature matching ``data``, if any."""
    if data[:len(EICAR)] == EICAR and len(data) <= len(EICAR) + 60:
        return "EICAR-Test-File"
    return None


def _http_get(url: str) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "GameSafetyScanner"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read(_MAX_DOWNLOAD)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


class SignatureDatabase:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.path.join(os.path.expanduser("~"), ".game_safety_scanner",
                                         "signatures.db")
        folder = os.path.dirname(self.path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.execute("CREATE TABLE IF NOT EXISTS hashes(sha256 TEXT PRIMARY KEY, name TEXT,"
                        " source TEXT, added REAL) WITHOUT ROWID")
            con.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=15)

    def _meta(self, key: str) -> Optional[float]:
        with closing(self._connect()) as con:
            row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return float(row[0]) if row else None

    def _set_meta(self, key: str, value: float) -> None:
        with closing(self._connect()) as con, con:
            con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))

    def count(self) -> int:
        with closing(self._connect()) as con:
            return con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]

    def last_update(self) -> Optional[float]:
        return self._meta("updated")

    def lookup(self, sha256: str) -> Optional[str]:
        """Malware name for a hash, or None when the hash is not listed."""
        with closing(self._connect()) as con:
            row = con.execute("SELECT name FROM hashes WHERE sha256 = ?",
                              (sha256.lower(),)).fetchone()
        return (row[0] or "known malware") if row else None

    def add(self, sha256: str, name: str = "", source: str = "manual") -> None:
        with closing(self._connect()) as con, con:
            con.execute("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?)",
                        (sha256.lower(), name, source, time.time()))

    @staticmethod
    def _label(line: str, m: "re.Match[str]") -> str:
        """A name for the hash on this line: the malware family if the line is
        an abuse.ch CSV row (column 9), otherwise whatever else is on the line."""
        if line.count(",") >= 8 and '"' in line:
            try:
                fields = next(csv.reader([line], skipinitialspace=True))
                family = fields[8].strip() if len(fields) > 8 else ""
                if family and family.lower() != "n/a":
                    return family[:80]
                kind = fields[6].strip() if len(fields) > 6 else ""
                return ("unclassified malware (%s)" % kind[:40]) if kind else ""
            except (csv.Error, StopIteration):
                pass
        label = (line[:m.start()] + " " + line[m.end():]).strip(" \t,;\"'|")
        return label[:80] if 2 < len(label) else ""

    def import_text(self, text: str, source: str) -> UpdateResult:
        """Merge every SHA-256 found in ``text`` (one per line) into the table."""
        rows, now = [], time.time()
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            m = _HASH.search(line)
            if m:
                rows.append((m.group(1).lower(), self._label(line, m), source, now))
        with closing(self._connect()) as con, con:
            before = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            con.executemany("INSERT OR IGNORE INTO hashes VALUES (?,?,?,?)", rows)
            if rows:
                con.execute("INSERT OR REPLACE INTO meta VALUES ('updated', ?)", (str(now),))
            added = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] - before
        return UpdateResult(len({r[0] for r in rows}), added)

    def import_file(self, path: str) -> UpdateResult:
        with open(path, "rb") as fh:
            return self.import_text(self._decode(fh.read(_MAX_DOWNLOAD)), os.path.basename(path))

    @staticmethod
    def _decode(blob: bytes) -> str:
        if blob[:2] == b"PK":                    # zipped export: use the first member
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                with archive.open(archive.namelist()[0]) as member:
                    blob = member.read(_MAX_DOWNLOAD)     # bounded: no zip bomb
        return blob.decode("utf-8", "replace")

    def update(self, url: str = DEFAULT_URL, key: str = "", fetch: Optional[Fetch] = None,
               now: Optional[float] = None) -> UpdateResult:
        """Download the hash list and merge it into the local database.

        ``url`` may contain ``{key}``, which is replaced by the Auth-Key.
        Raises :class:`SignatureError` - it never reports success unless a
        hash list was really downloaded. The key never appears in an error.
        """
        key = (key or "").strip()
        if "{key}" in url:
            if not key:
                raise SignatureError("no_key")
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key):
                raise SignatureError("rejected", "the key contains unexpected characters")
        now = time.time() if now is None else now
        last = self._meta("fetched")
        if last is not None and 0 <= now - last < MIN_FETCH_INTERVAL:
            raise SignatureError("rate_limit", "wait %d more seconds"
                                 % (MIN_FETCH_INTERVAL - (now - last)))
        try:
            status, blob = (fetch or _http_get)(url.replace("{key}", key))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SignatureError("network", type(exc).__name__)
        self._set_meta("fetched", now)           # the server saw a request: start the clock
        if status in (401, 403, 404) and "{key}" in url:
            raise SignatureError("rejected", "HTTP %d" % status)
        if status != 200:
            raise SignatureError("network", "HTTP %d" % status)
        try:
            text = self._decode(blob)
        except (zipfile.BadZipFile, IndexError, OSError, ValueError):
            raise SignatureError("empty")
        if not _HASH.search(text):
            head = text[:300].lower()
            if "{key}" in url and ("auth" in head or "key" in head or "unauthor" in head):
                raise SignatureError("rejected")
            raise SignatureError("empty")
        return self.import_text(text, url.split("/")[2] if "://" in url else "list")

    def clear(self) -> None:
        with closing(self._connect()) as con, con:
            con.execute("DELETE FROM hashes")
            con.execute("DELETE FROM meta")
