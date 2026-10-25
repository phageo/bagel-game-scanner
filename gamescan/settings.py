"""User settings, stored as JSON in ``~/.game_safety_scanner/settings.json``.

The API keys in it are encrypted for the current Windows user (see
:mod:`gamescan.secrets_store`); in memory, ``load()`` hands them out decrypted."""
from __future__ import annotations

import json
import os
from typing import Any, Dict

from . import secrets_store

DIR = os.path.join(os.path.expanduser("~"), ".game_safety_scanner")
PATH = os.path.join(DIR, "settings.json")

DEFAULTS: Dict[str, Any] = {
    "language": None,                 # None = follow the operating system
    "yara_dir": os.path.join(DIR, "yara"),
    "vt_enabled": False,
    "vt_api_key": "",
    "vt_max_lookups": 20,
    "vt_min_age_days": 30,            # a clean VirusTotal result only counts after this long
    "trusted_publishers": None,       # None = the built-in list in context.py
    "auto_quarantine": False,
    "amsi_enabled": True,             # show extracted content to the Windows antimalware engine
    "defender_scan": False,           # also run MpCmdRun.exe on the scan target
    "memory_enabled": True,           # remember scans and learn from feedback
    "realtime_enabled": False,        # watch folders and scan new files
    "watch_dirs": None,               # None = Downloads and Desktop
    # {key} is replaced by the abuse.ch Auth-Key below
    "signature_url": "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
    "abusech_key": "",
}
_OLD_SIGNATURE_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"


SECRETS = ("vt_api_key", "abusech_key")    # never written to disk in plain text (secrets_store)


def load() -> Dict[str, Any]:
    """The settings, with the API keys decrypted for use in memory. Keys that
    an earlier version left in plain text are protected right away."""
    values = dict(DEFAULTS)
    plain = False
    try:
        with open(PATH, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        values.update({k: v for k, v in stored.items() if k in DEFAULTS})
        for key in SECRETS:
            raw = stored.get(key, "")
            plain |= bool(raw) and secrets_store.available() and not secrets_store.is_protected(raw)
            values[key] = secrets_store.reveal(raw)
    except (OSError, ValueError, AttributeError):
        pass
    if values["signature_url"] == _OLD_SIGNATURE_URL:      # saved by an earlier version
        values["signature_url"] = DEFAULTS["signature_url"]
    if plain:
        try:
            save(values)
        except OSError:
            pass
    return values


def save(values: Dict[str, Any]) -> None:
    """Write the settings. API keys go to disk encrypted for this Windows user
    (DPAPI); where that is not available the file is made owner-only. A key
    that cannot be protected on Windows is not written at all."""
    os.makedirs(DIR, exist_ok=True)
    out = {k: values.get(k, d) for k, d in DEFAULTS.items()}
    for key in SECRETS:
        sealed = secrets_store.protect(out.get(key) or "")
        out[key] = "" if sealed is None else sealed
    temporary = PATH + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    secrets_store.restrict(temporary)
    os.replace(temporary, PATH)
    secrets_store.restrict(DIR)


def update(**changes: Any) -> Dict[str, Any]:
    values = load()
    values.update(changes)
    save(values)
    return values
