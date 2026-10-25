"""Is a file, byte for byte, a file of an official distribution the scanner has a table of?

One question over every table built from official releases only - never from a scanned game:
the engines (:mod:`gamescan.engine_hashes`: NW.js, Ren'Py, Unity), Inno Setup, NSIS,
Electron, Microsoft's DirectX package, the libraries games bundle, published npm packages,
and the RPG Maker runtimes taken from the vendor's own installers. A file whose SHA-256 is
in one of them is known content, wherever it sits - loose, or inside an archive or an
installer (phageo, 2026-10-17, fifty-ninth message).

Not here: what is verified by anything less than the whole file (a launcher apart from its
resources), and the one RGSS build that is evidence, not a vendor's file
(``runtimes.NOT_FROM_VENDOR``).
"""
from __future__ import annotations

from typing import Optional

from . import (directx_official, electron_official, engine_hashes, inno_official, library_hashes,
               npm_hashes, nsis_official, runtimes)


def exact(sha256: str) -> Optional[str]:
    """What official file has this SHA-256 (None: none of the tables holds it)."""
    if not sha256:
        return None
    return (engine_hashes.verified(sha256) or inno_official.verified(sha256) or nsis_official.verified(sha256)
            or electron_official.verified(sha256) or directx_official.verified(sha256)
            or library_hashes.verified(sha256) or npm_hashes.verified(sha256) or runtimes.vendor_rgss(sha256))
