"""Engine runtimes that are recognised by their exact content.

RPG Maker's ``RGSSxxx.dll`` ships protected (packed), unsigned, and with a
keyboard-reading import - to a scanner it looks just like a packed
keylogger. It cannot be trusted for its *name*: anything can be called
``RGSS301.dll``. So it is trusted only when its SHA-256 is one of the builds
below. A file with the runtime's name and any other content is treated like
every other unknown program, and additionally pointed out (``RGSS-RT-001``).

Where the hashes come from (2026-10-04):

* the builds described as "official RTP" - and ``RGSS202E.dll`` - are in the
  vendor's own RTP installers, linked from
  https://rpgmakerofficial.com/support/rtp/ (``xp_rtp103.zip``,
  ``vx_rtp202.zip``) and https://www.rpgmakerweb.com/run-time-package
  (``xp_rtp104e.exe``). The installers were not run: each file was rebuilt from
  the installer's data and matches the checksum the installer itself stores
  for it. ``RGSS202E.dll`` was also found, with the same hash, in a VX game
  from a Steam release and in a second, unrelated VX game distribution;
* ``RGSS300.dll`` / ``RGSS301.dll`` (the same bytes under both names) is *not*
  from the vendor: the VX Ace RTP installs no runtime library at all (it
  ships with each game). This build was found byte-identical in two
  unrelated VX Ace game distributions - that is
  evidence, not a vendor statement.

Builds not listed here (any other VX Ace build, runtimes patched by a
translation or protection tool, ...) are simply not known yet - add a build once its hash has been
confirmed from a source you trust, or put the file on the allowlist.
"""
from __future__ import annotations

import re
from typing import Optional

KNOWN_RGSS = {
    "3f8ec6209a117ad6ec24eb748b20631b1b09ee65566e2b98fbe5a7021967e40a":
        "RGSS202E.dll - RPG Maker VX runtime 2.02 (English), 852,480 bytes",
    "27647690ed16218cd988dd71069fdca67207515b2a2df775be361f0198ab6876":
        "RGSS300.dll / RGSS301.dll - RPG Maker VX Ace runtime, 1,085,952 bytes",
    "f646e0b2db58d8fa881dfde3002b736dc374ecaaab15852b91ec719da7d3b90b":
        "RGSS100J.dll - RPG Maker XP runtime (Japanese), 771,584 bytes; official RTP xp_rtp103.zip",
    "ab4f7ccc49d56161b38e0da0debb05b6f522b00b1c48356f776910934122278f":
        "RGSS102J.dll - RPG Maker XP runtime (Japanese), 781,312 bytes; official RTP xp_rtp103.zip",
    "899b0d3df7829345223a1d4c29d1246c5eecec8e6d84151791f8505f7dd3c039":
        "RGSS103J.dll - RPG Maker XP runtime (Japanese), 685,056 bytes; official RTP xp_rtp103.zip",
    "f079a18c0abc9569429d402357e2daa4fe2af4cdbe3c002a5f05a70d33e7bffb":
        "RGSS102E.dll - RPG Maker XP runtime (English), 778,752 bytes; official RTP xp_rtp103.zip",
    "c0fc024497229a12425fb6d2196b234a7bab0119470f8a36bea602e0d4a14d56":
        "RGSS200J.dll - RPG Maker VX runtime (Japanese), 805,376 bytes; official RTP vx_rtp202.zip",
    "ac186c2e0103ddf208aafe027065284ee5bebaa4be791a4a3594e349a32103bf":
        "RGSS202J.dll - RPG Maker VX runtime (Japanese), 855,040 bytes; official RTP vx_rtp202.zip",
    "beb9c9a6ce5ceaa9d562e2906d4be7027a85a1c937266daaae743f272b296cf3":
        "RGSS104J.dll - RPG Maker XP runtime (Japanese), 761,856 bytes; official RTP xp_rtp104e.exe",
    "7b6acb5e2c245b8cfda77fced2cc0e94108384cd1b9ffc8510e7304fcb9feb6c":
        "RGSS104E.dll - RPG Maker XP runtime (English), 758,272 bytes; official RTP xp_rtp104e.exe",
}
_RGSS_NAME = re.compile(r"(^|[/!])rgss[123]\d\d[a-z]?\.dll$")


def named_like_rgss(key: str) -> bool:
    """Does the (lower-cased) path carry the RGSS runtime's file name?"""
    return _RGSS_NAME.search(key) is not None


def verified_rgss(sha256: str) -> Optional[str]:
    """Description of the official build with this SHA-256, or None."""
    return KNOWN_RGSS.get(sha256.lower())


# the VX Ace build above that is evidence (two game distributions), not a file of the vendor
NOT_FROM_VENDOR = frozenset({"27647690ed16218cd988dd71069fdca67207515b2a2df775be361f0198ab6876"})


def vendor_rgss(sha256: str) -> Optional[str]:
    """``verified_rgss`` for the builds taken from the vendor's own installers only."""
    sha256 = sha256.lower()
    return None if sha256 in NOT_FROM_VENDOR else KNOWN_RGSS.get(sha256)
