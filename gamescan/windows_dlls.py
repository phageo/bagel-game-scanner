"""Names of the libraries Windows itself ships (generated - do not edit by hand).

For SIDELOAD-001 (``gamescan/sideload.py``): a library of one of these names beside a
program is named like a part of Windows. Only names - nothing of the files is kept.

Made on 2026-10-17 from ``C:/Windows/System32/*.dll`` of the development PC (Windows 11
Home, build 26300): every library whose signature Windows' own check calls valid and whose
certificate is "Microsoft Windows" or "Microsoft Corporation". Libraries that drivers put
there (signed through Microsoft's hardware / software compatibility programme - vulkan-1,
OpenCL, a graphics card's libraries) are not in it; the Microsoft redistributables are matched
by ``sideload.REDISTRIBUTABLE`` instead. 3409 names.
"""
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/windows_dlls.py")

NAMES = frozenset(_IND[0].split())


# Microsoft redistributables a game may ship that a PC's System32 may lack (phageo, 2026-10-17): the
# DirectX End-User Runtimes (June 2010) and the Visual C++ runtimes - written out by hand, names only.
# (gamescan/sideload.py also takes the families of these names by pattern - api-ms-win-*, mfc* ...)
REDISTRIBUTABLE = frozenset(_IND[1].split())
