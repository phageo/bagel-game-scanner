"""Is a file that is *named* like an engine component really that component?

Engine and library files are exempt from most heuristics - a browser engine
or a language runtime does, legitimately, everything a rule looks for. That
exemption must not be available to a file that merely imitates one.

**Programs and native libraries** earn it in one way only: a valid
Authenticode signature (verified by Windows, see :mod:`gamescan.trust`)
from the vendor that publishes the component - Unity Technologies for
``UnityPlayer.dll``, Valve for ``steam_api.dll``, Microsoft for the
compiler runtime. The right name, the right identity in the export table
and the right exports are *not* enough: all of that can be built into a
hostile library. Without the vendor's signature the file is scanned as any
unknown program, and the report says why (``ENGINE-002``); if it does not
even have the component's structure, that is pointed out as well
(``ENGINE-001``).

The consequence is deliberate and visible: components whose vendors do not
sign their builds - NW.js / Chromium as shipped with RPG Maker MV / MZ, the
Python runtime Ren'Py bundles, open-source libraries such as SDL, FFmpeg,
zlib - can no longer be exempted at all, and their findings show.
``REQUIRE_VENDOR_SIGNATURE = False`` (``--allow-unsigned-engine-files``)
restores the structural check as sufficient.

**Framework assemblies** (managed code) have no exports to imitate and are
never signed by Unity; they must be .NET assemblies whose module name is
the file's name. **Scripts** are checked by their handlers.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/handlers/engine_files.py")

import os
import re
from typing import Optional, Tuple

from .. import sigblock, trust
from ..models import FileContext
from ..unpack import dotnet_meta, spool

MANAGED = "Unity engine / .NET framework assembly"

# name pattern -> what a library of that name must export (any one of them; a
# trailing * matches a prefix)
_EXPORTS = (
    (r"unityplayer\.dll$", ("UnityMain",)),
    (r"steam_api(?:64)?\.dll$", ("SteamAPI_Init", "SteamAPI_InitSafe", "SteamAPI_InitFlat")),
    (r"steamclient(?:64)?\.dll$", ("CreateInterface",)),
    (r"mono(?:-2\.0-(?:bdwgc|sgen))?\.dll$", ("mono_jit_init",)),
    (r"(?:lib)?python[\d.]*\.dll$", ("Py_Initialize",)),
    (r"sdl2\.dll$", ("SDL_Init",)),
    (r"sdl2_\w+\.dll$", ("IMG_Init", "TTF_Init", "Mix_Init", "SDL*", "GFX*", "SDLNet_Init")),
    (r"zlib1?\.dll$", ("inflate",)),
    (r"d3dcompiler_\d+\.dll$", ("D3DCompile",)),
    (r"libegl\.dll$", ("eglInitialize",)),
    (r"libglesv2\.dll$", ("glActiveTexture", "?ActiveTexture@gl@@*", "glClear")),
    (r"(?:ffmpeg|avcodec-\d+|avformat-\d+|avutil-\d+)\.dll$", ("av*",)),
    (r"swscale-\d+\.dll$", ("sws_*",)),
    (r"swresample-\d+\.dll$", ("swr_*",)),
    (r"openal32\.dll$", ("alcOpenDevice",)),
    (r"fmod\w*\.dll$", ("FMOD_*", "FMOD5_*", "?*@FMOD@@*")),
    (r"bass\.dll$", ("BASS_Init",)),
    (r"xinput\d_\d\.dll$", ("XInputGetState",)),
    (_IND[0], (_IND[1],)),
    (r"eossdk-win(?:32|64)-shipping\.dll$", ("EOS_Initialize",)),
    (r"libcrypto-[\w-]+\.dll$", ("EVP_*",)),
    (r"libssl-[\w-]+\.dll$", ("SSL_new",)),
    (r"libogg(?:-\d)?\.dll$", ("ogg_sync_init",)),
    (r"libvorbis[\w-]*\.dll$", ("vorbis_*", "ov_*")),
    (r"vulkan-1\.dll$", ("vkCreateInstance",)),
    (r"vk_swiftshader\.dll$", ("vk_icdGetInstanceProcAddr", "vkCreateInstance")),
    (r"node\.dll$", ("napi_*", "node_*", "?*@node@@*")),
)
# name pattern -> library a program of that name must import from
_IMPORTS = (
    (r"pythonw?\.exe$", r"(?:lib)?python[\d.]*\.dll$"),
    (r"nw\.dll$", r"(?:nw_elf|chrome_elf|ffmpeg)\.dll$"),
    (r"lib/(?:py\d?-|windows-|python)[^/]*/[^/]+\.exe$", r"(?:lib)?python[\d.]*\.dll$"),
)
_EXPORTS_RX = [(re.compile(p), names) for p, names in _EXPORTS]
_IMPORTS_RX = [(re.compile(p), re.compile(lib)) for p, lib in _IMPORTS]


def _has(exports, wanted: str) -> bool:
    if "*" not in wanted:
        return wanted in exports
    pattern = re.compile(".*".join(re.escape(part) for part in wanted.split("*")) + r"\Z")
    return any(pattern.match(name) for name in exports)


def claims_identity(ctx: FileContext, description: str) -> bool:
    """Does the file's *name* claim to be one particular component (as opposed
    to merely sitting in an engine folder)? Only then is a mismatch worth
    pointing out; otherwise the file is simply judged like any other."""
    name = ctx.name
    return (description == MANAGED or any(p.search(name) for p, _n in _EXPORTS_RX)
            or any(p.search(ctx.key) for p, _l in _IMPORTS_RX[:2]))


REQUIRE_VENDOR_SIGNATURE = True

# name pattern -> publishers whose valid signature proves the component genuine
# (matched like the trusted-publisher list: the certificate's name starts with it)
_VENDORS = [(re.compile(p), v) for p, v in (
    (r"(?:^|[/!])(?:unityplayer\.dll|unitycrashhandler(?:32|64)\.exe|monoposixhelper\.dll"
     r"|mono(?:-2\.0-(?:bdwgc|sgen))?\.dll)$|(?:^|[/!])monobleedingedge/", ("Unity Technologies",)),
    (r"(?:^|[/!])(?:steam_api(?:64)?|steamclient(?:64)?)\.dll$", ("Valve",)),
    (r"(?:^|[/!])(?:d3dcompiler_\d+|d3dx9_\d+|xinput\d_\d|vcruntime\d+(?:_\d)?|msvc[pr]\d+"
     r"|ucrtbase|api-ms-win-[\w-]+|concrt\d+)\.dll$", ("Microsoft",)),
    (_IND[2], (_IND[3],)),
    (r"(?:^|[/!])eossdk-win(?:32|64)-shipping\.dll$", ("Epic Games",)),
    (r"(?:^|[/!])galaxy(?:64)?\.dll$", ("GOG",)),
)]
_MAX_SIGNED_MEMBER = 256 * 1024 * 1024   # an in-memory archive member whose signature is verified


def expected_vendors(ctx: FileContext) -> Tuple[str, ...]:
    """Publishers that sign the component this file is named after (empty:
    the component is not distributed signed, so no signature can prove it)."""
    for pattern, vendors in _VENDORS:
        if pattern.search(ctx.key):
            return vendors
    return ()


def signer(ctx: FileContext) -> Optional[str]:
    """Who validly signed this program (None = nobody). Windows verifies a
    signature on a file, so a program that is an archive member is written
    to a temporary file for the check - under a name that cannot be run -
    and removed again; it is never executed. (Not done in a memory-only
    scan: such a member then counts as unsigned.)"""
    if "signer" not in ctx.cache:
        # data behind the certificate table: Windows does not accept such a signature,
        # and neither does the scanner - whatever a check of the file might say
        ctx.cache["signer"] = None if ctx.pe is not None and sigblock.data_after(ctx) else _signer(ctx)
    return ctx.cache["signer"]


def package_signer(ctx: FileContext) -> Optional[str]:
    """Who validly signed this Windows Installer package (None = nobody) - checked by Windows
    as for a program (:func:`signer`), on the file itself or on a temporary copy; never in a
    memory-only scan. The caller makes sure the package has a signature stream."""
    if "signer" not in ctx.cache:
        ctx.cache["signer"] = _signer(ctx, package=True)
    return ctx.cache["signer"]


def _signer(ctx: FileContext, package: bool = False) -> Optional[str]:
    if not package and (ctx.pe is None or not ctx.pe.has_signature):
        return None
    if ctx.on_disk:
        return trust.signer_name(ctx.path)
    if ctx.truncated or len(ctx.data) > _MAX_SIGNED_MEMBER or not spool.DISK:
        return None
    handle, path = spool.temporary_file()
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(ctx.data)
        return trust.signer_name(path)
    except OSError:
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _signed_by(who: Optional[str], vendors: Tuple[str, ...]) -> bool:
    name = (who or "").strip().lower()
    return any(name == v.lower() or (name.startswith(v.lower()) and not name[len(v)].isalnum())
               for v in vendors)


def binary(ctx: FileContext, description: str) -> str:
    """"" if the program is verified to be the engine component its name
    claims; otherwise why it is not. ``ctx.cache`` then says which kind of
    failure it is: ``engine_unsigned`` (built like the component, but not
    signed by its vendor) or - set by the caller - a structural mismatch."""
    pe = ctx.pe
    if pe is None:
        return "its headers cannot be read"
    if description == MANAGED or pe.is_dotnet or not REQUIRE_VENDOR_SIGNATURE:
        return structure(ctx, description)
    vendors = expected_vendors(ctx)
    who = signer(ctx)
    if vendors and _signed_by(who, vendors):
        return ""                                           # the vendor vouches for this very file
    problem = structure(ctx, description)
    if problem:
        return problem
    if who is not None and vendors:
        ctx.cache["vendor_conflict"] = True                 # signed - by somebody else
        return 'it is signed by "%s", not by %s' % (who or "an unnamed publisher",
                                                    " / ".join(vendors))
    if vendors:
        why = "it has no valid signature; the genuine file is signed by %s" % " / ".join(vendors)
    else:
        why = ("this component is not distributed with a vendor signature, so that it is "
               "genuine cannot be verified")
    ctx.cache["engine_unsigned"] = (description, why)
    return why


def structure(ctx: FileContext, description: str) -> str:
    """"" if the program is at least *built* like the engine component its name
    claims (identity in the export table, the component's exports, or imports
    from its runtime); otherwise what is wrong with it."""
    pe = ctx.pe
    if pe is None:
        return "its headers cannot be read"
    name = ctx.name
    if description == MANAGED or pe.is_dotnet:
        if not pe.is_dotnet:
            return "it is not a .NET assembly"
        module: Optional[str] = dotnet_meta.module_name(ctx.data, pe)
        if module is None:
            return "its assembly metadata cannot be read"
        if module.lower() != name:
            return "the assembly inside calls itself %s" % module
        return ""
    if pe.packer:
        return "it is packed (%s)" % pe.packer
    if pe.exports:
        if pe.export_name.lower() != name:
            return "it calls itself %s in its export table" % (pe.export_name or "nothing")
        for pattern, names in _EXPORTS_RX:
            if pattern.search(name):
                if not any(_has(pe.exports, wanted) for wanted in names):
                    return "it does not export %s" % names[0].replace("*", "...")
                break
        if name.endswith(".pyd"):
            leaf = name[:-4].rsplit(".", 1)[-1]
            if not any(entry.lower() in ("init" + leaf, "pyinit_" + leaf) for entry in pe.exports):
                return "it has no Python module entry point"
        return ""
    for pattern, library in _IMPORTS_RX:
        if pattern.search(ctx.key):
            if any(library.search(dll) for dll in pe.imports):
                return ""
            return "it does not import from the runtime it belongs to"
    return "it exports nothing, so it cannot be told apart from any other program"
