"""RPG Maker MV/MZ and other NW.js games: JavaScript, HTML, JSON data."""
from __future__ import annotations

import re
from typing import List

from ..dataflow import electron_ipc, electron_windows, jswrites, remote
from ..models import FileContext, Finding
from ..rules import RuleEngine
from .base import BaseHandler


# what the stock file of that name must contain (any one of the markers)
_CONTENT = [(re.compile(p), m) for p, m in (
    (r"js/(?:rpg|rmmz)_core\.js$", ("function Utils()", "Utils.RPGMAKER_NAME")),
    (r"js/(?:rpg|rmmz)_managers\.js$", ("function DataManager()",)),
    (r"js/(?:rpg|rmmz)_objects\.js$", ("function Game_Temp()",)),
    (r"js/(?:rpg|rmmz)_scenes\.js$", ("function Scene_Base()",)),
    (r"js/(?:rpg|rmmz)_sprites\.js$", ("function Sprite_Base()", "function Sprite_Clickable()")),
    (r"js/(?:rpg|rmmz)_windows\.js$", ("function Window_Base()",)),
    (r"js/libs/pixi[\w.-]*\.js$", ("PIXI",)),
    (r"js/libs/fpsmeter[\w.-]*\.js$", ("FPSMeter",)),
    (r"js/libs/lz-string[\w.-]*\.js$", ("LZString",)),
    (r"js/libs/iphone-inline-video[\w.-]*\.js$", ("inline",)),
    (r"js/libs/effekseer[\w.-]*\.js$", ("effekseer",)),
    (r"js/libs/vorbisdecoder[\w.-]*\.js$", ("VorbisDecoder", "vorbis")),
    (r"js/libs/localforage[\w.-]*\.js$", ("localforage",)),
    (r"js/libs/pako[\w.-]*\.js$", ("pako",)),
    (r"js/plugins/visumz_\d+_\w+\.js$", ("VisuMZ",)),
)]


class RpgMakerHandler(BaseHandler):
    name = "rpgmaker"
    engine = "RPG Maker / NW.js"
    # .json is included because map/event data carries "Script" commands
    extensions = frozenset({".js", ".mjs", ".cjs", ".html", ".htm", ".json"})
    markers = (r"(^|/)js/(?:rpg|rmmz)_core\.js$", r"\.(?:rpgproject|rmmzproject)$")
    baseline = (
        (r"(^|[/!])js/(?:rpg|rmmz)_(?:core|managers|objects|scenes|sprites|windows)\.js$",
         "RPG Maker core script"),
        (r"(^|[/!])js/libs/", "RPG Maker bundled library"),
        (r"(^|[/!])js/plugins/visumz_\d+_\w+\.js$",
         "VisuStella MZ plugin (commercially obfuscated)"),
    )

    def structure(self, ctx: FileContext, desc: str) -> str:
        # core scripts and bundled libraries are trusted for their name - so
        # they must contain what that script / library defines
        if ctx.is_pe:
            return super().structure(ctx, desc)
        text = ctx.text()
        for pattern, markers in _CONTENT:
            if pattern.search(ctx.key):
                if any(marker in text for marker in markers):
                    return ""
                return "it does not define %s" % markers[0].strip("( ")
        return "it is not one of the libraries the engine ships"

    def scan(self, ctx: FileContext, rules: RuleEngine) -> List[Finding]:
        style = None if ctx.ext == ".json" else "c"
        # an encoded script block (#@~^ ... ^#~@) inside a page or a script: decoded, then read as if plain
        text, notes = self.decode_script(ctx, ctx.text())
        # (a script file: words inside its quoted texts are no call sites - rules.QuotedText;
        # a page or a data file is not read that way)
        out = notes + (rules.scan(text, "js", ctx, self.name, comment_style=style,
                                  quoted=ctx.ext in (".js", ".mjs", ".cjs"))
                       + self.entropy_literals(ctx, text, "js"))
        if ctx.ext in (".html", ".htm") and "<script" in text.lower():
            page = self.vbscript_code(ctx, text, wrapped=True)     # the page's VBScript blocks
            for f in page:
                # a script the page loads by its address: in an Electron app what it can reach
                # depends on the window the page is shown in (Scanner._join_windows)
                if f.rule_id == "CHAIN-REMOTE-CODE" and f.evidence.startswith("script src loads "):
                    f.context[electron_windows.PAGE_SCRIPT] = True
            out += page
            if electron_windows.app_root(ctx.relpath) is not None:
                # the app's own scripts this page loads (Scanner._join_renderer)
                ctx.cache["page_scripts"] = electron_windows.page_scripts(text)
        elif ctx.ext in (".js", ".mjs", ".cjs"):
            script = electron_windows.read(text)                   # windows, exposed functions, messages
            if script is None and electron_windows.app_root(ctx.relpath) is not None:
                script = electron_windows.NOTHING                  # (a script of an app that says nothing: it is there)
            if script is not None:
                ctx.cache["electron_script"] = script
            if electron_windows.app_root(ctx.relpath) is not None and electron_ipc.keeps(ctx.relpath, text):
                # what the main process does with the pages' messages is read after the scan,
                # from the app's own scripts (Scanner._join_windows; phageo, 2026-10-15)
                if len(text) <= electron_ipc.MAX_SCRIPT:
                    ctx.cache["electron_text"] = text
                else:
                    ctx.cache["electron_big"] = "ipcMain" in text
        if ctx.ext != ".json":
            # file writes that only put a data file into the game's folder (context._data_write)
            ctx.cache["js_data_writes"] = jswrites.data_writes(text)
            # a page larger than the tracer reads: its limit applies to the script in the page -
            # the joined script blocks -, not to the page (phageo, 2026-10-12)
            large = ctx.ext in (".html", ".htm") and len(text) > remote.MAX_SOURCE
            out += self.resolve_payloads(ctx, rules, text, "js",
                                         chain_text=self.page_scripts(text) if large else None)
            out += self.antimalware(ctx, rules, text, "JavaScript")
        return out
