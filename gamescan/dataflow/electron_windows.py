"""What a page of an Electron app can reach: the settings of the window it is shown in.

A page that loads a script by its address (``<script src="https://...">``) runs
whatever that address answers. In a browser that script is shut into the page.
In an Electron app it depends on the window (phageo, 2026-10-14):

* ``nodeIntegration: true`` or ``contextIsolation: false`` - the page's scripts
  have Node.js, or share their world with a preload script that has it: the
  remote script can start programs and read files. **Exposed.**
* A preload script that hands the page a function which reaches a sink
  (``contextBridge.exposeInMainWorld``: a function that starts a program, runs
  text, writes a file - itself, or through a message to the main process whose
  handler does) - or one that hands on the message channel itself. **Bridged.**
* Neither: the script runs as it would in a browser. **Shut in.**

The defaults changed over the years, so a setting that is not written out is
read by the app's Electron version (the one the runtime table verified):
``nodeIntegration`` is off since 5, ``contextIsolation`` on since 12, ``sandbox``
on since 20. Without a version, or with a setting that is not a written-out
``true`` / ``false``, the answer is "not known" - never "shut in".

Everything here reads text. Nothing is run. It is a reading by patterns and
brackets, like the rest of the JavaScript readers: a window built in a way it
does not see is "not known".
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from ..rules import _MASKS

MAX_SOURCE = 32 * 1024 * 1024       # characters of one script that are read (as textflow.JS_MAX_SOURCE)
MAX_WINDOWS = 64                    # windows read in one script
MAX_CHANNELS = 400                  # message channels kept per script
_MAX_BODY = 200_000                 # characters of one handler / one exposed object that are looked at

EXPOSED, BRIDGED, UNKNOWN, SHUT_IN = "exposed", "bridged", "not known", "shut in"
_ORDER = {SHUT_IN: 0, UNKNOWN: 1, BRIDGED: 2, EXPOSED: 3}
OPEN = "*"                          # a channel that is not a written-out text: any channel
PAGE_SCRIPT = "page_script"         # Finding.context: a page loads a script by its address
LOWERED = "PAGE-REMOTE-SCRIPT"      # the finding for such a page in a window that is not exposed
NODE_ON = "nodeIntegration is on"   # why a window is exposed: the page's scripts have Node.js
REAL_BEHAVIOUR = "real_behaviour"   # Finding.context: what the app really does, by its own settings
SCRIPT_ELEMENT = "script_element"   # Finding.context: a script element a script makes loads a remote address
NOT_IDENTIFIED = "not identified (a script element made by a script)"
MAX_SCRIPTS = 4000                  # scripts of one scan whose windows and messages are kept
_APP = ("resources/app.asar!", "resources/app.asar.unpacked/", "resources/app/")
# A page's own script that loads code - import(), eval, new Function, a Worker, importScripts - and
# runs only in windows whose pages are shut in (phageo, 2026-10-15, forty-seventh message): what it
# loads runs as in a web browser and does not reach the PC - the premise of the chain is disproven
# (CLAUDE.md, rule 13), so the finding gets a name of its own, MEDIUM (Scanner._join_renderer).
RENDERER = "renderer_sink"          # Finding.context: the code-loading sink of such a finding
CONTAINED = "RENDERER-CODE-LOAD"
RENDERER_SINKS = frozenset({"import", "eval", "new Function", "new Worker", "new SharedWorker", "importScripts"})
MAX_PAGE_SCRIPTS = 64               # script files of one page that are kept
# what the main process does with a message channel the page may choose (judge)
MESSAGES_KEPT = ("no message handler of the main process passes a message on to a program start, a code load, "
                 "the shell's open or a written file that is started (%d handlers read)")
MESSAGE_REACHES = "the handler of %s (%s, line %d): %s"
MESSAGES_UNREAD = "the main process could not be read in full: %s"
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*(["']?)([^"'\s>]{1,300})\1""", re.I)


def page_scripts(text: str) -> Tuple[str, ...]:
    """The file names (lower case, without a folder) of the app's own scripts a page loads by
    ``<script src=...>`` - not those of an address on another server (``https:``, ``//host``)."""
    out: List[str] = []
    for m in _SCRIPT_SRC.finditer(text):
        src = m.group(2).split("?", 1)[0].split("#", 1)[0]
        if re.match(r"(?:[a-z][\w+.-]*:|//)", src, re.I) and not src.lower().startswith("file:"):
            continue
        name = src.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name and name not in out:
            out.append(name)
        if len(out) >= MAX_PAGE_SCRIPTS:
            break
    return tuple(out)


def app_root(file: str) -> Optional[str]:
    """What stands in front of an Electron app's own files in ``file``'s path (None: the
    file is not one of an app's): the same for the app's pages, scripts and program."""
    low = file.replace("\\", "/").lower()
    for mark in _APP:
        at = low.find(mark)
        if at >= 0:
            return low[:at]
    return None


def program_root(file: str) -> str:
    """The same for the app's program (it lies beside ``resources``)."""
    low = file.replace("\\", "/").lower()
    return low[:max(low.rfind("/"), low.rfind("!")) + 1]

_ID = r"[A-Za-z_$][\w$]*"
_WINDOW = re.compile(r"(?<![\w$.])new\s+(?:%s\s*\.\s*)?(BrowserWindow|BrowserView|WebContentsView)\s*\(" % _ID)
_NAMED = re.compile(r"(?<![\w$.])((?:this\s*\.\s*)?%s)\s*=\s*(?:await\s+)?\Z" % _ID)
_PREFERENCES = re.compile(r"(?<![\w$.])webPreferences\s*:\s*")
_SETTING = r"(?<![\w$.])%s\s*:\s*(!0\b|!1\b|true\b|false\b)?"
_PRELOAD = re.compile(r"(?<![\w$.])preload\s*:\s*")
_FILE = re.compile(r"""["'`]([^"'`\n]{0,200}?([\w.-]+\.(?:c?js|mjs|html?)))["'`]""")
_SINK = re.compile(
    r"(?<![\w$.])(?:child_process|execSync|execFileSync|spawnSync)\b"
    r"|\.\s*(?:exec|execFile|spawn|fork)\s*\(|(?<![\w$.])eval\s*\(|(?<![\w$.])new\s+Function\s*\("
    r"|\.\s*(?:openPath|openItem|openExternal)\s*\(|\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync)\s*\("
    r"|\.\s*(?:runInThisContext|runInNewContext|executeJavaScript)\s*\(|(?<![\w$.])process\s*\.\s*dlopen\s*\(")
_EXPOSE = re.compile(r"(?<![\w$])contextBridge\s*\.\s*exposeInMainWorld\s*\(")
_SEND = re.compile(r"(?<![\w$])ipcRenderer\s*\.\s*(?:send|invoke|sendSync|sendToHost|postMessage)\s*\(\s*")
_RAW_IPC = re.compile(r"(?<![\w$.])ipcRenderer\s*(?:[,})]|\.\s*(?:send|invoke|sendSync|on)\s*(?:[,})]|\.bind))")
_HANDLE = re.compile(r"(?<![\w$])ipcMain\s*\.\s*(?:on|once|handle|handleOnce)\s*\(\s*")
_QUOTED = re.compile(r"""\s*(["'`])([^"'`\n$]{1,200})\1\s*[,)]""")
_ON = frozenset({"true", "!0"})


class Window(NamedTuple):
    """One window a script makes. A setting is True, False, None (not written: the
    version's default) or ``UNKNOWN`` (written, but not as ``true`` / ``false``)."""
    line: int
    node: object                    # nodeIntegration (also in workers / sub-frames)
    isolation: object               # contextIsolation
    sandbox: object
    preload: str                    # the preload script's file name ("": none; UNKNOWN: not read)
    loads: Tuple[str, ...]          # file names of the pages it is given, as far as written out


class Script(NamedTuple):
    """What one script of an app says about its windows and messages."""
    windows: Tuple[Window, ...]
    exposes: bool                   # it hands the page functions (contextBridge)
    sink: bool                      # ... and reaches a sink itself
    sends: frozenset                # channels it sends on (OPEN: any)
    handles: frozenset              # channels whose handler in this script reaches a sink


NOTHING = Script((), False, False, frozenset(), frozenset())


def _bare(code: str) -> str:
    """``code`` with comments and the inside of strings blanked (same length)."""
    def blank(m: "re.Match[str]") -> str:
        token = m.group(0)
        if token[:1] in "\"'`" and len(token) > 1 and not (token[:1] == "`" and "${" in token):
            return token[0] + re.sub(r"[^\n]", " ", token[1:-1]) + token[-1]
        if token[:2] in ("//", "/*"):
            return re.sub(r"[^\n]", " ", token)
        return token
    return _MASKS["c"].sub(blank, code)


def _close(bare: str, opener: int, limit: int = _MAX_BODY) -> int:
    """The bracket that closes the one at ``opener`` (-1: not found within ``limit``)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for i in range(opener, min(len(bare), opener + limit)):
        ch = bare[i]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if not stack or stack.pop() != ch:
                return -1
            if not stack:
                return i
    return -1


def _setting(bare: str, a: int, b: int, name: str) -> object:
    found = None
    for m in re.compile(_SETTING % name).finditer(bare, a, b):
        value = UNKNOWN if m.group(1) is None else m.group(1) in _ON
        if found is not None and value != found:
            return UNKNOWN                                  # written twice, two ways
        found = value
    return found


def read(text: str) -> Optional[Script]:
    """What the JavaScript ``text`` says about windows, exposed functions and messages
    (None: nothing of that kind in it). Never raises."""
    if not text or not ("BrowserWindow" in text or "BrowserView" in text or "WebContentsView" in text
                        or "contextBridge" in text or "ipcRenderer" in text or "ipcMain" in text):
        return None
    try:
        code = text[:MAX_SOURCE]
        bare = _bare(code)
        return Script(tuple(_windows(code, bare)), _EXPOSE.search(bare) is not None,
                      ("contextBridge" in bare or "ipcRenderer" in bare) and _SINK.search(bare) is not None,
                      frozenset(_sends(code, bare)), frozenset(_handles(code, bare)))
    except Exception:                    # an analysis aid must never break the scan itself
        return None


def _windows(code: str, bare: str) -> List[Window]:
    out: List[Window] = []
    line_of = lambda pos: code.count("\n", 0, pos) + 1
    for m in _WINDOW.finditer(bare):
        if len(out) >= MAX_WINDOWS:
            break
        opener = m.end() - 1
        close = _close(bare, opener)
        if close < 0:
            out.append(Window(line_of(m.start()), UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, ()))
            continue
        node = isolation = sandbox = None
        preload = ""
        inner = bare[opener + 1:close].strip()
        prefs = _PREFERENCES.search(bare, opener, close)
        if inner and not inner.startswith("{"):
            node = isolation = sandbox = preload = UNKNOWN  # new BrowserWindow(options): not written out here
        elif prefs is not None:
            if bare[prefs.end():prefs.end() + 1] != "{":
                node = isolation = sandbox = preload = UNKNOWN          # webPreferences: something
            else:
                end = _close(bare, prefs.end())
                end = close if end < 0 else end
                node = _setting(bare, prefs.end(), end, "nodeIntegration")
                for other in ("nodeIntegrationInWorker", "nodeIntegrationInSubFrames"):
                    if _setting(bare, prefs.end(), end, other) is True:
                        node = True
                isolation = _setting(bare, prefs.end(), end, "contextIsolation")
                sandbox = _setting(bare, prefs.end(), end, "sandbox")
                if "..." in bare[prefs.end():end]:          # ...shared: settings from elsewhere
                    node = UNKNOWN if node is None else node
                    isolation = UNKNOWN if isolation is None else isolation
                p = _PRELOAD.search(bare, prefs.end(), end)
                if p is not None:
                    stop = bare.find(",", p.end(), end)
                    depth_end = _close(bare, bare.find("(", p.end(), end)) if "(" in bare[p.end():stop if stop > 0 else end] else -1
                    stop = max(stop if stop > 0 else end, depth_end + 1)
                    names = _FILE.findall(code[p.end():stop])
                    preload = names[-1][1] if names else UNKNOWN
        # the pages this window is given: <name>.loadURL(...) / loadFile(...) after it
        loads: List[str] = []
        named = _NAMED.search(bare, max(0, m.start() - 80), m.start())
        if named:
            name = re.sub(r"\s+", "", named.group(1))
            again = re.compile(r"(?<![\w$.])%s\s*=(?!=)" % re.escape(name).replace(r"\.", r"\s*\.\s*"))
            later = again.search(bare, close)
            stop = later.start() if later else min(len(bare), close + 400_000)
            for use in re.compile(r"(?<![\w$.])%s\s*(?:\.\s*webContents\s*)?\.\s*(?:loadURL|loadFile)\s*\("
                                  % re.escape(name).replace(r"\.", r"\s*\.\s*")).finditer(bare, close, stop):
                end = _close(bare, use.end() - 1, 4000)
                if end > 0:
                    loads += [found[1].lower() for found in _FILE.findall(code[use.end():end])]
        out.append(Window(line_of(m.start()), node, isolation, sandbox, preload, tuple(dict.fromkeys(loads))))
    return out


def _channel(code: str, at: int) -> str:
    m = _QUOTED.match(code, at)
    return m.group(2) if m else OPEN


def _sends(code: str, bare: str) -> Set[str]:
    out: Set[str] = set()
    for m in _SEND.finditer(bare):
        if len(out) >= MAX_CHANNELS:
            break
        out.add(_channel(code, m.end()))
    for m in _EXPOSE.finditer(bare):                        # the channel object itself is handed on
        close = _close(bare, m.end() - 1)
        if close > 0 and _RAW_IPC.search(bare, m.end(), close):
            out.add(OPEN)
    return out


def _handles(code: str, bare: str) -> Set[str]:
    """The channels of ``ipcMain.on`` / ``handle`` whose handler reaches a sink."""
    out: Set[str] = set()
    for m in _HANDLE.finditer(bare):
        if len(out) >= MAX_CHANNELS:
            break
        close = _close(bare, bare.rfind("(", 0, m.end()))
        if close < 0:
            continue
        body = bare[m.end():close]
        direct = _SINK.search(body) is not None
        if not direct:
            # a handler that is a name, or that calls one function of the script: its body
            for name in re.findall(r"(?<![\w$.])(%s)\s*\(" % _ID, body)[:6] + re.findall(r",\s*(%s)\s*\Z" % _ID, body):
                f = re.compile(r"(?<![\w$.])(?:async\s+)?(?:function\s+%s\s*\(|(?:const|let|var)\s+%s\s*=\s*(?:async\s*)?"
                               r"(?:function\b|\())" % (re.escape(name), re.escape(name))).search(bare)
                if f:
                    brace = bare.find("{", f.end())
                    end = _close(bare, brace) if brace >= 0 else -1
                    if end > 0 and _SINK.search(bare, brace, end):
                        direct = True
                        break
        if direct:
            out.add(_channel(code, m.end()))
    return out


def defaults(version: str) -> Optional[Tuple[bool, bool, bool]]:
    """``(nodeIntegration, contextIsolation, sandbox)`` as Electron ``version`` sets them
    when a window does not say (None: no version)."""
    m = re.match(r"(\d+)\.", version or "")
    if not m:
        return None
    major = int(m.group(1))
    return major < 5, major >= 12, major >= 20


def judge(window: Window, version: str, scripts: Dict[str, Script], ipc=None) -> Tuple[str, str]:
    """``(what the page's scripts can reach, why)`` for a page shown in ``window`` of an app
    with Electron ``version`` ("": not known) whose scripts are ``scripts`` (file name ->
    what :func:`read` found). ``ipc``: what the app's main process does with the pages'
    messages (``electron_ipc.Reading``; None: not read) - a preload script that hands the page
    a message channel of its choice still leaves it shut in when no message handler passes a
    message's data to a program start, a code load, the shell's open or a written file that is
    started (phageo, 2026-10-15, forty-eighth message)."""
    preset = defaults(version)
    node, isolation, sandbox = window.node, window.isolation, window.sandbox
    if node is None:
        node = preset[0] if preset else UNKNOWN
    if isolation is None:
        isolation = preset[1] if preset else UNKNOWN
    if sandbox is None:
        sandbox = (preset[2] and node is not True) if preset else UNKNOWN
    if node is True:
        return EXPOSED, NODE_ON
    if isolation is False:
        return EXPOSED, "contextIsolation is off"
    if UNKNOWN in (node, isolation):
        return UNKNOWN, "its settings are not written out" + ("" if preset else " and the Electron version is not known")
    if not window.preload:
        return SHUT_IN, "no Node.js in the page, isolated, no preload script"
    if window.preload == UNKNOWN:
        return UNKNOWN, "it has a preload script whose file is not named"
    found = [script for name, script in scripts.items()
             if name.replace("\\", "/").lower().endswith("/" + window.preload.lower())
             or name.lower().split("!")[-1] == window.preload.lower()]
    if not found:
        return UNKNOWN, "its preload script %s was not found" % window.preload
    handled = set().union(*[script.handles for script in scripts.values()]) if scripts else set()
    worst = (SHUT_IN, "its preload script %s hands the page nothing that reaches a sink" % window.preload)
    for script in found:
        if not script.exposes:
            continue                                        # isolated, and nothing is handed over
        if script.sink:
            state = (EXPOSED if sandbox is False else BRIDGED,
                     "its preload script %s hands the page functions and starts programs, runs text or writes files"
                     % window.preload)
        elif OPEN in script.sends:
            state = (BRIDGED, "its preload script %s hands the page a message channel of its choice" % window.preload)
            if ipc is not None and ipc.contained:
                if worst[0] == SHUT_IN:
                    worst = (SHUT_IN, "%s; %s" % (state[1], MESSAGES_KEPT % len(ipc.handlers)))
                continue
            if ipc is not None:
                h = ipc.first()
                state = (BRIDGED, "%s; %s" % (state[1], MESSAGE_REACHES % (h.channel, h.file.replace("\\", "/").rsplit(
                    "/", 1)[-1].rsplit("!", 1)[-1], h.line, h.why) if h else MESSAGES_UNREAD % ipc.why))
        elif script.sends & handled or (script.sends and OPEN in handled):
            state = (BRIDGED, "its preload script %s hands the page a message whose handler starts programs, "
                              "runs text or writes files" % window.preload)
        else:
            continue
        if _ORDER[state[0]] > _ORDER[worst[0]]:
            worst = state
    return worst


def worst(states: Iterable[Tuple[str, str]]) -> Tuple[str, str]:
    """The most open of several answers (no window at all: not known)."""
    out = None
    for state in states:
        if out is None or _ORDER[state[0]] > _ORDER[out[0]]:
            out = state
    return out or (UNKNOWN, "no window of the app was found")
