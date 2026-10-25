"""Remote code execution in JavaScript: does what runs come from the network?

The attack chains in :mod:`gamescan.chains` put signals together that sit near
each other. That says nothing in a minified file (everything is on one line),
and it needs an obfuscation signal that a plain downloader does not have. This
module answers that directly, by following the data:

``source``  a network request - ``XMLHttpRequest``, ``fetch``, Node's ``http`` /
            ``https``, ``request``, ``axios``, jQuery, ``WebSocket``
``flow``    the response travels through variables, callbacks, promise chains,
            ``return`` values, arrays, ``Blob`` / object URLs
``sink``    ... and is executed: ``eval``, ``new Function``, ``vm``, a script
            element, ``importScripts``, ``import()``, a ``Worker``,
            ``WebAssembly``, a ``child_process`` command, or a file that is
            written to disk and then started or ``require``d (a dropper)

A script element, ``importScripts``, ``import()`` or a ``Worker`` whose address
is remote is reported as well: there the address *is* the code.

What decides is the address the request goes to:

* remote (``http://``, ``https://``, ``//host`` ...) or decoded - reported;
* not resolvable (a value that only exists at runtime) - reported, because a
  downloader whose address cannot be read is no better than one that shows it;
* a file of the game itself (``"data/Map001.json"``, ``__dirname + ...``) - not
  a download, nothing is reported.

``WebAssembly`` is the one exception: it is only reported for a remote or
decoded address. Every Emscripten-built library loads the ``.wasm`` file next
to it through an address it is handed at runtime, and a WebAssembly module can
only call what the page gives it.

Like the rest of the JavaScript resolver this is a tracer, not a parser:
scope is judged by braces and names. Nothing is executed.
"""
from __future__ import annotations
from ..indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/dataflow/remote.py")

import bisect
import json
import re
import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from ..rules import _MASKS, QuotedText, _MAX_PLACES, find_all as _find, quoted_text, shared, text_places
from . import values as V
from .textflow import JS_MAX_SOURCE as MAX_SOURCE, TextFlow
from .values import Budget, Clock, Sym, show

MAX_STEPS = 600_000             # character / occurrence steps of the flow analysis per file
MAX_SECONDS = V.SAFETY_SECONDS  # a far safety cap only (the steps are the limit); it makes the note too
_MAX_FUNCTIONS = 60_000
_MAX_OCCURRENCES = 2_000        # uses of one tainted name that are followed
_MAX_TAINTS = 3_000
_MAX_SITES = 4_000              # sources / sinks of one kind that are looked at
_MAX_HITS = 8
_MAX_WEAK = 4
_BACK = 8_000                   # how far an expression is followed to its start
_LOAD_TEXT_STEPS = 20_000       # steps of its own for where the text of a blob: / data: load comes from
_TEXT_LOADERS = frozenset({"import", "new Worker", "new SharedWorker", "importScripts"})
_DIRECT_SEARCHES = 24           # names whose uses are searched one by one, before the file is indexed
_MANY_PLACES = 10_000           # places of a path's first word above which a search is cheaper

REMOTE, HIDDEN, UNRESOLVED, LOCAL = "remote", "decoded", "unresolved", "local"
_RANK = {REMOTE: 3, HIDDEN: 2, UNRESOLVED: 1, LOCAL: 0}

_ID = r"[A-Za-z_$][\w$]*"
_IDENT = re.compile(_ID)
_WORD = re.compile(r"(?<![\w$.])" + _ID)
_NAME_ONLY = re.compile(_ID + r"\Z")
_PATH_ONLY = re.compile(r"(?:this|%s)(?:\.%s)+\Z" % (_ID, _ID))
_TARGET = re.compile(r"((?:this|%s)(?:\s*(?:\.\s*%s|\[[^\[\]]*\]))*)\s*\Z" % (_ID, _ID))
_BRACKETS = re.compile(r"[()\[\]{}]")
_BLANKS = re.compile(r"[ \t\r\n]*")
_WORD_CHAR = re.compile(r"[\w$]")
_BEFORE_WORD = re.compile(r"[\w$.]")
# a remote address written out in the code; XML namespaces and this PC are not downloads
_WRITTEN = re.compile(r"""https?://(?!www\.w3\.org\b|localhost\b|127\.0\.0\.1\b|\[::1\])[\w-]+[^\s"'`<>)\\]*""", re.I)
_FACT = re.compile(r"\s*\.\s*(?:length|byteLength|size|status|statusText|readyState|ok|headers|redirected)\b(?!\s*\()")
_REMOTE = re.compile(r"\s*(?:(?:https?|wss?|ftp)\s*:\s*/?/|//)", re.I)
# the game's own location: an address built on these stays inside the game folder
_OWN = re.compile(r"(?:__dirname|__filename|document\.(?:currentScript|baseURI|URL)|process\.(?:cwd|execPath"
                  r"|mainModule)|nw\.App\.|location\.(?:href|origin|pathname|host|hostname|protocol)"
                  r"|require\.main|import\.meta)")
_CONTROL = frozenset("if for while switch catch with function return typeof".split())
# words of the language: never a name that carries a mark (phageo, 2026-10-14 - `x = void 0` had
# made `void` a marked "name", and every later `... = void 0` carried the mark on)
_KEYWORDS = frozenset("""void typeof await new delete undefined null true false this in instanceof return yield
function class const let var if else for while do switch case default break continue throw try catch finally with
super extends import export NaN Infinity""".split())
# programs that run what they are given: a marked argument of one of these is a marked command
_INTERPRETERS = frozenset(_IND[0].split())
_JS_RUNTIMES = frozenset({"node", "nodejs", "electron"})    # read what they run as JavaScript
_STRINGIFY = re.compile(r"(?<![\w$.])JSON\s*\.\s*stringify\s*\(")
_CODE_FLAG = re.compile(r"""["'`](?:-e|--eval|-p|--print)["'`]""")   # ... given as code text
_SHELL_OPTION = re.compile(r"(?<![\w$.])shell\s*:(?!\s*(?:false|!1|0|null|undefined|void)\b)")
_COLLECT = frozenset("push unshift add append set concat".split())
_NET_MODULES = r"https?|http2|request|request-promise|axios|got|node-fetch|needle|superagent|undici"
_SPAWN = r"exec|execSync|spawn|spawnSync|execFile|execFileSync|fork"
_SPLIT_START = frozenset({"spawn", "spawnSync", "execFile", "execFileSync", "fork"})   # program and arguments apart
# -- where the parts of a process start come from (phageo, 2026-10-14) -------------------------------
# Local: the app's own values - its folder, this PC's settings and environment. A start made only
# of these and of written-out text is not steered from outside. Everything else - a parameter,
# what a call returns (a download, a file read, a message from a page), an object's field - is not.
_LOCAL_VALUES = frozenset("""__dirname __filename process.platform process.arch process.execPath
process.resourcesPath os.tmpdir os.homedir os.platform os.arch os.EOL path.sep path.delimiter""".split())
_APP_PATHS = ("app.getPath", "app.getAppPath")       # Electron's folders of the app and of this user
_THROUGH = frozenset("""String Number parseInt parseFloat JSON.stringify encodeURIComponent path.join path.resolve
path.dirname path.basename path.normalize path.relative path.extname path.win32.join path.posix.join""".split())
_NOT_VALUES = frozenset("true false null undefined NaN Infinity typeof void new in of instanceof".split())
_CHAIN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)(\s*\()?")
_KEY = re.compile(r"([{,]\s*)[A-Za-z_$][\w$]*\s*:(?!:)")
_RUN_FIRST = re.compile(r"""\s*["'`]?([^"'`\s]+)""")
# what makes one command line several commands, or feeds one into another: such a line is a
# script for the shell, whatever its first word (phageo, 2026-10-14, forty-second message)
_SHELL_OPERATORS = re.compile(r"[&|;<>`]|\$\(")


def _runtime(command: str) -> bool:
    """Does the command line ``command`` (lower case, as the reading shows it) start a
    script runtime - ``cmd``, ``powershell``, ``node`` ... (``_INTERPRETERS``), the command
    shell named by ``%COMSPEC%``, or the app's own runtime (``process.execPath``)?"""
    m = _RUN_FIRST.match(command)
    if m is None:
        return False
    word = m.group(1)
    if "comspec" in word or "execpath" in word:
        return True
    name = re.split(r"[\\/]", word)[-1]
    return (name[:-4] if name.endswith(".exe") else name) in _INTERPRETERS


def _plain_command(command: str) -> bool:
    """Is the command line ``command`` (as the reading shows it) one plain command for the
    shell: its first word is not a script runtime, and no operator of the shell (``&`` ``|``
    ``;`` ``>`` ``<`` a backtick, ``$(``) stands in what is written out (phageo, 2026-10-14)?
    Only such a line can count as local; one with an operator is a script for the shell."""
    return not _runtime(command) and not _SHELL_OPERATORS.search(V.known_part(command))


def _code_parts(text: str) -> str:
    """``text`` (JavaScript, comments already blanked) with what is written out blanked: the
    inside of strings and the text of templates. A template's ``${...}`` stays: it is code."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(" " * (min(j, n - 1) - i + 1))
            i = j + 1
        elif ch == "`":
            j = i + 1
            out.append(" ")
            while j < n and text[j] != "`":
                if text[j] == "\\":
                    out.append("  ")
                    j += 2
                elif text.startswith("${", j):
                    depth, k = 1, j + 2
                    while k < n and depth:
                        depth += {"{": 1, "}": -1}.get(text[k], 0)
                        k += 1
                    out.append(" (" + _code_parts(text[j + 2:k - 1]) + ")")
                    j = k
                else:
                    out.append(" ")
                    j += 1
            out.append(" ")
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)
_QUIET = frozenset("""path fs os process require __dirname __filename join resolve normalize env tmpdir
String Buffer console JSON Math Object Array this window global nw gui App dataPath homedir basename
dirname sep true false null undefined new var let const function return""".split())

# a parameter list: names, and - since 2026-10-14 - one level of { } for a parameter that is
# taken apart or has an empty object as its default (`(command, args, options = {}) =>`,
# `async run({ id, path })`). Until then such a function was not seen as one, and its
# parameters were taken for the same-named variables of the functions around it.
_PARAMS = r"((?:[^(){};]|\{[^(){};]{0,200}\}){0,400})"
_FUNCTION = re.compile(
    r"(?<![\w$.])function\b\s*\*?\s*(%s)?\s*\(%s\)\s*\{"
    r"|(?<![\w$.])(?:\(%s\)|(%s))\s*=>\s*(\{)?"
    # (... and since 2026-10-15 a method whose name is a number: webpack 5 writes each module of its
    # table as `625764(e, t, n) { ... }`. Until then no module of such a bundle was a function, and
    # the whole bundle was one scope - forty-seventh message)
    r"|(?<![\w$.])(?!(?:if|for|while|switch|catch|with|function|return|typeof|await|new)\b)(%s|\d+)\s*\(%s\)\s*\{"
    % (_ID, _PARAMS, _PARAMS, _ID, _ID, _PARAMS))
_ARROW = re.compile(r"=>")
_BODY = re.compile(r"\)\s*\{")
# what declares a name (RemoteFlow._own_names)
_DECLARE = re.compile(r"(?<![\w$.])(?:var|let|const)\b(?![$])(?=\s*[\[{A-Za-z_$])\s*")
_CATCH_NAME = re.compile(r"(?<![\w$.])catch\s*\(\s*(%s)\s*\)" % _ID)
_CLASS_NAME = re.compile(r"(?<![\w$.])class\s+(%s)" % _ID)
_STOPS = re.compile(r"[()\[\]{},;\n]")


def _functions_in(bare: str):
    """The matches of ``_FUNCTION`` in ``bare``, as ``finditer`` gives them (phageo, 2026-10-15:
    the searches where a match can begin). A function begins with ``function``, at the ``(`` or
    the name in front of ``=>``, or at the name in front of ``( ... ) {``; the pattern is tried
    only there - the search over the whole text tried it at every character (7 s of a 19 MB
    bundle). What stands between the brackets holds no bracket, so the ``(`` is the last one
    before the ``)``."""
    if len(bare) < 64 * 1024:
        yield from _FUNCTION.finditer(bare)
        return
    from .textflow import _id_start, _matched
    places = text_places(bare)
    where = places._where("function") if places._ready() else None
    if where is None or len(where) > _MAX_PLACES:
        yield from _FUNCTION.finditer(bare)
        return
    found = set(where)

    def opening(close: int) -> int:
        return bare.rfind("(", max(0, close - 81_000), close)

    for m in _ARROW.finditer(bare):
        k = m.start() - 1
        while k >= 0 and bare[k].isspace():
            k -= 1
        if k < 0:
            continue
        if bare[k] == ")":
            p = opening(k)
            if p >= 0:
                found.add(p)
        else:
            k = _id_start(bare, k)
            if k >= 0:
                found.add(k)
    for m in _BODY.finditer(bare):
        p = opening(m.start())
        k = p - 1
        while k >= 0 and bare[k].isspace():
            k -= 1
        end = k
        k = _id_start(bare, k) if k >= 0 and p >= 0 else -1
        if k < 0 and p >= 0 and end >= 0 and bare[end].isdigit():
            k = end                                         # a method named by a number (webpack 5)
            while k > 0 and bare[k - 1].isdigit():
                k -= 1
        if k >= 0:
            found.add(k)
    yield from _matched(_FUNCTION, bare, found)


_ACCESS = re.compile(r"\.\s*(?:responseText|responseXML|responseBody|responseStream|response)\b(?!\s*=(?!=))")
_XHR_OPEN = re.compile(r"\.\s*open\s*\(")
_NET_ALIAS = re.compile(r"""(?<![\w$.])(%s)\s*=\s*(?:nw\s*\.\s*)?require\s*\(\s*['"](?:node:)?(?:%s)['"]\s*\)(?!\s*\.)"""
                        % (_ID, _NET_MODULES))
_NET_INLINE = re.compile(r"""(?<![\w$.])(?:nw\s*\.\s*)?require\s*\(\s*['"](?:node:)?(%s)['"]\s*\)"""
                         r"""(?:\s*\.\s*(?:get|post|put|request))?\s*\(""" % _NET_MODULES)
_NET_CALL = re.compile(r"(?<![\w$.])fetch\s*\(|(?<![\w$])(?:window|self|globalThis)\s*\.\s*fetch\s*\("
                       r"|(?<![\w$.])(?:\$|jQuery)\s*\.\s*(?:get|post|ajax|getJSON)\s*\("
                       r"|(?<![\w$.])axios(?:\s*\.\s*(?:get|post|request))?\s*\("
                       r"|(?<![\w$.])new\s+(?:WebSocket|EventSource)\s*\(")
_CP_ALIAS = re.compile(r"""(?<![\w$.])(%s)\s*=\s*(?:nw\s*\.\s*)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)(\s*\.\s*(?:%s)\b)?"""
                       % (_ID, _SPAWN))
_CP_UNPACK = re.compile(r"""\{([^{}=;]{1,200})\}\s*=\s*(?:nw\s*\.\s*)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)""")
_CP_INLINE = re.compile(r"""(?<![\w$.])(?:nw\s*\.\s*)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.\s*(?:%s)\s*\("""
                        % _SPAWN)
_CODE_SINK = re.compile(
    r"(?<![\w$.])eval\s*\(|(?<![\w$])(?:window|self|globalThis|global|this)\s*\.\s*eval\s*\("
    r"|\(\s*0\s*,\s*eval\s*\)\s*\(|(?<![\w$.])(?:new\s+)?Function\s*\("
    r"|\.\s*(?:runInThisContext|runInNewContext|runInContext|globalEval)\s*\("
    r"|(?<![\w$.])new\s+(?:%s\s*\.\s*)?Script\s*\(|(?<![\w$.])execScript\s*\(" % _ID)
_NAMED_SINK = re.compile(r"""\[\s*(["'])(eval|Function)\1\s*\]\s*\(""")
_BUILT_SINK = re.compile(r"\[(?=[^\]\n]{1,300}\]\s*\()")
_THEN_EVAL = re.compile(r"\.\s*then\s*\(\s*(?:window\s*\.\s*)?eval\s*\)")
_WASM_SINK = re.compile(r"""(?<![\w$.])WebAssembly\s*(?:\.\s*|\[\s*["'])(instantiateStreaming|instantiate"""
                        r"""|compileStreaming|compile|Module)(?:["']\s*\])?\s*\(""")
_LOADER = re.compile(r"(?<![\w$.])importScripts\s*\(|(?<![\w$.])import\s*\(|(?<![\w$.])new\s+(?:Shared)?Worker\s*\("
                     r"|(?<![\w$.])(?:\$|jQuery)\s*\.\s*getScript\s*\(")
# jQuery's other ways of fetching a script and running it (phageo, 2026-10-20, seventy-third message):
# ``$(...).load(address)`` (the scripts of the page it fetches are run) and ``$.ajax({..., dataType:
# "script"})`` - counted only with an address that is remote, decoded or a download's answer
_JQ_LOAD = re.compile(r"(?<![\w$.])(?:\$|jQuery)\s*\([^()\n]{0,200}\)\s*\.\s*load\s*\(")
_JQ_AJAX = re.compile(r"(?<![\w$.])(?:\$|jQuery)\s*\.\s*ajax\s*\(\s*\{")
_JQ_SCRIPT_TYPE = re.compile(r"""(?<![\w$.])dataType\s*:\s*["']script["']""")
_JQ_URL = re.compile(r"(?<![\w$.])url\s*:")
_SCRIPT_NEW = re.compile(r"""(?<![\w$.])((?:this\.)?%s)\s*=\s*[\w$.\s]{0,60}?\.\s*createElement\s*\(\s*["'](?i:script)["']\s*\)"""
                         % _ID)
_WRITE = re.compile(r"(?<![\w$])(writeFileSync|writeFile|appendFileSync|appendFile)\s*\(")
_STREAM = re.compile(r"createWriteStream\s*\(")
_PIPE = re.compile(r"\.\s*pipe\s*\(")
_LAUNCH = re.compile(r"\.\s*(?:openItem|openPath|openExternal)\s*\(|(?<![\w$.])require\s*\("
                     r"|(?<![\w$.])process\s*\.\s*dlopen\s*\(|(?<![\w$.])new\s+Worker\s*\(")
_HINT = re.compile(r"eval|Function|WebAssembly|importScripts|import\s*\(|Worker|createElement|writeFile"
                   r"|appendFile|createWriteStream|Context\s*\(|getScript|child_process|Script\s*\("
                   r"|\]\s*\(|SaveToFile|ActiveXObject|CreateTextFile|OpenTextFile|\.\s*load\s*\(|dataType")
_NET_HINT = re.compile(r"XMLHttpRequest|fetch|https?|axios|request|WebSocket|EventSource|\$\.|jQuery|\bgot\b"
                       r"|needle|superagent|undici|response|ActiveXObject|XMLHTTP|WinHttp")
# JScript under the Windows Script Host: objects by name, files that are written, programs that are started
_WSH_NEW = re.compile(r"(?<![\w$.])(?:new\s+ActiveXObject|WScript\s*\.\s*CreateObject)\s*\(")
_WSH_NAMED = re.compile(r"(?<![\w$.])(%s)\s*=\s*\Z" % _ID)
_WSH_START = _IND[1]
_WSH_SAVE = re.compile(r"(?<![\w$.])(%s)\s*\.\s*SaveToFile\s*\(" % _ID)
_WSH_FILE = re.compile(r"\.\s*(?:CreateTextFile|OpenTextFile)\s*\(")
_WSH_KINDS = {"wscript.shell": "WScript.Shell", "shell.application": "Shell.Application"}
# -- the file of a download, followed to a start (phageo, 2026-10-14, forty-second message) ----------
_PIPELINE = re.compile(r"(?<![\w$])pipeline\s*\(")
_CALLBACK = re.compile(r"(?:async\s+)?(?:function\b|\([^()]{0,300}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
# a check of a file's signature (phageo, 2026-10-15, two messages): a real crypto verification -
# PowerShell's Get-AuthenticodeSignature in a command the script starts, WinVerifyTrust, the
# check of a verified updater library (``RemoteFlow.updater``), or the verify call of a crypto
# library - openpgp.verify, node's crypto.verify / createVerify(...).verify - with a public key
# written out in the app (not fetched at run time). A function only named like a check
# (verifySignature, checkSignature ...) is no such check. It counts only where the start is
# reached on its success alone: in the branch of a condition that holds only when the check
# passed, behind ``if (...) return / throw`` that leaves on its failure, or behind a check that
# throws when it fails - never on the failure branch (RemoteFlow._checked, _sense).
_OS_CHECK = re.compile(r"Get-AuthenticodeSignature|WinVerifyTrust", re.I)
_UPDATER_CHECK = re.compile(r"(?<![\w$])(?:verifySignature|verifyUpdateCodeSignature)\s*\(")
UPDATER_PACKAGES = ("electron-updater",)        # the verified updater libraries (npm package names)
_CRYPTO_CHECK = re.compile(r"(?<![\w$])verify\s*\(")
_BOUND = (r"(?<![\w$.])(?:const|let|var)\s+(%s)\s*=\s*require\s*\(\s*([\"'])(?:node:)?%s\2\s*\)"
          r"|(?<![\w$.])import\s+(?:\*\s+as\s+)?(%s)\s+from\s+([\"'])(?:node:)?%s\4")
_PGP_BOUND = re.compile(_BOUND % (_ID, "openpgp", _ID, "openpgp"))
_NODE_BOUND = re.compile(_BOUND % (_ID, "crypto", _ID, "crypto"))
_KEY_WRAP = re.compile(r"(?:\A|\.)(?:readKey|readKeys|createPublicKey|from)\Z")
_KEY_MIN = 64                   # characters of a public key written out (a shorter text is no key)
_TOP_OPS = re.compile(r"&&|\|\||[!=]==?|>=|<=|(?<![=!<>])[<>](?!=)")
_LITERAL = {"true": True, "!0": True, "false": False, "!1": False, "null": None, "undefined": None,
            "void 0": None, "0": 0, "-1": -1, '""': "", "''": ""}
_PROCESS_CALL = re.compile(r"(?:\A|\.)(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|execAsync"
                           r"|execFileAsync|execa|execaSync)\Z")
_IF = re.compile(r"(?<![\w$.])if\s*\(")
_ANSWER_TO = re.compile(r"(?:(?<![\w$.])(?:const|let|var)\s+)?(\{[^{}=;]{0,300}\}|\[[^\[\]=;]{0,300}\]|%s)"
                        r"\s*=\s*(?:await\s+)?\Z" % _ID)
_DERIVED = re.compile(r"(?:(?<![\w$.])(?:const|let|var)\s+(\{[^{}=;]{0,300}\}|\[[^\[\]=;]{0,300}\])"
                      r"|(?<![\w$.])(%s))\s*=(?![=>])" % _ID)
# ... and the check's own start of PowerShell, which reads the file and starts nothing of it: a
# constant command that is only Get-AuthenticodeSignature, the one part not written out a quoted
# value (the file's path) - RemoteFlow._only_check
_CHECK_ONLY = re.compile(
    r"\A\s*[\"']?(?:[A-Za-z]:)?(?:[\w .()-]*[\\/])*(?:powershell|pwsh)(?:\.exe)?[\"']?"
    r"(?:\s+-(?:NoProfile|NonInteractive|NoLogo|ExecutionPolicy\s+(?:Bypass|RemoteSigned|Unrestricted)"
    r"|InputFormat\s+None|OutputFormat\s+Text|Command|c))*\s+"
    r"(?P<q0>[\"']?)\s*(?:\(\s*)?Get-AuthenticodeSignature(?:\s+-(?:FilePath|LiteralPath))?\s+(?P<q>[\"'])‹[^‹›]*›(?P=q)"
    r"\s*\)?(?:\s*\.\s*Status(?:\s*\.\s*ToString\(\))?|\s*\|\s*ConvertTo-Json(?:\s+-Compress)?"
    r"|\s*\|\s*Select-Object\s+(?:-ExpandProperty\s+)?\w+(?:\s*,\s*\w+)*)?\s*(?P=q0)\s*;?\s*\Z", re.I)
_MAX_CHECKS = 64                # signature checks of one file that are looked at
_GATE_REACH = 20_000            # characters from a check within which its answer is followed
_PATH_DEPTH = 10                # hand-overs followed back from one start
_PATH_TOTAL = 4_000             # expressions looked at for all starts of one file (then the limit note)
_PATH_STARTS = 400              # starts of one file whose arguments are followed
_PATH_REACH = 4_097              # characters of an expression that are measured (a longer one is no path)
_THIS_FIELD = re.compile(r"(?<![\w$.])this\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?![=>])")
_CALL_NAME = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")
_PATH_WAYS = 8                  # ways from downloads to one start that are collected
# a marker file written after a signature check and read before a start (RemoteFlow._gated)
_MARKER_GUARD = re.compile(
    r"(?<![\w$.])if\s*\(\s*(?P<root>[A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*){0,3}\s*"
    r"(?:(?P<not>!==?)|===?)\s*(?P<q>[\"'`])(?P<value>[\w.-]{1,40})(?P=q)\s*\)\s*"
    r"(?:(?P<ret>(?:\{\s*)?return\b)|(?P<block>\{))")
_MARKER_READ = re.compile(r"(?<![\w$])readFile(?:Sync)?\s*\(")
_MARKER_BRANCH = re.compile(r"(?<![\w$.])if\s*\(\s*([A-Za-z_$][\w$]*)\s*(?:===?\s*(?:true|!0)\s*)?\)\s*\{")
# a branch that leaves its function at its end: `return ...` / `throw ...` as its last statement
_LEAVES = re.compile(r"(?:\A|[;}]\s*|\n\s*)(?:return|throw)\b[^;{}]*;?\s*\Z")
_FLAG_BRANCH = re.compile(r"(?<![\w$.])if\s*\(\s*(!\s*)?([A-Za-z_$][\w$]*)\s*\)")
_MARKER_PLAIN = frozenset({"writeFileSync", "writeFile"})
_MARKER_MOVES = frozenset({"copyFileSync", "copyFile", "renameSync", "rename", "cpSync", "cp", "linkSync", "symlinkSync"})
_MARKER_WRITES = tuple(sorted(_MARKER_PLAIN | _MARKER_MOVES | {"appendFileSync", "appendFile", "createWriteStream",
                                                               "openSync", "open"}))


class _Download(NamedTuple):
    pos: int
    key: str                    # the path as read (_path_key; "": not read)
    name: str                   # the path argument, when it is one name
    scope: Tuple[int, int]      # ... and where that name lives
    src: "Source"
    shown: str                  # how the path is shown in the finding


def _path_key(value: Any) -> str:
    """A read file path in one form - ``/`` for ``\\``, lower case, no quotes ("": not a path
    whose file name is known)."""
    if not isinstance(value, (str, Sym)):
        return ""
    key = re.sub(r"[\\/]+", "/", show(value).strip().strip("\"'`")).lower()
    base = key.rsplit("/", 1)[-1]
    return key if len(base) >= 3 and not V.is_partial(base) else ""


def _same_file(a: str, b: str) -> bool:
    """Two read paths name the same file: the same path, or the same file name with an
    ending (``x.exe``) - as the start of a dropper is matched by its file's name."""
    if a == b:
        return True
    base = a.rsplit("/", 1)[-1]
    return base == b.rsplit("/", 1)[-1] and "." in base.strip(".")


@dataclass
class Source:
    """One network request."""

    what: str                   # XMLHttpRequest, fetch, https.get ...
    pos: int
    kind: str                   # remote | decoded | unresolved | local
    address: str                # resolved text; ‹name› marks runtime-only parts
    literal: bool = False       # it went through JSON.stringify on the way: a JavaScript literal


def _strength(src: Source) -> Tuple[int, bool]:
    """Which of two marks counts: the kind of request first, then a mark that is not only a
    JSON literal before one that is (phageo, 2026-10-14)."""
    return _RANK[src.kind], not src.literal


@dataclass
class Hit:
    """Something that is executed and came from the network."""

    how: str                    # code | command | argument | wasm | loader | dropper
    line: int                   # where it is executed
    sink: str                   # eval, new Function, script.src, child_process.exec ...
    source: str                 # the request ("" when the sink loads the address itself)
    source_line: int
    kind: str                   # remote | decoded | unresolved
    address: str
    detail: str = ""            # dropper: the file that is written
    weak: bool = False          # the address is not resolved, and only the file's other
    seen: str = ""              # content (a remote address in its code: ``seen``) speaks against it
    route: str = ""             # dropper found by following the file's path: the hand-overs on its way
    checked: bool = False       # a signature check stands on the way, before the file is handed on or started
    ways: int = 0               # route: the ways from a download to this start that were found
    checked_ways: int = 0       # ... and those of them with a signature check
    local: bool = False         # a weak import(): every part of its address is the app's own (RemoteFlow._local)
    text_from: str = ""         # a load of a blob: / data: URL whose text no download reaches: "app" (_import_text);
    #                             "local": its text was followed back to written-out text and the app's own values
    checks: Tuple[str, ...] = ()    # the kinds of signature check the file's checked starts rely on (_checked)
    folder: str = ""            # dropper reached through a folder, not the file's own path: the start's
    #                             working folder holds the file, or the started program lies beside it
    #                             (remote_py; phageo, 2026-10-18) - "working folder" / "program's folder"


class _Function:
    __slots__ = ("start", "name", "params", "a", "b", "parent", "method")

    def __init__(self, start: int, name: str, params: List[str], a: int, b: int, method: bool) -> None:
        self.start, self.name, self.params, self.a, self.b = start, name, params, a, b
        self.parent: Optional["_Function"] = None
        self.method = method


class _Parse:
    """What the readings of one JavaScript text find out about the text alone: where each
    bracket closes, its functions, which function declares which name, where every name
    stands. Filled as they ask for it, shared by every reading of the same text (rules.shared;
    phageo, 2026-10-14, forty-second message). None of it counts steps."""

    __slots__ = ("closing", "scopes", "homes", "functions", "words", "by_name", "calls", "fields", "own", "bindings")

    def __init__(self) -> None:
        self.closing: Dict[int, int] = {}
        self.scopes: Dict[Tuple[int, str], bool] = {}
        self.own: Optional[Dict[int, set]] = None          # function body start (-1: the text) -> names it declares
        self.bindings: Dict[Tuple[int, str], Tuple[int, int]] = {}     # (innermost function, name) -> its binding
        self.homes: Dict[int, Tuple[int, int, str]] = {}
        self.functions: Optional[tuple] = None              # (functions, body starts, by head, heads)
        self.words: Optional[Dict[str, List[int]]] = None
        self.by_name: Optional[Dict[str, List[_Function]]] = None
        self.calls: Optional[Dict[str, List[Tuple[int, int]]]] = None      # name -> (start, "(") of its calls
        self.fields: Optional[Dict[str, List[Tuple[int, int]]]] = None     # x -> where this.x is given a value


class RemoteFlow:
    def __init__(self, text: str, updater: bool = False) -> None:
        # updater: the text is a file of a verified updater library (UPDATER_PACKAGES) - its
        # own check of a download's signature counts as a check (_checked)
        self.updater = updater
        self._checks: Optional[List[Tuple[int, str]]] = None    # signature checks of the text (_check_places)
        self._gate_memo: Dict[Tuple[int, int], bool] = {}
        self.relied: set = set()        # kinds of check a start was found behind: os, call, pgp, node
        self.flow = TextFlow(text[:MAX_SOURCE], "js", Clock())
        self.size, self.cut = len(text), ""                 # cut: the limit the reading stopped at
        self.code = self.flow.code                          # comments blanked
        # ... and what is inside strings
        self.bare = shared("bare", self.code, lambda: _MASKS["c"].sub(_blank, self.code))
        self.n = len(self.bare)
        self.clock = Clock(MAX_STEPS, MAX_SECONDS)
        self._parse = parse = shared("functions", self.bare, _Parse)
        self.functions: List[_Function] = []
        self._starts: List[int] = []                        # body starts, ascending
        self._heads: List[int] = []                         # where each function begins, ascending
        self._by_head: List[_Function] = []
        self._closing: Dict[int, int] = parse.closing
        self._scopes: Dict[Tuple[int, str], bool] = parse.scopes
        self.names: Dict[str, List[Tuple[int, int, Source, bool]]] = {}
        self.paths: Dict[str, List[Tuple[int, int, str, Source, bool]]] = {}
        self.wholes: Dict[str, List[Tuple[int, int, Source]]] = {}      # objects with a marked property
        self._homes: Dict[int, Tuple[int, int, str]] = parse.homes
        self.spans: List[Tuple[int, int, Source]] = []      # expressions that are a response
        self._span_starts: List[int] = []
        self._work: List[Tuple[str, str, int, int, Source, bool, str]] = []
        self._taints = 0
        self._searches = 0
        self._words: Optional[Dict[str, List[int]]] = parse.words   # every name -> where it stands (_uses)
        self.opens: List[Tuple[int, str, Source]] = []
        self.hits: List[Hit] = []
        self.weak: List[Hit] = []                           # kept apart: they never crowd out a hit
        self._literal: Optional[str] = None
        self._quoted: Optional[QuotedText] = None           # the quoted texts of the script (_feeding_texts)
        self._cp_methods: Dict[str, str] = {}               # a name given a child_process function -> which one
        self._by_name: Optional[Dict[str, List[_Function]]] = parse.by_name    # functions by the name they are called by
        self._markers: Dict[tuple, Any] = {}                # guards on marker files and what they rest on (_gated)

    # -- text helpers ----------------------------------------------------------------
    def _real(self, pos: int) -> bool:
        """Is ``pos`` code (and not the inside of a string)?"""
        return self.bare[pos:pos + 1] == self.code[pos:pos + 1]

    def _ws(self, pos: int) -> int:
        # (a whole run of blanks at once: the inside of a long string is blanks here - stepped
        # over one character at a time it was most of the time of a large bundle's reading)
        bare, n = self.bare, self.n
        if pos < 0:
            while pos < n and bare[pos] in " \t\r\n":
                pos += 1
            return pos
        if pos >= n or bare[pos] not in " \t\r\n":
            return pos
        return _BLANKS.match(bare, pos).end()

    def _back(self, pos: int) -> int:
        bare = self.bare
        if pos < 0 or bare[pos] not in " \t\r\n":
            return pos
        for _ in range(64):                                   # (most runs are short)
            pos -= 1
            if pos < 0 or bare[pos] not in " \t\r\n":
                return pos
        while pos >= 0:
            start = max(0, pos - 4095)
            kept = bare[start:pos + 1].rstrip(" \t\r\n")
            if kept:
                return start + len(kept) - 1
            pos = start - 1
        return -1

    def _close(self, opener: int) -> int:
        """Position of the bracket that closes the one at ``opener`` (-1: none)."""
        found = self._closing.get(opener)
        if found is not None:
            return found
        depth, out = 0, -1
        for m in _BRACKETS.finditer(self.bare, opener, min(self.n, opener + 400_000)):
            if m.group(0) in "([{":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    out = m.start()
                    break
        self._closing[opener] = out
        return out

    def _open(self, closer: int) -> int:
        """Position of the bracket that the one at ``closer`` closes (-1: none)."""
        depth, bare = 0, self.bare
        i, floor = closer, max(0, closer - 400_000)
        while i >= floor:
            ch = bare[i]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                depth -= 1
                if depth == 0:
                    return i
            i -= 1
        return -1

    def _expr_end(self, pos: int, reach: int = 200_000) -> int:
        """End of the expression that starts at ``pos`` (looked for ``reach`` characters far)."""
        bare, depth = self.bare, 0
        i, limit = pos, min(self.n, pos + reach)
        while i < limit:
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    return i
                depth -= 1
            elif depth == 0 and ch in ",;":
                return i
            elif depth == 0 and ch == "\n" and self._line_ends(i):
                return i
            i += 1
        return limit

    def _line_ends(self, newline: int) -> bool:
        """Does a statement end at this line break?"""
        before, after = self._back(newline - 1), self._ws(newline + 1)
        last = self.bare[before] if before >= 0 else ""
        first = self.bare[after:after + 1]
        return last not in "=+-*/%&|^?:,.([{<>!~" and first not in ".?:+-*/%&|^,)]}="

    def _arguments(self, opener: int) -> List[Tuple[int, int]]:
        """``(start, end)`` of each argument of the call whose list opens at ``opener``."""
        close = self._close(opener)
        if close < 0:
            return []
        out, depth, start = [], 0, opener + 1
        for m in re.compile(r"[()\[\]{},]").finditer(self.bare, opener + 1, close):
            ch = m.group(0)
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif depth == 0:
                out.append((start, m.start()))
                start = m.end()
        if self.bare[start:close].strip():
            out.append((start, close))
        return out

    def _callee(self, end: int) -> Tuple[int, str]:
        """The dotted name that ends at ``end``: ``(start, "a.b.c")``; calls and
        index brackets on the way are stepped over."""
        bare, i, parts = self.bare, end, []
        while i >= 0:
            if bare[i] in ")]":
                opener = self._open(i)
                if opener < 0:
                    break
                i = self._back(opener - 1)
                if i < 0 or not (bare[i].isalnum() or bare[i] in "_$)]"):
                    return opener, ".".join(reversed(parts))
                continue
            j = i
            while j >= 0 and (bare[j].isalnum() or bare[j] in "_$"):
                j -= 1
            if j == i:
                break
            parts.append(bare[j + 1:i + 1])
            start = j + 1
            k = self._back(j)
            if k >= 0 and bare[k] == ".":
                i = self._back(k - 1 if bare[k - 1:k] != "?" else k - 2)
                continue
            return start, ".".join(reversed(parts))
        return end + 1, ".".join(reversed(parts))

    # -- functions and scopes -----------------------------------------------------------
    def _find_functions(self) -> None:
        if self._parse.functions is not None:                # (another reading of this text found them)
            self.functions, self._starts, self._by_head, self._heads = self._parse.functions
            return
        found: List[_Function] = []
        for m in _functions_in(self.bare):
            if len(found) >= _MAX_FUNCTIONS:
                break
            if m.group(2) is not None:
                name, params, brace, method = m.group(1) or "", m.group(2), m.end() - 1, False
            elif m.group(7) is not None:
                name, params, brace, method = m.group(6), m.group(7), m.end() - 1, True
            else:
                name, params, method = "", m.group(3) if m.group(3) is not None else m.group(4), False
                brace = m.end() - 1 if m.group(5) else -1
            if brace >= 0:
                a, b = brace + 1, self._close(brace)
                if b < 0:
                    continue
            else:
                a = m.end()
                b = self._expr_end(a)
            found.append(_Function(m.start(), name, _IDENT.findall(params or ""), a, b, method))
        found.sort(key=lambda f: f.a)
        stack: List[_Function] = []
        for f in found:
            while stack and stack[-1].b <= f.a:
                stack.pop()
            f.parent = stack[-1] if stack else None
            stack.append(f)
        self.functions = found
        self._starts = [f.a for f in found]
        self._by_head = sorted(found, key=lambda f: f.start)
        self._heads = [f.start for f in self._by_head]
        self._parse.functions = (self.functions, self._starts, self._by_head, self._heads)

    def _inner(self, pos: int) -> Optional[_Function]:
        """The innermost function whose body contains ``pos``."""
        i = bisect.bisect_right(self._starts, pos) - 1
        f = self.functions[i] if i >= 0 else None
        while f is not None and not f.a <= pos < f.b:
            f = f.parent
        return f

    def _declares(self, f: _Function, name: str) -> bool:
        key = (f.a, name)
        if key not in self._scopes:
            self._scopes[key] = name in f.params or re.compile(
                # (also taken apart: const { data } = ..., let [a, b] = ... - until 2026-10-14 such a
                # name was nobody's, and so the same variable in every function of the file)
                r"(?<![\w$.])(?:var|let|const)\b(?:[^;{}]*?|\s*[\{\[][^;=]{0,300}?)(?<![\w$.])%s(?![\w$])" % re.escape(name)
            ).search(self.bare, f.a, f.b) is not None
        return self._scopes[key]

    def _scope(self, name: str, pos: int) -> Tuple[int, int]:
        """Where the variable ``name`` that is used at ``pos`` lives."""
        f = self._inner(pos)
        while f is not None:
            if self._declares(f, name):
                return f.a, f.b
            f = f.parent
        return 0, self.n

    # -- bindings: which declaration a name stands for (phageo, 2026-10-15, forty-seventh message) ----
    # A mark is kept for one variable - the declaration a name is bound to - not for every name
    # that is spelled the same. In a minified bundle nearly every function has an ``e``, ``t``,
    # ``n``: a mark kept by the name and the stretch of text spread from one of them into the
    # others (98 % of ELE-01's marks were on such names). _scope above stays as it was for the
    # readings that use it (the path tracker, the checks).
    def _own_names(self) -> Dict[int, set]:
        """For every function (by its body's start; -1: the text outside every function) the
        names it declares itself - ``var`` / ``let`` / ``const`` declarators (also taken apart),
        the names of ``function`` declarations and classes in its body, ``catch (e)`` - not
        those of the functions inside it. Read once per text, shared by its readings."""
        own = self._parse.own
        if own is not None:
            return own
        own = {}
        bare = self.bare

        def home(pos: int) -> int:
            f = self._inner(pos)
            return f.a if f is not None else -1

        def keep(name: str, pos: int) -> None:
            if name not in _KEYWORDS:
                own.setdefault(home(pos), set()).add(name)

        for m in _DECLARE.finditer(bare):
            i = m.end()
            for _ in range(256):                            # the declarators of one statement
                i = self._ws(i)
                ch = bare[i:i + 1]
                if ch in ("{", "["):
                    close = self._close(i)
                    if close < 0:
                        break
                    for w in _WORD.finditer(bare, i, close):    # { a, b: c, d = 1 } / [a, , b]
                        after = self._ws(w.end())
                        if bare[after:after + 1] != ":":
                            keep(w.group(0), m.start())
                    i = close + 1
                else:
                    word = _IDENT.match(bare, i)
                    if word is None:
                        break
                    keep(word.group(0), m.start())
                    i = word.end()
                i = self._ws(i)
                if bare[i:i + 1] == "=" and bare[i + 1:i + 2] not in ("=", ">"):
                    i = self._ws(self._initializer_end(i + 1))
                if bare[i:i + 1] != ",":
                    break
                i += 1
        for m in _CATCH_NAME.finditer(bare):
            keep(m.group(1), m.start())
        for m in _CLASS_NAME.finditer(bare):
            keep(m.group(1), m.start())
        for f in self.functions:
            if f.name and not f.method:                     # function name(...) { ... }: its parent's
                own.setdefault(f.parent.a if f.parent is not None else -1, set()).add(f.name)
        self._parse.own = own
        return own

    def _initializer_end(self, pos: int) -> int:
        """Where the value of a declarator that begins at ``pos`` ends: at a ``,`` / ``;`` or a
        closing bracket outside its brackets, or at a line break that ends the statement."""
        bare, n = self.bare, self.n
        while True:
            m = _STOPS.search(bare, pos)
            if m is None:
                return n
            at, ch = m.start(), m.group(0)
            if ch in "([{":
                close = self._close(at)
                if close < 0:
                    return n
                pos = close + 1
            elif ch == "\n" and not self._line_ends(at):
                pos = at + 1
            else:
                return at

    def _binding(self, name: str, pos: int) -> Tuple[int, int]:
        """The scope of the declaration that ``name`` used at ``pos`` is bound to: the innermost
        function around ``pos`` that has it as a parameter or declares it itself (``_own_names``);
        ``(0, n)`` - the text's own, or a name declared nowhere in it. Per function; a block's
        ``let`` / ``const`` counts for its whole function, as in ``_scope``."""
        f = self._inner(pos)
        key = (f.a if f is not None else -1, name)
        found = self._parse.bindings.get(key)
        if found is not None:
            return found
        own = self._own_names()
        out = (0, self.n)
        g = f
        while g is not None:
            if name in g.params or name in own.get(g.a, ()):
                out = (g.a, g.b)
                break
            g = g.parent
        self._parse.bindings[key] = out
        return out

    def _same_variable(self, name: str, pos: int, scope: Tuple[int, int]) -> bool:
        """Is ``name`` at ``pos`` the variable whose binding is ``scope``? (For a dotted path:
        its first name.)"""
        return self._binding(name.split(".", 1)[0], pos) == scope

    # -- addresses ------------------------------------------------------------------------
    def _value(self, pos: int) -> Any:
        """The value of the expression at ``pos`` (None: could not be read)."""
        # (20 000 steps for one expression: a count. The clock is the reading's own emergency
        # brake - not a quarter second of its own, which a busy PC reached; phageo, 2026-10-12)
        clock = self.flow.clock = Clock(20_000, MAX_SECONDS)
        clock.deadline = self.clock.deadline
        del self.flow._trace[:]
        saved, self.flow._paren = self.flow._paren, 1
        try:
            return self.flow.ternary(pos)[0]
        except (Budget, RecursionError, IndexError):
            if clock.steps > 0 and clock.stopped:           # the brake, not the count
                self.cut = V.also(self.cut, clock.stopped)
            return None
        finally:
            self.flow._paren = saved

    def _classify(self, value: Any, pos: int, follow: bool = True) -> Tuple[str, str]:
        """``(kind, address)`` of a request that goes to ``value``."""
        if not isinstance(value, (str, Sym)):
            return UNRESOLVED, ""
        text = show(value).strip()
        if self.flow._is_hidden(value):
            return HIDDEN, text[:300]
        if _REMOTE.match(text):
            return REMOTE, text[:300]
        if not text:
            return UNRESOLVED, ""
        if text.startswith(V.OPEN):
            name = text[1:text.find(V.CLOSE)]
            if _OWN.match(name):
                return LOCAL, text[:300]
            if follow:
                known = self._from_callers(name, pos)
                if known is not None:
                    return known
            return UNRESOLVED, text[:300]
        return LOCAL, text[:300]

    def _from_callers(self, name: str, pos: int) -> Optional[Tuple[str, str]]:
        """``name`` is a parameter: what do the callers of that function pass?"""
        f = self._inner(pos)
        while f is not None and name not in f.params:
            f = f.parent
        if f is None:
            return None
        called = f.name
        if not called:
            m = re.compile(r"(%s)\s*=\s*(?:async\s+)?\Z" % _ID).search(self.bare, max(0, f.start - 80), f.start)
            called = m.group(1) if m else ""
        if not called or len(called) < 2:
            return None
        index, found = f.params.index(name), []
        for m in re.compile(r"(?<![\w$.])%s\s*\(" % re.escape(called)).finditer(self.bare):
            if m.start() == f.start or self.bare[max(0, m.start() - 12):m.start()].rstrip().endswith("function"):
                continue
            arguments = self._arguments(m.end() - 1)
            if len(arguments) <= index or len(found) >= 12:
                return None
            found.append(self._classify(self._value(arguments[index][0]), m.start(), False))
        if not found:
            return None
        worst = max(found, key=lambda k: _RANK[k[0]])
        return worst if worst[0] != UNRESOLVED else None

    def _address(self, opener: int, index: int = 0) -> Tuple[str, str]:
        arguments = self._arguments(opener)
        if len(arguments) <= index:
            return UNRESOLVED, ""
        return self._classify(self._value(arguments[index][0]), opener)

    # -- taint ---------------------------------------------------------------------------
    def _tick(self, cost: int = 1) -> None:
        self.clock.tick(cost)

    def _add(self, name: str, scope: Tuple[int, int], src: Source, call_only: bool = False) -> None:
        if name in _KEYWORDS:
            return
        # (a mark is one variable's: its name and the scope of its binding - since 2026-10-15 an
        # equal scope, not one around it: a name bound further out is another variable)
        held = self.names.setdefault(name, [])
        for a, b, other, only in held:
            if a == scope[0] and scope[1] == b and _strength(other) >= _strength(src) and (
                    not only or call_only):
                return
        if self._taints >= _MAX_TAINTS:
            return
        self._taints += 1
        held.append((scope[0], scope[1], src, call_only))
        self._work.append(("name", name, scope[0], scope[1], src, call_only, ""))

    def _add_whole(self, name: str, pos: int, src: Source) -> None:
        """The object ``name`` holds the response in one of its properties: where the object
        is handed on whole - ``resolve(name)``, ``send(name)``, ``return name`` - it carries
        the mark; ``name.other`` and ``name.method()`` do not."""
        if name in _KEYWORDS or not _NAME_ONLY.match(name):
            return
        scope = self._binding(name, pos)
        held = self.wholes.setdefault(name, [])
        for a, b, other in held:
            if a == scope[0] and scope[1] == b and _strength(other) >= _strength(src):
                return
        if self._taints >= _MAX_TAINTS:
            return
        self._taints += 1
        held.append((scope[0], scope[1], src))
        self._work.append(("whole", name, scope[0], scope[1], src, False, ""))

    def _block(self, pos: int) -> int:
        """The ``{`` of the innermost block around ``pos`` (-1: none)."""
        depth, bare = 0, self.bare
        i, floor = pos - 1, max(0, pos - 400_000)
        while i >= floor:
            ch = bare[i]
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth == 0:
                    return i
                depth -= 1
            i -= 1
        return -1

    def _home(self, pos: int) -> Tuple[int, int, str]:
        """Where ``this`` means the same object as at ``pos``: ``(start, end, owner)``.
        Methods written as ``Owner.prototype.name = function`` share the owner's
        name; methods of a class or of an object literal share its block."""
        first = f = self._inner(pos)
        key = first.a if first else -1
        if key in self._homes:
            return self._homes[key]
        out = (first.a, first.b, "") if first else (0, self.n, "")
        while f is not None:
            before = self.bare[max(0, f.start - 120):f.start]
            m = re.search(r"(%s)\s*\.\s*prototype\s*\.\s*%s\s*=\s*\Z" % (_ID, _ID), before)
            if m:
                out = (f.parent.a, f.parent.b, m.group(1)) if f.parent else (0, self.n, m.group(1))
                break
            if f.method or re.search(r"""[\w$"'\]]\s*:\s*\Z""", before):
                opener = self._block(f.start)
                close = self._close(opener) if opener >= 0 else -1
                if close > 0:
                    out = (opener, close, "")
                    break
            f = f.parent
        self._homes[key] = out
        return out

    def _add_path(self, path: str, pos: int, src: Source, call_only: bool = False) -> None:
        this = path.startswith("this.")
        if this:
            a, b, owner = self._home(pos)
        else:
            (a, b), owner = self._binding(path.split(".")[0], pos), ""
        held = self.paths.setdefault(path, [])
        for x, y, who, other, only in held:
            if (x <= a and b <= y if this else (x, y) == (a, b)) and who == owner and \
                    _strength(other) >= _strength(src) and (not only or call_only):
                return
        if self._taints >= _MAX_TAINTS:
            return
        self._taints += 1
        held.append((a, b, owner, src, call_only))
        self._work.append(("path", path, a, b, src, call_only, owner))

    def _target(self, text: str, pos: int, src: Source) -> None:
        """Something that came from the network is stored in ``text``."""
        text = re.sub(r"\s+", "", text)
        if "[" in text:
            text = text[:text.index("[")]
        if _NAME_ONLY.match(text):
            if text not in ("this", "undefined", "null"):
                self._add(text, self._binding(text, pos), src)
        elif _PATH_ONLY.match(text):
            self._add_path(text, pos, src)

    def _span(self, a: int, b: int, src: Source) -> None:
        i = bisect.bisect_left(self._span_starts, a)
        self._span_starts.insert(i, a)
        self.spans.insert(i, (a, b, src))

    def _tainted(self, a: int, b: int, skip_functions: bool = False) -> Optional[Source]:
        """The request whose response is (part of) the expression in ``[a, b)``."""
        best: Optional[Source] = None
        skip: List[Tuple[int, int]] = []
        if skip_functions:
            i = bisect.bisect_left(self._heads, a)
            while i < len(self._heads) and self._heads[i] < b:
                skip.append((self._by_head[i].a, self._by_head[i].b))
                i += 1

        literals: List[Tuple[int, int]] = []             # JSON.stringify(...) used as a whole literal
        for m in _STRINGIFY.finditer(self.bare, a, b) if self.bare.find("stringify", a, b) != -1 else ():
            opener = m.end() - 1
            if self._json_literal(m.start(), opener):
                literals.append((opener, self._close(opener)))

        def take(src: Source, pos: int) -> None:
            nonlocal best
            if any(x <= pos < y for x, y in skip):
                return
            if not src.literal and any(x < pos < y for x, y in literals):
                src = dataclasses.replace(src, literal=True)
            if best is None or _strength(src) > _strength(best):
                best = src

        # a request written inside the expression - not an expression that merely sits
        # inside a request (the body of its callback)
        i = bisect.bisect_left(self._span_starts, a)
        while i < len(self.spans) and self.spans[i][0] < b:
            if self.spans[i][1] <= b:
                take(self.spans[i][2], self.spans[i][0])
            i += 1
        bare = self.bare
        if self.names:
            for m in _WORD.finditer(bare, a, b):
                held = self.names.get(m.group(0))
                if not held:
                    continue
                for x, y, src, only in held:
                    if x <= m.start() < y and (not only or bare[self._ws(m.end()):self._ws(m.end()) + 1] == "(") \
                            and self._same_variable(m.group(0), m.start(), (x, y)):
                        take(src, m.start())
        if self.wholes:
            for m in _WORD.finditer(bare, a, b):
                held = self.wholes.get(m.group(0))
                if not held:
                    continue
                after = self._ws(m.end())
                if bare[after:after + 1] in (".", "[") or bare.startswith("?.", after):
                    continue                                 # a property of it, not the object
                for x, y, src in held:
                    if x <= m.start() < y and self._same_variable(m.group(0), m.start(), (x, y)):
                        take(src, m.start())
        for path, held in self.paths.items():
            at = bare.find(path, a, b)
            while at != -1:
                end = at + len(path)
                if not (bare[at - 1:at].isalnum() or bare[at - 1:at] in ("_", "$", ".")) and not (
                        bare[end:end + 1].isalnum() or bare[end:end + 1] in ("_", "$")):
                    for x, y, owner, src, only in held:
                        if x <= at < y and (not only or bare[self._ws(end):self._ws(end) + 1] == "(") and (
                                self._home(at)[2] == owner if owner else
                                path.startswith("this.") or self._same_variable(path, at, (x, y))):
                            take(src, at)
                at = bare.find(path, at + 1, b)
        return best

    def _callbacks(self, a: int, b: int, src: Source) -> None:
        """Functions written directly in ``[a, b)`` receive the response."""
        i = bisect.bisect_left(self._heads, a)
        while i < len(self._heads) and self._heads[i] < b:
            f = self._by_head[i]
            i += 1
            if f.parent is not None and a <= f.parent.start < b:
                continue
            for name in f.params:
                self._add(name, (f.a, f.b), src)

    def _chain(self, pos: int, src: Source) -> None:
        """``value.on("data", f)`` / ``value.then(f).then(g)``: f and g receive it."""
        bare, i = self.bare, pos
        for _ in range(64):
            i = self._ws(i)
            ch = bare[i:i + 1]
            if ch == "." or bare.startswith("?.", i):
                i = self._ws(i + (1 if ch == "." else 2))
                m = _IDENT.match(bare, i)
                if not m:
                    return
                i = m.end()
                j = self._ws(i)
                if m.group(0).startswith("on") and bare[j:j + 1] == "=" and bare[j + 1:j + 2] != "=":
                    self._callbacks(j + 1, self._expr_end(j + 1), src)     # ws.onmessage = function(e)
                    return
            elif ch in "([":
                close = self._close(i)
                if close < 0:
                    return
                if ch == "(":
                    self._callbacks(i + 1, close, src)
                i = close + 1
            else:
                return

    def _returns(self, pos: int, src: Source) -> None:
        """The function around ``pos`` hands the response to its caller."""
        f = self._inner(pos)
        if f is None:
            return
        if f.method:
            return self._add_path("this." + f.name, f.a, src, True)
        outer = (f.parent.a, f.parent.b) if f.parent else (0, self.n)
        m = re.search(r"((?:this\s*\.\s*)?%s(?:\s*\.\s*%s)*)\s*([=:])\s*(?:async\s+)?\Z" % (_ID, _ID),
                      self.bare[max(0, f.start - 120):f.start])
        if m:                                                # read = function(url) {...} / read: function
            name = re.sub(r"\s+", "", m.group(1))
            if ".prototype." in name or m.group(2) == ":":
                self._add_path("this." + name.rsplit(".", 1)[-1], f.a, src, True)
            elif "." in name:
                self._add_path(name, f.start, src, True)
            else:
                self._add(name, self._binding(name, f.start), src, True)
        if f.name:
            # (the name of `function name(...)` is bound in the function around it - as the
            # binding reads it; until 2026-10-15 a named function given to a variable kept the
            # mark of its own name inside itself only)
            self._add(f.name, self._binding(f.name, f.start), src, True)

    def _consume(self, pos: int, src: Source, depth_left: int = 3) -> None:
        """Follow the expression that contains the response at ``pos`` to the left:
        into the variable it is assigned to, out of the function that returns it,
        through the calls that wrap it."""
        bare = self.bare
        i, depth, comma = pos - 1, 0, False
        floor = max(0, pos - _BACK)
        # the properties the response is put under on the way out ({ a: { b: response } }: b, a) -
        # None once that cannot be said: a computed key, a spread, a call or an array in between
        keys: Optional[List[str]] = []
        inner = pos                                         # where the innermost value began
        while i >= floor:
            self._tick()
            ch = bare[i]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth:
                    depth -= 1
                elif ch == "(":
                    keys = None                             # handed to a call: what comes back is another thing
                    j = self._back(i - 1)
                    if j < 0:
                        return
                    if bare[j].isalnum() or bare[j] in "_$)]":
                        start, callee = self._callee(j)
                        last = callee.rsplit(".", 1)[-1]
                        if callee == "return":
                            return self._returns(pos, src)
                        if callee in _CONTROL or bare[max(0, start - 12):start].rstrip().endswith("function"):
                            return
                        if callee == "JSON.stringify" and not src.literal and self._json_literal(start, i):
                            src = dataclasses.replace(src, literal=True)         # "x = " + JSON.stringify(data)
                        if last in _COLLECT and "." in callee:
                            self._target(callee.rsplit(".", 1)[0], i, src)       # chunks.push(part)
                        elif _NAME_ONLY.match(callee) and depth_left:
                            self._settles(callee, i, src, depth_left)             # resolve(data)
                        i, comma = start - 1, False
                        continue
                    comma = False
                elif ch == "[":
                    keys = None
                    j = self._back(i - 1)
                    if j >= 0 and (bare[j].isalnum() or bare[j] in "_$)]"):
                        i, comma = self._callee(j)[0] - 1, False
                        continue
                    comma = False
                else:
                    j = self._back(i - 1)
                    before = bare[j] if j >= 0 else ""
                    if before and before in "=(,:[?" and bare[j - 1:j + 1] != "=>" or \
                            bare[max(0, j - 5):j + 1] == "return":
                        if keys is not None:                                    # an object literal
                            key = self._key_of(i, inner)
                            keys = keys + [key] if key else None
                        inner = i
                        i, comma = j, False
                        continue
                    return
            elif depth:
                pass
            elif ch == ";":
                return
            elif ch == ",":
                comma = True
            elif ch == "\n":
                if self._line_ends(i):
                    return
            elif ch == "=":
                before, after = bare[i - 1:i], bare[i + 1:i + 2]
                if after == "=":
                    pass
                elif after == ">":
                    return self._returns(pos, src)
                elif before in ("=", "!", "<", ">") and bare[i - 2:i] not in ("<<", ">>"):
                    return                                  # a comparison: yes or no, not the data
                elif comma:
                    return
                else:
                    k = i - 1
                    while k >= 0 and bare[k] in "+-*/%&|^?<>":
                        k -= 1
                    return self._assigned(k, src, keys)
            elif ch.isalnum() or ch in "_$":
                j = i
                while j >= 0 and (bare[j].isalnum() or bare[j] in "_$"):
                    j -= 1
                word = bare[j + 1:i + 1]
                if bare[j:j + 1] != ".":
                    if word == "return":
                        return self._returns(pos, src)
                    if word == "of":                          # for (const part of response)
                        m = re.search(r"(?:var|let|const)\s+(%s)\s*\Z" % _ID, bare[max(0, j - 80):j + 1])
                        if m:
                            self._add(m.group(1), self._binding(m.group(1), pos), src)
                        return
                    if word in ("throw", "case", "if", "while", "for", "else", "do"):
                        return
                i = j
                continue
            i -= 1

    def _json_literal(self, start: int, opener: int) -> bool:
        """``JSON.stringify(...)`` at ``start`` is used as a whole JavaScript literal (phageo,
        2026-10-14): its result is not cut or changed (``.slice(1, -1)``, ``.replace(...)``), and
        it is not put inside the quotes of a text it is joined to (``"x = '" + ... + "'"`` - a
        quote in the data would end that text there)."""
        bare, code = self.bare, self.code
        close = self._close(opener)
        if close < 0:
            return False
        after = self._ws(close + 1)
        if bare[after:after + 1] in (".", "[") or bare.startswith("?.", after):
            return False
        quote = lambda at: 0 <= at < len(code) and code[at] in "'\"`"
        before = self._back(start - 1)
        if before >= 0 and bare[before] == "+":
            k = self._back(before - 1)
            if k > 0 and quote(k) and (quote(k - 1) or code[k - 1] == "\\"):
                return False
        elif before > 0 and bare[before] == "{" and bare[before - 1] == "$":
            if quote(before - 2):                               # `x = '${JSON.stringify(data)}'`
                return False
        if bare[after:after + 1] == "+":
            k = self._ws(after + 1)
            if quote(k) and quote(k + 1):
                return False
        elif bare[after:after + 1] == "}" and quote(after + 1):
            return False
        return True

    def _key_of(self, opener: int, value: int) -> str:
        """The key under which the value that begins at or after ``value`` stands in the
        object literal opened at ``opener`` ("": a computed key ``[k]: v``, a spread, or
        something this cannot read - the whole object then carries the mark)."""
        bare = self.bare
        start, depth = opener + 1, 0
        for i in range(opener + 1, min(value, opener + 4000)):          # the last comma before the value
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and not depth:
                start = i + 1
        if value - opener > 4000:
            return ""
        part = self.code[start:value + 200]
        m = re.match(r"""\s*(?:(%s)|"(%s)"|'(%s)')\s*:(?!:)""" % (_ID, _ID, _ID), part)
        if m:
            return m.group(1) or m.group(2) or m.group(3)
        m = re.match(r"\s*(%s)\s*(?:[,}]|\Z)" % _ID, self.code[start:self._close(opener) + 1 if self._close(opener) > 0 else start])
        return m.group(1) if m else ""                      # { title }: the short form

    def _assigned(self, end: int, src: Source, keys: Optional[List[str]] = None) -> None:
        """The response is assigned to whatever ends at ``end`` - or, with ``keys``, to that
        property of it: ``x = { a: response }`` marks ``x.a``, not all of ``x`` (phageo,
        2026-10-14; a computed key or a spread still marks the whole object). The object
        itself still carries the mark where it is handed on whole (``wholes``)."""
        bare = self.bare
        end = self._back(end)
        if end < 0:
            return
        if bare[end] in "}]":
            opener = self._open(end)
            if opener < 0:
                return
            j = self._back(opener - 1)
            declared = re.search(r"(?:var|let|const)\Z", bare[max(0, j - 5):j + 1]) is not None
            if bare[end] == "}" or declared or j < 0 or not (bare[j].isalnum() or bare[j] in "_$)]"):
                for m in _WORD.finditer(bare, opener, end):   # var {a, b} = ... / [a, b] = ...
                    if bare[self._ws(m.end()):self._ws(m.end()) + 1] != ":":
                        self._add(m.group(0), self._binding(m.group(0), end), src)
                return
        m = _TARGET.search(bare, max(0, end - 300), end + 1)
        if m:
            target = re.sub(r"\s+", "", m.group(1))
            if keys and "[" not in target and (_NAME_ONLY.match(target) or _PATH_ONLY.match(target)) \
                    and target not in ("this", "module.exports", "exports"):
                self._add_path("%s.%s" % (target, ".".join(reversed(keys))), end, src)
                self._add_whole(target, end, src)
            else:
                self._target(m.group(1), end, src)

    def _settles(self, callee: str, pos: int, src: Source, depth_left: int) -> None:
        """``new Promise(function(resolve) { ... resolve(data) })``: the promise carries it."""
        f = self._inner(pos)
        while f is not None and callee not in f.params:
            f = f.parent
        if f is None or not f.params or f.params[0] != callee:
            return
        m = re.compile(r"new\s+Promise\s*\(\s*(?:async\s+)?\Z").search(self.bare, max(0, f.start - 40), f.start)
        if m:
            self._chain(self._close(self.bare.index("(", m.start())) + 1, src)
            self._consume(m.start(), src, depth_left - 1)

    def _uses(self, kind: str, name: str, a: int, b: int):
        """``(start, end)`` of every place in ``[a, b)`` where ``name`` - a name, or a dotted
        path - stands as a whole word that is not a property of something: what a search
        for ``(?<![\\w$.])name(?![\\w$])`` finds there, in the same order. The first few
        names are searched for one by one. A script with many names to follow is read once
        for all of them: until 2026-10-13 it was read once per name - up to 3,000 passes
        over a script of megabytes, which the steps did not count and only the clock ended."""
        bare = self.bare
        self._searches += 1
        places: List[int] = []
        first = name.split(".", 1)[0] if kind == "path" else name
        if self._searches > _DIRECT_SEARCHES:
            if self._words is None:
                words: Dict[str, List[int]] = {}
                for m in _WORD.finditer(bare):
                    words.setdefault(m.group(0), []).append(m.start())
                self._words = self._parse.words = words
            held = self._words.get(first, [])
            lo, hi = bisect.bisect_left(held, a), bisect.bisect_left(held, b)
            if name == first or hi - lo <= _MANY_PLACES:
                size, out = len(name), []
                for p in held[lo:hi]:
                    end = p + size
                    if end > b:
                        break
                    if name == first or (bare.startswith(name, p) and (end == b or not _WORD_CHAR.match(bare, end))):
                        out.append((p, end))
                p = b - size
                if name == first and a <= p and b < self.n and _WORD_CHAR.match(bare, b) and bare.startswith(name, p) \
                        and not (p and _BEFORE_WORD.match(bare, p - 1)):
                    out.append((p, b))              # (a name that the end of the stretch cuts in two)
                return out
        rx = re.compile(r"(?<![\w$.])%s(?![\w$])" % re.escape(name))
        return ((m.start(), m.end()) for m in rx.finditer(bare, a, b))

    def _propagate(self) -> None:
        while self._work:
            kind, name, a, b, src, only, owner = self._work.pop()
            count = 0
            own = kind != "path" or not owner and not name.startswith("this.")
            for start, end in self._uses(kind, name, a, b):
                if own and not self._same_variable(name, start, (a, b)):
                    self._tick()                            # the same name, another variable
                    continue
                count += 1
                if count > _MAX_OCCURRENCES:
                    break
                self._tick(4)
                after = self._ws(end)
                nxt = self.bare[after:after + 2]
                if only and nxt[:1] != "(":
                    continue
                if nxt[:1] == "=" and nxt != "==" and nxt != "=>":
                    continue                                # it is given a new value here
                if _FACT.match(self.bare, end):
                    continue                                # response.length: a number, not the data
                if kind == "whole" and (nxt[:1] in (".", "[") or nxt == "?."):
                    continue                                # a property of the object, not the object
                if kind != "path":
                    before = self._back(start - 1)
                    if nxt[:1] == ":" and self.bare[before:before + 1] in ("{", ","):
                        continue                            # a key in an object literal
                elif owner and self._home(start)[2] != owner:
                    continue
                self._chain(end, src)
                self._consume(start, src)

    # -- sources -----------------------------------------------------------------------------
    def _sources(self) -> None:
        bare, code = self.bare, self.code
        for m in _find(_XHR_OPEN, bare):
            if len(self.opens) >= _MAX_SITES:
                break
            opener = m.end() - 1
            arguments = self._arguments(opener)
            if len(arguments) < 2:
                continue
            verb = self._value(arguments[0][0])
            if not isinstance(verb, str) or verb.upper() not in ("GET", "POST", "PUT", "HEAD", "PATCH", "DELETE"):
                continue
            start, receiver = self._callee(self._back(m.start() - 1)) if m.start() else (0, "")
            kind, address = self._classify(self._value(arguments[1][0]), opener)
            self.opens.append((start, receiver, Source("XMLHttpRequest", start, kind, address)))
        seeds: List[Tuple[int, int, Source, int]] = []      # (start, end, request, "(" of a call or -1)
        for m in _find(_ACCESS, bare):
            if len(seeds) >= _MAX_SITES:
                break
            start, receiver = self._callee(self._back(m.start() - 1)) if m.start() else (0, "")
            if not receiver:
                continue
            same = [o for o in self.opens if o[1] == receiver] or self.opens
            before = [o for o in same if o[0] <= start]
            chosen = before[-1] if before else (same[0] if same else None)
            src = chosen[2] if chosen else Source("XMLHttpRequest", start, UNRESOLVED, "")
            seeds.append((start, m.end(), src, -1))
        aliases = {m.group(1) for m in _find(_NET_ALIAS, code) if self._real(m.start())} \
            if "require" in code else set()
        calls = [m for m in _find(_NET_CALL, bare)]
        if "require" in code:
            calls += [m for m in _find(_NET_INLINE, code) if self._real(m.start())]
        for alias in sorted(aliases):                        # a one-letter name only as h.get(...)
            rx = re.compile(r"(?<![\w$.])%s(?:\s*\.\s*(?:get|post|put|request|stream))%s\s*\("
                            % (re.escape(alias), "?" if len(alias) > 2 else ""))
            calls += [m for m in _find(rx, bare)]
        for m in calls[:_MAX_SITES]:
            opener = m.end() - 1
            close = self._close(opener)
            if close < 0:
                continue
            what = re.sub(r"\s+", " ", code[m.start():opener]).strip()
            if what.startswith("require") or what.startswith("nw"):
                what = re.sub(r"""^.*?['"](?:node:)?([\w-]+)['"]\s*\)\s*""", r"\1", what)
            kind, address = self._address(opener)
            seeds.append((m.start(), close + 1, Source(what[:40], m.start(), kind, address), opener))
        for a, b, src, opener in sorted(seeds, key=lambda s: s[0]):
            self._span(a, b, src)
        for a, b, src, opener in seeds:
            if opener >= 0:
                self._callbacks(opener + 1, b - 1, src)
            self._chain(b, src)
            self._consume(a, src)

    # -- sinks -------------------------------------------------------------------------------
    def _remote_literal(self) -> str:
        """The first remote http(s) address written in the code of this file - not in
        a comment, and not an XML namespace or this PC ("" if there is none)."""
        if self._literal is None:
            m = _WRITTEN.search(self.code)
            self._literal = m.group(0)[:120] if m else ""
        return self._literal

    def _hit(self, how: str, pos: int, sink: str, src: Optional[Source], kind: str = "", address: str = "",
             detail: str = "", weak: bool = False, route: str = "", checked: bool = False,
             local: bool = False, text_from: str = "") -> None:
        if src is not None:
            kind, address = src.kind, src.address
        # WebAssembly, script elements, import() and Worker with an address that cannot be
        # resolved are what every library loader looks like. They are reported, one level
        # lower, only if the file itself names a remote address in its code: that is how an
        # address is kept out of sight behind a function parameter.
        weak = weak or (how == "wasm" and kind == UNRESOLVED)
        seen = self._remote_literal() if weak else ""
        held = self.weak if weak else self.hits
        if kind == LOCAL or (weak and not seen) or len(held) >= (_MAX_WEAK if weak else _MAX_HITS):
            return
        line = self.flow.line_of(pos)
        if any(h.how == how and h.line == line and h.sink == sink for h in held):
            return
        if how in ("dropper", "command") and not checked:
            checked = self._checked(pos)
        held.append(Hit(how, line, sink, src.what if src else "",
                        self.flow.line_of(src.pos) if src else line, kind, address, detail, weak, seen, route, checked,
                        local=local, text_from=text_from))

    def _loads_unresolved(self, pos: int, label: str, a: int, b: int, kind: str, address: str) -> None:
        """A loader whose address could not be resolved (an object URL is not an address).
        For ``import()`` (phageo, 2026-10-14, forty-second message) the parts of the address are
        judged like the parts of a process start: all of them the app's own - its folder, its
        settings, written-out text - is ``local`` (MEDIUM); anything else stays as it was."""
        if kind == UNRESOLVED and not re.search(r"createObjectURL|\bBlob\b", self.code[a:b]):
            try:
                local = label == "import" and self._local(a, b)
            except Budget:
                local = False           # (no steps left: "local" cannot be said - the load is kept as it was)
            self._hit("loader", pos, label, None, kind, address, weak=True, local=local)

    def _in_text(self, pos: int) -> bool:
        """Does ``pos`` stand in quoted text - the text part of a template literal, which the
        blanked copy keeps when the template has a ``${...}``?"""
        if self._quoted is None:
            self._quoted = quoted_text(self.code)
        return self._quoted.holds(pos)

    def _const_value(self, name: str, pos: int) -> Optional[int]:
        """Where the value of the nearest ``const name = ...`` whose block holds ``pos`` begins
        (a const is given its value once); None: the nearest assignment that holds ``pos`` is
        no const, or there is none within reach."""
        floor = max(0, pos - 200_000)
        rx = re.compile(r"(?<![\w$.])%s\s*=(?![=>])" % re.escape(name))
        for m in reversed(list(rx.finditer(self.bare, floor, pos))[-64:]):
            if not self._holds_to(m.start(), pos):
                continue                                    # (in a block that is closed before pos)
            head = self.bare[max(floor, m.start() - 2000):m.start()]
            return m.end() if re.search(r"(?<![\w$.])const\s[^;{}]*\Z", head) else None
        return None

    def _braces(self, pos: int) -> Tuple[int, int]:
        """The braces ``{ ... }`` that hold ``pos`` (the whole text: none)."""
        floor = max(0, pos - 400_000)
        depth = 0
        for m in reversed(list(_BRACKETS.finditer(self.bare, floor, pos))):
            if m.group(0) in ")]}":
                depth += 1
            elif depth:
                depth -= 1
            elif m.group(0) == "{":
                close = self._close(m.start())
                return (m.start(), close) if close > pos else (0, self.n)
        return 0, self.n

    def _import_text(self, a: int, b: int, pos: int, depth: int = 0) -> Optional[Tuple[str, Any]]:
        """For ``import()`` (phageo, 2026-10-15, forty-fifth message): is the address at ``[a, b)``
        a ``blob:`` URL (``URL.createObjectURL(new Blob([...]))``) or a ``data:`` URL - followed
        through a variable and the callers of a function -, and where does its text come from?
        ``("network", request)``: a download reaches it; ``("app", what)``: no download reaches
        it - the app's own text; None: not such a URL, or not known."""
        if depth > 3 or b <= a or b - a > 4000:
            return None
        self._tick(5)
        bare = self.bare
        blob = re.search(r"(?<![\w$])createObjectURL\s*\(", bare[a:b])
        if blob:
            inner = self._first_argument(a + blob.end() - 1)
            word = bare[inner[0]:inner[1]].strip()
            if _NAME_ONLY.match(word):                      # const blob = new Blob([...]); createObjectURL(blob)
                start = self._const_value(word, inner[0])
                start = self._one_value(word, inner[0]) if start is None else start
                inner = (start, self._expr_end(start)) if start is not None else inner
            made = re.match(r"\s*new\s+Blob\s*\(", bare[inner[0]:inner[1]])
            if made is None:
                return None
            parts = self._first_argument(inner[0] + made.end() - 1)
            src = self._tainted(parts[0], parts[1], True)
            if src is not None:
                return "network", src
            return self._text_origin(parts, "blob: URL of a text")
        value = self._value(a)
        if isinstance(value, (str, Sym)) and re.match(r"\s*data:", show(value), re.I):
            src = self._tainted(a, b, True)
            return ("network", src) if src is not None else self._text_origin((a, b), "data: URL of a text")
        name = bare[a:b].strip()
        if not _NAME_ONLY.match(name) or name in _KEYWORDS:
            return None
        f = self._inner(pos)
        while f is not None and name not in f.params and not self._declares(f, name):
            f = f.parent
        found: List[Optional[Tuple[str, Any]]] = []
        if f is not None and name in f.params:
            # a parameter: what the callers of the function hand it (in the scope of its name)
            called, index = self._function_name(f), f.params.index(name)
            if not called:
                return None
            home = self._scope(called, f.start)
            if re.search(r"(?<![\w$.])(?:const|let)\s[^;{}]*?(?<![\w$.])%s\s*=\s*\Z" % re.escape(called),
                         bare[max(0, f.start - 2000):f.start]):
                home = self._braces(f.start)                # (const / let: the block it is declared in)
            for start, opener in self._calls_of(called, home[0], home[1], dotted=False)[:16]:
                close = self._close(opener)
                if start == f.start or bare[self._ws(close + 1):self._ws(close + 1) + 1] == "{":
                    continue                                # (a definition of that name, not a call)
                arguments = self._arguments(opener)
                if len(arguments) > index:
                    found.append(self._import_text(arguments[index][0], arguments[index][1], start, depth + 1))
                if len(found) > 8:
                    return None
        else:
            start = self._const_value(name, pos)
            start = self._one_value(name, pos) if start is None else start
            if start is None:
                return None
            found.append(self._import_text(start, self._expr_end(start), start, depth + 1))
        if not found or any(item is None for item in found):
            return None
        return next((item for item in found if item[0] == "network"), found[0])

    def _text_origin(self, span: Tuple[int, int], what: str) -> Tuple[str, str]:
        """The text of a blob: / data: URL that no download reaches: ``("local", ...)`` when it
        was followed back to its every source and each is written-out text or one of the app's
        own values (``_local``: a proof that holds whether or not the rest of the file was read -
        phageo, 2026-10-15, forty-sixth message), else ``("app", ...)`` - nothing found reaches it,
        which says something only of a file read to its end."""
        a, b = span
        try:
            local = self._local(a, b)
        except Budget:
            local = False
        return ("local", what + " made of written-out text and the app's own values") if local \
            else ("app", what + " the app makes")

    def _load_text(self, a: int, b: int, pos: int) -> Optional[Tuple[str, Any]]:
        """``_import_text`` with steps of its own (``_LOAD_TEXT_STEPS``): where the text a load
        is given comes from is followed back also in a file whose reading ran out of steps
        (phageo, 2026-10-15, forty-sixth message) - the same answer for the same file, and the
        reading's own count is not touched."""
        saved, self.clock = self.clock, Clock(_LOAD_TEXT_STEPS, MAX_SECONDS)
        try:
            return self._import_text(a, b, pos)
        except Budget:
            return None                     # (not known: the load is judged as before)
        finally:
            self.clock = saved

    def _first_argument(self, opener: int) -> Tuple[int, int]:
        arguments = self._arguments(opener)
        return arguments[0] if arguments else (opener + 1, opener + 1)

    def _sinks(self) -> None:
        bare, code = self.bare, self.code
        self._loaders()
        if not self.spans:
            return                                           # nothing is requested: nothing to follow
        # 1. the response is run as code
        sites: List[Tuple[int, int, str]] = [
            (m.start(), m.end() - 1, _label(m.group(0))) for m in _find(_CODE_SINK, bare)]
        sites += [(m.start(), m.end() - 1, _label(m.group(2))) for m in _find(_NAMED_SINK, code)
                  if self._real(m.start())]
        built = seen = 0
        for m in _find(_BUILT_SINK, bare):                 # window["ev" + "al"](...)
            seen += 1
            if built >= 200 or seen > 20_000:
                break
            close = self._close(m.start())
            if close < 0 or not re.search(r"""["'`+]|^\s*[A-Za-z_$][\w$]*\s*$""", code[m.end():close]):
                continue
            if re.fullmatch(r"""\s*(["'])[\w$]*\1\s*""", code[m.end():close]):
                continue                                     # a plain name: read above
            built += 1
            name = self._value(m.end())
            if isinstance(name, str) and name in ("eval", "Function"):
                sites.append((m.start(), self._ws(close + 1), _label(name)))
        for pos, opener, label in sites[:_MAX_SITES]:
            close = self._close(opener)
            if close > 0:
                src = self._tainted(opener + 1, close, True)
                if src is not None and not src.literal:     # a JSON literal in code text is no code
                    self._hit("code", pos, label, src)
        for m in _find(_THEN_EVAL, bare):
            start = self._callee(self._back(m.start() - 1))[0] if m.start() else 0
            src = self._tainted(start, m.start())
            if src is not None and not src.literal:
                self._hit("code", m.start(), "eval", src)
        # 2. ... as a WebAssembly module
        for m in _find(_WASM_SINK, code) if "WebAssembly" in code else ():
            if self._real(m.start()):
                a, b = self._first_argument(m.end() - 1)
                src = self._tainted(a, b, True)
                if src is not None:
                    self._hit("wasm", m.start(), "WebAssembly." + m.group(1), src)
        # 4. ... as a command, or as a file that is written and then started
        launches = self._launches() if "child_process" in code else []
        if "ActiveXObject" in code or "CreateObject" in code:
            launches = launches + self._wsh_launches()
        for pos, opener, label in launches:
            close = self._close(opener)
            if close > 0 and label.startswith(("child_process", "WScript.Shell", "Shell.Application", "ActiveXObject")):
                how, src = self._started(pos, opener, close, label)
                if src is not None:
                    self._hit(how, pos, label, src)
        self._droppers(launches)

    def _started(self, pos: int, opener: int, close: int, label: str) -> Tuple[str, Optional[Source]]:
        """``(how, request)`` for a process start whose brackets hold something downloaded
        (phageo, 2026-10-14). ``"command"`` - what is run is downloaded: the command text of
        ``exec`` / ``execSync`` (and of every start whose kind is not known, and of the Script
        Host), the program of ``spawn`` / ``execFile`` / ``fork``, anything at all when the
        start goes through a shell (``shell: true``) or the program is itself something that
        runs what it is given (``cmd``, ``powershell``, ``node`` ...). ``"argument"`` -
        ``spawn`` / ``execFile`` without a shell, a fixed or local program, and only an
        argument, the environment or the folder is downloaded: data handed to a program,
        not a program."""
        whole = self._tainted(opener + 1, close, True)
        if whole is None or not label.startswith("child_process"):
            return "command", whole
        word = _IDENT.findall(self.bare[pos:opener])
        method = word[-1] if word else ""
        method = method if method in _SPLIT_START or method in ("exec", "execSync") else self._cp_methods.get(method, "exec")
        arguments = self._arguments(opener)
        if method not in _SPLIT_START or not arguments:
            return "command", whole
        a, b = arguments[0]
        program = self._tainted(a, b, True)
        if program is not None:
            return "command", program
        if _SHELL_OPTION.search(self.bare, b, close):
            return "command", whole
        value = self._value(a)
        name = show(value) if isinstance(value, (str, Sym)) else ""
        name = re.split(r"[\\/]", V.known_part(name).strip().strip("\"'"))[-1].lower()
        name = name[:-4] if name.endswith(".exe") else name
        if name in _JS_RUNTIMES and whole.literal and _CODE_FLAG.search(self.code, b, close):
            # only a JSON literal of what was downloaded stands in the JavaScript it is given: no
            # code chain - data handed to a program, judged as such (phageo, 2026-10-14)
            return "argument", whole
        if name in _INTERPRETERS:
            return "command", whole
        return "argument", whole

    def _loaders(self) -> None:
        """The address itself is the code: importScripts, import(), Worker, script elements."""
        bare = self.bare
        for m in _find(_LOADER, bare):
            opener = m.end() - 1
            a, b = self._first_argument(opener)
            label = re.sub(r"[\s(]+", " ", m.group(0)).strip()
            if label == "import" and self._in_text(m.start()):
                continue                    # `import(${q}${name}${q}).` - the text of a template, no load
            src = self._tainted(a, b, True)
            if src is not None:
                self._hit("loader", m.start(), label, src)
                continue
            # (import(), and since 2026-10-15, forty-sixth message, a Worker and importScripts:
            # a blob: / data: URL is judged by where its text comes from)
            found = self._load_text(a, b, m.start()) if label in _TEXT_LOADERS else None
            if found is not None:
                if found[0] == "network":
                    self._hit("loader", m.start(), label, found[1])
                else:
                    self._hit("loader", m.start(), label, None, UNRESOLVED, found[1], weak=True, text_from=found[0])
            else:
                kind, address = self._classify(self._value(a), opener)
                if kind in (REMOTE, HIDDEN):
                    self._hit("loader", m.start(), label, None, kind, address)
                else:
                    self._loads_unresolved(m.start(), label, a, b, kind, address)
        if "createElement" in self.code:
            self._script_elements()
        if "load" in self.code or "dataType" in self.code:
            self._jquery_loads()

    def _jquery_loads(self) -> None:
        """``$(...).load(address)`` and ``$.ajax({url: address, dataType: "script"})``: jQuery fetches
        a script and runs it. Only an address that is remote, decoded or a download's answer counts -
        never one that cannot be resolved: ``.load`` is also jQuery's old event shortcut, and a library's
        own loader with its address as a parameter is what rule 13's library exception covers (phageo,
        2026-10-20, seventy-third message: app code that hands such a loader a remote address stays
        CRITICAL)."""
        bare, code = self.bare, self.code
        sites: List[Tuple[int, str, int, int]] = []
        for m in _find(_JQ_LOAD, bare):
            a, b = self._first_argument(m.end() - 1)
            sites.append((m.start(), "jQuery .load", a, b))
        for m in _find(_JQ_AJAX, bare) if "dataType" in code else ():
            close = self._close(m.end() - 1)
            if close < 0 or not _JQ_SCRIPT_TYPE.search(code, m.end(), close):
                continue
            key = _JQ_URL.search(bare, m.end(), close)
            if key is not None:
                start = self._ws(key.end())
                sites.append((m.start(), "jQuery.ajax (script)", start, self._expr_end(start)))
        for pos, label, a, b in sites:
            src = self._tainted(a, b, True)
            if src is not None:
                self._hit("loader", pos, label, src)
                continue
            kind, address = self._classify(self._value(a), pos)
            if kind in (REMOTE, HIDDEN):
                self._hit("loader", pos, label, None, kind, address)

    def _script_elements(self) -> None:
        bare, code = self.bare, self.code
        for m in list(_find(_SCRIPT_NEW, code))[:_MAX_SITES]:
            if not self._real(m.start()):
                continue
            name = re.escape(m.group(1))
            f = self._inner(m.start())
            end = f.b if f is not None else self.n
            again = re.compile(r"(?<![\w$.])%s\s*=(?!=)" % name).search(bare, m.end(), end)
            if again:
                end = again.start()
            uses = re.compile(r"""(?<![\w$.])%s\s*\.\s*(?:(src|text|textContent|innerHTML|innerText)\s*=(?!=)"""
                              r"""|setAttribute\s*\(\s*["']src["']\s*,|(appendChild|append)\s*\()""" % name)
            for use in uses.finditer(code, m.end(), end):
                if not self._real(use.start()):
                    continue
                start = self._ws(use.end())
                stop = self._expr_end(start)
                src = self._tainted(start, stop, True)
                if use.group(1) in (None, "src") and not use.group(2):
                    if src is not None:
                        self._hit("loader", use.start(), "script.src", src)
                    else:
                        kind, address = self._classify(self._value(start), use.start())
                        if kind in (REMOTE, HIDDEN):
                            self._hit("loader", use.start(), "script.src", None, kind, address)
                        else:
                            self._loads_unresolved(use.start(), "script.src", start, stop, kind, address)
                elif src is not None and not src.literal:
                    self._hit("code", use.start(), "script element", src)

    def _launches(self) -> List[Tuple[int, int, str]]:
        """``(position, "(" position, label)`` of everything that starts a program or loads code."""
        bare, code = self.bare, self.code
        out: List[Tuple[int, int, str]] = []
        names, modules = set(), set()
        for m in _find(_CP_ALIAS, code):
            if self._real(m.start()):
                (names if m.group(2) else modules).add(m.group(1))
                if m.group(2):                               # run = require("child_process").spawn
                    self._cp_methods[m.group(1)] = _IDENT.findall(m.group(2))[-1]
        for m in _find(_CP_UNPACK, code):
            if self._real(m.start()):
                for part in m.group(1).split(","):
                    words = _IDENT.findall(part)
                    if words and words[0] in _SPAWN.split("|"):
                        names.add(words[-1])
                        self._cp_methods[words[-1]] = words[0]     # { spawn: run } = require(...)
        for m in _find(_CP_INLINE, code):
            if self._real(m.start()):
                out.append((m.start(), m.end() - 1, "child_process"))
        if modules:
            rx = re.compile(r"(?<![\w$.])(?:%s)\s*\.\s*(?:%s)\s*\(" % ("|".join(map(re.escape, sorted(modules))), _SPAWN))
            out += [(m.start(), m.end() - 1, "child_process") for m in _find(rx, bare)]
        if names:
            rx = re.compile(r"(?<![\w$.])(?:%s)\s*\(" % "|".join(map(re.escape, sorted(names))))
            out += [(m.start(), m.end() - 1, "child_process") for m in _find(rx, bare)]
        return out[:_MAX_SITES]

    def _wsh_launches(self) -> List[Tuple[int, int, str]]:
        """The same for JScript under the Windows Script Host: ``Run`` / ``Exec`` of a
        ``WScript.Shell`` and ``ShellExecute`` of a ``Shell.Application`` object. The
        object's name is worked out through variables; an object whose name cannot be
        worked out counts too (label ``ActiveXObject``), one of a known other kind does not."""
        bare = self.bare
        out: List[Tuple[int, int, str]] = []
        names: Dict[str, str] = {}
        for m in list(_find(_WSH_NEW, bare))[:_MAX_SITES]:
            opener = m.end() - 1
            arguments = self._arguments(opener)
            close = self._close(opener)
            if not arguments or close < 0:
                continue
            value = self._value(arguments[0][0])
            label = _WSH_KINDS.get(value.strip().lower(), "") if isinstance(value, str) else "ActiveXObject"
            if not label:
                continue
            named = _WSH_NAMED.search(bare, max(0, m.start() - 120), m.start())
            if named:
                names[named.group(1)] = label
            inline = re.compile(r"\s*\.\s*(%s)\s*\(" % _WSH_START).match(bare, close + 1)
            if inline:                                       # new ActiveXObject("WScript.Shell").Run(...)
                out.append((m.start(), inline.end() - 1, "%s.%s" % (label, inline.group(1))))
        for name, label in sorted(names.items()):
            rx = re.compile(r"(?<![\w$.])%s\s*\.\s*(%s)\s*\(" % (re.escape(name), _WSH_START))
            out += [(m.start(), m.end() - 1, "%s.%s" % (label, m.group(1))) for m in _find(rx, bare)]
        return out[:_MAX_SITES]

    def _loads(self) -> List[Tuple[int, int, str]]:
        """Everything else that runs a file: require(file), shell.openItem, process.dlopen, Worker."""
        bare, code = self.bare, self.code
        out: List[Tuple[int, int, str]] = []
        for m in _find(_LAUNCH, bare):
            label = re.sub(r"[\s(.]+", " ", m.group(0)).strip()
            if label == "require" and re.match(r"""\s*["'][\w@/.:-]*["']\s*\)""", code[m.end():m.end() + 200]) \
                    and not re.match(r"""\s*["'][^"']*\.(?:js|node|json|exe|dll)["']""", code[m.end():m.end() + 200]):
                continue                                     # require("fs"): a module by name
            if label.startswith("open") and self._browser_open(m.end() - 1):
                continue                                     # shell.openExternal("https://..."): a page
            out.append((m.start(), m.end() - 1, label))
        return out[:_MAX_SITES]

    def _browser_open(self, opener: int) -> bool:
        """Is the shell's open (``openExternal`` / ``openPath`` / ``openItem``) whose ``(`` stands
        at ``opener`` handed an http(s) address (phageo, 2026-10-15, forty-sixth message)? That is
        a page the browser opens, no process start. A file path, an address of any other kind
        (``file:``, ``ms-settings:`` ...) or a value that cannot be read is a start - for the
        program starts and for the chains alike."""
        arguments = self._arguments(opener)
        if not arguments:
            return False
        value = self._value(self._ws(arguments[0][0]))
        return isinstance(value, (str, Sym)) and re.match(r"\s*https?://", show(value), re.I) is not None

    def _only_check(self, opener: int) -> bool:
        """Is the start that opens at ``opener`` the signature check itself (``_CHECK_ONLY``;
        phageo, 2026-10-15)? It hands the file to Windows' check and runs none of it."""
        close = self._close(opener)
        if close < 0 or not _OS_CHECK.search(self.code, opener, close):
            return False
        parts: List[str] = []
        for a, b in self._arguments(opener)[:4]:
            s = self._ws(a)
            if _CALLBACK.match(self.bare, s) or self.bare[s:s + 1] == "{":
                continue                                    # (a callback, the options)
            items = self._arguments(s) if self.bare[s:s + 1] == "[" else [(a, b)]
            for x, _y in items[:12]:
                value = self._value(x)
                if not isinstance(value, (str, Sym)):
                    return False
                parts.append(show(value))
        text = " ".join(parts)
        return text.count("‹") == 1 and _CHECK_ONLY.match(text) is not None

    def _droppers(self, launches: List[Tuple[int, int, str]]) -> None:
        bare, code = self.bare, self.code
        # (the signature check's own PowerShell is no start of the file it checks)
        launches = [item for item in launches if not self._only_check(item[1])]
        written: List[Tuple[int, Tuple[int, int], Source]] = []     # (position, path argument, request)
        for m in list(_find(_WRITE, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            if len(arguments) >= 2:
                src = self._tainted(arguments[1][0], arguments[1][1], True)
                if src is not None:
                    written.append((m.start(), arguments[0], src))
        writers: Dict[str, Tuple[int, int]] = {}
        for m in list(_find(_STREAM, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            if not arguments:
                continue
            named = re.compile(r"(?<![\w$.])(%s)\s*=\s*[\w$.\s]{0,40}\Z" % _ID).search(bare, max(0, m.start() - 120),
                                                                                    m.start())
            if named:
                writers[named.group(1)] = arguments[0]
        for m in list(_find(_PIPE, bare))[:_MAX_SITES]:
            start = self._callee(self._back(m.start() - 1))[0] if m.start() else 0
            src = self._tainted(start, m.start())
            if src is None:
                continue
            a, b = self._first_argument(m.end() - 1)
            inner = _STREAM.search(bare, a, b)
            if inner:
                arguments = self._arguments(inner.end() - 1)
                if arguments:
                    written.append((m.start(), arguments[0], src))
            else:
                word = bare[a:b].strip()
                if word in writers:
                    written.append((m.start(), writers[word], src))
        # JScript under the Windows Script Host: stream.Write(x) ... stream.SaveToFile(path), and a
        # text file of the FileSystemObject (file = fso.CreateTextFile(path); file.Write(x))
        for m in list(_find(_WSH_SAVE, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            if not arguments:
                continue
            wrote = re.compile(r"(?<![\w$.])%s\s*\.\s*(?:Write|WriteText)\s*\(" % re.escape(m.group(1)))
            for use in list(_find(wrote, bare))[:_MAX_SITES]:
                close = self._close(use.end() - 1)
                src = self._tainted(use.end(), close, True) if close > 0 else None
                if src is not None:
                    written.append((m.start(), arguments[0], src))
                    break
        for m in list(_find(_WSH_FILE, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            close = self._close(m.end() - 1)
            if not arguments or close < 0:
                continue
            named = re.compile(r"(?<![\w$.])(%s)\s*=\s*[\w$.\s]{0,40}\Z" % _ID).search(bare, max(0, m.start() - 120),
                                                                                    m.start())
            if named:
                writers[named.group(1)] = arguments[0]
            chained = re.compile(r"\s*\.\s*(?:Write|WriteLine)\s*\(").match(bare, close + 1)
            if chained:                                      # fso.CreateTextFile(path).Write(x)
                end = self._close(chained.end() - 1)
                src = self._tainted(chained.end(), end, True) if end > 0 else None
                if src is not None:
                    written.append((m.start(), arguments[0], src))
        for name, path in writers.items():
            for m in re.compile(r"(?<![\w$.])%s\s*\.\s*(?:write|end|Write|WriteLine)\s*\(" % re.escape(name)).finditer(bare):
                close = self._close(m.end() - 1)
                src = self._tainted(m.end(), close, True) if close > 0 else None
                if src is not None:
                    written.append((m.start(), path, src))
        # stream.pipeline(response, ..., file) / await pipeline(response.body, createWriteStream(path)):
        # the first stream is the download, the last one that is not a callback the file
        # (phageo, 2026-10-14, forty-second message - until then only .pipe() was read)
        for m in list(_find(_PIPELINE, bare))[:_MAX_SITES] if "pipeline" in bare else ():
            arguments = [(x, y) for x, y in self._arguments(m.end() - 1)
                         if not _CALLBACK.match(bare, self._ws(x))]
            if len(arguments) < 2:
                continue
            src = self._tainted(arguments[0][0], arguments[0][1], True)
            if src is None:
                continue
            a, b = arguments[-1]
            inner = _STREAM.search(bare, a, b)
            if inner:
                path = self._arguments(inner.end() - 1)
                if path:
                    written.append((m.start(), path[0], src))
            elif bare[a:b].strip() in writers:
                written.append((m.start(), writers[bare[a:b].strip()], src))
        if written:
            launches = launches + self._loads()
        for pos, (a, b), src in written[:40]:
            words = {w for w in _WORD.findall(bare[a:b])} - _QUIET
            value = self._value(a)
            literal = show(value) if isinstance(value, (str, Sym)) else ""
            base = re.split(r"[\\/]", V.known_part(literal))[-1].strip()
            for at, opener, label in launches:
                close = self._close(opener)
                if close < 0:
                    continue
                # (the same variable, not the same word in another function - as for a text that
                # is written and started; measured on a clean launcher, 2026-10-14)
                shared = {word for word in words & set(_WORD.findall(bare[opener + 1:close]))
                          if self._scope(word, pos) == self._scope(word, at)}
                started = self._value(self._ws(opener + 1))
                text = show(started) if isinstance(started, (str, Sym, list)) else ""
                if shared or (len(base) >= 3 and (base in text or base in code[opener + 1:close])):
                    self._hit("dropper", at, label, src, detail=(literal or code[a:b].strip())[:120])
                    break
        if written:
            self._path_runs(written[:40], launches)

    # -- the file of a download, followed to a start (phageo, 2026-10-14, forty-second message) -------
    # A downloaded file's path rarely goes straight from the write to the start: it is handed to a
    # function that checks the file, comes back through a callback or a promise, is kept in a field.
    # From every start, what it is handed is followed back - through variables, the callers of a
    # function (its arguments), the callbacks a function calls, what a function returns or a
    # promise settles with, the fields of `this` - until it is the path a download was written to
    # (the same path once read, or the same file name), or nothing more can be said. Bounded.
    def _path_runs(self, written, launches) -> None:
        downloads: List[_Download] = []
        for pos, (a, b), src in written:
            value = self._value(a)
            word = re.sub(r"\s+", "", self.bare[a:b])
            name = word if (_NAME_ONLY.match(word) and word not in _KEYWORDS) or (
                word.startswith("this.") and _PATH_ONLY.match(word) and word.count(".") == 1) else ""
            key = _path_key(value)
            if key or name:
                downloads.append(_Download(pos, key, name, self._place(name, pos) if name else (0, 0), src,
                                           (show(value) if isinstance(value, (str, Sym)) else self.code[a:b].strip())[:120]))
        if not downloads:
            return
        state = {"steps": 0, "seen": set(), "downloads": downloads, "found": []}
        done = {(h.line, h.sink) for h in self.hits if h.how == "dropper"}
        for at, opener, label in launches[:_PATH_STARTS]:
            line = self.flow.line_of(at)
            if (line, label) in done or state["steps"] >= _PATH_TOTAL:
                continue
            if self._close(opener) < 0:
                continue
            state["seen"], state["found"] = set(), []
            began = self._way_checked(at)
            for x, y in self._arguments(opener)[:3]:
                if not _CALLBACK.match(self.bare, self._ws(x)):
                    self._path_back(x, y, at, 0, state, (), began)
            if state["found"]:
                download, route, _checked = state["found"][0]
                shown = " -> ".join(reversed(route)) or "the same path"
                # (a signature check on every way that was found from the download to this start)
                checked = all(item[2] for item in state["found"])
                self._hit("dropper", at, label, download.src, detail="%s; followed: %s" % (download.shown, shown),
                          route=shown, checked=checked)
                if self.hits and self.hits[-1].route == shown:
                    self.hits[-1].ways = len(state["found"])
                    self.hits[-1].checked_ways = sum(1 for item in state["found"] if item[2])
                done.add((line, label))
        if state["steps"] >= _PATH_TOTAL:
            self.cut = V.also(self.cut, "more than %d steps following a downloaded file's path" % _PATH_TOTAL)

    def _path_back(self, a: int, b: int, pos: int, depth: int, state: dict, route: tuple, checked: bool) -> None:
        """Is the expression ``[a, b)`` (used at ``pos``) the path of a downloaded file? Every
        way that is found goes into ``state["found"]``: ``(download, hand-overs from the start
        back to the write, a signature check stands on that way)``."""
        if depth > _PATH_DEPTH or state["steps"] >= _PATH_TOTAL or b <= a or b - a > 4000 \
                or (a, b) in state["seen"] or len(state["found"]) >= _PATH_WAYS:
            return
        state["seen"].add((a, b))
        state["steps"] += 1
        self._tick(5)
        value = self._value(a)
        key = _path_key(value)
        word = re.sub(r"\s+", "", self.bare[a:b])
        for d in state["downloads"]:
            if (key and d.key and _same_file(key, d.key)) or (
                    d.name and word == d.name and self._place(word, pos) == d.scope):
                state["found"].append((d, route, checked))
                return
        text = _code_parts(self.code[a:b])
        if "=>" in text or re.search(r"(?<![\w$.])(?:function|class)\b", text):
            return
        for m in _CHAIN.finditer(text):
            chain, called = re.sub(r"\s+", "", m.group(1)), bool(m.group(2))
            at = a + m.start(1)
            first = chain.split(".", 1)[0]
            # (a parameter may be called `path` or `file`: no name is passed over for its word)
            if (first in _KEYWORDS and chain[:5] != "this.") or chain in _NOT_VALUES or chain in _LOCAL_VALUES \
                    or chain.startswith("process.env") or (called and chain in _THROUGH):
                continue
            if called:
                self._results_back(chain, at, depth, state, route, checked)
            elif chain.startswith("this.") and chain.count(".") == 1:
                self._field_back(chain, at, depth, state, route, checked)
            elif "." not in chain:
                self._name_back(chain, at, depth, state, route, checked)

    def _name_back(self, name: str, at: int, depth: int, state: dict, route: tuple, checked: bool) -> None:
        """``name`` at ``at``: a parameter (its callers, or what the function it is a callback
        of is handed), or a variable (what it is given in its scope)."""
        f = self._inner(at)
        while f is not None:
            if name in f.params:
                return self._parameter_back(f, f.params.index(name), depth, state, route, checked,
                                            self._flag_of(f, at))
            if self._declares(f, name):
                break
            f = f.parent
        scope = self._scope(name, at)
        count = 0
        for start, kind, end in self.flow._definitions(name):
            if kind not in ("=", "+") or not scope[0] <= start < scope[1] or self._scope(name, start) != scope:
                continue
            count += 1
            if count > 8:
                break
            self._path_back(end, self._expr_end(end, _PATH_REACH), start, depth + 1, state, route, checked)

    def _flag_of(self, f: _Function, at: int) -> Tuple[int, bool]:
        """The parameter of ``f`` (its number) on which ``at`` stands, and whether it must be
        true there: ``if (ok) { ... at ... }`` / ``if (!ok) { ... at ... }`` in ``f``'s own body;
        (-1, True): none."""
        flag = (-1, True)
        for m in _FLAG_BRANCH.finditer(self.code, f.a, at):
            if not self._real(m.start()) or m.group(2) not in f.params or self._inner(m.start()) is not f:
                continue
            after = self._ws(m.end())
            if self.bare[after:after + 1] == "{":
                holds = self._close(after) > at
            else:
                holds = self._expr_end(after, 4000) >= at
            if holds:
                flag = (f.params.index(m.group(2)), not m.group(1))
        return flag

    def _hands_false(self, arguments: List[Tuple[int, int]], flag: Tuple[int, bool]) -> bool:
        """Does a call hand the flag parameter the plain value that keeps ``at`` out (false for
        ``if (ok)``, true for ``if (!ok)``), so that it is no way there?"""
        index, true = flag
        if not 0 <= index < len(arguments):
            return False
        given = self.code[arguments[index][0]:arguments[index][1]].strip()
        return given in (("false", "!1", "0", "null", "undefined") if true else ("true", "!0"))

    def _parameter_back(self, f: _Function, index: int, depth: int, state: dict, route: tuple, checked: bool,
                        flag: Tuple[int, bool] = (-1, True)) -> None:
        """What the parameter number ``index`` of ``f`` is handed: the arguments of the calls of
        ``f`` by its name, or - for a function written as an argument - what the function it
        is handed to calls it with (``.then``: what the promise settles with). ``flag``: the
        use stands in ``if (<parameter number flag>)`` - a call that hands that a plain false
        is no way there (phageo, 2026-10-15: a start on the failure branch is no check)."""
        name = self._function_name(f)
        if len(name) >= 2:
            count = 0
            for start, opener in self._calls_of(name):
                if start == f.start or self.bare[max(0, start - 12):start].rstrip().endswith("function"):
                    continue
                count += 1
                if count > 12:
                    break
                arguments = self._arguments(opener)
                if len(arguments) > index and not self._hands_false(arguments, flag):
                    self._path_back(arguments[index][0], arguments[index][1], start, depth + 1, state,
                                    route + ("argument of " + name,), checked or self._way_checked(start))
        call = self._call_around(f.start)
        if call is None:
            return
        callee, k, receiver = call
        if callee.rsplit(".", 1)[-1] == "then":
            if k == 0 and index == 0 and receiver is not None:
                self._path_back(receiver[0], receiver[1], receiver[0], depth + 1, state, route + ("promise",), checked)
            return
        g = self._named_function(callee)
        if g is not None and k < len(g.params):
            self._callback_back(g, g.params[k], index, depth, state, route, checked, 0, flag)

    def _callback_back(self, g: _Function, callback: str, index: int, depth: int, state: dict, route: tuple,
                       checked: bool, hops: int, flag: Tuple[int, bool] = (-1, True)) -> None:
        """``callback`` is a parameter of ``g``: what ``g`` calls it with (argument number
        ``index``; not a call that hands ``flag`` a plain false) - also where ``g`` hands it on
        to another function of the file."""
        step = route + ("callback of " + (self._function_name(g) or "a function"),)
        for start, opener in self._calls_of(callback, g.a, g.b, dotted=False):
            arguments = self._arguments(opener)
            if len(arguments) > index and not self._hands_false(arguments, flag):
                self._path_back(arguments[index][0], arguments[index][1], start, depth + 1, state, step,
                                checked or self._way_checked(start))
        if hops >= 3:
            return
        for start in self._words_of(callback, g.a, g.b):
            after = self._ws(start + len(callback))
            if self.bare[after:after + 1] not in (",", ")"):
                continue
            call = self._call_around(start)
            if call is None:
                continue
            h = self._named_function(call[0])
            if h is not None and h is not g and call[1] < len(h.params):
                self._callback_back(h, h.params[call[1]], index, depth + 1, state, step,
                                    checked or self._way_checked(start), hops + 1, flag)

    def _results_back(self, chain: str, at: int, depth: int, state: dict, route: tuple, checked: bool) -> None:
        """``chain(...)`` at ``at`` calls a function of this file: what it returns, or what the
        promise it makes settles with (``resolve(x)``)."""
        g = self._named_function(chain)
        if g is None:
            return
        step = route + ("result of " + (self._function_name(g) or chain),)
        for start in self._words_of("return", g.a, g.b):
            if self._inner(start) is g:
                value = self._ws(start + 6)
                self._path_back(value, self._expr_end(value, _PATH_REACH), start, depth + 1, state, step,
                                checked or self._way_checked(start))
        for start, opener in self._calls_of("Promise", g.a, g.b, dotted=False):
            if not re.search(r"(?<![\w$.])new\s+\Z", self.bare[max(0, start - 20):start]):
                continue
            i = bisect.bisect_left(self._heads, opener + 1)
            executor = self._by_head[i] if i < len(self._heads) and self._heads[i] < opener + 41 else None
            if executor is None or not executor.params:
                continue
            for use, inner in self._calls_of(executor.params[0], executor.a, executor.b, dotted=False):
                arguments = self._arguments(inner)
                if arguments:
                    self._path_back(arguments[0][0], arguments[0][1], use, depth + 1, state, step,
                                    checked or self._way_checked(use))

    def _field_back(self, chain: str, at: int, depth: int, state: dict, route: tuple, checked: bool) -> None:
        """``this.x``: what it is given where ``this`` is the same object."""
        owner = self._home(at)
        field = chain.split(".", 1)[1]
        count = 0
        if self._parse.fields is None:
            fields: Dict[str, List[Tuple[int, int]]] = {}
            for m in _THIS_FIELD.finditer(self.bare):
                fields.setdefault(m.group(1), []).append((m.start(), m.end()))
            self._parse.fields = fields
        for start, end in self._parse.fields.get(field, ()):
            if not owner[0] <= start < owner[1] or self._home(start)[2] != owner[2]:
                continue
            count += 1
            if count > 8:
                break
            self._path_back(end, self._expr_end(end, _PATH_REACH), start, depth + 1, state,
                            route + ("field " + chain,), checked)

    def _calls_of(self, name: str, a: int = 0, b: int = -1, dotted: bool = True) -> List[Tuple[int, int]]:
        """``(start, "(" position)`` of every call of ``name`` in ``[a, b)``, in order - also as a
        method (``x.name(``) unless ``dotted`` is False. One pass over the text for all names."""
        if self._parse.calls is None:
            calls: Dict[str, List[Tuple[int, int]]] = {}
            for m in _CALL_NAME.finditer(self.bare):
                calls.setdefault(m.group(1), []).append((m.start(), m.end() - 1))
            self._parse.calls = calls
        held = self._parse.calls.get(name, ())
        b = self.n if b < 0 else b
        lo = bisect.bisect_left(held, (a, -1))
        out = []
        for start, opener in held[lo:]:
            if start >= b:
                break
            if dotted or self.bare[start - 1:start] != ".":
                out.append((start, opener))
        return out

    def _words_of(self, name: str, a: int, b: int) -> List[int]:
        """Where ``name`` stands in ``[a, b)`` as a whole word that is not a property (``_WORD``)."""
        if self._words is None:
            words: Dict[str, List[int]] = {}
            for m in _WORD.finditer(self.bare):
                words.setdefault(m.group(0), []).append(m.start())
            self._words = self._parse.words = words
        held = self._words.get(name, [])
        return held[bisect.bisect_left(held, a):bisect.bisect_left(held, b)]

    def _place(self, name: str, pos: int) -> tuple:
        """Where ``name`` (a variable, or ``this.x``) used at ``pos`` lives."""
        return self._home(pos) if name.startswith("this.") else self._scope(name, pos)

    def _function_name(self, f: _Function) -> str:
        """The name a function is called by: its own, or the name it is assigned to."""
        if f.name:
            return f.name
        m = re.compile(r"(%s)\s*[=:]\s*(?:async\s+)?\Z" % _ID).search(self.bare, max(0, f.start - 80), f.start)
        return m.group(1) if m else ""

    def _named_function(self, callee: str) -> Optional[_Function]:
        """The function of this file that ``callee`` (``name``, ``this.name``) calls - only
        one that has a single definition by that name."""
        parts = callee.split(".")
        if len(parts) > 2 or (len(parts) == 2 and parts[0] != "this"):
            return None
        name = parts[-1]
        if name in _KEYWORDS or len(name) < 2:
            return None
        if self._by_name is None:
            by_name: Dict[str, List[_Function]] = {}
            for f in self.functions:
                by_name.setdefault(self._function_name(f), []).append(f)
            self._by_name = self._parse.by_name = by_name
        found = self._by_name.get(name, [])
        return found[0] if len(found) == 1 else None

    def _call_around(self, pos: int):
        """The call whose brackets hold ``pos`` as one of its arguments: ``(callee, argument
        number, (start, end) of what the callee is called on - ``x`` of ``x.then(...)`` - or
        None)``; None when ``pos`` is not an argument of a call."""
        bare = self.bare
        before = self._back(pos - 1)
        if before >= 4 and bare[before - 4:before + 1] == "async":
            before = self._back(before - 5)
        if before < 0 or bare[before] not in "(,":
            return None
        depth, i, commas = 0, before, 0
        floor = max(0, pos - 8000)
        while i >= floor:
            ch = bare[i]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                commas += 1
            i -= 1
        if i < floor or bare[i] != "(":
            return None
        end = self._back(i - 1)
        if end < 0 or not (bare[end].isalnum() or bare[end] in "_$"):
            return None
        start, callee = self._callee(end)
        receiver = None
        if callee.endswith(".then"):
            dot = bare.rfind(".", start, end + 1)
            receiver = (start, dot) if dot > start else None
        return callee, commas, receiver

    # -- a real signature check that the start depends on (phageo, 2026-10-15, two messages) ------
    # The check is Get-AuthenticodeSignature in a command the script starts, WinVerifyTrust, a
    # verified updater library's check, or a crypto library's verify call with a public key
    # written out in the app (_crypto_kind, _constant_key). ``pos`` counts as checked only when
    # it is reached on the check's success alone. The answer - what the started command hands
    # back (its callback's parameters, ``.then``, the variable it is given to) or what the check
    # call gives back, also one step on (``const ok = out.includes("Valid")``) - is read for
    # which way it points (_implies, _atom): ``pos`` stands in a branch that is entered only
    # when the check passed, behind ``if (...) return / throw`` that leaves when it failed, or
    # behind a check that throws when it fails (``await result.signatures[0].verified``, an
    # awaited ``openpgp.verify`` with ``expectSigned: true``). A start on the failure branch is
    # no check.
    def _checked(self, pos: int) -> bool:
        """Is ``pos`` reached only when a real signature check passed?"""
        for at, kind in self._check_places():
            if at >= pos:
                break
            if pos - at <= _GATE_REACH and self._gates(at, kind, pos):
                # (which kind of check this file relies on: a crypto library's counts only when
                # the library itself is verified - read after the scan, Scanner._join_updates)
                self.relied.add(kind)
                return True
        return False

    def _check_places(self) -> List[Tuple[int, str]]:
        if self._checks is None:
            found = [(m.start(), "os") for m in _find(_OS_CHECK, self.code)]
            if self.updater:
                found += [(m.start(), "call") for m in _find(_UPDATER_CHECK, self.bare)]
            if "openpgp" in self.code or "crypto" in self.code:
                for m in _find(_CRYPTO_CHECK, self.bare):
                    kind = self._crypto_kind(m.end() - 1)
                    if kind:
                        found.append((m.start(), kind))
                    if len(found) >= _MAX_CHECKS:
                        break
            self._checks = sorted(found)[:_MAX_CHECKS]
        return self._checks

    def _gates(self, at: int, kind: str, pos: int) -> bool:
        key = (at, pos)
        known = self._gate_memo.get(key)
        if known is None:
            # (a template text is not blanked: what stands in one counts as code here)
            call = self._started_around(at) if kind == "os" else None
            sense = "text"                                  # (what a started check prints)
            if call is None and self._real(at):             # WinVerifyTrust(...), a library's own check
                opener = self.bare.find("(", at, at + 80)
                if opener > 0 and self.bare[at:opener].strip().replace(" ", "").isidentifier():
                    call = (self._callee(self._back(opener - 1))[0], opener)
                    sense = {"os": "zero", "call": "null", "pgp": "pgp", "node": "pos"}[kind]
            known = False
            if call is not None:
                names, scope = self._answer(call[0], call[1], sense)
                known = self._under(at, call, names, scope, pos, sense)
            self._gate_memo[key] = known
        return known

    def _bound(self, rx: "re.Pattern[str]") -> set:
        """The names the script gives a library by ``require`` / ``import`` (``_PGP_BOUND``,
        ``_NODE_BOUND``)."""
        key = ("bound", rx.pattern)
        names = self._markers.get(key)
        if names is None:
            names = self._markers[key] = {m.group(1) or m.group(3) for m in _find(rx, self.code)
                                          if self._real(m.start())}
        return names

    def _crypto_kind(self, opener: int) -> str:
        """``pgp`` / ``node`` for the verify call of a crypto library whose ``(`` stands at
        ``opener`` - ``openpgp.verify``, node's ``crypto.verify``, ``createVerify(...).verify`` -
        when its public key is written out in the script; "" for anything else."""
        start, callee = self._callee(self._back(opener - 1))
        parts = callee.split(".")
        if len(parts) < 2 or parts[-1] != "verify":
            return ""
        arguments = self._arguments(opener)
        if len(parts) == 2 and parts[0] in self._bound(_PGP_BOUND):
            key = self._option(arguments[0], "verificationKeys") if arguments else None
            return "pgp" if key is not None and self._constant_key(key, 0) else ""
        node = self._bound(_NODE_BOUND)
        if len(parts) == 2 and parts[0] in node:
            index = 2                                   # crypto.verify(algorithm, data, key, signature)
        elif parts[0] in node and parts[1] == "createVerify":
            index = 0                                   # crypto.createVerify(a).update(d).verify(key, signature)
        elif len(parts) == 2 and self._made_by(parts[0], start, node):
            index = 0                                   # v = crypto.createVerify(a); ... v.verify(key, signature)
        else:
            return ""
        return "node" if len(arguments) > index and self._constant_key(arguments[index], 0) else ""

    def _made_by(self, name: str, pos: int, node: set) -> bool:
        """Is ``name`` (used at ``pos``) given its one value by ``crypto.createVerify(...)``?"""
        found = self._one_value(name, pos)
        m = re.match(r"\s*(%s)\s*\.\s*createVerify\s*\(" % _ID, self.bare[found:found + 200]) if found else None
        return m is not None and m.group(1) in node

    def _one_value(self, name: str, pos: int) -> Optional[int]:
        """Where the one value of ``name`` (used at ``pos``) begins - the only ``name = ...`` in
        its scope, or in the file when its scope has none (the scope is a guess: ``const ok =
        f(KEY)`` reads as declaring ``KEY`` too); None: no such single value."""
        every = [d for d in self.flow._definitions(name)[:64]]
        lo, hi = self._scope(name, pos)
        found = [d for d in every if lo <= d[0] < hi] or every
        return found[0][2] if len(found) == 1 and found[0][1] == "=" else None

    def _option(self, span: Tuple[int, int], name: str) -> Optional[Tuple[int, int]]:
        """Where the value of the property ``name`` of the object written at ``span`` stands
        (``{ name: value }``, ``{ name }``); None: not written there."""
        s = self._ws(span[0])
        if self.bare[s:s + 1] != "{":
            return None
        for x, y in self._arguments(s)[:32]:
            m = re.match(r"\s*%s\s*(?::|\Z)" % re.escape(name), self.bare[x:y])
            if m:
                return (x + m.end(), y) if m.group(0).rstrip().endswith(":") else (self._ws(x), y)
        return None

    def _constant_key(self, span: Tuple[int, int], depth: int) -> bool:
        """Is the key at ``span`` a public key written out in the script - a text of ``_KEY_MIN``
        characters or more, reached through names given one value, ``await``, a list and the
        library's own readers (readKey, createPublicKey, Buffer.from)? A key read from a file or
        a download is not (it can be changed after the scan)."""
        a, b = self._ws(span[0]), span[1]
        text = self.bare[a:b].rstrip()
        if depth > 4 or not text:
            return False
        if re.match(r"await\b", text):
            return self._constant_key((a + 5, b), depth + 1)
        if text[0] == "[":
            items = self._arguments(a)
            return 0 < len(items) <= 8 and all(self._constant_key(i, depth + 1) for i in items)
        if _NAME_ONLY.match(text):
            found = self._one_value(text, a)
            if found is None:
                return False
            return self._constant_key((found, self._expr_end(found, 200_000)), depth + 1)
        if text.endswith(")"):
            opener = self._open(a + len(text) - 1)
            if opener <= a:
                return False
            _s, callee = self._callee(self._back(opener - 1))
            items = self._arguments(opener)
            if not _KEY_WRAP.search(callee) or not items:
                return False
            inner = self._option(items[0], "armoredKey") or self._option(items[0], "binaryKey") \
                or self._option(items[0], "key") or items[0]
            return self._constant_key(inner, depth + 1)
        value = self._value(a)
        return isinstance(value, str) and not V.is_partial(value) and len(value.strip()) >= _KEY_MIN

    def _started_around(self, at: int) -> Optional[Tuple[int, int]]:
        """``(start, "(")`` of the process start (exec, execFile, spawn ...) whose arguments hold
        the text at ``at`` - at most three brackets out."""
        bare, depth, i = self.bare, 0, at
        floor, levels = max(0, at - 4000), 0
        while i > floor and levels < 3:
            i -= 1
            ch = bare[i]
            if ch in ")]}":
                depth += 1
            elif ch in "([{":
                if depth:
                    depth -= 1
                    continue
                levels += 1
                if ch == "(":
                    end = self._back(i - 1)
                    if end >= 0 and (bare[end].isalnum() or bare[end] in "_$"):
                        start, callee = self._callee(end)
                        if _PROCESS_CALL.search(callee):
                            return start, i
        return None

    def _answer(self, start: int, opener: int, sense: str) -> Tuple[Dict[str, str], Tuple[int, int]]:
        """What the call at ``start`` hands back - each name with the way it points (``sense``:
        text - what a started check prints; zero / null / pos - the check passed when it is 0 /
        null / true; pgp - an OpenPGP result) - and where those names live: the parameters of a
        callback it is given (or of ``.then``), or the variable it is assigned to."""
        close = self._close(opener)
        if close < 0:
            return {}, (0, 0)
        callbacks = [x for x, _y in self._arguments(opener) if _CALLBACK.match(self.bare, self._ws(x))]
        then = re.compile(r"\s*\.\s*then\s*\(").match(self.bare, close + 1)
        if then:
            callbacks += [x for x, _y in self._arguments(then.end() - 1)[:1] if _CALLBACK.match(self.bare, self._ws(x))]
        for x in callbacks:
            i = bisect.bisect_left(self._heads, self._ws(x))
            if i < len(self._heads) and self._heads[i] < self._ws(x) + 8:
                f = self._by_head[i]
                if f.params:
                    if sense == "pos":                  # crypto.verify(..., (err, ok) => ...)
                        return ({f.params[1]: sense} if len(f.params) > 1 else {}), (f.a, f.b)
                    return {p: sense for p in f.params}, (f.a, f.b)
        m = _ANSWER_TO.search(self.bare, max(0, start - 400), start)
        if m:
            names = set(_IDENT.findall(m.group(1))) - _KEYWORDS
            if names:
                return {n: sense for n in names}, self._scope(sorted(names)[0], start)
        return {}, (0, 0)

    def _under(self, at: int, call: Tuple[int, int], names: Dict[str, str], scope: Tuple[int, int],
               pos: int, sense: str) -> bool:
        """Is ``pos`` reached only when the check passed - through a condition on ``names`` (or
        on the check call ``call`` itself), or behind the check's own throw?"""
        lo, hi = scope
        start, opener = call
        if names and not lo <= pos < hi:
            return False
        names = dict(names)
        if names:
            # one step on: a name given a value made of the answer (and which way that points)
            for m in _DERIVED.finditer(self.bare, max(lo, at), min(pos, hi)):
                given = m.group(1) or m.group(2)
                if given in names or given in _KEYWORDS:
                    continue
                end = self._expr_end(m.end(), 2000)
                made = self._derive(m.end(), end, names)
                if made is None:
                    continue
                if m.group(1):                          # (taken apart: const { verified } = ...)
                    for n in set(_IDENT.findall(given)) - _KEYWORDS:
                        part = _part(made, n)
                        if part:
                            names[n] = part
                else:
                    names[given] = made
                if len(names) > 24:
                    break
        if self._throws_before(at, call, names, pos, sense):
            return True
        f = self._inner(pos)
        bare = self.bare
        for m in _IF.finditer(bare, max(lo, at - 400) if names else max(0, at - 400), pos):
            if not self._real(m.start()):
                continue
            cond = m.end() - 1
            shut = self._close(cond)
            if shut < 0 or shut >= pos:
                continue
            inline = None
            if cond < opener < shut:                    # if (WinVerifyTrust(...) === 0)
                inline = (start, self._close(opener) + 1, sense)
            elif m.start() < at:
                continue
            after = self._ws(shut + 1)
            if bare[after:after + 1] == "{":
                end = self._close(after)
                if end < 0:
                    continue
                inside = after < pos < end
                body = bare[after + 1:end].strip()
                rest = end + 1
            else:
                end = self._expr_end(after, 4000)
                inside = after <= pos <= end
                body = bare[after:end].strip()
                rest = end + 1 if bare[end:end + 1] == ";" else end
            if inside:
                if self._implies(cond + 1, shut, names, True, inline):
                    return True
                continue
            # ... else { pos }: entered when the condition is false
            other = self._ws(rest)
            if re.match(r"else\b", bare[other:other + 5]):
                branch = self._ws(other + 4)
                if bare[branch:branch + 1] == "{":
                    close = self._close(branch)
                    entered = branch < pos < close
                else:
                    entered = not re.match(r"if\b", bare[branch:branch + 3]) and \
                        branch <= pos <= self._expr_end(branch, 4000)
                if entered and self._implies(cond + 1, shut, names, False, inline):
                    return True
            # if (...) return / throw: what follows in the same block is reached only past it -
            # when the condition is false
            if _LEAVES.search(body) and end < pos and self._inner(m.start()) is f \
                    and self._holds_to(m.start(), pos) and self._implies(cond + 1, shut, names, False, inline):
                return True
        return False

    def _holds_to(self, a: int, pos: int) -> bool:
        """Does the block that holds ``a`` also hold ``pos`` (no bracket open at ``a`` closes on
        the way - a guard in a branch, a ``try`` whose ``catch`` swallows the throw ...)?"""
        depth = 0
        for m in _BRACKETS.finditer(self.bare, a, pos):
            depth += 1 if m.group(0) in "([{" else -1
            if depth < 0:
                return False
        return True

    def _throws_before(self, at: int, call: Tuple[int, int], names: Dict[str, str], pos: int, sense: str) -> bool:
        """Is ``pos`` behind a check that throws when it fails, in the same block: an awaited
        promise of an OpenPGP result (``await verified``, ``await sig.verified``) or an awaited
        ``openpgp.verify`` with ``expectSigned: true``?"""
        f = self._inner(pos)
        if sense == "pgp" and self._inner(at) is f and self._close(call[1]) < pos and \
                re.search(r"await\s*\Z", self.bare[max(0, call[0] - 40):call[0]]):
            items = self._arguments(call[1])
            flag = self._option(items[0], "expectSigned") if items else None
            if flag is not None and self.code[flag[0]:flag[1]].strip() in ("true", "!0") and self._holds_to(call[0], pos):
                return True
        for name, kind in names.items():
            if kind not in ("promise", "pgp"):
                continue
            tail = "" if kind == "promise" else r"(?:\s*\.\s*signatures\s*\[\s*\d+\s*\])?\s*\.\s*verified"
            for m in re.finditer(r"(?<![\w$.])await\s+%s%s(?![\w$.(\[])" % (re.escape(name), tail),
                                 self.bare[at:pos]):
                where = at + m.start()
                if self._real(where) and self._inner(where) is f and self._holds_to(where, pos):
                    return True
        return False

    def _derive(self, a: int, b: int, names: Dict[str, str]) -> Optional[str]:
        """Which way a value made of the answer points (None: none that can be read)."""
        text = self.bare[a:b].strip()
        if not text or not any(re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(n), text) for n in names):
            return None
        way = self._atom(a, b, names, None)
        if way == 1:
            return "pos"                                # const ok = out.includes("Valid")
        if way == -1:
            return "falsy"                              # const bad = out !== "Valid"
        m = re.fullmatch(r"(?:await\s+)?(%s)((?:\s*\.\s*%s|\s*\[[^\[\]]{0,40}\])*)" % (_ID, _ID), text)
        if m and m.group(1) in names:
            props = re.findall(r"\.\s*(%s)" % _ID, m.group(2))
            base = names[m.group(1)]
            if not props:
                return base
            return _part(base, props[-1]) if base in ("pgp", "text") else None
        if any(names[n] == "text" and re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(n), text) for n in names) \
                and not re.search(r"[=!<>?]", text):
            return "text"                               # String(out).trim()
        return None

    def _top(self, a: int, b: int, op: str) -> List[Tuple[int, int]]:
        """``[a, b)`` cut at ``op`` where it stands outside every bracket."""
        parts, depth, start, i, bare = [], 0, a, a, self.bare
        while i < b:
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif depth == 0 and bare.startswith(op, i):
                parts.append((start, i))
                i += len(op)
                start = i
                continue
            i += 1
        parts.append((start, b))
        return parts

    def _implies(self, a: int, b: int, names: Dict[str, str], when: bool, inline, depth: int = 0) -> bool:
        """Does the condition ``[a, b)`` being ``when`` mean that the check passed?"""
        while a < b and self.bare[a] in " \t\r\n":
            a += 1
        while b > a and self.bare[b - 1] in " \t\r\n":
            b -= 1
        if a >= b or depth > 8 or b - a > 2000:
            return False
        if len(self._top(a, b, "?")) > 1:
            return False                                # (a ? b : c, a?.b, a ?? b - not read)
        ors = self._top(a, b, "||")
        if len(ors) > 1:
            ways = [self._implies(x, y, names, when, inline, depth + 1) for x, y in ors]
            return all(ways) if when else any(ways)
        ands = self._top(a, b, "&&")
        if len(ands) > 1:
            ways = [self._implies(x, y, names, when, inline, depth + 1) for x, y in ands]
            return any(ways) if when else all(ways)
        compared = self._compared(a, b)
        if compared is None and self.bare[a] == "!":
            return self._implies(a + 1, b, names, not when, inline, depth + 1)
        if compared is None and self.bare[a] == "(" and self._close(a) == b - 1:
            return self._implies(a + 1, b - 1, names, when, inline, depth + 1)
        return self._atom(a, b, names, inline) == (1 if when else -1)

    def _compared(self, a: int, b: int) -> Optional[Tuple[int, int, str]]:
        """``(start, end, operator)`` of the one comparison outside every bracket in ``[a, b)``
        (None: none; ``(-1, -1, "")``: more than one)."""
        found, depth, bare = [], 0, self.bare
        i = a
        while i < b:
            ch = bare[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif depth == 0 and ch in "=!<>":
                m = _TOP_OPS.match(bare, i)
                if m and m.group(0) not in ("&&", "||") and not (m.group(0) == "!" or bare[i:i + 2] == "=>"):
                    found.append((m.start(), m.end(), m.group(0)))
                    i = m.end()
                    continue
            i += 1
        return None if not found else found[0] if len(found) == 1 else (-1, -1, "")

    def _atom(self, a: int, b: int, names: Dict[str, str], inline) -> Optional[int]:
        """One test: 1 - it holds only when the check passed; -1 - it holds only when it failed;
        0 - not about the answer; None - about it, but which way is not read."""
        bare, code = self.bare, self.code
        senses = {names[n] for n in names if re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(n), bare[a:b])}
        if inline is not None and a <= inline[0] < b:
            senses.add(inline[2])
        if not senses:
            return 0
        if len(senses) > 1:
            return None
        sense = senses.pop()
        compared = self._compared(a, b)
        if compared is not None:
            x, y, op = compared
            if x < 0:
                return None
            left, right = (a, x), (y, b)
            if not self._mentions(left, names, inline):
                left, right = right, left
            if self._mentions(right, names, inline):
                return None
            literal = _literal(code[right[0]:right[1]])
            if literal is _UNKNOWN:
                return None
            side = bare[left[0]:left[1]]
            if re.search(r"\.\s*(?:indexOf|search)\s*\(", side):
                if sense != "text" or "Valid" not in code[left[0]:left[1]] or literal not in (-1, 0):
                    return None
                found = {("!==", -1), ("!=", -1), (">", -1), (">=", 0)}
                missing = {("===", -1), ("==", -1), ("<", 0)}
                return 1 if (op, literal) in found else -1 if (op, literal) in missing else None
            sense = self._sense_of(left, sense, names, inline)
            if sense is None or op not in ("===", "==", "!==", "!="):
                return None
            way, exact = _equal(sense, literal)
            if way is None:
                return None
            if op in ("===", "=="):
                return way
            return -way if exact else None
        text = code[a:b]
        if sense == "text" and "Valid" in text and \
                re.search(r"\.\s*(?:includes|startsWith|endsWith|test|match)\s*\(", text):
            return 1                                    # out.includes("Valid"), /^Valid/.test(out)
        if inline is not None and a <= inline[0] < b:
            if bare[a:inline[0]].strip() not in ("", "await") or bare[inline[1]:b].strip():
                return None
            awaited = False                             # if (WinVerifyTrust(...)) - the call alone
        else:
            plain = re.fullmatch(r"(await\s+)?(%s)((?:\s*\.\s*%s|\s*\[[^\[\]]{0,40}\])*)" % (_ID, _ID), bare[a:b].strip())
            if plain is None or plain.group(2) not in names:
                return None
            awaited = bool(plain.group(1))
            sense = self._sense_of((a, b), sense, names, inline)
        if sense == "promise":
            return 1 if awaited else None               # (a promise is always true; awaited, it throws)
        return {"pos": 1, "falsy": -1, "zero": -1, "null": -1}.get(sense)

    def _mentions(self, span: Tuple[int, int], names: Dict[str, str], inline) -> bool:
        if inline is not None and span[0] <= inline[0] < span[1]:
            return True
        return any(re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(n), self.bare[span[0]:span[1]]) for n in names)

    def _sense_of(self, span: Tuple[int, int], sense: str, names: Dict[str, str], inline) -> Optional[str]:
        """The way a side of a test points: the name's own, or a part of an OpenPGP result
        (``.valid``, ``.verified``); a value the side makes of the name in another way (a call
        with arguments, arithmetic) points nowhere that can be read."""
        text = self.bare[span[0]:span[1]].strip()
        if inline is not None and span[0] <= inline[0] < span[1]:
            rest = self.bare[inline[1]:span[1]].strip()
            return sense if not rest or re.fullmatch(r"\)*", rest) else None
        m = re.fullmatch(r"(?:await\s+)?(?:String\s*\(\s*)?(%s)((?:\s*\.\s*%s|\s*\[[^\[\]]{0,40}\]|\s*\(\s*\))*)\s*\)?"
                         r"((?:\s*\.\s*%s\s*\(\s*\))*)" % (_ID, _ID, _ID), text)
        if m is None or m.group(1) not in names:
            return None
        if sense == "pgp":
            props = re.findall(r"\.\s*(%s)(?!\s*\()" % _ID, m.group(2))
            return _part(sense, props[-1]) if props else None
        if sense != "text" and (m.group(2).strip() or m.group(3).strip()):
            return None                                 # (a part of a true / 0 / null answer: not read)
        return sense

    # -- a marker file written only after a signature check (phageo, 2026-10-14, forty-third message) --
    # An updater often checks the download in one run of the app and starts it in another: after
    # the check it writes a small file (`{ is: "ready" }`), and the start only happens when that
    # file says so. The check then stands before the marker's write, not before the start. A way
    # counts as checked through such a marker only when the start stands behind a guard on a
    # value read from the marker file, and EVERY write of the file in this script that can give
    # it that value stands after a signature check - directly, or in the branch of a callback
    # that only a call after a check can enter. A write of the file that is not understood (a
    # stream, a copy, a rename onto it) or no write at all: not checked.
    def _way_checked(self, pos: int) -> bool:
        """A signature check before ``pos`` (``_checked``), or a guard on a marker file that the
        script writes only after one (``_gated``)."""
        return self._checked(pos) or self._gated(pos)

    def _gated(self, pos: int) -> bool:
        f = self._inner(pos)
        if f is None:
            return False
        key = ("gates", f.a)
        gates = self._markers.get(key)
        if gates is None:
            gates = self._markers[key] = self._guards(f)
        for at, end, root, value in gates:
            if at < pos <= end and self._marker_checked(f, at, root, value):
                return True
        return False

    def _guards(self, f: _Function) -> List[Tuple[int, int, str, str]]:
        """``(where, up to where it holds, variable, value)`` of each guard in ``f``: ``if (v.x
        !== "C") return ...`` (holds to the end of ``f``) and ``if (v.x === "C") { ... }`` (holds
        in its block)."""
        out: List[Tuple[int, int, str, str]] = []
        for m in _MARKER_GUARD.finditer(self.code, f.a, f.b):
            if not self._real(m.start()) or self._inner(m.start()) is not f or len(out) >= 16:
                continue
            if m.group("not"):
                if m.group("ret"):
                    out.append((m.start(), f.b, m.group("root"), m.group("value")))
            elif m.group("block"):
                close = self._close(m.end() - 1)
                if close > 0:
                    out.append((m.start(), close, m.group("root"), m.group("value")))
        return out

    def _marker_checked(self, f: _Function, at: int, root: str, value: str) -> bool:
        """The guard at ``at`` compares a value read from a file; every write of that file in the
        script that can give it ``value`` stands after a signature check."""
        key = ("marker", f.a, at)
        known = self._markers.get(key)
        if known is not None:
            return known
        self._markers[key] = False
        marker = ""
        for start, kind, end in self.flow._definitions(root)[:64]:
            if not f.a <= start < at or self._inner(start) is not f:
                continue
            expr = self.code[end:self._expr_end(end, _PATH_REACH)]
            read = _MARKER_READ.search(expr)
            if read is None:
                if re.search(r"""(["'`])%s\1""" % re.escape(value), expr):
                    return False                        # (the value is given here, not read)
                continue
            found = _path_key(self._value(end + read.end()))
            if not found or (marker and found != marker):
                return False
            marker = found
        if not marker:
            return False
        quoted = re.compile(r"""(["'`])%s\1""" % re.escape(value))
        writes = 0
        for name in _MARKER_WRITES:
            for start, opener in self._calls_of(name)[:64]:
                arguments = self._arguments(opener)
                if not arguments:
                    continue
                places = arguments[:2] if name in _MARKER_MOVES else arguments[:1]
                keys = [_path_key(self._value(a)) for a, _b in places]
                if not any(k and _same_file(k, marker) for k in keys):
                    continue
                if name not in _MARKER_PLAIN or len(arguments) < 2:
                    return False                        # (what it writes is not read here)
                if not quoted.search(self.code, arguments[1][0], arguments[1][1]):
                    continue                            # (another state: "downloading" ...)
                if not (self._checked(start) or self._branch_checked(start)):
                    return False
                writes += 1
        self._markers[key] = writes > 0
        return writes > 0

    def _branch_checked(self, pos: int) -> bool:
        """``pos`` stands in ``if (ok) { ... }`` of a function handed to another function as its
        callback (``check(file, (ok, ...) => { if (ok) ... })``), and every call of that callback
        that does not hand it a plain ``false`` stands after a signature check - also where the
        callback is handed on to a third function (three hops)."""
        h = self._inner(pos)
        if h is None or not h.params:
            return False
        flag = None
        for m in _MARKER_BRANCH.finditer(self.code, h.a, pos):
            if self._real(m.start()) and m.group(1) in h.params and self._inner(m.start()) is h:
                close = self._close(m.end() - 1)
                if close > pos:
                    flag = h.params.index(m.group(1))
        if flag is None:
            return False
        call = self._call_around(h.start)
        if call is None:
            return False
        g = self._named_function(call[0])
        if g is None or call[1] >= len(g.params):
            return False
        calls: List[Tuple[int, int]] = []
        self._callback_calls(g, g.params[call[1]], 0, calls)
        if not calls:
            return False
        for start, opener in calls:
            arguments = self._arguments(opener)
            if len(arguments) <= flag:
                return False
            given = self.code[arguments[flag][0]:arguments[flag][1]].strip()
            if given in ("false", "!1", "0", "null", "undefined"):
                continue
            if not self._checked(start):
                return False
        return True

    def _callback_calls(self, g: _Function, callback: str, hops: int, out: List[Tuple[int, int]]) -> None:
        if len(out) > 32:
            return
        out.extend(self._calls_of(callback, g.a, g.b, dotted=False))
        if hops >= 3:
            return
        for start in self._words_of(callback, g.a, g.b):
            after = self._ws(start + len(callback))
            if self.bare[after:after + 1] not in (",", ")"):
                continue
            call = self._call_around(start)
            h = self._named_function(call[0]) if call is not None else None
            if h is not None and h is not g and call[1] < len(h.params):
                self._callback_calls(h, h.params[call[1]], hops + 1, out)

    def _written_name(self, a: int, b: int, pos: int) -> str:
        """The last file name with an ending that is written out in the path expression
        ``[a, b)`` - or, when that is one name, in what the name was last given before
        ``pos`` ("": none)."""
        code = self.code
        names = _FILE_NAME.findall(code[a:b])
        word = code[a:b].strip()
        if not names and re.fullmatch(_ID, word):
            given = None
            for given in re.compile(r"(?<![\w$.])%s\s*=(?!=)" % re.escape(word)).finditer(self.bare, max(0, pos - 20_000), pos):
                pass
            if given is not None:
                names = _FILE_NAME.findall(code[given.end():self._expr_end(given.end())][:600])
        return names[-1] if names else ""

    def _feeding_texts(self, start: int, stop: int = 0) -> str:
        """The quoted texts in the expression at ``start`` and in what the names it uses
        were given - assignments, ``+=``, a property of that name, the body of a function of
        that name -, a few steps deep, one after the other ("": none, or the expression
        turns a value into JSON). For a written value the reading could not put together."""
        bare, code = self.bare, self.code
        if self._quoted is None:
            self._quoted = quoted_text(code)
        quoted = self._quoted

        def ends(pos: int) -> int:
            # where the expression at pos ends - a template of several lines, or one behind a
            # tag (String.raw`...`), does not end it
            end = self._expr_end(pos)
            for _ in range(8):
                i = bisect.bisect_right(quoted.begins, end + 1) - 1
                at = self._ws(end)
                if i >= 0 and end < quoted.ends[i]:
                    end = self._expr_end(quoted.ends[i] + 1)
                elif bare[at:at + 1] == "`":
                    j = bisect.bisect_left(quoted.begins, at)
                    if j >= len(quoted.begins) or quoted.begins[j] != at + 1:
                        break
                    end = self._expr_end(quoted.ends[j] + 1)
                else:
                    break
            return end

        end = max(stop, ends(start))
        if re.match(r"\s*JSON\s*\.\s*stringify\s*\(", bare[start:end]):
            return ""
        regions, seen, parts, size = [(start, end, 0)], set(), [], 0
        while regions and len(seen) < _MAX_FEEDING:
            a, b, depth = regions.pop(0)
            if (a, b) in seen or b <= a:
                continue
            seen.add((a, b))
            self._tick(20)
            i = bisect.bisect_left(quoted.begins, a)
            while i < len(quoted.begins) and quoted.begins[i] < b and size < MAX_WRITTEN_TEXT:
                piece = code[quoted.begins[i]:quoted.ends[i]]
                parts.append(piece)
                size += len(piece)
                i += 1
            if depth >= _FEEDING_DEPTH:
                continue
            for m in _FED_NAME.finditer(bare, a, min(b, a + 4000)):
                name = m.group(1)
                if name in _QUIET or name in _FED_SKIP or quoted.holds(m.start()):
                    continue
                given = re.compile(r"(?<![\w$])%s\s*(?:\+?=(?!=)|:(?!:))" % re.escape(name))
                found = 0
                for use in given.finditer(bare, max(0, start - _FEEDING_REACH), min(self.n, start + _FEEDING_REACH)):
                    if not quoted.holds(use.start()) and not a <= use.start() < b:
                        regions.append((use.end(), ends(use.end()), depth + 1))
                        found += 1
                        if found >= 6:
                            break
                for f in self.functions:
                    if f.name == name:
                        regions.append((f.a, f.b, depth + 1))
                        break
        text = "\n".join(parts)
        return _ESCAPED.sub(lambda m: _ESCAPES.get(m.group(1), m.group(1)), text)[:MAX_WRITTEN_TEXT]

    def _trace_texts(self, launches) -> None:
        """For ``WRITTEN_TRACE``: where the long quoted texts of the script stand and what
        takes them - the name of the call around them only when it is one of a fixed list of
        well-known functions -, and how many arguments each start has. Numbers only."""
        if self._quoted is None:
            self._quoted = quoted_text(self.code)
        quoted, bare = self._quoted, self.bare
        known = ("writeFileSync", "writeFile", "appendFileSync", "appendFile", "spawn", "spawnSync", "exec", "execSync",
                 "execFile", "execFileSync", "fork", "eval", "Function", "executeJavaScript", "loadURL", "send", "write",
                 "end", "from", "join", "concat", "push", "stringify", "replace", "trim", "setTimeout", "runInThisContext",
                 "require", "insertCSS", "postMessage", "encode", "btoa", "atob", "log", "raw")
        shown = 0
        for a, b in zip(quoted.begins, quoted.ends):
            if b - a < 200 or shown >= 12:
                continue
            shown += 1
            opener, depth, i = -1, 0, a - 1
            while i >= max(0, a - 3000):                     # the bracket the text stands in
                ch = bare[i]
                if ch == ")":
                    depth += 1
                elif ch == "(":
                    if depth == 0:
                        opener = i
                        break
                    depth -= 1
                i -= 1
            callee = re.search(r"(%s)\s*\Z" % _ID, bare[max(0, opener - 60):opener]) if opener >= 0 else None
            before = bare[max(0, a - 40):a - 1].rstrip()
            WRITTEN_TRACE.append("   text lines %d-%d, %d characters | inside the brackets of: %s | right after: %s" % (
                self.flow.line_of(a), self.flow.line_of(b), b - a,
                "nothing" if opener < 0 else callee.group(1) if callee and callee.group(1) in known else "another function",
                "=" if before.endswith("=") else "(" if before.endswith("(") else "," if before.endswith(",")
                else ":" if before.endswith(":") else "+" if before.endswith("+") else "return" if before.endswith("return")
                else "something else"))
        for at, opener, label in launches[:12]:
            arguments = self._arguments(opener)
            close = self._close(opener)
            inside = sum(1 for a in quoted.begins if opener < a < close) if close > 0 else 0
            WRITTEN_TRACE.append("   start line %d (%s): %d argument(s), %d quoted text(s) in its brackets, %d name(s)" % (
                self.flow.line_of(at), label, len(arguments), inside,
                len({w for w in _WORD.findall(bare[opener + 1:close])} - _QUIET) if close > 0 else 0))

    def _names_behind(self, a: int, b: int, pos: int) -> set:
        """The names that stand in what the names of ``[a, b)`` were given, two steps deep
        (``args = ["/c", file]; spawn(tool, args)``: ``file`` stands behind ``args``)."""
        bare = self.bare
        out: set = set()
        todo = [(name, 0) for name in sorted({w for w in _WORD.findall(bare[a:b])} - _QUIET)[:8]]
        seen = set()
        while todo and len(seen) < 24:
            name, depth = todo.pop(0)
            if name in seen:
                continue
            seen.add(name)
            self._tick(10)
            given = re.compile(r"(?<![\w$.])%s\s*=(?!=)" % re.escape(name))
            for count, use in enumerate(given.finditer(bare, max(0, pos - _FEEDING_REACH), pos)):
                if count >= 4:
                    break
                found = {w for w in _WORD.findall(bare[use.end():self._expr_end(use.end())][:2000])} - _QUIET
                out |= found
                if depth < 1:
                    todo += [(word, depth + 1) for word in sorted(found)[:8]]
            # ... and what is pushed into it: args.push(file)
            for count, use in enumerate(re.compile(r"(?<![\w$.])%s\s*\.\s*(?:push|unshift|concat)\s*\(" % re.escape(name)).finditer(
                    bare, max(0, pos - _FEEDING_REACH), pos)):
                if count >= 8:
                    break
                close = self._close(use.end() - 1)
                if close > 0:
                    out |= {w for w in _WORD.findall(bare[use.end():close][:2000])} - _QUIET
        return out

    def _local(self, a: int, b: int, depth: int = 0, seen: frozenset = frozenset()) -> bool:
        """Is every part of the expression ``code[a:b]`` that is not written out one of the
        app's own, local values (phageo, 2026-10-14): ``__dirname``, ``process.env``,
        ``process.platform``, ``app.getPath()`` ... (``_LOCAL_VALUES``), passed through
        ``path.join()`` and the like (``_THROUGH``), or a variable of this file whose every
        assignment is such a value? Anything else - a parameter, what a call returns (a
        download, a file read, a message of a page), a field of an object - is not: False.
        Bounded: four steps from variable to variable, eight assignments per variable."""
        if depth > 4 or b - a > 4000:
            return False
        self._tick(5)
        text = _code_parts(self.code[a:b])
        if "=>" in text or re.search(r"(?<![\w$.])(?:function|class|await|yield|this)\b", text):
            return False
        text = _KEY.sub(r"\1", text)                          # { cwd: x } - the key is a name, not a value
        for m in _CHAIN.finditer(text):
            chain, called = re.sub(r"\s+", "", m.group(1)), bool(m.group(2))
            if chain in _NOT_VALUES or chain in _LOCAL_VALUES or chain.startswith("process.env") \
                    or chain.endswith(_APP_PATHS) or (called and chain in _THROUGH):
                continue
            if called or "." in chain or chain in seen or not _NAME_ONLY.match(chain):
                if chain in seen:
                    continue                                  # x = x + "-y": what it was, and a constant
                return False
            if chain in self.flow._parameters():
                return False                                  # what a caller hands in is not known
            places = self.flow._definitions(chain)
            if not places or len(places) > 8:
                return False
            for _start, kind, end in places:
                if kind not in ("=", "+") or not self._local(end, self._expr_end(end), depth + 1, seen | {chain}):
                    return False
        return True

    def _written(self) -> List[Written]:
        """See :func:`written_and_started`."""
        bare, code = self.bare, self.code
        self._find_functions()
        writes: List[Tuple[int, Tuple[int, int], Tuple[int, int]]] = []    # (position, path argument, text argument)
        for m in list(_find(_WRITE, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            if len(arguments) >= 2:
                writes.append((m.start(), arguments[0], arguments[1]))
        writers: Dict[str, Tuple[int, int]] = {}
        for m in list(_find(_STREAM, bare))[:_MAX_SITES]:
            arguments = self._arguments(m.end() - 1)
            named = _WRITER_NAMED.search(bare, max(0, m.start() - 120), m.start())
            if arguments and named:
                writers[named.group(1)] = arguments[0]
        for name, path in sorted(writers.items()):
            for m in list(re.compile(r"(?<![\w$.])%s\s*\.\s*(?:write|end)\s*\(" % re.escape(name)).finditer(bare))[:40]:
                arguments = self._arguments(m.end() - 1)
                if arguments:
                    writes.append((m.start(), path, arguments[0]))
        if not writes:
            return []
        launches = self._launches() if "child_process" in code else []
        if "ActiveXObject" in code or "CreateObject" in code:
            launches = launches + self._wsh_launches()
        launches = launches + self._loads()
        out: List[Written] = []
        starts: Dict[int, list] = {}
        if WRITTEN_TRACE is not None:
            labels: Dict[str, int] = {}
            for _at, _opener, label in launches:
                labels[label] = labels.get(label, 0) + 1
            WRITTEN_TRACE.append("%d characters: %d write(s), %d start(s) %s" % (self.size, len(writes), len(launches), labels))
            self._trace_texts(launches)
        for pos, (a, b), (text_at, text_end) in sorted(writes)[:200]:
            self._tick(50)
            if WRITTEN_TRACE is not None:
                content = self._value(text_at)
                WRITTEN_TRACE.append("   write line %d | path: %d name(s), read as text: %s | written value: %s" % (
                    self.flow.line_of(pos), len({w for w in _WORD.findall(bare[a:b])} - _QUIET),
                    "yes" if isinstance(self._value(a), (str, Sym)) else "no",
                    "%s, %d characters known" % (type(content).__name__, len(V.known_part(show(content))))
                    if isinstance(content, (str, Sym)) else type(content).__name__))
            words = {w for w in _WORD.findall(bare[a:b])} - _QUIET
            value = self._value(a)
            literal = show(value) if isinstance(value, (str, Sym)) else ""
            known = V.known_part(literal)
            base = re.split(r"[\\/]", known)[-1].strip()
            for at, opener, label in launches:
                seen = starts.get(opener)
                if seen is None:                             # (each start is read once, for all writes)
                    close = self._close(opener)
                    started = self._value(self._ws(opener + 1)) if close > 0 else None
                    seen = starts[opener] = [close, set(_WORD.findall(bare[opener + 1:close])) if close > 0 else set(),
                                             show(started) if isinstance(started, (str, Sym, list)) else "", None]
                close, inside, shown, behind = seen
                if close < 0:
                    continue
                self._tick()
                # (the same variable, not the same word: `options` in two functions of a bundle
                # are two things - measured on a clean launcher, 2026-10-13)
                same = lambda found: any(self._scope(word, pos) == self._scope(word, at) for word in words & found)
                reached = same(inside) or (len(base) >= 3 and (base in shown or base in code[opener + 1:close]))
                if not reached and words:
                    if behind is None:
                        behind = seen[3] = self._names_behind(opener + 1, close, at)
                    reached = same(behind)
                if not reached:
                    continue
                content = self._value(text_at)
                written = show(content) if isinstance(content, (str, Sym)) else ""
                if len(V.known_part(written).strip()) < _MIN_WRITTEN_TEXT:
                    # the value is not put together in a way the reading follows (a function
                    # that returns the text, .replace(), a property, a buffer): the quoted
                    # texts of the expressions it is made from, as they stand
                    written, taken = "", True
                else:
                    taken = False
                ending = _PATH_ENDING.search(literal.strip())
                ending = ending.group(1).lower() if ending else ""
                if not ending:
                    # the path is put together by a call (path.join(os.tmpdir(), "helper.js")):
                    # the last file name written out in it, or in what its name was given
                    named = self._written_name(a, b, pos)
                    ending = _PATH_ENDING.search(named).group(1).lower() if named else ""
                    literal = literal or named
                language = WRITTEN_SCRIPTS.get(ending, "")
                if not ending and (label == "require" or re.match(r"node(?:\.exe)?\b", shown.strip())):
                    language = "js"                          # require(file), node <file>: JavaScript
                if taken and (language or ending in WRITTEN_PROGRAMS):
                    # (only for a file that is a script or a program by its name or by how it is
                    # started: for any other file the quoted texts around a value say too little)
                    written = self._feeding_texts(text_at, text_end)
                if WRITTEN_TRACE is not None:
                    WRITTEN_TRACE.append("      -> its file reaches the start at line %d (%s): ending %r, %d characters of text" % (
                        self.flow.line_of(at), label, ending, len(V.known_part(written).strip())))
                if (len(V.known_part(written).strip()) < _MIN_WRITTEN_TEXT or ending in WRITTEN_DATA
                        or (not ending and _looks_like_data(written))):
                    break                                    # no text that can be read, or data
                out.append(Written(self.flow.line_of(at), label, self.flow.line_of(pos), literal[:200], ending,
                                   language, written[:MAX_WRITTEN_TEXT]))
                break
            if len(out) >= MAX_WRITTEN:
                break
        return out

    def _starts_of(self) -> List[Start]:
        bare, code = self.bare, self.code
        launches = self._launches() if "child_process" in code else []
        if "ActiveXObject" in code or "CreateObject" in code:
            launches = launches + self._wsh_launches()
        launches = launches + [item for item in self._loads() if item[2].startswith("open")]
        out: List[Start] = []
        constant = lambda value: isinstance(value, str) or (
            isinstance(value, list) and all(isinstance(item, str) for item in value))
        for pos, opener, label in sorted(launches)[:MAX_STARTS]:
            self._tick(20)
            close = self._close(opener)
            arguments = self._arguments(opener) if close > 0 else []
            line = self.flow.line_of(pos)
            via = "child_process" if label.startswith("child_process") else label
            if via == "child_process" and self._only_check(opener):
                via = "check"                       # (the signature check's own PowerShell)
            if not arguments:
                out.append(Start(line, OPEN_START, False, "", False, via))
                continue
            first = self._value(arguments[0][0])
            shown = show(first).lower() if isinstance(first, (str, Sym, list)) else ""
            # (what is handed over: the program, its arguments, the options - not a callback)
            given = [(x, y) for x, y in arguments[:3]
                     if "=>" not in bare[x:y] and not bare[self._ws(x):y].startswith("function")]
            local = lambda: all(self._local(x, y) for x, y in given)
            if not label.startswith("child_process"):
                out.append(Start(line, SHELL, constant(first), shown,       # the Script Host, the shell's open
                                 _plain_command(shown) and local(), via))
                continue
            word = _IDENT.findall(bare[pos:opener])
            method = word[-1] if word else ""
            method = method if method in _SPLIT_START or method in ("exec", "execSync") else self._cp_methods.get(method, "exec")
            if method not in _SPLIT_START:
                # a command line for the shell: local when what is not written out is the app's
                # own, the command does not hand its text to a script runtime, and it is one
                # command - no operator of the shell in it
                out.append(Start(line, SHELL, isinstance(first, str), shown,
                                 _plain_command(shown) and local(), via))
                continue
            rest_known, rest = True, ""
            if len(arguments) > 1 and bare[self._ws(arguments[1][0]):][:1] != "{":
                second = self._value(arguments[1][0])
                rest_known = constant(second)
                rest = " " + show(second).lower() if isinstance(second, (str, Sym, list)) else ""
            known = isinstance(first, str) and rest_known
            name = re.split(r"[\\/]", V.known_part(shown).strip().strip("\"'"))[-1]
            name = name[:-4] if name.endswith(".exe") else name
            # (the program may be a name the reading keeps as a reference: process.execPath)
            runtime = name in _INTERPRETERS or _runtime(shown) or _runtime(show(first).lower())
            if _SHELL_OPTION.search(bare, arguments[0][1], close):
                kind = SHELL
            elif runtime:
                kind = RUNTIME
            else:
                kind = QUIET if known else OPEN_START
            out.append(Start(line, kind, known, shown + rest, kind in (SHELL, OPEN_START) and not runtime and (
                kind != SHELL or _plain_command(shown + rest)) and local(), via))
        return out

    def run(self) -> List[Hit]:
        bare, code = self.bare, self.code
        if self.size > MAX_SOURCE:                           # what lies behind that is not read at all
            self.cut = "larger than %d MB" % (MAX_SOURCE >> 20)
        if not _HINT.search(code):
            return []
        # most files neither request anything nor load a script: they cost one look
        if not (_ACCESS.search(bare) or _NET_CALL.search(bare) or _LOADER.search(bare) or _JQ_LOAD.search(bare)
                or ("require" in code and (_NET_ALIAS.search(code) or _NET_INLINE.search(code)))
                or ("createElement" in code and _SCRIPT_NEW.search(code))):
            return []
        if not self._has_sink():
            # nothing here runs code, starts a program or loads a script: no download can reach
            # one, so the reading is not done - it would find nothing (phageo, 2026-10-14, forty-
            # second message). Until then such a text was followed to its end, and a large one
            # could stop at the step limit, with its note, without a place it could have reached.
            return []
        try:
            self._find_functions()
            self._sources()
            self._propagate()
        except Budget:
            self._cut()                                      # keep what was found so far
        except RecursionError:
            self.cut = V.also(self.cut, "nested too deeply")
        try:
            self._sinks()
        except Budget:
            self._cut()
        except RecursionError:
            self.cut = V.also(self.cut, "nested too deeply")
        for hit in self.hits:
            if hit.checked or hit.checked_ways:
                hit.checks = tuple(sorted(self.relied))
        return self.hits + self.weak

    def _has_sink(self) -> bool:
        """Does the text have a place a download would have to reach to be run - code that is
        run (``eval``, ``Function``, ``vm``, a name put together in brackets and called), a
        WebAssembly module, a loader (``import()``, ``importScripts``, a ``Worker``, a script
        element), a program start (``child_process``, the Script Host), or a file that is
        written beside something that starts or loads a file? The same patterns the sinks are
        looked for with (``_sinks``), searched once each; where a pattern can only say "maybe"
        the answer is yes."""
        bare, code = self.bare, self.code
        if _CODE_SINK.search(bare) or _THEN_EVAL.search(bare) or _LOADER.search(bare) or _BUILT_SINK.search(bare) \
                or _NAMED_SINK.search(code) or _JQ_LOAD.search(bare) \
                or ("dataType" in code and _JQ_SCRIPT_TYPE.search(code)):
            return True
        if "child_process" in code or "ActiveXObject" in code or "CreateObject" in code:
            return True
        if ("WebAssembly" in code and _WASM_SINK.search(code)) or ("createElement" in code and _SCRIPT_NEW.search(code)):
            return True
        return bool((_WRITE.search(bare) or _STREAM.search(bare) or _WSH_SAVE.search(bare) or _WSH_FILE.search(bare))
                    and _LAUNCH.search(bare))

    def _cut(self) -> None:
        """The reading stopped: at its count of steps (the limit - the same file is always
        cut at the same place), or at the clock, which is only an emergency brake for a PC
        so slow that the steps take too long. Either way that is said."""
        self.cut = V.also(self.cut, "more than %d steps" % MAX_STEPS if self.clock.steps <= 0
                                else "%.0f seconds" % MAX_SECONDS)


_UNKNOWN = object()


def _literal(text: str) -> Any:
    """The value of a literal a check's answer is compared with (``_UNKNOWN``: not one)."""
    text = text.strip()
    m = re.fullmatch(r"([\"'`])(.*)\1", text, re.S)
    if m and "${" not in text:
        return m.group(2)
    if text in _LITERAL:
        return _LITERAL[text]
    return int(text) if re.fullmatch(r"-?\d{1,9}", text) else _UNKNOWN


def _equal(sense: str, value: Any) -> Tuple[Optional[int], bool]:
    """``answer == value``: (1 - it holds only when the check passed, -1 - only when it failed,
    None - not read; True when it holds exactly then, so that ``!=`` says the opposite)."""
    boolean = isinstance(value, bool)
    number = isinstance(value, int) and not boolean
    empty = value is None or value == "" or (number and value == 0)
    if sense == "pos":                              # true when it passed
        return ((1 if value else -1), True) if boolean else ((-1, False) if empty else (None, False))
    if sense == "falsy":                            # false when it passed
        return ((-1 if value else 1), True) if boolean else ((1, False) if empty else (None, False))
    if sense == "zero":                             # 0 when it passed (WinVerifyTrust)
        if number and value == 0:
            return 1, True
        return (-1, False) if number or value is None or isinstance(value, str) else (None, False)
    if sense == "null":                             # null when it passed (the updater's check)
        if value is None:
            return 1, True
        return (-1, False) if isinstance(value, str) else (None, False)
    if sense == "text":                             # what Get-AuthenticodeSignature prints
        if isinstance(value, str):
            return (1, True) if value == "Valid" else (-1, False)
    return None, False


def _part(sense: str, name: str) -> Optional[str]:
    """Which way a part of an answer points: of an OpenPGP result ``verified`` (a promise that
    throws when the check failed), ``valid`` (true when it passed), ``signatures``; any part of
    a printed text is text."""
    if sense == "pgp":
        return {"verified": "promise", "valid": "pos", "signatures": "pgp"}.get(name)
    return "text" if sense == "text" else None


def _blank(m: "re.Match[str]") -> str:
    """A string or regular-expression literal with its content blanked (same length)."""
    token = m.group(0)
    if token[:2] in ("//", "/*") or (token[:1] == "`" and "${" in token):
        return token                                         # code: an unclosed comment, `${...}`
    if token[:1] in ("\"", "'", "`"):
        return token[0] + re.sub(r"[^\n]", " ", token[1:-1]) + (token[-1] if len(token) > 1 else "")
    return re.sub(r"[^\n]", " ", token)                      # a regular expression


def _label(text: str) -> str:
    """How a sink is named in the report."""
    for name, shown in (("Function", "new Function"), ("eval", "eval"), ("execScript", "execScript"),
                        ("Script", "vm.Script")):
        if name in text:
            return shown
    return re.sub(r"[\s(.]+", "", text)


def analyse(text: str, updater: bool = False) -> List[Hit]:
    """What ``text`` (JavaScript) executes that came from the network. Never raises."""
    return study(text, updater=updater)[0]


def updater_library(baseline: str) -> bool:
    """Is a file with this baseline one of a verified updater library (``UPDATER_PACKAGES``)?"""
    return any(("npm package %s " % name) in baseline for name in UPDATER_PACKAGES)


def study(text: str, failed: Optional[List[str]] = None, updater: bool = False) -> Tuple[List[Hit], str]:
    """``(hits, cut)``: the same, and the limit the reading stopped at ("": none) - a count
    (steps, size), so that the same file always gets the same answer; the clock is an
    emergency brake and is named when it is what stopped the reading. ``failed``: a list
    that gets the error, if the reading failed (it then says nothing, as before).
    ``updater``: the text is a file of a verified updater library (``updater_library``)."""
    if not text or not _NET_HINT.search(text):
        return [], ""
    try:
        flow = RemoteFlow(text, updater)
        return flow.run(), flow.cut
    except Exception as exc:             # an analysis aid must never break the scan itself
        if failed is not None:
            failed.append(type(exc).__name__)
        return [], ""


# -- text of the script that is written to a file which is then started -------------------------
# phageo, 2026-10-13: quoted text does not count on its own (rules.QuotedText) - but a text the
# script writes to a file and then starts is a program, and is followed.
WRITTEN_SCRIPTS = {".js": "js", ".mjs": "js", ".cjs": "js", ".jse": "js", ".ps1": "powershell", ".psm1": "powershell",
                   ".bat": "batch", ".cmd": "batch", ".py": "python", ".pyw": "python", ".rb": "ruby",
                   ".vbs": "vbs", ".vbe": "vbs", ".wsf": "vbs", ".hta": "vbs", ".sh": "sh"}
WRITTEN_PROGRAMS = frozenset({".exe", ".dll", ".scr", ".com", ".node", ".lnk", ".msi", ".jar"})
WRITTEN_DATA = frozenset({".json", ".txt", ".log", ".ini", ".cfg", ".conf", ".xml", ".yml", ".yaml", ".toml", ".csv",
                          ".md", ".html", ".htm", ".css", ".svg", ".png", ".jpg", ".dat", ".sav", ".save", ".lock",
                          ".pid", ".tmp", ".env", ".properties", ".plist", ".desktop", ".reg"})
MAX_WRITTEN_TEXT = 1024 * 1024      # characters of one written text that are handed on
MAX_WRITTEN = 8                     # written-and-started texts reported per script
_MIN_WRITTEN_TEXT = 8
# for measuring (a developer's tool sets it: the runner of the real samples): a list that gets one line of
# numbers per write the reading looked at - no name and no text of the script
WRITTEN_TRACE: Optional[List[str]] = None
_PATH_ENDING = re.compile(r"(\.[A-Za-z0-9]{1,10})\Z")
_FILE_NAME = re.compile(r"""["'`]([^"'`\n]{0,120}\.[A-Za-z0-9]{1,10})["'`]""")
_MAX_FEEDING = 60                   # expressions looked at for the quoted texts of one written value
_FEEDING_DEPTH = 3                  # names followed from the written value
_FEEDING_REACH = 200_000            # characters around the write in which a name's value is looked for
_FED_NAME = re.compile(r"(?<![\w$])(%s)(?![\w$])" % _ID)
_FED_SKIP = frozenset("const let var function return new this true false null undefined typeof await async if else "
                      "String Buffer raw from join replace trim concat toString map filter split slice".split())
_ESCAPED = re.compile(r"""\\([ntr\\"'`])""")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}
_WRITER_NAMED = re.compile(r"(?<![\w$.])(%s)\s*=\s*[\w$.\s]{0,40}\Z" % _ID)


class Written(NamedTuple):
    """A text of the script that is written to a file which the script then starts."""
    line: int               # where it is started
    sink: str               # child_process, shell openPath, require ...
    write_line: int
    path: str               # the file's path as far as it can be read ("": not at all)
    ending: str             # ".js", ".bat" ... ("": not known)
    language: str           # of WRITTEN_SCRIPTS ("": a program, or not known)
    text: str               # the written text (holes for parts only known at runtime)


def _looks_like_data(text: str) -> bool:
    """JSON - a configuration, a save - is data whatever the file is called."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[\"" or V.is_partial(stripped):
        return False
    try:
        json.loads(stripped)
        return True
    except (ValueError, RecursionError):
        return False


def written_and_started(text: str) -> Tuple[List[Written], str]:
    """``(found, cut)``: every text of the JavaScript ``text`` - a string, a constant, a
    template, pieces put together - that reaches ``fs.writeFile`` / ``writeFileSync`` /
    ``appendFile`` or a stream of ``createWriteStream``, and whose file then reaches
    something that starts or loads it: ``child_process``, the shell's ``openPath`` /
    ``openItem`` / ``openExternal``, ``require``, the Windows Script Host. "Reaches": the
    start names the same variable as the write's path, or the file's name.

    No chain: a file whose ending is one of data (``WRITTEN_DATA``: a configuration that is
    written before a fixed program is started with it); with an ending that is not known, a
    text that is JSON. ``cut``: the limit the reading stopped at ("": none). Never raises;
    nothing is run."""
    if not text or not ("writeFile" in text or "appendFile" in text or "createWriteStream" in text):
        return [], ""
    try:
        flow = RemoteFlow(text)
        cut = "larger than %d MB" % (MAX_SOURCE >> 20) if flow.size > MAX_SOURCE else ""
        try:
            found = flow._written()
        except (Budget, RecursionError) as exc:
            flow.clock.ended(exc)
            return [], V.also(V.also(cut, flow.cut), flow.clock.stopped)
        return found, V.also(cut, flow.cut)
    except Exception:                    # an analysis aid must never break the scan itself
        return [], ""


# -- what a script's process starts are made of ----------------------------------------------------
# phageo, 2026-10-14, "severity by flow, not mention": a script that starts a fixed program with
# fixed arguments and no shell is not the same as one that starts whatever a text says.
QUIET, RUNTIME, SHELL, OPEN_START = "constant", "script runtime", "shell", "not constant"
MAX_STARTS = 400


class Start(NamedTuple):
    """One place where a JavaScript file starts a program."""
    line: int
    kind: str       # QUIET: a constant program, constant arguments, no shell;
    #                 RUNTIME: the program is one that runs what it is given (cmd, powershell, node ...);
    #                 SHELL: the command goes through a shell (exec, shell: true, the Script Host);
    #                 OPEN_START: the program or an argument is not a written-out constant
    known: bool     # everything that is started is written out (nothing comes from elsewhere)
    text: str       # the program and arguments as far as they are written out (lower case)
    local: bool = False   # SHELL / OPEN_START: what is not written out is all the app's own (RemoteFlow._local)
    via: str = ""         # child_process; check - only a signature check (_only_check); or the other
    #                       way it starts (the Script Host, the shell's open ...)


_BARE_REQUIRE = re.compile(r"""(?:\A|[;{}\n])[ \t]*require\s*\(\s*["'](?:node:)?child_process["']\s*\)[ \t]*(?=;|\n|\Z)""")


def asked_for_nothing(text: str) -> bool:
    """Does the JavaScript ``text`` name ``child_process`` only in statements that ask for
    the module and throw the result away (``require("child_process");`` on a line of its
    own - what a bundler leaves in a chunk that used to import it)? Then it can start
    nothing through it."""
    code = _MASKS["c"].sub(lambda m: m.group(0) if m.group(0)[:1] in "\"'`" else re.sub(r"[^\n]", " ", m.group(0)),
                           text[:MAX_SOURCE])
    named = code.count("child_process")
    return 0 < named == len(_BARE_REQUIRE.findall(code)) and len(text) <= MAX_SOURCE


def starts(text: str) -> Optional[List[Start]]:
    """Every process start of the JavaScript ``text`` (``child_process``, the Windows Script
    Host, the shell's ``openPath`` / ``openItem`` / ``openExternal``), each with its kind.
    None: the reading failed or stopped at a limit - nothing is known then. Never raises."""
    if not text or not ("child_process" in text or "ActiveXObject" in text or "CreateObject" in text
                        or "openPath" in text or "openExternal" in text or "openItem" in text):
        return []
    try:
        flow = RemoteFlow(text)
        if flow.size > MAX_SOURCE:
            return None
        flow._find_functions()
        return flow._starts_of()
    except (Budget, RecursionError):
        return None
    except Exception:                    # an analysis aid must never break the scan itself
        return None


def wsh_commands(text: str, cut: Optional[List[str]] = None) -> List[Tuple[int, str]]:
    """``(line, command line)`` of what a JScript under the Windows Script Host starts
    with ``WScript.Shell`` ``Run`` / ``Exec`` or ``Shell.Application`` ``ShellExecute``,
    where the command can be worked out. They are PowerShell / batch themselves and are
    read by that chain, as the command lines of the other languages are. ``cut``: a list
    that gets the limit this reading stopped at, if it did (silent until 2026-10-12).
    Never raises."""
    out: List[Tuple[int, str]] = []
    if not text or not ("ActiveXObject" in text or "CreateObject" in text):
        return out

    def said(why: str) -> None:
        if why and cut is not None:                     # (every cause once: values.also)
            cut[:] = [V.also(cut[0] if cut else "", why)]
    try:
        flow = RemoteFlow(text)
        if flow.size > MAX_SOURCE:
            said("larger than %d MB" % (MAX_SOURCE >> 20))
        try:
            flow._find_functions()
            for pos, opener, label in flow._wsh_launches():
                parts = []
                for a, _b in flow._arguments(opener)[:2 if label.endswith(_IND[2]) else 1]:
                    value = flow._value(a)
                    if isinstance(value, str) and value.strip():
                        parts.append(value)
                if parts and len(out) < 200:
                    out.append((flow.code.count("\n", 0, pos) + 1, " ".join(parts)[:8000]))
            said(flow.cut)
        except (Budget, RecursionError) as exc:
            flow.clock.ended(exc)
            said(V.also(flow.cut, flow.clock.stopped))
    except Exception:
        return []
    return sorted(out)
