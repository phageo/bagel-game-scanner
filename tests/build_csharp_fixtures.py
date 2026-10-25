"""Build the C# test libraries of ``tests/fixtures_cs`` - run once, by hand.

    python tests/build_csharp_fixtures.py

Compiles ``Cases.cs`` once per case (one ``#if`` symbol each) with Windows' own
C# compiler (``csc.exe`` of the .NET Framework; allowed by phageo on 2026-10-11 for
test fixtures only - CLAUDE.md, rule 14) and writes the results into
``tests/fixtures_cs/fixtures.json``: for every library its SHA-256, its size and
its bytes (base64). The tests read that file and never need the compiler.

The libraries are kept as text, not as ``.dll`` files, and are scanned from
memory: a library that downloads and loads code is exactly what antivirus
programs remove from a folder, however harmless these are (their addresses are
under ``example.invalid``). Nothing here is ever run; the compiler writes into
a temporary folder that is deleted afterwards.

The compiler does not write the same bytes twice (it stamps a time and a random
number), so a rebuild changes every SHA-256: build once, keep the file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.join(HERE, "fixtures_cs")
OUT = os.path.join(FOLDER, "fixtures.json")
FRAMEWORK = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Microsoft.NET", "Framework64", "v4.0.30319")
CSC = os.path.join(FRAMEWORK, "csc.exe")


def run(args, cwd):
    done = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise SystemExit("csc failed: %s\n%s%s" % (" ".join(args), done.stdout, done.stderr))


def main() -> int:
    if not os.path.isfile(CSC):
        raise SystemExit("the C# compiler is not at " + CSC)
    with open(os.path.join(FOLDER, "Cases.cs"), encoding="utf-8") as fh:
        cases = re.findall(r"(?m)^#if (\w+)", fh.read())
    with open(CSC, "rb") as fh:
        compiler = hashlib.sha256(fh.read()).hexdigest()
    work = tempfile.mkdtemp(prefix="gss-cs-")
    out = {"compiler": {"path": CSC, "sha256": compiler}, "libraries": {}}
    if os.path.isfile(OUT):
        # a library that was built once is kept as it is: only new cases are compiled
        with open(OUT, encoding="utf-8") as fh:
            out["libraries"] = json.load(fh)["libraries"]
    built = 0
    try:
        for name in ("UnityStub.cs", "Cases.cs"):
            shutil.copy(os.path.join(FOLDER, name), work)
        run([CSC, "/nologo", "/target:library", "/optimize+", "/out:UnityEngineStub.dll", "UnityStub.cs"], work)
        # the libraries other cases call into (LIB...) come first; a kept one is written
        # out for the compiler to refer to (read by it, never run)
        shared = [case for case in cases if case.startswith("LIB")]
        for case in shared + [case for case in cases if case not in shared]:
            target = case.lower() + ".dll"
            if case in out["libraries"]:
                if case in shared:
                    with open(os.path.join(work, target), "wb") as fh:
                        fh.write(base64.b64decode(out["libraries"][case]["data"]))
                continue
            # (LIBNET and LIBNET2 have a method of the same name: a case refers to one of them -
            # XUSE2_... to LIBNET2, every other case to LIBNET)
            second = case.startswith("XUSE2")
            # (LIBBASE defines a type named like one of the base library: only the case that
            # calls into it refers to it)
            skip = {"LIBNET" if second else "LIBNET2"} | (set() if case.startswith("XUSE_BASE") else {"LIBBASE"})
            refer = [] if case in shared else ["/r:%s.dll" % name.lower() for name in shared if name not in skip]
            run([CSC, "/nologo", "/target:library", "/optimize+", "/define:" + case, "/out:" + target,
                 "/r:UnityEngineStub.dll", "/r:System.Net.Http.dll"] + refer + ["Cases.cs"], work)
            with open(os.path.join(work, target), "rb") as fh:
                data = fh.read()
            out["libraries"][case] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                                      "data": base64.b64encode(data).decode("ascii")}
            built += 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("%d new, %d kept" % (built, len(out["libraries"]) - built))
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("%d libraries -> %s" % (len(out["libraries"]), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
