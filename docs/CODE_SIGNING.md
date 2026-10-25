# Code signing policy

> **DRAFT** - written for the application to the SignPath Foundation (source release,
> 2026-10-25). Nothing is signed yet; this page becomes the project's policy once SignPath has
> accepted the project and the signing step of the workflow is switched on.

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

## What is signed

Only files that the workflow `.github/workflows/build.yml` builds on GitHub's own Windows runner
from this repository, at a tagged commit:

| File | What it is |
| --- | --- |
| `Bagel.exe` | the start program of the package (source `tools/launcher/Bagel.cs`, built by `tools/build_launcher.py` with the .NET Framework's `csc.exe`) |
| `Bagel-<version>-setup.exe` | the installer (`tools/build_installer.py`, Inno Setup) |

The portable zip carries the signed `Bagel.exe`. Bagel's own Python code is not signed (it is
text); the package's start-up self-check compares every file with the SHA-256 list built with it.
Files of other projects inside the package (python.org's Python, Tcl/Tk) are shipped as their
publishers made them and are **not** signed by this project.

Nothing built on a developer's PC is ever submitted for signing.

Repository: [github.com/phageo/bagel-game-scanner](https://github.com/phageo/bagel-game-scanner)

## Team roles

The project has one member, who holds every role:

| Role | Who |
| --- | --- |
| Author (committer) | [phageo](https://github.com/phageo) |
| Reviewer | [phageo](https://github.com/phageo) |
| Approver (approves each signing request) | [phageo](https://github.com/phageo) |

The team uses multi-factor authentication for GitHub and SignPath.

## How a release is signed

1. A version is tagged (`v<version>`); the workflow builds everything from the repository alone -
   its outside parts come through `tools/fetch.py`, each checked against the SHA-256 in the
   manifests.
2. `Bagel.exe` is built and submitted to SignPath **before** the zip is made, so that the
   package's file list (`app/package_files.json`) holds the signed file's SHA-256. Then the zip
   and the installer are built, and the installer is submitted. For each request an approver
   checks that it comes from the tagged commit's workflow run and approves it by hand.
3. The workflow runs the release checklist (`tools/release_check.py`) and the privacy check
   (`tools/privacy_check.py`) on the signed files. If either fails, nothing is published.
4. The signed files are published as the release, with their SHA-256.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically
requested by the user or the person installing or operating it.

In detail: Bagel contacts no server by itself. Only when the user turns these on in Settings
with a key of their own does it ask VirusTotal about a program's SHA-256 (never the file) or
download abuse.ch MalwareBazaar's list of recent malware hashes. See [SECURITY.md](../SECURITY.md).
