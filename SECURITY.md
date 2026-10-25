# Security policy

Bagel is a static scanner: it reads the files of a game and reports what looks dangerous. It
never runs, imports or unpickles what it scans (the project's rule 2), and every reader has
size, depth and step limits (rule 3). A way to break one of these promises is a security bug.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.9.0-beta (the newest release) | yes |
| anything older | no - please update first |

## What counts as a security bug

- a scanned file that makes Bagel run, load or import any part of it;
- a scanned file that makes Bagel write outside its own data folder
  (`%USERPROFILE%\.game_safety_scanner`) or outside a folder the user chose for a report;
- a crafted file that hangs Bagel or uses memory without limit, past the documented limits;
- the "Safe launch" starting a game the scan rated DANGEROUS, or starting it without asking when
  the verdict says it should ask;
- a package, installer or `Bagel.exe` that differs from what the workflow in
  `.github/workflows/build.yml` builds from this repository.

A **missed detection or a false alarm is not a security bug**: Bagel is a second opinion next to
Windows Security, not a replacement, and its documented limits are in the README ("Limits").
Please report those as ordinary issues - with a SHA-256, never with the file itself.

## How to report

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then
**Report a vulnerability**. Please do not open a public issue for a security bug.

- Describe what happens and how to make it happen.
- Never attach live malware. Give its SHA-256 (and, if you like, its MalwareBazaar or
  VirusTotal page); a harmless file that shows the problem is best.
- You will get an answer within 14 days. A fix goes into the next release, and the release notes
  name the problem once it is fixed.

## What Bagel sends over the network

Nothing, unless the user switches it on in Settings with a key of their own:

- **VirusTotal** (the user's API key): only the SHA-256 of a program, never the file.
- **abuse.ch MalwareBazaar** (the user's Auth-Key): downloads the list of recent malware hashes.

Windows Defender is asked through Windows' own AMSI interface, on the user's PC.

## Signed builds

Releases are not signed yet. Code signing through SignPath is planned: see
[docs/CODE_SIGNING.md](docs/CODE_SIGNING.md). Until then, Windows SmartScreen may warn about the
installer and `Bagel.exe`; the SHA-256 of every release file is published with the release.
