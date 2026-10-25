# Changelog

## 0.9.0-beta (2026-10-25)

The first public release. Bagel was called "Game Safety Scanner" before it.
The release notes (`docs/RELEASE_NOTES.md`, English and Turkish) say what it does not do yet and
why it is a beta.

### Scanning

- Static triage of a game folder or file: Ren'Py, RPG Maker XP / VX / VX Ace / MV / MZ, Unity
  (.NET and IL2CPP metadata), Electron / NW.js apps, Windows programs, scripts, Office documents,
  media files, archives and installers (zip, 7z, RAR, Cabinet, NSIS, Inno Setup, MSI). Nothing it
  scans is ever run, imported or unpickled; every reader has size, depth and step limits.
- Five verdicts: CLEAN, LIKELY SAFE, REVIEW, SUSPICIOUS, DANGEROUS. A part that could not be read
  is never CLEAN.
- Pattern rules, attack chains (download -> write -> run, local decode -> write -> run, DLL
  side-loading, self-update without a signature check ...), payload resolution by data flow for
  JavaScript, Python / Ren'Py, Ruby, PowerShell / batch, C#, and the instructions of NSIS and
  Inno Setup installers.
- Official engine and library files are recognised by their exact SHA-256 (Ren'Py SDKs, Electron,
  NW.js, Unity, published npm packages, installer tools), so their normal behaviour is not flagged;
  a CRITICAL finding is never lowered for trust reasons.
- Optional, with the user's own key: VirusTotal (the SHA-256 only) and abuse.ch MalwareBazaar
  hash lists. Windows Defender through AMSI. Authenticode signatures checked by Windows.
- Every finding explained in plain words, English and Turkish window; reports as JSON, HTML or PDF.

### Safe launch

- After a scan, or from the right-click menu on a program: scans the game's folder the strict way,
  then starts the game (CLEAN / LIKELY SAFE), asks once (REVIEW, or a part that could not be read),
  asks for the typed word `launch` (SUSPICIOUS) or refuses (DANGEROUS). Every question defaults to
  "no".

### Windows package

- Portable zip `Bagel-0.9.0-beta.zip` with its own Python 3.13 (no installed Python needed) and the
  start program `Bagel.exe`; at start Bagel checks its own files against the list built into it.
- Installer `Bagel-0.9.0-beta-setup.exe`: only for me (no administrator rights) or for all users,
  a folder of the user's choice (a folder only an administrator may write to is refused for "only
  for me" with a plain message), Start menu entry, the right-click entry "Bagel" (Scan; Scan and
  Safe launch on programs); uninstall removes only what it installed.
- Not signed yet: Windows SmartScreen may warn.

### Building from source

- `.github/workflows/build.yml` builds the zip and the installer on a clean Windows runner from
  this repository alone; outside parts come only through `tools/fetch.py`, each checked by its
  SHA-256. `Bagel.exe` is built deterministically from `tools/launcher/Bagel.cs`.
- The release checklist (`tools/release_check.py`) and the privacy check (`tools/privacy_check.py`)
  run at the end of every build.
- The privacy check accepts its options between the paths (the first workflow run stopped there); it
  says how many private words it got and whether a mapping file was given (never the words), and
  marks each check PASS, FAIL or SKIPPED.
