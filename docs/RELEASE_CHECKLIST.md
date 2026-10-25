# Release checklist of the user package (portable zip and installer)

From the decisions of 2026-10-12 (distribution, release checklist), 2026-10-24 (0.9-beta
packaging) and packaging session 3 (phageo). Every line must pass on the **final** build; the
CHANGELOG entry of the release says which build (SHA-256 of the zip) it was run on.

## Before the build

1. No code change after the last `gamescan/` change but the kept readings:
   `python tools/build_known_findings.py --archives <engine_archives>` - kept count unchanged (85),
   "texts of the files kept as places" printed (no excerpt of a table file stored as text).
2. Full suite on the project's Python: `python -m unittest tests.test_gamescan` - all pass.
3. Full suite on the package's own Python (from an unzipped copy):
   `<package>\python\python.exe tools\package_suite.py` - all pass. It leaves out the tests of the
   malicious-sample runner (`tools/positive_benchmark.py`, a developer's tool that is never shipped:
   its guard mistakes the embeddable Python's library for project code - see the tool's text).
4. Tested only on Python 3.13 64-bit; no other version is claimed (phageo, 2026-10-24).

## The build

5. `python tools/build_package.py --inputs <python.org files> --names <mapping file> --out <folder>`
   - refuses on its own: a python.org file that is not the manifest's row, a name off the
   allowlist, content of `tests/` or `engine_archives`, a real game name, the build PC's Windows
   user name or profile path, a missing licence text, a module with an indicator string as plain text
   (`tools/move_indicators.py --check` must say 0; since 2026-10-24, AV false positives). Built twice: the same bytes.

## On the final zip: `python tools/release_check.py <zip> --names <mapping file> --samples <clean sample folder> ...`

(The sample folders have no default path: `--samples`, repeatable, or the variable `BAGEL_SAMPLE_FOLDERS`,
folders separated by `;`. On a build machine without the private files, `tools/ci_release_check.py` runs the same
lines and marks dev content, samples and game names SKIPPED.)

| # | Line | Passes when |
| --- | --- | --- |
| 1 | version | top folder, README title and `models.TOOL_VERSION` inside all say 0.9.0-beta |
| 2 | names | every file on the allowlist; nothing of `tests/`, `tests/_tools`, `engine_archives`, `docs`, `tools`, `yara_rules`, the behaviour monitor; no compiled file |
| 3 | dev content | no file has the bytes of a file in `tests/` or `engine_archives` |
| 4 | samples | no app or note file has the bytes of a file in the clean sample folders (the clean benchmark and the two clean held-out sets, given by `--samples` / `BAGEL_SAMPLE_FOLDERS`; no folder given = FAIL; the malicious folders are never read - rule 19) |
| 5 | game names | no real game name of the mapping file (outside the project) in app or notes |
| 6 | user name | no Windows user name / profile path of the build PC in app or notes |
| 7 | file list | the zip holds exactly the files of `app/package_files.json` plus that list |
| 8 | self-check | every file's SHA-256 equals its line in `app/package_files.json` |
| 9 | licences | `LICENSE` (MIT, "Copyright (c) 2026 phageo"), `THIRD-PARTY-NOTICES.txt`, `python/LICENSE.txt`, `python/tcl/tk8.6/license.terms` |
| 10 | notes | `README.md` (user section) and `RELEASE-NOTES.md` (English and Turkish) |
| 11 | icon | `app/gamescan/bagel.ico` with the sizes 16, 24, 32, 48, 64, 128, 256 (`tools/build_icon.py`) |
| 12 | start | `Bagel.exe`: a windowed program (no console), version information FileDescription / ProductName "Bagel", CompanyName "phageo", version 0.9.0-beta, every picture of `bagel.ico` inside (final polish, 2026-10-25) |
| 13 | images | no picture of Bagel's own files - `bagel.ico`, the icon inside `Bagel.exe`, any PNG - holds metadata (text, time, EXIF, colour profile, content credentials): only the chunks IHDR, PLTE, tRNS, IDAT, IEND (source release, phageo 2026-10-25; python.org's files are not looked at) |
| 14 | installer | with `--installer <Bagel-<version>-setup.exe>`: it installs exactly the zip's files, byte for byte (read in memory by the scanner's own Inno Setup reader; nothing run) |

## The installer (0.9-beta polish, phageo)

16. `python tools/build_installer.py --package <the final zip>` - the pinned Inno Setup 6.7.3 compiler
    of `tests/_tools/innosetup` (dev-only); output `Bagel-<version>-setup.exe` beside the zip.
17. Script: Inno's "only for me / for all users" question (`PrivilegesRequired=lowest`,
    `PrivilegesRequiredOverridesAllowed=dialog`; all users needs admin), folder page with
    `{autopf}\Bagel` as default, registry through `HKA`; Start menu shortcut to `Bagel.exe` with
    AppUserModelID `phageo.Bagel`; the one "Bagel" entry with its submenu (shellmenu's keys and
    commands) at install, older entries replaced; uninstall removes only what it installed plus Python's
    `__pycache__` folders; `BagelInstallerTests` pass.
18. Real test on the build PC: registry (`HKCU\Software\Classes` entries, the uninstall key) and files
    (install folder, Start menu shortcut) recorded before; install silently into a custom folder; both
    submenu items used on a clean benchmark game (Scan; Safe launch answered "no"); the installed
    window's self-check silent; Task Manager shows "Bagel" with the icon; uninstall silently; registry
    and files equal to "before" (Bagel's data folder kept unless `/PURGE`).
19. SHA-256 of the zip and of the installer written into the CHANGELOG entry (for phageo's VirusTotal
    check); README says the installer is unsigned and SmartScreen may warn.

## Proof from an unzipped copy

11. The package's `python.exe` is its own 3.13.16; `sys.path` holds only the package; the kept
    readings are current (85).
12. RPY-05, ELE-03, INS-04 scanned with the benchmark's scanner: every finding byte for byte the
    project's run, and the verdicts of the current clean result file.
13. The window starts through `Bagel.exe` (`tools/build_launcher.py --check` says it is the kept
    file); the self-check gives no warning.
14. Right-click menu: add, use (Scan, Safe launch on a clean benchmark game only), remove - the
    registry as before.
15. The project holds no real name of the author and no path with the Windows user name (count 0).
