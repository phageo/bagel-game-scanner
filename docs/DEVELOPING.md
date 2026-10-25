# Developing Bagel

Running from source, tests, the benchmarks, `tools/fetch.py`, the tables, the cache, the build and CI.
Moved out of the old README.md word for word (phageo, 2026-10-25); the short README.md is for users.
A "see ... above / below" in the text may now point into one of the other files: `docs/HOW_IT_WORKS.md`, `docs/DEVELOPING.md`, `docs/LIMITS.md`.

## Run

- **Package (0.9.0-beta, no installed Python needed):** unzip
  `Bagel-0.9.0-beta.zip` anywhere and double-click
  `Bagel.exe` (`tools/build_launcher.py`); it starts the window with the Python in its own
  `python` folder only (built by `tools/build_package.py`, see "Distribution
  without an installed Python" below). **Installer:** `Bagel-0.9.0-beta-setup.exe`
  (`tools/build_installer.py`, Inno Setup; only for me (no admin) or for all users (admin),
  folder page; Start menu entry and the right-click entry at install, nothing left at uninstall).
- **GUI:** double-click `Run Scanner.bat` (or `GameSafetyScanner.pyw`). The batch
  file tries the Python Launcher (`pyw -3`), then `pythonw` on PATH, then a
  per-user Python install, and otherwise explains how to install Python. If the
  app fails to start, the error is written to
  `~/.game_safety_scanner/startup_error.log` and shown in a message box.
- **CLI:** `python -m gamescan <folder-or-file> [options]`
  - Reports: `--json FILE`, `--html FILE`, `--pdf FILE` (`--min-severity` filters HTML/PDF)
  - `--strict`, `--show-suppressed`, `--allowlist FILE`, `--no-memory`
  - `--yara PATH` - YARA rule file or folder
  - `--no-amsi`, `--defender-scan` - Windows Defender integration (see below)
  - `--vt-key KEY` (or `VT_API_KEY`), `--vt-max N`, `--vt-min-age DAYS` - VirusTotal
  - `--update-signatures`, `--abusech-key KEY` (or `ABUSECH_AUTH_KEY`), `--import-hashes FILE`
  - `--quarantine` - move files with HIGH/CRITICAL findings to quarantine
  - `--allow-unsigned-engine-files` - exempt engine components by structure alone
    (see "Engine files" in the features table)
  - Experimental: `--quick`, `--system`, `--full`, `--watch` (`--watch` is switched off in
    0.9-beta: see "Experimental: PC-wide features")
  - Exit code: 0 clean, 1 low/medium findings, 2 high/critical, 3 signature update failed.
- **Secure launcher:** `python -m gamescan --launch <Game.exe> [-- arguments for the game]`
  scans the game's folder first, then starts the game, asks you first, or
  refuses (see "Secure launcher" below).
- **Tests:** `python -m unittest tests.test_gamescan`

## For developers

What a clone of the repository needs, and what it does without the parts that are not in it.

- **Python 3.13** (64-bit, Windows) with its standard library - nothing to install. Run
  everything from the repository's top folder.
- **Tests:** `python -m unittest tests.test_gamescan` (unittest writes to stderr). Set
  `GSS_FAST=1` to leave out the slow tests (`@slow`). The full suite takes about 10 to 25
  minutes; it can be run in parts by test class
  (`python -m unittest tests.test_gamescan.<Class>`).
- **What is not in the repository, and how the tests behave without it.** Every test that
  needs one of these **skips** with a message naming what is missing; none fails because of it:
  - `tests/_tools` - the official NSIS and Inno Setup compilers the installer tests build real
    installers with. They are fetched on purpose only: `GSS_BUILD_INSTALLERS=1` (downloads
    through `tools/fetch.py`, checks the SHA-256 and the publisher's signature, sets Inno Setup
    up in portable mode inside `tests/_tools`). `GSS_TEST_TOOLS` names another folder.
  - `engine_archives` - the official engine and library archives the hash tables are built from
    (`GSS_ENGINE_ARCHIVES`, default: the folder beside the repository).
  - clean benchmark games - real games, never part of the repository. There is no default
    folder: set `GSS_SAMPLES` to the folder with one sub-folder per sample code, or those tests
    skip. (`tools/release_check.py` takes its sample folders by `--samples` or
    `BAGEL_SAMPLE_FOLDERS`, also without a default.)
  - `tools/launcher/Bagel.exe` - built from `tools/launcher/Bagel.cs` by
    `python tools/build_launcher.py` with the .NET Framework's own `csc.exe` (already on
    Windows). The build is deterministic: the same source gives the same SHA-256 as
    `tools/launcher/launcher.json`, so a rebuilt file can be compared with the published one.
- **Outside files only through `tools/fetch.py`.** `tools/manifest*.json` lists every file the
  project takes from outside - name, official address, SHA-256, size, licence; `fetch.py`
  downloads only a listed file, only over https from the listed servers, and deletes anything
  whose SHA-256 differs. `--list` and `--check --to <folder>` contact no server.
- **How the tables are rebuilt.** The generated tables in `gamescan/` (`engine_hashes`,
  `compiled_hashes`, `library_hashes`, `electron_official`, `inno_official`, `nsis_official`,
  `directx_official`, `npm_hashes`) are written by the builders in `tools/`
  (`build_engine_hashes.py`, `build_library_hashes.py`, `build_electron_tables.py`,
  `build_inno_tables.py`, `build_nsis_tables.py`, `build_directx_table.py`,
  `build_npm_hashes.py`), each run as `python tools/<builder> --archives <engine_archives>`.
  A builder has no download of its own: it asks `fetch.py` (`fetch.obtain`) for each archive it
  needs, which takes the file already in the folder when its SHA-256 is the manifest's and
  otherwise fetches exactly that row; `--offline` never downloads. After any change in
  `gamescan/`, `python tools/build_known_findings.py --archives
  <engine_archives>` renews the kept readings (`gamescan/known_findings.json.gz`, tied to the
  code's fingerprint; stale ones are ignored, never wrong).
- **The package and the installer:** `python tools/fetch.py --manifest tools/manifest_package.json
  --fetch --to <inputs>` (python.org's embeddable Python and the full package Tcl/Tk is taken
  from), `python tools/build_launcher.py`, `python tools/build_package.py --inputs <inputs>
  --names <mapping file> --out <folder>`, `python tools/build_installer.py --package <zip>`,
  then `python tools/release_check.py <zip> --installer <setup.exe> --names <mapping file>`
  (`docs/RELEASE_CHECKLIST.md`). The workflow `.github/workflows/build.yml` does the same on a
  clean Windows runner.

## False-positive benchmark

    python tools/fp_benchmark.py D:\CleanGames --out before.csv
    (change a rule)
    python tools/fp_benchmark.py D:\CleanGames --out after.csv --rules after_rules.csv

`D:\CleanGames` must contain one sub-folder per game you know to be clean. The
CSV has one row per game (engine, verdict, files, findings per severity,
suppressed, errors, `launcher`: what the secure launcher does with
the game - `start`, `ask`, `ask-word` or `block` - and `launcher_diff`), then
one `TOTAL` row per engine and a grand total. On known-clean games every finding is a false alarm, so compare the
totals of the two files. `--rules` also writes how often each rule fired.

Since 2026-10-12 (phageo) **three games are scanned at once** (`--workers N`;
`1`: one after the other), each in a process of its own with a temporary
folder of its own, and the rows are written in the order of the games'
names. The result files hold **no times** any more (the `seconds` column
is gone; `--times FILE` writes them, and they are printed): the same games
give the same two files byte for byte, whatever `--workers` is and however
busy the PC - so two results can be compared as files.

`--cache` (since 2026-10-13) lets the benchmark's own scan use the cache
of unpacked and parsed files (see "The cache of unpacked and parsed
files"); `--cache-dir FOLDER` names its folder. Without `--cache` the
benchmark never uses it, and the second scan - the launcher's way - never
does. The switch is there to measure time: the two result files must be
the same with it, without it, with the cache empty and with it filled
(measured on the 23 samples: all four pairs of files are identical).

The benchmark reads nothing of the user's profile: no memory center (scan
history, feedback) and no allow list, and it records no scan. A result
therefore does not depend on what was scanned or marked on this PC before.
The secure launcher builds its scanner with the same function
(`scanner.neutral_scanner`), so the two judge a game the same way.

That is checked on every run: each game is scanned a second time the way the
launcher scans it (its own temporary folder, the Windows antimalware engine
on), and the two lists of findings are compared. `launcher_diff` is the
number of findings they do not share (0 = the same). If there is any, the
tool prints `LAUNCHER CHECK FAILED` with every differing finding and ends
with exit code 1; otherwise it prints `launcher check: OK`. The `launcher`
column is the decision on that second scan. A run takes about twice as long
because of it. Not covered: your own known-malware hash list and YARA rules,
which the launcher also uses and which can only add findings.

### Held-out check (finish criterion 3; built 2026-10-17, not run yet)

`tools/heldout.py --malicious "<malicious held-out folder>" --clean <folder> --out <csv>`
scans samples never used for tuning: the malicious ones (password zips in
`heldout\renpy` and `heldout\electron`, read only by the positive runner,
in memory, its guard on) and clean games (a folder of their own, one code
per sub-folder, through `fp_benchmark.py`). It writes **one baseline CSV,
once** (an existing file is refused) with a `same_build` column - the
tuning sample with an identical profile (a malicious sample's rules; a
clean game's counts), i.e. the same build under another name - and reports
criterion 1 for the clean set and criterion 2 for the malicious set, the
second with and without the same-build samples. A held-out sample that
could not be read counts as missed. No rule may change in the session of
the first held-out run (phageo).

### Positive benchmark: real malicious samples (development only)

    python tools/positive_benchmark.py <folder> [<folder> ...] --out docs/benchmark/<name>.csv

Since 2026-10-12 (phageo; CLAUDE.md, rule 19). The false-positive benchmark
says what the scanner wrongly reports; this one says what it finds in real
malware. The samples are not part of the project and are handled under
strict terms:

- They stay in password-protected zips as MalwareBazaar hands them out
  (AES, password "infected"), outside the project. The tool reads a zip
  into memory, decrypts and unpacks its members in memory, and gives the
  bytes to the scanner. **Nothing of a sample is written to disk** - the
  scanner runs in its memory-only form, without signature checks (7-Zip /
  tar and Windows' cabinet library are used by no scan at all since
  2026-10-20 / 2026-10-19).
- **Nothing is run.** Besides the scanner never running anything, a guard
  is installed before the first sample is opened: it ends the run the
  moment this process is about to start a program, the project's own code
  calls `exec` / `eval` / `compile`, or a Windows library other than the
  one that provides AES is loaded.
- The result is one CSV: per sample its SHA-256, the folder it came from,
  the verdict, the rules that fired and the "not read" notes. No file
  name, no evidence text, no content.

**First result (`positive_baseline.csv`, 2026-10-12, no rule tuned for
it):** twenty samples in two folders. Ren'Py: 8 of 10 DANGEROUS (all with
`CHAIN-REMOTE-CODE`), 2 LIKELY SAFE. Electron: 2 DANGEROUS, 2 SUSPICIOUS,
4 LIKELY SAFE, 2 CLEAN. **Eight of twenty were missed:** two are archives
with another password, four could not be unpacked in memory, and two
Electron samples came out CLEAN without a note (probably the kind the
scanner does not read yet - `app.asar`, compiled JavaScript; not
confirmed on the samples).

**After the `app.asar` reader and a 1 GiB in-memory limit for this tool
(`positive_1gib.csv`, `positive_electron_asar.csv`, the same day):**
Electron 4 DANGEROUS, 4 SUSPICIOUS, 1 LIKELY SAFE, 1 CLEAN; Ren'Py
unchanged. One Electron sample is still CLEAN without a note; the four
SUSPICIOUS ones carry HIGH JavaScript findings out of the archive but no
CRITICAL chain.

**After two more changes the same day (`positive_after_unread.csv`):**
unread content counts as at least REVIEW, and a Ren'Py archive inside
another archive is read (it was not - found through one of these samples).
Ren'Py: 8 DANGEROUS, 1 SUSPICIOUS, 1 REVIEW. Electron: 4 DANGEROUS,
4 SUSPICIOUS, 1 REVIEW, 1 CLEAN - the CLEAN one turned out to be a small
Java archive, a kind the scanner has no reader for. **Read these numbers
with the clean Electron game in mind (see "Electron games"): the scanner
calls that one DANGEROUS too**, for reasons that have nothing to do with
malice, and the same reasons are at work in the malicious Electron
samples. Limits: twenty samples say little;
memory-only opens fewer archives than a normal scan does; the cause of
each miss was read off the CSV, not off the sample.

**After the packed-line rule and the Electron runtime table
(`positive_after_packed.csv`, `positive_after_electron.csv`, 2026-10-13):**
Ren'Py unchanged. Electron: 2 DANGEROUS, 6 SUSPICIOUS, 1 REVIEW; the Java
archive is labelled `other` and is REVIEW. Two samples went from DANGEROUS
to SUSPICIOUS with the packed-line rule (their chains were "on the same
very long line"; accepted by phageo); the runtime table moved no verdict.

Two measuring modes (2026-10-13; numbers and the scanner's own words
only, guard on): `--readings` prints, for every download-and-run reading
of a script that took half a second or more, stopped at a limit or found
something, the size of the script, the seconds and the counted steps of
each part of the reading and where it stopped; `--profile FILE` writes
where the time of the run went, by the names of the scanner's own
functions (Python's `cProfile`; never into a sample folder). The cache is
always off in this tool: nothing of a sample is kept on disk in any form.

Two more since the evening of 2026-10-13 (numbers and short marks only):
`--sites RULE` prints where each active finding of a rule stands - the
number of its file, its line, and marks of its place and of its evidence
text -, to tell several places from one place said several times
(`--sites QUOTED`: per file, which matches were hidden as quoted text of a
script and what is active beside them - rule names, lines, the names of
well-known functions; `--sites WRITTEN`: the numbers of the "written and
started" reading - writes, starts, how much text it could read);
`--stealer-count` prints, per sample, what a stealer chain across the
members of an app would rest on (`tools/stealer_count.py`: add-ons that
import the function that decrypts stored secrets, scripts that name a
browser's, a chat program's or a wallet's store - in their text, or only
after resolving -, and scripts with a network call). A count, not a rule:
no verdict rests on it. `--packages` prints the npm packages a sample
carries (name and version of every `package.json` under `node_modules`,
when both are plain - nothing else), which of them the registry does not
have, which published packages hold a chain or a decrypt add-on (package
names only) and, in numbers, how much of `node_modules` the npm table
verifies. The same count for a clean sample's folder:
`python tools/stealer_count.py <folder>`. With `--electron-versions` every
resource whose kind has a name of its own is listed too (kind, name, size,
how it begins).

**The current result** (`positive_after_no_flow_local.csv`, 2026-10-14,
forty-first message): `renpy` 8 DANGEROUS, 1 SUSPICIOUS, 1 REVIEW;
`electron` 1 DANGEROUS, 7 SUSPICIOUS, 1 REVIEW; `other` 1 REVIEW. The one
change against the fortieth message: `b187436e...` DANGEROUS -> SUSPICIOUS
(its chain of nearness in a published library is `CHAIN-NO-FLOW` now; six
programs without an ending keep it SUSPICIOUS).
(Since 2026-10-15, forty-ninth message, the current result is
`positive_after_stealer_app.csv`: `renpy` 8 / 1 / 1; `electron` 4
DANGEROUS, 4 SUSPICIOUS, 1 REVIEW; `other` 1 REVIEW - three samples
DANGEROUS through `CHAIN-STEALER` across the app.)

Since 2026-10-14 (phageo, forty-first message): **a sample whose zip could
not be opened in a run** (held by another program, no memory) is
**MISSING**, not a verdict - a zip that is what it is (another password,
not a zip) stays NOT READ. `--compare <earlier CSV>` prints every verdict
that changed against an earlier result, by SHA-256, and lists every
MISSING sample - one this run could not open, or one of the earlier result
it has no row for - apart: **a missing sample is never counted as a
verdict change.** **But it fails the gate** (phageo, 2026-10-15,
forty-ninth message): a MISSING row, a sample of the `--compare` result
without a row, or a lower verdict ends the run with exit code 4 and
"GATE FAILED" (`gate`). `--memory FILE` (same day) writes each sample's
peak memory - the process's working set, read every 20 ms while the
sample is scanned - to a file of its own (folder, SHA-256, MB), so that
the result CSV stays comparable byte for byte; a rise shorter than 20 ms
can be missed. `--sinks` measures the JavaScript download-and-run
reading of each sample against a sink-first reading
(`tools/sink_count.py`: times, number of sinks, steps of a backward trace
from each - numbers only; the same for a clean sample's folder:
`python tools/sink_count.py <folder>`). `--download-runs` (2026-10-14,
forty-second message) prints, per sample, every download-and-run chain
with four answers - address constant / from the app's own settings file /
only at runtime, HTTPS, the same server as the app names for itself, a
signature check on the way - words only (`tools/download_runs.py`; for a
clean sample's folder: `python tools/download_runs.py <folder>`).

Three modes print metadata instead of scanning for a result (all in
memory, guard on; their output is not kept in the project):
`--inventory` (per sample every file and member: name, size, kind by first
bytes, reader, the "not read" notes, which rules fired where - numbers
only; for a program what it was taken for), `--electron-versions` (which
Electron version each sample's program states - nothing else is read), and
with `--archives <folder>` a comparison of such a program with the
official one of its version, section by section, in numbers.

### False alarms that were taken apart (MV-01 and RPY-01)

Until 2026-10-06 two real games were SUSPICIOUS for reasons that turned out
to be false alarms when every HIGH and MEDIUM finding was read. Seven rules
came out of that, and an eighth on 2026-10-07 out of three more Ren'Py
samples (the last row of the table). Each lowers or hides exactly the case that was read, and
each has tests for the neighbouring cases that have to stay reported
(`FalseAlarmFixTests`). What decides is always something read from the file
- never a file name or a folder alone.

| What was seen | What the scanner does now | What stays as it was |
| --- | --- | --- |
| A script *shows* `"os.remove(\"images/...png\")"` on a fake console: the whole line is one string | A MEDIUM-or-lower pattern on a line that is nothing but one string literal is "text, not code" (`context._text_literal`; suppressed with that reason). Python / Ren'Py only | the text is an argument or part of a longer expression (on its own line too); the file executes text anywhere (`exec`, `eval`, `compile`, `py_exec` ...); every HIGH and CRITICAL pattern |
| `Game.exe` of an RPG Maker MV game is NW.js's `nw.exe` with the game's icon: it matches no official SHA-256 | A program whose headers and every section except the resource section (`.rsrc`) are byte for byte those of an official `nw.exe` is accepted as "official NW.js launcher with other resources" (`pe.resource_frame_key`, table `engine_hashes.LAUNCHERS`: eight launchers, built from the official archives only) | one changed byte of code, data, import table or relocations; a moved entry point; an added section; changed flags; a signature directory; a program inside the resources - all refuse the match. The resources and anything appended to the file are scanned again on their own and their findings are **not** covered by the acceptance; a game appended as a zip gets nothing from it |
| A script runs `wmic process get Description` | A fully written-out query for the running programs (`wmic process get <columns>`, `tasklist`) in a file without any network call is `PROC-LIST-001`, LOW: "reads the list of running programs" (`context._process_list`, decided on the command the payload resolver read) | every other use of `wmic` (`call create`, `/node:`, `/format:`, `shadowcopy`, a filter, a second command, a pipe); a command put together from parts; any network call or address in the same file |
| The usual "one copy of the game at a time" helper creates `%TEMP%/<program>.lock` and deletes it | Suppressed as "the script's own lock file" when the resolved path is a `.lock` / `.pid` file directly in the temporary folder that the script itself opens for writing, and the name that holds the path is assigned exactly once (`context._own_lock_file`) | `.exe`, `.bat`, `.ps1`, `.dll` or no extension in the temporary folder; a lock file anywhere else; a sub-folder, a wild card, `shutil.rmtree`; any other file deleted in the same script |
| A plugin writes `_index.json` (a list of its cursor images) into its own folder | A Node.js `writeFile` / `appendFile` whose path starts from the game's own folder, ends in a written-out data extension, and is not a file the engine reads is LOW (`dataflow/jswrites.py`, `context._data_write`) | **files the engine reads as code or configuration stay MEDIUM**: `package.json` (NW.js takes its start-up settings from it), `plugins.js`, RPG Maker's data files (`Map001.json`, `CommonEvents.json`, `Troops.json`, `Skills.json`, `System.json` ...), and any name that could be the *end* of one (`"001.json"`, `".json"`); scripts and programs; the user's profile, the environment, a drive, `..`; a path or name that is set in more than one way; deletions, renames, copies |
| A 221-character string of neighbouring Unicode characters, used to draw random "glitch" text | No entropy finding for a literal in which at least nine of ten characters are the direct successor of the one before (`entropy.consecutive`) | the same characters in another order; random text in or outside ASCII; a run with a payload in the middle; base64 and hex |
| A base64-looking puzzle text that is written to a file of the game | LOW when the literal stands right in `open(config.basedir + "/name", "w").write("...")`, the name has no extension or `.txt`, and the script executes no text anywhere (`context._written_text`) | written to `.py` / `.rpy` / `.exe` / `.bat`; outside the game; in binary mode; decoded before or after; kept in a variable or handed to a function; a script with `exec` / `eval` |
| A long sentence of a game's Japanese translation (RPY-03 to RPY-05, read on 2026-10-07): ordinary Japanese prose measures 6.0 bits per character, like random data, because the writing has thousands of characters | The entropy finding `ENT-STR-001` is suppressed as "natural-language text" (`context._natural_text`; kept in the record) when the literal is a sentence in Japanese, Chinese or Korean writing: every character is from the basic ideograph block, Hiragana, Katakana, Hangul syllables, CJK punctuation or the fullwidth forms, or is ASCII (text tags like `{b}` are not counted); at least 90 % are from those blocks (the four real sentences: 100 %); it contains kana, Hangul or sentence punctuation (、。「」，！？ ...); and the script executes no text and names no decoder anywhere. Python / Ren'Py only | one character from any other block (encodings like base65536 spread over many - and so does a sentence with a rare ideograph outside the basic block, which therefore stays reported); ideographs without kana or punctuation, or more than 40 of them in a row; more than 15 letters and digits in a row (a Base64 piece inside the sentence; fullwidth letters count as the ASCII they stand for); a file with `exec` / `eval` / `compile`, or with `base64`, `codecs`, `zlib`, `marshal`, `pickle`, `fromhex`, `.decode`, `.translate`, `ord(` ...; every other rule; HIGH and CRITICAL |

Known weak points of the eighth rule (the last row): random ideographs
with sentence punctuation put in every few characters pass as a sentence,
and so would data written in kana - in a file that neither executes nor
decodes anything, so whatever turns it back into data has to be in another
file, which a one-file check does not see. Korean is written with spaces,
and a literal with spaces was never measured for entropy in the first
place. Other engines (RPG Maker's JavaScript and Ruby) do not have this
rule: nobody looked at their files for "executes text" / "decodes".

Known weak points of these seven, all on the side of "a note where a
warning might be due": a process list that is read in one script and sent
from another file is not connected; the folder part of a plugin's path may
come from a plugin setting nobody can read (the file name and its
extension may not); the launcher's resource section is scanned for text
and for programs, not parsed (a manifest that asks for administrator
rights would not be noticed); a text literal that another *file* executes
is beyond a one-file check, like everything else here.

### False alarms that were taken apart (MZ-01 and VX-01)

On 2026-10-07 the last two real games that still needed a question were read
finding by finding: one MEDIUM in MZ-01, seven in VX-01. All eight were false
alarms with five causes. As above, each rule covers exactly the case that
was read, and each has tests for the neighbouring cases that have to stay
reported (`MzVxFalseAlarmTests`).

| What was seen | What the scanner does now | What stays as it was |
| --- | --- | --- |
| A map event declares `ShellExecute` to open the game's store page. The declaration was reported twice: as `RB-NATIVE-003` (LOW, with what is opened) and again as the plain "calls a Windows function" note `RB-NATIVE-001` (MEDIUM) | When the declaration is lowered to `RB-NATIVE-003`, the plain note on the same declaration is suppressed as "the same declaration is reported as RB-NATIVE-003" (`RgssHandler._shell_execute`, `context._same_declaration`) | a `ShellExecute` that starts a program, cannot be resolved, is never called or is handed on: both findings stay (HIGH and MEDIUM); another declaration on the same line or elsewhere; in a map file, where matches carry no line, one other declaration anywhere in the file keeps the note |
| A save-screen script declares `SetFileAttributes` and calls it twice, on its save folder: hidden, or normal in test mode | The declaration is a LOW note that names the folder, when every call was read, each sets only plain attributes (hidden, normal, read-only, archive) and each target is a folder or file of the game itself (`remote_rb.own_attributes`, `context._rgss_api`) | a target that is a program or script, outside the game, under `Data` / `Graphics` / `Audio` ..., not resolvable, or held in a constant that is built, changed or given twice; the system attribute; a call written where the function is made; the function handed on or used in any other way |
| The same script deletes a save file and its thumbnail: `File.delete(filename)`, where `filename` comes from two small methods that return `FOLDER + "/#{index + 1}.rvdata"` | Suppressed as "the game's own save data", with the paths in the evidence, when every path the call can delete was read: quoted text, constants given one literal and never changed, a name set from such values, methods that return nothing else - and each path is a file in a sub-folder of the game, not a program, not under an engine folder (`remote_rb.own_deletes`, `context._deletion_target`) | a name the method is given, a global, a second file that is not known, `FileUtils.rm_rf`, a call without brackets, a free name inside the path (`#{name}` - only a number counted from a name is accepted), a method that does anything else, a method defined twice, an absolute or profile path (HIGH as before), a file directly in the game's folder |
| A window-resize script declares four functions of `Resize.dll`, a library that lies in the game's folder | Each declaration is a LOW note ("calls the game's own library ..., read in full") when the library is named as a plain literal, lies beside the game's program, was read to its end as a program, and holds no "could not be read" note and no active finding of MEDIUM or higher. Decided after the whole folder was scanned (`Scanner._own_libraries`, `ContextEngine.own_library`), so the order of the two files does not matter | the library is missing, in another folder, not a program, named like a library of Windows (`winmm`, `kernel32` ...), has a finding or an unread part; the name is computed or is a path; strict mode; a single script scanned without its folder; functions that start programs or download are `RB-NATIVE-002` and stay HIGH |
| `greenworks.js`, the open-source Steam wrapper, defines a helper that renames a folder (`fs.rename`); nothing in the game calls it | The file is, byte for byte, the `greenworks.js` of the official Greenworks releases 0.15.0 to 0.22.0 and is accepted by that: `gamescan/library_hashes.py`, a table generated by `tools/build_library_hashes.py` from the projects' own release archives only - never from a game. It also holds Effekseer for WebGL 1.70b. A file in the table is trusted for its content, whatever it is called and wherever it lies | one changed byte; a file of that name with other content; strict mode; a CRITICAL finding or chain inside such a file |

Known weak points of these five: the library table rests on the HTTPS
download alone (neither project publishes checksums), and it knows two
libraries in a few versions - any other version is judged by its folder and
name, or as an ordinary script, exactly as before. A library of the game
that was read and found quiet is still a program the script hands control
to: the note says that the file was scanned, not that it is harmless, and
a library whose findings are all LOW lowers the note too. The path
reader for `File.delete` and `SetFileAttributes` reads one script: a method
or constant that another script redefines is not seen. Hiding a folder of
the game is a LOW note whatever is in the folder.

### Current results

`docs/benchmark/after_ruby_objects.csv` (2026-10-12). Twenty-two samples, kept
outside the project and named by code only. They are treated as clean because
they come from sources their user regards as official; none was verified
independently (for the four IL2CPP builds see "Limits"), and twenty-two samples
say little about games in general.

| Code | What it is | Verdict | CRITICAL | HIGH | MEDIUM | LOW | Suppressed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| XP-01 | RPG Maker XP game | CLEAN | 0 | 0 | 0 | 0 | 12 |
| XP-02 | RPG Maker XP game | CLEAN | 0 | 0 | 0 | 0 | 12 |
| VX-01 | RPG Maker VX game | LIKELY SAFE | 0 | 0 | 0 | 8 | 84 |
| VXA-01 | RPG Maker VX Ace game | LIKELY SAFE | 0 | 0 | 0 | 19 | 129 |
| MV-01 | RPG Maker MV game (NW.js) | LIKELY SAFE | 0 | 0 | 0 | 19 | 52 |
| MZ-01 | RPG Maker MZ game (NW.js) | LIKELY SAFE | 0 | 0 | 0 | 52 | 100 |
| RPY-01 | Ren'Py 6.99 game | LIKELY SAFE | 0 | 0 | 0 | 18 | 260 |
| RPY-02 | Ren'Py 7.3.5 game | LIKELY SAFE | 0 | 0 | 0 | 16 | 294 |
| RPY-03 | Ren'Py 7.3.5 game | LIKELY SAFE | 0 | 0 | 0 | 167 | 308 |
| RPY-04 | Ren'Py 8.1.3 demo game, Windows build | LIKELY SAFE | 0 | 0 | 0 | 25 | 334 |
| RPY-05 | the same demo, Linux build | LIKELY SAFE | 0 | 0 | 0 | 25 | 312 |
| RPY-06 | Ren'Py 8.4.1 game | LIKELY SAFE | 0 | 0 | 0 | 28 | 400 |
| UNI-01 | Unity 2019.2.6 game (Mono, 64-bit) | LIKELY SAFE | 0 | 0 | 0 | 3 | 52 |
| UNI-02 | Unity 2019.3.6 game (Mono, 32-bit; its engine files are unsigned) | LIKELY SAFE | 0 | 0 | 0 | 18 | 67 |
| INS-01 | the Inno Setup tool's own installer | LIKELY SAFE | 0 | 0 | 0 | 28 | 74 |
| INS-02 | the NSIS tool's own installer | SUSPICIOUS | 0 | 17 | 2 | 40 | 6 |
| INS-03 | game installer, Inno Setup 5.6.2 (from a store) | CLEAN | 0 | 0 | 0 | 0 | 91 |
| INS-04 | game installer, NSIS | LIKELY SAFE | 0 | 0 | 0 | 18 | 5 |
| IL2-01 | Unity IL2CPP sample build, 2019.4.34 (empty project) | LIKELY SAFE | 0 | 0 | 0 | 4 | 5 |
| IL2-02 | Unity IL2CPP sample build, 2022.3.35 (empty project) | LIKELY SAFE | 0 | 0 | 0 | 5 | 4 |
| IL2-03 | Unity IL2CPP sample build, 6000.5.0a6 (empty project) | LIKELY SAFE | 0 | 0 | 0 | 3 | 3 |
| IL2-04 | Unity IL2CPP sample build, 6000.6.0b1 (empty project) | LIKELY SAFE | 0 | 0 | 0 | 3 | 3 |
| | **all twenty-two** | 3 CLEAN, 18 LIKELY SAFE, 0 REVIEW, 1 SUSPICIOUS, 0 DANGEROUS | 0 | 17 | 2 | 499 | 2607 |

Against `after_il2cpp.csv`, the benchmark before the download-and-execute
chains for Python, Ruby, PowerShell and batch files were added: VX-01 went
from SUSPICIOUS to REVIEW (its one HIGH finding was a `ShellExecute` that
opens the game's store page; it is a LOW note now, with the address), and
the two Ren'Py samples each have two more suppressed findings - the
download-and-execute chain in Ren'Py's own updater, found in `00updater.rpy`
and `.rpyc` and hidden because both files are verifiably the official ones.
The other thirteen samples are unchanged. No new chain fired in any game's
own scripts.

Against `after_step4.csv` (the follow-ups of the evening of 2026-10-06, see
`docs/CHANGELOG.md`): three more LOW notes, `ENGINE-003`, on the three engine
files the two Ren'Py games changed (RPY-01 one, RPY-02 two). Nothing else
changed in any sample - not through the command lines started from Python
and Ruby, the tracer's wider reach, or the three added SDK versions.

Against `after_followups.csv` (the seven rules of "False alarms that were
taken apart", 2026-10-07): MV-01 and RPY-01 went from SUSPICIOUS to LIKELY
SAFE - MV-01 lost 3 HIGH and 2 MEDIUM, RPY-01 1 HIGH and 15 MEDIUM; RPY-01
has two more LOW notes (`PROC-LIST-001`: it reads the list of running
programs; the puzzle text it writes into a file), MV-01 as many LOW as
before (one note fewer in its launcher, one more for the data file its
plugin writes). The other fourteen samples are unchanged, finding for
finding. Step by step: `after_mv_rpy_step1.csv` to `..._step6.csv`. (The
last two runs read the sixteen sample folders through links, because three
folders without a code had appeared in the sample root; a scan through a
link gives the same findings.)

Against `after_mv_rpy.csv`: three samples were added on 2026-10-07 (RPY-03
to RPY-05; first result `after_rpy03.csv`, the sixteen earlier samples
exactly as before). All three were REVIEW for one reason - four MEDIUM
`ENT-STR-001` findings on sentences of their Japanese translations. With
the natural-language rule (`after_cjk_text.csv`) the four are suppressed
and the three samples are LIKELY SAFE; the other sixteen are unchanged,
count for count, and the only rule count that differs is `ENT-STR-001`
MEDIUM (4 -> 0). All their LOW findings are `URL-001` (web addresses in
credits and translations).

Against `after_cjk_text.csv` (the five rules of "False alarms that were
taken apart (MZ-01 and VX-01)", 2026-10-07): MZ-01 and VX-01 went from
REVIEW to LIKELY SAFE. MZ-01 lost its one MEDIUM finding (suppressed: the
file is an official library release). VX-01 lost all seven: five are LOW
notes now (four calls into the game's own library, one `SetFileAttributes`
on its save folder), two are suppressed (the duplicate note on the
`ShellExecute` declaration, the deletion of its own save files). The other
seventeen samples are unchanged, count for count, and no other rule count
differs.

Against `after_mz_vx.csv`: three samples were added late on 2026-10-07 -
two Unity games (UNI-01, UNI-02; both Mono) and a Ren'Py 8.4.1 game
(RPY-06); first result `after_uni_rpy06.csv`, the nineteen earlier samples
exactly as before. UNI-01 and RPY-06 were LIKELY SAFE at once. UNI-02 was
SUSPICIOUS with 3 HIGH and 1 MEDIUM, all four in engine files that carry no
signature: two injection functions in the Mono runtime's import table, the
text `rundll32.exe` in the player, a download function in the crash
handler. With the official files of Unity 2019.3.6f1 in the engine table
(`after_unity_hashes.csv`) those files are, byte for byte, the official
ones; their findings are suppressed for that reason, the "not signed" notes
are gone, and UNI-02 is LIKELY SAFE (LOW 30 -> 18, ten more suppressed).
The other twenty-one samples are unchanged, count for count. RPY-06's
engine scripts all verify as the official 8.4.1 files.

Against `after_unity_hashes.csv` (and `after_command_lines.csv`, which is
the same count for count): since 2026-10-08 the engine's compiled Python is
compared with the official SDK (`after_pyo_reader.csv`). No verdict changed.
RPY-01 has one LOW note more and RPY-02 two, all `ENGINE-005`: the compiled
forms of the three engine files those two games changed. Every other
compiled file of RPY-01, RPY-02 and RPY-03 contains exactly what the
official one contains, and no other count differs in any sample. (The files
column of the Ren'Py samples is higher: compiled files are read now.) The
comment-only rule and the leftover note of the same day changed nothing in
any sample (`after_pyo_tokens.csv`: the same, count for count). Nor did
reading the calls of compiled files (`after_pyo_walk.csv`): the same
verdicts and counts; RPY-02 has one more suppressed finding, an `exec` in a
changed engine file that the rules now see in its compiled form. Since
2026-10-10 (`after_1b_step1.csv`) that finding is shown, a LOW note: a
compiled engine file that differs no longer has the folder's trust - RPY-02
16 LOW instead of 15, nothing else in any sample. Following a download
through objects, callbacks and threads (the same day) changed no sample,
and neither did following it across two files nor reading compiled Python
per function (`after_1b_step2_join.csv`, `after_1b_step2.csv`: the same,
count for count), nor the closing step - `persistent`, the dropper across
two files, the note for a second reading that was cut short
(`after_1b_closing.csv`, and `after_1b_fixes.csv` after two fixes to it: the same again; no sample gets that note).
Reading the instructions of NSIS installers changed nothing either
(`after_nsis_reader.csv`). Reading Inno Setup's `[Code]` and `[Run]`
(`after_inno_reader.csv`, 2026-10-11) changed one sample, as intended:
INS-01, 28 HIGH -> 25 and 96 LOW -> 99 - the two download words in the names
of its example files and the chain on them are LOW notes now - and the
launcher asks for the typed word instead of refusing it. Reading the `[Run]` rows
of installers without `[Code]` (`after_inno_rows.csv`) changed nothing.
With Inno Setup's own programs in the official hash table and its standard
messages recognised (`after_inno_official.csv`, 2026-10-11), INS-01 went from
SUSPICIOUS to REVIEW: 25 HIGH -> 0, 3 MEDIUM -> 1, 99 LOW -> 104; the
launcher asks once instead of asking for the typed word. No other sample
changed - INS-02, INS-03 and INS-04 are as before. With the table rebuilt
from the official installers themselves and widened to every file of the
distributions (`after_inno_installers.csv`, the same day), INS-01 is LIKELY
SAFE: its last MEDIUM is gone, 104 LOW -> 28 (the notes in the compiler's
own programs are covered now), and the launcher starts it. Nothing else
changed. And with the setup header taken from the loader's table
(`after_inno_loader_table.csv`, the same day) INS-03 is read for the first
time: LIKELY SAFE -> CLEAN, its three "could not be inspected" notes gone,
4 -> 91 suppressed findings (it is signed by a trusted publisher, whose
signature covers what is packed inside), the launcher starts it. Nothing
else changed. The two changes to how installer headers are found
(`after_installer_fallback.csv`, the same day) changed no sample. With
Unity 2019.2.6f1 in the engine table (`after_unity_2019_2.csv`, the same
day) UNI-01 has 3 LOW notes instead of 6 (its "not signed" note and two
address notes in its player files are covered); no verdict changed. The
reader of compiled C# (`after_csharp_step1.csv`, the same day) changed no
sample: no library of UNI-01 or UNI-02 downloads and then loads or starts
anything. Its second step (between methods, delegates, between libraries;
`after_csharp_step2.csv`, the same day) changed no sample either; the two
Unity games took about twenty seconds longer to scan, and after the speed
changes of the same day (`after_csharp_speed.csv`, again no sample
changed) about four to five seconds longer than before the second step
(UNI-01 8.8 s, UNI-02 14.4 s for the whole scan). With libraries that
define a loader followed as well and every library read a second time for
a fixed answer (`after_csharp_defines.csv`, again no sample changed):
14.0 s and 19.8 s. The VBScript chain (`after_vbscript.csv`, the same
day) changed no sample: the five small `.vbs` files in the Ren'Py samples
download nothing. Decoding encoded scripts, JScript under the Windows
Script Host and the "limit reached" note (`after_script_encoder.csv`,
2026-10-12) changed no sample either, and no sample gets one of the two
new notes. With the limit note made by every tracer
(`after_limit_notes.csv`, the same day) one sample gets it - **MZ-01: one
LOW note more (52 -> 53) for its 4.7 MB `credits.html`, still LIKELY SAFE,
and the launcher asks once instead of starting it.** Nothing else changed.
With the size limit applied to the script in a page, the NW.js table
holding every file of its archives and the tracers' clocks turned into
five-second brakes (`after_html_blocks.csv`, the same day) MZ-01 loses that
note again and the launcher starts it; the result is, row for row and rule
for rule, the one of `after_script_encoder.csv`. The joins across Ruby
scripts and across shell scripts (`after_ruby_join.csv`,
`after_shell_join.csv`, the same day) changed no sample, and neither did
following Ruby objects (`after_ruby_objects.csv`), nor `renpy.sh` in the
official table with the note for more than four classes
(`after_renpy_sh.csv`), nor the lowering of findings in a hash-verified
`.sh` launcher (`after_sh_baseline.csv`). With the files of the official
NSIS 3.13 distribution in a hash table (`after_nsis_official.csv`, the
same day) one sample changed, the expected one - **INS-02, the setup
package of NSIS: SUSPICIOUS -> LIKELY SAFE (17 HIGH -> 0, 2 MEDIUM -> 0,
40 LOW -> 9), and the launcher starts it.** No sample is SUSPICIOUS or
REVIEW now, and no HIGH or MEDIUM finding is shown in any of the 22:
3 CLEAN, 19 LIKELY SAFE; 468 LOW notes.

Since the payload reading says when it stops at its step limit
(`after_count_limit.csv`, 2026-10-12, the current result) **RPY-02 has one
more LOW note (16 -> 17; 469 in all) and the launcher asks about it once**:
its `renpy/main.py` is not the official file of its Ren'Py version, and the
reading of what reaches `exec` / the shell stops in it after 250,000 steps
- as it always did, without saying so. Still LIKELY SAFE. Nothing else
changed.

After the sweep of the silent limits (`after_limit_sweep.csv`, the same
day, the current result) **MV-01 has one more LOW note too (19 -> 20; 470
in all) and is asked about once**: its `www/js/libs/pixi.js` has more than
600 calls of the kind the payload reading looks at, and only the first 600
are read. Still LIKELY SAFE. Nothing else changed.

All fourteen real games are CLEAN or LIKELY SAFE, and the secure
launcher starts twelve of them without a question (RPY-02 and MV-01: see above). (For one benchmark run on
2026-10-12 MZ-01 was asked about: its `credits.html`, 4.7 MB - the licence
page that comes with NW.js -, was larger than the 4 MB the JavaScript
tracer read of any file, and the new note `SCRIPT-LIMIT-001` said so. The
same day the limit became a limit on the script in a page, and the page
was found to be the official one of NW.js 0.48.4.) The two
installer tool packages:

- **INS-01** - LIKELY SAFE since 2026-10-11. Its 25 HIGH and 3 MEDIUM are
  gone: every program in it - the setup engine in its two variants, its
  two loaders, the compiler and its editor - is, by SHA-256, a file of the
  official Inno Setup 6.7.3 installer (the chains in them are LOW notes),
  `RegSvr32` in the script texts stands in standard messages, and the
  words in the names of its example files are file names.
- **INS-02** - 17 HIGH, none in the outer installer (2 LOW): the twelve stub
  programs the tool ships without a file extension and one named `.bin`
  (`NAME-002`, 13), `regsvr32` in that `.bin` and the chain it forms, and the
  compiler's window program (an input hook plus network imports, and their
  chain).

INS-03 was LIKELY SAFE for a different reason until 2026-10-11: the reader
took the wrong one of two setup headers and read nothing of it; it is read
and CLEAN now. The two MEDIUM findings that are left are in INS-02.

The seconds column of these files is not a measurement: the same code took
between 17 and 37 seconds on MV-01 in four runs on the same day.

## Outside files, tables, cache and the package

(These sections stood under "Architecture" in the old README.)

### Files from outside: the manifest and the fetcher

Since 2026-10-12 (phageo; open item 19, step 1). Everything the project
takes from outside is listed in one place, **`tools/manifest.json`**: the
official engine and library archives the hash tables are built from, and
the compilers the installer tests use - 39 files, about 2.6 GB. One row
per file: its name, the official address, its SHA-256, its size, a short
licence note, what uses it, and the group it belongs to (`archives`,
`test-tools`; the six Inno Setup installers and the NSIS zip are in
both). None of these
files is in the project, and none is shipped.

**`tools/fetch.py`** works from that list:

    python tools/fetch.py --list
    python tools/fetch.py --check --to C:\somewhere\engine_archives
    python tools/fetch.py --fetch --group archives --to C:\somewhere\engine_archives

- **A first download** (since 2026-10-17): a publisher that states no
  SHA-256 (Microsoft's DirectX package) is listed once with `"sha256":
  null` and a `"first"` note. That row is downloaded once, its SHA-256 is
  printed, and it is refused everywhere until the value is written into
  the manifest (after the file was checked - for DirectX, Microsoft's
  signature on it) and the note is taken out. Such a row names its
  publisher (`"publisher"`, as the signing certificate states it, e.g.
  `"Microsoft Corporation"`), and the download is **kept only when
  Windows' own check (`WinVerifyTrust`) finds a valid signature of exactly
  that publisher** - no signature, a broken one or another name: deleted
  and refused (phageo, 2026-10-17; Windows only).
- It downloads **only what is listed** - a file is named by its row; an
  address is never taken from the command line -, only over https, only
  from the publishers' servers written in the script, and it follows a
  redirect only to the download servers written there.
- It **refuses any mismatch**: a download whose SHA-256 or size is not the
  listed one is deleted, nothing of it is kept. A file that is already
  there under the name and is not the listed file is reported and left as
  it is.
- It **tries up to three times** when a server cannot be reached or the
  connection breaks, five seconds apart (since 2026-10-12: renpy.org
  answered only a second try that day) - and never after a mismatch: what
  came and is not the listed file is refused at once, as is an error
  answer of the server or a redirect away from the official servers.
- It **never runs, unpacks or opens** what it fetched (a test reads the
  script for that).
- `--list` and `--check` contact no server. A download still needs phageo's
  word first (CLAUDE.md, rule 14).

The switch `GSS_BUILD_INSTALLERS=1` of the installer tests has no download
of its own any more: `tests/build_installers.py` asks the fetcher, so only
a listed compiler with the pinned SHA-256 arrives (it then sets the
compiler up and runs it, as before - that is what the switch is for).

**The table builders have no download of their own** (step 2, the same
day): `build_engine_hashes.py`, `build_library_hashes.py`,
`build_inno_tables.py` and `build_nsis_tables.py` get every archive through
the fetcher (`fetch.obtain` - only a row of the manifest), and a
publisher's checksum list through `fetch.read_listing` (only a list that a
row names as its `listing`). A kept archive is compared with the
manifest's SHA-256 on every run, also offline - before, a kept archive was
compared with nothing unless its publisher's list was read. To cover a new
version: add its row to the manifest, then the version to the tool's
`SOURCES`. Rebuilt offline through the new path, all four tables came out
byte for byte as they were.

Limits, said plainly: **one real download was made for the project** -
`nsis-3.13.zip` from SourceForge on 2026-10-12, one try, SHA-256 as pinned.
GitHub, renpy.org, nwjs.io and Unity were each tried once the same day
with one small listed file (compared and deleted; all four as listed,
renpy.org at the second try); `files.jrsoftware.org` and GitHub's release
files were not. The refusals, the retries and the manifest are tested with
local files standing in for the server - the retry was never needed on a
real download since it was built. The licence notes are short reminders written from memory, not
legal texts - to be checked against the official licence pages before any
release (phageo, 2026-10-12). The builders keep their own lists of versions
and addresses (`SOURCES`); a test holds those lists and the manifest
together.
`renpy-8.6.0-sdk.zip` lies in the archives folder but is not listed: it is
in no table (renpy.org publishes no checksum for it).

### The positive runner: findings of official files, and `--diagnose` (2026-10-17, sixtieth message)

- **The column `official`** of `tools/positive_benchmark.py`'s CSV holds the
  part of `rules` whose files are, byte for byte, files of an official table
  (`gamescan.official`, a Ren'Py engine script by SHA-256, a compiled engine
  script by its content key) - checked by the runner itself for every file
  the scanner reads (`watch_origins`, `official_origin`), apart from what the
  scanner makes of the file.
- **The gate** (phageo's rule): a malicious verdict may drop only when every
  finding the earlier run had and this one has not - by rule and level -
  stood in such a file in the earlier run (`official_drop`). Such a drop is
  printed as "accepted drop"; any other fails the gate (exit code 4), and so
  does every drop against a result written before the column existed.
- **`--diagnose`** (`tools/renpy_diagnosis.py`): per sample, where its HIGH /
  CRITICAL findings stand (the endings of the containers and of the file,
  official or not), what its scripts that are not official name (network /
  decode / run / write words, counted), what the local reading
  (`CHAIN-LOCAL-DROP`) saw in each file, which compiled scripts could not be
  read (by their header), and what the resolved command lines start - endings,
  rule numbers and counts only. The probe of the local reading evaluates a
  few expressions a second time, so a `--diagnose` run is a measurement only;
  its verdicts are not a result.

### The npm library table

Since 2026-10-14 (phageo; `gamescan/npm_hashes.py`, built by
`tools/build_npm_hashes.py`). An Electron app carries its libraries with
it (`node_modules`), and in a clean app nearly every HIGH finding stands in
one of them - a hardware-information library asks Windows through `wmic`
and PowerShell, an update library starts the installer. The folder and
name of such a file can be imitated; its exact content cannot.

- **Which packages:** the names and versions in `tools/npm_packages.txt`,
  read from the `package.json` files of the clean Electron samples and of
  the real samples - **names and versions only** (the runner's
  `--packages` mode for the real ones). 691 packages.
- **Where every hash comes from:** the package's archive on
  `registry.npmjs.org`, through `fetch.py`. The registry states the
  SHA-512 of each version's archive (`dist.integrity`); `--register`
  reads it, downloads the archive once, refuses it when its SHA-512 is
  another one, and writes the row of `tools/manifest_npm.json` (the
  registry's value, and the SHA-256 of that same file - `fetch.py`
  checks both from then on; the new manifest field `integrity`). The
  archive is read in memory, file by file; nothing is unpacked, no
  install script is looked at. **No hash comes from a sample.**
- **What is in the table:** the files with an ending of code (`.js`,
  `.cjs`, `.mjs`, `.node`, `.json`, `.html`, `.wasm`, programs and shell
  scripts) of at least 24 bytes; not `package.json` (npm rewrites it when
  it installs). 6,232 files.
- **Checked first** on one package: the 23 files of `systeminformation`
  5.27.7 in ELE-02 are byte for byte the registry's.
- **What a verified file gets** (`official library release, verified by
  SHA-256: npm package <name> <version>`): **its single pattern findings
  are lowered** (hidden as verified) - and nothing else. **npm
  verification proves origin, not intent** (phageo, 2026-10-14, the same
  day, after the first form of this table had moved two real samples from
  SUSPICIOUS to REVIEW): a verified file **keeps its chains**, HIGH ones
  too - the ones a reader makes (`CHAIN-TEXT-RUN`, `CHAIN-REMOTE-ARG`,
  `CHAIN-REMOTE-LOAD`) and the ones its lowered signals add up to
  (`CHAIN-FETCHRUN` ...) - and what it is able to do
  (`ADDON-DECRYPT-001`). A CRITICAL was never lowered (rule 13). Limit
  notes are not made for it. The app's own scripts are read as ever.
  Strict mode trusts no table.
- **A HIGH chain that starts and ends inside one verified file is the
  library's own mechanism: MEDIUM**, still shown, tagged
  (`context["library_mechanism"]` = the package; the reason says "a
  mechanism of the library") - phageo, 2026-10-14 (fortieth message).
  CRITICAL and `ADDON-DECRYPT-001` are not touched; a chain made across
  files after the scan (one that starts in the app's own code) is not
  touched either. Not in strict mode.
- **Since 2026-10-20 (phageo, seventy-third message: an exception to rule
  13) a CRITICAL chain whose source and sink both lie inside one verified
  library file is MEDIUM too** - in a file of a published npm package and in
  a file of an official library release (`library_hashes`: jQuery from
  `code.jquery.com`, Greenworks, Effekseer, SDL2, OpenAL Soft). Tagged
  `context["library_was_critical"]`, the reason says "It was CRITICAL: the
  library can run code it is given, but nothing in this file hands it an
  address". Why: jQuery's own `_evalUrl` - a `<script src>` in markup handed
  to `.html()` / `.load()` is fetched and run - was CRITICAL in every app
  that ships jQuery (HO-01). **App code that hands such a loader a remote
  address stays CRITICAL** (`CHAIN-REMOTE-CODE`, read in the app's own
  script): `$.getScript(...)`, and since the same day `$(...).load(address)`
  and `$.ajax({url: address, dataType: "script"})` - only with an address
  that is remote, decoded or a download's answer (`.load` is also jQuery's
  old event shortcut). Not covered: app code that hands a download's answer
  to `.html()` (markup, not an address). Strict mode keeps the CRITICAL.
- **The whole published package** (phageo, the same message): the library
  tables hold every file of a package, not only its main file - first
  jQuery: all 64 releases on the npm registry (1.5.1 ... 4.0.0, the
  pre-releases too) are rows of `tools/npm_packages.txt` /
  `tools/manifest_npm.json`, so `src/manipulation/_evalUrl.js` and the
  other files of `src/` are known content (2,048 files more; 755 packages,
  8,280 files).
- **Why:** real samples are built from published packages, the dangerous
  parts included. Measured: three of the six add-ons that decrypt stored
  secrets in real samples are a published package's own file, and the
  script of one sample that hands a text to the runtime is one too.
- **Weak points:** a package that is bundled into one file, patched, or
  fetched from another place is not covered; nor is any version that is
  not on the list. Lowered single findings of a published package are not
  seen unless one asks for the hidden ones.

### The cache of unpacked and parsed files

Since 2026-10-13 (phageo; `gamescan/cache.py`). Work that depends on a
file's bytes alone is kept on disk and found again when the same file is
scanned by the same code:

| Kind | What is kept | Module whose source hash is in the key |
| --- | --- | --- |
| `pe-strings` | the texts of a program (`pe.extract_strings`) | `gamescan.pe` |
| `dotnet-listing` | what a .NET library refers to (`dotnet_meta.decompile`) | `gamescan.unpack.dotnet_meta` |
| `dotnet-il` | the reading of a .NET library's methods (`remote_cs.analyse`) | `gamescan.dataflow.remote_cs` |
| `asar-index` | the list of files of an `app.asar` | `gamescan.unpack.asar` |

- **Key:** the file's SHA-256, the kind, the size that was read, and the
  *source hash* of the module that does the work - the SHA-256 over that
  module's file and over every module of the package it imports, directly
  or through others (read from the `import` lines; `cache.source_hash`).
  A change to that code makes its entries unreachable; a change to a rule
  does not (no rule is among those imports - a test holds that).
- **Nothing that depends on the rules is kept:** no finding, no verdict.
  The rules run on every scan.
- **A limit a reader reached** while the work was done is kept with the
  result and said again when the result comes from the cache, so the "not
  read" note is the same either way.
- **Where:** the folder the benchmark is given (`--cache-dir`), by default
  the developer's `%LOCALAPPDATA%\GameSafetyScanner\cache`
  (`GSS_CACHE_DIR` names another). Never inside the application's own
  folder - such a folder is refused -, so it cannot get into a package
  that is handed on. An entry holds no file name and no path.
- **Size:** at most 1 GB in all (the entries used longest ago are deleted
  first), 48 MB for one entry. After a benchmark of the 23 samples: 677
  entries, 13 MB.
- **A developer's tool - off for every user** (phageo, 2026-10-13, the
  evening of the day it was built): the command line, the window and the
  secure launcher never use it and have no switch for it (`--no-cache` is
  gone - there is nothing to switch off). The reason: any program of the
  user can write to that folder, and a planted entry could make a scan
  skip a file. **Used only** by the false-positive benchmark, and only
  with `--cache`, on clean samples, to measure time. **The positive
  benchmark locks it** for its whole process (`cache.forbid`): text taken
  from a real sample must not reach the disk in any form.
- **Form:** a mark, the entry's own SHA-256, zlib, JSON. Nothing is
  unpickled or run. A damaged entry is deleted and the work is done again.
- **Effect** (the 23 samples, scans alone, the same load both times): 614
  seconds with the cache empty, 514 with it filled. Most for games with
  many .NET libraries (UNI-02: 39 -> 11 s); little for games that are
  mostly script (their time is the rules and the readings, which are not
  kept).
- **Weak points:** the cache is no proof of anything - whoever can write
  to the user's profile can write an entry (its SHA-256 only finds
  damage). That is why no scan a user's verdict comes from reads it. What a module does
  through something other than its imports (a data file read at run time,
  a switch set from outside) is not in its source hash; none of the four
  kinds has such a thing today. Unpacked members of archives, the LZ4
  blocks of Unity bundles and the parsed headers of programs are not kept
  (they are large, or not measured to be worth it).

### Distribution without an installed Python (built 2026-10-24, start-up check since packaging session 2)

Built on 2026-10-24 (packaging session 1 of 3-4 for 0.9-beta):
`python tools/build_package.py --inputs <folder> --names <mapping file> --out <folder>`
writes `GameSafetyScanner-0.9.0-beta.zip` (about 1,095 files, 16.7 MB):

- Since packaging session 2 (2026-10-24) also at the top: `LICENSE` (the
  project's MIT licence, phageo), `README.md` (the user section of this
  file, between its `user-section` markers), `THIRD-PARTY-NOTICES.txt` (the
  licence of every bundled part, then python.org's "Licenses and
  Acknowledgements for Incorporated Software" from the full package's
  `Doc/html/license.html`, as plain text), and `app\package_files.json` -
  the SHA-256 of every other file. **Start-up check** (`gamescan/selfcheck.py`,
  `App._startup_checks`): the window compares the files with that list;
  any changed, missing or added file (`__pycache__` / `.pyc` aside, which
  Python writes itself) gives one warning in plain words, and scanning
  stays allowed. Outside a package (no list) nothing is checked.
- **Packaging session 3 (2026-10-24):** "Safe launch with Game Safety
  Scanner" on programs (`SystemFileAssociations\.exe\shell`, command
  `... GameSafetyScanner.pyw --launch "%1"`) and a "Safe launch…" button after
  a scan: both run `launcher.secure_launch` with the window's dialogs
  (`App.safe_launch`; the scanner from `launcher.launch_scanner`, the same as
  `--launch`). The package also carries `RELEASE-NOTES.md`
  (`docs/RELEASE_NOTES.md`); the builder refuses the build PC's Windows user
  name. `tools/release_check.py` runs the release checklist on a zip
  (`docs/RELEASE_CHECKLIST.md`); `tools/package_suite.py` runs the suite on the
  package's Python. The kept readings hold no text of the table files: each
  text is places in the file plus a hash (`known_findings.Places`), rebuilt
  from the scanned file; a mismatch means the file is read as usual.
- **Explorer right-click menu** (`gamescan/shellmenu.py`; opt-in, a button in
  Settings and on the main window): one entry "Bagel" (icon, `SubCommands` = "")
  on folders (`Directory\shell`), files (`*\shell`) and programs
  (`SystemFileAssociations\.exe\shell`, where the same verb name wins over `*`)
  with the submenu `shell\1scan` "Scan" and, on programs, `shell\2launch` "Safe
  launch" (since 2026-10-25; the older separate `GameSafetyScannerLaunch` entry is
  removed), under `HKEY_CURRENT_USER\Software\Classes` only - no admin rights,
  never the default verb. Commands: `"<Bagel.exe>" "%1"` / `"<Bagel.exe>" --launch
  "%1"` of the running package (`shellmenu.start_program`), or `"<pythonw.exe>" -I
  "<GameSafetyScanner.pyw>" ...` where there is no `Bagel.exe` (the project folder);
  a path with `"`, `%` or a line break is refused. "Scan" on a program scans its
  folder, the folder Safe launch scans; a program carrying an installer or a
  self-extracting archive (Inno, NSIS, 7z, RAR, CAB by the scanner's own
  detection), a non-program, or one at a drive's top is scanned as itself
  (`launcher.scan_target`); the window's status line says which. An installation
  for all users writes the same keys below HKLM; the window only reads them
  (`shellmenu.machine_wide`) and shows the menu as on. Every key it had to make
  (also a missing `shell` / `Directory` / `*` parent) is written down in the
  entry and removed again on "Remove", parents only while empty. When the
  entry names another copy (the folder moved), the window offers to point
  it to the running copy.

- `Bagel.exe` - the one start program (`tools/launcher/Bagel.cs`, built once by
  `tools/build_launcher.py` with Windows' own .NET Framework `csc.exe`, kept with its
  SHA-256 in `tools/launcher/launcher.json`): a windowed program (no console) with
  Bagel's icon and version information (Bagel, phageo, 0.9.0-beta) that starts
  `python\pythonw.exe -I app\GameSafetyScanner.pyw <its arguments as written>`,
  waits for it and exits with its exit code - so Task Manager shows "Bagel" with
  the icon, and the window sets the AppUserModelID `phageo.Bagel`. The embeddable Python's `python313._pth`
  fixes its library path, so no installed Python, no `PYTHONPATH` and no
  user site folder is used.
- `python\` - python.org's **embeddable Python 3.13.16, 64-bit** (the tested
  3.13 line), plus `tkinter`, `_tkinter.pyd`, the Tcl/Tk libraries and their
  `tcl` folder from python.org's full `python-3.13.16-amd64.zip` (the
  embeddable package has no Tcl/Tk). Both files are rows of
  `tools/manifest_package.json` with the SHA-256 python.org states in
  `windows-3.13.16.json`; the builder compares them before it reads them,
  as zips - nothing is installed, unpacked to disk or run.
- `app\` - `GameSafetyScanner.pyw` and `gamescan\` only (its tables and
  kept readings included; the experimental monitor left out - the kept
  readings' code fingerprint does not count those two modules, so the
  package uses them).
- The builder refuses `tests/`, `tests/_tools`, `engine_archives`,
  `docs/benchmark`, `docs/memory`, the behaviour monitor, `__pycache__`, and
  any name outside its allowlist; it compares every file by content with
  `tests/` and `engine_archives` (none may match) and searches the app's
  files for the real names of the benchmark games, read from the mapping
  file outside the project (none may stand; a hit is reported by sample
  code only). The zip is the same bytes for the same inputs.

The plan as decided by phageo on 2026-10-12 (CLAUDE.md, open item 19 d) - the
start-up hash check below is **built since packaging session 2** (above):

- The package will bring **Python 3.13, 64-bit** with it, the version
  this project is tested on. Looked at on 2026-10-12: python.org's
  embeddable package has no Tcl/Tk (which the window needs); its plain
  `python-3.13.16-amd64.zip` has everything - `python.exe`, the
  libraries, `_tkinter`, the Tcl/Tk files -, and python.org publishes its
  SHA-256. So the package can be put together from that one zip, read
  as a zip: no installer is run.
- The `lz4` package is not needed: the scanner has its own LZ4 decoder
  (standard library only, with limits). Without `lz4` nothing is left
  unread and no note changes - large Unity bundles only take longer.
- At start the package will compare its own files with a list of hashes
  and name any that is missing or changed. **That check finds damage - a
  broken download, a half-copied folder, a file an antivirus removed. It
  does not find tampering:** whoever can change the files can change the
  list beside them. Only the SHA-256 of the whole package, published
  somewhere else, and later a signature, speak to that.

Adding an engine: subclass `BaseHandler`, set `extensions` (and `magics`,
`baseline`, `markers`), implement `scan()` (and `expand()` for containers),
and add it to `default_handlers()` in `handlers/__init__.py`.

The JSON report only ever gains fields; existing fields are not renamed
(`verdict_plain` and per-finding `advice` were added most recently).
