# How Bagel works

Engines, rules and verdict logic of Bagel (internal name Game Safety Scanner, `gamescan`).
Moved out of the old README.md word for word (phageo, 2026-10-25); the short README.md is for users.
A "see ... above / below" in the text may now point into one of the other files: `docs/HOW_IT_WORKS.md`, `docs/DEVELOPING.md`, `docs/LIMITS.md`.

## About

**Bagel** is its name for users since 0.9-beta (window, reports, menu, package
and installer); the code keeps its internal names (`gamescan`).

Static malware triage for game folders (Ren'Py, RPG Maker XP/VX/VX Ace/MV/MZ,
Unity/.NET, native Windows programs, scripts). Standard library only.
**Tested only on Python 3.13** (64-bit, Windows) - the only version it has
ever run on. The code is written for 3.9 and later, but no other version was
tested (phageo, 2026-10-24: no 3.9 test run for 0.9-beta). Nothing from a
scanned file is ever executed or imported - files are only read, with size,
decompression and recursion limits throughout.

It is a second opinion next to Windows Security, not a replacement for it.
Licence: MIT, "Copyright (c) 2026 phageo" (`LICENSE`).

## When part of the content could not be read

Since 2026-10-12 (phageo): a scan in which content could not be read never
ends in CLEAN or LIKELY SAFE. A password-protected archive (`ARC-001`), an
archive, installer or `app.asar` of which a part was not unpacked
(`ARC-002`), compiled JavaScript (`JSC-FMT-001`) and a program of a kind
the scanner does not read (`EXEC-FMT-001`: Java class files) make the
verdict at least **REVIEW** - "Part of the content could not be read" - and the secure
launcher asks once before it starts the game. The notes themselves stay
LOW and are never hidden by a signature, a hash or a folder; only your own
"false positive" mark or allow list sets one aside. A higher verdict stays
what it is. On the clean benchmark samples this changed nothing: none of
them has such a note.

**Known content is no unread content** (phageo, 2026-10-17, fifty-ninth
message; `gamescan/official.py`, `Scanner._scan_one`): a file that is, byte
for byte, a file of one of the official tables (engines, Inno Setup, NSIS,
Electron, DirectX, the libraries games bundle, published npm packages, the
RPG Maker runtimes from the vendor's own installers) gets none of these
notes and no packed-program note of its own - its content is known. Inside
an archive or an installer a file of a format nobody reads is unpacked for
this, up to 16 MB (`containers.MAX_COMPARED`): one that is in no table gets
its own note, a larger one is named in the archive's note as before. Not
known content: the RPG Maker VX Ace runtime build the table holds as
evidence from two games, not from the vendor (`runtimes.NOT_FROM_VENDOR`),
and anything verified by less than its whole file (a launcher apart from
its resources).

### Windows Installer packages (MSI)

Since 2026-10-18 (phageo's plan of 2026-10-17, part 1 of 2) an MSI package (and a
patch, transform or merge module) is opened: `gamescan/unpack/cfb.py` reads the
compound file it is (sectors, the FAT and mini FAT, the directory tree,
streams), `gamescan/unpack/msi.py` the installer database in it (packed stream
names, the string pool - texts over 64 KB and three-byte text numbers too -,
`_Tables` / `_Columns`, tables stored column by column). From `File`,
`Component`, `Media`, `Binary`, `CustomAction`, `InstallExecuteSequence`,
`Property` and the other streams it says what the package holds: the files it
installs (name, declared size), its cabinets (embedded or beside it), the
programs and scripts it carries in `Binary`, its custom actions (name, type in
words, source name, length of the command line or script, whether they are
scheduled), property names. **Names and sizes only** - no property value, no
command line, no script text. The positive runner's `--inventory` prints these
lines (`MSI ...`) under the file.

**Part 2 (2026-10-19, phageo): what the package carries is scanned**
(`msi.Contents`, `UnreadFormatHandler.expand`), each piece as a member, like a
member of an archive, every one held in memory (nothing is written to disk,
nothing is run):

- **the files of its cabinets** - embedded (`Media.Cabinet` `#name`, or a merge
  module's `MergeModule.CABinet`) or lying beside the package (when the package
  is a file of the scanned folder) - under the names it installs them as, built
  from `File`, `Component` and `Directory` (`PFiles/Fixture Game/start.bat`).
  Stored, MSZIP and LZX folders are decompressed by the scanner's own readers
  (`cab.members`: deflate through `zlib`, each block's window carried on; LZX by
  the project's own decoder, below); a **Quantum cabinet is not decoded** - the
  note `ARC-002` says "compressed with Quantum ... could not be read" and the scan
  is at least REVIEW. (Windows' `cabinet.dll` is not used here, so a normal scan
  and the memory-only runner read the same.) A cabinet beside the package is also
  scanned on its own, as a file of the folder.
- **the `Binary` streams**, named by what their custom action runs them as
  (`[Binary]/WixCA.dll`, `.exe`, `.js`, `.vbs`) or by their content;
- **the scripts of its custom actions** - written in the action (types 37 / 38),
  held in a property, or an installed file run as a script (`[custom
  action]/<action>.vbs` / `.js`) - for the VBScript and JScript tracers;
- **the command lines of its custom actions**, in the order they run, as one
  batch text `[custom action command lines].cmd` for the ordinary rules and the
  shell chain: programs started with a command line (34), a program a property
  names (50), an installed file (18), a `Binary` program (2), and what a
  deferred action is handed (`CustomActionData`: a property of the action's own
  name; WiX's `...CmdLine`). Windows Installer's `[names]` are put in where the
  package says what they are (properties, folders - its own standard folders as
  `%ProgramFiles%\` and the like -, `[#file]`, `[$component]`, `[%VAR]`);
- any other stream that is a program or an archive (`[stream]/<name>`).

**Signatures (phageo, 2026-10-19).** A package with a signature stream is checked by
Windows, as a program is (`engine_files.package_signer`; on disk, or a temporary
copy in a normal scan; never in a memory-only scan). The **files of its embedded
cabinets share that signature** when it is valid and its publisher trusted, as the
members of a signed installer do; the `Binary` streams, the scripts and the command
lines do not. A cabinet beside the package is judged by its own signature. In such
a package, a HIGH finding on a command line that **starts a file of the same
package and fetches or decodes nothing** (`msi.FETCH_OR_DECODE`: an address, a
UNC path, `-enc`, Base64, `certutil`, `bitsadmin`, web requests ...) is MEDIUM,
tagged (`package_start`), still shown - as for a chain inside a published npm file;
a chain of that text only when every line is such a start. CRITICAL is never
lowered; an unsigned package, or a line that fetches or decodes, keeps its level.

**LZX (phageo, 2026-10-19): `gamescan/unpack/lzx.py`**, standard library only, in
memory. Windows of 2^15 to 2^21 bytes; all three block kinds (verbatim, aligned
offset, stored); the trees carried from block to block; the x86 call translation
(`E8`) undone per 32 KB frame. Bounded: a frame is at most 32 KB and every symbol
writes at least one byte; tree reading walks a fixed number of lengths; at most
1 GB is decoded from one folder (`cab.MAX_LZX_OUT`; over it the limit note). Each
data block's cabinet checksum is checked (a block without a checksum is decoded
without that check). **A block that does not match its checksum is decoded and
scanned all the same - never skipped - and said once per folder** (`ARC-002`: "an
LZX data block does not match its checksum ... decoded and scanned all the same";
phageo, 2026-10-19): the bytes may not be what was packed, so the scan is at least
REVIEW, but nothing that is there goes unread. A code longer than 16 bits, an
incomplete tree, a match before the start of the data or over its frame's end, a
frame of the wrong size, or data that ends early make the cabinet "could not be
read" (`ARC-002`) - never a crash. Checked against Windows' own `makecab` (windows
2^15, 2^18, 2^21: every byte as given) and, on the clean MSI-01, against the
package's own `MsiFileHash` table (every listed file equal). makecab writes only
aligned-offset blocks; verbatim and stored blocks are tested with a stream built
by a small encoder in the tests. Speed in pure Python: about 5-8 MB/s measured
(program files about 5 MB/s).

**No Windows program reads a scanned file's cabinet (phageo, 2026-10-19).** Until
then every cabinet outside an MSI package - a `.cab` file, a cabinet inside an
archive, the cabinet behind a self-extracting program - was read on Windows by
Windows' own `cabinet.dll` (FDI, loaded into the scanner's process through
`ctypes`; its file callbacks were served from memory, and members over 32 MB went
to a temporary file like any large archive member); where it was missing, a
Quantum cabinet went to Windows' `tar.exe` or 7-Zip, through a temporary copy of
the packed cabinet when it lay inside another file. Now all of them go through
the project's own reader (`cab.members`: stored, MSZIP, LZX), and nothing else:
`cab.extract` and the `ctypes` part are gone, and a Quantum cabinet is said
(`ARC-002` "needs Quantum decompression, which the scanner does not decode") -
no program, no copy on disk. What still goes to disk is what goes there for every
archive: a member larger than 32 MB is unpacked into a temporary file of the
scan's own folder and deleted after it is scanned (never in the memory-only
runner). LZX in pure Python is slower than `cabinet.dll` was.

**No program reads a scanned file's 7z archive either (phageo, 2026-10-20).** Until
then a 7z archive the project's own reader could not decode (PPMd, Deflate64, AES,
a dictionary over 512 MB, an unusual coder chain) went to Windows' `tar.exe` (bsdtar)
or 7-Zip, through a temporary copy when it lay inside another file. Now it is said
(`ARC-002` "needs compression method ..., which the scanner does not decode") - at
least REVIEW, no program, no copy.

**No external program extracts any scanned file (phageo, 2026-10-20, seventy-third
message).** RAR compression and NSIS's bzip2 method were the last that went to
`tar.exe` / 7-Zip. Now a compressed RAR member is said (`ARC-002` "needs RAR
decompression, which the scanner does not decode"; stored members are still read
by the own reader), and so is an NSIS installer packed with bzip2 ("needs NSIS
bzip2 compression ...") - at least REVIEW (rule 15), no program, no copy on disk.
`gamescan/unpack/external.py` is gone.

What is still not read, and said (`ARC-002`, one note each): a Quantum
cabinet; an embedded cabinet that is missing or damaged; a cabinet beside the
package that is not there (or a package read from memory, whose folder cannot be
looked into); a script held in a property that is set only while installing;
storages inside the package (embedded transforms or packages); a member over
256 MB; a reached limit (4 GB unpacked, 2,000 command lines, a value over 32,768
characters). A transform or patch changes another package: what it changes is not
read (the note says so); its streams are still handed on. A damaged database is
said in the note, never a crash. Not looked at: files of the package that lie
uncompressed beside it in a source tree (they are files of the folder anyway).

## Reading the result

The top of the window (and of every HTML/PDF report) gives one sentence:

| Sentence | When |
| --- | --- |
| No clear signs of danger found | nothing above LOW |
| Probably fine: N file(s) do something unusual - worth a quick look | worst finding is MEDIUM |
| Caution: N suspicious file(s) - review before running | worst finding is HIGH |
| Do not run this game | any CRITICAL finding |

Each finding shows *what it means* and *what to do*. The advice is written per
category (13 texts) with a specific text for 36 rules where the general one
would mislead (`gamescan/advice.py`).

## Features

| Feature | Module | What it does |
| --- | --- | --- |
| Ren'Py unpacking | `unpack/rpyc.py`, `handlers/renpy.py` | `.rpyc` syntax trees are rebuilt with inert stand-ins and their Python code is scanned at its original line numbers. `.rpa` archives are opened and their script members scanned. |
| RPG Maker XP / VX / VX Ace | `unpack/rgss.py`, `handlers/rgss.py` | `.rgssad`, `.rgss2a` and `.rgss3a` archives are decrypted (documented XOR schemes). `Scripts.rxdata` / `.rvdata` / `.rvdata2` are read with a minimal Ruby Marshal reader and each script is scanned as Ruby. Other data files are scanned for "Script" event commands as strings. The report names the generation (XP, VX or VX Ace) from the file names. The protected `RGSSxxx.dll` runtime is trusted only when its SHA-256 is a known official build (`runtimes.py`); a file that merely has the name is judged like any unknown program and pointed out (`RGSS-RT-001`). |
| Archives and installers | `handlers/containers.py`, `unpack/cab.py`, `unpack/sevenzip.py`, `unpack/rar.py`, `unpack/nsis.py`, `unpack/inno.py` | A game shipped as an archive or as one installer `.exe` is read in place - the program is never run and nothing is unpacked to disk; members are scanned one at a time like files in a folder. Read with the standard library alone: **cabinets** (stored / MSZIP / LZX everywhere - LZX by the project's own decoder since 2026-10-19; Quantum is said, not read), **7z** (LZMA, LZMA2, BCJ, BCJ2, Delta, Deflate, BZip2 - also as self-extractor), **NSIS** installers (zlib / LZMA, solid or not; every file under the path the installer script writes it to, plus the script's command lines), **Inno Setup** installers (LZMA / LZMA2 / zlib / stored; every installed file under its destination name and byte-identical to the installed file - Inno Setup's rewriting of program code is undone and each file is accepted only if it has the checksum the installer stores for it; installers of an unrecognised layout fall back to a search of the unpacked data by content, without names), **RAR** 4 / 5 (file table, and members stored without compression). What the project's own readers cannot decode - RAR compression, NSIS's bzip2, Quantum, some 7z methods - goes to no program (no `tar`, no 7-Zip: cabinets since 2026-10-19, 7z and, phageo's seventy-third message, RAR and NSIS bzip2 since 2026-10-20); the report says the content was not inspected (`ARC-002`). |
| RPG Maker MV / MZ, NW.js | `handlers/rpgmaker.py`, `handlers/containers.py` | JavaScript, HTML and JSON data are scanned - also when the whole game is a zip appended to the launcher (`package.nw` inside `Game.exe`). |
| .NET metadata | `unpack/dotnet_meta.py` | Referenced types, called members, P/Invoke imports and string literals are decoded from the metadata tables. |
| .NET method bodies | `unpack/dotnet_il.py`, `dataflow/remote_cs.py` | The instructions (IL) of every method are read as data, and a download is followed to `Assembly.Load` / `Process.Start` inside one method, through the fields of one class, between methods (four hand-overs), through delegates, and one hop between two libraries (see "Compiled C#" under "Remote code execution"). |
| Unity bundles (streaming) | `unpack/unity.py`, `unpack/lz4block.py`, `handlers/dotnet.py` | `UnityFS` bundles are decompressed (LZ4 / LZMA) one block at a time and looked at through a sliding window, so a file of any size is inspected to its end with bounded memory. LZ4 is decoded by the standard library on every CPU core: pure-Python worker processes that exchange blocks through shared memory (about 4x one core when it was measured on 2026-10-04, on a Unity game that is no longer among the samples). The native `lz4` package is used instead if it happens to be installed, and is never required. Embedded Windows executables are carved out (also across window seams) and analysed; asset data is scanned as strings. Parts the bundle lists as raw texture / mesh / audio streams are carved and read in full as well - see the next row. |
| Media files and media streams | `unpack/media.py`, `handlers/media.py` | Pictures, sound and video (loose files, members of archives / installers / RPG Maker archives, and the media streams of Unity bundles) are read by structure, with no guessing about what "looks like text". **Boundaries:** PNG chunks (CRC-checked), JPEG segments, GIF blocks, Ogg pages, RIFF chunks (WAV / WebP / AVI), MP4 boxes, BMP, MP3 frames with their ID3 / APE / Lyrics3 tags, MIDI chunks and Matroska / WebM elements are walked as the format defines them; data after the media's end, or from where its structure breaks, is analysed as what it is - a program, archive or script there is `MEDIA-002` (HIGH) and is scanned as a member, anything else is `MEDIA-001` (LOW). **Metadata:** text chunks, comments and private chunks are read; compressed PNG text (`zTXt`, `iTXt`, `iCCP`) is inflated first. **Sliding window:** the whole file / stream is searched for every run of eight or more printable characters (ASCII or UTF-16, line breaks included), so a command line of any size between binary data is read; Windows programs anywhere inside are carved out. |
| Progress inside large files | `scanner.py` | Files over 64 MB report how far they are - while being read and while being unpacked / streamed - several times a second, and name the archive member being looked at; Cancel takes effect inside the file. |
| Archives and documents | `handlers/documents.py` | ZIP-family archives are opened (nested, with limits), Office macros are detected, password-protected archives are flagged. |
| Native executables | `pe.py`, `handlers/native_pe.py` | Sections, imports, packers, abnormal entry point; API names only count if they are really imported. |
| YARA signatures | `yara.py` | Built-in engine for the common YARA subset (see the module docstring), including the obfuscation modifiers `xor`, `xor(min-max)`, `base64`, `base64wide` and `base64("alphabet")`. `xor` covers all 256 single-byte keys in one pass over the data. Unsupported rules are skipped and listed, never silently passed. Starter rules: `yara_rules/game_threats.yar`. |
| Unity IL2CPP | `unpack/il2cpp.py`, `handlers/dotnet.py`, `handlers/native_pe.py` | An IL2CPP game has no managed assemblies; its code is native (`GameAssembly.dll`). What it leaves readable is `global-metadata.dat`, which is parsed (metadata versions 24 - 108 checked): all string literals, and per assembly the type names, method names and the methods implemented by a native library (P/Invoke). They go to the rules, to YARA and to AMSI. Names in the game's own assemblies and all string literals count fully; names that are merely present in the engine / .NET framework code compiled into the build are reported as LOW. `GameAssembly.dll` itself is not disassembled: its strings are carved over the whole file, API names count even when they are only strings (IL2CPP resolves P/Invoke by name), and stretches of statistically random data inside its data sections are reported (`PE-ENT-003`). |
| IL2CPP import profile | `pe.py`, `il2cpp_baseline.py`, `handlers/native_pe.py` | The import table of `GameAssembly.dll` is written by Unity's runtime, not by the game's C# code, so it is nearly the same in every game. It is compared with a baseline (212 functions from 10 libraries, the union of four real builds: Unity 2019.4, 2022.3 and two Unity 6 versions). Everything outside it is reported by what it is: functions that write into or start threads in other processes (`IAT-001`, CRITICAL), anything from `ntdll.dll` - the undocumented native API (`IAT-002`, HIGH), networking libraries such as WinInet / WinHTTP or socket functions beyond the four the runtime uses (`IAT-003`, HIGH), cryptography beyond the runtime's random-number calls (`IAT-004`, HIGH), functions that start programs or change services, registry and tokens (`IAT-005`, HIGH), and anything else that is merely unknown (`IAT-006`, LOW). |
| Engine files are verified, not just named | `handlers/engine_files.py`, `runtimes.py`, `trust.py` | **Programs and native libraries** are exempted as engine components only with a valid Authenticode signature (verified by Windows) from the component's own vendor: Unity Technologies for `UnityPlayer.dll`, the crash handler and Unity's Mono; Valve for `steam_api.dll`; Microsoft for the compiler runtime and DirectX libraries; Discord, Epic Games and GOG for their SDKs. The right name, identity and exports are not enough. A component that is built correctly but unsigned, or one whose vendor never signs it (NW.js, the Python that Ren'Py bundles, SDL, FFmpeg, ...), is scanned like any unknown program; if it has findings, `ENGINE-002` (LOW) says why they are shown. **Unsigned engines by official hash** (`engine_hashes.py`): a program or library whose SHA-256 is that of a file in an official NW.js release archive (dl.nwjs.io) or an official Ren'Py SDK (renpy.org) is treated as if its vendor had signed it - whatever it is called, so a `nw.exe` renamed to `Game.exe` counts; the right name with any other content does not. CRITICAL findings in such a file are reported unchanged; an attack chain found inside it stays visible as a LOW note; strict mode ignores the table. The table is generated by `tools/build_engine_hashes.py` and never contains a hash taken from a game. Signed by somebody else, or not even built like the component: `ENGINE-001`. `--allow-unsigned-engine-files` goes back to accepting the structure alone (a library must name itself in its export table and export what that component exports; a program without exports must import from its runtime). **Other files:** a framework assembly must be a .NET assembly with that module name (Unity does not sign these); a stock RPG Maker script must define the class it is named after, a core / library JavaScript file what that file defines; the RGSS runtime must have a known SHA-256. Signatures are verified for archive members too, and what is packed inside a validly signed file shares its signature. |
| Secure launcher | `launcher.py`, `cli.py` | `--launch <executable>`: scans the executable's folder like the benchmark does, then starts the game, asks first, or refuses - see below. |
| Large files and archive members | `unpack/spool.py`, `handlers/containers.py` | An archive member larger than 32 MB is unpacked into a temporary file (`gss-*.part`, never executable, deleted right after the member is scanned) and read from there in a stream, so there is no 32 MB / 1 GB cap any more: members up to 8 GB and 64 GB per archive are scanned with bounded memory. Free disk space is checked before and during unpacking (2 GB are always left), so a decompression bomb ends in a report, not a full disk. |
| API keys | `secrets_store.py`, `settings.py` | The VirusTotal and abuse.ch keys are encrypted with Windows DPAPI before they are written to `settings.json`: only the same Windows account on the same PC can decrypt them. A key an earlier version saved in plain text is encrypted on first load. Off Windows the file is made owner-only (0600) instead. |
| Entropy analysis | `entropy.py` | Shannon entropy plus a chi-square test over sections, overlays and long string literals. |
| Payload resolution | `dataflow/` | For calls that run code, start programs, open network addresses or delete files, the value that really reaches the call is reconstructed and shown (details below). Python and Ren'Py, JavaScript, Ruby, PowerShell, batch files. |
| Signature area | `sigblock.py` | Data inside a signed program's certificate table beyond the signature (Windows still calls the signature valid), or behind the table (Windows does not): always reported, never hidden by a signature, scanned on its own without the signature's trust. A file with data behind its signature is treated as unsigned. |
| Attack chains | `chains.py` | Several signals close together in one file become one finding (for example network + hidden payload + execution = downloader). The spyware chain tells scripts from native programs: in a script, capturing input, the clipboard or the screen next to network code is CRITICAL; in a program the import table alone is HIGH at most (see "Limits"). |
| Remote code execution | `dataflow/remote.py` (JavaScript), `dataflow/remote_py.py` (Python, Ren'Py), `dataflow/remote_rb.py` (Ruby), `dataflow/remote_sh.py` (PowerShell, batch) | `CHAIN-REMOTE-CODE`, CRITICAL: what a script executes was fetched from the network - run as code or as a command, or written to a file that is then started. Found by following the data from the request to the place it is run, not by how close two signals are, and without any obfuscation signal. `CHAIN-REMOTE-LOAD` (JavaScript), HIGH: code loaded from an address that cannot be resolved, in a file that names a remote address (details below). |
| Ren'Py engine scripts are verified | `handlers/renpy_engine.py`, `engine_hashes.py`, `unpack/rpyc.py` | Ren'Py's own updater downloads and executes by design. A download-and-execute chain in a file under `renpy/` is hidden only when the file is verifiably an official SDK script (by SHA-256, compiled scripts by content); in an unlisted Ren'Py version it is HIGH with a note, in a listed version with a changed file it is CRITICAL (details below). A changed engine file of a listed version also gets a visible LOW note (`ENGINE-003`). |
| Ren'Py's compiled Python is compared | `unpack/pyo.py`, `handlers/renpy_engine.py`, `compiled_hashes.py` | Python runs a compiled `.pyo` instead of the `.py` beside it. A compiled file under `renpy/` or `lib/` (Ren'Py 6 and 7, Python 2.7) is read as data - never unmarshalled - and compared with the official SDK's by content. One that differs is HIGH (`ENGINE-004`) when its source is the official file or missing, and a visible LOW note (`ENGINE-005`) when the developer changed the code of the source too (a change of comments alone does not count: the source is compared token by token, `unpack/pytokens.py`). An official file of another listed version is a LOW note, "leftover from" that version (`ENGINE-006`). The calls of every compiled Python 2.7 file that is not official - also a game's own modules - are rebuilt from its instructions (`unpack/pycalls.py`: an instruction table of its own, nothing run) and read by the Python rules and chains; a compiled engine file that calls a name its changed source never writes is HIGH (`ENGINE-007`); a file that cannot be walked is reported as not read (`PYO-FMT-001`). Ren'Py 8 (Python 3): exact official copies are recognised, nothing more yet (details below). |
| What `ShellExecute` opens (Ruby) | `dataflow/remote_rb.py`, `handlers/rgss.py` | A `ShellExecute` declared through `Win32API` whose every call only opens a web address or a document of the game is LOW / MEDIUM with the address shown (`RB-NATIVE-003`) instead of HIGH; a program, an unresolved target or a downloaded file keeps it HIGH or makes it a chain. Event "Script" commands in map files are read as the lines they are (`unpack/rgss.py`, `marshal_strings`). |
| Windows Defender: AMSI | `defender.py` | Content the scanner *extracted* (code from `.rpyc`, RPG Maker JavaScript, .NET metadata strings, Ruby scripts) is shown to the installed antimalware engine through AMSI. A detection is a CRITICAL finding naming the content and the source file. On by default; no administrator rights needed. A detection may also appear in Windows Security's own history. |
| Windows Defender: file scan | `defender.py` | Optional, off by default: runs `MpCmdRun.exe -Scan -ScanType 3 -File <target> -DisableRemediation` on a single scan target and merges its verdict. The flag is always passed; if Defender does not accept it the scan is reported as not performed rather than retried without it. |
| VirusTotal | `reputation.py` | SHA-256 lookups for executables after the scan (only hashes are sent). A file is treated as known-clean only if no engine flags it **and** VirusTotal has known it for at least 30 days (setting); then its LOW/MEDIUM findings are suppressed. Any detection prevents suppression. The file's age is shown. |
| Signature trust | `trust.py` | A valid Authenticode signature (checked by Windows, no network) from a publisher on the trusted list silences heuristic findings. Any other valid signature lowers heuristic findings by one severity level and names the signer. CRITICAL findings and blocklist hits are never affected; strict mode ignores signatures. The list can be changed in Settings; a scan with a list that is not the built-in one says so in the report's notes, naming what was added and left out (`scanner.publishers_changed`; phageo, 2026-10-19). |
| Known-malware database | `signatures.py` | SHA-256 blocklist in SQLite. Updates download abuse.ch MalwareBazaar's recent-samples list, which needs a free Auth-Key (Settings, `--abusech-key`). Each update is merged into the local table; at most one fetch per 5 minutes. Without a key, or if the key is rejected, the update fails with an explicit message. Any text/CSV of hashes can be imported. The EICAR test file is detected. |
| Quarantine | `quarantine.py` | Moves a file to `~/.game_safety_scanner/quarantine`, XOR-scrambled, restorable. Manual (button) or automatic for HIGH/CRITICAL (off by default). |
| Memory and learning | `memory.py`, `context.py` | Scans, snippets and your false-positive / confirmed-threat decisions are kept in a local SQLite database and adjust rule confidence (details below). |
| Reports | `export.py` | JSON (complete), HTML and PDF (current filter). A saved JSON report can be opened again. |
| Languages | `i18n.py` | English and Turkish for the interface, findings, advice and HTML/PDF reports. JSON and the CLI are English. |
| False-positive benchmark | `tools/fp_benchmark.py` | Measures false alarms over a folder of known-clean games (see below). |
| Engine hash table builder | `tools/build_engine_hashes.py` | Downloads official NW.js and Ren'Py SDK archives (from `dl.nwjs.io` and `www.renpy.org` only), checks each against the SHA-256 its publisher lists where there is such a list, hashes the programs and libraries inside without unpacking them to disk or running anything, and writes `gamescan/engine_hashes.py` with the version and source URL of every entry. `--archives FOLDER` keeps the downloads (outside the project); `--offline` rebuilds from them. |

Settings are in the GUI under **Settings** and stored in
`~/.game_safety_scanner/settings.json` (API keys are encrypted, see "API keys").

## Secure launcher

`python -m gamescan --launch "C:\Games\Some Game\Game.exe" -- -windowed`

1. The folder the executable is in is scanned, sub-folders included, with the
   same scanner the false-positive benchmark uses (`scanner.neutral_scanner`),
   so the launcher judges a game the way the benchmark measures it. Nothing of
   your profile can hide a finding: no memory center, no allowlist, the
   built-in list of trusted publishers; nothing is quarantined and nothing is
   looked up on the network. Three things can only add findings and are used:
   the known-malware hash list if you downloaded it before, your YARA rules,
   and the Windows antimalware engine (AMSI).
2. Temporary files are used as in an ordinary scan (large archive members,
   the signature check of a program inside an archive), but in a folder made
   for this one scan (`gss-...`, for the current user), under names that
   cannot be run (`gss-*.part`); each is deleted after use and the folder is
   removed when the scan ends, also when it ends with an error. (Until
   2026-10-20 an archive inside another file that only 7-Zip or bsdtar could
   read got a copy with its own extension for that program; since then no
   program reads a scanned file, so there is no such copy.)
3. What happens then depends on the result:

   | Result of the scan | What the launcher does |
   | --- | --- |
   | CLEAN, LIKELY SAFE | starts the game |
   | REVIEW (MEDIUM findings) | shows the findings and asks once; `y` starts it |
   | a part could not be inspected (`ARC-002` and the other "could not be read" notes, a scan error) | says so and asks once - whatever the verdict |
   | SUSPICIOUS (HIGH findings) | shows the two or three main reasons in plain words; the word `launch` has to be typed (`başlat` works too, and `baslat` without the Turkish letter) |
   | any CRITICAL finding (every DANGEROUS game); an attack chain of HIGH severity in a script (one exception, below); a known-malware hash; a detection by Windows' own engine (`AMSI-001`, `DEFENDER-001`); a program posing as an engine component (`ENGINE-001` on a program, MEDIUM) | refuses, without asking |

   An attack chain inside a *program* rests on its import table - on what the
   program can do, not on a call that was seen; some games install a keyboard
   hook only to switch off the Windows key. It is asked about (SUSPICIOUS),
   not refused. In a script the calls themselves are seen, so a chain there
   is refused. `ENGINE-001` on a *script* is a LOW note - a game that rewrote
   one of the engine's default scripts; the script is scanned like any other
   file, and the launcher goes by the verdict.

   One chain in a script is asked about instead of refused: a
   download-and-run chain in an engine file of a Ren'Py version whose official
   files are not in the scanner's table (HIGH, see "Ren'Py's own scripts").
   The official updater has that chain, so refusing it would refuse every
   game on such a version. The word has to be typed, and the prompt says
   first, in its own words, that a download-and-run chain was found in an
   engine file that could not be verified. The same chain in a changed file
   of a listed version, or outside the engine's folders, is CRITICAL and
   refused.
4. Every answer defaults to "no". When nobody is there to answer (the input
   is not an interactive terminal) the game is not started. There is no option
   that answers for you. The questions are English or Turkish, following the
   app's language setting.
5. Before the start the executable is hashed again - it must be the file that
   was scanned - and started with `subprocess.Popen` (no shell), in its own
   folder, with the arguments after `--`.

Exit codes: 0 started; not started: 1 (MEDIUM findings), 2 (HIGH / CRITICAL
findings, or a finding that always blocks), 3 (only a part that could not be
inspected, scan cancelled, file changed, could not be started).

It is a gate, not a sandbox: the game is not watched once it runs, and a data
file replaced between the scan and the moment the game reads it is not
noticed. A game on an engine that nobody signs (RPG Maker MV / MZ on NW.js,
Ren'Py) gets HIGH findings when its engine build is not in the official hash
table, and is then asked about, unless `--allow-unsigned-engine-files` is
given - see "Limits".

## Payload resolution

Scripts rarely write `os.system("powershell ...")` in one piece. They build
the text from fragments, decode it, or look the function up by an assembled
name. `gamescan/dataflow/` undoes that without running anything and reports
the result as its own findings:

| Finding | Meaning |
| --- | --- |
| `DF-EXEC-001` | The code given to `exec` / `eval` / `Invoke-Expression`, decoded. The decoded code is then analysed like a file of its own (up to 3 layers) and scanned with the ordinary rules and AMSI. |
| `DF-CMD-001` | The command line a process-launch call receives. |
| `DF-URL-001` | The address a network call receives. |
| `DF-PATH-001` | The file a delete call receives, or a write whose target is a program or a system / profile location. |
| `DF-CALL-001` | The function or module a built-up name resolves to (`getattr(os, 'sys' + 'tem')`). In JavaScript a call written as `obj["name"](...)` with one plain string is an ordinary call (minifiers and Emscripten write every call that way) and is not reported - unless the name is a risky one (`eval`, `Function`, `child_process` ...), which is reported on any object, and however the name is put together. |

The evidence names the call, the resolved value and the variables it came
from (`os.system receives: powershell -w hidden  [k <- line 2]  [decoded]`).
Parts that only exist at runtime (user input, files, function parameters with
no visible caller) are shown as `‹name›`; they are never guessed.

How it works:

- **Python and Ren'Py** (`pyflow.py`): the source is parsed with `ast` and
  modelled by an abstract interpreter: assignments, string operations,
  `%` / `.format` / f-strings, loops over known data, comprehensions,
  functions called with the arguments of their call sites, `self.x`
  attributes, and the usual decoders (base64, hex, zlib, bz2, lzma, rot13,
  `chr`/XOR). Python 2 `print` / `exec` statements are repaired before
  parsing; in `.rpy` files the `python:` blocks, `$` lines and `define` /
  `default` statements are read.
- **JavaScript, Ruby, PowerShell** (`textflow.py`): there is no parser for
  these in the standard library, so the resolver starts at each sensitive
  call, reads the argument as an expression and traces every variable in it
  backwards to its assignment. It understands string literals and
  concatenation, template strings, `atob`, `String.fromCharCode`,
  `split/reverse/join`, `Buffer.from`, `unpack('m')`, `pack('c*')`,
  `Base64.decode64`, `[char]` casts and `FromBase64String`.
- **PowerShell `-EncodedCommand`** is decoded wherever a command contains it;
  **batch** `%variables%` are filled in from the file's own `set` lines.

A finding is only raised when resolution added something: a plain literal at
the call is left to the ordinary rules, and `eval("config." + name)`-style
game code is not reported.

Not covered by this payload resolution: VBScript and C# (each has a
download-and-run chain of its own, see below), compiled code, values that
come from another
file, object fields in JavaScript (`this.url`), and control flow that depends
on runtime data (both branches are followed; the result may be one of
several possibilities). JavaScript, Ruby and PowerShell scoping is
approximated by brace depth, so a resolved value there is a strong hint, not
a proof.

### Remote code execution (`CHAIN-REMOTE-CODE`)

For JavaScript, `dataflow/remote.py` follows what a network request returns
to the place where it is executed. The attack chains above need their signals
within 60 lines of each other, which says nothing in a minified file (one
line), and the downloader chain needs an obfuscation signal that a plain
downloader does not have.

- **Requests:** `XMLHttpRequest`, `fetch`, Node's `http` / `https`,
  `request`, `axios`, `got`, jQuery, `WebSocket`.
- **Followed through:** variables, object fields (`this.code`), callbacks,
  promise chains, `await`, `return` values, `new Promise`, arrays, `Blob` and
  object URLs.
- **Executed as:** `eval`, `new Function`, `vm`, the text of a script
  element, `import()`, `importScripts`, a `Worker`, `WebAssembly`, a
  `child_process` command, or a file that is written to disk
  (`fs.writeFile`, `createWriteStream`) and then started or `require`d - the
  dropper.
- **The address is the code:** a script element, `import()`,
  `importScripts`, a `Worker` or `$.getScript` with a remote address is
  reported without any request in between.

What decides is the address. Remote (`http://`, `https://`, `//host`) or
decoded: reported. Not resolvable: reported, because a downloader whose
address cannot be read is no better than one that shows it. A file of the
game itself (`"data/Map001.json"`, `"js/plugins/" + name`, `__dirname + ...`,
or a parameter for which every caller in the file passes such a file): not a
download, nothing is reported. The finding is CRITICAL, so no baseline - not
even the engine / library folder - silences it.

Two stated exceptions, both there to keep genuine libraries quiet:
`WebAssembly` is CRITICAL only for a remote or decoded address (every
Emscripten-built library loads the `.wasm` file next to it through an address
it is handed at runtime), and a script element, `import()` or `Worker` is
CRITICAL for a remote or decoded address, not for one that merely cannot be
resolved (`function loadScript(url)` is everywhere).

The middle ground for these four is `CHAIN-REMOTE-LOAD`, HIGH: the address
cannot be resolved **and** the same file names a remote http(s) address in
its code - not in a comment, and not an XML namespace or `localhost`. That
is what hiding the address behind a function parameter looks like
(`list.forEach(loadScript)`, `loader.load("https://...")`). A helper that is
called directly with a remote address is followed to its caller and is the
CRITICAL finding. Although it is HIGH, a baseline that rests on folder and
name - the bundled libraries in `js/libs/`, the core scripts - does not
silence it, because a repack can imitate both; a valid trusted signature or
the hash of an official build still covers it.

#### Python and Ren'Py, Ruby, PowerShell and batch files

Since 2026-10-06 the same question is asked in four more languages. The
finding is the same (`CHAIN-REMOTE-CODE`, CRITICAL), the address rule is the
same (remote, decoded or not resolvable counts; this PC - `localhost`, a
`file:` address - does not), and no obfuscation is needed. Before, a plain
`exec(urlopen(address).read())` was MEDIUM, and the best a Ruby or
PowerShell downloader got was HIGH.

| Language | Module | Requests | Executed as |
| --- | --- | --- | --- |
| Python, Ren'Py (`.py`, `.rpy`, `.rpyc`) | `dataflow/remote_py.py` | `urllib` / `urllib2`, `requests` (also through a session), `http.client` / `httplib`, a `socket`, `ftplib`, `renpy.fetch` | `exec`, `eval`, `compile` (also `future.utils.exec_` / `six.exec_`), `marshal.loads` / `pickle.loads` (both rebuild code objects), a command (`os.system`, `subprocess`, ...), native code through `ctypes`; or written to a file that is then started, imported or executed |
| Ruby (RPG Maker XP / VX / VX Ace scripts and event scripts) | `dataflow/remote_rb.py` | `URLDownloadToFile` and the WinINet functions through `Win32API`, `open-uri`, `Net::HTTP`, `TCPSocket` | `eval` and its relatives, `system` / `exec` / `spawn` / backticks; or the downloaded file is started with `WinExec`, `ShellExecute`, `CreateProcess` or loaded with `load` / `require` |
| PowerShell, batch (`.ps1`, `.psm1`, `.bat`, `.cmd`) | `dataflow/remote_sh.py` | `DownloadString` / `DownloadData` / `DownloadFile`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer`, `bitsadmin`, `certutil -urlcache`, `curl`, `wget` | `Invoke-Expression` / `iex`, a script block or assembly built from the download, another interpreter it is piped into; or the downloaded file is started (`Start-Process`, `start`, `call`, `&`, the file name as a command, `rundll32`, ...); `mshta`, `msiexec /i`, `regsvr32` with a remote address |

- Python is read with `ast` (never run): names are followed per function, a
  value counts from the line that assigns it, and the response is followed
  through function arguments and return values. The whole downloader may be
  packed (`exec(base64.b64decode(...))`): the decoded code is analysed too.
  A function of the script that saves a download to the path it is given
  (`def urlretrieve(url, fn)` around `requests.get`) is followed to the file
  the caller named - this is how Ren'Py 7.4 to 8.3 write their updater. A
  log file that downloaded text is written to and that a started program
  gets as its output (`stdout=log`) is not "a downloaded file that is
  started".
- Since 2026-10-10 the download is also followed, inside one file, through
  objects and through functions that are handed on as values. Objects: a
  name made from a class of the file is an object of that class - its
  methods are that class's (or its base class's in the file), `Class(data)`
  hands `data` to `__init__`, and a field (`self.x`, `obj.x`) belongs to
  the class and the classes related to it in the file, no longer to every
  class at once. Functions: one given to a parameter, a name, a field or a
  table and called there, a `lambda`, `functools.partial` / `renpy.curry`,
  and what starts a function in a thread - `threading.Thread(target=f,
  args=...)`, `Timer`, `start_new_thread`, `renpy.invoke_in_thread`;
  `start()` on a class of the file that has a `run` method is `run()`.
  Limits: a function is followed through four hand-overs, 200 classes and
  2,000 fields per file (beyond them the tracer falls back to what it did
  before), besides the step and time limits. A pool of threads or processes
  counts too (`concurrent.futures` executors, `multiprocessing` pools:
  `submit`, `map`, `apply_async` ...; what a submitted function returns is
  what `.result()` gives). Not followed: a queue between threads.
- Since 2026-10-10 also **across two files**: one script stores a download
  under a name the scripts share, another runs what that name holds. Shared
  names are those of Ren'Py's store - a top-level name of a `.rpy` / `.rpyc`
  script, `store.x` / `renpy.store.x` anywhere, also what a top-level
  function of a script returns - and the top-level names and functions of a
  `.py` file that another file imports (`import net` ... `net.payload`,
  `from net import get`). Every script leaves a short summary while it is
  scanned - loose, compiled or inside an `.rpa` archive -, and one pass
  after the folder scan joins them (`dataflow/shared.py`). The finding is
  the same `CHAIN-REMOTE-CODE`, reported on the file that runs; its
  evidence names both files by their path inside the game and ends with
  `[across two files]`. It is judged like the chain inside one file: hidden
  only when *every* file in it is verifiably an official engine script,
  HIGH when the files are engine files of a Ren'Py version that cannot be
  compared, CRITICAL otherwise. A name the running file computes itself at
  its top level is its own, whatever another file stores under it; one it
  only declares (`default payload = None`) is not. Limits: one hop (A
  fills, B runs - not A to B to C), 64 shared names per file, 2,000
  scripts, 200 chains and one second for the join (a limit that cuts the
  join short is said in the report's notes), 400,000 steps for the second
  reading of each file. Since the closing step of 2026-10-10:
  - **A field of Ren'Py's `persistent`** is a shared name like a name of
    the store (`persistent.x`, also written `store.persistent.x`,
    `renpy.store.persistent.x`, `renpy.game.persistent.x`, or imported into
    a `.py` file from the store). A plain `persistent` in a `.py` file that
    does not import it from the store is that file's own.
  - **The dropper across two files:** one script writes a download to a
    file, another starts that file - a command, `os.startfile`, `execfile`,
    `runpy.run_path`, `imp.load_source`, `__import__` /
    `importlib.import_module` by name, a library loaded through `ctypes`.
    The two are tied the way the dropper inside one file is: by the file's
    name where both scripts write it out (`update.exe`, also inside a
    longer path or a command line), or by a shared name that holds the path
    (`target`, `persistent.tool`). The evidence then reads `-> file
    update.exe ->` or `-> path in shared name store.target ->` and gives the
    path as the first script wrote it. One hop, judged like every other
    chain across files.
  - **A downloaded module that another script imports:** one script writes
    a download to `<folder>/<name>.py` (`.pyc`, `.pyo` - the compiled form
    Ren'Py 6 and 7 load -, `.pyd`, or the package
    `<name>/__init__.py`), another has a plain `import <name>` / `from
    <name> import ...` (also Ren'Py's `$ import`). `<folder>` has to be the
    game's folder or one Python looks into from there: the folder itself,
    `game/`, `python-packages`, the bundled Python's folders under `lib/`;
    a module in a sub-folder is matched by its dotted name (`mods/extra.py`
    by `import mods.extra`). A folder that cannot be read from the script
    counts; the temporary folder, the user's folder, the save folder or a
    full path elsewhere do not. Evidence: `-> module extra -> import extra
    (line 1)`. Every script says what it imports (read from its text, line
    by line; 256 names per script, 20,000 module names per scan, 8 chains
    per module - the report's notes say when there were more). One hop.
  - **A second reading that is cut short is said:** when the second
    reading of a script reaches its limit of 400,000 steps, the file gets
    the visible LOW note `PY-JOIN-001`, "script not read to its end for
    chains across files". The limit is counted in steps, not in time, so
    the same file gets the same answer on every PC and in every scan; a
    clock stands behind it as a far safety cap (ten minutes since
    2026-10-13; five seconds before), and the note is made when that one
    stops the reading too. It is one of the
    "could not be read" notes: never hidden by a folder, a signature or a
    hash, and the secure launcher asks once. A verified official engine
    script gets no note - what those do is known.

  Not followed across files: a function of another file that runs what it
  is handed, a class of another file, a scan of several folders at once, a
  path that is put together from the running file's own names only, an
  import that runs over several lines or is made by other means than the
  `import` statement and `__import__` / `import_module` with the name
  written out, a module whose file name is put together when the script
  runs, a folder added to Python's search path by the script itself.
  **Known weak point of the join:** a name the running file assigns itself
  at its top level counts as its own - also when the assignment stands
  under a condition (`if not ready: payload = ""`). A script that runs a
  shared name and also gives it some value itself, anywhere at its top
  level, is therefore not tied to the file that downloads into that name.
  Deliberate (otherwise two scripts that both use a name like `data` would
  be a CRITICAL false alarm), and silent.
- Compiled Ren'Py scripts: Ren'Py 8.4 and later store the block of an
  `init python:` as it stood in the file, indented. The block is moved to
  the left margin before it is analysed (`unpack/rpyc.py`, `decompile(...,
  unindent=True)`); before 2026-10-06 the Python analysis saw nothing of
  such a block (the pattern rules did).
- Ruby and the shell languages are read line by line. A batch file's
  `powershell -Command "..."` is read as PowerShell, and `-EncodedCommand` is
  decoded first.
- A command line that a Python, Ren'Py, Ruby or JavaScript script starts is
  PowerShell or batch itself: `os.system("powershell -c ...")` and
  `subprocess` with an argument list; Ruby's `system`, backticks, `%x{...}`,
  `IO.popen` and `Open3`; and, since 2026-10-08, JavaScript's
  `child_process` functions `exec`, `execSync`, `spawn`, `execFile` and
  `fork`, with the command as one string or as a program and an argument
  list, with or without `shell: true`. The command lines the payload
  resolver worked out - also those put together from parts - are read by
  the shell chain, together and in their order, so a download in one command
  and the start of the file in a later one is found
  (`remote_sh.analyse_commands`); the evidence ends with `[in a command line
  this script starts]`. An address that cannot be read counts, as everywhere
  in this chain; a command that cannot be read at all is nothing the chain
  can judge. Not covered: a `child_process` module reached through a name
  the resolver cannot follow (an object field, another file), a Ruby
  heredoc, a `%x` literal that runs over several lines.
- Not a chain: a download that is only displayed or saved, running a script
  of the game itself, a request to this PC.
- **An installer's own script** (the `[installer script]` of an NSIS or
  Inno Setup installer) is a list of the installer's texts, not a batch
  file; the batch chain does not read it (the ordinary rules do). What an
  **NSIS** installer downloads and then starts is read from its
  instructions instead (since 2026-10-11; `unpack/nsis.py`,
  `dataflow/remote_nsis.py`, `redist.py`):
  - a download is a call into a download plug-in (`NSISdl`, `inetc`,
    `NScurl` ...) or a `System::Call` of a Windows download function; a
    start is `Exec` / `ExecWait` / `ExecShell`, a plug-in that starts
    programs (`nsExec` ...), `RegDLL` or a call into a library. They are
    tied when the file the download is saved to is named in what is
    started. The command lines the installer starts are also read like the
    lines of one batch file (PowerShell, certutil, bitsadmin, curl).
  - **Starting a file of the package is no chain** - that file is scanned
    itself. A download that is only saved is no chain either.
  - **A download over https from the hand-kept list of official
    redistributable addresses** is a visible LOW note, `INST-REDIST-001`,
    which nothing hides (not a signature, not a folder). The list
    (`gamescan/redist.py`) is a constant of the code - exact host and the
    beginning of the path, each entry with the vendor page it was read
    from; no scanned file can add to it: `aka.ms/vc14/` (the link on
    Microsoft's page today), `aka.ms/vs/` (the older Microsoft link, no
    longer on that page; kept), `download.microsoft.com/download/`,
    `builds.dotnet.microsoft.com/dotnet/`, `www.openal.org/downloads/`.
    `go.microsoft.com/fwlink` counts with exact link numbers only, and no
    number is listed yet. An address with a part that is filled in when the
    installer runs (`$x`, `{code:...}`) is never a listed one.
  - **Every other download that is started is `CHAIN-REMOTE-CODE`,
    CRITICAL**: another address, `http`, the right host with another path,
    a look-alike host, an address that is only known when the installer
    runs.
  - Not read (NSIS): an installer packed with bzip2 (since 2026-10-20 no
    program unpacks it: `ARC-002`);
    what a plug-in or the registry puts into a variable; a download whose
    target file the script does not write out; instruction numbers of NSIS
    builds that differ from NSIS 2 / 3; the reader's limits are silent.
    Tested on constructed installers (by hand and from the NSIS 3.13
    compiler); no benchmark sample downloads anything.
- **Inno Setup installers: `[Code]` and `[Run]`** (since 2026-10-11, the
  same policy; `unpack/ifps.py`, `unpack/inno.py`, `dataflow/remote_inno.py`):
  - The compiled `[Code]` (Pascal Script, the text in the setup script that
    starts with `IFPS`) is read as data: types, procedures, variables and
    the instructions of every procedure, with `struct` only. Nothing is
    compiled, interpreted or run. Limits: 16 MB, 50,000 types / procedures,
    2,000,000 instructions, 4,096 characters per text.
  - A download is `DownloadTemporaryFile`, the `Add` of a download page, a
    function of a download plug-in (`idpAddFile`, `ITD_...`, `isxdl_...`)
    or a Windows download function the script imports. A start is `Exec` /
    `ShellExec` and their relatives, a `[Run]` or `[UninstallRun]` row, an
    imported `ShellExecute` / `CreateProcess`, or a library the script
    calls into. They are tied by the file: the path the download is saved
    to, the place a `[Files]` row copies it to, or its file name behind a
    folder nobody can read. The command lines also go to the batch chain.
  - The results are the same three: a packaged file started - nothing; a
    listed https address - `INST-REDIST-001`; anything else -
    `CHAIN-REMOTE-CODE`, CRITICAL.
  - **The `[Run]` rows are read whether or not there is `[Code]`** (since
    the follow-up of 2026-10-11): their place comes from the entry counts of
    the setup header. A row that downloads and starts something in its
    command line (`powershell -Command "Invoke-WebRequest ...; Start-Process
    ..."`, `certutil` and a start), or one row that downloads and a later
    one that starts, is `CHAIN-REMOTE-CODE`.
  - **`INNO-CODE-001`** (LOW, never hidden, the launcher asks once): the
    `[Code]` could not be read to its end (damaged, over a limit, an
    instruction the reader does not know), or the `[Run]` rows were not
    found. (Not when the file table itself was not read: `ARC-002` says that
    already.)
  - **A download word or the name of a system tool that is only the name of
    an installed file** (a line of the script texts that is, as a whole, the
    destination of a `[Files]` row - `{app}\Examples\DownloadFiles.iss`,
    `{app}\Examples\PowerShell.iss`) is a LOW note, "file name, not an
    instruction" (`SH-DL-001`, and since the second follow-up of 2026-10-11
    `LOL-001`), and a chain that exists only because of it is LOW too. The
    same word in a command line, or on a line that holds more than the file
    name, keeps its level. Only when the `[Code]` (if there is one) was read to its
    end, the `[Run]` rows were read, and the code names nothing that
    downloads (no download function, no network library, no download word
    in its texts) - never when either could not be read. A chain that would
    be CRITICAL is not lowered. **The same for an NSIS installer** (since
    2026-10-17, fifty-ninth message; `nsis.installed_texts`,
    `remote_nsis.Found.downloads`): its instructions read to their end,
    nothing in them downloads (no download plug-in, no Windows download
    function, no download word in their texts), and the line is - as the
    script's text cuts it, between two variables - the name a `File`
    instruction writes (`$INSTDIR\dotnet\...\System.Net.WebClient.dll`).
    (Since the same day `DownloadFiles.iss` names no download function at
    all: API and tool names are whole words - "Rules: API and tool names".)
  - **Inno Setup's own parts** (since the third follow-up of 2026-10-11;
    `gamescan/inno_official.py`, generated by `tools/build_inno_tables.py`
    from the official installers of Inno Setup 5.5.9, 5.6.1, 6.0.5, 6.2.2,
    6.4.3 and 6.7.3 themselves - kept in the folder of official archives
    with a note of their sources, read in memory with the scanner's own
    reader and never run; an installer whose SHA-256 is not the recorded
    one is refused; nothing comes from a scanned file):
    - *its files*: every file of those distributions (380) - the setup
      engine and its loaders (`Setup.e32`, `SetupCustomStyle.e32`,
      `SetupLdr.e32`, `SetupLdr.e64`), which every installer carries, and
      the compiler itself (`Compil32.exe`, `ISCC.exe`, its libraries such
      as `isunzlib.dll`), its language files, examples and help. The table
      holds all 380 on purpose - it *is* the official distribution (decided
      by phageo, 2026-10-11) -, and the scanner consults it for programs only.
      A file is shown with every version that holds it: `Setup.e32 - Inno
      Setup 6.7.3`, `isunzlib.dll - Inno Setup 6.2.2-6.7.3`.
      A program with the SHA-256 of one of them is an "official engine
      build, verified by SHA-256", under the same rules as the NW.js and
      Ren'Py tables: one changed byte and it is judged like any unknown
      program; a chain inside it is shown as a LOW note; CRITICAL is always
      shown; strict mode ignores the table.
    - *its standard messages*: the name of a system tool (`LOL-001`) on a
      line that is exactly a standard message - `RegSvr32 failed with exit
      code %1` and its translations, the `[Messages]` texts of `Default.isl`
      and every bundled language file - is a LOW note, "standard installer
      message", and forms no chain. Decided on where the text stands in the
      setup script: every place of it must be inside a stored message
      (they lie one behind the other, each ended by a zero) that is, as a
      whole, a standard one. A custom message (`[CustomMessages]`), a `[Run]`
      row or a file name - texts with their length in front -, a text in the
      compiled `[Code]`, and a text in single bytes are never covered, also
      when they say exactly the same.
    - Not covered: the outer program of an installer (the loader with the
      installer's own icon and data - it matches no hash), other versions
      than the six, messages of languages that are not bundled with the
      compiler. The 6.x installers' SHA-256 are the ones GitHub shows for
      the releases; for the two 5.x installers nothing is published - theirs
      is the value of the first download (HTTPS and a valid signature).
  - **NSIS's own parts** (since 2026-10-12, phageo; `gamescan/nsis_official.py`,
    generated by `tools/build_nsis_tables.py` from the official
    `nsis-3.13.zip` of the NSIS project's download place on SourceForge -
    kept in the folder of official archives, fetched through
    `tools/fetch.py`, read in memory and never unpacked or run; a zip whose
    SHA-256 is not the listed one is refused; nothing comes from a scanned
    file). The table holds every file of that distribution (436; empty
    files left out): the compiler and its window (`makensis.exe`,
    `makensisw.exe`), the installer stubs every NSIS installer is built on
    (`Stubs/lzma-x86-unicode` ... - programs without a file ending), the
    plug-in libraries an installer unpacks while it runs
    (`Plugins/x86-unicode/System.dll`, `nsDialogs.dll` ...), small tools
    (`Bin/RegTool-x86.bin`), and its scripts, headers and texts. As for
    Inno Setup the scanner consults it for programs only: a program with
    such a SHA-256 is an "official engine build, verified by SHA-256"
    (`Stubs/lzma-x86-unicode - NSIS 3.13`) - one changed byte and it is
    judged like any unknown program; a chain inside it is a LOW note;
    CRITICAL is always shown; strict mode ignores the table; a script or
    text of the table gets nothing from it.
    - Not covered: the outer program of an installer (its stub with the
      installer's own data matches no hash) - also the setup program of
      NSIS itself, which is not a file of the zip; every NSIS version but
      3.13. NSIS publishes no SHA-256: the zip's value is the one pinned
      when the test compiler was first downloaded, and the download of
      2026-10-12 had it again.
  - How it reads: each procedure once, top to bottom, with the script
    machine's stack as a list of texts; a procedure of the script is read
    again at each call with what it is handed (three levels); variables of
    the script keep the text they were given last. Limit: 1,000,000
    instructions per reading (two readings); the clock is a far safety
    cap (ten minutes).
  - Not read / weak points: jumps are not followed (both arms of an `if`
    count); what Inno Setup's own functions return, except the few that
    hand a text on (`ExpandConstant`, `AddBackslash` ...); records, arrays
    and objects; a download through a COM object (`WinHttpRequest`) - it
    blocks the lowering but makes no chain; a downloaded archive that is
    unpacked and a file from it started; `[Icons]` and `[Registry]` rows;
    installers the file table of which cannot be read get nothing of this.
    (An installer with one single file is read like any other
    since 2026-10-11: before, its file was named `unnamed`, and with Inno
    Setup 6.7 it was not unpacked at all.)
  - Versions: the rows are found by their shape and the numbers in the
    setup header. Checked on installers written by the official compilers
    5.5.9, 5.6.1, 6.0.5, 6.2.2, 6.4.3 and 6.7.3 (Unicode editions; file
    table, `[Code]`, rows and the chain - all read fully) and on INS-01.
    Not seen: the non-Unicode editions of Inno Setup 5, versions before
    5.5. (INS-03, a store's installer, says 5.6.2 and is read like the
    others since 2026-10-11.)
  - **Where the setup header is** (since 2026-10-11): the place the
    loader's own table names (`inno.header`, `LOADER_TABLE`), as Inno Setup
    itself finds it - never the first place where the header's text stands.
    That text can stand in the data more than once: INS-03 holds it twice
    (once inside its packed files), an installer that carries another
    installer holds a whole second header. Without a readable table (a very
    old or damaged installer) the places of the text are looked at: one
    place, with a setup script behind it, is taken; two or more, and
    nothing says which one the installer uses - none is taken, and an
    `ARC-002` note ("... stands more than once ... the installer was not
    read") says so, never hidden (since 2026-10-11; before, the first one
    was believed, also a decoy). Only the table form of the compilers
    5.5.9 to 6.7.3 is known.
  - **Where an NSIS installer's first header is** (since 2026-10-11): where
    NSIS itself finds it (`nsis.first_header`) - NSIS reads its own file
    from the start in 512-byte steps and takes the first step at which a
    first header stands. So a header inside the program itself is the one
    that is read (an `ARC-002` note then says that the data behind the
    program was not read as an installer of its own), and behind the
    program the first header on a step, not the first mark found. A header
    on no step is nothing NSIS would run; it is still read when there is
    no other. The search ends one megabyte behind the program; NSIS's own
    has no end - a first header further back is not read, and an `ARC-002`
    note says so ("... stands N MB behind the program ... was not read").

**Ren'Py's own scripts.** The updater that ships with Ren'Py (`renpy/common/
00updater.rpy`) really does execute code that it downloaded - a signed update
list may carry a patch. It must not make every Ren'Py game DANGEROUS, and its
folder must not be an excuse either, because a repack can put anything into
`renpy/`. So a chain found in a file under `renpy/` or `lib/python*/` is
judged by what the file *is* (`handlers/renpy_engine.py`):

| The file | The chain is |
| --- | --- |
| is an official engine script: its SHA-256 is in the table built from the Ren'Py SDKs, or - a compiled script - it contains exactly what the official one contains | kept among the suppressed findings, with the reason |
| is in a Ren'Py whose version is in the table, and is not that version's file | CRITICAL - no trust at all |
| is in a Ren'Py whose version is not in the table | HIGH, with the note "the engine file could not be verified" |
| is not under the engine's folders | CRITICAL, always |

A compiled script (`.rpyc`) is never the same file twice - it carries the
folder of the PC that compiled it - so it is compared by content: its code at
its line numbers and the set of its other strings, without that folder
(`unpack/rpyc.py`, `content_key`). The version is read from the engine's own
`vc_version.py` / `__init__.py`.

A file under the engine's folders that is not the official file of a listed
version also gets a visible LOW note, `ENGINE-003`: "this engine file differs
from the official version X". Games do change engine files for harmless
reasons (RPY-01 changed one, RPY-02 two), so it is a note and nothing more:
the file's ordinary findings keep the folder's trust, and only the chain
above loses it. The folder baseline does not hide the note.

#### Ruby objects (inside one script and across the scripts of a game)

Since 2026-10-12 the Ruby tracer (`dataflow/remote_rb.py`) follows a
download through objects, as the Python tracer does:

- **Fields per class:** `@x` set in one method and used in another method
  of the same class. The same name in another class is another field
  (before, `@x` was one name for the whole script).
- **`attr_accessor` / `attr_reader` / `attr_writer` fields:** `obj.code =
  <download>` and `obj.code` read elsewhere, or `@code` set inside the class
  and read from outside; a setter written out (`def code=(text)`) is handed
  the value.
- **Methods called on objects:** what `obj.fetch` gives back (`return x`,
  or the method's last statement), and what `obj.run(x)` hands to the
  method's parameters. Which class an object is, is not known: `obj.name`
  stands for every class of the script that has such a method or field (at
  most four); `Owner.name` for that class only. When a download goes that
  way and the script has more than four such classes, the classes behind
  the fourth are not followed and the note `SCRIPT-LIMIT-001` says so
  ("more than 4 classes for one obj.name"; phageo, 2026-10-12 - before, it
  stopped silently). Without a download nothing is noted.
- **`Class.new(x)`** hands `x` to that class's `initialize`.
- **Blocks, procs and lambdas:** a block kept in a name (`lambda { |c| }`,
  `proc`, `Proc.new`, `->(c) { }`) and called (`.call`, `.()`, `[]`); one
  handed to a method that calls it; `yield x` and `block.call(x)` into the
  caller's block.
- **Across scripts** (the join of the next section): a field of a class
  another script reopens (`Owner.@x`); a field or a method reached through
  an object (`obj.name` - by the name alone); `Owner.new(x)` and `obj.m(x)`
  into a class another script defines.
- **Limits:** a value is followed over four readings of the script (about
  four hand-overs); 20,000 methods, 2,000 fields, 2,000 classes and 2,000
  kept blocks per script - beyond them the note `SCRIPT-LIMIT-001` is made.
  A method ends at its own `end` (by its indentation); before, it ran on to
  the next `def`.
- **Not followed:** which object a variable holds (two objects of one
  class are one); class variables (`@@x`) beyond their name; `send` /
  `method(:name)`; `define_method`; a method reached through inheritance
  or a mixed-in module (`include`); a block with more than one parameter
  beyond its first.
- **Checked on:** constructed scripts only - eighteen shapes with harmless
  twins, among them a Scene / Game pair as an RPG Maker game would have it.
  The Ruby samples name no network word, so the tracer does not run on
  them.

#### Ruby and shell scripts across files (one hop)

Since 2026-10-12 the join that finds a download in one Python script and
its start in another (`dataflow/shared.py`, `Scanner._join_shared`) also
joins Ruby scripts and shell scripts. Each script leaves a short summary
while it is scanned; after the whole folder was scanned the summaries are
put together - one hop (A fills, B runs; never A to B to C). The finding
is the same `CHAIN-REMOTE-CODE`, CRITICAL, made for the script that runs,
with both files in its evidence and the mark "[across two files]".

**Ruby** (`remote_rb.shared`): the sections of `Scripts.rxdata` /
`.rvdata` / `.rvdata2` and the loose `.rb` files of a game are one program.

- Shared names: a `$global`; a constant (`NAME`, `Module::NAME`); what a
  method gives back - a method at the top of a script, or of a class or
  module that any script can reopen (`Owner.name()`: called as
  `Owner.name` / `Owner::name`, or by its bare name inside that class in
  another script); and a file one script writes a download to and another
  starts.
- Run: everything the Ruby tracer knows - `eval` and its relatives,
  `system` / `exec` / `spawn`, backticks and `%x`, `IO.popen`, `Open3`,
  `WinExec` / `ShellExecute` / `CreateProcess` through `Win32API`, `load` /
  `require` of a written file.
- A name the running script sets itself (to more than `nil` or an empty
  value) is its own, whatever another script stores under it.
- Not followed: a second hop; instance variables and methods called on an
  object (`obj.fetch`); a method's value that travels through an argument;
  the order in which the sections run.

**Batch, PowerShell and sh** (`remote_sh.shared`):

- An environment variable: set from a download in one script (batch `for
  /f ... in ('curl ...') do set NAME=...`; PowerShell `$env:NAME = ...`,
  `[Environment]::SetEnvironmentVariable`, `setx`; sh `export
  NAME=$(curl ...)`) and run in another that does not set it itself (batch:
  `%NAME%` as the command, or handed to `call` / `start` / `cmd` /
  `powershell`; PowerShell: `Invoke-Expression`, a script block, `&` or
  `Start-Process`; sh: `eval`, `sh -c`, the variable as the command). The
  two Windows shells share their names (whatever their case); sh has its
  own.
- The arguments of a script: one script hands a download to another it
  calls or starts (`call b.bat %NAME%`, `powershell -File b.ps1 $x`,
  `./b.sh "$NAME"`), and that script runs what it was handed (`%1`,
  `$args`, `$1`). Any argument, not one by its position.
- A file: one script writes a download to it, another starts it.
- Not asked: whether the first script really starts the second (a variable
  set with `setx`, or a file, outlives the script). Not followed: a second
  hop; what a batch or sh script does with a value in between (those
  summaries are read from statements with a few patterns - the tracer
  keeps no batch or sh variables); a renamed file; `source`d functions.
- **`.sh` scripts have no single-file tracer, by design** (phageo,
  2026-10-12): a `.sh` file is not run on Windows without extra tools, so
  a download-and-run *inside* one `.sh` file is found only by the ordinary
  rules. What they share with other scripts is read (above). The `.sh`
  launchers of the six Ren'Py samples are, byte for byte, the `renpy.sh` of
  their SDK, and **the official table holds that file** (phageo, 2026-10-12):
  `renpy.sh` of each of the thirteen listed SDKs - seven different files;
  it is the only `.sh` file of those archives - is in
  `engine_hashes.KNOWN`, so `engine_hashes.verified` names such a launcher
  whatever the game calls it (a test checks the six). **What that gives**
  (phageo, 2026-10-12, second decision): a `.sh` file with such a hash is
  judged like the other hash-verified engine files - it gets the baseline
  "official engine build, verified by SHA-256", so what the rules find in
  it is lowered (kept among the suppressed findings), and no limit note is
  made for it. **A CRITICAL finding or chain is always shown** (rule 13) -
  also a download one such script hands to another. Strict mode trusts
  nothing, as everywhere. Only the content counts: the same bytes under
  another kind of name (`.bat`), or a `.sh` file that is some other file of
  the table, are judged as before. Measured: the seven official launchers
  have no finding at all, so today this changes nothing in any sample.

Limits: those of the tracers (steps, lines, size) for each summary - a
reading that stops gets `SCRIPT-LIMIT-001` -, 200 names of each kind per
script, and the join's own (2,000 scripts, 200 chains, 8 per file, one
second - a line in the report's notes says when one is reached). Every
batch, PowerShell and sh script, and every Ruby script that names a
network word or something that runs, is read once more for its summary.

Checked on constructed scripts only (written to a temporary folder and
scanned as a folder): no sample has such a chain - the Ruby samples name no
network word at all.

#### VBScript (`.vbs`, and the VBScript blocks of `.wsf` and `.hta`)

Since 2026-10-11 (`dataflow/remote_vbs.py`, called from `handlers/shell.py`),
one file at a time, like the PowerShell tracer:

- **Download:** a request object - `MSXML2.XMLHTTP`, `Microsoft.XMLHTTP`,
  `MSXML2.ServerXMLHTTP`, `WinHttp.WinHttpRequest`, any version - and what is
  read from it: `responseBody`, `responseText`, `responseStream`,
  `responseXML`. The address is the one handed to `Open`; an address on
  this PC is no download.
- **Run:** the answer is written to a file - `ADODB.Stream` `Write` +
  `SaveToFile`, or a text file of `Scripting.FileSystemObject` - and that
  file is started with `WScript.Shell` `Run` / `Exec` or
  `Shell.Application` `ShellExecute` (by the variable that holds its path,
  or by its file name inside the command line); or the answer is run as
  code with `Execute` / `ExecuteGlobal` / `Eval`.
- **Object names through variables:** `CreateObject(name)` is worked out
  through variables and joined texts (`&`, `+`, `Chr`, `StrReverse`,
  `LCase` / `UCase` / `Trim`). When a name cannot be worked out, an object
  is still a request object by what is read from it (`.responseText`), and
  `Run` / `Exec` / `ShellExecute` on it still counts as a start; an object
  of a *known other* kind with a method called `Run` does not.
- **Also:** a `Sub` / `Function` of the script is followed (what it is
  handed, what it gives back by its name); `GetObject("script:http...")`
  and a `<script src="http...">` of a `.wsf` / `.hta` file load a remote
  script by themselves; the command lines the script starts are handed to
  the PowerShell / batch chain ("[in a command line this script starts]").
- **`.wsf` and `.hta`:** the `<script>` blocks whose `language` (or `type`)
  says VBScript are read, with the file's line numbers. JScript blocks go
  to the JavaScript chain (see "JScript under the Windows Script Host"
  below); in an `.hta` a block that names no language is JScript.
- **Limits, as for PowerShell:** 4 MB of text, 50,000 lines, 300,000
  statements over both readings (the script is read twice, so that a `Sub`
  below its call is known), 8 findings per file. When a limit that is a
  count is reached nothing is guessed, and the note `SCRIPT-LIMIT-001`
  says so (see "When a reading stops at its limit" below).
- **What it is:** a tracer over statements. Variables are one script-wide
  set of names; branches are not taken; a variable keeps what it was ever
  set to.
- **Not followed (missed, silently):** a text
  handed to `ExecuteGlobal` that itself downloads (it is not read again);
  classes and `With` blocks (`.Run` without an object in front); a
  download written to a file by a command line and started by the script,
  or the other way round; anything across two files.
- **Checked on:** constructed scripts only (seven shapes with harmless
  twins, `.wsf` and `.hta` forms). The five `.vbs` files in the samples
  (small launch helpers in Ren'Py games) give no chain. No real VBScript
  dropper was at hand.

#### When a reading stops at its limit (`SCRIPT-LIMIT-001`)

Every tracer that follows a download to where it is run has limits, and
since 2026-10-12 every one of them says so when it stops at one: the note
`SCRIPT-LIMIT-001` - LOW, a "could not be read" note, never hidden, the
launcher asks once. One note per file.

**The note names its cause** (phageo, 2026-10-13; `values.cause`): `size` -
the script is larger than what is read of a script; `step limit` - a count
was reached (steps, lines, statements, classes, depth: the same for the
same file on every PC); `safety cap` - the far cap by the clock, which is
not meant to be reached. It reads `... stopped at its limit: larger than
4 MB [cause: size]`, and when a second kind of limit was reached in the
same file, that one is added: `...; also: more than 600000 steps [cause:
step limit]`. Until then the first limit won and the others were dropped
(`values.also`): on a real sample a script that always has the note for
its size hid that its reading had been cut by the clock as well. The note
of the reading across files (`PY-JOIN-001`) names its cause the same way.

| Tracer | Limits that make the note | Safety cap by the clock |
| --- | --- | --- |
| JavaScript (`remote.py`) | 600,000 steps; 32 MB (4 MB until 2026-10-14) | 10 min |
| Python / Ren'Py, inside one file (`remote_py.py`) | 400,000 steps | 10 min |
| Ruby (`remote_rb.py`) | 300,000 steps; 60,000 lines; 4 MB; more than four classes for one `obj.name` a download goes through | 10 min |
| PowerShell and batch (`remote_sh.py`) | 300,000 steps; 50,000 lines; 4 MB | 10 min |
| VBScript (`remote_vbs.py`) | 300,000 statements; 50,000 lines; 4 MB | none |
| Payload reading - what reaches `exec` / the shell (`values.py`, `pyflow.py`, `textflow.py`) | 250,000 steps; a value larger than the reading models; nested too deeply; Python over 2 MB; JavaScript over 32 MB; other scripts over 4 MB; more than 2,000 calls (600 until 2026-10-15) - in JavaScript since 2026-10-15 (forty-eighth message) 2,000 in each module function of a bundle (webpack's numbered modules, esbuild's modules by path; a call belongs to the innermost module, the code outside them is one more) and 20,000 in the whole text; a batch file over 50,000 lines | 10 min |
| NSIS instructions (`remote_nsis.py`) | 400,000 steps | 10 min |
| Calls rebuilt from a compiled Python file (`remote_py.py`) | 200,000 lines kept, 100,000 lines tried; then the Python tracer's limits | 10 min |

**The sweep of 2026-10-12** (phageo): no clock stops a reading silently any
more, and none is shorter than five seconds - the NSIS reading and the
rebuilt calls had two-second clocks that said nothing, the join across
files one second (it said so in the scan's notes). The Python tracer on
decoded code, and the reading of the command lines a JScript starts, had
the limits above but swallowed them; they make the note now. A Python file
over 2 MB (or nested deeper than 150 brackets) and a script over 4 MB were
not read by the payload reading at all, without a word; they get the note
when they name anything the reading looks for. **Files and archives:** a
file on disk of which only the first 64 MB were inspected gets `ARC-002`
(before: a line in the scan's notes, which neither the verdict nor the
launcher reads); so does an `.rpa` whose member list cannot be read or is
of an unknown layout (**before: no finding at all - it came out CLEAN**),
an `.rpa` member over 32 MB, members beyond the counts of an `.rpa` or an
RPG Maker archive, and a large program whose texts are not searched to the
end. The full list with before and after: `docs/CHANGELOG.md`,
twenty-sixth message. Not covered by the sweep: see "Not made" below and
the changelog's "found and not changed".

**The payload reading** (see "Payload resolution") is the sixth row since
2026-10-12 (phageo). Until then it had a two-second clock that stopped it
without a word, so a busy or slow PC could find less than a fast one - seen
once: with six scans at a time, four hidden findings of MZ-01's `pixi.js`
were missing. Now its steps are the limit, the clock is the same five-second
brake as elsewhere, and either makes the note (the evidence says "reading
what reaches exec / the shell"). Two things changed with it: for JavaScript
the reading looked through the whole file once for every variable name -
seconds on a large library, which no step counted; it now makes one pass
for all names (the same places are found; a test compares both ways). And
the JavaScript tracer's reading of a single expression had a clock of its
own, a quarter of a second, equally silent: it now shares the tracer's
brake. **Its step limit was already reached before this change, silently:**
by six to eight engine scripts in each Ren'Py sample (`renpy/main.py`,
`atl.py`, `00updater.rpy` ...; measured 2026-10-12). For a verified
official file no note is made, as for the other tracers.

The limits are counts, so the same file always gets the same answer. The
count is the real limit everywhere. The clocks are emergency brakes for a
PC so slow that the steps take too long; they were raised from two to five
seconds (the PowerShell tracer's on 2026-10-12, the JavaScript, Python and
Ruby tracers' the same day), and when one does fire the note is made as
well and names the seconds (as for `PY-JOIN-001`) - a reading that stops
is never silent now.

**Since 2026-10-13 (phageo) the clock decides nothing.** A verdict must not
depend on how fast the PC is, and a five-second brake still did: a real
sample's CRITICAL chain was found in one run of three. It stands in a
packed script of 16 MB (the first 4 MB are read). The reading followed
every name the download went into by searching the whole script for that
name - up to 3,000 searches of 4 MB each, which the step count did not
count - and needed about 30 seconds; the brake cut it at five, at a place
that depended on what else the PC was doing. (The file already carried the
limit note for its size, so the cut itself was not visible.) Now:

- **Every clock is a far safety cap of ten minutes** (`values.SAFETY_SECONDS`,
  one number for every reading in the table and for the join across
  files). The counts - steps, sites, sizes - are what stops a reading; the
  cap is for what nobody foresaw, and when it fires the note is made, as
  before.
- **The reading that was slow counts differently:** after the first 24
  names the script is read once for all names (`RemoteFlow._uses`), and
  the lowest brace depth between a definition and its use is taken from
  blocks of 64 braces (`TextFlow._visible`). Both give exactly what the
  slow way gave (tests compare them; so did 9,800 comparisons on the
  scripts of two clean samples). That script's reading takes 13 seconds
  now, the same sample's 2.7 MB script 3.5 instead of 12.
- **What is left that takes time is bounded by size:** a script is read
  for at most its first 4 MB, in a fixed number of passes. The slowest
  reading measured takes 13 seconds on this PC; a PC forty times slower
  still gets the same answer.
- **Measured:** the three positive-benchmark runs of 2026-10-13 are the
  same file byte for byte (one of them beside a full clean benchmark), and
  a test scans constructed scripts of every language with a clock that
  runs five hundred times too fast.

**HTML pages:** the JavaScript tracer's size limit is a limit on script. A
page (`.html`, `.htm`) larger than the limit (32 MB since 2026-10-14; 4 MB before) is not handed to the tracer as a
whole: its JavaScript blocks are joined - each on the lines it has in the
page - and that joined text is what the tracer reads and what the limit
applies to. A big page with little script gets no note, and its script is
read wherever in the page it stands; a page whose scripts together exceed
the limit gets the note. A page of up to the limit is read as before, as
one text.

Not made: for a file that is verifiably an official file of its engine or
of a known library, or any file of an official engine archive in the table
(what those do is known - as for `PY-JOIN-001`); for
the smaller limits inside a tracer (how many call sites or uses of one
name are looked at); for JavaScript, Ruby or shell code that was decoded out of a script and
is read again (decoded Python makes the note since 2026-10-12); for the
command lines one language hands to the shell chain;
for the chain across files (`PY-JOIN-001` is its note); for compiled C#
(`DN-IL-001`).

#### Encoded scripts (`.vbe`, `.jse`, `#@~^` blocks)

Microsoft's Script Encoder turns a script into a block `#@~^ ... ^#~@`
that Windows decodes and runs like a plain one. Since 2026-10-11 the
scanner decodes it too (`unpack/screnc.py`: three replacement tables, a
pattern of 64 steps, five escapes; data only, standard library): a `.vbe`
or `.jse` file, and encoded blocks inside `.wsf`, `.hta`, `.html` / `.htm`
and `.js` files. The decoded text takes the block's place, and the file is
then read as if it were plain - by the ordinary rules and by the VBScript /
JavaScript chains.

- A block is accepted only when its length fits and its checksum is that of
  the decoded text. Anything else - a changed character, a block cut
  short, a missing end mark - is not read at all (not even as plain text),
  and the note `ENC-SCRIPT-001` says so: LOW, "could not be read", never
  hidden, the launcher asks once.
- Limits: 256 blocks per file, 16 MB per block.
- Checked against Windows' own encoder: eight texts encoded once by it
  (`tests/build_screnc_fixtures.py`, kept with their SHA-256), among them
  one that holds every character at every step of the pattern, and a page
  the encoder marked itself. No encoded script from the wild was at hand.
- Characters outside ASCII (Turkish, Japanese ...) stand in a block as
  they are; they do not move the pattern on and are not in the checksum.
  Checked with a script of Turkish and Japanese text encoded by Windows'
  encoder (since 2026-10-12). That is what the encoder *object* does with
  text; a file written by the old command-line encoder in another code
  page was not at hand.

#### JScript under the Windows Script Host

The JavaScript chain (`dataflow/remote.py`) knows, since 2026-10-11, the
objects of the Windows Script Host: an `ADODB.Stream` that was handed a
download and is saved (`Write` / `WriteText` + `SaveToFile`), and a text
file of the `Scripting.FileSystemObject` (`CreateTextFile` /
`OpenTextFile` + `Write` / `WriteLine`), are "written to a file";
`WScript.Shell` `Run` / `Exec` and `Shell.Application` `ShellExecute` are
"started" - and a download handed to `Run` directly is a command. The
request object was known before by its `open` and `responseText`;
`responseBody` / `responseStream` are answers too now.

- Object names (`new ActiveXObject(name)`, `WScript.CreateObject(name)`)
  are worked out through variables. A name that cannot be worked out counts
  as something that may start (shown as `ActiveXObject.Run`); an object of
  a known other kind with a method of that name does not.
- The JScript blocks of `.wsf` / `.hta` files are handed to the chain with
  the file's own line numbers; `.jse` files after decoding.
- The command lines a JScript starts with `Run` / `Exec` / `ShellExecute`
  are handed to the PowerShell / batch chain, as for VBScript (since
  2026-10-12; `remote.wsh_commands`) - where the command can be worked
  out as a text.
- Not followed: `GetObject("script:...")` in JScript; everything the
  JavaScript chain does not follow anyway (object fields, other files).
- Checked on constructed scripts only (six shapes with harmless twins,
  names through variables, `.wsf` and `.hta` blocks).

#### Compiled C# (.NET libraries, Unity Mono games)

Since 2026-10-11 the methods of a managed program are read instruction by
instruction (`unpack/dotnet_il.py`: where each method's body is, its header,
and the instruction set of ECMA-335 written out as a table - bytes are
walked, nothing is loaded, compiled or run). `dataflow/remote_cs.py` follows
a download through them:

- **What counts as a download:** what `WebClient` (`DownloadData`,
  `DownloadString`, `OpenRead`, `DownloadFile`, the answers to its uploads,
  the `...Completed` events), `HttpClient`, `WebRequest.GetResponse`,
  `UnityWebRequest`, the old `WWW`, a `TcpClient` / `UdpClient` / `Socket`
  hand back. A download from this PC (`localhost`, `127.x`) is none, as in
  the other languages.
- **What counts as running it:** every way a managed program loads code -
  `Assembly.Load` / `LoadFrom` / `LoadFile` / `LoadModule` /
  `LoadWithPartialName` / `UnsafeLoadFrom` / `ReflectionOnlyLoad...`,
  `AppDomain.Load` / `ExecuteAssembly...` / `CreateInstance...` (also
  `...From`), `Activator.CreateInstanceFrom` -, `Process.Start` (also
  through a `ProcessStartInfo`, and a `Process` whose `StartInfo` was
  filled in),
  the Windows functions `ShellExecute`, `CreateProcess`, `WinExec`,
  `LoadLibrary` reached through P/Invoke - or the download is written to a
  file (`File.WriteAllBytes`, a `FileStream` / writer, `CopyTo`,
  `DownloadFile`) and that file is then started or loaded.
  `Assembly.LoadFrom` with a remote address written out is a chain by
  itself.
- **How far a value is followed:** inside one method (the evaluation stack,
  local variables, arguments), and through the fields of one class together
  with the classes nested in it. The second is what makes the usual Unity
  forms visible: the compiler turns a coroutine (`IEnumerator` with
  `yield`), an `async` method and a lambda into small generated classes
  whose steps hand values on through fields.
- **Between methods (since the second step, 2026-10-11):** as an argument
  into the method that is called and as what a method gives back - at most
  four such hand-overs in a row (`MAX_DEPTH`). Every method that is read
  is known by three things: what it gives back (a download, or what it was
  handed), which of its arguments reach a load or a start, and whether it
  writes an argument to a file. A call is then judged by what is handed
  to *that* call - so a method that loads is no chain when one caller hands
  it a packaged file and another caller's download goes elsewhere. A class
  that keeps what its constructor is handed in a field is followed the
  same way.
- **Delegates and hand-overs:** a method that is passed on as a value (a
  lambda, a method group) is known wherever that value goes; whatever
  call receives it - `Task.Run`, `ContinueWith`, `new Thread(...).Start(x)`,
  `ThreadPool.QueueUserWorkItem`, `Invoke`, an event - what travels with it
  is taken to reach the method, and what the method gives back to come out
  of the call. `StartCoroutine(Apply(data))` is an ordinary call of
  `Apply`.
- **Between two libraries, one hop** (`remote_cs.join`,
  `Scanner._join_managed`; a scan of one folder): every library leaves
  which of its methods give a download back and which load or start what
  they are handed, and which methods of *other* libraries it relies on for
  either. After all files were scanned the call is resolved through the
  assembly its reference names (the caller's MemberRef -> TypeRef ->
  AssemblyRef; since 2026-10-11, before that by the method's name alone):
  only a library that gives itself that name is the one that is called, so
  a second library with a method of the same name is no chain. When the
  call cannot be resolved - the reference names no assembly, no scanned
  library has that name, or the one that has it only passes the type on -
  every library with such a method is reported; none is picked. Overloads
  are still one name. The finding is made for the library that loads or
  starts, marked "[across two libraries]".
- **Levels (phageo, 2026-10-11):** `CHAIN-REMOTE-CODE`, CRITICAL, in the
  game's own code and in every library that is not verified - also one that
  is only *named* like the engine's (`mscorlib.dll`, `System.dll`,
  `UnityEngine.UI.dll` cannot be verified by the table: a name proves
  nothing). Hidden only in a file that is, byte for byte, a file of an
  official engine package (`engine_hashes`), like the chain in Ren'Py's own
  updater. A chain across two libraries is hidden only when *both* are
  such files. There is no table of third-party hot-update frameworks
  (phageo, 2026-10-11: not for now) - until a real sample needs one, such a
  framework's chain is CRITICAL like any other; frameworks are then added
  from their official release page.
- **Limits:** 400,000 methods, 1 MB of instructions per method, 20 million
  instructions per program over all readings; four hand-overs between
  methods; a method is read again at most twelve times when something it
  uses has changed; 4,000 shared names per library and kind, 50 chains
  across libraries per scan.
- **What is read at all (since 2026-10-11, for speed):** nothing is
  followed in a library whose own reference tables - the members of other
  libraries it refers to and the Windows functions it imports - name no
  download, no load or start and no file write. By content; what the file
  is called plays no part. A library that *defines* such a method itself
  is followed too (the .NET base library `mscorlib.dll` defines
  `Assembly.Load` and names it in no reference table - a helper beside it
  could hand a download straight to it), unless the file is, byte for
  byte, a file of an official engine package. Inside a library the reading
  begins with the methods that name a download or a start, and their
  classes, and spreads to what calls a method only when something became
  known about it: it gives a download back, or one of its arguments
  reaches a start.
- **The same answer whatever the order:** what is known about a method
  depends on whether it was read, so after the reading has spread it is
  done again from nothing with that set of methods - until the set stays
  as it is (at most four times). Where one of several equal things has to
  be named (which download, which method), the first by name is taken, not
  the first that happens to be met. The libraries of a scan give the same
  summaries and findings in any file order, and in any Python process.
- **Cost:** about nine to twelve seconds for the 88 libraries of a Unity
  Mono game on this PC - most of it in `System.Xml.dll`, `System.dll` and
  `mscorlib.dll`, and about half of it the second reading that makes the
  answer independent of the order. (Two seconds before the second step,
  about twenty right after it, five to six before libraries that define a
  loader were followed and before the second reading.)
  When the reading does not get to the end - a limit, an unknown
  instruction, tables in an unusual form - the note `DN-IL-001` (LOW,
  "could not be read": never hidden, the launcher asks once) says so. A
  program that names no type that can download, or none that can load or
  start, is not walked at all.
- **What it is:** a model, not an interpreter. The instructions of a method
  are read in the order they stand; branches are not taken; what a call
  into another library - or into a method that was not read - gives back
  is taken to depend on what went in (except plain numbers and flags); the
  fields of a class are known by everything any method stores in them.
- **Not followed (missed, silently):** a fifth hand-over between methods (a
  test pins this); a value that travels between two classes through
  anything but a call (a static field of another class, a list both
  hold); a method an interface call reaches when more than eight methods
  have that name; a download a called method writes into a buffer it is
  handed; a second hop between libraries, and fields or delegates between
  libraries; reflection (`MethodInfo.Invoke`); a script engine fed from
  the network; Unity asset bundles (data); code hidden by an obfuscator
  that rewrites the control flow.
- **Checked on:** forty-two libraries compiled once from
  `tests/fixtures_cs/Cases.cs` with Windows' own C# compiler (seventeen
  shapes, each with a harmless twin; the depth limit; three libraries for
  the chain across libraries; kept as text with their SHA-256 in
  `fixtures.json`, never run), and the 175 managed libraries of UNI-01 and
  UNI-02: all read to the end, no chain inside a library and none across
  them. No real program with such a chain was at hand. The cross-library
  tests join libraries that are scanned from memory; a scan of a real
  folder with such a pair was not tried (an antivirus program would
  remove the files).

#### Ren'Py's compiled Python (`.pyo`, `.pyc`)

Ren'Py 6 and 7 ship the engine and its Python library as compiled files
(`.pyo`) beside the sources, and Python runs the compiled file, not the
source, when the time stamp inside it fits. So a changed `.pyo` beside an
untouched `.py` would run unseen. Since 2026-10-08 a compiled file under
`renpy/` or `lib/` is compared with the official SDK
(`handlers/renpy_engine.py`, `compiled_status`; table
`gamescan/compiled_hashes.py`, built from the same SDK archives as the engine
table):

| The compiled file | Result |
| --- | --- |
| contains exactly what a compiled file of an official SDK contains | nothing - it is the official file |
| is an official compiled file, but only of other listed versions than the one this copy of Ren'Py says it is | `ENGINE-006`, a visible LOW note: "leftover from Ren'Py X" |
| differs, and the code of the `.py` beside it differs from the official one too (the developer changed that engine file) | `ENGINE-005`, a visible LOW note |
| differs, and the `.py` beside it is the official one - or there is no `.py` | `ENGINE-004`, HIGH |
| differs, and the `.py` beside it differs from an official one in comments and spacing only | `ENGINE-004`, HIGH - unless the compiled file is what that official source compiles to apart from line numbers (then `ENGINE-005`) |
| is in a Ren'Py whose version is not in the table | nothing: there is nothing to compare with |

A changed comment must not explain a changed compiled file. So the changed
`.py` is cut into tokens with the standard library's `tokenize`
(`unpack/pytokens.py`: text only, nothing is compiled or run) and compared
with the official sources without comments, blank lines and spacing; where a
block begins and ends still counts. The table holds, for each official
source that has a compiled file beside it in an SDK, what it compiles to
without line numbers (709 sources) - comments and blank lines move the
lines and change nothing else. A changed source the tokenizer cannot read
keeps the LOW note, and the note says that this was not checked.

A game's compiled files are never the SDK's bytes - they are compiled on the
developer's PC. So the file is read as data (`unpack/pyo.py`: a walk over
its bytes; no `marshal`, no `pickle`, nothing is built or run; limits on
size, depth, number of objects and digits) and compared by content, with four
things left out that differ from one compilation to the next and change
nothing about what the code does: the time stamp, the path of the source
file stored in every code object, whether a whole number above 32 bits is
stored as a "long" or an "int", and whether a short text is stored in place
or as a reference to an identical earlier one. Everything else - every
instruction, constant, name and line number, in its order - has to be the
same. The stored source path is the developer's own folder; the reader walks
over it and it never reaches a finding or a report.

**The calls of a compiled file are read** (since 2026-10-08;
`unpack/pycalls.py`). Every compiled Python 2.7 file that is not an official
one - an engine file that differs, a file of a Ren'Py whose version is not
in the table, a compiled module of the game's own, wherever it lies - has
its instructions walked once, as data: the 2.7 instruction numbers are
written out in the scanner (the `dis` module of the Python that runs it
describes Python 3), no code object is built and nothing is run. A small
model of Python's stack that holds texts puts names, attributes, constants
and calls back together - `os.system('...')`, `urllib2.urlopen(...).read()`,
imports, assignments - each at the line number the file's own line table
gives. The ordinary Python rules read that text, and the attack chains
follow from what they find, as in any script; a finding says "in a call
rebuilt from the compiled file". A name imported with `from os import system
as run` is written `os.system` where it is called.

| The compiled file | Result |
| --- | --- |
| differs, the developer changed the code of its source - but it calls a name that source never writes | `ENGINE-007`, HIGH: "this compiled engine file calls X, which the source file beside it never names" |
| differs - whether nothing explains it (`ENGINE-004`, `ENGINE-007`) or its changed source does (`ENGINE-005`; since 2026-10-10) | the folder it lies in hides nothing: what the rules find in its calls is shown and forms chains |
| lies in a Ren'Py of an unlisted version | single findings in its calls keep the folder's trust, as in a script of the engine |
| is a module of the game's own | judged like any script |
| cannot be walked to its end: cut off, an instruction Python 2.7 does not have, an argument that points at nothing, beyond the limits | `PYO-FMT-001`, LOW, "could not be read" - never hidden, and the secure launcher asks |

In the seven Python 2 SDKs all 4,147 compiled files are read to their end,
and in none of the 881 pairs of a source and its compiled file does the
compiled file call a name its source does not write (names inside comments
and texts do not count; the two halves of a `with` statement and the stored
form of a class's private names are allowed for).

What this does not do. The walk is a sweep, not a decompiler: jumps are not
followed, so the text holds every call but not which branch it is in, and
what is built with `getattr`, from pieces, or handed around as a value is
only as visible as it would be in a source file. The payload resolver does
not read the rebuilt text; the rules and the chains by nearness do, and
since 2026-10-10 so does the data-flow chain (`CHAIN-REMOTE-CODE`) - from a
second output of the walk that keeps every function apart (in the flat text
a `data` of one function would be the `data` of every function): a `def`
with its parameters for each code object, the plain assignments and
`return` written out, a rebuilt line that does not parse by itself left
out. The chain is judged as in a script (no trust for an engine file that
differs; HIGH in a Ren'Py of an unlisted version); its evidence ends with
the same "rebuilt" mark. What it cannot follow there: a value that goes
through a loop variable or an unpacked tuple, which class a method belongs
to, another file. The source check asks for
*called names* only: a compiled file that calls nothing but names its
changed source also writes (a large engine file writes `open`, `eval`,
`os` ...) still gets the LOW note - what it calls is then read by the rules,
and since 2026-10-10 without the folder's trust: every finding in its calls
is shown (in the samples that is one LOW note, `PY-EXEC-001` in
`renpy/main.pyo` of RPY-02). An
`ENGINE-005` file is not proven to be what its source compiles to. The
source keys are
made by the tokenizer of the Python that runs the scanner; the table was
built with Python 3.13, and should another Python cut a file differently,
that file counts as "code changed" - the LOW note, never a wrong HIGH. A
leftover file (`ENGINE-006`) is an official file of another version, and
Python may still run it instead of this version's source.
Ren'Py 8 compiles with Python 3: its files are known by their
exact bytes only (the bundled Python library matches that way), and one that
differs is neither read nor reported yet - see "Limits".
#### What a `ShellExecute` call opens (Ruby)

RPG Maker games use `ShellExecute` through `Win32API` to open their store
page or a manual, and the declaration alone used to be HIGH (`RB-NATIVE-002`).
Now every call through that declaration is read (`dataflow/remote_rb.py`,
`shell_execute`), also in the "Script" commands of map and common-event files:

| What is opened | Result |
| --- | --- |
| an `https://` address, a `mailto:` address, or a document of the game (`readme.txt`, `Manual/index.html`, a picture, a PDF) | `RB-NATIVE-003`, LOW, with what is opened |
| an `http://` address, a bare network address, a link shortener, a folder | `RB-NATIVE-003`, MEDIUM |
| a program or script, anything outside the game folder, another verb than `open` | stays `RB-NATIVE-002`, HIGH |
| one call whose target cannot be resolved, a declaration that is never called, a function that is handed on | stays HIGH |
| a file that was downloaded before | `CHAIN-REMOTE-CODE`, CRITICAL |

## Windows Defender integration

Defender never sees code that is compressed, pickled or encrypted inside a
game file. The scanner unpacks it and hands the text to Defender through AMSI,
so the two tools cover each other's blind spot. If AMSI or Defender is
missing, disabled, or replaced by another antivirus, an `INFO:` note is added
to the report and the scan continues without it.

## Experimental: PC-wide features

**Hidden in 0.9-beta (phageo, 2026-10-24):** this part was never tested. The
Protection button is not in the window, real-time protection never starts
(also when an older version saved it as on), `--watch` is refused, and the
package leaves its two modules out (`gamescan/protection.py`,
`gamescan/monitor.py`). The code stays in the project, switched off by
`models.EXPERIMENTAL_PROTECTION = False`. What follows describes it as it
was.

Real-time protection and the Quick / Full PC scans are in an **Experimental**
group in the Protection window. They repeat what Windows Security already
does, less well, and cause false alarms outside game folders (the rules were
written for game scripts).

- *Real-time protection* polls Downloads and Desktop (configurable), scans new
  or changed files after they are written, and shows an alert for HIGH/CRITICAL.
  It only runs while the window (or `--watch`) is open and cannot block a
  program before it starts.
- *Quick scan* covers Downloads, Desktop, temp and the Startup folders;
  *Full scan* reads every fixed drive.

*Startup items and running programs* (registry Run keys, Startup folders,
running process images, plus heuristics on the autostart commands) is not in
the experimental group.

## Memory center and learning

`memory.py` keeps `~/.game_safety_scanner/memory.db` with three tables:
`scans`, `observations` (every finding: snippet, engine, severity, decision)
and `feedback` (resolutions). The last 300 scans are kept.

- **Exact memory.** *False positive* / *Confirm threat* (buttons or
  right-click) is keyed by rule + whitespace-normalised code, so the same line
  is resolved in later scans in any file or game. A newer decision replaces
  the older one.
- **Rule confidence.** Per (rule, engine):
  `(confirmed + base*4) / (confirmed + false_positives + 4)`. Feedback fades
  with a 180-day half-life.
- **Sources.** Explicit clicks 1.0; quarantining a file 1.0 (confirmed);
  allowlisting a file 0.7 (false positive); VirusTotal verdicts 0.5. The
  scanner never feeds back its own conclusions.
- **Guard rail.** Statistics alone may only drop a LOW/MEDIUM finding, after
  5+ false positives with no confirmation and confidence under 15%.
- **New since last scan.** Findings absent from the previous scan of the same
  target are marked NEW.

## Hardening

Each item has a regression test in `tests/test_gamescan.py`; the mapping, and
the gaps, are in `docs/CLAIMS_AUDIT.md`.

Detection bypasses closed:

- Per-rule limits are applied after false-positive evaluation.
- False-positive decisions read code only, never comment text.
- The JavaScript lexer understands regex literals; only real Python docstrings
  count as documentation; CRITICAL rules are reported even inside comments.
- URL trust is decided on the real destination host.
- Windows-system trust requires the file to really be under `%WINDIR%`.
- A complete CRITICAL attack chain is reported even inside an engine / library
  folder or a default RPG Maker script.
- Data hidden in or behind a signature block is found, reported with a note
  no signature can hide or lower, and scanned (`SIG-DATA-001`, `SIG-DATA-002`).
- A zip appended to a program - an NW.js game packed into `Game.exe` - is
  opened and its scripts and pages are scanned.
- A file whose content could not be read is never CLEAN: the "could not be
  fully inspected" note (`ARC-002`) and the other "could not be read" notes
  (unreadable Unity bundle, compiled script, RPG Maker archive, .NET or
  IL2CPP metadata, a file the analyser failed on) are not hidden by a signature, an official
  hash, a folder baseline, a clean VirusTotal result or learned statistics.
  A signature says who made a file, not what is in it.
- Remote code execution is found by data flow, so a bundled library with a
  download-and-execute payload injected into it is CRITICAL wherever in the
  file the payload sits; the remote-code analysis is bounded in steps and time.
- UTF-16 scripts without a BOM are decoded; `\u`-escaped JavaScript identifiers
  and `getattr(os, 'sys' + 'tem')` style lookups are flagged.
- "This plugin only opens a web page" is accepted only when every process
  launch in the file was resolved and each one is nothing but a URL handed to
  the system's opener; one unreadable or different command keeps the alarm.
- Ruby backtick commands containing `#{...}` are no longer read as comments.

Robustness:

- "Rest of line" patterns are bounded; unterminated block comments cost one pass.
- Decompression is bounded for `.rpyc`, the `.rpa` index, RGSS scripts, LZ4,
  LZMA and zip members; pickles cannot request sized allocations.
- The Ruby Marshal reader accepts only arrays, integers, strings, symbols,
  booleans and nil, with depth and size limits.
- A file that makes the analyser fail shows up as a finding.
- Signature-trust results are tied to the file's size and timestamp.
- The payload resolver never runs or imports scanned code: it works on the
  syntax tree with its own values. It is limited to 250,000 steps per file
  (the limit; the clock is only a far safety cap - ten minutes since
  2026-10-13 -, and whichever stops it makes the note `SCRIPT-LIMIT-001` - since 2026-10-12; before, a
  two-second clock stopped it silently), 1 MB per value and 3 nested layers; format widths,
  repetition, powers and decompression are checked before they are computed.
  `marshal` and `pickle` payloads are deliberately not decoded.
  For Python it reads a function anew at every call - except a *pure* one
  (since 2026-10-12): a function that writes nothing outside its own
  variables (no `global` / `nonlocal`, no assignment to an attribute or an
  item, nothing defined inside it) is read once for the same arguments, as
  long as every name and attribute it reads is as it was and every function
  of the file it may call is pure too. This changes no finding; it saves
  steps where a helper is called in a loop.
  A `while` loop is modelled for up to 5,000 turns - but it ends as soon as
  a full turn has left everything the reading knows (globals, attributes
  of modules and objects, the variables of the function and of those
  around it, what was found) exactly as the turn before left it: the
  remaining turns would do the same (since 2026-10-12). A loop that
  changes anything keeps going. This is what lets the engine file of
  RPY-02 be read to its end (2.8 million steps before, 4,232 now).

Trust boundaries:

- A report opened from a file cannot teach the scanner or add to the
  allowlist, and quarantine re-checks the file's SHA-256 before acting.
- Network paths from a report are never opened.
- The quarantine index cannot point restore/delete outside the quarantine.
- Auto-quarantine never touches Windows, Program Files, Python or the
  scanner's own folder.
- Windows Defender is never allowed to remove anything on the scanner's behalf.
- The abuse.ch Auth-Key never appears in error messages.

## Architecture

| Module | Role |
| --- | --- |
| `handlers/` | One `BaseHandler` subclass per engine family: Ren'Py, RPG Maker MV/MZ, RPG Maker XP/VX/Ace, Unity/.NET, native PE, shell scripts, archives/documents. |
| `unpack/` | Pure unpackers / decompilers the handlers call before analysis. |
| `rules.py` | `Rule` definitions and the shared `RuleEngine` (regex rules, YARA, AMSI hook). Each rule's regex is skipped when a literal it needs is absent from the file. |
| `dataflow/` | Payload resolution: `pyflow.py` (Python `ast` interpreter), `textflow.py` (backward tracing for JavaScript, Ruby, PowerShell; batch expansion), `remote.py` (JavaScript: from a network request to where its response is executed - `CHAIN-REMOTE-CODE`), `values.py` (bounded decoders and limits). Handlers call it through `BaseHandler.resolve_payloads()`. |
| `context.py` | `ContextEngine` - owns every false-positive decision, signature and reputation trust, the feedback loop - and the `HashAllowlist`. |
| `chains.py`, `entropy.py`, `pe.py`, `yara.py` | Analysis primitives. |
| `runtimes.py`, `engine_hashes.py` | SHA-256 tables of official engine builds (RGSS runtime; NW.js, Ren'Py runtime and Unity's Windows player files - generated by `tools/build_engine_hashes.py`, which reads Unity's package with `tools/xar_reader.py`). |
| `library_hashes.py` | SHA-256 table of official releases of libraries games bundle (Greenworks, Effekseer; since 2026-10-19 jQuery, SDL2, OpenAL Soft - generated by `tools/build_library_hashes.py`). |
| `bintable.py` | The binary form of the large generated tables (since 2026-10-19): `engine_hashes`, `compiled_hashes`, `library_hashes` and `electron_official` load their dictionaries from a `.bin` file beside them (a SHA-256 as its 32 bytes, every text once; read with `struct` only, every count checked). |
| `defender.py`, `reputation.py`, `trust.py`, `signatures.py` | External verdicts: Defender, VirusTotal, Authenticode, hash blocklist. |
| `quarantine.py`, `memory.py`, `monitor.py`, `system.py` | Isolation, learning, real-time watcher, PC scan targets. |
| `launcher.py` | Secure launcher (`--launch`): scan, then start, ask first, or refuse. |
| `scanner.py` | `Scanner` - the pipeline; builds the `ScanReport`. |
| `models.py`, `advice.py` | `Finding`, `ScanReport` (JSON in and out), plain-language advice. |
| `export.py`, `i18n.py`, `gui.py`, `dialogs.py`, `widgets.py`, `cli.py` | Presentation. |

### A game of an engine the scanner does not know

Since 2026-10-12 (phageo; the first part of a plan). The scanner chooses a
reader by a file's ending (87 endings) or, for programs and archives, by
its first bytes. A game of another engine - KiriKiri (`.xp3`), Godot
(`.pck`), GameMaker (`data.win`), Wolf RPG ... - has neither, and until
then nothing of it was opened: a constructed folder of that kind came out
**0 % read, CLEAN, and the launcher started it.** Now:

- **Coverage.** Every scan counts the bytes of all files and the bytes of
  the files a reader opened; the share is in the JSON report
  (`stats.bytes_total`, `stats.coverage`) and on the command line.
- **`SCAN-COVERAGE-001`** - LOW, a "could not be read" note, never
  hidden, the launcher asks once: the scan of one folder read less than
  10 % of its bytes and left at least 1 MB unread. So such a folder is
  never CLEAN. The note names the largest unread files. It is for an
  engine the scanner does not know: when an engine was recognised *and*
  a file of the scan is an official engine file by its SHA-256, the note
  is not made (that engine's data files are left unread on purpose). A
  folder that only has the names of a known engine still gets it.
- **Text is read by what it is.** A file no reader takes by its name is
  sampled; if it is text (up to 8 MB), the language-neutral rules read
  it (an address by itself is left out), and if it looks like a batch,
  PowerShell, VBScript or JavaScript file it goes to that reader as
  `<file>!content<.ending>`.

Limits: the 10 % was set where no sample is caught - the lowest are the
Unity games (15.7 % and 27.6 %: Unity's `.resS` / `.resource` data files
are not read), an RPG Maker MZ game (38.7 %: its encrypted media) and a
Ren'Py game (41.1 %: `.so` libraries, fonts). A script in a language the
scanner has no reader for is read by the neutral rules only: a command
line of a system tool in it is found, a call of the engine's own "open
this address" is not. The engine is not named, and a system library's
name on a file in the game's folder (side-loading) is not checked - both
are the next parts of the plan.

### Electron games: `app.asar` and compiled JavaScript

Since 2026-10-12 (phageo). An Electron game is a browser engine plus the
game's own code, which sits in `resources/app.asar`. That archive is
opened as what it is - a list of files as JSON, then the files, no
compression (`gamescan/unpack/asar.py`: data only, sizes and places
checked before anything is read, limits on the list, the number of files
and the depth of folders). Its members are scanned like any file: the
JavaScript by the JavaScript reader, with the download-and-run chain; the
`.node` add-ons by the program reader. It makes no difference whether the
archive lies in the game's folder or inside the `app-64.7z` of an
installer.

What is not read is said, and never hidden (rule 15):

- an archive that is encrypted, of another layout or damaged, and a
  script inside that is not text (some tools scramble the files of an
  asar): `ARC-002`;
- **compiled JavaScript (`.jsc`, what the "bytenode" tool writes):
  `JSC-FMT-001`.** It is V8's own instruction format, different in every
  version; the scanner does not read it. What such a file does stays
  unknown - the note says exactly that.

Limits: tested on constructed archives and on ten real malicious samples
(see "Positive benchmark"). The archive's "integrity" data is not checked.

**A clean Electron game is in the benchmark since 2026-10-12 (ELE-01) -
and the scanner calls it DANGEROUS.** It is the first clean sample with
CRITICAL false alarms: six chains, 48 HIGH findings, the launcher blocks
it. Where they come from:

- **the game's program, which is the Electron runtime under the game's
  name** (not signed, not in any hash table): the import table and texts
  of a whole browser engine - key hooks, `CryptUnprotectData`, process
  functions, a network stack - add up to `CHAIN-SPYWARE`, `CHAIN-STEALER`
  (CRITICAL) and `CHAIN-BACKDOOR`;
- **the game's own JavaScript, packed into a few very long lines**
  (bundles of 1 to 10 MB): network calls, "obfuscation" and words like
  `powershell` (in a code editor's syntax tables) stand on the same line,
  which the chain rule reads as "next to each other" - four
  `CHAIN-DOWNLOADER` (CRITICAL);
- **type-description and map files read as text** (`.d.ts`, `.js.map` -
  the text-by-content reader of the same day): `keylog` (a TLS option) and
  `powershell` in them are HIGH findings, some of them twice.

This sample has no `app.asar` (its code lies in a plain `resources/app`
folder), so it does not test the asar reader itself; it does show what the
JavaScript rules say about a real Electron game. Nothing was tuned for it.

**After the thirty-second message (same day; the three sections below):**
ELE-01 is still DANGEROUS, with 3 CRITICAL (was 6), 21 HIGH (48),
39 MEDIUM (43), 336 LOW (365). The type-description and map files are no
longer read as code; three of the four `CHAIN-DOWNLOADER` are gone. What
is left: the three chains of the program (the Electron runtime - see the
plan below) and one `CHAIN-DOWNLOADER` in a packed code-editor script,
whose parts stand in one single statement - a list of quoted texts, 3.2
million characters long (see "What is left in ELE-01" below).

**The price, on the real malicious Electron samples:** two of the four
that were DANGEROUS are SUSPICIOUS now (their CRITICAL chains were chains
of nearness inside packed lines); the launcher asks for the typed word
there instead of refusing. Whether those chains were right for the right
reason cannot be said - the samples are not looked at.

**After the thirty-third message (2026-10-13, the runtime table below):**
ELE-01 has 1 CRITICAL, 11 HIGH, 37 MEDIUM, 317 LOW - nothing of the
runtime is shown any more. It is still DANGEROUS and blocked, for one
chain: the code editor it embeds carries TypeScript's description files
as quoted texts inside a packed script, and the words `fetch(`, `atob(`
and `WScript` in those texts add up to a "downloader". Nothing is
downloaded or run there; the rule that would see that (words inside a
quoted text of a packed line do not chain) is proposed, not built.

On the real Electron samples no verdict moved: the runtime's program is
verified in four of the six that carry one and refused in two (a resource
kind with a name of its own). What is left in them is the app's own: a
native add-on that can decrypt what Windows stores for the user (five of
six), and scripts that are mostly packed and encoded.

#### The Electron runtime under the game's name

Since 2026-10-13 (phageo; `gamescan/electron_official.py`, built by
`tools/build_electron_tables.py`). An Electron game is the Electron runtime
- a whole browser engine, published unsigned by the Electron project - plus
the game's own code. Measured on ELE-01 against the official zip of its
version: 73 of its 74 runtime files are the official files byte for byte,
and the 74th, the game's program, is the official `electron.exe` with
another resource section (icon, version text, manifest) and nothing else.

So the runtime is recognised by the official releases, as the other engines
are (official files only, never a scanned sample):

- **The table** holds every file of the official Windows zip of ten
  releases - 41.4.0 (ELE-01), the six versions the programs of the real
  Electron samples state (40.1.0, 29.4.6, 29.1.0, 27.3.11, 21.4.1,
  18.3.15; of a sample only that version text was read) and, since the
  evening of 2026-10-13, the versions of the clean samples ELE-02 to
  ELE-04 (37.3.1, 21.3.1 - the 32-bit build -, 43.1.1). Each zip comes
  through the fetcher and has the SHA-256 of the Electron project's own
  `SHASUMS256.txt`. Libraries and data files are compared by their exact
  SHA-256.
- **The program** is compared by a key that covers its headers and every
  section except the resources, and leaves out the checksum field and the
  entry that says where a signature is appended (the NW.js launcher's key,
  `pe.resource_frame_key`, with that one entry more: a game's maker may
  sign the program, which the official one is not).
- **Not verified - the program is then judged like any unknown one:** an
  extra or another section; one changed byte of code, data or headers;
  data appended that is not the signature the headers name; a resource of
  a kind that neither the official program has (cursor, icon, their
  groups, version, manifest) nor branding needs; a program inside the
  resources.
- **One resource with a name of its own is accepted - exactly one**
  (phageo, 2026-10-13; `pe.only_asar_integrity`): the integrity record of
  the app archive that Electron's packaging tools write - kind
  `INTEGRITY`, name `ELECTRONASAR`, a JSON list of rows `{"file", "alg":
  "SHA256", "value": 64 hex digits}` (measured: 122 bytes in the two real
  programs that were refused for it, and in two of the three new clean
  samples). Accepted only in that form: one such entry, at most 16 KB,
  valid JSON of exactly that shape, at most 32 rows. Another named kind,
  another name, a second entry, another field, text behind the JSON:
  refused as before. (The record's checksum is not compared with the
  archive: the scanner reads the archive itself.)
- **Still scanned, outside the acceptance:** the texts of the resource
  section; what stands in the signature's area (`SIG-DATA-001` / `-002`,
  as for every program).

What it does not say: that the game is harmless. The runtime runs whatever
code the app brings - `resources/app`, `app.asar`, native `.node` add-ons -
and that is read on its own. The findings a verified runtime has are hidden
as "official Electron program with other resources"; **its attack chains
are not formed at all** - the import table of a browser engine has a key
hook, a credential function and a network stack, and in every Electron app
that added up to two CRITICAL chains.

**Limits:** ten versions (nine 64-bit, one 32-bit); any other version is
judged as before. The resource tree is walked only to find resources with
a name of their own, and the manifest is not read: one that asks for administrator rights is not
noticed. A program of 200 MB is read to its end for the comparison (from
disk; inside an archive only when it is at hand in memory or as a
temporary file).

#### Text that describes code is not read as code

Since 2026-10-12 (phageo). Two kinds of text files come with JavaScript
programs and are never run: TypeScript declaration files (`.d.ts`,
`.d.mts`, `.d.cts` - types only) and source maps (`.map` - a table from
packed code back to its sources). The script rules and the chains do not
read them; they count as read for the coverage figure. A `.map` is taken
for a source map only when it is one (JSON with a source map's fields);
anything else under that ending is text like any other.

**Limit:** a declaration file goes by its name. A file named `x.d.ts`
that some program loads as a script by that name would not be read. No
engine does that by itself; it would need code that names the file, and
that code is read.

#### Programs of a kind the scanner does not read

Since 2026-10-12 (phageo): a Java class file (`.class`, or its first bytes)
gets the note `EXEC-FMT-001` - "program of a kind the scanner does not
read" - whether it lies in a folder or inside an archive (there as
`ARC-002`: "N program file(s) of a kind the scanner does not read (Java
class files) were not inspected"; a `.jar` is a zip and is opened). The
note is never hidden and the scan is at least REVIEW.

**Not noted, on purpose:** programs for Linux and macOS and WebAssembly
files. Every Ren'Py game ships Linux and Mac programs, and two clean
samples a `.wasm`; a note for those would put every such game at REVIEW.
The Windows scanner does not read them, and nothing says so - a known gap.

#### Packed code: one long line is not "next to each other"

Since 2026-10-12 (phageo). Packed ("minified") JavaScript keeps a whole
program on a few lines of thousands of characters. The chains by nearness
(`CHAIN-DOWNLOADER` and the others: the parts within 60 lines of each
other) then say nothing - everything is on the same line. So in a line of
more than 1,000 characters the parts of such a chain have to stand in the
**same statement** (the line is cut at `;`, `{` and `}` outside quoted
text). A download in one statement, a decoder in another and an `eval` in
a third are three findings and no chain.

A real hand-over - what was downloaded is what is run - is found as
before, in one statement or across many: that is the data-flow chain
`CHAIN-REMOTE-CODE`, which follows the value and does not go by nearness.
Ordinary lines are judged exactly as before.

**Limits:** a packed dropper whose parts are spread over statements *and*
that the data-flow reader loses (a value through an object field, another
file) is no chain now - its parts are still reported one by one, at their
own level. The cut does not know regular-expression literals: a `;` or a
brace inside one cuts where it should not, which can only split a
statement (fewer chains, never more).

#### Near each other, but no flow: `CHAIN-NO-FLOW`

Since 2026-10-14 (phageo, forty-first message; CLAUDE.md, rule 13: a
separate name only where the premise is statically disproven;
`chains.NO_FLOW`, `scanner._flowless`, `base.FLOW_READ` / `FLOW_CUT`).
`CHAIN-DOWNLOADER` and `CHAIN-FETCHRUN` say "something fetched from the
network is run". In a JavaScript file whose data-flow reading **read the
whole file** - no size limit, no step limit, no failure - **and found no
download that reaches code or a program start** (no `CHAIN-REMOTE-CODE`,
no `CHAIN-REMOTE-LOAD` in it), that premise is disproven there:

- The chain is reported as **`CHAIN-NO-FLOW`, HIGH** - "the parts near
  each other, no flow between them" -, with its parts and a note of which
  chain it would have been. In a file of a published npm package it is
  **MEDIUM** (the library mechanism of the fortieth message); in strict
  mode HIGH.
- It stands where the CRITICAL stood: a folder that is trusted for its
  name, a signature of a known but untrusted publisher or an official
  engine build lower it no further.
- **What a disproven downloader implied is not implied any more:** an
  obfuscated loader beside it (`CHAIN-LOADER`, decoding next to `eval`) is
  formed and shown on its own.
- **Unchanged:** a file the reading did not finish (it has the limit note,
  or none when it is an official or published file - the mark is kept
  either way); a file with a real flow; the other chains of nearness
  (stealer, spyware ... - no reading follows their premise); programs;
  every other language (their readings do not yet say "read to the end"
  in one place). `CHAIN-REMOTE-ARG` (a download handed to a program as
  data) does not count as a flow that runs the download.
- **Weak point:** "no flow found" is the reading's answer - a hand-over
  it does not follow (an object field across functions, another file, a
  computed name) is a flow it does not see. The parts are still listed,
  HIGH outside a published package.
- **.NET libraries** (since 2026-10-17, fifty-ninth message; phageo: "MEDIUM
  when the file is fully read, HIGH when not", for the reading of .NET
  methods): when the reading of a library's methods (`remote_cs`, "Compiled
  C#") ends without a limit and finds no download that is loaded or
  started, its chain of nearness is `CHAIN-NO-FLOW`, **MEDIUM**. A library
  whose methods were not read to their end keeps its chain as it was (a
  CRITICAL one stays CRITICAL - rule 13). A chain across two libraries is
  made after the scan and is not hidden by this. **JavaScript is not
  changed:** there the rule is the one of the forty-first message as
  recorded (HIGH, MEDIUM in a published npm file; a file not read to its
  end keeps its chain).

### One signal for the limits of the format readers

Since 2026-10-12 (`gamescan/unpack/limits.py`). Each reader of a file
format has limits - entries walked, sizes of tables and members, nesting.
Where one is applied the reader says `limits.hit(reader, what)`; the scan
watches every file and, when a limit was reached and the file has no "not
read" note of that reader's kind, makes one ("a limit of the reader was
reached: ..."). A verified official file gets none. Of the 79 named
limits 65 say so this way; the other 14 are listed in a test, each with
the reason why reaching it loses nothing that is not said otherwise. A
new limit without either fails that test. Not covered: numbers written
directly in the code, and the limits outside `unpack/`.

### Rules: API and tool names are whole words; injection without a writer

Since 2026-10-17 (phageo, fifty-ninth message; `rules._names`):

- **API and tool names match as whole words only** - never as a part of a
  longer name: `pyHook` is no hook library inside `CopyHook`, `KeyLog` none
  inside `SSLKeyLogger`, `DownloadFile` no download inside
  `CodeDownloadFiles.iss`. A letter, a digit or `$` beside the name makes it
  part of a longer one; a dot, a quote, a path separator or an underscore
  does not (`start_keylogger`, `_winreg.SetValueEx`, `_WriteProcessMemory@20`).
  (For a few hours on 2026-10-23 an underscore joined parts of a name; phageo
  took it back at that day's gate: `start_keylogger` in a script must be
  found. OpenSSL's `nss_keylog_int` in a library is found again too, HIGH.) A Windows function also
  stands with `A` / `W` at its end (its two forms; the import table check
  reads them the same), and the longer functions of a family that were
  matched before are written out (`CreateRemoteThreadEx`,
  `VirtualAllocExNuma`, `QueueUserAPC2`, `Wow64SetThreadContext`,
  `InternetReadFileEx`, `HttpSendRequestEx`, `DownloadFileAsync`,
  `CreateKeyEx`). Rules: `INJ-001`, `NET-PE-001`, `INPUT-001`, `INPUT-002`,
  the API names of `CRED-001`, `SH-DL-001`, `PERSIST-001`, `EVADE-001` and
  `RB-NATIVE-002` (`LOL-001` had word bounds already). Words that are no
  names (`token_grab`, file names, paths) are found as before.
- **`INJ-001` without a function that writes into another process is
  MEDIUM**, for every program (`scanner._injection_without_writer`):
  starting a thread elsewhere, queueing to it, unmapping or setting a
  thread's state is what debuggers, runtimes and audio libraries do with
  their own. "A writer" is `WriteProcessMemory` or `NtWriteVirtualMemory` /
  `ZwWriteVirtualMemory`, imported or named anywhere in the program's texts
  (a function found by name at run time counts).
- **Engine files inside archives and installers are checked by content,
  wherever they sit there** (`renpy_engine.status` / `compiled_status`):
  a Ren'Py script that is, by its SHA-256 (or, compiled, by what it
  contains), an official one is the official one inside a zip or an
  installer too - its updater's chain is hidden as on disk. A member that
  is not official is no engine file (no folder can be asked which version
  it is), as before; a loose file is an engine file by its folder, as
  before. (Programs and the other tables were looked up by SHA-256 wherever
  they sat already.) A compiled script is compared by its content only
  under a `renpy/` or `lib/` folder (the comparison costs a decompression).

### Rules are tried only where a match can begin

Since 2026-10-13. Measured first (Python's `cProfile` on the three slowest
clean samples): **more than half of the time of a scan was the rules' own
search of the text** - 128 of 236 seconds for ELE-01, 58 of 93 for MZ-01 -
and most of that four rules whose patterns are long lists of alternatives
(`PERSIST-001`, `CRED-001`, `EVADE-001`, `LOL-001`): the search tries every
alternative at every character.

For 60 of the 71 rules it can be read off the pattern how a match must
*begin*: with one of a few written-out texts (`CurrentVersion`, `schtasks`,
`reg` ...; `rules.start_texts`). For such a rule the pattern is tried only
at the places where one of those texts stands - found by a plain search of
the lower-cased text -, in the order of the places and never inside a
match already made (`rules._Places`). That is what the search over the
whole text does, so **the matches are the same ones**. The plain search is
used as before when a rule has no such texts, when a text holds a
character whose lower case is two characters (the Turkish capital dotted
I: the places would shift), when a rule would be tried at more than
200,000 places, or when a text holds more than 2,000 characters that pass
for an ASCII letter without being one (dotless i, long s, Kelvin sign,
ligatures - `rules.lookalikes`; with fewer, every place from which a start
text could reach one of them is tried as well).

- **Checked:** every rule both ways on a megabyte of text full of the
  rules' own words, also with look-alike characters put into them (tests);
  and on every text of four clean samples - 12,163 comparisons, none
  different. The benchmark's two result files are byte for byte the ones
  from before.
- **Effect** (the 23 clean samples, scans alone, three at once): 906
  seconds before, 597 after. ELE-01 269 -> 167 s, MZ-01 101 -> 38 s, MV-01
  65 -> 28 s.
- **Not done:** the eleven rules without start texts (`OBF-CAT-001` and
  `JS-OBF-004` are the costly ones) are searched as before; so are the
  whole-script passes of the JavaScript download-and-run reading (about a
  second each on 4 MB).

### JavaScript: quoted text is not code

Since 2026-10-13 (phageo; `rules.QuotedText`). In a script file (`.js`,
`.mjs`, `.cjs`, an encoded `.jse`, and code the data-flow reading decoded)
a word inside a string literal, inside the text parts of a template
literal or inside a comment is **never a call site**: a match of a
call-site rule (`JS-EXEC-001`, `JS-OBF-002`, `JS-OBF-004`, `JS-PROC-001`,
`JS-PROC-002`, `JS-NET-001`, `JS-FS-001`, `JS-ENV-001`) that begins there
is kept as a hidden finding ("Match is inside a quoted text of the script,
not a call") and forms no chain. The case it was made for: a clean game's
code editor carries TypeScript's description files as quoted texts -
`fetch(`, `atob(` and `WScript` in one statement of three million
characters, which was a CRITICAL `CHAIN-DOWNLOADER`.

- **What stays code:** `${...}` inside a template (also nested); a call
  that begins in code and takes a text (`require("child_process")`, `new
  ActiveXObject("WScript.Shell")`); and every quoted text inside the
  brackets of a call that runs text - `eval`, `new Function`,
  `setTimeout` / `setInterval`, `execScript`, `vm`'s `runIn...Context` /
  `Script` / `compileFunction`, `document.write`, `importScripts`,
  `insertAdjacentHTML`.
- **Text that reaches such a call another way** - through a name, built
  from pieces, decoded - is found by the data-flow reading, which hands
  the rules what it resolved (`eval(atob(...))` hiding a `fetch` is a
  chain as before).
- **Where the reading of quotes cannot be sure, it is code:** a quote not
  closed on its line opens nothing, a template that is never closed is no
  text, a regular-expression literal is stepped over and counts as code.
  CRITICAL rules are never hidden this way (rule 13), as inside a comment.
- **Unchanged:** rules that look for a text - an address, the name of a
  system tool (`LOL-001`), a store path - read quoted texts as before;
  HTML pages and JSON data files are read as before (a "Script" command
  in a game's data file is a text that is run).
- **Weak points:** text that is run by a way not on the list above or
  below (a worker made from a text blob, a `script` element given text)
  is not a call site any more unless the data-flow reading follows it; the reading
  of quotes is a lexer, not a parser - a regular expression that is not
  recognised as one can open a quote.
- **Cost:** one pass over a script that has a match of a call-site rule
  (0.4 s on 4 MB).

### JavaScript: a text of the script that is run as a program (`CHAIN-TEXT-RUN`)

Since 2026-10-13, late (phageo: "quoted text does not count on its own; text
written to a file that is then started is followed" - after a real sample
lost its CRITICAL chain to the section above). Two ways are followed, both
reported as `CHAIN-TEXT-RUN` (HIGH - helper and update scripts are written
the same way), and in both the text is then **read like a script of its
own**: by the rules of its language and by that language's
download-and-run reading. Their findings stand at the line of the write or
the start and say where they were found; what the text does decides the
rest (a download that is run inside it is `CHAIN-REMOTE-CODE`, a download
next to a decoder and a start is `CHAIN-DOWNLOADER`, as in any script).

- **Written to a file that is then started** (`remote.written_and_started`):
  a string, a constant, a template, pieces put together, that reaches
  `fs.writeFile` / `writeFileSync` / `appendFile` or a stream of
  `createWriteStream`, and whose file then reaches `child_process`, the
  shell's `openPath` / `openItem` / `openExternal`, `require`, or the
  Windows Script Host. "Reaches": the start names the variable of the
  write's path - the same variable, not the same word in another function
  -, a name that variable was put into (`args = ["-File", p]`,
  `args.push(p)` - two steps), or the file's name. The language is the one
  of the file's ending (`.js`, `.bat` / `.cmd`, `.ps1`, `.vbs`, `.py`,
  `.rb`, `.sh`; a program or an unknown ending: read as plain text;
  `require(file)` and `node <file>` mean JavaScript).
- **Handed to a script runtime as its program** (`inline_programs`;
  confirmed and scoped by phageo on 2026-10-14): a command line the
  data-flow reading resolved in which a script runtime gets the text
  behind its code flag - Node.js / Electron / the running program itself
  (`process.execPath`) with `-e` / `--eval` / `-p`, PowerShell with
  `-Command` (or a short form of it), Python with `-c`. No file is
  written at all. Only these runtimes and flags: `cmd /c`, a file
  argument, or another program's `-e` is not this.
- **Where the reading cannot put the written value together** (a function
  that returns the text, `.replace()`, a property, a buffer, a tagged
  template, lines pushed one by one) the quoted texts of the expressions
  the value is made from are taken as they stand (three names deep, 60
  expressions) - only for a file that is a script or a program by its
  ending or by how it is started.
- **No chain:** a file with the ending of data (`.json`, `.txt`, `.log`,
  `.ini`, `.xml` ...: a configuration written before a fixed program is
  started with it); with an unknown ending, a text that is JSON or a value
  made by `JSON.stringify`; a text shorter than eight characters; a file
  that is written and never started; another program's `-e` switch.
- **Limits:** eight texts per script, 1 MB per text, the JavaScript
  reading's 4 MB and its step count (`SCRIPT-LIMIT-001` when cut).
- **Weak points:** JavaScript only; "reaches" goes by names in one file -
  a path handed through other functions or files is not followed; a text
  built by code the reading cannot follow and not written out in quotes
  (decoded at run time) is not seen here (the payload reading may);
  PowerShell's or cmd's inline text (`powershell -Command <text>`) is
  read by the shell chain as before, not by this.

### JavaScript: how exactly a download is followed

Since 2026-10-14 (phageo, after a clean launcher's 13 MB bundle gave eight
CRITICAL `CHAIN-REMOTE-CODE` from one web request for a list). The reading
in `dataflow/remote.py` follows the answer of a request by names; these
make it more exact:

- **Words of the language are never names** (`void`, `typeof`, `await`,
  `new`, `undefined` ...; `_KEYWORDS`). `x = void 0` had made `void` a
  marked "name".
- **A variable that is taken apart has a scope** (`const { data } = ...`,
  `let [a, b] = ...`). Until then such a name belonged to nobody - and so
  was the same variable in every function of the file.
- **A function whose parameters are taken apart, or have `{}` as a
  default, is a function** (`(command, args, options = {}) =>`, `async
  run({ id })`). Its parameters are its own; before, they were taken for
  the same-named variables around it.
- **One property is marked, not the whole object:** `x = { a: response }`
  marks `x.a`. `x.other` and `x.method()` are not the response. The object
  still carries the mark where it is handed on whole (`resolve(x)`,
  `return x`, `send(x)`). A computed key (`{ [k]: v }`, `x[k] = v`), a
  spread, or an object made inside a call still mark the whole thing.
- **A method's result marks `this.name()` only in its own class** (this
  was already so; a test holds it now).
- **For a process start it matters what is downloaded** (`_started`):
  the command text of `exec` / `execSync`, the program of `spawn` /
  `execFile` / `fork`, anything when the start goes through a shell
  (`shell: true`) - and, added here, anything when the program is itself
  one that runs what it is given (`cmd`, `powershell`, `node`, `python`,
  `wscript`, `rundll32` ...) - is `CHAIN-REMOTE-CODE`, CRITICAL, as
  before. `spawn` / `execFile` **without** a shell, with a program that is
  not downloaded, where only an argument, the environment or the folder
  is downloaded: the new `CHAIN-REMOTE-ARG`, **HIGH** - data handed to a
  program, not a program.
- **A download that is written and then started** needs the same
  variable in the write and in the start, not the same word in two
  functions.
- **A mark belongs to one variable** (since 2026-10-15, phageo, forty-seventh
  message: `RemoteFlow._binding`, `_own_names`): a name stands for the
  declaration it is bound to - the innermost function that has it as a
  parameter, or declares it itself (`var` / `let` / `const`, also taken
  apart; `function name`; `class name`; `catch (name)`) - and a use counts
  only when it is bound to the same declaration as the mark. Until then a
  mark covered every same-named word in the stretch of its function, and
  only a parameter of an inner function stopped it.
- **The modules of a webpack 5 bundle are functions** (since the same day):
  webpack 5 writes each module of its table as a method named by its
  number (`625764(e, t, n) { ... }`), which was not seen as a function - so
  every module's `var r = n(...)` stood in one scope with all the others,
  and one mark on `r` was a mark on the `r` of a thousand modules. That,
  not the reused names alone, is why ELE-01's app bundle never finished
  (measured: with the binding rule alone the marks still ran into their
  cap of 3,000; with the modules seen as functions it ends after 8 marks
  and 1,431 steps).
- **Weak points:** still a reading by names and braces in one file. The
  narrower scopes can lose a real flow that only held because two
  different variables had one name; a block's `let` / `const` counts for
  its whole function, and a name bound nowhere in the file is one variable
  for the whole file; "the program is not downloaded" does
  not look at what the started program does with its arguments.

#### The file of a download, followed to where it is started

Since 2026-10-14 (phageo, forty-second message: "follow a file path from a
download write through checks to a process start - variables, fields,
promise results"; `RemoteFlow._path_runs`, `_path_back`, `_name_back`,
`_parameter_back`, `_callback_back`, `_results_back`, `_field_back`,
`_call_around`, `_checked`; `DownloadPathTests`). An updater rarely starts
what it downloaded in the same statement: the path goes to a function that
checks the file, comes back through a callback or a promise, is kept in a
field. Found as seen in ELE-02, whose `CHAIN-NO-FLOW` was wrong for that
reason.

- **Download writes:** `writeFile` / `appendFile`, a stream of
  `createWriteStream` fed by `.pipe()`, `.write()` or - new -
  `stream.pipeline(download, ..., file)`, the Script Host's
  `SaveToFile` / text files; the written content must carry a download's
  mark.
- **From every start backwards** (what `child_process`, the Script Host,
  `require(file)`, `openPath` ... are handed; callbacks are skipped):
  through a variable to what it is given in its scope; through a parameter
  to the arguments of the calls of that function by its name; for a
  function written as an argument, to what the function it is handed to
  calls it with (also when that one hands its callback on to a third
  function); `.then(f)` to what the promise settles with; a call of a
  function of the file to its `return` and `resolve(...)`; `this.x` to
  what it is given in the same object. It ends when the expression is the
  downloaded file - the same path once read (`/` and `\` alike, any case),
  the same file name with an ending, or the variable / field the download
  was written through.
- **What it gives:** the dropper `CHAIN-REMOTE-CODE` as before (level
  unchanged - the self-update policy is phageo's to decide), with the way in
  the evidence (`followed: argument of check -> ... -> argument of
  install`). Every way found (up to eight) is kept: `Hit.ways`, and how
  many of them pass a **signature check** (`Hit.checked_ways`). Since
  2026-10-15 (phageo, two messages) a signature check is **a real crypto
  verification** - PowerShell's `Get-AuthenticodeSignature` in a command
  the script starts (`exec`, `execFile`, `spawn`, their `Sync` / promise
  forms), `WinVerifyTrust`, the check of a verified updater library
  (`verifySignature` inside a file of `electron-updater` that the npm table
  verifies; `remote.UPDATER_PACKAGES`), or **the verify call of a crypto
  library with a public key written out in the app** - `openpgp.verify`
  (its `verificationKeys`), node's `crypto.verify` (third argument) or
  `createVerify(...).verify` (first argument); the library is the name
  `require` / `import` gives `openpgp` or `crypto`, and the key is a text
  of 64 characters or more reached through names given one value, `await`,
  a list and the readers `readKey` / `createPublicKey` / `Buffer.from`
  (`_crypto_kind`, `_constant_key`, `_one_value`) - a key fetched or read
  from a file is none. **And the start must be reachable only on success
  (polarity):** in the branch of a condition that holds only when the check
  passed, in the `else` of one that holds only when it failed, behind
  `if (...) return / throw` that leaves when it failed (in the same block),
  or behind a check that throws when it fails (`await
  result.signatures[0].verified`, an awaited `openpgp.verify` with
  `expectSigned: true`) in the same block (`RemoteFlow._checked`, `_gates`,
  `_answer`, `_under`, `_implies`, `_atom`, `_throws_before`). Which way an
  answer points is read per kind: the text Windows prints (`"Valid"`),
  `0` for `WinVerifyTrust`, `null` for the updater's check, `true` for a
  crypto verify, an OpenPGP result's `.valid` / `.verified`; `&&`, `||`,
  `!` and comparisons with literals are read, anything else is "not known"
  (no check). The answer is what the started command hands back (its
  callback's parameters, `.then`, the variable it is given to) or what the
  check call gives back - also one step on (`const ok =
  out.includes("Valid")`, `const { verified } = result.signatures[0]`). A
  start on the failure branch is no check; neither is a function only named
  like a check. A call back that hands a plain `false` never enters `if
  (ok) { ... }` and is no way to what stands there (`_flag_of`,
  `_hands_false`). The
  check's own start of PowerShell - a written-out command that is only
  `Get-AuthenticodeSignature` (with `.Status`, `| ConvertTo-Json` or
  `| Select-Object` at most), the file's path as its one quoted part not
  written out - hands the file to Windows and runs none of it: it is no
  start of the file (`_only_check`, `_CHECK_ONLY`). Measured by
  `tools/download_runs.py` and the runner's `--download-runs`.
- **Limits:** ten hand-overs per way, 4,000 expressions per file
  (`_PATH_TOTAL` - reaching it makes the limit note), 400 starts, twelve
  callers per function, eight assignments per variable; a function is
  found by a name with one definition in the file.
- **Weak points:** one file; a function called through an object
  (`updater.install(file)`) or found by two definitions is not followed;
  which way an answer points is read from the text, not run - a condition
  it cannot read (a ternary, `?.`, a call with arguments on the answer)
  makes no check; an answer handed to another function before the condition
  is not followed (the hand-over after the condition counts); a hash
  comparison is not a signature check; whether the key written in the app
  is its maker's is not read; the same file name in two folders counts as
  the same file. (Whether the crypto library is the genuine one is read
  after the scan since 2026-10-15 - the next section.)

#### A check carried by a marker file, and the checked self-update (`CHAIN-SELF-UPDATE`)

Since 2026-10-14 (phageo, forty-third message: "every way to the start must
pass a signature check (strict); same host / HTTPS / constant URL alone are
not enough"; `RemoteFlow._way_checked`, `_gated`, `_guards`,
`_marker_checked`, `_branch_checked`, `_callback_calls`;
`dataflow/self_update.py`, `Scanner._join_updates`; `CheckedSelfUpdateTests`).

- **A marker file.** An updater may check the download in one run and start
  it in a later one: after the check it writes a small file
  (`{ is: "ready" }`), and the start happens only when that file says so.
  A way counts as checked through such a marker when the start stands
  behind a guard on a value read from the file (`if (s.is !== "ready")
  return`, or inside `if (s.is === "ready") { ... }`, `s` given only what
  `readFileSync(<the file>)` returns or text without that value), **and
  every** write of that file in the script that gives it that value stands
  after a signature check - in the same function, or in the `if (ok)`
  branch of a callback whose every call that does not hand it a plain
  `false` stands after one (also where the callback is handed on, three
  hops). Not checked: no such write at all (anyone could have put the file
  there), one write without a check, or any write of the file that is not
  read (a stream, a copy or a rename onto it, `appendFile`, `open`).
  ELE-02's third way is checked this way.
- **The checked self-update.** A dropper `CHAIN-REMOTE-CODE` becomes
  `CHAIN-SELF-UPDATE`, **MEDIUM** (the launcher asks once), only when all
  hold: a downloaded *file* is started (not downloaded code run); **every**
  way the reading found passes a signature check; the script was read to its
  end (no limit note, no failed reading, not code decoded out of it); the
  server is written out or comes from a JSON settings file packed with the
  app (`require("./config.json")`); HTTPS; and the server has the same last
  two names as one the app names for itself (its `package.json`:
  homepage, repository, bugs, author, the updater's `publish`; an
  `app-update.yml`). Only for the scripts of an Electron app (its settings
  files are kept during the scan: 256 KB each, 2,000 per scan, none under
  `node_modules`). Anything else stays CRITICAL, and the evidence says what
  was missing ("not a checked self-update: ...").
- **The crypto library must itself be verified** (phageo, 2026-10-15,
  forty-sixth message; `self_update.libraries`, `crypto_package`,
  `remote.Hit.checks`, `RemoteFlow.relied`, `Scanner._app_libraries`): a
  check made with `openpgp` counts only when the app's own
  `node_modules/openpgp/` holds at least one script file and **every** one
  is, by its SHA-256, a file of the published npm package (the npm table);
  a check made with node's `crypto` counts only when the app's Electron
  program is verified by the Electron table. A folder only named `openpgp`,
  a changed or added file in it, a copy bundled into the app's own script,
  or an unverified runtime: CRITICAL, with the reason in the evidence.
  Windows' own check (`Get-AuthenticodeSignature`, `WinVerifyTrust`) needs
  no library. Which kinds of check a file relies on is kept for the whole
  file, so one library that is not verified undoes the file's other checks
  of that kind too. Not worked out: which of several copies `require` would
  load - every copy in the app must be the published one.
- **What is folded into it** (phageo, 2026-10-15, forty-fifth message;
  `Scanner._fold_update`, `remote.Start.via`): once the checked
  self-update stands, the findings of that same path are hidden with the
  reason "Part of the app's checked self-update" and named in its
  evidence - the start of the checked file (`DF-CMD-001` / `LOL-001` on its
  line, and on the line of the check's own PowerShell), the `child_process`
  import it needs (`JS-PROC-001`) and the "download and run" chain of
  nearness made of them (`CHAIN-FETCHRUN`). **Other dynamic parts keep their
  level:** the import and the chain fold only when every other
  `child_process` start of the script is a fixed program or made of the
  app's own values; with such starts left, the import is MEDIUM (what they
  make it), and one start with a part from outside keeps it HIGH. The
  shell's `openExternal` and the Script Host are not `child_process` and do
  not count for the import. ELE-02: SUSPICIOUS -> REVIEW.
- **Weak points:** the checked file and the marker lie where the app puts
  them (the temporary folder, as a rule) - another program could change
  them between the check and the start; "the same last two names" is too
  loose for a shared domain (`co.uk`, a hosting service); the fold goes by
  lines and finding names in the one script, not by a flow of its own.

### Speed: 7-Zip's BCJ2 filter

Since 2026-10-15 (phageo, forty-fifth message; `sevenzip.bcj2`, `_CALLS`,
`_JCC`, `_WINDOW`; `test_7z_bcj2_is_byte_for_byte_what_it_was`). BCJ2 - how
7-Zip packs program code, used by the inner archive of electron-builder
installers - was most of ELE-04's 7z time: every jump opcode cost a search
with a look-behind and a copy. Now the opcodes of each 4 MB of code are
listed by two plain searches, only the places where a moved operand goes
back are kept, and the output is put together once. The range-coded bits
are decoded exactly as before. ELE-04's 16 BCJ2 folders: 38 s -> 7 s (the
225 MB one 26.8 s -> 5.3 s), every output byte for byte the old one's; a
test compares the two on random code full of opcodes, cut at any size and
damaged.

### Speed: one reading per text, and no download reading without a place to reach

Since 2026-10-14 (phageo, forty-second message; `rules.shared`,
`textflow._Parse`, `remote._Parse`, `RemoteFlow._has_sink`).

- **One shared reading per text.** A JavaScript file is read by the rules
  and by five data-flow readings; each masked its comments, found its
  quoted texts and cut it into functions again. What depends on the text
  alone - the comment mask, the text with strings blanked, the quoted
  texts, the brace depths and line starts, the function table, which
  function declares which name, where every name stands and where it is
  given a value - is now kept by the text's content for the last few texts
  (12 results; texts under 64 KB are read again) and dropped at the end of
  a scan. None of it counts steps, so where a reading stops and what it
  finds do not change. (For Python, Ruby and the shells the places a name
  is given a value count steps; each reading finds them itself.)
- **A sink gate.** A text with no place a download would have to reach -
  no code that is run, no WebAssembly, no loader or script element, no
  `child_process` / Script Host, no file written beside something that
  starts or loads a file - gets no download-and-run reading. It could find
  nothing. **The one difference in results:** such a text that used to
  stop at the reading's step limit no longer gets that limit note, and
  counts as read to its end (so `CHAIN-NO-FLOW` can apply there).
- **All text rules from one index per text** (phageo, forty-third message;
  `rules._Places.has` / `_where`). Each start text and each required
  literal of the rules is looked for once per text, whichever rules share
  it. (A single combined pattern of all start texts was measured first: in
  Python's regular expressions it was slower - 3.5 s against 2.0 s for the
  162 texts on a 19 MB script - so the index is the one pass.) Found on the
  way: one character whose lower case is two characters (the Turkish dotted
  capital I) in a text made every rule search the whole text plainly - 65
  of ELE-01's 94 seconds of rules. The text is now lowered with that
  character kept in its place; it is a letter look-alike, so the places
  around it are tried too. The same matches (tests compare both ways).
- **Kept readings of the official tables' larger files**
  (`gamescan/known_findings.py`, `known_findings.json.gz`,
  `tools/build_known_findings.py`). A file of a published npm package or of
  an official Electron release (exact SHA-256) of 128 KB or more is read
  once when the tables are built - twice, under two unrelated paths, and
  kept only when both readings agree. A scan gives that reading back
  instead of reading the file (its name checks, the judging of each
  finding, the chains and the joins run as for any file - the findings are
  shown as before). Used only for the same reader, file ending, baseline
  and size, a file read whole, and the same notes before the reading; tied
  to the code's fingerprint (SHA-256 over every source file of the
  package): after any change of the code it is not used - the file is
  read as usual, slower, never different. The builder runs once, in the
  gate at the end of a session, and before a release (phageo, 2026-10-15);
  until then the test of the kept readings skips with a note. Not covered:
  the app's own program (the Electron runtime under the app's name differs
  from the official file by its resources). Part of the package, made from
  official files only - not a cache a program on the PC could write to.
- **The flow readings' searches where a match can begin** (phageo,
  2026-10-15: "the three flow checks in one traversal per text with
  combined sinks, outputs byte-identical"; `rules.find_all`,
  `_Places.find_all`, `_finder`, `text_places`; `textflow._js_calls`,
  `_js_computed`; `remote._functions_in`; `FlowSearchTests`). The payload
  reading, the download-and-run reading and the program starts each
  searched the whole text for their sinks and sources with patterns that
  begin with "not after a letter" - the search tries those at every
  character (on ELE-01's 19 MB bundle: 8.8 s for eval-like calls that
  matched 3 times). Now one index per text, shared by the three readings
  and the rules: each written start text is looked for once, an
  alternative that begins with a written-out character is found by the
  fast search, and a pattern is tried only at those places, in order and
  never inside a match already made - exactly the matches of the plain
  search. A pattern none of whose required texts stands in the text is not
  searched at all. Calls that begin with up to five `name .` parts (`a.b.
  exec(`) are found from the called name backwards; the function table
  from `function`, `=>` and `) {`. Four patterns that begin with any name
  are still searched plainly. The readings themselves are unchanged (one
  reading per kind, as before); compared on ELE-01's three bundles and
  ELE-02's script: the same matches, the searches 3 to 7 times faster.

### Electron: a page that loads a script by its address

Since 2026-10-14 (phageo; `dataflow/electron_windows.py`,
`Scanner._join_windows`). A page (`.html`) inside an Electron app's own
files (`resources/app`, `app.asar`) that loads a script from a remote
address was always `CHAIN-REMOTE-CODE`, CRITICAL. What that script can
reach depends on the window the page is shown in, so after the app's
scripts were all read the finding is judged by it:

| The window | Finding |
| --- | --- |
| `nodeIntegration` on (also for workers / sub-frames) - and only that | `CHAIN-REMOTE-CODE`, **HIGH**, tagged "real behaviour of the app" (phageo, 2026-10-17, fifty-ninth message: the app's own setting gives the page Node.js) |
| `contextIsolation` off; or a preload script that hands the page functions and itself starts programs, runs text or writes files, with `sandbox: false` | stays `CHAIN-REMOTE-CODE`, CRITICAL (the window is named) |
| a preload script that hands the page (`contextBridge.exposeInMainWorld`) a function reaching a sink - in itself, or through a message whose handler in the main process (`ipcMain.on` / `handle`) starts programs, runs text or writes files -, or a message channel of the page's choice (or the channel object) when a message handler passes the message's data on to a sink, or what the handlers do cannot be read in full (next-but-one section); settings that are not a written-out `true` / `false`; an Electron version that is not known; a preload script that is not found; no window found | `PAGE-REMOTE-SCRIPT`, HIGH |
| no Node.js in the page, isolated, and nothing handed over that reaches a sink - also a message channel of the page's choice when no message handler of the main process passes a message's data on to a sink (since 2026-10-15) | `PAGE-REMOTE-SCRIPT`, MEDIUM, no chain - a remote script as in any web page |

- **A setting that is not written** is read by the defaults of the app's
  Electron version: `nodeIntegration` off since 5, `contextIsolation` on
  since 12, `sandbox` on since 20. The version is the one of the app's
  runtime program **when the runtime table verified it** - an unknown or
  changed program gives no version, and then nothing is taken for granted.
- **Which window:** the one whose `loadURL` / `loadFile` names the page's
  file; when that cannot be read, every window of the app, and the most
  open one counts.
- **Only Electron apps:** a page anywhere else (an NW.js game's page has
  Node.js) keeps its finding.
- **Weak points:** a reading by patterns - a window built by a helper
  function, settings merged from several objects, a `<webview>` tag or a
  page opened by `window.open` are "not known" at best; a handler is
  followed one function deep; scripts the page loads from the app's own
  files are not judged here (but see the next section). `webSecurity:
  false` is not looked at.
- **A script element that a script makes** (`s = document.createElement
  ("script"); s.src = "https://..."` - phageo, 2026-10-17, sixtieth message;
  `Scanner._join_script_elements`): the same remote script, but loaded by
  one of the app's scripts. Its window is named only when every page that
  loads that script (by `<script src>`) is shown by a window found in the
  app. Such windows decide as above, except that every case but "more than
  Node.js" is HIGH: `contextIsolation` off or a preload script that starts
  programs without a sandbox keeps it CRITICAL; Node.js on, bridged, not
  known, shut in - and **a window that cannot be named at all** -
  `CHAIN-REMOTE-CODE` **HIGH**, tagged "real behaviour of the app" (the
  evidence says "the window it runs in: not identified (a script element
  made by a script)"). Why at most HIGH: the page's remote script with
  Node.js on is HIGH (fifty-ninth message), so one whose window is not
  even known is no worse. Only for a script element given an address; a
  script element given downloaded text (`s.text = ...`) is unchanged, and
  so is any such script outside an Electron app's own files.

#### A page's own script that loads code (`RENDERER-CODE-LOAD`)

Since 2026-10-15 (phageo, forty-seventh message; `Scanner._join_renderer`,
`electron_windows.page_scripts`, `base._renderer_mark`). A JavaScript
`CHAIN-REMOTE-CODE` or `CHAIN-REMOTE-LOAD` whose sink loads code -
`import()`, `eval`, `new Function`, a `Worker` / `SharedWorker`,
`importScripts` - in a script of an Electron app's pages becomes
**`RENDERER-CODE-LOAD`, MEDIUM**, when that script runs only in windows
whose pages are shut in (the "shut in" row above: no Node.js, isolated,
no preload function that reaches a sink). The chain's premise - that the
code reaches the PC - is then disproven (rule 13). Where the script runs
must be known in full, otherwise the finding stays as it was:

- the script is a page of the app, or a page of the app names it in
  `<script src=...>` (by file name);
- the app's `package.json` was read, and the script is not its `main`, nor
  any window's preload script;
- every page that runs it is shown by a window found in the app's scripts,
  and each such window is shut in.

A process start, a dropper, WebAssembly or a script element keep their
level. What a page sends to the main process stays external to whatever
the main process starts (as before). **Weak points:** pages and scripts
are matched by file name only (two files of one name in different
folders count as one); a script that another page script imports, or a
worker file, has no known window and keeps its finding.

#### What the main process does with the pages' messages

Since 2026-10-15 (phageo, forty-eighth message; `dataflow/electron_ipc.py`,
`Scanner._ipc`, `electron_windows.judge`). A preload script that hands the
page a message channel of its choice (`send: (channel, data) =>
ipcRenderer.send(channel, data)`) lets any script of the page send any
message. The window still counts as shut in when **no** `ipcMain.on` /
`once` / `handle` handler of the app passes a message's data to a process
start (`child_process`, `execa` ...), a code load (`eval`, `new Function`,
`vm`, `require` / `import()` of a name not written out, `process.dlopen`, a
`Worker`), the shell's open (`shell.openPath` / `openItem` /
`openExternal`; an address written out as http(s) is a browser open) or a
file write whose path is then started (a start of the app names a text or
a name of the written path). The data are the handler's parameters after
the event, and the reading follows them through assignments, taken-apart
objects and spreads, `for ... of`, functions of the same script (also one
wrapped like `debounce(async (a, b) => ...)`), functions of the app's own
modules (`require("./storage")`), a promise (`resolve(data)`: what the
function around the promise gives back) and fields of objects that are not
the function's own (`window.gameInfo = {...arg}`: every `.gameInfo` read in
the main process carries it). The main process is the app's main script
(`package.json`), every script with a message handler and the app's own
modules they `require`; pages, workers and preload scripts run elsewhere.

**Not known - so not shut in:** a handler function that is not found;
data handed to a function the reading does not find (a parameter, a
computed call `table[key](data)`); the main script not known; a module of
the main process not among the scanned scripts; a script with handlers
over 1 MB; more than 16 MB of the app's scripts; a part of the app that
could not be read (`UNREAD_CONTENT`); its limits (20,000 readings and 8
hand-overs per handler). The reason in the finding names the handler and
what it reaches (`the handler of push-game-ready (main.js, line 167):
opens a file with the shell (menu.js, line 196)`), or why it is not known;
a write that nothing starts is said too. **Weak points:** a reading by
names, not a parser - two variables of one name in one function are one
(that only adds data); a function of a published package is a library,
and only one named like a sink counts (`exec` from `child_process`,
`spawn`, `openPath` ...); `executeJavaScript` runs in the page and does not
count; a function handed on as a value and called elsewhere, getters /
setters, `Reflect` / `Proxy`, a field written through a computed key, and a
main script bundled so that its modules call each other through the
bundler's own `require` (their calls are "not known"). A message channel
named by the page is judged this way only when the preload hands on a
channel of the page's choice; a preload that names its channels is judged
as before (by the handlers of those channels).

### JavaScript: severity by flow, not mention

Since 2026-10-14 (phageo; `ContextEngine._by_flow`, `remote.starts`). Two
HIGH findings of a JavaScript file (`.js`, `.mjs`, `.cjs`) were made by a
word alone; they now look at what the data-flow reading knows about the
file's process starts. **Lowered to MEDIUM, never hidden**, and the
finding says why; chains are made as before (they do not look at levels).

- **Every process start is given a kind** (`child_process`, the Windows
  Script Host, the shell's `openPath` / `openExternal`): *constant* - a
  written-out program, written-out arguments, no shell (`spawn` /
  `execFile` / `fork`); *script runtime* - the program is one that runs
  what it is given (`cmd`, `powershell`, `wscript`, `mshta`, `node`,
  `python` ...); *shell* - `exec`, `shell: true`, the Script Host; *not
  constant* - the program or an argument comes from somewhere else.
- **`JS-PROC-001`** ("can start programs") is MEDIUM when the file has at
  least one start and every start is *constant*. A script runtime (with
  constant code too), a shell, an argument that is not written out, or
  `child_process` asked for with no start to be seen: HIGH as before.
- **`LOL-001`** (the name of a system tool in a text) stays HIGH when the
  name reaches a start: it stands in a command or a program the file
  starts (also through a variable), or the file has a start whose command
  is not written out - the text may be what is started. In a file whose
  starts are all written out and do not name it, or that starts nothing,
  the name is a word: MEDIUM.
- **Nothing is lowered** when the reading failed, stopped at a limit (a
  script over 32 MB - 4 MB until the fortieth message - or its step
  count), or left a start unread; in pages, data files, shell
  scripts and programs (judged as before).
- **A module's name in a string** (phageo, 2026-10-15, forty-sixth message;
  `TextFlow._module_uses`): "every use of `child_process` accounted for"
  counts a name in a string only as a `require` / `import` argument or
  where it can reach one - **not as an element of a list**. A quoted
  `"child_process"` that stands in a list made only of quoted texts
  (`["assert", "buffer", "child_process", ...]`, the list of Node's
  built-in modules TypeScript keeps) is no use - unless the file's code
  loads a module whose name is not written out (`require(m)`, `import(m)`),
  the only way an element of a list reaches one. Any other place (an object
  value, a call's argument, `modules["child_process"]`, a variable given to
  `require`) counts as before. ELE-01's TypeScript worker: its 5 `LOL-001`
  are MEDIUM now.
- **The shell's open** (phageo, 2026-10-15, forty-sixth message;
  `RemoteFlow._browser_open`, `TextFlow._web`): `shell.openExternal` /
  `openPath` / `openItem` handed an **http(s) address** opens a page in the
  browser - **no process start**, also not for the chains (a downloaded
  file "started" that way is no start). A file path, an address of any
  other kind (`file:`, `ms-settings:` ...) or a value that cannot be read
  is a start, as before.
- **Weak points:** "reaches" is judged inside one file - a name handed to
  another file's function that starts it is not seen (the other file's
  own findings are); a constant program is not looked at for what it is
  (`spawn("updater.exe")` is MEDIUM whatever `updater.exe` does - the
  file itself is scanned if it is in the package).

#### Where the parts of a start come from: local or not

Since 2026-10-14 (phageo, forty-first message; `RemoteFlow._local`,
`remote.Start.local`, `_LOCAL_VALUES`, `_THROUGH`, `_runtime`). A start
that is not all written out is judged by **where its other parts come
from**:

- **Local** - the app's own values: written-out text, `__dirname`,
  `__filename`, `process.env.*`, `process.platform` / `arch` /
  `execPath` / `resourcesPath`, `app.getPath()` / `app.getAppPath()`,
  `os.tmpdir()` / `homedir()`, and these passed through `path.join()`,
  `path.resolve()`, `String()`, `JSON.stringify()` and the like - also
  through a variable of the file whose every assignment is such a value
  (four steps deep, eight assignments at most).
- **Not local** - everything else: what a call returns (a download, a file
  read, a page's message over IPC), a parameter (what a caller hands in is
  not known), an object's field, a name that is never given a value here.
- **A shell command (`exec`, `shell: true`, the Script Host, the shell's
  open) or a start that is not constant, whose parts are all local:
  `JS-PROC-001` is MEDIUM**, and `LOL-001` is judged as for written-out
  starts. A constant shell command counts as local (it has no other
  parts). One start that is not local keeps the file HIGH.
- **One command only** (phageo, 2026-10-14, forty-second message;
  `remote._plain_command`, `_SHELL_OPERATORS`): a command for the shell
  counts as local only when its first word is no script runtime **and** no
  operator of the shell stands in what is written out - `&` `|` `;` `>`
  `<` a backtick `$(`. `exec("git --version")` is MEDIUM;
  `exec("git --version && git status")`, `exec("tasklist | find x")`,
  `exec("echo ok > " + file)` stay HIGH: such a line is a script for the
  shell. Starts without a shell are not affected (no shell reads those
  characters there).
- **`import()` is judged the same way** (phageo, 2026-10-14, forty-second
  message; `RemoteFlow._loads_unresolved`, `Hit.local`,
  `base.LOCAL_IMPORT`): an `import()` whose address cannot be read, in a
  file that names a remote address (`CHAIN-REMOTE-LOAD`, HIGH), is MEDIUM
  when every part of its address is local (`import(path.join(
  app.getAppPath(), "plugins", "x.js"))`); a parameter, a field or a
  call's result keeps it HIGH. Only `import()` - `importScripts`, a
  `Worker` and a script element are unchanged.
- **`blob:` and `data:` addresses of `import()`** (phageo, 2026-10-15,
  forty-fifth message; `RemoteFlow._import_text`, `_const_value`,
  `_braces`, `Hit.text_from`, `base.LOCAL_BLOB`): an address made by
  `URL.createObjectURL(new Blob([...]))` or a `data:` text - followed
  through a variable (the nearest `const` whose block holds the use) and
  through the callers of a function (`const run = (u) => import(u)`) - is
  judged by where its text comes from: a download reaches it ->
  `CHAIN-REMOTE-CODE` (CRITICAL); no download reaches it -> MEDIUM, in a
  script read to its end (otherwise HIGH as before). Like every unresolved
  loader it is shown only in a file that names a remote address.
  **Since 2026-10-15 (forty-sixth message)** the same for `new Worker` /
  `new SharedWorker` and `importScripts` (`remote._TEXT_LOADERS`) - a Worker
  of the app's own text in a script not read to its end says nothing, as
  before (an object URL was never an address there); and **a text followed
  back to its every source** - each written-out text or one of the app's
  own values above, through variables (`_text_origin`, `_local`) - is
  MEDIUM **also in a script not read to its end** (`base.LOCAL_BLOB_TRACED`):
  that is a proof the rest of the file cannot change. The backward trace
  has 20,000 steps of its own (`_LOAD_TEXT_STEPS`, `_load_text`), so a
  reading that ran out of steps still gets the same answer. A field of an
  object, a parameter or a call's result is not followed to its end: HIGH
  as before (ELE-01's app bundle: the text is the `code` field of an
  in-game script object handed in by other modules of the bundle).
- **Text that looks like `import(` is no load:** a match inside the text of
  a template literal (`` `import(${q}${name}${q}).` ``, what TypeScript's
  code fixes write) is skipped (`RemoteFlow._in_text`); a string built with
  `+` never looked like one.
- **Script runtimes are unchanged:** a command that starts `cmd`,
  `powershell`, `node`, `wscript`, `explorer` ... (the list of the
  thirty-ninth message), the command shell named by `%COMSPEC%`, or the
  app's own runtime (`process.execPath`) stays HIGH, whatever its parts.
- **Weak points:** the list of local values is a list - a value the
  scanner does not know is "not local" (HIGH), never the other way round;
  a variable's assignments are found by name in the whole file (one
  assignment from outside anywhere keeps it HIGH); a local value can still
  name a file someone else put there (a program in the app's folder is
  scanned itself if it is in the package).

### JavaScript: a value put into code text through `JSON.stringify` is a literal

Since 2026-10-14 (phageo, fortieth message; `remote.py`, `Source.literal`,
`RemoteFlow._json_literal`). `"var o = " + JSON.stringify(data) + ";"`
puts a JavaScript literal into the code, not code: when that is all of a
download that stands in code text, there is **no code chain** - `eval`,
`new Function`, `vm`, a script element's text; and given to Node.js /
Electron with `-e` / `--eval` / `-p` it is judged as **data handed to a
program** (`CHAIN-REMOTE-ARG`, by its own rule).

- **Only as a whole:** the result must not be cut or changed
  (`JSON.stringify(x).slice(1, -1)`, `.replace(...)`) and must not stand
  inside the quotes of the text it is joined to (`"'" + JSON.stringify(x)
  + "'"` - a quote in the data would end that text). The mark goes on
  through names (`s = "x=" + JSON.stringify(d); eval(s)`).
- **Not for a shell or another interpreter:** `exec("node -e " +
  JSON.stringify(d))`, `cmd /c`, PowerShell - JSON quoting is not their
  quoting; they stay code chains. Nor for `node` without a code flag.
- A mark that is not only a literal always wins over one that is.
- Measured on the library it was asked about (`xmlhttprequest-ssl` 2.1.2):
  what the reading marks reaches its `-e` text only through
  `JSON.stringify(options)`; the request body goes through
  `JSON.stringify(data).slice(1, -1).replace(/'/g, "\\'")` inside quotes
  (not the plain form, so not covered - and not marked there). The
  library's start was "data handed to a program" already; its CRITICAL is
  a chain of nearness this rule does not touch. (Since the forty-first
  message that chain is `CHAIN-NO-FLOW`, MEDIUM there - see "Near each
  other, but no flow" - and the sample is SUSPICIOUS.)

### Memory of one text (2026-10-17, fifty-ninth message)

Python keeps a decoded text in 1, 2 or 4 bytes a character, by its widest
character (one emoji makes a whole script 4 bytes a character), and the
readings hold several copies of it at once. **One text may take 128 MB**
(`models.MAX_DECODED`); a larger one is read up to there and gets
`ARC-002` "[cause: memory]" - at least REVIEW. No sample reaches it (the
largest: 94 MB). The patterns for quoted texts are written so that the
regular-expression engine keeps no record per character of a literal
(`rules._DQ`): a real sample's 47-million-character script took 5.3 GB
before, 1.5 GB since, with the same matches. The positive runner's
`--memory-where` shows, per sample, which of the scanner's functions run at
the peak (names and numbers only).

### JavaScript: read up to 32 MB

Since 2026-10-14 (phageo, fortieth message; `textflow.JS_MAX_SOURCE`,
`textflow.limit`, `remote.MAX_SOURCE`, `jswrites.MAX_SOURCE`,
`electron_windows.MAX_SOURCE`). The readings of a JavaScript file - what
reaches `exec` / the shell, download-and-run, process starts, writes,
Electron windows - read up to 32 MB (4 MB before; other languages keep
4 MB). The bundles of Electron apps are 7 to 18 MB and were not read by
them at all.

- **Measured against the other way asked for** - cutting webpack /
  esbuild bundles into their module functions, each piece read under 4 MB
  (built for the measurement, then taken out): the cut reached only
  webpack bundles (ELE-01's three), not ELE-04's 13 MB script (a Rollup
  output: one flat scope, no module functions); it made ELE-01 DANGEROUS
  with a new CRITICAL in the bundled code editor (a mark of `fetch` reaching
  `import(e)` through one-letter names - most likely a tracer false
  alarm). The 32 MB limit reaches every kind of bundle and changed no
  clean verdict. Both were deterministic (two runs each, the same result).
- **What it costs:** time - ELE-01 201 s -> 396-447 s, ELE-04 155 s ->
  231-256 s (the clean set's two big ones).
- **What it does not do:** on such a file the reading mostly stops at its
  counted steps (600,000), with the limit note - so the flow check still
  lowers nothing there. More is read, not all.

### `ADDON-DECRYPT-001`: a native add-on that can decrypt stored secrets

Since 2026-10-14 (phageo), HIGH, no chain yet. A native add-on of an app
(`.node`) whose import table names `CryptUnprotectData` - the Windows
function that decrypts what browsers, chat programs and password stores
keep for the signed-in user. **Also for an add-on that is a published
package's own file** (his decision of the same day: three of six such
add-ons in real samples are published ones) - the evidence then names the
package; only an official engine file is left out. Counted before it was
built: such an add-on was in five of eight real Electron samples and in
none of four clean ones. The evidence says how many scripts of the same
package have an active network finding. A clean app that keeps its own
login with such an add-on gets this HIGH.

### `ARC-ENC-EXEC-001`: a password zip that holds programs or scripts

Since 2026-10-15 (phageo, fiftieth message; `handlers/documents.py`). A zip
whose members are encrypted (`ARC-001`) still shows its list of entries.
When that list names a program (`.exe`, `.dll`, `.scr`, `.com`, `.msi`,
`.node`, `.sys`, `.cpl`, `.ocx`, `.pif`, `.jar`) or a script (`.js`,
`.vbs`, `.hta`, `.ps1`, `.bat`, `.cmd`, `.py`, `.rpy`, `.rb`, `.lnk`,
`.html` and their kin - `ENCRYPTED_SCRIPTS`) or, since the fifty-first
message, a further archive (`.zip`, `.7z`, `.rar`, `.asar`, `.rpa`,
`.cab`, `.gz`, `.tar`, `.iso`, RPG Maker archives ... - it hides its
content twice), the archive also gets this HIGH finding (never hidden):
SUSPICIOUS, the launcher asks for the typed word. A password zip of
pictures, sound or documents only (bonus content of a visual novel) stays
`ARC-001` alone - REVIEW. By the ending of the entry's name only.
**Limits:** zips only - a 7z or RAR archive that hides its names stays
`ARC-002`. The positive runner's
`--encrypted-count` gives the same numbers per sample (entries by kind, no
names; `tools/encrypted_count.py`, also for a clean sample's folder).

### `CHAIN-STEALER` across the members of an Electron app

Since 2026-10-15 (phageo, forty-ninth message; `gamescan/stealer.py`,
`Scanner._join_addons`). CRITICAL when **one app** - everything behind
one `resources/app.asar`, `app.asar.unpacked` or `resources/app` - holds
all three: an add-on with `ADDON-DECRYPT-001`; a script that names a
**store of a browser** (`Login Data`, `Local State`, `Web Data`,
`User Data/Default/.../Cookies`, `cookies.sqlite`, `logins.json`,
`key3.db` / `key4.db`), **of Discord** (`discord/Local Storage`, also the
canary / ptb / development folders) **or of a wallet** (`wallet.dat`,
Exodus, Electrum, Atomic, Ethereum keystore, Jaxx, Coinomi, Guarda, the
MetaMask and Phantom extension ids); and a script with an active network
finding. Generic words do not count: `discord_token`, `token_grab`,
`cookies`, `password`, `Local Storage/leveldb` alone (every Electron app
has its own), and Telegram, Steam, SSH or cloud keys. **Limits:** the
store name is read from a script's text as it stands (a name the
data-flow reading only decodes is not used - none was seen in the real
samples); that the stored data itself reaches the network is not traced;
at most 16 scripts per app and 64 apps per scan are kept. A network call
counts also when it stands in a file of a published npm package or an
official library and is lowered there (phageo, 2026-10-15: npm proves
origin, not intent) - the real samples' calls all stand in such files.
The older
`CHAIN-STEALER` (a credential finding and a network finding near each
other in one file) is unchanged.

### `CHAIN-LOCAL-DROP`: a file of the game decoded, written and started

Since 2026-10-17 (phageo; `remote_py.local_drops`, `BaseHandler.local_code`,
`gamescan/localdrop.py`, `Scanner._join_local`). A Python / Ren'Py script
reads a file of the game (`open(...)` for reading, `renpy.file`,
`renpy.open_file`, `renpy.loader.load`, `Path(...).read_bytes()`), decodes
it - Base64 (also URL-safe, Base32, Base85, Ascii85), hex, zlib, gzip,
bz2, lzma, `codecs.decode`, a text's `.decode("base64")`, XOR, other
byte-wise arithmetic, `.translate` -, writes the result to a file or
unpacks it as an archive (`extractall`, `extract`,
`shutil.unpack_archive`) and starts, imports or loads what it wrote. No
download is needed. The download-and-run reading does this with one other
source; the written file is tied to the start the same way (the path,
the text, the expression). **HIGH.** A file that is read and written
without a decoder is no chain (copying a bundled program is ordinary), nor
is a decoded file that is never started.

**CRITICAL only by proof:** once the whole scan was seen, the file the
script read is looked for by its name - a loose file of the scanned
folder, or a member of an archive of the scan (members no reader takes are
kept for this while the scan runs: in memory only, 16 MB per file, 64 MB
in all, no pictures, sound, video or fonts) - and the script's own steps
are applied to it **in memory** (at most 64 MB in, 128 MB out per step;
nothing is written to disk, run or unpacked). If the result begins as a
Windows program (`MZ` with a PE header) or is a zip whose list names a
program, the chain is CRITICAL and says so. A step that cannot be applied
again (a key that is not written out in the script, a cut `data[a:b]` whose
bounds are not written out, a decompressor or a translation of its own)
leaves it HIGH.

**A static limit, not a gap to close** (phageo, 2026-10-18, sixty-second
message): when the script cuts its data with bounds it does not write out,
the scanner does not guess them and does not try to rebuild what the
decoding would give - the chain stays **HIGH**. The same holds for a library
side-loaded from inside such decoded content: it exists only after the
decoding, so `SIDELOAD-001` cannot see it. Measured on the real Ren'Py
samples (counts only): in every one of their `CHAIN-LOCAL-DROP` chains the
in-memory proof stops at step 2, such a cut; Base64 is decoded first and the
parts are joined after.

**Limits:** Python and Ren'Py only (JavaScript, Ruby, the shell languages:
not built); one file - a script that decodes in one file and starts in
another is not joined; the file read is known by its file name only; a
7z / RAR result is not looked into; the version of a name per line is kept
for this reading only (`data = zlib.decompress(data)` is read as one step,
not one per round), the download reading is unchanged.

**Started through its folder** (since 2026-10-18, phageo's decision 1;
`remote_py._Flow._in_folder`, `_Drop.folders`, `_parents`, `_folder_ids`,
`WORKING_FOLDER` / `PROGRAM_FOLDER`). A process start (`subprocess.*`,
`os.system`, `os.startfile`, `os.exec*` / `spawn*` ...) that is not given the
written file itself still reaches it when **the folder it works in
(`cwd=`) holds a file the same script decoded, downloaded or unpacked**, or
is the folder an archive was unpacked to - or when **the program it starts
lies in the folder the script wrote that file to**. A program finds its
libraries and data files in its own folder and the one it works in, so this
is how a library is put beside a genuine program. Folders are recognised as
the paths are: the variable, the expression (`os.path.join(a, b)` without its
last part, `d + "/" + name`, `d / name`) and the text as far as it is written
out. In `CHAIN-LOCAL-DROP` such a chain is **HIGH**, and **CRITICAL** when the
script's own steps, applied in memory to any decoded file written to that
folder, give a program or a library (header only: `MZ`, a PE header, the
library mark); its title then reads "... and a program started beside it".
In the download chains (`CHAIN-REMOTE-CODE` in Python / Ren'Py) it is
**HIGH**: what was downloaded cannot be looked at. A file read in a loop over
written-out names (`for name in ('a.dat', 'b.dat')`) is tried under each name
for the proof. **Limits:** the log file (`stdout=`) and the environment
(`env=`) still never count; a folder handed in from another file, or made
from a value the script does not show, is not recognised; a command line
that changes folder itself (`cd x && run`) is not read for this.

**Together with persistence or evasion: `CHAIN-LOCAL-DROP-PLUS`, CRITICAL**
(since 2026-10-18, phageo's fix A; `Scanner._local_combined`). When a game holds
an active `CHAIN-LOCAL-DROP` that is HIGH (not proven a program) **and** an
active HIGH `PERSIST-001` (start with Windows) or `EVADE-001` (switching off
protection, anti-analysis) **anywhere in the same game**, one CRITICAL finding
is added beside the chain (one per game); the chain itself stays HIGH. Its
evidence names the rules and the files of both sides, and its text says the
two may stand in different files. **Across the game, not inside one script:**
measured on the real samples (rule ids and file numbers only), the signs never
stood in the chain's own script - 0 of 22 Ren'Py samples (10 tuning, 12
held-out); the chain is in a compiled script inside an `.rpa`, the signs in
loose `.py` files or in a library. **One game** (phageo, same day;
`Scanner._game_root`): a file unpacked from an archive or installer that lies
on disk in the scan (a `.zip` / `.7z` / `.rar` / `.cab` / `.msi`, or any file
in which an archive or installer was found) belongs to that archive's game;
every other file - a game's own data archive such as an `.rpa` included -
belongs to the scanned folder (with several targets, to the target that holds
it). So two downloaded archives in one folder, or two folders scanned
together, are never joined; two games already unpacked inside one scanned
folder are one game by this definition. No clean sample has a
`CHAIN-LOCAL-DROP`, so none is affected.

### `ENGINE-009`: a program beside a verified app runtime that nothing verifies

Since 2026-10-20 (phageo, seventy-third message, decision 3;
`Scanner._note_app_program`, `_app_program_notes`). A verified app runtime -
Electron's program (by SHA-256, or its code apart from the branding
resources) or NW.js's launcher (the same) - marks its folder. Every program
or library (a PE file; **not** a `.node` add-on) in that folder or below it
that is in no official table, carries no valid signature of a trusted
publisher and is no Windows system file gets a visible **MEDIUM** note: at
least REVIEW, the launcher asks. It works inside archives and installers too
(the folder is the runtime's place in the archive). A folder baseline does
not hide it. Why: the held-out malicious sample `c396c80d...` is an official
Electron 28.3.3 runtime, app scripts that do nothing the scanner can see, and
one more 107 KB program in no table - LIKELY SAFE before this note.

### `ENGINE-008`: a program in Ren'Py's folder that is not the official file

Since 2026-10-18 (phageo's decision 2; `Scanner._note_engine_program`,
`_note_engine_text`, `_engine_program_notes`, `renpy_engine.engine_root`,
`version_file`, `version_from`, `sdk_program`). A program or library (by its
content: a PE file - `.dll`, `.pyd`, `.exe`) in the engine's place of a
Ren'Py game (`lib/` or `renpy/` beside the engine's root) gets a visible
**MEDIUM** note when that engine's `renpy/vc_version.py` /
`renpy/__init__.py` say a version whose official files are in the tables and
the program is none of them - not a file of any official table and not
validly signed by a trusted publisher. The evidence says whether an SDK has a
program of that name (a replaced file) or not (an added one). The version is
read from those two files wherever they are in the scan, so it works inside
archives too. A folder baseline does not hide the note.

**The game's own start program** (phageo, 2026-10-18, sixty-second message;
`Scanner._renpy_program`, `engine_hashes.RENPY_PROGRAMS`, built by
`tools/build_engine_hashes.py` from the SDK archives only). A Ren'Py game
ships the SDK's start program renamed, with the game's icon. Such a program
gets no note when, with its resource section left out, it is byte for byte a
program of a listed SDK (`pe.resource_frame_key`, as for a renamed `nw.exe`),
**and** its resources hold icons, icon groups, a version and a manifest and
nothing else (no kind with a name of its own, no program inside them), and
it has no signature and no appended data. Every section's flags are part
of the comparison: a writable resource section (the GNU linker writes one,
as in the SDK programs of 7.3.5 to 8.0.3) is accepted only when the official
file has exactly the same flags (phageo, 2026-10-18; the same holds for the
renamed `nw.exe` and the Electron program, which use the same key; an
executable resource section is never accepted). Any other difference keeps
the note. Only the note is affected: the program is scanned as before and gets
no trust from this.

**Limits:** "the
official file" is any file of the official tables, not the one of exactly that
version; a program of an unlisted version, or of an engine whose version files
are not in the scan, gets nothing; Linux and macOS programs are not looked at.

### A `.rpyc` without a Ren'Py header

Since 2026-10-18 (phageo's decision 3; `RenPyHandler.scan`, `script_text`,
`content_kind`, rule `RPY-CONTENT-001`). A compiled-script name proves
nothing. A `.rpyc` / `.rpymc` with no Ren'Py header (and no old headerless
zlib form) that is **plain text** (UTF-8, no NUL, 95 % printable) is read as
the script it is - as Python when it parses as Python, else as a Ren'Py
script - with every rule and chain of a `.rpy`. Anything else is named by its
first bytes in **`RPY-CONTENT-001`**, a visible "not read" note: an archive
(zip, 7z, RAR, gzip, bzip2, xz, cabinet, `.rpa`) or encrypted / random data
(7.5 bits per byte or more) **MEDIUM**, a Linux / macOS program **HIGH**, a
picture, sound or other data **LOW**. A Windows program under that name is
taken by the program reader by its content, as before, and called a disguised
program (`NAME-002`, HIGH). Such a file is also kept for the local chain's
proof (it may be the encoded file a script decodes). A file with Ren'Py's
header that cannot be read keeps `RPY-FMT-001`.

### `SIDELOAD-001`: a library named like a part of Windows beside a program that loads it

Since 2026-10-17 (phageo; `gamescan/sideload.py`, `gamescan/windows_dlls.py`,
`Scanner._join_local`). Windows looks for a library first in the folder of
the program that asks for it. A library **named like a part of Windows**
(the 3,409 libraries of `System32` signed by Microsoft itself on the
development PC - drivers' libraries such as `vulkan-1.dll` are not in it)
**or like a Microsoft redistributable** - a fixed list of 137 names
(`windows_dlls.REDISTRIBUTABLE`: the DirectX End-User Runtimes of June 2010
- `d3dx9_24` to `_43`, `d3dx10*`, `d3dx11_42/43`, `d3dcompiler_33` to `_47`,
`xinput1_*`, `xaudio2_*`, `x3daudio1_*`, `xapofx1_*`, `xactengine*` - and
the Visual C++ runtimes - `msvcp*` / `msvcr*` 6.0 to 14.0, `vcruntime140*`,
`vcomp*`, `vcamp*`, `vccorlib*`, `concrt140`, `ucrtbase`), and by pattern
their families (`api-ms-win-*`, `mfc*` ...). Both lists live in the
repository; the scanning PC's own folders are never read for them, so the
answer does not depend on the PC (phageo, 2026-10-17). Such a library, lying in the same folder
as a program (`.exe`) that **imports it, or names it beside a
`LoadLibrary` import**, is **HIGH** - unless it is validly signed by
Microsoft or is, by its SHA-256, a file of an official table (engine,
Electron, Inno Setup, NSIS, a known library). Loose files and members of
archives and installers alike ("the same folder": inside the same
archive). A file in Windows' own folders is never one.
**The DirectX table** (since 2026-10-17; `gamescan/directx_official.py`,
built by the developer's tool `tools/build_directx_table.py` from
Microsoft's "DirectX End-User Runtimes (June 2010)" package - a row of the
manifest, fetched through `fetch.py`): 190 libraries of the package by
SHA-256, each one checked once, when the table was built, to carry a valid
signature of Microsoft; since the same day also the 10 without one - the
Managed DirectX libraries of 2006 and `dxupdate.dll` -, kept apart and
tagged "from signed package", the package's SHA-256 as their source (they
came out of the package whose signature was verified; phageo). None of
those ten is a name `SIDELOAD-001` looks at. A file in it is recognised like a
file of the other official tables, also inside an archive read in memory.
The Visual C++ runtimes have no table yet (deferred, phageo).
**Limits:** a name put together at run time is not seen; a scan in memory
(the positive benchmark) cannot check a signature, so there only the
official tables clear a library; a library inside a file that a trusted
publisher signed shares that signature (as for every finding). The
positive runner's `--sideload-count` gives the numbers per sample
(`tools/sideload_count.py`, also for a clean sample's folder).

### The fix session before 0.9-beta (phageo, 2026-10-23)

From the round-2 diagnosis (`docs/benchmark/EXPECTATIONS.md`, "Round 2
diagnosis"); the effect on the samples is in "Round 2: tuning results after
the fix session" there.

- **A load in compiled C# counts only through the argument that chooses the
  code** (`remote_cs`, `_LOAD_TWO`): the first argument of `Assembly.Load*`,
  `AppDomain.Load` / `ExecuteAssembly*`, `LoadLibrary`; the assembly and the
  type name of `CreateInstance*` / `CreateInstanceFrom` /
  `CreateComInstanceFrom`; `LoadModule`'s two. A download that is only a
  constructor argument, the program's own arguments or the domain the call is
  made on chooses nothing. The same across two libraries: each side keeps
  the argument numbers (`Shares.run_args`, `wants_args`), and a link needs
  one in both. (Unity 4.6 / 5.1: Mono's `NetworkStream` handed to
  `Activator.CreateInstance` was a false chain.)
- **Media files: the rules read only their text parts and what lies beyond
  their own structure** (`handlers/media.py`) - metadata, chunks that are not
  picture or sound, a RIFF file from a broken chunk on, data behind the end.
  The picture / sound data itself is random bytes in which short words turn
  up by chance (`{wmic[` in a `.wav`). A program hidden in it is still carved
  out; a file of a format the scanner does not recognise still goes through
  the sliding window. Not seen any more: a command line written into the
  samples or pixels themselves (a loader that pulls it out is a script or a
  program, read on its own).
- **A member of an archive or installer that is left out is said**
  (`containers.Policy.settle`): members without a telling ending were kept
  only for a program / archive head and otherwise dropped without a word.
  Now such a member gets the "not inspected" note (`ARC-002`, so at least
  REVIEW) unless it is clearly harmless data by its content
  (`containers.harmless`): padding, text, a picture or sound that is all
  media, a font, or a file of an official table. One that is too large to be
  looked at (16 MB) is said too. Text counts as data because a member under
  an ending Windows runs (`.bat`, `.ps1`, `.js` ...) is read anyway, and any
  other text runs only through something that reads it, which is scanned on
  its own. Measured first: reading every text member cost four clean games
  SUSPICIOUS (read-me texts, licence pages, language files), and telling
  scripts apart by content flagged ordinary prose. The note names the kind
  (Linux / macOS program, compiled Python, data of an unknown kind).
- **A password-protected 7z says "password"** wherever the encryption
  stands in its coder chain (it named the coder after it: "filter 030101").
- **Whole words across an underscore: taken back** at the gate (phageo,
  2026-10-23) - an underscore is no part of a name, as before (see "Rules:
  API and tool names are whole words").
- **A downloaded value handed to a fixed program that is no shell or
  interpreter is `CHAIN-REMOTE-ARG` (HIGH) in Python too**
  (`remote_py._command_kind`): `subprocess.*([program, ..., download])` with
  the program written out and not in the list of shells and interpreters
  (`cmd`, `powershell`, `sh`, `node`, `python`, `wscript`, `mshta`,
  `rundll32` ... - the JavaScript reading's list), no `shell=True`, no
  `executable=`. A command text, a shell, a program that is not written out
  and a name shared with another file stay `CHAIN-REMOTE-CODE` CRITICAL, and
  a download that is also run as code is CRITICAL beside it. **Since
  2026-10-24 (phageo) also when the list reaches the start through a name**
  (`remote_py._command_lists`): a list assigned to a name in the same
  function (`cmd = ["git", "clone", url]; subprocess.run(cmd)`), or handed as
  an argument to a function of the file that starts it
  (`self._execute(["git", "clone", url, target])` and
  `subprocess.Popen(command, ...)` inside `_execute` - HO2-01's tool). Every
  value the name can have must be such a list; a name of the file (any code
  may set it), one value that is not a list, or more values than are kept
  (16 per parameter) leave it CRITICAL.
- **Overloads of one C# method name are told apart across libraries**
  (phageo, 2026-10-24; `dotnet_il.Module.shape`, `remote_cs._meets`): the
  argument numbers that carry a download into another library and those
  that reach a load there are compared overload for overload, by the
  parameter types (`Activator.CreateInstance(Type, object[])` is not
  `(string, string)`). Before, every overload of the name was one, so a
  network stream handed to Mono's `System.dll` -> `Activator.CreateInstance(Type,
  object[])` as a constructor argument met the `(string, string, ...)`
  overload that loads by its type name - a false `CHAIN-REMOTE-CODE`
  CRITICAL in Unity 4.6 / 5.1 games (HO2-06, HO2-07). An overload whose
  types cannot be read (a function pointer, a kept reading of older code)
  is compared with every overload of the name, as before.
- **A text alone in a compiled program is MEDIUM - REMOVED** (phageo,
  2026-10-24; was `scanner._text_only`, switched off at the gate of
  2026-10-23): with it on, 45 of 51 malicious samples were at least
  SUSPICIOUS, 88 %, below the 90 % bar (EXPECTATIONS.md). A text rule's
  HIGH match among a program's strings (`rundll32.exe`, `.ssh/id_rsa`)
  stays HIGH.
