# Limits of Bagel 0.9-beta

The full list (the README has the short one).
Moved out of the old README.md word for word (phageo, 2026-10-25); the short README.md is for users.
A "see ... above / below" in the text may now point into one of the other files: `docs/HOW_IT_WORKS.md`, `docs/DEVELOPING.md`, `docs/LIMITS.md`.

## Limits

General:

- **Keyboard-hook imports (0.9 limit, phageo, 2026-10-23):** a program that
  imports `SetWindowsHookEx` gets `INPUT-001` HIGH, also when it is an
  ordinary library or engine (SDL2, an old RPG Maker runtime) - not lowered,
  because a malicious sample rests on exactly that import. Two clean round-2
  games are SUSPICIOUS by it.

- Static pattern analysis: a clean result lowers risk, it does not prove safety.
- **The local chain (`CHAIN-LOCAL-DROP`) is traced in Python / Ren'Py only,
  inside one file** (recorded by phageo, 2026-10-17): a game file decoded,
  written and started by JavaScript, Ruby or a shell script is not
  followed as such, and neither is a script that decodes in one file while
  another starts the result. (A start through the written file's folder -
  `cwd=`, or a program beside it - counts since 2026-10-18.)
- **A decoding with cut bounds that are not written in the script cannot be
  proven** (phageo, 2026-10-18): such a `CHAIN-LOCAL-DROP` stays HIGH, and a
  library side-loaded from inside such decoded content is not seen. The
  scanner never guesses the bounds or rebuilds the content.
- **Time:** since 2026-10-13 no reading is cut by a clock of seconds, so a
  script that used to be cut at five seconds is read until its count
  limit - the result is the same on every PC, and such a file can take
  longer than before (measured: at most 13 seconds for one reading). A
  file built to be slow can hold a scan for up to the ten-minute safety
  cap per reading; it then gets the limit note.
- **Real malicious samples are used since 2026-10-12** (the positive
  benchmark, "Positive benchmark: real malicious samples"; read only in
  memory by `tools/positive_benchmark.py`): 51 read samples (Ren'Py,
  Electron, MSI), with the bars "at least 90 % at least SUSPICIOUS, at
  least one third DANGEROUS". The tests themselves still rest on scripts
  and programs they construct, and how much malware outside these sets is
  caught is not known.
- Heuristics can be evaded by sufficiently indirect code: values that only
  exist at runtime, logic split across files, languages the payload resolver
  does not cover. The attack chains of `chains.py` need their signals within
  60 lines of each other; only download-and-execute is followed by data flow
  instead (JavaScript, Python / Ren'Py, Ruby, PowerShell, batch).
- Compiled Python (`.pyc`, `.pyo`): Python 2.7 files are compared with the
  official SDK and, when they are not official, their calls are rebuilt from
  the instructions and read by the rules ("Ren'Py's compiled Python") - a
  sweep that does not follow branches. Not looked at at all: compiled
  Python of other versions than 2.7, and with it those Ren'Py 8 files
  (Python 3) that are not the SDK's bytes - in the three Ren'Py 8 samples
  that is every one of the engine's own modules under `renpy/` (128 of 985
  and 155 of 1,002 files), because each is compiled again on the developer's
  PC; there is no Python 3 reader yet.
- Not inspected: .NET method bodies (IL); native code;
  `.wasm` files; individual objects inside Unity asset files; RPG Maker MV/MZ
  encrypted image/audio assets; anything downloaded at runtime.
- Real data: the benchmark samples (see "Current results"): RPG Maker
  XP, VX, VX Ace, MV and MZ games, two Ren'Py games, four installers, and
  four Unity IL2CPP sample builds (IL2-01 to IL2-04).
  Two real Unity games, both Mono, are among them since 2026-10-07 (UNI-01,
  UNI-02); no real IL2CPP game is. What is said about Unity below was
  measured on 2026-10-04 on one Unity (Mono) game that is no longer on the
  PC, and on those four IL2CPP builds. Their status: source verified
  (Cpp2IL test files), import table audited, clean on VirusTotal; not built
  by us; empty sample projects only.

Download and execute (`CHAIN-REMOTE-CODE`, `CHAIN-REMOTE-LOAD`):

- Languages: JavaScript, Python / Ren'Py, Ruby, PowerShell and batch files,
  compiled C# (.NET method bodies) and VBScript (both since 2026-10-11).
  JScript under the Windows Script Host and encoded scripts (`.vbe`,
  `.jse`) are read since 2026-10-11 as well.
  Not covered: IL2CPP games, native code, `.pyo` bytecode (its rebuilt
  calls are read by the rules and the chains by nearness, not by this
  data-flow chain). Installers: NSIS instructions and Inno Setup's
  `[Code]` / `[Run]` are read since 2026-10-11 (see above).
  Everything "detected" here was tested on constructed scripts only.
- Python / Ren'Py: one file at a time. Objects are told apart by name only,
  a reassignment does not clear a name, both branches of a condition are
  followed, and a value handed to a thread, a callback or another file is not
  followed. `pickle.loads` / `marshal.loads` on downloaded data is CRITICAL
  although a game with online saves might do it for data. Importing a module
  is only connected to a download through the file name.
- Ren'Py engine scripts: the tables hold thirteen SDK versions (6.99.12.4,
  7.3.5, 7.4.11, 7.5.3, 7.6.3, 7.7.3, 7.8.7, 8.0.3, 8.1.3, 8.2.3, 8.3.7,
  8.4.1, 8.5.3 - exact releases). 8.6.0 is not in: renpy.org publishes no
  checksum list for it. A game on any other version gets HIGH instead of
  CRITICAL for a chain in its engine folder - and so does an altered engine
  that claims such a version, because the version is read from the engine's
  own files; the launcher asks about that chain with the typed word. In the
  official updaters the chain is found in all thirteen versions, in the
  script and in its compiled form (a test reads them from the official
  archives). The verification is used for this chain and for the
  `ENGINE-003` note only; single findings in engine scripts are still
  trusted for the folder.
- Ruby and the shell languages are read line by line, not parsed: a variable
  counts from the line that sets it to the end of its method or file,
  multi-line expressions and blocks are followed only in their common forms,
  and quoting in batch files is handled approximately. A download and a start
  are connected by the file name or the variable, so a renamed or moved file
  in between breaks the chain; so does a download in one script and the
  start in another.
- `ShellExecute` (Ruby): the level rests on reading every call through the
  declaration. In map files the event lines are picked out of binary data;
  nothing is lowered unless every declaration and call in the raw file was
  among them. A game folder document is judged by its name (`readme.txt`),
  not by what the file really is.
- JavaScript: it is a tracer, not a parser: one file at a time, scope by braces and
  names. Not followed: a response handed to another file, stored in an
  object that is passed on (`params.data = ...; run(params)`), stored through
  an alias of `this` (`self.code = ...` read back as `this.code`), or run
  through `setTimeout("code")`, `document.write` or the `innerHTML` of an
  ordinary element. It can also be wrong the other way: an unrelated variable
  of the same name in the same function is taken for the response.
- An address that cannot be resolved counts for code, commands and droppers.
  A clean plugin that evaluates what it loads through a parameter no caller
  in the file fills in is called CRITICAL. Neither NW.js game in the
  benchmark has one - which is two games.
- `WebAssembly`, script elements, `import()` and `Worker` are CRITICAL for a
  remote or decoded address only. With an address that cannot be resolved
  they are HIGH (`CHAIN-REMOTE-LOAD`), and only if the file names a remote
  address in its code - which shows that the file knows such an address, not
  that it is the one being loaded. A `<script src="https://...">` tag
  written in an HTML file is not reported.
- RPG Maker's bundled libraries (`js/libs/`) and core scripts are trusted
  for folder, name and a content marker - things a repack can imitate. A
  CRITICAL finding and `CHAIN-REMOTE-LOAD` stay visible there; a quiet change
  that is neither does not. A hash table of official library releases
  exists since 2026-10-07 (`library_hashes.py`): Effekseer for WebGL 1.70b
  (MZ-01's `effekseer.min.js` and `effekseer.wasm` are these files),
  `greenworks.js` of Greenworks 0.15.0 to 0.22.0, and since 2026-10-19 every
  jQuery core file of jQuery's own release list (228 files, 1.0 to 4.0, each
  with the SHA-256 that list states; jQuery Migrate is not taken), and the
  Windows libraries and tools of SDL2 2.32.8 / 2.32.10 and OpenAL Soft
  1.25.1 / 1.25.2 - the only releases of the two for which GitHub states a
  SHA-256 (older ones are left out, not taken on HTTPS alone). Every other
  bundled library is still trusted for folder and name. `vorbisdecoder.js`
  has no known official source.

Spyware (`CHAIN-SPYWARE`):

- In a native program only the import table is seen, and it shows what a
  program *can* do, not what it does: every windowed program imports
  clipboard and drawing functions, every game reads the keyboard, many use
  the network. So reading the keyboard state plus network is no chain (that
  function and the clipboard import are LOW notes), an input hook plus
  network is HIGH, and CRITICAL needs two independent strong signs out of
  three: a hook, a known exfiltration address (`NET-EXFIL-001`), a
  key-logging dictionary (`INPUT-003`: six different bracketed key names,
  one of them BACKSPACE / CAPSLOCK / DEL, or the word "keylog").
- The price: a native key logger with a hook and nothing else is HIGH; one
  that only polls the keyboard is not a chain even when it sends to a known
  exfiltration address (the address itself is HIGH); a clipboard stealer or
  screen grabber written as a native program is not recognised. The other
  way round, a game with both a full bracketed key-name table and a chat
  webhook, or with a hook and a webhook, is CRITICAL.
- In scripts the calls are seen: a hook library, the clipboard or a screen
  capture next to network code (60 lines) is CRITICAL; reading the keyboard
  state plus network alone is HIGH. A `keydown` listener, `pygame.key` and
  RPG Maker's keyboard calls are not capture.

Signatures and the signature area:

- A valid signature from a publisher on the trusted list silences heuristic
  findings in that file and in what is packed inside it; any other valid
  signature lowers them one level. Neither touches CRITICAL findings, the
  "could not be read" notes or the signature-area notes. Programs signed by
  a publisher that is not on the list therefore show MEDIUM / LOW findings
  that are usually harmless.
- Data inside a certificate table beyond the signature, or behind the table
  (`SIG-DATA-001`, `SIG-DATA-002`): readable text of up to 16 KB is LOW
  (installers keep a download tag there; the threshold is a judgement - no
  real tagged file was at hand), longer text or data that is not recognised
  is MEDIUM, a program, script or archive is HIGH. Data that is not
  recognised (encrypted, packed) is reported but cannot be scanned; a
  program or archive is looked for in the first megabyte of the area only;
  at most 64 MB of each area are read; text that is not recognised as a
  script is read by the command-line rules only.
- Windows on this PC still accepts a signature with data inside the table
  and rejects one with data behind it (checked with modified copies of one
  signed program). A PC with Microsoft's optional stricter check enabled -
  CVE-2013-3900, the `EnableCertPaddingCheck` registry setting, opt-in and
  not planned to become the default - rejects the first case too; the
  scanner reports the data either way.
- Signature results are tied to the file's size and timestamp. A signature
  check on an archive member writes the member to a temporary file (never
  executed); in `--launch` mode that is skipped and the member counts as
  unsigned.

Engine files:

- A program or native library is exempted only with its vendor's valid
  signature, or with the SHA-256 of an official build (the RGSS runtime;
  NW.js, Ren'Py's bundled runtime and Unity's Windows player files through
  `engine_hashes.py`). The table holds NW.js 0.29.0 and 0.48.4 (normal and
  sdk, 32 and 64 bit), thirteen Ren'Py SDKs (6.99.12.4, 7.3.5, 7.4.11,
  7.5.3, 7.6.3, 7.7.3, 7.8.7, 8.0.3, 8.1.3, 8.2.3, 8.3.7, 8.4.1, 8.5.3) and,
  since 2026-10-07, the Windows Mono player support of Unity 2019.3.6f1
  (262 programs: the player, the crash handler, the Mono runtime
  and Unity's own managed libraries, 32 and 64 bit) and, since 2026-10-11,
  of Unity 2019.2.6f1 (88 more) - 701 programs from 23
  archives, and from the Ren'Py SDKs 2,849 engine scripts by SHA-256 and 489
  compiled ones by content. Since 2026-10-12 the table holds every file of
  the eight NW.js archives, not only the programs (175 more: `credits.html`,
  `icudtl.dat`, the `.pak` files, the locales ... - 876 files in all; the
  table is the official distribution, as for Inno Setup). The scanner asks
  it for programs only - a page or data file of NW.js gets no exemption
  from it - and for the note `SCRIPT-LIMIT-001`, which is not made for a
  file of an official archive. That Unity package does not hold every
  engine-named library of a game: the .NET class libraries (`mscorlib`,
  `System.*`) come with the Unity editor and Unity's package libraries
  (`UnityEngine.UI`, `Unity.TextMeshPro` ...) are compiled by the game's
  developer - 26 of the 86 engine-named managed libraries of UNI-01 and of
  UNI-02 are not in the table and are trusted for folder and name. Any other
  build is scanned like an unknown program (`ENGINE-002` says so), which
  means false alarms on genuine engines until `tools/build_engine_hashes.py`
  is run for that version.
- The archives' own SHA-256 were confirmed against the publisher's checksum
  list for NW.js 0.48.4 and all thirteen Ren'Py SDKs (a Ren'Py SDK without a
  published checksum - 8.6.0 on 2026-10-06 - is not taken); NW.js 0.29.0 has
  no such list,
  so those entries rest on the HTTPS download (and on nine files of MV-01
  matching one of its four archives).
- The Unity entries rest on **HTTPS and an MD5 - a weak checksum**, like
  NW.js 0.29.0 on HTTPS alone: Unity lists an MD5 for each package of a
  release and no SHA-256. The package (the Windows player files as Unity
  publishes them for its macOS editor, 105 MB) is compared with that MD5
  before anything of it is read. It is a macOS installer package; the
  builder reads it with a small reader of its own (`tools/xar_reader.py`:
  standard library, limits on every step, nothing unpacked to disk, any
  other form of package refused). Unity signs these files in most builds -
  a valid signature still comes first; the table matters where it did not:
  the 32-bit player files of benchmark sample UNI-02 are unsigned and are,
  byte for byte, the files of that package. The game's own program
  (Unity's launcher with the game's icon) matches nothing and is judged as
  before. Only this one Unity version is in the table.
- A hash proves the file is the official one, not that the engine is
  harmless: NW.js and Python run whatever script the game gives them (the
  scripts are scanned on their own), and an old engine keeps its known
  weaknesses.
- A launcher that was altered rather than renamed matches no official file.
  RPG Maker MV / MZ only replace the resources (the icon) of `nw.exe`; such a
  launcher is accepted when everything else is byte for byte an official
  `nw.exe` of the table (NW.js 0.29.0 and 0.48.4, eight launchers; see
  "False alarms that were taken apart"). A launcher of another NW.js
  version, or one changed anywhere else, still keeps its findings. Its
  resources are not verified: they are scanned as text and for programs.
- `--allow-unsigned-engine-files` goes back to the structural check
  (identity and exports), which raises the bar from "rename a file" to
  "build a look-alike library" but is not proof of origin.
- The vendor list covers Unity, Valve, Microsoft, Discord, Epic Games and
  GOG; the signer names were confirmed on real files for Unity only.
- Not signature-checked: managed framework assemblies (module name only -
  Unity does not sign them) and Ren'Py's own Python source files (`renpy/`,
  `lib/python*/`), which are exempt by location - except for a
  download-and-execute chain, where they are checked against the official
  SDK files (see "Remote code execution"). Ren'Py's stock launcher
  script is recognised by its position and by importing `renpy.bootstrap`;
  a default RPG Maker XP / VX / Ace script by its name plus a definition of
  the class or module of that name - things a game can write on purpose.
  CRITICAL findings and complete CRITICAL chains are reported in all of
  these anyway, and strict mode ignores every exemption.
- The RGSS runtime list holds ten builds. Nine come from the vendor's own RTP
  installers (XP: `RGSS100J`, `RGSS102J`, `RGSS103J`, `RGSS104J`, `RGSS102E`,
  `RGSS104E`; VX: `RGSS200J`, `RGSS202J`, `RGSS202E`). The VX Ace build
  (`RGSS300` / `RGSS301`) is in no vendor package - the VX Ace RTP installs
  no runtime - and rests on two unrelated game distributions. Any other
  build shows up as a packed program plus `RGSS-RT-001` until it is added.
- In RPG Maker XP / VX / Ace scripts `GetAsyncKeyState` is treated as game
  input, window and drawing calls (the Fullscreen++ script) as helpers, and
  `system("explorer.exe", ...)` as opening a page or folder.

Installers and archives:

- (Solved on 2026-10-11: INS-03, a store's Inno Setup installer, could not
  be read - "setup script is damaged". It was not a variant of the format:
  the reader took the first of two places where the setup header's text
  stands. See "Where the setup header is" above. INS-03 is CLEAN because a
  trusted publisher signed it and nothing CRITICAL was found inside; its 91
  suppressed findings are listed with `--show-suppressed`.)
- The setup engine that every Inno Setup installer carries inside it,
  compressed, is never read, so a modified engine is not seen. (In the
  tool's own package the same engine is a loose file and gets HIGH
  findings - see INS-01 above.)
- Inno Setup file names are found by the shape of the file entries, not from
  a per-version table (checked on real installers of 5.1.10, 5.3.10, 5.4.2
  and 6.7.3); if that fails, or the installer is encrypted, the report
  says so and the data is searched by content instead - without names, and
  with programs that do not have their original SHA-256. NSIS blocks the
  script does not name are named by content.
- A zip appended to a program is opened only when its directory is at the
  end of the appended data; a zip in the middle of other appended data is
  not looked for. No real NW.js game packed this way was at hand.
- Reported as not inspected: password-protected or multi-part archives,
  password-protected members of an appended zip, NSIS's bzip2 method, RAR
  compression, 7z archives with PPMd, Deflate64, AES or a dictionary over 512 MB
  (since 2026-10-20 none of them is handed to a program), members over
  8 GB, and what exceeds 64 GB unpacked from one file.
- Large members are written to temporary files while they are scanned: that
  needs free disk space (2 GB are kept free), and antivirus software may
  remove such a file if it holds malware - the member is then reported as
  not analysed. A large member of a kind that is not read in a stream (a
  100 MB JavaScript file) is inspected for its first 64 MB only, and
  reported.

Unity:

- **IL2CPP: no instruction-level chain check - a documented limit, not a
  finding** (phageo, 2026-10-11). In a Unity IL2CPP game the game's C# code
  is compiled to machine code inside `GameAssembly.dll`, so the
  download-and-run chain of "Compiled C#" cannot be followed through it
  (that would mean finding each method in the machine code and following
  values through x86 / x64 instructions). What is scanned: the program's
  import table and strings, and the names and string literals of
  `global-metadata.dat`, with the ordinary rules. A scan that meets such a
  game says so in one information line of the report ("INFO: Unity IL2CPP
  game - game code compiled to machine code; no instruction-level chain
  check ..."). It is information only: no finding, no effect on the
  verdict, and the launcher does not ask because of it.
- IL2CPP: the metadata shows names and strings, not behaviour - which API a
  game really calls, and with what, is in native code that is not
  disassembled. Metadata that a protection tool encrypted or scrambled is
  reported (`IL2CPP-META-001`) and only read as raw text. Record layouts are
  found by validation rather than taken from a per-version table; checked on
  builds of Unity 2019.4, 2022.3 and two Unity 6 versions, all of them empty
  sample projects.
- IL2CPP import profile: the baseline is the union of those four builds. A
  real game that links a native plugin statically, uses a Unity version or
  module that was not surveyed, or is wrapped by a protection tool will
  import more and get `IAT-` findings that are not malware - networking and
  cryptography (HIGH) are the likely ones; no real IL2CPP game was available
  to measure how often. It reads the import table only: a program that
  resolves functions at runtime (`GetProcAddress`, which the baseline itself
  contains) or calls the system directly imports nothing suspicious. The
  baseline was audited on 2026-10-05: it is exactly the union of the four
  import tables, and by the scanner's own categories it holds no
  process-tampering function, nothing from `ntdll.dll` and no function that
  starts programs or changes services, the registry or tokens; it holds
  seven network entries (three `iphlpapi.dll` functions that list network
  adapters, and the `ws2_32.dll` start-up, clean-up, last-error and `send`
  ordinals) and four functions for random numbers.
- IL2CPP import profile: whatever `GameAssembly.dll` imports from
  `baselib.dll`, `unityplayer.dll` or `api-ms-win-core-winrt-*` is not
  checked - for the name alone, which a repack can imitate. It is not yet
  tied to a valid Unity signature on the folder's `UnityPlayer.dll`.
- Large bundles are read completely, media streams included. Without the
  optional `lz4` package this takes minutes for gigabytes (a 3.3 GB bundle:
  about 3.5 minutes on all cores, 1.5 with `lz4`; measured 2026-10-04 on a
  game that is no longer among the samples, not re-measured).

Media:

- Every picture and sound is read, which about doubles the scan time of an
  RPG Maker folder. Not detectable by any static reader: data hidden inside
  validly coded pixels or samples (steganography), a payload that is itself
  compressed or encrypted, and text of fewer than eight characters. Ogg page
  checksums are not verified, and an MP3 is taken to end where its frame
  chain breaks. Encrypted RPG Maker MV/MZ assets have no structure to parse -
  they go through the sliding window only.

Secure launcher:

- It decides on what a static scan can see, and only at the moment of
  starting. A game whose launcher is clean but which loads code later
  (downloads, mods, a file changed after the scan) is started.
- All fourteen real games of the benchmark start without a question since
  2026-10-07 - on fourteen samples, which says little about games in
  general (the three added that day: UNI-01 and RPY-06 at once, UNI-02 since
  its unsigned engine files are in the engine table).
  The benchmark's `launcher` column (`docs/benchmark/after_unity_hashes.csv`,
  2026-10-07) says what the launcher does with each sample: XP-01, XP-02,
  VXA-01 and RPY-02 start, and so do MV-01 and RPY-01 (which needed the
  typed word before), RPY-03 to RPY-05 and MZ-01 and VX-01 (which were asked
  about once before). Of the four installers,
  INS-04 starts, INS-03 starts too since it is read (2026-10-11; it asked
  once before), INS-02 needs the
  typed word, and INS-01 starts since 2026-10-11
  (`after_inno_installers.csv`; it was refused at first, for a chain in
  its script texts that stood on the names of two example files, and
  needed the typed word while its programs counted as unknown). The four
  IL2CPP
  builds would start (they hold no program to start). Before the launcher
  decided by verdict it refused 8 of the 12 samples it was measured on (4 of
  the 8 real games).
- A question that comes up for every second game teaches people to answer
  "yes". The typed word for SUSPICIOUS slows that down; it does not solve it.
  The real fix is fewer false alarms (see "Current results").
- A SUSPICIOUS game can be started by typing the word. A download-and-execute
  in JavaScript, Python, Ruby, PowerShell or a batch file is CRITICAL and
  refused; one the tracers lose (see "Download and execute") shows as single
  findings and is only asked about.
- A download-and-execute chain in an engine script of a Ren'Py version that
  cannot be verified is HIGH and is asked about with the typed word (since
  2026-10-06; before, it was refused without asking). That is the weaker
  side of this rule: an altered engine that claims an unlisted version gets
  a question instead of a refusal - that prompt says so in plain words.
- The column is computed from a scan made the way the launcher makes it, with
  the Windows antimalware engine on. The launcher itself also uses the
  known-malware hash list and your YARA rules, which can only add findings -
  so on a given PC it can be stricter than the column, never milder.
- At a real console only the "no" answer was tried, once (a SUSPICIOUS
  sample, Turkish text, exit code 2, nothing started); every other answer was
  given by the tests. The launcher has never actually started a program.

Other:

- YARA: no modules (`pe.`, `math.`), `for` loops or rule references. `xor` and
  `base64` apply to text strings only and, as in YARA, not together with `nocase`.
- AMSI sees at most about 32 MB of text per extracted item.
- VirusTotal and abuse.ch need your own API keys. They are encrypted for your
  Windows account (DPAPI): any program running as you can still ask Windows to
  decrypt them, and they are in memory in plain form while the scanner runs.
- PDF export embeds a system font, which makes each PDF about 1 MB.
