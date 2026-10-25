# Contributing to Bagel

Thank you for helping. Bagel is a static scanner: it only reads files. **Nothing it scans is
ever run, imported, unpacked to disk or opened with `marshal` / `pickle`** - not in the program,
not in the tests, not in a pull request. A change that breaks this is not accepted.

## Report a false alarm or a missed sample

Open an issue and give:

- the **SHA-256** of the file (and, if you like, its VirusTotal or MalwareBazaar page);
- the verdict Bagel gave and the one you expected;
- the rule ids from the report (for example `CHAIN-REMOTE-CODE`), and Bagel's version.

**Never attach live malware**, and never a password zip of it - hashes only. For a false alarm,
a link to the game's official download page helps. A way to make Bagel run, load or write what
it scans is a security bug: report it privately (see [SECURITY.md](SECURITY.md)).

## Run the tests

You need Python 3.13 (the only version tested); Bagel uses the standard library only (no new
dependencies).

```
python -m unittest tests.test_gamescan
```

unittest writes to stderr. `GSS_FAST=1` leaves out the slow tests; one class alone:
`python -m unittest tests.test_gamescan.<Class>`. Tests that need sample games or outside
archives skip without them. Details: [docs/DEVELOPING.md](docs/DEVELOPING.md).

Every change in behaviour needs a test. New text a user sees goes into `gamescan/i18n.py` in
English; a Turkish translation is welcome but not required - the maintainer adds missing ones
before release.

## Pull requests

- Keep a pull request small and say what it changes and why.
- **CI runs on a pull request only after the maintainer has approved the run** (a first look at
  the change comes first; the workflow builds and tests on Windows).
- Use made-up names and paths in tests and examples - no real game names, user names or
  personal folders.
