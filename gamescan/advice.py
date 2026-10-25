"""Plain-language "what should I do?" advice for findings.

Every rule already explains *what it means* (``Finding.reason``). This module
adds the practical next step. Advice is written per category, with a more
specific text for the rules where the general one would mislead. The Turkish
versions live in ``i18n.ADVICE_TR`` under the same keys.
"""
from __future__ import annotations

BY_CATEGORY = {
    "EXECUTION": "Check where the code being run comes from. Code from the game's own files is "
                 "normal; code that is downloaded or decoded first is a reason not to run the game.",
    "OBFUSCATION": "Hidden or encoded code deserves suspicion in a game. Unless the developer "
                   "explains it (for example a commercial plugin), treat the game as unsafe.",
    "PROCESS": "Games rarely need to start other programs. Look at the snippet: opening a folder "
               "or a web page is harmless, running cmd or PowerShell is not.",
    "NETWORK": "Look at the address. A developer's site, an update check or a store link is "
               "normal; an unknown server or a bare number address is a reason not to run the game.",
    "FILESYSTEM": "See what is deleted or changed. The game's own saves and cache are fine; "
                  "anything in your user folder or in Windows is not.",
    "PERSISTENCE": "A game has no reason to start together with Windows. Do not run it unless "
                   "you know exactly why it does this.",
    "CREDENTIALS": "Nothing in a game should read browser passwords, wallets or chat logins. Do "
                   "not run it; if you already did, change your passwords from another device.",
    "INPUT_CAPTURE": "Reading keys inside the game is normal; recording keys, the screen or the "
                     "clipboard outside it is spying. Do not run it unless you trust the source.",
    "PACKING": "A packed program hides its real code. Some developers do this against piracy, "
               "but nobody can check what it does - only run it if you trust where it came from.",
    "EVASION": "Honest software does not disguise files or switch protection off. Treat this as "
               "a strong warning sign.",
    "SIGNATURE": "A known-malware signature matched. Do not run the file; quarantine it.",
    "REPUTATION": "Open the VirusTotal address shown in the snippet to see which antivirus "
                  "engines flag the file, and what they call it.",
    "CHAIN": "Several risky behaviours appear together, which is how real malware is built. Do "
             "not run this game unless the developer can explain every part.",
}

_HARMLESS_ALONE = ("Common in game scripts and harmless by itself. It only matters together "
                   "with downloading or decoding - check whether an attack chain is reported.")
_ENGINE_VERDICT = ("Windows' own antimalware engine identified this as malware. Do not run the "
                   "game; quarantine the file.")
_STARTUP = ("Open Task Manager, go to Startup apps and disable the entry if you do not "
            "recognise it.")
_DISGUISE = ("A program pretending to be a picture or a document is a classic trick. Do not "
             "open it.")
_MACRO = ("Do not click \"Enable content\" in Office unless you expected this document and "
          "trust who sent it.")

BY_RULE = {
    "PY-EXEC-001": _HARMLESS_ALONE, "JS-EXEC-001": _HARMLESS_ALONE, "RB-EXEC-001": _HARMLESS_ALONE,
    "URL-001": "Usually harmless. Check that the address belongs to the developer or to a "
               "service you recognise.",
    "SIG-EICAR": "This is only a test file. It is harmless and can simply be deleted.",
    "AMSI-001": _ENGINE_VERDICT, "DEFENDER-001": _ENGINE_VERDICT,
    "VT-003": "Unknown does not mean bad - most small indie games are unknown. Judge by the "
              "other findings.",
    "VT-004": "Scan again in a few days, or judge by the other findings: a brand-new file with "
              "no detections proves nothing yet.",
    "SCAN-ERR-001": "The scanner could not read this file, so nothing is known about it. If "
                    "you do not need it, do not run it; otherwise scan it with Windows Security.",
    "ARC-001": "If you were given a password with the archive, unpack it into a folder and "
               "scan that folder.",
    "ARC-ENC-EXEC-001": "Do not run anything from this archive unless you trust where it came from. "
                        "If you were given a password, unpack it into a folder and scan that folder "
                        "before opening anything in it.",
    "DOC-001": _MACRO, "DOC-002": _MACRO,
    "AUTORUN-001": _STARTUP, "AUTORUN-002": _STARTUP,
    "AUTORUN-003": "A harmless leftover. You can remove the entry in Task Manager under "
                   "Startup apps.",
    "NAME-001": _DISGUISE, "NAME-002": _DISGUISE,
    "RGSS-FMT-001": "The scripts could not be inspected. Run the game only if you trust where "
                    "it came from.",
    "RGSS-FMT-002": "The scripts could not be inspected. Run the game only if you trust where "
                    "it came from.",
    "MEDIA-001": "Usually harmless by itself. Judge by the other findings for the same file.",
    "MEDIA-002": "There is no ordinary reason for a program inside a picture or sound file. Do "
                 "not run the game unless the developer can explain it.",
    "PE-ENT-003": "Commercial protection also does this. Judge by where the game came from and "
                  "by the other findings.",
    "ENGINE-001": "Engine files are normally left as they are. If you did not get the game from "
                  "a source you trust, pay attention to this file's other findings.",
    "ENGINE-002": "Many genuine engine files are simply not signed (NW.js, Ren'Py's Python, SDL). "
                  "Judge by this file's other findings and by where the game came from.",
    "PROC-LIST-001": "Harmless by itself. If you would rather not have a game look at what else "
                     "is running, that is a reason to ask its developer - not a sign of malware.",
    "ENGINE-003": "Games sometimes adjust an engine file, and that alone is harmless. If you did "
                  "not get the game from a source you trust, look at this file's other findings.",
    "ENGINE-004": "Do not run the game unless you got it from its developer's own page and the "
                  "developer can explain this file. A fresh copy of the game from the official "
                  "source should not have it.",
    "ENGINE-005": "Harmless when the developer adjusted the engine file - the source file beside "
                  "it shows what was changed. If you did not get the game from a source you "
                  "trust, look at the findings of that source file.",
    "ENGINE-006": "Harmless: an official file that an update of the engine left behind. Nothing "
                  "needs to be done.",
    "IAT-001": "A game has no reason to import these. Do not run it unless you know exactly why "
               "(for example an anti-cheat you chose to install).",
    "IAT-002": "Unusual for a game. Protection software does this too; judge by the other "
               "findings and by where the game came from.",
    "IAT-003": "Online games with a native network library import these. If the game should "
               "work offline, be careful.",
    "IAT-004": "Asset protection also uses encryption. Judge by the other findings.",
    "IAT-005": "Unusual for a game's own code. Judge by the other findings and by where the "
               "game came from.",
    "IAT-006": "Usually just a Unity version that was not surveyed. No action is needed on its own.",
    "IL2CPP-META-001": "Common in protected games. Judge by the other findings.",
    "RGSS-RT-001": "If you got the game from a source you trust you can add the file to the "
                   "allowlist; if you are not sure, check the file on VirusTotal.",
    "ARC-002": "Part of the content could not be inspected. Run the file only if you trust "
               "where it came from.",
    "UNITY-FMT-001": "Part of the bundle could not be inspected. Run the game only if you "
                     "trust where it came from.",
    "RPY-FMT-001": "The script could not be inspected. Run the game only if you trust where "
                   "it came from.",
    "PYO-FMT-001": "The compiled file could not be inspected. Run the game only if you trust "
                   "where it came from.",
    "PY-JOIN-001": "One check of this script was not finished. Run the game only if you trust "
                   "where it came from.",
    "ENGINE-007": "Do not run the game unless you got it from its developer's own page and the "
                  "developer can explain this file. A compiled file should never do more than "
                  "its source.",
    "ENGINE-008": "Games rarely change the engine's programs. Run the game only if you got it from "
                  "its developer's own page; a fresh copy from there should have the official files.",
    "ENGINE-009": "Apps often bring helper programs of their own. Run the game only if you got it from "
                  "its developer's own page and the developer can say what this program is.",
    "RPY-CONTENT-001": "A file named like a compiled script that is something else is a way to hide a "
                       "program or data. Run the game only if you got it from its developer's own page.",
    "INST-REDIST-001": "Ordinary for game installers. The downloaded file comes from its official "
                       "address but is not part of the package, so it was not scanned; run the "
                       "installer only if you trust where it came from.",
    "INNO-CODE-001": "The installer's own instructions could not be read to the end. Run the "
                     "installer only if you trust where it came from.",
    "DN-IL-001": "The code of this .NET library could not be read to the end, so a download-and-run "
                 "inside it could have been missed. Start the game only if you trust where it came from.",
    "SCRIPT-LIMIT-001": "This script was not read to its end for download-and-run: it is larger or longer than "
                        "the scanner follows. Run it only if you trust where it came from.",
    "ENC-SCRIPT-001": "An encoded script in this file could not be decoded, so what it runs was not inspected. "
                      "Run it only if you trust where it came from.",
    "EXEC-FMT-001": "This is a program of a kind the scanner cannot read (Java): what it does was not "
                    "inspected. Start it only if you trust where it came from.",
    "JSC-FMT-001": "This is compiled JavaScript, which the scanner cannot read: what this code does was not "
                   "inspected. Start the game only if you trust where it came from.",
    "SCAN-COVERAGE-001": "Most of this folder is made of files of kinds the scanner does not read - probably a "
                         "game engine it does not know. The scan says little about it. Start the game only if "
                         "you trust where it came from.",
    "CHAIN-LOCAL-DROP": "A game has little reason to hide a program in its own files. Do not run it unless "
                        "you got it from its developer's own page and the developer can explain this.",
    "CHAIN-LOCAL-DROP-PLUS": "Do not run this game. Unless you got it from its developer's own page, delete it "
                             "and run a full scan of the PC with Windows Security.",
    "SIDELOAD-001": "Games ship such libraries, but signed by Microsoft. Do not run the program beside it "
                    "unless you got the game from its developer's own page; a fresh copy from there "
                    "should have the signed file.",
}


def key_for(rule_id: str, category: str) -> str:
    """Lookup key of the advice that applies (a rule id or a category name)."""
    if rule_id in BY_RULE:
        return rule_id
    return category if category in BY_CATEGORY else "SIGNATURE"


def for_finding(rule_id: str, category: str) -> str:
    """English advice for a finding."""
    key = key_for(rule_id, category)
    return BY_RULE.get(key) or BY_CATEGORY[key]
