"""English / Turkish presentation layer.

The detection core and the JSON report always speak English, so reports stay
stable for tools. Translation happens only when text is shown to a person:
``t()`` for interface strings, and ``title()`` / ``reason()`` /
``suppression()`` / ``evidence()`` for the text carried by a finding.
"""
from __future__ import annotations
from .indicators import strings as _indicator_strings   # strings as data: indicators.py
_IND = _indicator_strings("gamescan/i18n.py")

import locale
import re
import sys
from typing import Tuple

from . import advice as advice_module, settings
from .models import Category, Finding, ScanReport, Severity

LANGUAGES = {"en": "English", "tr": "Türkçe"}
_lang = "en"


def language() -> str:
    return _lang


def set_language(code: str) -> None:
    global _lang
    _lang = code if code in LANGUAGES else "en"


def detect_default() -> str:
    """Saved choice if any, otherwise the operating system's UI language."""
    saved = settings.load().get("language")
    if saved in LANGUAGES:
        return saved
    try:
        if sys.platform == "win32":
            import ctypes
            if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x1F:
                return "tr"
        elif (locale.getlocale()[0] or "").lower().startswith(("tr", "turkish")):
            return "tr"
    except (AttributeError, OSError, ValueError):
        pass
    return "en"


def save_language() -> None:
    try:
        settings.update(language=_lang)
    except OSError:
        pass                                   # the choice just won't persist


# -- interface strings (keyed by the English text) -----------------------------
UI_TR = {
    "Ren'Py  ·  RPG Maker  ·  Unity/.NET  ·  Electron/NW.js  ·  installers (Inno, NSIS, MSI)  ·  "
    "native PE  ·  scripts":
        "Ren'Py  ·  RPG Maker  ·  Unity/.NET  ·  Electron/NW.js  ·  kurulum dosyaları (Inno, NSIS, "
        "MSI)  ·  yerel PE  ·  betikler",
    "A scan is still running. Stop it and close the window?":
        "Bir tarama hâlâ sürüyor. Tarama durdurulup pencere kapatılsın mı?",
    # -- package self-check and the Explorer right-click menu (0.9-beta) ----------
    "Some files of this package are not as they were when it was built "
    "(%d changed, %d missing, %d added). For example:\n\n%s\n\nThe package may be "
    "damaged, or someone changed it. Download it again from where you got it. You "
    "can still scan, but the results of a changed package may be wrong.":
        "Bu paketin bazı dosyaları paket hazırlandığındaki gibi değil (%d değişmiş, %d eksik, "
        "%d fazla). Örneğin:\n\n%s\n\nPaket bozulmuş olabilir ya da biri onu değiştirmiş "
        "olabilir. Paketi aldığınız yerden yeniden indirin. Yine de tarama yapabilirsiniz, ama "
        "değiştirilmiş bir paketin sonuçları yanlış olabilir.",
    "The Explorer right-click menu still opens Bagel from another "
    "place:\n\n%s\n\nPoint it to this copy now?":
        "Gezgin'in sağ tık menüsü Bagel'ı hâlâ başka bir yerden açıyor:\n\n%s\n\n"
        "Menü şimdi bu kopyayı açacak şekilde güncellensin mi?",
    "The right-click menu could not be changed:\n\n%s": "Sağ tık menüsü değiştirilemedi:\n\n%s",
    "Explorer right-click menu": "Gezgin sağ tık menüsü",
    "Add to the right-click menu": "Sağ tık menüsüne ekle",
    "Remove from the right-click menu": "Sağ tık menüsünden kaldır",
    # one entry "Bagel" with a submenu (0.9-beta final polish, phageo 2026-10-25)
    "Adds one entry “Bagel” to the right-click menu, for your Windows account only (no "
    "administrator rights): “Scan” on folders and files, and also “Safe launch” on programs "
    "(.exe). Scan opens this window and scans what you clicked - for a program, its game "
    "folder; Safe launch scans the program's folder first and then starts the game, asks you, "
    "or refuses. On Windows 11 it is under “Show more options”. Removing it leaves nothing "
    "behind.":
        "Sağ tık menüsüne tek bir “Bagel” girişi ekler; yalnızca sizin Windows hesabınız için "
        "(yönetici izni gerekmez): klasörlerde ve dosyalarda “Tara”, programlarda (.exe) ayrıca "
        "“Güvenli başlat”. Tara bu pencereyi açar ve tıkladığınız şeyi tarar - bir programda onun "
        "oyun klasörünü; Güvenli başlat önce programın klasörünü tarar, sonra oyunu başlatır, size "
        "sorar ya da reddeder. Windows 11'de “Daha fazla seçenek göster” altındadır. "
        "Kaldırıldığında geride hiçbir şey kalmaz.",
    "Safe launch": "Güvenli başlat",
    "Remove the “Bagel” entry from the right-click menu?":
        "“Bagel” girişi sağ tık menüsünden kaldırılsın mı?",
    "The right-click menu was added for all users when Bagel was installed. It is removed when "
    "Bagel is uninstalled.":
        "Sağ tık menüsü, Bagel kurulurken tüm kullanıcılar için eklendi. Bagel kaldırıldığında o "
        "da kaldırılır.",
    "Scanned: the game folder of %s": "Taranan: %s dosyasının oyun klasörü",
    "Scanned: only %s (an installer or archive)": "Taranan: yalnızca %s (bir kurulum dosyası ya da arşiv)",
    # the uninstaller's one question (tools/build_installer.py; %1 is the folder, filled in by it)
    "Also delete Bagel's settings, scan memory and quarantine folder?\n\n%1\n\n"
    "Files in quarantine are deleted for good. Choose No to keep them.":
        "Bagel'ın ayarları, tarama hafızası ve karantina klasörü de silinsin mi?\n\n%1\n\n"
        "Karantinadaki dosyalar kalıcı olarak silinir. Saklamak için Hayır'ı seçin.",
    # the installer's folder page, "only for me" (tools/build_installer.py; %1 is the folder)
    "Bagel cannot be installed “only for me” in this folder:\n\n%1\n\n"
    "Only an administrator may write there (Program Files is such a folder). Choose a folder of "
    "your own - the suggested one is fine - or close Setup, start it again and choose to install "
    "for all users.":
        "Bagel bu klasöre “yalnızca benim için” kurulamaz:\n\n%1\n\n"
        "Oraya yalnızca bir yönetici yazabilir (Program Files böyle bir klasördür). Size ait bir "
        "klasör seçin - önerilen klasör uygundur - ya da Kurulum'u kapatıp yeniden başlatın ve "
        "tüm kullanıcılar için kurmayı seçin.",
    "Right-click menu: on": "Sağ tık menüsü: açık",
    "Right-click menu: another copy": "Sağ tık menüsü: başka kopya",
    "Add it now?": "Şimdi eklensin mi?",
    "Safe launch…": "Güvenli başlat…",
    "Choose the game's program to start": "Başlatılacak oyun programını seçin",
    "Programs": "Programlar",
    "Only a program (.exe) can be started:\n\n%s": "Yalnızca bir program (.exe) başlatılabilir:\n\n%s",
    "Safe launch: %s": "Güvenli başlatma: %s",
    "Start the game anyway?": "Oyun yine de başlatılsın mı?",
    "The game was not started.": "Oyun başlatılmadı.",
    "Not available on this computer.": "Bu bilgisayarda kullanılamıyor.",
    "It now opens another copy of Bagel. Remove it and add "
    "it again to use this copy.":
        "Şu anda Bagel'ın başka bir kopyasını açıyor. Bu kopyayı kullanmak için "
        "kaldırıp yeniden ekleyin.",
    "It is on.": "Açık.",
    "Scan": "Tara",
    "Cancel": "İptal",
    "File…": "Dosya…",
    "Folder…": "Klasör…",
    "Strict mode – do not trust engine / library file locations":
        "Sıkı mod – motor / kütüphane dosya konumlarına güvenme",
    "READY": "HAZIR",
    "Choose a game folder or file to scan": "Taranacak oyun klasörünü veya dosyayı seçin",
    "Suppressed": "Bastırılan",
    "Files scanned": "Taranan dosya",
    "Filter": "Filtre",
    "Show suppressed findings": "Bastırılan bulguları göster",
    "Export JSON report": "JSON raporu dışa aktar",
    "Allowlist this file": "Bu dosyayı güvenilir say",
    "Open file location": "Dosya konumunu aç",
    "Copy details": "Ayrıntıları kopyala",
    "Severity": "Önem",
    "Category": "Kategori",
    "Finding": "Bulgu",
    "File": "Dosya",
    "Line": "Satır",
    "Conf.": "Güven",
    "Choose a game folder": "Bir oyun klasörü seçin",
    "Choose a file to scan": "Taranacak dosyayı seçin",
    "Cancelling…": "İptal ediliyor…",
    "This path does not exist:\n\n%s": "Bu yol mevcut değil:\n\n%s",
    "SCANNING": "TARANIYOR",
    "Scanning…": "Taranıyor…",
    "Listing files…": "Dosyalar listeleniyor…",
    "Scanning… findings appear here as they are discovered.":
        "Taranıyor… bulgular bulundukça burada görünür.",
    "Cancelled  ·  ": "İptal edildi  ·  ",
    "%s files inspected, %s not applicable  ·  %.1fs":
        "%s dosya incelendi, %s dosya kapsam dışı  ·  %.1f sn",
    "  ·  %d read error(s)": "  ·  %d okuma hatası",
    "ERROR": "HATA",
    "The scan stopped unexpectedly": "Tarama beklenmedik şekilde durdu",
    "Scan failed\n": "Tarama başarısız oldu\n",
    "%s  ·  risk %d/100  ·  %s": "%s  ·  risk %d/100  ·  %s",
    "no known engine detected": "bilinen bir oyun motoru algılanmadı",
    "%s of %s findings shown": "%s / %s bulgu gösteriliyor",
    "  (first %s shown)": "  (ilk %s gösteriliyor)",
    "No active findings\n": "Etkin bulgu yok\n",
    "Nothing in this scan needs your attention.\n\n":
        "Bu taramada dikkatinizi gerektiren bir şey yok.\n\n",
    "%d finding(s) were suppressed as false positives. Tick “Show suppressed findings” "
    "to see each one and why it was suppressed.":
        "%d bulgu yanlış alarm olarak bastırıldı. Her birini ve neden bastırıldığını "
        "görmek için “Bastırılan bulguları göster” seçeneğini işaretleyin.",
    "No rule matched any inspected file.": "İncelenen dosyaların hiçbiri bir kuralla eşleşmedi.",
    "How it works\n": "Nasıl çalışır\n",
    "Pick a game folder (or a single file) and press Scan. Nothing is executed; files are "
    "only read.\n":
        "Bir oyun klasörü (veya tek bir dosya) seçip Tara'ya basın. Hiçbir şey "
        "çalıştırılmaz; dosyalar yalnızca okunur.\n",
    "\nWHAT IS CHECKED\n": "\nNELER DENETLENİR\n",
    "Dynamic code execution, encoded payloads, process spawning, network use, file "
    "tampering, persistence, credential access, input capture, packed binaries, and "
    "attack chains that combine them.\n":
        "Dinamik kod yürütme, kodlanmış yükler, süreç başlatma, ağ kullanımı, dosyalara "
        "müdahale, kalıcılık, kimlik bilgilerine erişim, girdi yakalama, paketlenmiş "
        "ikili dosyalar ve bunları birleştiren saldırı zincirleri.\n",
    "\nFALSE POSITIVES\n": "\nYANLIŞ ALARMLAR\n",
    "Engine files, comments, benign domains, save-data encoding and similar known-good "
    "patterns are suppressed. Suppressed findings are kept, with the reason, and can be "
    "shown at any time.\n":
        "Motor dosyaları, yorumlar, zararsız alan adları, kayıt verisi kodlaması ve benzeri "
        "bilinen zararsız kalıplar bastırılır. Bastırılan bulgular gerekçesiyle birlikte "
        "saklanır ve istendiğinde gösterilebilir.\n",
    "\nLIMITS\n": "\nSINIRLAR\n",
    "This is static triage, not an antivirus. A clean result lowers the risk; it does not "
    "prove a game is safe.":
        "Bu bir antivirüs değil, statik bir ön incelemedir. Temiz sonuç riski azaltır; "
        "oyunun güvenli olduğunu kanıtlamaz.",
    "  :  line %d": "  :  satır %d",
    "   %s   ·   %d%% confidence   ·   %s\n": "   %s   ·   %%%d güven   ·   %s\n",
    "\nSUPPRESSED – NOT COUNTED\n": "\nBASTIRILDI – SAYILMIYOR\n",
    "\nWHY IT MATTERS\n": "\nNEDEN ÖNEMLİ\n",
    "\nWHAT DOES THIS MEAN\n": "\nBU NE ANLAMA GELİYOR\n",
    "\nWHAT SHOULD I DO\n": "\nNE YAPMALIYIM\n",
    "What does this mean": "Bu ne anlama geliyor",
    "What should I do": "Ne yapmalıyım",
    "Experimental": "Deneysel",
    "These features repeat what Windows Security already does, less well, and cause false "
    "alarms outside game folders.":
        "Bu özellikler Windows Güvenliği'nin zaten yaptığını daha zayıf şekilde tekrarlar ve "
        "oyun klasörleri dışında yanlış alarmlara yol açar.",
    "\nLOCATION\n": "\nKONUM\n",
    "\nMATCHED EVIDENCE\n": "\nEŞLEŞEN KANIT\n",
    "\nSNIPPET\n": "\nKOD PARÇASI\n",
    "\nSHA-256\n": "\nSHA-256\n",
    "\nHANDLER\n": "\nİŞLEYİCİ\n",
    "n/a": "yok",
    "Save JSON report": "JSON raporunu kaydet",
    "Could not save the report:\n\n%s": "Rapor kaydedilemedi:\n\n%s",
    "Report saved to %s": "Rapor kaydedildi: %s",
    "Trust this exact file?\n\n%s\n\nAll of its findings will be suppressed in this and "
    "future scans. If the file changes in any way, it is checked again.":
        "Bu dosyaya olduğu gibi güvenilsin mi?\n\n%s\n\nDosyanın tüm bulguları bu ve sonraki "
        "taramalarda bastırılır. Dosya herhangi bir şekilde değişirse yeniden denetlenir.",
    "The allowlist could not be saved:\n\n%s": "Güvenilir dosya listesi kaydedilemedi:\n\n%s",
    "Could not open the folder:\n\n%s": "Klasör açılamadı:\n\n%s",
    "Details copied to clipboard": "Ayrıntılar panoya kopyalandı",
    # -- main window: reports, quarantine ---------------------------------------
    "Settings": "Ayarlar",
    "Quarantine": "Karantina",
    "Open report…": "Rapor aç…",
    "Export…": "Dışa aktar…",
    "Quarantine file": "Karantinaya al",
    "  ·  %d file(s) quarantined": "  ·  %d dosya karantinaya alındı",
    "\nNOTES\n": "\nNOTLAR\n",
    "\nThis file has been moved to quarantine.\n": "\nBu dosya karantinaya taşındı.\n",
    "severity: %s": "önem: %s",
    "text: %s": "metin: %s",
    "including suppressed": "bastırılanlar dahil",
    "Export report": "Raporu dışa aktar",
    "PDF document": "PDF belgesi",
    "HTML page": "HTML sayfası",
    "JSON data (complete report)": "JSON verisi (raporun tamamı)",
    "Open a saved JSON report": "Kayıtlı bir JSON raporu açın",
    "This file is not a scan report:\n\n%s": "Bu dosya bir tarama raporu değil:\n\n%s",
    "Loaded report %s": "Rapor yüklendi: %s",
    "Move this file to quarantine?\n\n%s\n\nIt is taken out of the game folder and scrambled "
    "so it cannot run. You can restore it later from the Quarantine window.":
        "Bu dosya karantinaya taşınsın mı?\n\n%s\n\nDosya oyun klasöründen çıkarılır ve "
        "çalışamayacak şekilde karıştırılır. Daha sonra Karantina penceresinden geri "
        "yükleyebilirsiniz.",
    "The file could not be quarantined:\n\n%s": "Dosya karantinaya alınamadı:\n\n%s",
    "The file at this location is not the file that was scanned (it has changed, is gone, "
    "or the report does not belong to this PC). Nothing was done.\n\n%s":
        "Bu konumdaki dosya taranan dosya değil (değişmiş, silinmiş veya rapor bu bilgisayara "
        "ait değil). Hiçbir işlem yapılmadı.\n\n%s",
    "Moved to quarantine: %s": "Karantinaya taşındı: %s",
    # -- settings window --------------------------------------------------------
    "YARA signatures": "YARA imzaları",
    "Browse…": "Gözat…",
    "VirusTotal": "VirusTotal",
    "Check executables on VirusTotal after each scan":
        "Her taramadan sonra çalıştırılabilir dosyaları VirusTotal'da denetle",
    "API key": "API anahtarı",
    "Max. lookups": "En fazla sorgu",
    "Only the SHA-256 hash of each program is sent, never the file. The free API allows 4 "
    "lookups per minute, so each new file adds about 15 seconds. The key is stored "
    "unencrypted in your user profile.":
        "Her programın yalnızca SHA-256 özeti gönderilir, dosyanın kendisi asla gönderilmez. "
        "Ücretsiz API dakikada 4 sorguya izin verir; bu yüzden her yeni dosya yaklaşık 15 "
        "saniye ekler. Anahtar, kullanıcı profilinizde şifrelenmeden saklanır.",
    "Automatically quarantine files with HIGH or CRITICAL findings":
        "YÜKSEK veya KRİTİK bulgusu olan dosyaları otomatik olarak karantinaya al",
    "Quarantined files are moved out of the game folder and scrambled so they cannot run. "
    "The game may stop working until you restore them from the Quarantine window.":
        "Karantinaya alınan dosyalar oyun klasöründen çıkarılır ve çalışamayacak şekilde "
        "karıştırılır. Karantina penceresinden geri yükleyene kadar oyun çalışmayabilir.",
    "Save": "Kaydet",
    "Choose the folder with YARA rules": "YARA kurallarının bulunduğu klasörü seçin",
    "%d signature(s) will be used, %d skipped as unsupported.":
        "%d imza kullanılacak, %d imza desteklenmediği için atlandı.",
    "Put .yar / .yara files in this folder.": ".yar / .yara dosyalarını bu klasöre koyun.",
    "Enter a VirusTotal API key or switch the VirusTotal check off.":
        "Bir VirusTotal API anahtarı girin veya VirusTotal denetimini kapatın.",
    "The settings could not be saved:\n\n%s": "Ayarlar kaydedilemedi:\n\n%s",
    # -- quarantine window ------------------------------------------------------
    "Date": "Tarih",
    "Original location": "Özgün konum",
    "Reasons": "Nedenler",
    "Restore to original location": "Özgün konumuna geri yükle",
    "Delete permanently": "Kalıcı olarak sil",
    "Close": "Kapat",
    "%d file(s) in quarantine  ·  %s": "Karantinada %d dosya  ·  %s",
    "Put this file back into the game folder? Only do this if you are sure it is safe.":
        "Bu dosya oyun klasörüne geri konulsun mu? Bunu yalnızca güvenli olduğundan "
        "eminseniz yapın.",
    "Permanently delete this quarantined file? This cannot be undone.":
        "Karantinadaki bu dosya kalıcı olarak silinsin mi? Bu işlem geri alınamaz.",
    # -- protection (antivirus features) ----------------------------------------
    "● Protection on": "● Koruma açık",
    "○ Protection off": "○ Koruma kapalı",
    "Protection": "Koruma",
    "Quick scan": "Hızlı tarama",
    "Startup items and running programs": "Başlangıç öğeleri ve çalışan programlar",
    "Full scan": "Tam tarama",
    "Real-time protection": "Gerçek zamanlı koruma",
    "Scan new and changed files in these folders automatically":
        "Bu klasörlerdeki yeni ve değişen dosyaları otomatik olarak tara",
    "Add folder…": "Klasör ekle…",
    "Reset folders": "Klasörleri sıfırla",
    "Works while this window is open. Files are checked right after they are written; a "
    "program cannot be blocked before it starts. Keep Windows Security switched on.":
        "Bu pencere açıkken çalışır. Dosyalar yazıldıktan hemen sonra denetlenir; bir "
        "program başlamadan önce engellenemez. Windows Güvenliği'ni açık tutun.",
    "Scan this PC": "Bu bilgisayarı tara",
    "Quick scan covers Downloads, Desktop, the temp folder and the Startup folders. A full "
    "scan reads every file on the fixed drives and can take hours.":
        "Hızlı tarama İndirilenler, Masaüstü, geçici klasör ve Başlangıç klasörlerini "
        "kapsar. Tam tarama sabit sürücülerdeki her dosyayı okur ve saatler sürebilir.",
    "Known-malware database": "Bilinen zararlı yazılım veritabanı",
    "Update from the internet": "İnternetten güncelle",
    "Import hash list…": "Özet listesi içe aktar…",
    "Recent real-time events": "Son gerçek zamanlı olaylar",
    "Time": "Saat",
    "Result": "Sonuç",
    "No folder to watch.": "İzlenecek klasör yok.",
    "Active · %d file(s) checked so far": "Etkin · şimdiye kadar %d dosya denetlendi",
    "The signature database is not available.": "İmza veritabanı kullanılamıyor.",
    "%s known-malware hashes  ·  last update: %s":
        "%s bilinen zararlı yazılım özeti  ·  son güncelleme: %s",
    "never": "hiç",
    "Choose a folder to watch": "İzlenecek klasörü seçin",
    "Choose a text or CSV file with SHA-256 hashes":
        "SHA-256 özetleri içeren bir metin veya CSV dosyası seçin",
    "%d new hash(es) added.": "%d yeni özet eklendi.",
    "Update failed: %s": "Güncelleme başarısız: %s",
    "Downloading…": "İndiriliyor…",
    "Threat detected": "Tehdit algılandı",
    "The file has been moved to quarantine.": "Dosya karantinaya taşındı.",
    # -- signature updates and startup ------------------------------------------
    "abuse.ch Auth-Key": "abuse.ch Auth-Key",
    "Needed to download the known-malware hash list. The key is free at "
    "https://auth.abuse.ch/ and is stored unencrypted in your user profile.":
        "Bilinen zararlı yazılım özet listesini indirmek için gereklidir. Anahtar "
        "https://auth.abuse.ch/ adresinden ücretsiz alınır ve kullanıcı profilinizde "
        "şifrelenmeden saklanır.",
    "%d hashes in the list, %d of them new.": "Listede %d özet var, bunların %d tanesi yeni.",
    "no abuse.ch Auth-Key is set. Get a free key at https://auth.abuse.ch/ and enter it in "
    "Settings.":
        "abuse.ch Auth-Key ayarlanmamış. https://auth.abuse.ch/ adresinden ücretsiz bir anahtar "
        "alıp Ayarlar'a girin.",
    "abuse.ch rejected the Auth-Key. Check the key in Settings.":
        "abuse.ch, Auth-Key'i reddetti. Anahtarı Ayarlar'da denetleyin.",
    "the list was downloaded less than 5 minutes ago. Try again later.":
        "liste 5 dakikadan kısa süre önce indirildi. Daha sonra yeniden deneyin.",
    "the server did not return a hash list. Nothing was changed.":
        "sunucu bir özet listesi döndürmedi. Hiçbir şey değiştirilmedi.",
    "the download did not work (%s). Nothing was changed.":
        "indirme başarısız oldu (%s). Hiçbir şey değiştirilmedi.",
    "Bagel could not start.\nThe technical details were saved to:\n%s":
        "Bagel başlatılamadı.\nTeknik ayrıntılar şu dosyaya kaydedildi:\n%s",
    "Bagel needs Python %d.%d or newer, but this is Python %d.%d.\n"
    "Install a newer Python from https://www.python.org/downloads/":
        "Bagel için Python %d.%d veya daha yenisi gerekir; bu sürüm Python "
        "%d.%d.\nhttps://www.python.org/downloads/ adresinden daha yeni bir Python kurun.",
    # -- Windows Defender ---------------------------------------------------------
    "Windows Defender": "Windows Defender",
    "Show unpacked content to the Windows antimalware engine (AMSI)":
        "Açılan içeriği Windows kötü amaçlı yazılımdan koruma motoruna (AMSI) göster",
    "Also let Windows Defender scan the game folder (detect only)":
        "Windows Defender oyun klasörünü de tarasın (yalnızca tespit)",
    "Defender cannot see code hidden inside archives and compiled scripts; the scanner "
    "unpacks it and shows it to Defender. Defender is never allowed to remove anything, and "
    "a detection may appear in Windows Security's history.":
        "Defender, arşivlerin ve derlenmiş betiklerin içine gizlenmiş kodu göremez; tarayıcı "
        "bu kodu açıp Defender'a gösterir. Defender'ın herhangi bir şeyi kaldırmasına asla "
        "izin verilmez; bir tespit, Windows Güvenliği geçmişinde görünebilir.",
    # -- trust settings -----------------------------------------------------------
    "Trust a clean result only after (days)": "Temiz sonuca şu kadar gün sonra güven",
    "Trusted publishers": "Güvenilir yayımcılar",
    "Programs validly signed by these publishers are treated like engine files. Any other "
    "valid signature only lowers a finding by one level. Separate names with commas.":
        "Bu yayımcılar tarafından geçerli şekilde imzalanan programlar motor dosyaları gibi "
        "değerlendirilir. Diğer geçerli imzalar bir bulguyu yalnızca bir kademe düşürür. "
        "Adları virgülle ayırın.",
    # -- memory center and feedback ---------------------------------------------
    "Memory": "Hafıza",
    "Confirm threat": "Tehdidi doğrula",
    "False positive": "Yanlış alarm",
    "  ·  %d new since last scan": "  ·  son taramadan beri %d yeni",
    "NEW · ": "YENİ · ",
    "\nLEARNING\n": "\nÖĞRENME\n",
    "Mark a finding as a false positive or a confirmed threat (buttons below, or right-click). "
    "The scanner remembers your decisions and adjusts how much it trusts each rule.\n":
        "Bir bulguyu yanlış alarm veya doğrulanmış tehdit olarak işaretleyin (aşağıdaki "
        "düğmeler veya sağ tıklama). Tarayıcı kararlarınızı hatırlar ve her kurala ne kadar "
        "güveneceğini buna göre ayarlar.\n",
    "This is static triage, not an antivirus. A clean result lowers the risk; it does not "
    "prove a game is safe.\n":
        "Bu bir antivirüs değil, statik bir ön incelemedir. Temiz sonuç riski azaltır; "
        "oyunun güvenli olduğunu kanıtlamaz.\n",
    "\nSHORTCUTS\n": "\nKISAYOLLAR\n",
    "F5 scan  ·  Ctrl+O open report  ·  Ctrl+E export  ·  Ctrl+F filter  ·  Esc clear filters":
        "F5 tara  ·  Ctrl+O rapor aç  ·  Ctrl+E dışa aktar  ·  Ctrl+F filtre  ·  "
        "Esc filtreleri temizle",
    "New since the last scan of this target.": "Bu hedefin son taramasından beri yeni.",
    "You confirmed this as a real threat.": "Bunu gerçek bir tehdit olarak doğruladınız.",
    "Confidence adjusted from %d%% by past feedback on this rule: %d false positive(s), "
    "%d confirmed.":
        "Güven, bu kuralla ilgili geçmiş geri bildirimlere göre %%%d değerinden ayarlandı: "
        "%d yanlış alarm, %d doğrulama.",
    "This exact code was seen %d times across %d scans.":
        "Tam olarak bu kod %d kez, %d farklı taramada görüldü.",
    "The memory center could not be updated:\n\n%s": "Hafıza merkezi güncellenemedi:\n\n%s",
    "Remembered as a false positive": "Yanlış alarm olarak hatırlanacak",
    "Remembered as a confirmed threat": "Doğrulanmış tehdit olarak hatırlanacak",
    "Remember scans and learn from my feedback":
        "Taramaları hatırla ve geri bildirimlerimden öğren",
    "Scan results, including the code snippets they contain, are kept in a local database "
    "on this PC. Nothing is uploaded.":
        "Tarama sonuçları, içerdikleri kod parçalarıyla birlikte bu bilgisayardaki yerel bir "
        "veritabanında tutulur. Hiçbir şey yüklenmez.",
    "What the scanner has learned": "Tarayıcının öğrendikleri",
    "Scan history": "Tarama geçmişi",
    "Rule": "Kural",
    "Engine": "Motor",
    "False positives": "Yanlış alarmlar",
    "Confirmed": "Doğrulanan",
    "Confidence": "Güven",
    "Verdict": "Sonuç",
    "Target": "Hedef",
    "Forget everything learned": "Öğrenilenlerin tümünü unut",
    "Clear scan history": "Tarama geçmişini temizle",
    "Learning is switched off in Settings.": "Öğrenme, Ayarlar'da kapatılmış.",
    "Each false positive lowers a rule's confidence for that engine and each confirmed "
    "threat raises it. Feedback slowly fades (half-life 180 days).":
        "Her yanlış alarm, kuralın o motor için güvenini düşürür; her doğrulanmış tehdit "
        "yükseltir. Geri bildirimin etkisi zamanla azalır (yarı ömrü 180 gün).",
    "Nothing learned yet. Mark findings as a false positive or a confirmed threat to teach "
    "the scanner.":
        "Henüz bir şey öğrenilmedi. Tarayıcıyı eğitmek için bulguları yanlış alarm veya "
        "doğrulanmış tehdit olarak işaretleyin.",
    "%d scans  ·  %d stored findings  ·  %d feedback entries":
        "%d tarama  ·  %d kayıtlı bulgu  ·  %d geri bildirim",
    "Double-click a scan to put its folder in the scan box.":
        "Klasörünü tarama kutusuna koymak için bir taramaya çift tıklayın.",
    "Forget every false-positive and confirmed-threat decision? Rule confidence returns to "
    "its built-in values.":
        "Tüm yanlış alarm ve doğrulanmış tehdit kararları unutulsun mu? Kural güvenleri "
        "yerleşik değerlerine döner.",
    "Delete the stored scan history and code snippets? What the scanner has learned is kept.":
        "Kayıtlı tarama geçmişi ve kod parçaları silinsin mi? Tarayıcının öğrendikleri "
        "korunur.",
    # -- exported reports -------------------------------------------------------
    "Scan report": "Tarama raporu",
    "Risk score": "Risk puanı",
    "Findings": "Bulgular",
    "Showing %d of %d findings": "%d / %d bulgu gösteriliyor",
    "No findings match the current filter.": "Geçerli filtreyle eşleşen bulgu yok.",
    "Confidence": "Güven",
    "Quarantined": "Karantinada",
    "Suppressed: %s": "Bastırıldı: %s",
    "Evidence": "Kanıt",
    "Snippet": "Kod parçası",
    "Quarantined files": "Karantinaya alınan dosyalar",
    "Notes": "Notlar",
    "Generated by %s %s": "%s %s tarafından oluşturuldu",
    "Page %d": "Sayfa %d",
    # -- secure launcher (command line) -------------------------------------------
    "launch: not a file: %s": "başlatma: bu bir dosya değil: %s",
    "launch: refusing to scan a whole drive as a game folder: %s":
        "başlatma: bütün bir sürücü oyun klasörü olarak taranmaz: %s",
    "launch: cannot read %s (%s)": "başlatma: %s okunamıyor (%s)",
    "launch: %s could not be started (%s)": "başlatma: %s başlatılamadı (%s)",
    "cancelled": "iptal edildi",
    "BLOCKED  : %s was NOT started - the scan did not complete (%s)":
        "ENGELLENDİ: %s BAŞLATILMADI - tarama tamamlanmadı (%s)",
    "BLOCKED  : %s was NOT started - %d finding(s) that always stop a launch:":
        "ENGELLENDİ: %s BAŞLATILMADI - başlatmayı her zaman durduran %d bulgu var:",
    "  ... and %d more": "  ... ve %d tane daha",
    "BLOCKED  : %s was NOT started - this needs a confirmation and nobody is there to give one "
    "(not an interactive terminal)":
        "ENGELLENDİ: %s BAŞLATILMADI - onay gerekiyor ama onay verecek kimse yok (etkileşimli "
        "bir terminal değil)",
    "BLOCKED  : %s was NOT started - not confirmed": "ENGELLENDİ: %s BAŞLATILMADI - onaylanmadı",
    "BLOCKED  : %s changed while it was being scanned - not started":
        "ENGELLENDİ: %s taranırken değişti - başlatılmadı",
    "LAUNCHED : %s (process %s) - started because you confirmed it":
        "BAŞLATILDI: %s (süreç %s) - siz onayladığınız için başlatıldı",
    "LAUNCHED : %s (process %s) - the scan found nothing that needs a question":
        "BAŞLATILDI: %s (süreç %s) - tarama, soru gerektiren bir şey bulmadı",
    "WARNING  : high-risk behaviour was found in the folder of %s. This can be a false alarm, "
    "but it is what harmful programs do too. The main reasons:":
        "UYARI    : %s dosyasının klasöründe yüksek riskli davranış bulundu. Bu yanlış alarm "
        "olabilir, ama zararlı programlar da böyle davranır. Başlıca nedenler:",
    "A download-and-run chain was found in an engine file that could not be verified":
        "Doğrulanamayan bir motor dosyasında indir-ve-çalıştır zinciri bulundu",
    "This file belongs to the game's engine (Ren'Py). It downloads something and runs it. The "
    "engine's official updater does that too, but this copy of the engine is a version the "
    "scanner has no official files for, so nobody checked that the file is the genuine one.":
        "Bu dosya oyunun motoruna (Ren'Py) ait. Bir şey indirip çalıştırıyor. Motorun resmi "
        "güncelleyicisi de bunu yapar; ancak motorun bu kopyası, tarayıcının elinde resmi "
        "dosyaları bulunmayan bir sürüm. Bu yüzden dosyanın gerçek dosya olup olmadığını kimse "
        "denetlemedi.",
    "QUESTION : the scan found something in the folder of %s that deserves a look:":
        "SORU     : tarama, %s dosyasının klasöründe göz atmaya değer bir şey buldu:",
    "NOT SEEN : %d part(s) of the game could not be inspected, so nobody knows what is inside. "
    "For example: %s":
        "GÖRÜLMEDİ: oyunun %d parçası incelenemedi; içinde ne olduğunu kimse bilmiyor. Örneğin: %s",
    "To start the game anyway, type the word %s and press Enter. Anything else means no: ":
        "Oyunu yine de başlatmak için %s sözcüğünü yazıp Enter'a basın. Başka her şey hayır "
        "demektir: ",
    "Start the game anyway? Type y for yes. Anything else means no [y/N]: ":
        "Oyun yine de başlatılsın mı? Evet için e yazın. Başka her şey hayır demektir [e/H]: ",
    "launch": "başlat",
}


def t(text: str, *args) -> str:
    """Interface string in the current language, %-formatted with ``args``."""
    if _lang == "tr":
        text = UI_TR.get(text, text)
    return text % args if args else text


# -- fixed vocabularies ---------------------------------------------------------
_SEVERITY_TR = {"CRITICAL": "KRİTİK", "HIGH": "YÜKSEK", "MEDIUM": "ORTA", "LOW": "DÜŞÜK"}
_SEVERITY_CAP_TR = {"CRITICAL": "Kritik", "HIGH": "Yüksek", "MEDIUM": "Orta", "LOW": "Düşük"}
_CATEGORY_TR = {
    "EXECUTION": "Kod Yürütme", "OBFUSCATION": "Gizleme", "PROCESS": "Süreç", "NETWORK": "Ağ",
    "FILESYSTEM": "Dosya Sistemi", "PERSISTENCE": "Kalıcılık", "CREDENTIALS": "Kimlik Bilgileri",
    "INPUT_CAPTURE": "Girdi Yakalama", "PACKING": "Paketleme", "EVASION": "Atlatma",
    "SIGNATURE": "İmza", "REPUTATION": "İtibar", "CHAIN": "Zincir",
}
_VERDICT_TR = {
    "CLEAN": ("TEMİZ", "Şüpheli bir davranış bulunamadı"),
    "LIKELY SAFE": ("MUHTEMELEN GÜVENLİ", "Yalnızca düşük önemde işaretler var"),
    "REVIEW": ("İNCELEYİN", "Bazı davranışlara elle göz atılmalı"),
    "SUSPICIOUS": ("ŞÜPHELİ", "Yüksek riskli davranış tespit edildi"),
    "DANGEROUS": ("TEHLİKELİ", "Zararlı yazılım benzeri davranış tespit edildi"),
}


def severity(sev: Severity, caption: bool = False) -> str:
    if _lang != "tr":
        return sev.name.title() if caption else sev.name
    return (_SEVERITY_CAP_TR if caption else _SEVERITY_TR)[sev.name]


def category(cat: Category) -> str:
    if _lang != "tr":
        return cat.value.replace("_", " ").title()
    return _CATEGORY_TR[cat.value]


_PLAIN_TR = {
    "safe": "Belirgin bir tehlike işareti bulunamadı",
    "unusual": "Muhtemelen sorun yok: %d dosya alışılmadık bir şey yapıyor - kısaca göz atmaya değer",
    "caution": "Dikkat: %d şüpheli dosya var - çalıştırmadan önce inceleyin",
    "unread": "Tam denetlenemedi: %d dosya okunamadı - yalnızca geldiği kaynağa güveniyorsanız çalıştırın",
    "danger": "Bu oyunu çalıştırmayın",
    "danger_pc": "İşaretlenen %d dosyayı çalıştırmayın",
}


def plain_verdict(report: ScanReport) -> str:
    """The one-sentence verdict for non-technical users, in the current language."""
    if _lang != "tr":
        return report.plain_verdict
    kind, files = report.plain_verdict_parts()
    if kind == "danger" and report.is_pc_scan:
        kind = "danger_pc"
    text = _PLAIN_TR[kind]
    return text % files if "%d" in text else text


_ARAC = ("Oyun betiklerinde yaygındır ve tek başına zararsızdır. Yalnızca indirme veya kod çözme "
         "ile birlikte önem kazanır - bir saldırı zinciri bildirilip bildirilmediğine bakın.")
_MOTOR = ("Windows'un kendi koruma motoru bunu zararlı yazılım olarak tanımladı. Oyunu "
          "çalıştırmayın; dosyayı karantinaya alın.")
_BASLANGIC = ("Görev Yöneticisi'ni açın, Başlangıç uygulamaları sekmesine gidin ve tanımıyorsanız "
              "girdiyi devre dışı bırakın.")
_KILIK = ("Resim veya belge gibi görünen bir program klasik bir hiledir. Açmayın.")
_MAKRO = ("Bu belgeyi beklemiyorsanız ve gönderene güvenmiyorsanız Office'te \"İçeriği "
          "Etkinleştir\"e tıklamayın.")
_INCELENEMEDI = ("Betikler incelenemedi. Oyunu yalnızca geldiği kaynağa güveniyorsanız "
                 "çalıştırın.")
ADVICE_TR = {
    "EXECUTION": "Çalıştırılan kodun nereden geldiğine bakın. Oyunun kendi dosyalarından gelen "
                 "kod normaldir; önce indirilen veya kodu çözülen kod, oyunu çalıştırmamak için "
                 "bir nedendir.",
    "OBFUSCATION": "Bir oyunda gizlenmiş veya kodlanmış kod şüphe uyandırmalıdır. Geliştirici "
                   "bunu açıklamıyorsa (örneğin ticari bir eklenti), oyunu güvensiz sayın.",
    "PROCESS": "Oyunların başka program başlatması nadiren gerekir. Kod parçasına bakın: bir "
               "klasör veya web sayfası açmak zararsızdır, cmd veya PowerShell çalıştırmak "
               "değildir.",
    "NETWORK": "Adrese bakın. Geliştiricinin sitesi, güncelleme denetimi veya mağaza bağlantısı "
               "normaldir; bilinmeyen bir sunucu veya yalnızca rakamlardan oluşan bir adres, "
               "oyunu çalıştırmamak için bir nedendir.",
    "FILESYSTEM": "Neyin silindiğine veya değiştirildiğine bakın. Oyunun kendi kayıtları ve "
                  "önbelleği sorun değildir; kullanıcı klasörünüzdeki veya Windows'taki herhangi "
                  "bir şey sorundur.",
    "PERSISTENCE": "Bir oyunun Windows ile birlikte başlaması için hiçbir neden yoktur. Bunu "
                   "neden yaptığını tam olarak bilmiyorsanız çalıştırmayın.",
    "CREDENTIALS": "Bir oyundaki hiçbir şey tarayıcı parolalarını, cüzdanları veya sohbet "
                   "oturumlarını okumamalıdır. Çalıştırmayın; çalıştırdıysanız parolalarınızı "
                   "başka bir cihazdan değiştirin.",
    "INPUT_CAPTURE": "Oyunun içinde tuşları okumak normaldir; oyunun dışında tuşları, ekranı "
                     "veya panoyu kaydetmek casusluktur. Kaynağa güvenmiyorsanız çalıştırmayın.",
    "PACKING": "Paketlenmiş bir program gerçek kodunu gizler. Bazı geliştiriciler bunu korsana "
               "karşı yapar, ancak ne yaptığını kimse denetleyemez - yalnızca geldiği yere "
               "güveniyorsanız çalıştırın.",
    "EVASION": "Dürüst yazılım dosyaları kılık değiştirmez veya korumayı kapatmaz. Bunu güçlü "
               "bir uyarı işareti sayın.",
    "SIGNATURE": "Bilinen bir zararlı yazılım imzası eşleşti. Dosyayı çalıştırmayın; karantinaya "
                 "alın.",
    "REPUTATION": "Hangi antivirüs motorlarının dosyayı işaretlediğini ve ona ne ad verdiklerini "
                  "görmek için kod parçasında gösterilen VirusTotal adresini açın.",
    "CHAIN": "Birkaç riskli davranış bir arada görülüyor; gerçek zararlı yazılımlar böyle "
             "kurulur. Geliştirici her parçayı açıklayamıyorsa bu oyunu çalıştırmayın.",
    "PY-EXEC-001": _ARAC, "JS-EXEC-001": _ARAC, "RB-EXEC-001": _ARAC,
    "URL-001": "Genellikle zararsızdır. Adresin geliştiriciye veya tanıdığınız bir hizmete ait "
               "olduğunu denetleyin.",
    "SIG-EICAR": "Bu yalnızca bir test dosyasıdır. Zararsızdır ve silinebilir.",
    "AMSI-001": _MOTOR, "DEFENDER-001": _MOTOR,
    "VT-003": "Bilinmiyor olması kötü olduğu anlamına gelmez - küçük bağımsız oyunların çoğu "
              "bilinmez. Diğer bulgulara göre karar verin.",
    "VT-004": "Birkaç gün sonra yeniden tarayın veya diğer bulgulara göre karar verin: hiç "
              "tespiti olmayan yepyeni bir dosya henüz hiçbir şey kanıtlamaz.",
    "SCAN-ERR-001": "Tarayıcı bu dosyayı okuyamadı; bu yüzden hakkında hiçbir şey bilinmiyor. "
                    "İhtiyacınız yoksa çalıştırmayın; varsa Windows Güvenliği ile tarayın.",
    "ARC-001": "Arşivle birlikte size bir parola verildiyse, arşivi bir klasöre açın ve o "
               "klasörü tarayın.",
    "ARC-ENC-EXEC-001": "Nereden geldiğine güvenmiyorsanız bu arşivden hiçbir şey çalıştırmayın. Size "
                        "bir parola verildiyse, arşivi bir klasöre açın ve içindekileri açmadan önce o "
                        "klasörü tarayın.",
    "CHAIN-LOCAL-DROP": "Bir oyunun kendi dosyalarında program saklaması için pek bir neden yoktur. Oyunu "
                        "geliştiricisinin kendi sayfasından almadıysanız ve geliştirici bunu açıklayamıyorsa "
                        "çalıştırmayın.",
    "CHAIN-LOCAL-DROP-PLUS": "Bu oyunu çalıştırmayın. Oyunu geliştiricisinin kendi sayfasından almadıysanız "
                             "silin ve bilgisayarı Windows Güvenliği ile tam taramadan geçirin.",
    "SIDELOAD-001": "Oyunlar bu tür kitaplıklarla gelir, ama Microsoft imzalı olarak. Oyunu "
                    "geliştiricisinin kendi sayfasından almadıysanız yanındaki programı çalıştırmayın; "
                    "oradan alınan temiz bir kopyada imzalı dosya bulunmalıdır.",
    "DOC-001": _MAKRO, "DOC-002": _MAKRO,
    "AUTORUN-001": _BASLANGIC, "AUTORUN-002": _BASLANGIC,
    "AUTORUN-003": "Zararsız bir kalıntı. Girdiyi Görev Yöneticisi'ndeki Başlangıç uygulamaları "
                   "bölümünden kaldırabilirsiniz.",
    "NAME-001": _KILIK, "NAME-002": _KILIK,
    "RGSS-FMT-001": _INCELENEMEDI, "RGSS-FMT-002": _INCELENEMEDI,
    "MEDIA-001": "Tek başına genellikle zararsızdır. Aynı dosyada başka bulgular varsa onlara "
                 "göre karar verin.",
    "MEDIA-002": "Bir görüntü veya ses dosyasının içinde program bulunması için meşru bir neden "
                 "yoktur. Geliştirici açıklayamıyorsa oyunu çalıştırmayın.",
    "PE-ENT-003": "Ticari korumalar da bunu yapar. Oyunun nereden geldiğine ve diğer bulgulara "
                  "göre karar verin.",
    "ENGINE-001": "Motor dosyaları genellikle değiştirilmez. Oyunu güvendiğiniz bir kaynaktan "
                  "almadıysanız bu dosyanın diğer bulgularına dikkat edin.",
    "ENGINE-002": "Birçok gerçek motor dosyası zaten imzalanmaz (NW.js, Ren'Py'nin Python'u, SDL). "
                  "Bu dosyanın diğer bulgularına ve oyunun nereden geldiğine göre karar verin.",
    "PROC-LIST-001": "Tek başına zararsızdır. Bir oyunun başka nelerin çalıştığına bakmasını "
                     "istemiyorsanız bunu geliştiricisine sorun - bu, zararlı yazılım belirtisi değildir.",
    "ENGINE-003": "Oyunlar bazen bir motor dosyasını uyarlar; bu tek başına zararsızdır. Oyunu "
                  "güvendiğiniz bir kaynaktan almadıysanız bu dosyanın diğer bulgularına bakın.",
    "ENGINE-004": "Oyunu geliştiricisinin kendi sayfasından almadıysanız ve geliştirici bu dosyayı "
                  "açıklayamıyorsa oyunu çalıştırmayın. Resmi kaynaktan yeni indirilen bir kopyada "
                  "bu dosya böyle olmamalıdır.",
    "ENGINE-005": "Geliştirici motor dosyasını uyarladıysa zararsızdır - yanındaki kaynak dosya "
                  "neyin değiştiğini gösterir. Oyunu güvendiğiniz bir kaynaktan almadıysanız o "
                  "kaynak dosyanın bulgularına bakın.",
    "ENGINE-006": "Zararsızdır: motorun güncellenmesinden geriye kalmış resmi bir dosya. Bir şey "
                  "yapmanız gerekmez.",
    "IAT-001": "Bir oyunun bunları içe aktarması için bir neden yoktur. Nedenini tam olarak "
               "bilmiyorsanız (örneğin kendi kurduğunuz bir hile koruması) oyunu çalıştırmayın.",
    "IAT-002": "Bir oyun için alışılmadık. Koruma yazılımları da bunu yapar; diğer bulgulara ve "
               "oyunun nereden geldiğine göre karar verin.",
    "IAT-003": "Yerel ağ kitaplığı kullanan çevrimiçi oyunlar bunları içe aktarır. Oyunun "
               "çevrimdışı çalışması gerekiyorsa dikkatli olun.",
    "IAT-004": "İçerik koruması da şifreleme kullanır. Diğer bulgulara göre karar verin.",
    "IAT-005": "Bir oyunun kendi kodu için alışılmadık. Diğer bulgulara ve oyunun nereden "
               "geldiğine göre karar verin.",
    "IAT-006": "Genellikle yalnızca incelenmemiş bir Unity sürümüdür. Tek başına bir işlem "
               "gerektirmez.",
    "IL2CPP-META-001": "Korumalı oyunlarda yaygındır. Diğer bulgulara göre karar verin.",
    "RGSS-RT-001": "Oyunu güvendiğiniz bir kaynaktan aldıysanız dosyayı güvenilir listesine "
                   "ekleyebilirsiniz; emin değilseniz dosyayı VirusTotal'da denetleyin.",
    "ARC-002": "İçeriğin bir bölümü incelenemedi. Dosyayı yalnızca geldiği kaynağa güveniyorsanız "
               "çalıştırın.",
    "UNITY-FMT-001": "Paketin bir bölümü incelenemedi. Oyunu yalnızca geldiği kaynağa "
                     "güveniyorsanız çalıştırın.",
    "RPY-FMT-001": "Betik incelenemedi. Oyunu yalnızca geldiği kaynağa güveniyorsanız çalıştırın.",
    "PYO-FMT-001": "Derlenmiş dosya incelenemedi. Oyunu yalnızca geldiği kaynağa güveniyorsanız "
                   "çalıştırın.",
    "PY-JOIN-001": "Bu betiğin denetimlerinden biri tamamlanamadı. Oyunu yalnızca geldiği kaynağa "
                   "güveniyorsanız çalıştırın.",
    "ENGINE-007": "Oyunu geliştiricisinin kendi sayfasından almadıysanız ve geliştirici bu dosyayı "
                  "açıklayamıyorsa oyunu çalıştırmayın. Derlenmiş bir dosya, kaynağından fazlasını "
                  "asla yapmamalıdır.",
    "ENGINE-008": "Oyunlar motorun programlarını nadiren değiştirir. Oyunu yalnızca geliştiricisinin "
                  "kendi sayfasından aldıysanız çalıştırın; oradan alınan yeni bir kopyada resmi "
                  "dosyalar olmalıdır.",
    "ENGINE-009": "Uygulamalar çoğu zaman kendi yardımcı programlarını getirir. Oyunu yalnızca "
                  "geliştiricisinin kendi sayfasından aldıysanız ve geliştirici bu programın ne olduğunu "
                  "söyleyebiliyorsa çalıştırın.",
    "RPY-CONTENT-001": "Derlenmiş betik gibi adlandırılmış ama başka bir şey olan bir dosya, bir programı "
                       "ya da veriyi saklamanın bir yoludur. Oyunu yalnızca geliştiricisinin kendi "
                       "sayfasından aldıysanız çalıştırın.",
    "INST-REDIST-001": "Oyun kurulum programlarında olağandır. İndirilen dosya resmi adresinden "
                       "geliyor ama paketin parçası olmadığı için taranamadı; kurulum programını "
                       "yalnızca geldiği kaynağa güveniyorsanız çalıştırın.",
    "INNO-CODE-001": "Kurulum programının kendi komutları sonuna kadar okunamadı. Kurulum programını "
                     "yalnızca geldiği kaynağa güveniyorsanız çalıştırın.",
    "DN-IL-001": "Bu .NET kitaplığının kodu sonuna kadar okunamadı; içindeki bir indir-ve-çalıştır "
                 "gözden kaçmış olabilir. Oyunu yalnızca geldiği kaynağa güveniyorsanız başlatın.",
    "SCRIPT-LIMIT-001": "Bu betik indir-ve-çalıştır açısından sonuna kadar okunmadı: tarayıcının izlediğinden "
                        "daha büyük ya da daha uzun. Yalnızca geldiği kaynağa güveniyorsanız çalıştırın.",
    "ENC-SCRIPT-001": "Bu dosyadaki şifrelenmiş betik çözülemedi; bu yüzden neyi çalıştırdığı incelenemedi. "
                      "Yalnızca geldiği kaynağa güveniyorsanız çalıştırın.",
    "EXEC-FMT-001": "Bu, tarayıcının okuyamadığı türden bir program (Java): ne yaptığı incelenemedi. "
                    "Yalnızca geldiği kaynağa güveniyorsanız başlatın.",
    "JSC-FMT-001": "Bu, tarayıcının okuyamadığı derlenmiş JavaScript: bu kodun ne yaptığı incelenemedi. "
                   "Oyunu yalnızca geldiği kaynağa güveniyorsanız başlatın.",
    "SCAN-COVERAGE-001": "Bu klasörün büyük bölümü, tarayıcının okumadığı türden dosyalardan oluşuyor - büyük "
                         "olasılıkla tarayıcının tanımadığı bir oyun motoru. Tarama bu klasör hakkında az şey "
                         "söylüyor. Oyunu yalnızca geldiği kaynağa güveniyorsanız başlatın.",
}


def advice(f: Finding) -> str:
    """"What should I do?" for a finding, in the current language."""
    key = advice_module.key_for(f.rule_id, f.category.value)
    if _lang == "tr" and key in ADVICE_TR:
        return ADVICE_TR[key]
    return advice_module.for_finding(f.rule_id, f.category.value)


def verdict_name(name: str) -> str:
    return _VERDICT_TR[name][0] if _lang == "tr" and name in _VERDICT_TR else name


def verdict(report: ScanReport) -> Tuple[str, str]:
    if _lang != "tr":
        return report.verdict, report.verdict_detail
    if report.unread_only:
        return _VERDICT_TR[report.verdict][0], "İçeriğin bir bölümü okunamadı"
    return _VERDICT_TR[report.verdict]


# -- findings: (title, reason) per rule id ---------------------------------------
RULES_TR = {
    "PY-EXEC-001": ("Dinamik kod yürütme (exec/eval)",
                    "Çalışma anında oluşturulan kodu çalıştırır. Oyun betiklerinde yaygındır; girdi "
                    "indirilmiş veya kodu çözülmüş veriyse tehlikelidir."),
    "PY-EXEC-002": ("Dinamik içe aktarma / kod nesnesi oluşturma",
                    "Modülleri çalışma anında adla yükler veya kod nesneleri oluşturur; bu, gerçekte neyin "
                    "çalıştırıldığını gizler."),
    "PY-EXEC-003": ("ctypes ile yerel kütüphane yükleme",
                    "Betik kodundan doğrudan işletim sistemi API'lerini çağırarak motorun korumalı "
                    "alanını atlar."),
    "PY-OBF-001": ("Kodu çözülmüş/açılmış yükün çalıştırılması",
                   "Gizli bir yükün kodunu çözüp tek adımda çalıştırır - klasik gizlenmiş yükleyici "
                   "kalıbı."),
    "PY-OBF-002": ("Yük kodu çözme işlevi",
                   "Gömülü verinin kodunu çözer veya sıkıştırmasını açar. Kayıtlar ve varlıklar için "
                   "zararsızdır; kod yürütmenin yanında şüphelidir."),
    "PY-PROC-001": ("Alt süreç / kabuk komutu başlatma",
                    "Oyun betiğinden harici bir program veya kabuk komutu başlatır."),
    "PY-NET-001": ("Ağ istemcisi kullanımı",
                   "Oyun betiğinden ağ bağlantıları açar (HTTP, ham soket, FTP veya e-posta)."),
    "PY-FS-001": ("Dosya / dizin silme", "Dosyaları veya dizin ağaçlarını siler."),
    "JS-EXEC-001": ("Dinamik kod yürütme (eval / Function)",
                    "Çalışma anında oluşturulan kodu çalıştırır. Eklentiler bunu not etiketleri için "
                    "kullanır; girdi indirilmiş veya kodu çözülmüş veriyse tehlikelidir."),
    "JS-OBF-001": ("Kodu çözülmüş yükün çalıştırılması",
                   "Gizli bir dizgenin kodunu çözüp hemen çalıştırır - gizlenmiş bir yükleyici."),
    "JS-OBF-002": ("Dizge kodu çözme işlevi",
                   "Dizgeleri kodlanmış veriden yeniden oluşturur; bu, URL'leri ve komutları "
                   "incelemeden gizler."),
    "JS-OBF-003": ("Kod gizleyici izi (_0x tanımlayıcıları)",
                   "Dosya bir JavaScript kod gizleyicisinden geçirilmiş; bu nedenle davranışı okunarak "
                   "incelenemez."),
    "JS-PROC-001": ("Alt süreç başlatma (Node.js)",
                    "Bilgisayarda istediği programı başlatma yeteneği kazanır. Oyun eklentilerinin buna "
                    "neredeyse hiç ihtiyacı olmaz."),
    "JS-PROC-002": ("Windows Script Host / ActiveX otomasyonu",
                    "Komut çalıştırabilen ve kayıt defterini değiştirebilen Windows betik nesnelerini "
                    "kullanır."),
    "JS-NET-001": ("Ağ isteği", "Bir ağ veya kaynak isteği yapar."),
    "JS-NET-002": ("NW.js node-remote etkin",
                   "İnternetten yüklenen sayfalara bu bilgisayarda tam Node.js erişimi verir."),
    "JS-FS-001": ("Node.js dosya sistemi yazma / silme", "Node.js üzerinden dosya yazar veya siler."),
    "JS-ENV-001": ("Kullanıcı profili / ortam erişimi",
                   "Kullanıcının oyun dizini dışında kalan profil klasörlerini sorgular."),
    "CS-PROC-001": ("Süreç başlatma", "Harici bir program başlatır."),
    "CS-NET-001": ("Ağ istemcisi kullanımı",
                   "Motorun kendi web istekleri yerine ham .NET ağ sınıflarını kullanır."),
    "CS-EXEC-001": ("Çalışma anında derleme yükleme / kod üretme",
                    "Çalışma anında kod yükler veya üretir."),
    "CS-OBF-001": ("Kodu çözülmüş baytlardan derleme yükleme",
                   "Gizli bir derlemenin kodunu çözüp doğrudan belleğe yükler."),
    "CS-OBF-002": ("Base64 kod çözme", "Gömülü Base64 verisinin kodunu çözer."),
    "CS-FS-001": ("Dosya / dizin silme", "Dosyaları veya dizinleri siler."),
    "CS-REG-001": ("Kayıt defteri erişimi", "Windows kayıt defterini okur veya yazar."),
    "CS-PINV-001": ("Sistem DLL'ine P/Invoke", "Yönetilen koddan ham Windows API'lerini çağırır."),
    "DN-PROC-001": ("Süreç başlatma (yönetilen)",
                    "Derleme, .NET süreç başlatma API'sine başvuruyor."),
    "DN-NET-001": ("Ham ağ istemcisi (yönetilen)",
                   "Derleme, motorun kendi web istekleri yerine ham .NET ağ sınıflarına başvuruyor."),
    "DN-EXEC-001": ("Çalışma anında kod üretme (yönetilen)",
                    "Derleme çalışma anında kod üretebilir veya derleyebilir."),
    "DN-OBF-001": ("Base64 kod çözme (yönetilen)", "Derleme Base64 verisinin kodunu çözüyor."),
    "DN-PACK-001": ("Zararlı yazılımlarla ilişkili .NET koruyucusu",
                    "Yayımlanmış oyunlardan çok zararlı yazılımlarda görülen bir araçla korunmuş."),
    "DN-PACK-002": ("Ticari .NET kod gizleyicisi",
                    "Derleme gizlenmiş; bu nedenle davranışı incelenemez."),
    "DN-REG-001": ("Kayıt defteri erişimi (yönetilen)",
                   "Derleme Windows kayıt defteri API'sine başvuruyor."),
    "SH-DL-001": ("Uzaktan indirme", "İnternetten içerik indirir."),
    "SH-EXEC-001": ("İfade çalıştırma / kabuğa yönlendirme",
                    "Metni kod olarak çalıştırır - indirilen yükler bu şekilde çalıştırılır."),
    "SH-PROC-001": ("Betikle süreç başlatma", "Bir betikten başka programlar başlatır."),
    "SH-OBF-001": ("Kodlanmış PowerShell komutu",
                   "Ne yaptığını gizlemek için PowerShell'e Base64 ile kodlanmış bir komut verir."),
    "SH-OBF-002": ("Yürütme ilkesi atlatma / gizli pencere",
                   "PowerShell'i gizli olarak ve güvenlik ilkeleri kapalı şekilde çalıştırır."),
    "SH-OBF-003": ("Kod çözme işlevi", "Gömülü veriyi kullanmadan önce kodunu çözer."),
    "SH-FS-001": ("Özyinelemeli / zorla silme",
                  "Dosyaları alt klasörleriyle birlikte veya onay almadan siler."),
    "SH-HIDE-001": ("Dosya gizleme", "Dosyaları gizli/sistem olarak işaretler."),
    "LOL-001": ("Sistem yorumlayıcısı / LOLBin çağrısı",
                "Zararlı yazılımların komut çalıştırmak ve yük indirmek için kullandığı bir Windows "
                "sistem aracına başvurur."),
    "INJ-001": ("Süreç enjeksiyonu API'si",
                "Çalışan başka bir sürecin içine kod yazar - güvenilir programların içine gizlenmek "
                "için kullanılır."),
    "OBF-BLOB-001": ("Büyük kodlanmış veri bloğu",
                     "Koda uzun bir kodlanmış dizge gömülmüş; bir yük gizliyor olabilir."),
    "OBF-BLOB-001#MZ": ("Gömülü Windows programı (kodlanmış blok)",
                        "Kodlanmış dizge çözüldüğünde bir Windows programına (MZ başlığı) dönüşüyor."),
    "OBF-HEX-001": ("Kaçış dizili bayt yükü",
                    "Uzun bir kaçış dizili bayt serisi okunabilir içeriği veya kabuk kodunu gizler."),
    "OBF-PE-001": ("Gömülü Windows programı (Base64)",
                   "Dosyaya, çözüldüğünde bir Windows programına dönüşen bir Base64 dizgesi gömülmüş."),
    "URL-001": ("Sabit kodlanmış URL",
                "Bilinen zararsız listesinde olmayan bir web adresine bağlanır veya bağlantı verir."),
    "URL-IP-001": ("Ham IP adresli URL",
                   "Adlandırılmış bir site yerine çıplak bir IP adresiyle konuşur - tek kullanımlık "
                   "zararlı yazılım sunucularının tipik özelliği."),
    "NET-EXFIL-001": ("Veri sızdırma / bırakma uç noktası",
                      "Bilgi hırsızlarının çalınan veriyi dışarı göndermek veya yük çekmek için "
                      "kullandığı bir hizmeti kullanır."),
    "NET-RECON-001": ("Genel IP sorgulama hizmeti",
                      "Oyuncunun genel IP adresini / konumunu sorgular."),
    "NET-PE-001": ("İnternetten indirme API'si",
                   "Uzak içeriği almak için Windows internet API'lerini kullanır."),
    "FS-SYS-001": ("Hassas sistem yolu",
                   "Bir oyunun dokunması için hiçbir neden olmayan işletim sistemi konumlarına "
                   "başvurur."),
    "PERSIST-001": ("Kalıcılık mekanizması",
                    "Bir şeyin bilgisayarla birlikte otomatik başlamasını ayarlar."),
    "CRED-001": ("Kimlik bilgisi / cüzdan / belirteç deposuna erişim",
                 "Tarayıcıların, sohbet uygulamalarının ve cüzdanların parolaları ve oturum "
                 "belirteçlerini sakladığı yerlere dokunur."),
    "INPUT-001": ("Tuş vuruşlarını yakalama",
                  "Kullanıcının oyun dışında yazdıklarını kaydedebilir."),
    "INPUT-002": ("Ekran / pano yakalama", "Ekranı yakalayabilir veya panoyu okuyabilir."),
    "INPUT-003": ("Tuş kaydı sözlüğü",
                  "Programın içinde köşeli parantezli bir tuş adı tablosu var ([ENTER], [BACKSPACE] "
                  "...); tuş kaydediciler yazılanı böyle not eder. Tek başına bir şey kanıtlamaz - "
                  "yardım metinleri de aynı gösterimi kullanır - ama bir girdi kancası veya bilinen "
                  "bir sızdırma adresi ile birlikte bir tuş kaydediciyi sıradan bir programdan ayıran "
                  "şey budur."),
    "EVADE-001": ("Güvenlik aracına müdahale / analiz engelleme",
                  "Korumayı kapatmaya, kurtarma verilerini yok etmeye veya analiz araçlarını "
                  "algılamaya çalışır."),
    # structural findings raised by handlers
    "NAME-001": ("Yanıltıcı çift uzantı",
                 "Dosya adı bir belge veya medya dosyası gibi görünüyor, ancak aslında "
                 "çalıştırılabilir."),
    "NAME-002": ("Gizlenmiş çalıştırılabilir dosya",
                 "Dosya bir Windows programı içeriyor, ancak uzantısı başka bir şey söylüyor."),
    "NAME-003": ("Alışılmadık çalıştırılabilir türü",
                 "Oyunlar normalde bu türde program içermez; bu tür, zararlı yazılımları gizlemek "
                 "için sık kullanılır."),
    "PE-FMT-001": ("Bozuk çalıştırılabilir başlığı",
                   "Dosya bir Windows programı gibi başlıyor, ancak başlıkları çözümlenemiyor."),
    "PE-PACK-001": ("Paketlenmiş çalıştırılabilir dosya (%s)",
                    "Programın gerçek kodu sıkıştırılmış/şifrelenmiş ve yalnızca bellekte açılıyor; bu, "
                    "kodu incelemeden gizler."),
    "PE-PACK-002": ("Yüksek entropili kod bölümü",
                    "Rastgele veriye benzeyen çalıştırılabilir kod genellikle şifrelenmiş veya "
                    "sıkıştırılmıştır."),
    "PE-PACK-003": ("Yazılabilir + çalıştırılabilir bölüm",
                    "Çalışma anında kendini yeniden yazabilen kod, paketleyicilerin ve kendini "
                    "değiştiren zararlı yazılımların tipik özelliğidir."),
    "PE-PACK-004": ("Çok küçük içe aktarma tablosu",
                    "Program neredeyse hiç sistem işlevi bildirmiyor; gerçekte kullandıklarını çalışma "
                    "anında çözümlüyor."),
    "DF-EXEC-001": ("Çalıştırılan kod çözümlendi",
                    "exec/eval çağrısına verilen kod, betiğin onu nasıl oluşturduğu izlenerek yeniden "
                    "kuruldu. Gerçekte çalışan kod budur."),
    "DF-CMD-001": ("Komut satırı çözümlendi",
                   "Bu betiğin başlattığı komut, değişkenleri atandıkları yere kadar geriye doğru "
                   "izlenerek yeniden kuruldu. Gerçekte çalışan program budur."),
    "DF-URL-001": ("Ağ adresi çözümlendi",
                   "Bu betiğin bağlandığı adres, değişkenleri atandıkları yere kadar geriye doğru "
                   "izlenerek yeniden kuruldu."),
    "DF-PATH-001": ("Dosya hedefi çözümlendi",
                    "Bu betiğin sildiği veya yazdığı dosya, değişkenleri atandıkları yere kadar "
                    "geriye doğru izlenerek yeniden kuruldu."),
    "DF-CALL-001": ("Gizli işlev çağrısı çözümlendi",
                    "Bir işlev veya modül, çalışma anında birleştirilen bir adla aranıyor; bu yüzden "
                    "gerçek çağrı dosyada hiç görünmüyor. Çözümlenen ad budur."),
    "RPY-FMT-001": ("Okunamayan derlenmiş betik",
                    "Derlenmiş betik bilinen bir Ren'Py biçiminde değil; bu nedenle içeriği "
                    "incelenemedi."),
    "PYO-FMT-001": ("Okunamayan derlenmiş Python dosyası",
                    "Derlenmiş Python dosyası yarım kalmış, okuyucunun sınırlarından büyük ya da "
                    "Python 2.7'nin yazdığı biçimde değil; bu nedenle komutları incelenemedi."),
    "PY-JOIN-001": ("Betik, dosyalar arası zincirler için sonuna kadar okunamadı",
                    "Tarayıcı her betiği ikinci kez okur ve betiğin, oyunun başka bir dosyasının "
                    "indirdiği bir şeyi çalıştırıp çalıştırmadığına bakar. Bu betikte o ikinci okuma "
                    "sınırına ulaştı ve erken durdu; bu yüzden başka bir dosyada başlayıp bu dosyada "
                    "biten bir indir-ve-çalıştır zinciri gözden kaçmış olabilir. Dosyanın geri kalan "
                    "her şeyi her zamanki gibi denetlendi."),
    "INST-REDIST-001": ("Kurulum programı resmi bir yardımcı paketi indirip çalıştırıyor",
                        "Bu kurulum programı bir dosya indiriyor ve onu başlatıyor. Adres, tarayıcının "
                        "yaygın yardımcı paketlerin (Visual C++, DirectX, .NET, OpenAL) resmi indirme "
                        "adresleri listesinde ve https üzerinden isteniyor; yani bu, sıradan oyun "
                        "kurulum programlarının yaptığı şeydir. İndirilen dosyanın kendisi "
                        "denetlenemedi: paketin parçası değil."),
    "EXEC-FMT-001": ("Tarayıcının okumadığı türden program",
                     "Bu dosya, tarayıcının okuyucusu olmayan bir çalışma ortamı için yazılmış bir program "
                     "(Java sınıf dosyası: Java için komutlar). Okunmadı; bu yüzden ne yaptığı incelenmedi."),
    "JSC-FMT-001": ("Derlenmiş JavaScript okunamadı",
                    "Bu dosya, V8 motorunun derlediği JavaScript (\"bytenode\" aracının yazdığı biçim): metin "
                    "değil, V8'in sürümden sürüme değişen kendi komutları. Tarayıcı bunları okumuyor; bu yüzden "
                    "bu kodun ne yaptığı incelenmedi. Oyunlar kaynak kodunu gizlemek için bunu kullanır; "
                    "zararlı yazılımlar da aynı nedenle."),
    "SCAN-COVERAGE-001": ("Klasörün büyük bölümü okunmadı",
                          "Bu klasördeki verinin büyük bölümü, tarayıcının açmadığı türden dosyalarda duruyor - "
                          "tanımadığı bir oyun motorunun arşivleri gibi. Okunmayan dosyalarda ne olduğu "
                          "bilinmiyor; içeriği okunmayan bir klasör hiçbir zaman temiz olarak bildirilmez."),
    "SCRIPT-LIMIT-001": ("Betik indir-ve-çalıştır açısından sonuna kadar okunmadı",
                         "Tarayıcı, bir betiğin indirdiği şeyi çalıştırıldığı yere kadar izler. Bu betikte bu okuma "
                         "sınırına ulaşıp erken durdu; bu yüzden betiğin daha aşağısındaki bir indir-ve-çalıştır "
                         "gözden kaçmış olabilir. Olağan kurallar dosyanın tamamını her zamanki gibi okudu."),
    "ENC-SCRIPT-001": ("Şifrelenmiş betik çözülemedi",
                       "Bu dosya, Microsoft'un Script Encoder biçiminde bir betik içeriyor; Windows bunu çözer ve "
                       "düz bir betik gibi çalıştırır. Tarayıcı da çözer ve gizlediğini okur. Burada bu olmadı - "
                       "blok bozuk, yarım ya da göründüğü şey değil - bu yüzden neyi çalıştıracağı incelenemedi."),
    "DN-IL-001": (".NET kitaplığının kodu tam okunamadı",
                  "Bir .NET kitaplığının (C# ile yazılmış oyun kodu) yöntemleri komut komut okunur; "
                  "tarayıcı, kitaplığın ağdan bir şey indirip sonra onu yükleyip yüklemediğini ya da "
                  "başlatıp başlatmadığını böyle görür. Burada bu okuma sona kadar gidemedi; bu yüzden "
                  "kitaplığın içindeki bir indir-ve-çalıştır gözden kaçmış olabilir. Kitaplığın adları "
                  "ve metinleri her zamanki gibi tarandı."),
    "INNO-CODE-001": ("Kurulum programının kendi komutları tam okunamadı",
                      "Bir Inno Setup kurulum programı kendi küçük programını ([Code] bölümü) ve "
                      "başlattığı programların listesini ([Run]) taşıyabilir. Tarayıcı, kurulum "
                      "programının bir şey indirip sonra onu başlatıp başlatmadığını görmek için "
                      "ikisini de okur. Burada bu okuma sonuna kadar gidemedi; bu yüzden kurulum "
                      "programının kendisinin yaptığı bir indir-ve-çalıştır gözden kaçmış olabilir. "
                      "Kurulum programının taşıdığı dosyalar her zamanki gibi tarandı."),
    "ENGINE-007": ("Derlenmiş motor dosyası, kaynağının yapmadığı bir şey yapıyor",
                   "Bu, kaynağını geliştiricinin değiştirdiği bir motor dosyasının derlenmiş hali. "
                   "Ama derlenmiş dosya, adı o kaynakta hiçbir yerde geçmeyen bir şeyi çağırıyor; "
                   "yani o kaynağın derlenmiş hali değil. Python kaynağı değil, derlenmiş dosyayı "
                   "çalıştırır: oyun, kaynağın göstermediği bir şey yapar. Derlenmiş dosyanın "
                   "çağrıları komutlarından yeniden kuruldu ve tarandı; kuralların bulduğu şeyler "
                   "bu dosya için listelendi."),
    "RB-PROC-001": ("Kabuk komutu çalıştırma (Ruby)",
                    "Bilgisayarda bir program veya kabuk komutu çalıştırır. RPG Maker "
                    "betiklerinin bunu yapması için olağan bir neden yoktur."),
    "RB-PROC-002": ("Ters tırnak komutu (Ruby)",
                    "Ruby'de ters tırnaklar arasındaki metin kabuk komutu olarak çalıştırılır."),
    "RB-EXEC-001": ("Dinamik kod yürütme (eval)",
                    "Çalışma anında oluşturulan Ruby kodunu çalıştırır. Motor bunu olay betik "
                    "komutları için yapar; kod çözülmüş veya indirilmişse tehlikelidir."),
    "RB-OBF-001": ("Kodu çözülmüş Ruby yükünün çalıştırılması",
                   "Gizli bir dizgenin kodunu çözüp tek adımda Ruby kodu olarak çalıştırır - "
                   "gizlenmiş bir yükleyici."),
    "RB-OBF-002": ("Sıkıştırması açılmış Ruby kodunun çalıştırılması",
                   "Verinin sıkıştırmasını açıp kod olarak çalıştırır. Özel betik yükleyicileri "
                   "de gizli yükler de bunu yapar."),
    "RB-OBF-003": ("Kod çözme işlevi (Ruby)",
                   "Gömülü verinin kodunu çözer veya sıkıştırmasını açar. Kayıtlar için "
                   "normaldir, kod yürütmenin yanında şüphelidir."),
    "RB-NATIVE-001": ("Yerel Windows API çağrısı (Win32API / Fiddle)",
                      "Bir oyun betiğinden, motorun korumalı alanı dışında doğrudan Windows "
                      "işlevlerini çağırır."),
    "RB-NATIVE-002": ("Program çalıştıran, indiren veya enjekte eden yerel API",
                      "Program başlatan, dosya indiren, kayıt defterini değiştiren veya "
                      "enjekte edilmiş kod çalıştıran bir Windows işlevine uzanır."),
    "RB-NATIVE-003": (_IND[0],
                      _IND[1]),
    "RB-NET-001": ("Ağ erişimi (Ruby)", "Bir oyun betiğinden ağ bağlantıları açar."),
    "RB-FS-001": ("Dosya / dizin silme (Ruby)", "Dosyaları veya dizinleri siler."),
    "RGSS-FMT-001": ("Okunamayan RPG Maker betik tablosu",
                     "Oyunun betik dosyası beklenen biçimde değil; bu nedenle Ruby kodu "
                     "incelenmedi."),
    "RGSS-FMT-002": ("Okunamayan RPG Maker arşivi",
                     "Şifreli oyun arşivi açılamadı; bu nedenle içindeki betikler incelenmedi."),
    "AMSI-001": ("Windows kötü amaçlı yazılımdan koruma motoru, açılan içeriği işaretliyor",
                 "Bu dosyadan açılan içerik, bu bilgisayarda kurulu olan koruma motoruna "
                 "(AMSI üzerinden Windows Defender) gösterildi ve motor onu zararlı yazılım "
                 "olarak tanımladı."),
    "DEFENDER-001": ("Windows Defender bu dosyayı tespit ediyor",
                     "Windows Defender bu dosyayı istek üzerine taradı ve zararlı yazılım "
                     "olarak tanımladı. Defender'a dosyayı kaldırmaması söylendi."),
    "SCAN-ERR-001": ("Dosya incelenemedi",
                     "Tarayıcı bu dosyayı incelerken bir hatayla karşılaştı; bu nedenle içeriği "
                     "denetlenmedi. Bozuk dosyalar bazen tarayıcıları bozmak için özel olarak "
                     "hazırlanır."),
    "PY-EXEC-004": ("Parçalardan oluşturulan bir adla dolaylı çağrı",
                    "Hassas bir işlev, parçalardan birleştirilen bir adla aranıyor; böylece "
                    "gerçek çağrı dosyada hiç görünmüyor."),
    "JS-OBF-004": ("Unicode kaçışlı tanımlayıcı",
                   "Bir işlev veya özellik adı \\u kaçışlarıyla yazılmış (\\u0065val, eval "
                   "demektir); bu, kodu okuyan veya tarayan herkesten onu gizler."),
    "SIG-001": ("Bilinen zararlı yazılım",
                "Dosyanın SHA-256 özeti bilinen zararlı yazılım listesinde: tam olarak bu dosya "
                "daha önce zararlı olarak tanımlanmış."),
    "SIG-EICAR": ("Antivirüs test dosyası (EICAR)",
                  "Bu, bir antivirüsün çalıştığını denetlemek için kullanılan, zararsız ve "
                  "sektör standardı olan test dosyasıdır."),
    "AUTORUN-001": ("Geçici bir konumdan otomatik başlatma",
                    "Windows ile birlikte başlayan bir program geçici, indirilenler veya ortak "
                    "bir klasörde duruyor - meşru yazılımlar başka yere kurulur."),
    "AUTORUN-002": ("Otomatik başlatma gizli veya kodlanmış bir betik çalıştırıyor",
                    "Bir şey, gizli, kodlanmış veya indir-ve-çalıştır argümanları kullanan bir "
                    "betik yorumlayıcısı aracılığıyla Windows ile birlikte başlıyor."),
    "AUTORUN-003": ("Otomatik başlatma girdisi eksik bir dosyayı gösteriyor",
                    "Bir otomatik başlatma girdisi artık var olmayan bir programa işaret ediyor - "
                    "çoğu zaman kaldırılmış bir yazılımın veya temizlenmiş bir zararlının kalıntısı."),
    "DOC-001": ("Office belgesi makro içeriyor",
                "Makrolar belgenin içindeki programlardır. Çoğu belgenin bunlara ihtiyacı yoktur "
                "ve zararlı yazılım dağıtmanın yaygın bir yoludur."),
    "DOC-002": ("Otomatik çalışan ve kod başlatan Office makrosu",
                "Belge, açıldığında kendiliğinden başlayan ve program çalıştırabilen veya dosya "
                "indirebilen bir makro içeriyor."),
    "ARC-001": ("Parola korumalı arşiv",
                "Arşiv şifreli olduğu için içeriği incelenemiyor. Zararlı yazılımlar "
                "tarayıcıları atlatmak için sıkça bu şekilde gönderilir."),
    "ARC-ENC-EXEC-001": ("Program, betik veya arşiv içeren parola korumalı arşiv",
                         "Arşiv şifreli olduğu için içeriği incelenemiyor - ve okunabilir kalan girdi "
                         "listesi programlar, betikler veya başka arşivler gösteriyor. Zararlı yazılımlar, "
                         "çalışacak şeye tarayıcılar bakamasın diye bu şekilde gönderilir."),
    "MEDIA-001": ("Ortam dosyasında ortama ait olmayan veri",
                  "Görüntü veya ses, dosya bitmeden sona eriyor ya da yapısı bir noktada bozuk. "
                  "Bazı düzenleme araçları oraya veri bırakır; aynı yer bir yükü saklamak için de "
                  "kullanılır. Oradaki veri metin olarak okundu ve içinde program arandı."),
    "MEDIA-002": ("Ortam dosyasının ardında program, arşiv veya betik",
                  "Dosya bir görüntü veya ses gibi adlandırılmış (hatta öyle açılıyor olabilir), "
                  "ancak içinde çalıştırılabilen veya açılabilen bir şey var. Bir yükleyici bu "
                  "gizli bölümü çıkarıp kullanabilir."),
    "PE-ENT-003": ("Veri bölümünün içinde şifrelenmiş blok",
                   "Programın verilerinin bir bölümü, çevresindeki veriden farklı olarak "
                   "istatistiksel olarak rastgele: çalışma anında çözülen gömülü bir yük böyle görünür."),
    "ENGINE-001": ("Motor dosyası gibi adlandırılmış, ancak öyle yapılmamış",
                   "Dosya, oyun motorunun bir bileşeninin adını ve konumunu taşıyor; bu onu çoğu "
                   "denetimden muaf tutardı - ancak içeriği o bileşenin yapısına sahip değil. Bu "
                   "nedenle herhangi bir dosya gibi değerlendirildi."),
    "ENGINE-002": ("Üreticisinin imzasını taşımayan motor bileşeni",
                   "Dosya, oyun motorunun bir bileşeninin adına ve yapısına sahip, ancak o bileşenin "
                   "üreticisinden geçerli bir dijital imza taşımıyor. Ad ve yapı taklit edilebilir; "
                   "bu nedenle dosya muaf tutulmadı: bilinmeyen herhangi bir program gibi tarandı "
                   "ve diğer bulguları geçerli."),
    "PROC-LIST-001": ("Çalışan programların listesini okuyor",
                      "Betik, Windows'tan çalışan programların adlarını istiyor (yalnızca okuyan sabit "
                      "bir sorgu; dosyada hiç ağ çağrısı yok). Oyunlar bunu kayıt ya da yayın "
                      "yazılımlarını fark etmek için yapar. Hiçbir şey başlatılmıyor ya da "
                      "değiştirilmiyor; ama bu, bir oyunun ihtiyaç duymadığı, bilgisayarınıza ait "
                      "bir bilgidir."),
    "ENGINE-003": ("Motor dosyası resmi sürümden farklı",
                   "Bu dosya motorun klasöründe duruyor ve Ren'Py'nin bu kopyası, resmi dosyalarını "
                   "tarayıcının bildiği bir sürüm - ama dosya onlardan biri değil: değiştirilmiş ya "
                   "da eklenmiş. Oyunlar motor dosyalarını zararsız nedenlerle uyarlar; bu yüzden bu "
                   "yalnızca bir not. Dosya tarandı; içindeki bir indir-ve-çalıştır zinciri "
                   "klasörden hiçbir güven almaz."),
    "ENGINE-004": ("Derlenmiş motor dosyası farklı, kaynağı ise değişmemiş",
                   "Bu, bir motor dosyasının derlenmiş hali ve resmi sürümün derlenmiş dosyası "
                   "değil - oysa yanındaki kaynak dosya resmi dosya (ya da ondan yalnızca yorum ve "
                   "boşluklarda farklı), ya da hiç kaynak dosya yok. "
                   "Python kaynağı değil, derlenmiş dosyayı çalıştırır; yani oyun, kaynağın "
                   "gösterdiğinden başka bir şey çalıştırır. Derlenmiş dosyanın çağrıları "
                   "komutlarından yeniden kuruldu ve tarandı; kuralların bulduğu şeyler bu dosya "
                   "için listelendi."),
    "ENGINE-005": ("Derlenmiş motor dosyası farklı, kaynağı da farklı",
                   "Bu, bir motor dosyasının derlenmiş hali ve resmi sürümün derlenmiş dosyası "
                   "değil. Yanındaki kaynak dosya da değiştirilmiş; bu durumu açıklar: bir motor "
                   "dosyasını uyarlayan geliştiricinin derlenmiş dosyası da yenilenir. Kaynak "
                   "dosya tarandı ve içinde yorum ve boşluklardan fazlasının değiştiği (ya da "
                   "derlenmiş dosyanın satır numaraları dışında hâlâ resmi dosya olduğu) "
                   "denetlendi. Derlenmiş dosyanın çağrıları komutlarından yeniden kuruldu: "
                   "çağırdığı her ad kaynakta geçiyor ve çağrıları olağan kurallar okudu. Dosyanın "
                   "tam olarak o kaynağın derlenmiş hali olduğu denetlenmedi."),
    "ENGINE-008": ("Motorun klasöründeki program resmi dosya değil",
                   "Bu program Ren'Py motorunun klasöründe duruyor ve Ren'Py'nin bu kopyası, resmi "
                   "dosyalarını tarayıcının bildiği bir sürüm olduğunu söylüyor - ama bu program onlardan "
                   "biri değil: değiştirilmiş ya da eklenmiş. Motor ve oyunun başlatma programı oradaki "
                   "programları ve kitaplıkları kendi parçaları gibi yükler. Oyunlar motorun programlarını "
                   "nadiren değiştirir; bu yüzden bu görünür bir not ve klasör ona güven vermez."),
    "ENGINE-009": ("Uygulamanın klasöründeki program resmi dosya değil",
                   "Bu program, çalışma ortamını tarayıcının resmi sürüm olarak doğruladığı bir uygulamanın "
                   "klasöründe duruyor - ama bu program hiçbir resmi dosya tablosunda yok ve güvenilir bir "
                   "yayıncının geçerli imzasını taşımıyor. Tarayıcı bir programın ne yaptığını değil, içe "
                   "aktarma tablosunu ve metinlerini okur; bu yüzden ne olduğu söylenemez; uygulama onu "
                   "başlatabilir ya da yükleyebilir. Bu, yanındaki doğrulanmış çalışma ortamının gizlemediği "
                   "görünür bir nottur."),
    "RPY-CONTENT-001": ("Derlenmiş betik başka bir şey içeriyor (%s)",
                        "Bu dosya derlenmiş bir Ren'Py betiği gibi adlandırılmış, ama Ren'Py başlığı yok ve "
                        "metin de değil: ilk baytlarına göre başka bir şey. Ren'Py onu betik olarak "
                        "yükleyemez; yani bir betik adı altında tutulan başka bir şey - bir programı ya da "
                        "veriyi oyunun dosyaları arasında saklamanın bir yolu. İçeriği okunmadı."),
    "ENGINE-006": ("Başka bir Ren'Py sürümünün derlenmiş motor dosyası",
                   "Bu derlenmiş dosya resmi bir Ren'Py dosyası - ama Ren'Py'nin bu kopyasının "
                   "söylediği sürümün değil, başka bir sürümün dosyası. Bir oyun motorun başka "
                   "bir sürümüne taşındığında geride böyle dosyalar kalır. Dosyada hiçbir şey "
                   "değiştirilmemiş; bu yüzden bu yalnızca bir not."),
    "IAT-001": ("IL2CPP programı süreçlere müdahale işlevlerini içe aktarıyor",
                "Oyunun yerel kodu, amacı başka süreçlerin belleğine yazmak, onlarda iş parçacığı "
                "başlatmak, klavyeyi sistem genelinde izlemek veya belleklerinin dökümünü almak olan "
                "işlevleri içe aktarıyor. Standart bir Unity IL2CPP derlemesi bunu içe aktarmaz."),
    "IAT-002": ("IL2CPP programı belgelenmemiş yerel API'yi içe aktarıyor",
                "Oyunun yerel kodu doğrudan ntdll.dll'yi çağırıyor - belgelenmiş Windows API'sinin "
                "altındaki, gözlemlenmekten kaçınmak için kullanılan katman. Standart bir Unity "
                "IL2CPP derlemesi bunu içe aktarmaz."),
    "IAT-003": ("IL2CPP programı ağ işlevlerini içe aktarıyor",
                "Oyunun yerel kodu bir ağ kitaplığını ya da Unity'nin kendi çalışma zamanının "
                "kullandığı dört işlevin ötesinde soket işlevlerini içe aktarıyor. Standart bir "
                "Unity IL2CPP derlemesi bunu içe aktarmaz."),
    "IAT-004": ("IL2CPP programı şifreleme işlevlerini içe aktarıyor",
                "Oyunun yerel kodu, Unity çalışma zamanının rastgele sayı çağrılarının ötesinde "
                "şifreleme işlevlerini içe aktarıyor: gizli bir yükü açmak veya dosyaları şifrelemek "
                "için gerekenler. Standart bir Unity IL2CPP derlemesi bunu içe aktarmaz."),
    "IAT-005": ("IL2CPP programı sistem denetimi işlevlerini içe aktarıyor",
                "Oyunun yerel kodu program başlatan, hizmetleri, kayıt defterini veya erişim "
                "belirteçlerini değiştiren ya da klavyeyi ve panoyu okuyan işlevleri içe aktarıyor. "
                "Standart bir Unity IL2CPP derlemesi bunu içe aktarmaz."),
    "IAT-006": ("IL2CPP programı Unity temel listesinin dışındaki işlevleri içe aktarıyor",
                "Oyunun yerel kodu, incelenen standart derlemelerin içe aktarmadığı Windows "
                "işlevlerini içe aktarıyor. Çoğunlukla yalnızca başka bir Unity sürümüdür; diğer "
                "bulgularla birlikte bakmaya değer."),
    "IL2CPP-META-001": ("IL2CPP meta verisi okunamadı",
                        "Bir IL2CPP oyununun kodunu adlandıran ve dizgelerini tutan dosya "
                        "şifrelenmiş, karıştırılmış veya bilinmeyen bir düzende; bu nedenle yalnızca "
                        "ham metni incelenebildi."),
    "RGSS-RT-001": ("Tanınmayan RPG Maker çalışma zamanı",
                    "Dosyanın adı RPG Maker'ın çalışma zamanı kütüphanesine benziyor, ancak "
                    "içeriği tarayıcının bildiği resmi sürümlerden biri değil. Henüz listede "
                    "olmayan bir sürüm olabilir - ya da bu adı kullanan başka bir program. Bu "
                    "nedenle bilinmeyen herhangi bir program gibi değerlendirildi."),
    "ARC-002": ("Arşiv tam olarak incelenemedi",
                "Bu arşivin bir bölümü açılamadı; bu nedenle içindekiler incelenmedi. İçeriği "
                "okunamayan bir dosya hiçbir zaman temiz olarak bildirilmez - geçerli bir imza "
                "taşısa bile: imza dosyayı kimin yaptığını söyler, içinde ne olduğunu değil."),
    "UNITY-FMT-001": ("Unity paketi tam olarak açılamadı",
                      "Bu varlık paketinin bir bölümü açılamadı; bu nedenle o bölümde "
                      "saklananlar incelenmedi."),
    "OBF-CAT-001": ("Küçük parçalardan birleştirilen dizge",
                    "Bir sözcük, dosyada hiç görünmemesi için karakter karakter oluşturuluyor - "
                    "komutları ve URL'leri tarayıcılardan gizlemenin bir yolu."),
    "OBF-REV-001": ("Ters çevrilmiş komut dizgesi",
                    "Bir komut veya URL tersten saklanıyor ve tespitten kaçınmak için çalışma "
                    "anında düzeltiliyor."),
    "PE-EP-001": ("Olağandışı program giriş noktası",
                  "Program, derleyicilerin asla kullanmadığı bir yerden çalışmaya başlıyor; bu, "
                  "paketlenmiş veya yamalanmış çalıştırılabilir dosyaların tipik özelliğidir."),
    "NAME-004": ("Oyun varlıkları arasına gizlenmiş program",
                 "Yalnızca görüntü, ses, kayıt veya veri bulunması gereken bir klasörde "
                 "çalıştırılabilir bir dosya veya betik duruyor."),
    "ENT-STR-001": ("Yüksek entropili dizge",
                    "Koddaki uzun bir dizge istatistiksel olarak rastgele veriye çok yakın; "
                    "şifrelenmiş veya özel kodlanmış yükler böyle görünür."),
    "PE-ENT-001": ("Çalıştırılabilir dosyaya eklenmiş yüksek entropili veri",
                   "Programın sonuna eklenen veri şifrelenmiş veya sıkıştırılmış. Kurulum programları "
                   "bunu meşru olarak yapar; bırakıcılar da yüklerini aynı şekilde gizler."),
    "PE-ENT-002": ("Şifrelenmiş veri bölümü",
                   "Büyük bir veri bölümü istatistiksel olarak rastgele; bu, çalışma anında "
                   "şifresi çözülen bir yüke işaret eder."),
    "DN-META-001": ("Derleme meta verisi okunamadı",
                    "Derlemenin başvuru tabloları bozuk veya korumalı; bu nedenle yalnızca ham "
                    "dizgeleri incelenebildi."),
    "UNITY-PE-001": ("Unity varlığına gömülü çalıştırılabilir dosya",
                     "Bir Windows programı, oyun klasöründe görünmediği bir varlık dosyasının "
                     "içinde saklanıyor. Mod yükleyiciler ve bırakıcılar tarafından kullanılır."),
    "VT-001": ("Antivirüs motorları tarafından zararlı olarak işaretlendi",
               "VirusTotal'daki birden fazla bağımsız antivirüs motoru tam olarak bu dosyayı "
               "zararlı yazılım olarak algılıyor."),
    "VT-002": ("Tek bir antivirüs motoru tarafından işaretlendi",
               "VirusTotal'daki bir motor bu dosyayı işaretliyor. Tekil tespitler çoğu zaman "
               "yanlış alarmdır, ancak göz atmaya değer."),
    "VT-004": ("Henüz tespit yok, ancak VirusTotal'da güvenmek için çok yeni",
               "Hiçbir antivirüs motoru bu dosyayı işaretlemiyor, ancak VirusTotal onu yalnızca "
               "kısa bir süredir tanıyor. Yeni zararlı yazılımlar ilk günlerinde çoğu zaman "
               "tespit edilmez; bu nedenle bu sonuç diğer bulguları göz ardı etmek için "
               "kullanılmadı."),
    "VT-003": ("VirusTotal tarafından bilinmiyor",
               "Hiçbir antivirüs üreticisi tam olarak bu programı daha önce görmemiş; yani ona "
               "kefil olan yok. Küçük bağımsız oyunlar için normaldir, yeni zararlı yazılımlar "
               "için de."),
    # attack chains
    "CHAIN-DOWNLOADER": ("İndirici / bırakıcı",
                         "Ağ erişimi, gizli bir yük ve kod yürütme bir arada görülüyor: dosya "
                         "internetten bir şey indirip çalıştırabilir."),
    "SIG-DATA-001": ("İmza bloğunun içine saklanmış veri",
                     "Bu program, imza bloğunun içinde, imzanın kendisinin ötesinde veri taşıyor. "
                     "Windows imzayı denetlerken bu alanı hesaba katmaz; bu yüzden oraya ne konursa "
                     "konsun imza geçerli kalır - ve imzalayan bunların hiçbirine kefil değildir. "
                     "Bazı kurulum programları burada kısa bir indirme etiketi tutar; bundan fazlasının "
                     "orada işi yoktur. Veri, imzanın dosyanın geri kalanına verdiği güven olmadan, "
                     "kendi başına tarandı."),
    "SIG-DATA-002": ("İmza bloğundan sonra veri",
                     "Bu programın imza bloğundan sonra veri geliyor. Windows bu şekilde değiştirilmiş "
                     "bir dosyanın imzasını kabul etmez; bu yüzden dosya burada da imzasız sayılır: "
                     "ona da içindekilere de hiçbir yayımcı güveni uygulanmaz. Veri kendi başına "
                     "tarandı."),
    "CHAIN-REMOTE-CODE": ("Uzaktan kod çalıştırma",
                          "Bu dosyanın çalıştırdığı şey ağdan geliyor: bir adresten veri istiyor ve "
                          "geleni çalıştırıyor - kod olarak, komut olarak ya da diske yazılıp sonra "
                          "başlatılan bir dosya olarak - veya bir betiği doğrudan uzak bir adresten "
                          "yüklüyor. O adresi kim denetliyorsa bu bilgisayarda neyin çalışacağına o "
                          "karar verir."),
    "CHAIN-TEXT-RUN": ("Betikteki bir metin program olarak çalıştırılıyor",
                       "Bu betik içinde bir metin tutuyor ve onu program olarak çalıştırıyor: metni bir "
                       "dosyaya yazıp o dosyayı başlatıyor ya da yüklüyor, veya metni komut satırında bir "
                       "yorumlayıcıya veriyor. İkinci bir betik birincinin içinde böyle gözden uzak "
                       "tutulur; yardımcı ve güncelleme betikleri de aynı biçimde yazılır. Metin ayrı bir "
                       "betik gibi okundu - bulguları bu dosyayla birlikte listeleniyor."),
    "CHAIN-LOCAL-DROP": ("Oyunun bir dosyası çözülüyor, yazılıyor ve başlatılıyor",
                         "Bu betik oyunun bir dosyasını okuyor, kodunu çözüyor, sonucu diske yazıyor (ya da "
                         "orada bir arşiv olarak açıyor) ve sonra yazdığını başlatıyor. Hiçbir şey "
                         "indirilmiyor: çalışan şey oyunun kendi dosyalarında, bir tarayıcının program "
                         "göremeyeceği kodlanmış bir biçimde taşınmış. Kurulum programları ve başlatıcılar "
                         "paketlenmiş bir aracı bazen böyle açar; bir oyun nadiren."),
    # ... the program is started through the folder the decoded file was written to (2026-10-18)
    "CHAIN-LOCAL-DROP#FOLDER": ("Oyunun bir dosyası çözülüyor, yazılıyor ve yanında bir program başlatılıyor",
                                "Bu betik oyunun bir dosyasını okuyor, kodunu çözüyor, sonucu diske yazıyor (ya da "
                                "orada bir arşiv olarak açıyor) ve sonra o klasörde bir program başlatıyor. Program "
                                "yazılan dosyanın kendi adıyla başlatılmıyor: dosyanın yazıldığı klasörde (çalışma "
                                "klasörü olarak) başlatılıyor ya da kendisi o klasörde duruyor. Bir program "
                                "kitaplıklarını ve veri dosyalarını kendi klasöründe ve çalıştığı klasörde bulur; "
                                "yani onu orada başlatmak yazılanı çalıştırır ya da yükler - gerçek bir programın "
                                "yanına konan bir kitaplık bunun bilinen yoludur. Hiçbir şey indirilmiyor: çalışan "
                                "şey oyunun kendi dosyalarında kodlanmış bir biçimde taşınmış."),
    "CHAIN-REMOTE-CODE#FOLDER": ("İndirilen dosyanın klasöründe bir program başlatılıyor",
                                 "Bu dosya bir şey indiriyor, diske yazıyor ve sonra yazdığı klasörde (çalışma "
                                 "klasörü olarak) bir program başlatıyor ya da o klasörde duran bir programı "
                                 "başlatıyor. Bir program kitaplıklarını ve veri dosyalarını kendi klasöründe ve "
                                 "çalıştığı klasörde bulur; yani indirilen şey bu yolla çalıştırılır ya da yüklenir. "
                                 "İndirilen içeriğin kendisi burada denetlenemiyor; bu yüzden düzey YÜKSEK."),
    "CHAIN-LOCAL-DROP-PLUS": ("Oyunun bir dosyası çözülüp başlatılıyor, ve oyun kendini gizliyor ya da yerleştiriyor",
                              "Bu oyunun bir betiği oyunun kendi dosyalarından birinin kodunu çözüyor, yazıyor ve "
                              "başlatıyor (CHAIN-LOCAL-DROP); aynı oyunda, bir şeyin kendini kullanıcıdan ya da "
                              "güvenlik yazılımından gizlediğine veya Windows ile birlikte başlamak üzere kendini "
                              "yerleştirdiğine dair yüksek riskli işaretler de var. Bu işaretlerin her biri tek "
                              "başına ŞÜPHELİ'dir; oyunun dosyalarında taşınan gizli bir programla birlikte, "
                              "oyunlara gizlenmiş zararlı yazılımın çalışma biçimidir. İşaretler zincirden başka "
                              "dosyalarda olabilir: tarayıcı bir dosyanın ötekini kullandığını kanıtlamıyor."),
    "SIDELOAD-001": ("Onu yükleyen bir programın yanında Windows parçası gibi adlandırılmış kitaplık",
                     "Windows bir kitaplığı önce onu isteyen programın klasöründe arar. Bu kitaplık Windows'un "
                     "veya bir Microsoft çalışma zamanı paketinin bir parçası gibi adlandırılmış ve yanındaki "
                     "program onu içe aktarıyor ya da adıyla yüklüyor - yani program gerçeği yerine bu dosyayı "
                     "çalıştırır. Zararlı yazılımlar güvenilir bir programa kendi kodlarını böyle "
                     "çalıştırtır (\"DLL side-loading\"). Gerçek kitaplık Microsoft imzalıdır; bu dosya "
                     "geçerli bir Microsoft imzası taşımıyor ve tarayıcının bildiği resmî bir sürümün "
                     "dosyası da değil. Oyunlar bu tür kitaplıklarla gelir, ama imzalı olarak."),
    "CHAIN-REMOTE-ARG": ("İndirilen veri bir programa veriliyor",
                         "Bu dosya bir adresten veri istiyor ve geleni başlattığı bir programa veriyor - "
                         "argüman olarak, ortam değişkenlerinde ya da çalışma klasörü olarak. Programın "
                         "kendisi indirilmiyor ve metni bir kabuk okumuyor; yani indirilen şey burada kod "
                         "olarak çalıştırılmıyor. Sonucu, başlatılan programın bu veriyle ne yaptığı "
                         "belirler. Hangi programın başlatıldığına ve ona ne verildiğine bakın."),
    "PAGE-REMOTE-SCRIPT": ("Sayfa uzak bir adresten betik yüklüyor",
                           "Bir Electron uygulamasının bu sayfası uzak bir adresten betik yüklüyor. Betiğin "
                           "bilgisayara ne kadar ulaşabileceği, sayfanın gösterildiği pencerenin ayarlarına "
                           "bağlıdır (Node.js kapalı mı, yalıtım açık mı, ön yükleme betiği sayfaya program "
                           "başlatan bir işlev veriyor mu); ayrıntı kanıt satırında. O adresi kim denetliyorsa "
                           "sayfanın ne göstereceğine o karar verir."),
    "RENDERER-CODE-LOAD": ("Kapalı bir uygulama penceresinin içinde kod yükleniyor",
                           "Bir Electron uygulamasının sayfalarındaki bu betik, tarayıcının uygulamanın "
                           "kendi kodu olduğunu gösteremediği bir kodu yüklüyor (import(), eval, new Function "
                           "ya da bir worker ile). Betik yalnızca, pencereleri ona bilgisayara erişim vermeyen "
                           "sayfalarda çalışıyor - Node.js yok, yalıtılmış bir ortam var ve program başlatan, "
                           "metin çalıştıran ya da dosya yazan hiçbir işlev verilmiyor; yani yüklediği şey bir "
                           "web tarayıcısındaki gibi çalışır, program başlatamaz ve dosya okuyamaz. O kodu kim "
                           "veriyorsa sayfanın ne yapacağına o karar verir ve sayfaya yazılanları okuyabilir."),
    "CHAIN-SELF-UPDATE": ("Denetlenen kendi kendini güncelleme",
                          "Bu uygulama kendisinin yeni bir sürümünü indirip başlatıyor. Tarayıcının bulduğu, "
                          "indirmeden başlatmaya giden her yol, dosyanın dijital imzasının gerçek bir "
                          "denetiminden geçiyor (Windows'un kendi denetimi ya da uygulamada yazılı bir açık "
                          "anahtarla yapılan şifreleme denetimi) ve dosya yalnızca denetim başarılı olunca "
                          "başlatılıyor; "
                          "indirme şifreli bağlantıyla (HTTPS) yapılıyor ve sunucu uygulamanın kendisine ait - "
                          "uygulamada ya da kendi ayar dosyasında yazılı ve paketinin adını verdiği sunucu. "
                          "Dikkatli bir güncelleyici böyle yazılır. Yine de uygulama bu taramadan sonra, "
                          "taramanın hiç görmediği bir programı çalıştırabilir; tarayıcı imzanın nerede "
                          "denetlendiğini okur, denetimin doğru olup olmadığını değil, ve indirilen dosya başka "
                          "programların yazabildiği bir klasörde bekler."),
    "ADDON-DECRYPT-001": ("Kayıtlı gizli bilgileri çözebilen yerel eklenti",
                          "Uygulamanın bu yerel eklentisi, tarayıcıların, sohbet programlarının ve parola "
                          "kasalarının oturum açmış kullanıcı için sakladıklarını (kayıtlı parolalar, oturum "
                          "çerezleri, belirteçler) çözen Windows işlevini içe aktarıyor. Uygulamanın bir betiği "
                          "onu çağırabilir. Parola yöneticileri ve oturum açma kitaplıkları bunu uygulamanın "
                          "kendi gizli bilgileri için kullanır; kimlik bilgisi hırsızları ise başka programların "
                          "kayıtları üzerinde kullanır. Yayımlanmış bir paketin kendi dosyası olması, "
                          "yapabildiği şeyi değiştirmez."),
    "CHAIN-REMOTE-LOAD": ("Gösterilmeyen bir adresten kod yükleme",
                          "Bu dosya, içinden okunamayan bir adresten kod yüklüyor - adres ancak betik "
                          "çalışırken geliyor - ve aynı dosyanın kodunda uzak bir adres yazıyor. Adresi "
                          "başka bir yerden vermek, bir indirmeyi gözden uzak tutmanın yoludur; sıradan "
                          "betik yükleyiciler de böyle yazılır. Bu yüzden adresin nereden geldiğine bakın."),
    "CHAIN-STEALER": ("Kimlik bilgisi hırsızı",
                      "Kimlik bilgisi / belirteç depolarını okuyor ve bunları dışarı göndermenin bir "
                      "yoluna sahip."),
    "CHAIN-STEALER#APP": ("Kimlik bilgisi hırsızı",
                          _IND[2]),
    "CHAIN-SPYWARE": ("Casus yazılım / tuş kaydedici",
                      "Tuş vuruşlarını, ekranı veya panoyu yakalıyor ve bunları dışarı göndermenin bir "
                      "yoluna sahip."),
    "CHAIN-BACKDOOR": ("Kalıcı arka kapı",
                       "Kendini bilgisayarla birlikte başlayacak şekilde kuruyor ve komut çalıştırabiliyor "
                       "veya ağla iletişim kurabiliyor."),
    "CHAIN-NO-FLOW": ("Parçalar yan yana, aralarında akış yok",
                      "Bu betikte ağ erişimi ile kod çalıştırma ya da program başlatma birbirine yakın "
                      "duruyor - bir \"indir ve çalıştır\" zincirinin parçaları. Tarayıcının veri akışı "
                      "okuması betiğin tamamını okudu ve indirilen bir şeyin kodun çalıştırıldığı ya da "
                      "programın başlatıldığı yere ulaşmasının hiçbir yolunu bulmadı; bu yüzden o zincir "
                      "olarak bildirilmiyor. Parçalar listeleniyor: betiğin neyi çalıştırıp başlattığına "
                      "bakın."),
    "CHAIN-FETCHRUN": ("İndir ve çalıştır",
                       "Ağ erişimini harici program başlatmayla birleştiriyor."),
    "CHAIN-LOADER": ("Gizlenmiş yükleyici",
                     "Dinamik kod yürütmenin yanında gizli verinin kodunu çözüyor."),
    "CHAIN-PACKED": ("Riskli yeteneğe sahip paketlenmiş ikili dosya",
                     "İkili dosya kodunu bir paketleyiciyle gizliyor ve yine de riskli davranış "
                     "sergiliyor."),
    "CHAIN-EVASIVE": ("Atlatmalı yürütme",
                      "Komut çalıştırırken veya ağı kullanırken kendini gizliyor ya da korumayı devre "
                      "dışı bırakıyor."),
}

_REASON_SUFFIX_TR = (
    # CHAIN-LOCAL-DROP made CRITICAL by its proof in memory (handlers/base.LOCAL_DROP_PROVEN)
    *((" The scanner applied the script's own decoding steps to that file in memory - nothing was written "
       "to disk - and the result is %s. So what this script starts is a program that was hidden in the "
       "game's files." % english,
       " Tarayıcı betiğin kendi kod çözme adımlarını o dosyaya bellekte uyguladı - diske hiçbir şey "
       "yazılmadı - ve sonuç %s. Yani bu betiğin başlattığı şey, oyunun dosyalarında saklanmış bir "
       "program." % turkish)
      for english, turkish in (("a Windows program", "bir Windows programı"),
                               ("a Windows library (DLL)", "bir Windows kitaplığı (DLL)"),
                               ("an archive holding a program", "içinde program olan bir arşiv"))),
    (" This script asks for the module and does not use it: it starts "
     "no program, so the level is lowered.",
     " Bu betik modülü istiyor ama kullanmıyor: hiçbir program başlatmıyor; bu yüzden düzey düşürüldü."),
    (" Every program this script starts is written out in it - a fixed program "
     "with fixed arguments, without a shell - so the level is lowered.",
     " Bu betiğin başlattığı her program betikte açıkça yazılı - sabit bir program, sabit "
     "argümanlar, kabuk yok - bu yüzden düzey düşürüldü."),
    (" Every program this script starts is made only of written-out text and of the app's own "
     "values - its folder, this PC's settings, environment variables -, nothing from the network, "
     "a file from elsewhere or a page of the app, and none is a script runtime - so the level is lowered.",
     " Bu betiğin başlattığı her program yalnızca açıkça yazılmış metinden ve uygulamanın kendi "
     "değerlerinden - klasörü, bu bilgisayarın ayarları, ortam değişkenleri - oluşuyor; ağdan, "
     "başka bir yerden gelen bir dosyadan ya da uygulamanın bir sayfasından hiçbir şey yok ve hiçbiri "
     "bir betik çalıştırıcısı değil - bu yüzden düzey düşürüldü."),
    (" Every part of the address this import() is given is written-out text or one of the "
     "app's own values - its folder, this PC's settings, environment variables -, nothing from "
     "the network, a file from elsewhere or a page of the app - so the level is lowered.",
     " Bu import() çağrısına verilen adresin her parçası açıkça yazılmış metin ya da uygulamanın "
     "kendi değerlerinden biri - klasörü, bu bilgisayarın ayarları, ortam değişkenleri -; ağdan, "
     "başka bir yerden gelen bir dosyadan ya da uygulamanın bir sayfasından hiçbir şey yok - bu "
     "yüzden düzey düşürüldü."),
    (" What this loads is a blob: or data: address made from a text inside the app; the "
     "scanner read the whole script and no download reaches that text - so the level is lowered. "
     "The app runs code it makes itself (a built-in script editor, a module it generates).",
     " Bunun yüklediği, uygulamanın içindeki bir metinden yapılmış bir blob: ya da "
     "data: adresi; tarayıcı betiğin tamamını okudu ve bu metne hiçbir indirme ulaşmıyor - bu yüzden "
     "düzey düşürüldü. Uygulama kendi ürettiği kodu çalıştırıyor (yerleşik bir betik düzenleyicisi, "
     "ürettiği bir modül)."),
    (" What this loads is a blob: or data: address made from a text whose every part was "
     "followed back to written-out text or one of the app's own values - nothing from the "
     "network, a file from elsewhere or a page of the app - so the level is lowered, also "
     "where the rest of the script was not read to its end.",
     " Bunun yüklediği, her parçası açıkça yazılmış metne ya da uygulamanın kendi değerlerinden "
     "birine kadar geriye doğru izlenmiş bir metinden yapılmış bir blob: ya da data: adresi - ağdan, "
     "başka bir yerden gelen bir dosyadan ya da uygulamanın bir sayfasından hiçbir şey yok - bu "
     "yüzden düzey düşürüldü; betiğin geri kalanı sonuna kadar okunmamış olsa da."),
    (" Its one start with a part that is not written out is the app's checked self-update "
     "(CHAIN-SELF-UPDATE); every other program this script starts is fixed or made of the "
     "app's own values, so the level is lowered.",
     " Açıkça yazılmamış bir parçası olan tek başlatması uygulamanın denetlenen kendi kendini "
     "güncellemesi (CHAIN-SELF-UPDATE); bu betiğin başlattığı diğer her program sabit ya da "
     "uygulamanın kendi değerlerinden oluşuyor - bu yüzden düzey düşürüldü."),
    (" In this script the name stands in a text that reaches no place where a "
     "program is started, so the level is lowered.",
     " Bu betikte ad, program başlatılan hiçbir yere ulaşmayan bir metnin içinde duruyor; "
     "bu yüzden düzey düşürüldü."),
    (" It was found in a file of a published npm package: the "
     "single signals are lowered for that, what they add up to is not.",
     " Yayımlanmış bir npm paketinin dosyasında bulundu: tek tek işaretler bu yüzden "
     "düşürülür, hepsinin toplamı düşürülmez."),
    (_IND[3],
     _IND[4]),
    (" Here the script is the compiled C# of a .NET library: its methods were read instruction "
     "by instruction to their end, so the level is MEDIUM.",
     " Burada betik, bir .NET kütüphanesinin derlenmiş C# kodu: yöntemleri komut komut sonuna "
     "kadar okundu; bu yüzden düzey ORTA."),
    (" The app itself gives the window's pages Node.js (nodeIntegration on), so this is real "
     "behaviour of the app, not something hidden in it: the level is HIGH.",
     " Pencerenin sayfalarına Node.js'i uygulamanın kendisi veriyor (nodeIntegration açık); bu "
     "yüzden bu, uygulamada gizlenmiş bir şey değil, uygulamanın gerçek davranışı: düzey YÜKSEK."),
    (" The remote script is loaded by a script element that a script of the app's pages "
     "makes, so it runs in one of the app's windows; by the app's own design such a "
     "script is real behaviour of the app, not something hidden in it: the level is HIGH.",
     " Uzak betiği, uygulamanın sayfalarındaki bir betiğin oluşturduğu bir script öğesi yüklüyor; "
     "yani betik uygulamanın pencerelerinden birinde çalışıyor. Uygulamanın kendi tasarımına göre "
     "böyle bir betik, uygulamada gizlenmiş bir şey değil, uygulamanın gerçek davranışı: düzey YÜKSEK."),
    (" It starts and ends inside this one file of a published npm package: "
     "a mechanism of the library, so the level is lowered to MEDIUM.",
     " Yayımlanmış bir npm paketinin bu tek dosyasında başlıyor ve bitiyor: kütüphanenin "
     "kendi işleyişi; bu yüzden düzey ORTA'ya düşürüldü."),
    (" It starts and ends inside this one file of an official release of a library: "
     "a mechanism of the library, so the level is lowered to MEDIUM.",
     " Bir kütüphanenin resmi sürümündeki bu tek dosyada başlıyor ve bitiyor: kütüphanenin "
     "kendi işleyişi; bu yüzden düzey ORTA'ya düşürüldü."),
    (" It was CRITICAL: the library can run code it is given, but nothing in this file "
     "hands it an address - an app script that does is reported on its own.",
     " KRİTİK idi: kütüphane kendisine verilen kodu çalıştırabilir, ama bu dosyada ona adres veren "
     "hiçbir şey yok - bunu yapan bir uygulama betiği ayrıca bildirilir."),
    (" In a program this rests on its import table alone: it can install an input hook and "
     "it can use the network, which many ordinary windowed programs with an update check "
     "can too. CRITICAL needs two independent signs - a hook, a known exfiltration address, "
     "a key-logging dictionary - so it is reported as HIGH.",
     " Bir programda bu yalnızca içe aktarma tablosuna dayanır: girdi kancası kurabilir ve ağı "
     "kullanabilir; güncelleme denetimi yapan pek çok sıradan pencereli program da bunu yapabilir. "
     "CRITICAL için birbirinden bağımsız iki işaret gerekir - kanca, bilinen bir sızdırma adresi, "
     "tuş kaydı sözlüğü - bu yüzden HIGH olarak bildirildi."),
    (" Only the state of the keyboard is read here - no hook, no clipboard, no screen "
     "capture - so it is reported as HIGH, not CRITICAL.",
     " Burada yalnızca klavyenin durumu okunuyor - kanca, pano veya ekran yakalama yok - bu "
     "yüzden CRITICAL değil HIGH olarak bildirildi."),
    (" In a program this function is ordinary: games read the keyboard for their "
     "controls, and anything with a text box can paste from the clipboard. It is "
     "shown as a LOW note.",
     " Bir programda bu işlev olağandır: oyunlar denetimleri için klavyeyi okur, metin kutusu "
     "olan her şey panodan yapıştırabilir. Bu yüzden LOW bir not olarak gösterilir."),
    (" It was found in a file that is otherwise trusted for sitting in an engine / library "
     "folder.",
     " Normalde motor / kütüphane klasöründe durduğu için güvenilen bir dosyada bulundu."),
    (" It was found inside a verified official build of a browser or runtime engine, "
     "where such combinations of functions are expected, so it is shown as a LOW note.",
     " Bir tarayıcı veya çalışma zamanı motorunun doğrulanmış resmi sürümünün içinde bulundu; "
     "bu tür işlev birleşimleri orada beklenir, bu yüzden DÜŞÜK düzeyde bir not olarak "
     "gösteriliyor."),
    (" The engine file could not be verified: this copy of Ren'Py is a version "
     "whose official files are not in the scanner's table, so the file is trusted "
     "for its folder only and the finding is shown as HIGH instead of CRITICAL.",
     " Motor dosyası doğrulanamadı: Ren'Py'nin bu kopyası, resmi dosyaları tarayıcının "
     "tablosunda bulunmayan bir sürüm; bu yüzden dosyaya yalnızca klasörü nedeniyle güveniliyor "
     "ve bulgu CRITICAL yerine HIGH olarak gösteriliyor."),
    (" Here the two halves are in two files: one file downloads the data and stores it under "
     "a name both files use, and this file runs what that name holds.",
     " Burada iki yarı iki ayrı dosyada: bir dosya veriyi indirip iki dosyanın da kullandığı bir "
     "ad altında saklıyor, bu dosya da o adın tuttuğu şeyi çalıştırıyor."),
    (" Here the two halves are in two files: one file downloads the data and writes it to a "
     "file on disk, and this file starts that file.",
     " Burada iki yarı iki ayrı dosyada: bir dosya veriyi indirip diskteki bir dosyaya yazıyor, "
     "bu dosya da o dosyayı başlatıyor."),
    (" Here the word stands in the name of a file this installer installs - file name, not an "
     "instruction: the installer's own code was read to its end and names nothing that "
     "downloads. It is shown as a LOW note.",
     " Burada sözcük, bu kurulum programının kurduğu bir dosyanın adında geçiyor - dosya adı, komut "
     "değil: kurulum programının kendi kodu sonuna kadar okundu ve içinde indirme yapan hiçbir şey "
     "yok. Bu yüzden DÜŞÜK düzeyde bir not olarak gösteriliyor."),
    (" Here one of the parts is only a word in the name of a file this installer installs - "
     "file name, not an instruction - and without it there is no chain, so it is shown as a "
     "LOW note.",
     " Burada parçalardan biri yalnızca bu kurulum programının kurduğu bir dosyanın adındaki bir "
     "sözcük - dosya adı, komut değil - ve o olmadan zincir de yok; bu yüzden DÜŞÜK düzeyde bir not "
     "olarak gösteriliyor."),
    (" Here the word stands in a standard installer message: a text of Inno Setup itself, "
     "which every installer made with it carries, not an instruction of this installer. "
     "It is shown as a LOW note.",
     " Burada sözcük standart bir kurulum mesajında geçiyor: Inno Setup'ın kendi metni; onunla "
     "yapılan her kurulum programında bulunur, bu kurulum programının bir komutu değildir. Bu "
     "yüzden DÜŞÜK düzeyde bir not olarak gösteriliyor."),
    (" Here the script writes a data file into the game's own folder: the path starts from "
     "the game's folder, the file name ends in a data extension, and it is not a file the "
     "engine reads as code or configuration. It is shown as a LOW note.",
     " Burada betik, oyunun kendi klasörüne bir veri dosyası yazıyor: yol oyunun klasöründen "
     "başlıyor, dosya adı bir veri uzantısıyla bitiyor ve bu, motorun kod ya da ayar olarak "
     "okuduğu bir dosya değil. Bu yüzden DÜŞÜK düzeyde bir not olarak gösteriliyor."),
    (" Here the function belongs to a library that lies in the game's own folder, named in "
     "full in the script. That file was read to the end in this scan, and nothing of "
     "MEDIUM or higher severity was found in it. It is shown as a LOW note; the library's "
     "own findings, if any, are listed under its file.",
     " Burada işlev, oyunun kendi klasöründe duran ve betikte adı tam yazılmış bir kitaplığa ait. "
     "O dosya bu taramada sonuna kadar okundu ve içinde ORTA ya da daha yüksek düzeyde hiçbir şey "
     "bulunmadı. Bu yüzden DÜŞÜK düzeyde bir not olarak gösteriliyor; kitaplığın kendi bulguları "
     "varsa kendi dosyasının altında listelenir."),
    (" Here the function is SetFileAttributes, and every call of it in this script was "
     "read: each one only hides or shows a folder or file of the game itself (shown in "
     "the evidence), never a program. Games hide their save folder this way. It is "
     "shown as a LOW note.",
     " Burada işlev SetFileAttributes ve bu betikteki her çağrısı okundu: her biri yalnızca "
     "oyunun kendi klasörünü ya da dosyasını gizliyor veya gösteriyor (kanıtta yazıyor), hiçbir "
     "zaman bir programı değil. Oyunlar kayıt klasörlerini böyle gizler. Bu yüzden DÜŞÜK düzeyde "
     "bir not olarak gösteriliyor."),
    (" Here the text is only written, as it stands, into a file of the game that has no "
     "program or script extension; this script never decodes or executes text. It is "
     "shown as a LOW note.",
     " Burada metin, olduğu gibi, oyunun program ya da betik uzantısı taşımayan bir dosyasına "
     "yazılıyor; bu betik hiçbir yerde metin çözmüyor ya da çalıştırmıyor. Bu yüzden DÜŞÜK "
     "düzeyde bir not olarak gösteriliyor."),
    (" It is MEDIUM rather than LOW because what is opened is harder to judge: an "
     "address without encryption, a bare network address, a link shortener, or a "
     "folder.",
     " LOW yerine MEDIUM, çünkü açılan şeyi değerlendirmek daha zor: şifrelemesiz bir adres, "
     "yalın bir ağ adresi, bir bağlantı kısaltıcı ya da bir klasör."),
    (" The address hides its real destination behind a user-name part.",
     " Adres, gerçek hedefini bir kullanıcı adı bölümünün arkasına gizliyor."),
    (" The target resolves to a user-profile or system location outside the game.",
     " Hedef, oyunun dışındaki bir kullanıcı profili veya sistem konumuna çözümleniyor."),
    (" (Not in the import table, but the table cannot be trusted for this binary.)",
     " (İçe aktarma tablosunda yok, ancak bu ikili dosya için tabloya güvenilemez.)"),
    (" (Not in the import table: an IL2CPP program finds the functions its C# code calls by "
     "name, at run time.)",
     " (İçe aktarma tablosunda yok: bir IL2CPP programı, C# kodunun çağırdığı işlevleri çalışma "
     "anında adlarıyla bulur.)"),
)
_REASON_PATTERN_TR = (
    (re.compile(r' The file has a valid signature from "(.*?)", which is not on the '
                r'trusted-publisher list, so the severity was lowered one level\.'),
     ' Dosya, güvenilir yayımcı listesinde olmayan "%s" tarafından geçerli şekilde '
     'imzalanmış; bu nedenle önem düzeyi bir kademe düşürüldü.'),
    (re.compile(r' The file has a valid signature from "(.*?)"\.'),
     ' Dosya "%s" tarafından geçerli şekilde imzalanmış.'),
)
_MZ_TITLE = "Embedded Windows executable (encoded blob)"

_ASSET_TR = {
    "PNG image": "PNG görüntüsü", "JPEG image": "JPEG görüntüsü", "GIF image": "GIF görüntüsü",
    "Ogg audio": "Ogg ses", "RIFF audio/image": "RIFF ses/görüntü", "MP3 audio": "MP3 ses",
    "web font": "web yazı tipi", "OpenType font": "OpenType yazı tipi",
    "TrueType font": "TrueType yazı tipi", "bitmap image": "bit eşlem görüntüsü",
    "SVG image": "SVG görüntüsü", "XML document": "XML belgesi", "JSON document": "JSON belgesi",
}
_BASELINE_TR = {
    "Windows system file": "Windows sistem dosyası",
    "RPG Maker default script": "RPG Maker varsayılan betiği",
    "Ren'Py launcher script": "Ren'Py başlatıcı betiği",
    "NW.js launcher": "NW.js başlatıcısı",
    "valid digital signature from a publisher Windows trusts":
        "Windows'un güvendiği bir yayımcıdan geçerli dijital imza",
    "Ren'Py engine runtime": "Ren'Py motor çalışma zamanı",
    "bundled Python standard library": "birlikte gelen Python standart kütüphanesi",
    "RPG Maker core script": "RPG Maker çekirdek betiği",
    "RPG Maker bundled library": "RPG Maker ile gelen kütüphane",
    "VisuStella MZ plugin (commercially obfuscated)": "VisuStella MZ eklentisi (ticari olarak gizlenmiş)",
    "Unity engine / .NET framework assembly": "Unity motoru / .NET çerçeve derlemesi",
    "Unity player runtime": "Unity oynatıcı çalışma zamanı",
    "Unity Mono runtime": "Unity Mono çalışma zamanı",
    "RPG Maker RGSS runtime (official build, verified by SHA-256)":
        "RPG Maker RGSS çalışma zamanı (resmi sürüm, SHA-256 ile doğrulandı)",
    "NW.js / Chromium runtime": "NW.js / Chromium çalışma zamanı",
    "Ren'Py bundled Python runtime": "Ren'Py ile gelen Python çalışma zamanı",
    "Python / MSVC runtime": "Python / MSVC çalışma zamanı",
    "common game middleware library": "yaygın oyun ara katman kütüphanesi",
}
SUPPRESSION_TR = {
    "File SHA-256 is on the allowlist": "Dosyanın SHA-256 özeti güvenilir listesinde",
    "Match is inside a comment / docstring, not executable code":
        "Eşleşme çalıştırılabilir kodda değil, bir yorumun / belge dizgesinin içinde",
    "Match is inside a quoted text of the script, not a call":
        "Eşleşme bir çağrı değil; betikteki tırnak içindeki bir metnin içinde",
    "API name appears only as a string; it is not in the PE import table":
        "API adı yalnızca bir dizge olarak geçiyor; PE içe aktarma tablosunda yok",
    _IND[5]:
        _IND[6],
    "Text, not code: the whole line is one string literal":
        "Metin, kod değil: satırın tamamı tek bir dizgeden oluşuyor",
    "Natural-language text: a sentence in Japanese, Chinese or Korean writing, not encoded data":
        "Doğal dil metni: Japonca, Çince ya da Korece yazıyla bir cümle, kodlanmış veri değil",
    "Only reads the list of running programs (reported as PROC-LIST-001)":
        "Yalnızca çalışan programların listesini okuyor (PROC-LIST-001 olarak bildirildi)",
    "The script's own lock file in the temporary folder (one copy of the game at a time)":
        "Betiğin geçici klasördeki kendi kilit dosyası (oyunun aynı anda tek kopyası çalışsın diye)",
    "Loopback address (localhost)": "Geri döngü adresi (localhost)",
    "Not an address: there is no domain name in it": "Adres değil: içinde alan adı yok",
    "IL2CPP runtime: thread signalling (no other injection function is imported)":
        "IL2CPP çalışma zamanı: iş parçacığı sinyalleşmesi (başka enjeksiyon işlevi içe aktarılmıyor)",
    "Loopback / private-network address": "Geri döngü / özel ağ adresi",
    "Target resolves to the game's own save / cache / temp data":
        "Hedef, oyunun kendi kayıt / önbellek / geçici verilerine çözümleniyor",
    "Decoding is used for save / settings data (legitimate save encoding)":
        "Kod çözme, kayıt / ayar verileri için kullanılıyor (meşru kayıt kodlaması)",
    "Only opens a folder / document with the system file manager":
        "Yalnızca sistem dosya yöneticisiyle bir klasör / belge açıyor",
    "Request loads a local game data file, not a remote resource":
        "İstek uzak bir kaynak değil, yerel bir oyun veri dosyası yüklüyor",
    "Only opens a web address with the default browser":
        "Yalnızca varsayılan tarayıcıyla bir web adresi açıyor",
    "Common RPG Maker helper API (window, input or settings)":
        "Yaygın RPG Maker yardımcı API'si (pencere, girdi veya ayarlar)",
    "Keyboard state is read for in-game input (RPG Maker script)":
        "Klavye durumu oyun içi girdi için okunuyor (RPG Maker betiği)",
    "Resolved as a false positive earlier (memory center)":
        "Daha önce yanlış alarm olarak çözüldü (hafıza merkezi)",
}
_SUPPRESSION_PATTERNS = (
    (re.compile(r"^Domain is on the benign allowlist \((.+)\)$"),
     lambda m: "Alan adı zararsız listesinde (%s)" % m.group(1)),
    (re.compile(r"^Blob decodes to an embedded asset \((.+)\)$"),
     lambda m: "Blok çözüldüğünde gömülü bir varlığa dönüşüyor (%s)"
     % _ASSET_TR.get(m.group(1), m.group(1))),
    (re.compile(r"^Learned: this rule was a false positive (\d+) times for this engine$"),
     lambda m: "Öğrenildi: bu kural bu motor için %s kez yanlış alarm verdi" % m.group(1)),
    (re.compile(r"^VirusTotal: 0 of (\d+) engines flag this file \(known for (\d+) days\)$"),
     lambda m: "VirusTotal: %s motorun hiçbiri bu dosyayı işaretlemiyor (%s gündür biliniyor)"
     % (m.group(1), m.group(2))),
    (re.compile(r"^Engine / library baseline: valid digital signature from trusted publisher: (.*)$"),
     lambda m: "Motor / kütüphane temel dosyası: güvenilir yayımcıdan geçerli dijital imza: %s"
     % m.group(1)),
    (re.compile(r"^Engine / library baseline: official engine build, verified by SHA-256: (.*)$"),
     lambda m: "Motor / kütüphane temel dosyası: resmi motor sürümü, SHA-256 ile doğrulandı: %s"
     % m.group(1)),
    (re.compile(r"^Engine / library baseline: official library release, verified by SHA-256: (.*)$"),
     lambda m: "Motor / kütüphane temel dosyası: resmi kütüphane sürümü, SHA-256 ile doğrulandı: %s"
     % m.group(1)),
    (re.compile(r"^Engine / library baseline: official NW\.js launcher with other resources, code "
                r"verified by SHA-256: (.*)$"),
     lambda m: "Motor / kütüphane temel dosyası: kaynakları (simgesi) farklı resmi NW.js başlatıcısı, "
               "kodu SHA-256 ile doğrulandı: %s" % m.group(1)),
    (re.compile(r"^Engine / library baseline: official Electron program with other resources, code "
                r"verified by SHA-256: (.*)$"),
     lambda m: "Motor / kütüphane temel dosyası: kaynakları (simgesi, sürüm bilgisi) farklı resmi Electron "
               "programı, kodu SHA-256 ile doğrulandı: %s" % m.group(1)),
    (re.compile(r"^Engine / library baseline: (.+)$"),
     lambda m: "Motor / kütüphane temel dosyası: %s" % _BASELINE_TR.get(m.group(1), m.group(1))),
    (re.compile(r"^Official Ren'Py engine script, verified against the SDK: (.*)$"),
     lambda m: "Resmi Ren'Py motor betiği, SDK ile karşılaştırılarak doğrulandı: %s" % m.group(1)),
)
_EVIDENCE_SUBS = (
    (re.compile(r"\(\+(\d+) more match\(es\) in this file\)"), r"(bu dosyada +\1 eşleşme daha)"),
    (re.compile(r"\[confirmed in import table\]"), "[içe aktarma tablosunda doğrulandı]"),
    (re.compile(r"^(\d+) occurrences, e\.g\. "), r"\1 kez geçiyor, örn. "),
    (re.compile(r", line (\d+)\)"), r", satır \1)"),          # attack-chain members
    (re.compile(r"^sections: "), "bölümler: "),
    (re.compile(r"^imports: none$"), "içe aktarmalar: yok"),
    (re.compile(r"^imports: "), "içe aktarmalar: "),
    (re.compile(r"^section "), "bölüm "),
    (re.compile(r"^(.*) entropy ([\d.]+) / 8\.00$"), r"\1 entropisi \2 / 8,00"),
    (re.compile(r"^MZ header in (.+)$"), r"\1 içinde MZ başlığı"),
    (re.compile(r"^hash not found$"), "özet bulunamadı"),
    (re.compile(r"first seen on VirusTotal (\d+) day\(s\) ago"),
     r"VirusTotal'da ilk kez \1 gün önce görüldü"),
    (re.compile(r"first-seen date unknown"), "ilk görülme tarihi bilinmiyor"),
    (re.compile(r"\(needs (\d+)\)"), r"(gereken: \1)"),
    (re.compile(r"^(\d+) characters, entropy ([\d.]+) bits/char$"),
     r"\1 karakter, entropi \2 bit/karakter"),
    (re.compile(r"(\d+)% of blocks high-entropy, chi-square"),
     r"blokların %\1'i yüksek entropili, ki-kare"),
    (re.compile(r"\(encrypted\)$"), "(şifreli)"),
    (re.compile(r"\(compressed\)$"), "(sıkıştırılmış)"),
    (re.compile(r"^condition matched$"), "koşul eşleşti"),
    (re.compile(r"^(.{1,80}?) receives: "), r"\1 şunu alıyor: "),
    (re.compile(r"<- line (\d+)"), r"<- satır \1"),
    (re.compile(r"\[decoded\]"), "[kodu çözüldü]"),
    (re.compile(r"\[inside decoded code\]"), "[kodu çözülmüş kodun içinde]"),
    (re.compile(r"\[parts in ‹› are only known at runtime\]"),
     "[‹› içindeki kısımlar yalnızca çalışma anında bilinir]"),
    (re.compile(r"\[in code decoded at line (\d+)\]"), r"[\1. satırda çözülen kodun içinde]"),
    (re.compile(r"; a file of npm package "), "; şu npm paketinin dosyası: "),
    (re.compile(r"; scripts of the same package with a network call: (\d+)"), r"; aynı pakette ağ çağrısı yapan betik sayısı: \1"),
    (re.compile(_IND[7]), r"\1 şunu içe aktarıyor: \2"),
    # a page of an Electron app: the window it is shown in (Scanner._join_windows)
    (re.compile(r"; the window it is shown in: "), "; gösterildiği pencere: "),
    (re.compile(r"; the window it runs in: "), "; çalıştığı pencere: "),
    (re.compile(r"not identified \(a script element made by a script\)"),
     "belirlenemedi (bir betiğin oluşturduğu script öğesi)"),
    # a page's script that loads code, shut in by its windows (Scanner._join_renderer)
    (re.compile(r"; runs only in page\(s\) (.{1,400}?); the window\(s\) they are shown in: "),
     r"; yalnızca şu sayfa(lar)da çalışıyor: \1; gösterildikleri pencere(ler): "),
    (re.compile(r"nodeIntegration is on"), "nodeIntegration açık"),
    (re.compile(r"\[real behaviour of the app\]"), "[uygulamanın gerçek davranışı]"),
    (re.compile(r"contextIsolation is off"), "contextIsolation kapalı"),
    (re.compile(r"its settings are not written out and the Electron version is not known"),
     "ayarları yazılı değil ve Electron sürümü bilinmiyor"),
    (re.compile(r"its settings are not written out"), "ayarları yazılı değil"),
    (re.compile(r"no Node\.js in the page, isolated, no preload script"), "sayfada Node.js yok, yalıtılmış, ön yükleme betiği yok"),
    (re.compile(r"it has a preload script whose file is not named"), "dosyası belirtilmeyen bir ön yükleme betiği var"),
    (re.compile(r"its preload script (\S+) was not found"), r"ön yükleme betiği \1 bulunamadı"),
    (re.compile(r"its preload script (\S+) hands the page nothing that reaches a sink"),
     r"ön yükleme betiği \1 sayfaya program başlatan, metin çalıştıran ya da dosya yazan hiçbir şey vermiyor"),
    (re.compile(r"its preload script (\S+) hands the page functions and starts programs, runs text or writes files"),
     r"ön yükleme betiği \1 sayfaya işlev veriyor ve program başlatıyor, metin çalıştırıyor ya da dosya yazıyor"),
    (re.compile(r"its preload script (\S+) hands the page a message channel of its choice"),
     r"ön yükleme betiği \1 sayfaya dilediği ileti kanalını veriyor"),
    (re.compile(r"its preload script (\S+) hands the page a message whose handler starts programs, runs text or writes files"),
     r"ön yükleme betiği \1 sayfaya, işleyicisi program başlatan, metin çalıştıran ya da dosya yazan bir ileti veriyor"),
    # ... and what the main process does with a message channel the page may choose (electron_ipc)
    (re.compile(r"; no message handler of the main process passes a message on to a program start, a code load, "
                r"the shell's open or a written file that is started \((\d+) handlers read\)"),
     r"; ana sürecin hiçbir ileti işleyicisi bir iletiyi program başlatmaya, kod yüklemeye, kabuğun açmasına ya da "
     r"yazılıp başlatılan bir dosyaya iletmiyor (\1 işleyici okundu)"),
    (re.compile(r"the handler of (.{1,200}?) \(([^,()]{1,200}), (?:line|satır) (\d+)\): "), r"\1 işleyicisi (\2, satır \3): "),
    (re.compile(r"the main process could not be read in full: "), "ana süreç tamamen okunamadı: "),
    (re.compile(r"starts a program \(([^,()]{1,200}), (?:line|satır) (\d+)\)"), r"program başlatıyor (\1, satır \2)"),
    (re.compile(r"loads code \(([^,()]{1,200}), (?:line|satır) (\d+)\)"), r"kod yüklüyor (\1, satır \2)"),
    (re.compile(r"opens a file with the shell \(([^,()]{1,200}), (?:line|satır) (\d+)\)"), r"kabukla bir dosya açıyor (\1, satır \2)"),
    (re.compile(r"writes a file that is then started \(([^,()]{1,200}), (?:line|satır) (\d+)\)"),
     r"sonra başlatılan bir dosya yazıyor (\1, satır \2)"),
    (re.compile(r"writes a file that nothing starts \(([^,()]{1,200}), (?:line|satır) (\d+)\)"),
     r"hiçbir şeyin başlatmadığı bir dosya yazıyor (\1, satır \2)"),
    (re.compile(r"the message's data is handed to (\S{1,120}) \(([^,()]{1,200}), (?:line|satır) (\d+)\), which the reading does not find"),
     r"iletinin verisi \1 işlevine veriliyor (\2, satır \3); okuma o işlevi bulamıyor"),
    (re.compile(r"its handler function is not found"), "işleyici işlevi bulunamadı"),
    (re.compile(r"the reading stopped at its limit \((.{1,80}?)\)"), r"okuma sınırında durdu (\1)"),
    (re.compile(r"a script with message handlers is larger than (\d+) MB"), r"ileti işleyicileri olan bir betik \1 MB'tan büyük"),
    (re.compile(r"the app's scripts are more than (\d+) MB"), r"uygulamanın betikleri \1 MB'tan fazla"),
    (re.compile(r"the app's main script is not known"), "uygulamanın ana betiği bilinmiyor"),
    (re.compile(r"a module of the main process \((.{1,200}?)\) was not read"), r"ana sürecin bir modülü (\1) okunmadı"),
    (re.compile(r"a part of the app could not be read \((\S{1,40})\)"), r"uygulamanın bir kısmı okunamadı (\1)"),
    (re.compile(r"more than (\d+) message handlers"), r"\1 taneden fazla ileti işleyicisi"),
    (re.compile(r"no window of the app was found"), "uygulamanın hiçbir penceresi bulunamadı"),
    (re.compile(r"\[in text this script writes to a file and starts, line (\d+)\]"),
     r"[bu betiğin bir dosyaya yazıp başlattığı metnin içinde, satır \1]"),
    (re.compile(r"\[in text this script hands to an interpreter as its program, line (\d+)\]"),
     r"[bu betiğin bir yorumlayıcıya program olarak verdiği metnin içinde, satır \1]"),
    (re.compile(r"^text handed to (.{1,80}?) as its program "), r"\1 komutuna program olarak verilen metin "),
    (re.compile(r"^text written to a file whose name is not resolved "), "adı çözülemeyen bir dosyaya yazılan metin "),
    (re.compile(r"^text written to (.{1,220}?) \(line (\d+)\) -> "), r"\1 dosyasına yazılan metin (satır \2) -> "),
    (re.compile(r"\[in a call rebuilt from the compiled file\]"),
     "[derlenmiş dosyadan yeniden kurulan bir çağrının içinde]"),
    (re.compile(r"^this compiled engine file calls (.*), which the source file beside it never names"
                r"(?: \(and (\d+) more\))?$"),
     lambda m: "bu derlenmiş motor dosyası %s adını çağırıyor; yanındaki kaynak dosyada bu ad hiç "
               "geçmiyor%s" % (m.group(1), " (ve %s tane daha)" % m.group(2) if m.group(2) else "")),
    (re.compile(r"\[in a command line this script starts\]"),
     "[bu betiğin başlattığı bir komut satırının içinde]"),
    (re.compile(r"\[across two files\]"), "[iki dosya arasında]"),
    (re.compile(r"\[in the installer's instructions\]"), "[kurulum programının komutlarının içinde]"),
    (re.compile(r" \(instruction (\d+)\)"), r" (komut \1)"),
    (re.compile(r" \(row (\d+)\)"), r" (satır \1)"),
    (re.compile(r"\[file name, not an instruction\]"), "[dosya adı, komut değil]"),
    (re.compile(r"\[standard installer message\]"), "[standart kurulum mesajı]"),
    (re.compile(r"^Inno Setup \[Code\] / \[Run\]: the reading stopped at its limit$"),
     "Inno Setup [Code] / [Run]: okuma sınırında durdu"),
    (re.compile(r"^Inno Setup \[Code\] / \[Run\]: the \[Run\] rows were not found$"),
     "Inno Setup [Code] / [Run]: [Run] satırları bulunamadı"),
    (re.compile(r"^Inno Setup \[Code\] / \[Run\]: (.*)$"), r"Inno Setup [Code] / [Run]: okunamadı (\1)"),
    (re.compile(r" -> shared name "), " -> ortak ad "),
    (re.compile(r" -> path in shared name "), " -> yolu tutan ortak ad "),
    (re.compile(r" -> file (.+?) -> "), r" -> dosya \1 -> "),
    (re.compile(r" -> module (.+?) -> import "), r" -> modül \1 -> import "),
    (re.compile(r"^the reading for chains across files stopped at its limit of (\d+) steps(?= \[|$)"),
     r"dosyalar arası zincirler için yapılan okuma \1 adımlık sınırında durdu"),
    (re.compile(r"^the reading for chains across files stopped at its limit of (-?\d+) seconds(?= \[|$)"),
     r"dosyalar arası zincirler için yapılan okuma \1 saniyelik sınırında durdu"),
    (re.compile(r"\[in the resources, which the comparison with the official launcher does not cover\]"),
     "[kaynakların içinde; resmi başlatıcıyla karşılaştırma burayı kapsamaz]"),
    (re.compile(r"\[in the appended data, which the comparison with the official launcher does not cover\]"),
     "[dosyanın sonuna eklenen veride; resmi başlatıcıyla karşılaştırma burayı kapsamaz]"),
    (re.compile(r"\[writes the data file (.*?) in the game's own folder\]"),
     r"[oyunun kendi klasörüne \1 veri dosyasını yazıyor]"),
    (re.compile(r"^decoded payload from "), "kodu çözülmüş içerik, kaynak: "),
    (re.compile(r"^MZ without valid PE header$"), "Geçerli PE başlığı olmayan MZ"),
    # SIG-DATA-001 / 002: "1024 bytes at offset 4096: a zip archive"
    (re.compile(r"^(\d+) bytes at offset (\d+): "), r"\2. konumda \1 bayt: "),
    (re.compile(r"readable text, short enough to be a download tag"),
     "okunabilir metin, bir indirme etiketi olacak kadar kısa"),
    (re.compile(r"readable text, too long for a download tag"),
     "okunabilir metin, bir indirme etiketi için fazla uzun"),
    (re.compile(r"data that could not be recognised \(entropy ([\d.]+) of 8 bits per byte\)"),
     r"tanınamayan veri (entropi: bayt başına 8 bitten \1)"),
    (re.compile(r"; only the first (\d+) MB were inspected"), r"; yalnızca ilk \1 MB incelendi"),
    # a text larger in memory than one text may be (models.MAX_DECODED; 2026-10-17)
    (re.compile(r"^only the first (\d+) of the (\d+) characters of this text were read: it takes (\d) byte\(s\) "
                r"a character in memory, more than the (\d+) MB one text may take \[cause: memory\]$"),
     r"bu metnin \2 karakterinden yalnızca ilk \1 tanesi okundu: bellekte karakter başına \3 bayt tutuyor, "
     r"bir metnin tutabileceği \4 MB'tan fazla [neden: bellek]"),
    (re.compile(r": a program library$"), ": bir program kütüphanesi"),
    (re.compile(r": a program$"), ": bir program"),
    (re.compile(r": an? (zip|cabinet|7z|RAR|RPG Maker) archive"), r": bir \1 arşivi"),
    (re.compile(r": a (PowerShell script|VBScript|batch script|JavaScript file)"), r": bir betik (\1)"),
    (re.compile(r"^(\d+) different key names, e\.g\. "), r"\1 farklı tuş adı, örn. "),
    (re.compile(r"^this engine file differs from the official version (.*)$"),
     r"bu motor dosyası resmi \1 sürümünden farklı"),
    (re.compile(r"^this compiled engine file differs from the official version (.*); "
                r"so does the source file beside it$"),
     r"bu derlenmiş motor dosyası resmi \1 sürümünden farklı; yanındaki kaynak dosya da farklı"),
    (re.compile(r"^this compiled engine file differs from the official version (.*); "
                r"so does the source file beside it \(the source could not be read token by token, "
                r"so it was not checked whether more than comments were changed\)$"),
     r"bu derlenmiş motor dosyası resmi \1 sürümünden farklı; yanındaki kaynak dosya da farklı "
     r"(kaynak parça parça okunamadı; bu yüzden yorumlardan fazlasının değişip değişmediği "
     r"denetlenmedi)"),
    (re.compile(r"^this compiled engine file differs from the official version (.*); "
                r"the source file beside it differs from the official one in comments and spacing only$"),
     r"bu derlenmiş motor dosyası resmi \1 sürümünden farklı; yanındaki kaynak dosya ise resmi "
     r"dosyadan yalnızca yorum ve boşluklarda farklı"),
    (re.compile(r"^leftover from Ren'Py (.*) \(this copy says it is (.*)\)$"),
     r"Ren'Py \1 sürümünden kalma (bu kopya \2 olduğunu söylüyor)"),
    (re.compile(r"^this compiled engine file differs from the official version (.*); "
                r"the source file beside it is the official one$"),
     r"bu derlenmiş motor dosyası resmi \1 sürümünden farklı; yanındaki kaynak dosya ise resmi dosya"),
    (re.compile(r"^this compiled engine file differs from the official version (.*); "
                r"there is no source file beside it$"),
     r"bu derlenmiş motor dosyası resmi \1 sürümünden farklı; yanında kaynak dosya yok"),
    # CHAIN-REMOTE-CODE in compiled C#: "... in Game.Updater::Run  [compiled C#]"
    (re.compile(r"  \[compiled C#\]"), "  [derlenmiş C#]"),
    (re.compile(r"; written to a file that is then started or loaded"), "; bir dosyaya yazılıyor, sonra o dosya başlatılıyor ya da yükleniyor"),
    (re.compile(r"^\.NET method bodies: "), ".NET yöntem gövdeleri: "),
    (re.compile(r"^the download-and-run reading stopped at its limit: "), "indir-ve-çalıştır okuması sınırında durdu: "),
    (re.compile(r"more than (\d+) calls to look at in one module function"), r"tek bir modül işlevinde \1 taneden fazla çağrı"),
    (re.compile(r"more than (\d+) calls to look at"), r"bakılacak \1 taneden fazla çağrı"),
    # ... and the cause of a limit (values.cause): "... [cause: size]; also: ... [cause: step limit]"
    (re.compile(r" \[cause: size\]"), " [neden: boyut]"),
    (re.compile(r" \[cause: step limit\]"), " [neden: adım sınırı]"),
    (re.compile(r" \[cause: safety cap\]"), " [neden: güvenlik tavanı]"),
    (re.compile(r"(?<=\]); also: "), "; ayrıca: "),
    (re.compile(r"^Script Encoder block: "), "Script Encoder bloğu: "),
    # CHAIN-REMOTE-CODE: "fetch (line 3) -> eval (line 5); address: ..."
    (re.compile(r" \(line (\d+)\)"), r" (satır \1)"),
    (re.compile(r"; address: not resolved"), "; adres: çözülemedi"),
    (re.compile(r"; address: "), "; adres: "),
    (re.compile(r"; written to disk as: "), "; diske şu adla yazılıyor: "),
    (re.compile(r"; opens: "), "; açılan: "),
    (re.compile(r"\[hides or shows only: "), "[yalnızca şunu gizliyor ya da gösteriyor: "),
    (re.compile(r"\[deletes only: "), "[yalnızca şunu siliyor: "),
    (re.compile(r"\[calls the game's own library (.*?), read in full\]"),
     r"[oyunun kendi kitaplığı \1 çağrılıyor; dosya sonuna kadar okundu]"),
    (re.compile(r"; remote address in this file: "), "; bu dosyadaki uzak adres: "),
    (re.compile(r"^(.{1,40}?) loads not resolved"), r"\1 şunu yüklüyor: çözülemedi"),
    (re.compile(r"^(.{1,40}?) loads "), r"\1 şunu yüklüyor: "),
)


def _key(f: Finding) -> str:
    if f.rule_id == "OBF-BLOB-001" and f.title == _MZ_TITLE:
        return "OBF-BLOB-001#MZ"
    if f.rule_id == "CHAIN-STEALER" and f.context.get("across_app"):
        return "CHAIN-STEALER#APP"            # the chain across the members of an app (stealer.py)
    if f.rule_id in ("CHAIN-LOCAL-DROP", "CHAIN-REMOTE-CODE") and f.context.get("in_folder"):
        return f.rule_id + "#FOLDER"          # started through the written file's folder (2026-10-18)
    return f.rule_id


def title(f: Finding) -> str:
    entry = RULES_TR.get(_key(f)) if _lang == "tr" else None
    if entry is None:
        return f.title
    if f.rule_id.startswith("CHAIN-"):
        return "Saldırı zinciri: " + entry[0]
    if "%s" in entry[0]:
        m = re.search(r"\((.+)\)$", f.title)
        return entry[0] % (m.group(1) if m else "?")
    return entry[0]


def reason(f: Finding) -> str:
    if _lang == "tr" and f.rule_id.startswith("YARA:"):
        return "'%s' adlı YARA imzasıyla eşleşti." % f.rule_id[5:]
    entry = RULES_TR.get(_key(f)) if _lang == "tr" else None
    if entry is None:
        return f.reason
    out = entry[1]
    for english, turkish in _REASON_SUFFIX_TR:
        if english in f.reason:
            out += turkish
    for pattern, turkish in _REASON_PATTERN_TR:
        m = pattern.search(f.reason)
        if m:
            out += turkish % m.groups()
    return out


def suppression(f: Finding) -> str:
    text = f.suppression_reason
    if _lang != "tr":
        return text
    if text in SUPPRESSION_TR:
        return SUPPRESSION_TR[text]
    for rx, build in _SUPPRESSION_PATTERNS:
        m = rx.match(text)
        if m:
            return build(m)
    return text


def evidence(f: Finding) -> str:
    text = f.evidence
    if _lang == "tr":
        for rx, repl in _EVIDENCE_SUBS:
            text = rx.sub(repl, text)
    return text
