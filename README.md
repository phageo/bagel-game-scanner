# Bagel (Game Safety Scanner)

<!-- user-section-start -->
## For users (English)

Bagel 0.9-beta reads a game folder or file (Ren'Py, RPG Maker, Unity, Windows programs,
scripts, archives, installers) and tells you how dangerous it looks. It is **static**: it only
reads files and **never runs the game or anything in it**. It is a second opinion next to
Windows Security, not a replacement for it. It is a **beta**: see the limits below.

### Download and install

Two ways; both are the same program.

- **Installer (`Bagel-0.9.0-beta-setup.exe`):** double-click it. Choose **only for me** (no
  administrator rights; `%LOCALAPPDATA%\Programs\Bagel`) or **for all users** (administrator;
  `C:\Program Files\Bagel`); the next page lets you pick another folder. It adds **Bagel** to
  the Start menu and to the right-click menu. Uninstall in Windows Settings -> Apps: it removes
  its program files and both entries, and asks whether to delete your settings, scan memory and
  quarantine too (default: keep). Other files in a folder you chose stay.
- **Portable zip (`Bagel-0.9.0-beta.zip`):** unzip it anywhere (for example `Documents`) and
  double-click `Bagel.exe`. Nothing is installed and no Python is needed: it uses the Python in
  the package's own `python` folder only.

**SmartScreen:** the installer and the program are not signed, so Windows may say "Windows
protected your PC". Click **More info** -> **Run anyway** only if you got the file from where
phageo published it, and compare its SHA-256 with the one in the release notes.

**Microsoft Defender may flag the unsigned installer** (a machine-learning guess, reported to
Microsoft as a false alarm); the zip is not flagged.

**Windows Defender:** at start Bagel compares its own files with a list written when the package
was built and says clearly if one was changed, is missing or was added (for example a file an
antivirus removed). You can still scan, but download Bagel again. This finds damage, not
deliberate changes. During a scan, code Bagel unpacks is also shown to Windows Defender (AMSI);
if Defender is missing or switched off, the report says so and the scan goes on.

### How to use

- **Scan:** click **Folder…** (or **File…**), choose the game, click **Scan**.
- **Safe launch:** the **Safe launch…** button after a scan (for a folder it asks which program),
  or **Bagel -> Safe launch** on a program's right-click menu. It scans the game's folder again
  the strict way (your settings cannot hide a finding), then: CLEAN / LIKELY SAFE - starts the
  game; REVIEW or "could not be read" - asks once; SUSPICIOUS - starts it only if you type
  `launch`; DANGEROUS - refuses. Every question defaults to "no". It checks only at the start and
  does not watch the game while it runs. (Command line: `python -m gamescan --launch Game.exe`.)
- **Right-click menu:** one **Bagel** entry: **Scan** on folders and files, **Scan** and **Safe
  launch** on programs (`.exe`). On a game's program, Scan checks the game's whole folder; an
  installer or archive on its own is scanned as itself; the window says which. On Windows 11 it
  is under "Show more options". The installer adds and removes it. With the zip, click **Add to
  the right-click menu** at the top of the window (or Settings -> **Explorer right-click menu**):
  your account only, no administrator rights; click **Right-click menu: on** to remove it -
  nothing is left behind. If you move the folder, the window offers to fix the menu.
- `Bagel.exe` only opens the window; it starts nothing else and changes nothing on the PC.
  Settings and scan history are kept in `.game_safety_scanner` in your user folder.

### What the verdicts mean

| Verdict | Meaning | What to do |
| --- | --- | --- |
| CLEAN | nothing suspicious found | fine to play, as far as a scan can tell |
| LIKELY SAFE | only low-level signs | fine to play; the signs are listed |
| REVIEW | some behaviour should be looked at, or a part could not be read | read the findings first |
| SUSPICIOUS | high-risk behaviour found | do not run it unless you know why it does that |
| DANGEROUS | behaviour like malware found | do not run it |

A part Bagel could not read (a password archive, an unknown packed format) never gives CLEAN or
LIKELY SAFE: the verdict is at least REVIEW, because nobody knows what is inside.

### Known limits of 0.9-beta

- Real malicious samples are used for testing, but no scanner catches everything: a game that
  is not flagged is not proven safe. Some clean games get REVIEW or SUSPICIOUS (false alarms),
  for example from libraries Bagel has no official list for, or from keyboard-hook imports.
- Not inspected: native machine code itself, `.wasm`, encrypted RPG Maker MV/MZ assets, anything
  the game downloads while it runs.
- No real-time "Protection" window in 0.9-beta. Report notes are in English only.
- Closing the window during a scan stops it at the next file (up to 5 seconds); a large file
  being read may leave temporary files in `%TEMP%`.
- Tested only on Windows with Python 3.13 64-bit.

### Licence

MIT, "Copyright (c) 2026 phageo" (`LICENSE`). The `python` folder is python.org's Python 3.13.16
with Tcl/Tk; its parts keep their own licences, listed in `THIRD-PARTY-NOTICES.txt`.

## Kullanıcılar için (Türkçe)

Bagel 0.9-beta bir oyun klasörünü veya dosyasını (Ren'Py, RPG Maker, Unity, Windows
programları, betikler, arşivler, kurulum dosyaları) okur ve ne kadar tehlikeli göründüğünü
söyler. **Statiktir**: dosyaları yalnızca okur, **oyunu ya da içindeki hiçbir şeyi asla
çalıştırmaz**. Windows Güvenliği'nin yanında ikinci bir görüştür, onun yerine geçmez. Bir
**beta** sürümüdür: aşağıdaki sınırlara bakın.

### İndirme ve kurulum

İki yol vardır; ikisi de aynı programdır.

- **Kurulum dosyası (`Bagel-0.9.0-beta-setup.exe`):** çift tıklayın. **Yalnızca benim için**
  (yönetici izni gerekmez; `%LOCALAPPDATA%\Programs\Bagel`) ya da **tüm kullanıcılar için**
  (yönetici izni gerekir; `C:\Program Files\Bagel`) seçin; sonraki sayfada başka bir klasör
  seçebilirsiniz. Başlat menüsüne ve sağ tık menüsüne **Bagel**'ı ekler. Windows Ayarlar ->
  Uygulamalar'dan kaldırın: program dosyalarını ve iki girişi kaldırır; ayarlarınızın, tarama
  hafızasının ve karantinanın da silinip silinmeyeceğini sorar (varsayılan: saklanır).
  Seçtiğiniz bir klasördeki başka dosyalar yerinde kalır.
- **Taşınabilir zip (`Bagel-0.9.0-beta.zip`):** istediğiniz yere açın (örneğin `Belgeler`) ve
  `Bagel.exe`'ye çift tıklayın. Hiçbir şey kurulmaz, Python gerekmez: yalnızca paketin kendi
  `python` klasöründeki Python'u kullanır.

**SmartScreen:** kurulum dosyası ve program imzalı değildir; Windows "Windows bilgisayarınızı
korudu" diyebilir. **Ek bilgi** -> **Yine de çalıştır**'a yalnızca dosyayı phageo'nun
yayımladığı yerden aldıysanız tıklayın ve SHA-256 değerini sürüm notlarındakiyle karşılaştırın.

**Microsoft Defender imzasız kurulum dosyasını işaretleyebilir** (makine öğrenmesine dayanan bir
tahmin; Microsoft'a yanlış alarm olarak bildirildi); zip işaretlenmiyor.

**Windows Defender:** Bagel açılırken kendi dosyalarını, paket hazırlanırken yazılmış bir
listeyle karşılaştırır; bir dosya değişmiş, eksik ya da fazlaysa (örneğin bir antivirüsün
sildiği bir dosya) bunu açıkça söyler. Yine de tarama yapabilirsiniz, ama Bagel'ı yeniden
indirin. Bu denetim bozulmayı bulur, bilerek yapılan değişikliği değil. Tarama sırasında
Bagel'ın açtığı kod Windows Defender'a da (AMSI) gösterilir; Defender yoksa ya da kapalıysa
rapor bunu söyler ve tarama sürer.

### Nasıl kullanılır

- **Tarama:** **Klasör…** (veya **Dosya…**) düğmesine tıklayın, oyunu seçin, **Tara**'ya tıklayın.
- **Güvenli başlatma:** taramadan sonra **Güvenli başlat…** düğmesi (bir klasör için hangi
  programın başlatılacağını sorar) ya da bir programın sağ tık menüsündeki **Bagel -> Güvenli
  başlat**. Oyunun klasörünü sıkı biçimde yeniden tarar (ayarlarınız bir bulguyu gizleyemez),
  sonra: TEMİZ / MUHTEMELEN GÜVENLİ - oyunu başlatır; İNCELEYİN ya da "okunamadı" - bir kez
  sorar; ŞÜPHELİ - yalnızca `başlat` (veya `launch`) yazarsanız başlatır; TEHLİKELİ - reddeder.
  Her sorunun varsayılan cevabı "hayır"dır. Yalnızca başlangıçta denetler, oyun çalışırken onu
  izlemez. (Komut satırı: `python -m gamescan --launch Game.exe`.)
- **Gezgin'de sağ tık menüsü:** tek bir **Bagel** girişi: klasörlerde ve dosyalarda **Tara**,
  programlarda (`.exe`) **Tara** ve **Güvenli başlat**. Bir oyunun programında Tara oyunun bütün
  klasörünü tarar; tek başına bir kurulum dosyası ya da arşiv kendisi olarak taranır; pencere
  neyi taradığını söyler. Windows 11'de "Daha fazla seçenek göster" altındadır. Kurulum dosyası
  ekler ve kaldırır. Zip ile pencerenin üstündeki **Sağ tık menüsüne ekle** düğmesine (ya da
  Ayarlar -> **Gezgin sağ tık menüsü**) tıklayın: yalnızca sizin hesabınız, yönetici izni
  gerekmez; kaldırmak için **Sağ tık menüsü: açık**'a tıklayın - geride hiçbir şey kalmaz.
  Klasörü taşırsanız pencere menüyü düzeltmeyi önerir.
- `Bagel.exe` yalnızca pencereyi açar; başka hiçbir şey başlatmaz, bilgisayarda hiçbir şeyi
  değiştirmez. Ayarlar ve tarama geçmişi kullanıcı klasörünüzdeki `.game_safety_scanner`
  içinde tutulur.

### Sonuçlar ne anlama gelir

| Sonuç | Anlamı | Ne yapmalı |
| --- | --- | --- |
| TEMİZ | şüpheli bir şey bulunamadı | bir taramanın söyleyebildiği kadarıyla oynanabilir |
| MUHTEMELEN GÜVENLİ | yalnızca düşük önemde işaretler var | oynanabilir; işaretler listelenir |
| İNCELEYİN | bazı davranışlara bakılmalı ya da bir kısım okunamadı | önce bulguları okuyun |
| ŞÜPHELİ | yüksek riskli davranış bulundu | neden böyle yaptığını bilmiyorsanız çalıştırmayın |
| TEHLİKELİ | zararlı yazılım benzeri davranış bulundu | çalıştırmayın |

Bagel'ın okuyamadığı bir kısım (parolalı arşiv, bilinmeyen bir paket biçimi) asla TEMİZ ya da
MUHTEMELEN GÜVENLİ vermez: içinde ne olduğunu kimse bilmediği için sonuç en az İNCELEYİN olur.

### 0.9-beta'nın bilinen sınırları

- Testlerde gerçek zararlı örnekler kullanılır, ama hiçbir tarayıcı her şeyi yakalayamaz:
  işaretlenmeyen bir oyunun güvenli olduğu kanıtlanmış olmaz. Bazı temiz oyunlar İNCELEYİN ya
  da ŞÜPHELİ alır (yanlış alarm); örneğin Bagel'ın resmi listesi olmayan kütüphaneler ya da
  klavye kancası içe aktarımları yüzünden.
- İncelenmeyenler: yerel makine kodunun kendisi, `.wasm`, şifreli RPG Maker MV/MZ dosyaları,
  oyunun çalışırken indirdiği her şey.
- 0.9-beta'da gerçek zamanlı "Koruma" penceresi yoktur. Rapor notları yalnızca İngilizcedir.
- Tarama sırasında pencereyi kapatmak taramayı bir sonraki dosyada durdurur (en çok 5 saniye);
  okunmakta olan büyük bir dosya `%TEMP%` içinde geçici dosya bırakabilir.
- Yalnızca Windows'ta, 64-bit Python 3.13 ile test edildi.

### Lisans

MIT, "Copyright (c) 2026 phageo" (`LICENSE`). `python` klasörü python.org'un Tcl/Tk içeren
Python 3.13.16'sıdır; parçaları kendi lisanslarını korur, `THIRD-PARTY-NOTICES.txt` içinde
listelenmiştir.

## More documentation / Daha fazla belge

In the source code, not in the download / Kaynak kodda, indirilen pakette değil (English only):

- [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) - engines, rules, verdict logic / motorlar, kurallar, sonuç mantığı
- [docs/DEVELOPING.md](docs/DEVELOPING.md) - tests, `tools/fetch.py`, tables, build, CI / testler, tablolar, derleme
- [docs/LIMITS.md](docs/LIMITS.md) - the full list of limits / sınırların tam listesi
- [CONTRIBUTING.md](CONTRIBUTING.md) - report a false alarm or a missed sample, tests, pull requests / yanlış alarm ya da kaçırılan örnek bildirme, testler
<!-- user-section-end -->
