# Bagel (Game Safety Scanner)

<!-- user-section-start -->
## For users (English)

Bagel 1.0 reads a game folder or file (Ren'Py, RPG Maker, Unity, Electron / NW.js apps, Windows
programs, scripts, archives, installers) and tells you how dangerous it looks. It is **static**: it
only reads files and **never runs the game or anything in it**. It is a second opinion next to
Windows Security, not a replacement for it. See the test results and the limits below.

### Download and install

Two ways; both are the same program.

- **Installer (`Bagel-1.0.0-setup.exe`):** double-click it. Choose **only for me** (no
  administrator rights; `%LOCALAPPDATA%\Programs\Bagel`) or **for all users** (administrator;
  `C:\Program Files\Bagel`); the next page lets you pick another folder. It adds **Bagel** to
  the Start menu and to the right-click menu. Uninstall in Windows Settings -> Apps: it removes
  its program files and both entries, and asks whether to delete your settings, scan memory and
  quarantine too (default: keep). Other files in a folder you chose stay.
- **Portable zip (`Bagel-1.0.0.zip`):** unzip it anywhere (for example `Documents`) and
  double-click `Bagel.exe`. Nothing is installed and no Python is needed: it uses the Python in
  the package's own `python` folder only.

**SmartScreen:** the installer and the program are not signed, so Windows may say "Windows
protected your PC". Click **More info** -> **Run anyway** only if you got the file from where
phageo published it, and compare its SHA-256 with the one in the release notes.

**Microsoft Defender may flag the unsigned installer** (a machine-learning guess about unsigned
programs). Compare the SHA-256 with the published one before you allow it.

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

### Privacy

The VirusTotal check (Settings) is off unless you turn it on. When on, Bagel sends VirusTotal only each program's
fingerprint (SHA-256); it never sends the file itself, its name or its location. VirusTotal can see which fingerprints
were looked up with your API key. If you downloaded the known-malware list, the comparison happens entirely on your
PC; nothing is sent. A clean result from VirusTotal never hides a finding; VirusTotal can only add new findings.

Bagel never uploads your files anywhere. During a scan, Windows' own malware check (Microsoft Defender) is also used.
If automatic sample submission is on in Windows Security, Windows may send suspicious files to Microsoft. You can turn
this off in Windows Security → Virus & threat protection settings.

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

In Bagel 1.0 a finding counts only as high as what it proves. SUSPICIOUS (or worse) means Bagel
traced a chain - data followed from one step to the next, such as a download that is run - or
found an act of hiding (a program disguised as a picture, code carried in a hidden form,
switching off Windows' protection). DANGEROUS needs more: code that has no harmless explanation,
such as hidden code that is decoded and run, code fetched from the internet and run, or browser,
wallet or Discord data sent out (or a file on the known-malware list). REVIEW means it found only capabilities - a keyboard hook, the
names of system tools, a script that can start programs - which games and malware both have;
Bagel still asks before it starts such a game.

### Test results

All numbers come from Bagel's own reading of the files: online lookups (VirusTotal, the
known-malware list) and Windows Defender's check were switched off for every measurement.

**(a) Files used while Bagel was developed.** Bagel was adjusted on these, so they show how it
behaves, not how well it would do on files it has never seen.

| Set | Files | At least REVIEW | SUSPICIOUS or above | DANGEROUS |
| --- | --- | --- | --- | --- |
| Clean games | 98 | - | 11 | 1 |
| Malicious samples | 51 | 51 | 39 | 21 |

The one clean game called DANGEROUS has a launcher that downloads a file and runs it without any
check; Bagel reports that behaviour as it is.

**(b) A test set never used during development (November 2026).** The targets were written down
before the test, and the set was scanned once.

Clean: 13 games - 0 DANGEROUS, 1 SUSPICIOUS, 11 REVIEW, 1 LIKELY SAFE, 0 CLEAN.

Malicious: 9 samples first seen on or after 2026-09-01 (8 Electron-based, 1 Ren'Py). One of them
matched a sample used during development, so 8 are counted. 15 to 20 were planned; only 9 met the
selection rules, and no malicious game-looking installer was found.

| Target (set before the test) | Wanted | Result | Met |
| --- | --- | --- | --- |
| Clean games called DANGEROUS | 0 | 0 of 13 | yes |
| Clean games SUSPICIOUS or above only with a traced chain or an act of hiding | all | 1 of 1 | yes |
| Malicious samples at least REVIEW | 100 % | 8 of 8 | yes |
| Malicious samples SUSPICIOUS or above, by a traced chain, hiding or malice | at least 2/3 | 5 of 8 (63 %) | no, one short |
| Malicious samples DANGEROUS | at least 1/3 | 2 of 8 (25 %) | no, one short |

Counting all 9 malicious samples: 9 at least REVIEW, 6 SUSPICIOUS or above, 2 DANGEROUS.

### Known limits of 1.0

- **The test set is small:** 13 clean games and 8 malicious samples. One sample more or less
  changes a rate a lot.
- **Game-looking installers were not measured:** no malicious one was found for the test set.
- **Electron-based malware is the weak side:** 3 of the 7 Electron samples in the test set got
  only REVIEW, and 6 of the 8 counted samples were not DANGEROUS.
- **REVIEW is common on clean games** (11 of 13 in the test set). REVIEW means "look at the
  findings", not "malicious"; the report gives the reason for every finding.
- **Static reading only:** no scanner catches everything, and a game that is not flagged is not
  proven safe. Not inspected: native machine code itself, `.wasm`, encrypted RPG Maker MV/MZ
  assets, anything the game downloads while it runs.
- No real-time "Protection" window. Report notes are in English only.
- Closing the window during a scan stops it at the next file (up to 5 seconds); a large file
  being read may leave temporary files in `%TEMP%`.
- Tested only on Windows with Python 3.13 64-bit.

### Reporting a security problem

Use GitHub's private vulnerability reporting on this repository (**Security** -> **Report a
vulnerability**), or open an issue if the problem is not sensitive.

### How it is made

Bagel is developed by phageo with AI assistance (Claude by Anthropic, through Claude Code). Every
change is checked by an automated test suite and by benchmarks against clean games and real
malware samples before release.

### Licence

MIT, "Copyright (c) 2026 phageo" (`LICENSE`). The `python` folder is python.org's Python 3.13.16
with Tcl/Tk, and it holds the tree-sitter parser for JavaScript; these parts keep their own
licences, listed in `THIRD-PARTY-NOTICES.txt`.

## Kullanıcılar için (Türkçe)

Bagel 1.0 bir oyun klasörünü veya dosyasını (Ren'Py, RPG Maker, Unity, Electron / NW.js
uygulamaları, Windows programları, betikler, arşivler, kurulum dosyaları) okur ve ne kadar
tehlikeli göründüğünü söyler. **Statiktir**: dosyaları yalnızca okur, **oyunu ya da içindeki hiçbir
şeyi asla çalıştırmaz**. Windows Güvenliği'nin yanında ikinci bir görüştür, onun yerine geçmez.
Aşağıdaki test sonuçlarına ve sınırlara bakın.

### İndirme ve kurulum

İki yol vardır; ikisi de aynı programdır.

- **Kurulum dosyası (`Bagel-1.0.0-setup.exe`):** çift tıklayın. **Yalnızca benim için**
  (yönetici izni gerekmez; `%LOCALAPPDATA%\Programs\Bagel`) ya da **tüm kullanıcılar için**
  (yönetici izni gerekir; `C:\Program Files\Bagel`) seçin; sonraki sayfada başka bir klasör
  seçebilirsiniz. Başlat menüsüne ve sağ tık menüsüne **Bagel**'ı ekler. Windows Ayarlar ->
  Uygulamalar'dan kaldırın: program dosyalarını ve iki girişi kaldırır; ayarlarınızın, tarama
  hafızasının ve karantinanın da silinip silinmeyeceğini sorar (varsayılan: saklanır).
  Seçtiğiniz bir klasördeki başka dosyalar yerinde kalır.
- **Taşınabilir zip (`Bagel-1.0.0.zip`):** istediğiniz yere açın (örneğin `Belgeler`) ve
  `Bagel.exe`'ye çift tıklayın. Hiçbir şey kurulmaz, Python gerekmez: yalnızca paketin kendi
  `python` klasöründeki Python'u kullanır.

**SmartScreen:** kurulum dosyası ve program imzalı değildir; Windows "Windows bilgisayarınızı
korudu" diyebilir. **Ek bilgi** -> **Yine de çalıştır**'a yalnızca dosyayı phageo'nun
yayımladığı yerden aldıysanız tıklayın ve SHA-256 değerini sürüm notlarındakiyle karşılaştırın.

**Microsoft Defender imzasız kurulum dosyasını işaretleyebilir** (imzasız programlar hakkında
makine öğrenmesine dayanan bir tahmin). İzin vermeden önce SHA-256 değerini yayımlananla
karşılaştırın.

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

### Gizlilik

VirusTotal denetimi (Ayarlar) siz açmadıkça kapalıdır. Açıkken Bagel, VirusTotal'a yalnızca her programın parmak
izini (SHA-256) gönderir; dosyanın kendisini, adını ya da konumunu asla göndermez. VirusTotal, API anahtarınızla hangi
parmak izlerinin sorgulandığını görebilir. Bilinen zararlılar listesini indirdiyseniz karşılaştırma tamamen
bilgisayarınızda yapılır; hiçbir şey gönderilmez. VirusTotal'dan temiz sonuç gelmesi hiçbir bulguyu gizlemez;
VirusTotal yalnızca yeni bulgu ekleyebilir.

Bagel dosyalarınızı hiçbir yere yüklemez. Tarama sırasında Windows'un kendi kötü amaçlı yazılım denetimi (Microsoft
Defender) de kullanılır. Windows Güvenliği'nde otomatik örnek gönderme açıksa Windows şüpheli dosyaları Microsoft'a
gönderebilir. Bunu Windows Güvenliği → Virüs ve tehdit koruması ayarlarından kapatabilirsiniz.

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

Bagel 1.0'da bir bulgu yalnızca kanıtladığı kadar yüksek sayılır. ŞÜPHELİ (ya da daha kötüsü),
Bagel'ın bir zinciri izlediği - verinin bir adımdan ötekine takip edildiği, örneğin indirilen bir
şeyin çalıştırılması - ya da bir saklama eylemi bulduğu anlamına gelir (resim gibi görünen bir
program, saklı biçimde taşınan kod, Windows'un korumasını kapatma). TEHLİKELİ daha fazlasını
ister: zararsız bir açıklaması olmayan kod; örneğin çözülüp çalıştırılan saklı kod, internetten
alınıp çalıştırılan kod ya da dışarı gönderilen tarayıcı, cüzdan veya Discord verisi (ya da bilinen zararlılar listesindeki bir dosya). İNCELEYİN
yalnızca yetenekler bulduğu anlamına gelir - bir klavye kancası, sistem araçlarının adları,
program başlatabilen bir betik - bunlar hem oyunlarda hem zararlı yazılımlarda bulunur; Bagel
böyle bir oyunu başlatmadan önce yine de sorar.

### Test sonuçları

Bütün sayılar Bagel'ın dosyaları kendi okumasından gelir: her ölçümde çevrim içi sorgular
(VirusTotal, bilinen zararlılar listesi) ve Windows Defender denetimi kapalıydı.

**(a) Bagel geliştirilirken kullanılan dosyalar.** Bagel bunlar üzerinde ayarlandı; bu yüzden
Bagel'ın nasıl davrandığını gösterirler, hiç görmediği dosyalarda ne kadar başarılı olacağını
değil.

| Küme | Dosya | En az İNCELEYİN | ŞÜPHELİ ya da üstü | TEHLİKELİ |
| --- | --- | --- | --- | --- |
| Temiz oyunlar | 98 | - | 11 | 1 |
| Zararlı örnekler | 51 | 51 | 39 | 21 |

TEHLİKELİ denen tek temiz oyunun başlatıcısı bir dosya indirip hiçbir denetim yapmadan
çalıştırıyor; Bagel bu davranışı olduğu gibi bildirir.

**(b) Geliştirme sırasında hiç kullanılmamış bir test kümesi (Kasım 2026).** Hedefler testten
önce yazıldı ve küme bir kez tarandı.

Temiz: 13 oyun - 0 TEHLİKELİ, 1 ŞÜPHELİ, 11 İNCELEYİN, 1 MUHTEMELEN GÜVENLİ, 0 TEMİZ.

Zararlı: ilk kez 2026-09-01'de ya da sonrasında görülmüş 9 örnek (8'i Electron tabanlı, 1'i
Ren'Py). Biri geliştirme sırasında kullanılan bir örnekle eşleşti; bu yüzden 8'i sayıldı. 15-20
örnek planlanmıştı; seçim kurallarına yalnızca 9'u uydu ve oyun gibi görünen zararlı bir kurulum
dosyası bulunamadı.

| Hedef (testten önce belirlendi) | İstenen | Sonuç | Karşılandı |
| --- | --- | --- | --- |
| TEHLİKELİ denen temiz oyun | 0 | 13 oyundan 0 | evet |
| ŞÜPHELİ ya da üstü temiz oyunlar yalnızca izlenen bir zincir ya da saklama eylemiyle | hepsi | 1 oyundan 1 | evet |
| En az İNCELEYİN denen zararlı örnek | %100 | 8 örnekten 8 | evet |
| İzlenen bir zincir, saklama ya da kötü niyetle ŞÜPHELİ ya da üstü zararlı örnek | en az 2/3 | 8 örnekten 5 (%63) | hayır, bir eksik |
| TEHLİKELİ denen zararlı örnek | en az 1/3 | 8 örnekten 2 (%25) | hayır, bir eksik |

9 zararlı örneğin hepsi sayıldığında: 9'u en az İNCELEYİN, 6'sı ŞÜPHELİ ya da üstü, 2'si TEHLİKELİ.

### 1.0'ın bilinen sınırları

- **Test kümesi küçüktür:** 13 temiz oyun ve 8 zararlı örnek. Bir örnek fazla ya da eksik bir
  oranı çok değiştirir.
- **Oyun gibi görünen kurulum dosyaları ölçülmedi:** test kümesi için zararlı bir tane
  bulunamadı.
- **Electron tabanlı zararlılar zayıf taraftır:** test kümesindeki 7 Electron örneğinden 3'ü
  yalnızca İNCELEYİN aldı ve sayılan 8 örnekten 6'sı TEHLİKELİ değildi.
- **Temiz oyunlarda İNCELEYİN sıktır** (test kümesinde 13 oyundan 11'i). İNCELEYİN "bulgulara bakın"
  demektir, "zararlı" demek değildir; rapor her bulgunun nedenini söyler.
- **Yalnızca statik okuma:** hiçbir tarayıcı her şeyi yakalayamaz; işaretlenmeyen bir oyunun
  güvenli olduğu kanıtlanmış olmaz. İncelenmeyenler: yerel makine kodunun kendisi, `.wasm`,
  şifreli RPG Maker MV/MZ dosyaları, oyunun çalışırken indirdiği her şey.
- Gerçek zamanlı "Koruma" penceresi yoktur. Rapor notları yalnızca İngilizcedir.
- Tarama sırasında pencereyi kapatmak taramayı bir sonraki dosyada durdurur (en çok 5 saniye);
  okunmakta olan büyük bir dosya `%TEMP%` içinde geçici dosya bırakabilir.
- Yalnızca Windows'ta, 64-bit Python 3.13 ile test edildi.

### Güvenlik sorunu bildirme

Bu depoda GitHub'ın özel güvenlik açığı bildirimini kullanın (**Security** -> **Report a
vulnerability**) ya da sorun gizli değilse bir issue açın.

### Nasıl geliştiriliyor

Bagel, phageo tarafından yapay zekâ desteğiyle (Anthropic'in Claude modeli, Claude Code üzerinden)
geliştirilmektedir. Her değişiklik, yayından önce otomatik testlerle ve temiz oyunlar ile gerçek
zararlı örnekler üzerinde yapılan karşılaştırmalı ölçümlerle denetlenir.

### Lisans

MIT, "Copyright (c) 2026 phageo" (`LICENSE`). `python` klasörü python.org'un Tcl/Tk içeren
Python 3.13.16'sıdır ve JavaScript için tree-sitter ayrıştırıcısını içerir; bu parçalar kendi
lisanslarını korur, `THIRD-PARTY-NOTICES.txt` içinde listelenmiştir.
<!-- user-section-end -->
