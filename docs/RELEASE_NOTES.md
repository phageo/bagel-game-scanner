# Bagel 0.9.0-beta - release notes

Author: phageo. Licence: MIT (`LICENSE`); the bundled Python and Tcl/Tk keep their own licences
(`THIRD-PARTY-NOTICES.txt`). Bagel was called "Game Safety Scanner" before this release.

## English

### What 0.9-beta does

- Reads a game folder or file - Ren'Py, RPG Maker XP / VX / VX Ace / MV / MZ, Unity (.NET and
  IL2CPP metadata), Electron / NW.js apps, Windows programs, scripts, archives and installers
  (zip, 7z, RAR, Cabinet, NSIS, Inno Setup, MSI) - and says how dangerous it looks: CLEAN, LIKELY
  SAFE, REVIEW, SUSPICIOUS or DANGEROUS. It never runs anything it scans.
- Each finding says in plain words what it means and what to do; reports as JSON, HTML or PDF.
- Official engine and library files are recognised by their exact SHA-256 (Ren'Py SDKs, Electron,
  NW.js, Unity, published npm packages, installer tools), so their normal behaviour is not flagged.
- **Safe launch:** after a scan, "Safe launch…" in the window - or **Bagel -> Safe launch** in
  Explorer's right-click menu on a program - scans the game's folder the strict way
  (nothing in your settings can hide a finding) and then starts the game (CLEAN / LIKELY SAFE),
  asks you once (REVIEW, or a part that could not be read), asks you to type the word `launch`
  (SUSPICIOUS) or refuses (DANGEROUS). Every question defaults to "no".
- **Two ways to get it, the same program:** the installer `Bagel-0.9.0-beta-setup.exe` (only for
  you - no administrator rights, `%LOCALAPPDATA%\Programs\Bagel` - or for all users with
  administrator rights, `C:\Program Files\Bagel`; another folder can be chosen; Start menu entry;
  the right-click entry is added at install and removed at uninstall, which leaves no file or
  registry key of Bagel - your settings, scan memory and quarantine only if you say so) or the
  portable zip `Bagel-0.9.0-beta.zip` (unzip and double-click `Bagel.exe`; no installed Python
  needed).
- **Right-click menu:** one entry **Bagel** with its icon: **Scan** on folders and files, **Scan**
  and **Safe launch** on programs. Scan on a game's program scans the whole game folder; an
  installer or archive on its own is scanned as itself, and the window says which. Removed without
  a trace. In the portable zip: the button **Add to the right-click menu** at the top of the main
  window (also in Settings; your Windows account only).
- At start Bagel checks its own files against a list built into it and warns if one was changed.

### Known limits

- No scanner catches everything: a game that is not flagged is not proven safe. Some clean games
  get REVIEW or SUSPICIOUS (false alarms) - for example from libraries the scanner has no official
  list for, or from keyboard-hook imports that ordinary engines also have.
- Not inspected: native machine code itself, `.wasm`, encrypted RPG Maker MV / MZ assets, anything a
  game downloads while it runs. A decoding whose bounds are not written in the script cannot be
  proven. Password archives and unknown packed formats are reported as "could not be read" and
  never called CLEAN.
- Safe launch decides once, at the start; it does not watch the game while it runs.
- The real-time "Protection" window is not part of 0.9-beta.
- The start-up check finds damage, not tampering. **The installer and the program are not signed:
  Windows SmartScreen may warn** ("Windows protected your PC" -> More info -> Run anyway, only for
  a file from where phageo published it, with the SHA-256 published beside the download). On
  Windows 11 the right-click entry is under "Show more options".
- Report notes are in English only. Tested only on Windows with Python 3.13 (64-bit).

### Why this is a beta

The finish criteria for 1.0 include **criterion 3: no false alarms and no missed malware on games
the scanner was never tuned on (held-out games), in two rounds. It was not met.** Round 1
(2026-10-17): 4 of 5 clean held-out games came out SUSPICIOUS or worse, and 2 of 27 malicious
samples were missed. Round 2 (2026-10-23): of 14 new clean games, 3 came out DANGEROUS and 4
SUSPICIOUS (allowed: none DANGEROUS, at most 2 SUSPICIOUS), and of 5 new malicious installers only
2 reached SUSPICIOUS. The fixes that followed were tuned on those games, so they no longer count as
unseen. 1.0 needs a third round with new clean games. Measured now on all 51 malicious samples
read: 46 at least SUSPICIOUS (90 %), 27 DANGEROUS.

## Türkçe

### 0.9-beta ne yapar

- Bir oyun klasörünü veya dosyasını okur - Ren'Py, RPG Maker XP / VX / VX Ace / MV / MZ, Unity
  (.NET ve IL2CPP üst verisi), Electron / NW.js uygulamaları, Windows programları, betikler,
  arşivler ve kurulum dosyaları (zip, 7z, RAR, Cabinet, NSIS, Inno Setup, MSI) - ve ne kadar
  tehlikeli göründüğünü söyler: TEMİZ, MUHTEMELEN GÜVENLİ, İNCELEYİN, ŞÜPHELİ veya TEHLİKELİ.
  Taradığı hiçbir şeyi çalıştırmaz.
- Her bulgu ne anlama geldiğini ve ne yapılması gerektiğini sade bir dille söyler; raporlar JSON,
  HTML veya PDF olarak alınabilir.
- Resmi motor ve kütüphane dosyaları tam SHA-256 değerleriyle tanınır (Ren'Py SDK'ları, Electron,
  NW.js, Unity, yayımlanmış npm paketleri, kurulum araçları); bu yüzden olağan davranışları
  işaretlenmez.
- **Güvenli başlatma:** taramadan sonra penceredeki "Güvenli başlat…" ya da Gezgin'de bir programın
  sağ tık menüsündeki **Bagel -> Güvenli başlat**, oyunun klasörünü sıkı biçimde tarar
  (ayarlarınızdaki hiçbir şey bir bulguyu gizleyemez) ve sonra oyunu başlatır (TEMİZ / MUHTEMELEN
  GÜVENLİ), bir kez sorar (İNCELEYİN ya da okunamayan bir kısım), `başlat` sözcüğünü yazmanızı ister
  (ŞÜPHELİ) veya reddeder (TEHLİKELİ). Her sorunun varsayılan cevabı "hayır"dır.
- **İki yol, aynı program:** kurulum dosyası `Bagel-0.9.0-beta-setup.exe` (yalnızca sizin için -
  yönetici izni gerekmez, `%LOCALAPPDATA%\Programs\Bagel` - ya da yönetici izniyle tüm kullanıcılar
  için, `C:\Program Files\Bagel`; başka bir klasör seçilebilir; Başlat menüsü kaydı; sağ tık girişi
  kurulurken eklenir, kaldırılırken silinir ve Bagel'dan hiçbir dosya ya da kayıt defteri anahtarı
  kalmaz - ayarlarınız, tarama hafızası ve karantina yalnızca siz isterseniz silinir) ya da
  taşınabilir zip `Bagel-0.9.0-beta.zip` (açın ve `Bagel.exe` dosyasına çift tıklayın; kurulu Python
  gerekmez).
- **Sağ tık menüsü:** simgesiyle tek bir **Bagel** girişi: klasör ve dosyalarda **Tara**,
  programlarda **Tara** ve **Güvenli başlat**. Bir oyunun programında Tara bütün oyun klasörünü
  tarar; tek başına duran bir kurulum dosyası ya da arşiv kendisi olarak taranır ve pencere neyi
  taradığını söyler. İz bırakmadan kaldırılır. Taşınabilir zip'te: ana pencerenin üstündeki **Sağ
  tık menüsüne ekle** düğmesi (Ayarlar'da da vardır; yalnızca sizin Windows hesabınız için).
- Bagel açılırken kendi dosyalarını içindeki bir listeyle karşılaştırır ve değişen bir dosya varsa
  uyarır.

### Bilinen sınırlar

- Hiçbir tarayıcı her şeyi yakalayamaz: işaretlenmeyen bir oyunun güvenli olduğu kanıtlanmış olmaz.
  Bazı temiz oyunlar İNCELEYİN ya da ŞÜPHELİ alır (yanlış alarm) - örneğin tarayıcının resmi
  listesi olmayan kütüphaneler ya da sıradan motorlarda da bulunan klavye kancası içe aktarımları
  yüzünden.
- İncelenmeyenler: yerel makine kodunun kendisi, `.wasm`, şifreli RPG Maker MV / MZ dosyaları,
  oyunun çalışırken indirdiği her şey. Sınırları betikte yazılı olmayan bir çözme işlemi
  kanıtlanamaz. Parolalı arşivler ve bilinmeyen paket biçimleri "okunamadı" olarak bildirilir ve
  asla TEMİZ sayılmaz.
- Güvenli başlatma bir kez, başlangıçta karar verir; oyun çalışırken onu izlemez.
- Gerçek zamanlı "Koruma" penceresi 0.9-beta'da yoktur.
- Açılış denetimi bozulmayı bulur, kasıtlı değişikliği değil. **Kurulum dosyası ve program imzalı
  değildir: Windows SmartScreen uyarı verebilir** ("Windows bilgisayarınızı korudu" -> Ek bilgi ->
  Yine de çalıştır; yalnızca phageo'nun yayımladığı yerden alınmış ve SHA-256 değeri indirme yerinde
  yayımlananla aynı bir dosya için). Windows 11'de sağ tık girişi "Daha fazla seçenek göster"
  altındadır.
- Rapor notları yalnızca İngilizcedir. Yalnızca Windows'ta, 64-bit Python 3.13 ile test edildi.

### Neden beta

1.0'ın bitiş ölçütleri arasında **ölçüt 3 var: tarayıcının hiç ayarlanmadığı oyunlarda (ayrılmış
oyunlar) iki turda yanlış alarm ve kaçırılan zararlı yazılım olmaması. Bu ölçüt karşılanmadı.**
1. tur (2026-10-17): ayrılmış 5 temiz oyundan 4'ü ŞÜPHELİ ya da daha kötü çıktı, 27 zararlı
örnekten 2'si kaçırıldı. 2. tur (2026-10-23): 14 yeni temiz oyundan 3'ü TEHLİKELİ, 4'ü ŞÜPHELİ
çıktı (izin verilen: hiç TEHLİKELİ yok, en çok 2 ŞÜPHELİ); 5 yeni zararlı kurulum dosyasından
yalnızca 2'si ŞÜPHELİ seviyesine ulaştı. Ardından yapılan düzeltmeler bu oyunlar üzerinde
ayarlandığı için artık "görülmemiş" sayılmazlar. 1.0 için yeni temiz oyunlarla üçüncü bir tur
gerekiyor. Okunan 51 zararlı örneğin tamamında şu anki ölçüm: 46'sı en az ŞÜPHELİ (%90), 27'si
TEHLİKELİ.
