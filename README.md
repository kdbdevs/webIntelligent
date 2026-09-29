# Web Intelligent

App lokal untuk memetakan website dari URL: screenshot dengan penanda elemen, wiring navigasi, alur data, dan inspector network. Frontend **React 19 + React Flow**, backend **Node.js + Express + Playwright**.

## Jalankan

Gunakan Node **22.16+ pada seri 22, atau 24+**. Versi 1.6 memakai `node:sqlite` bawaan Node; tidak ada dependency npm baru. Pengujian pengembangan dilakukan pada Node 26.0.0.

```sh
npm install
npm run browser:install
npm run build
npm start
```

Buka **http://127.0.0.1:8787**. Di Mac, app bisa memakai Google Chrome yang sudah terpasang apabila browser bundled Playwright belum tersedia. Dependensi dan build sudah disiapkan pada instalasi project ini.

Development dengan hot reload:

```sh
npm run dev
```

Port berbeda: `PORT=8788 npm start`. Data kasus dan artefak disimpan di `.data/evidence.sqlite`; atur `DATA_DIR` untuk lokasi lain. Kunci enkripsi berada di direktori terpisah `${DATA_DIR}.keys/master.key` (default `.data.keys/master.key`); `EVIDENCE_KEY_DIR` dapat menunjuk direktori kunci di luar `DATA_DIR`. `BROWSER_CHANNEL=chrome` memilih Chrome secara eksplisit.

## Pakai app

1. Pilih **Buat kasus**, isi judul, tujuan, operator, scope navigasi domain/URL, dan catatan. Kasus dapat diedit atau ditutup setelah run selesai. Tanpa pilihan kasus, audit membuat kasus otomatis. Isi URL, pilih batas 1–10 halaman, lalu **Audit website**. URL tanpa scheme memakai HTTPS.
2. **Elemen** menampilkan screenshot asli dengan penanda, selector, field name, form induk, deklarasi method/action/enctype, dan listener langsung yang terdeteksi.
3. **Alur halaman** menampilkan hubungan `href` melalui React Flow. Node bisa digeser; canvas bisa di-pan/zoom. URL yang belum dipindai dibedakan dari halaman yang sudah dipindai.
4. **Alur data** mempertahankan ringkasan elemen, handler, parameter, endpoint, dan respons. **Wiring & aset** menyediakan graph per capture dengan referensi bukti serta hubungan **observed**, **declared**, **correlated**, **inferred**, atau **unknown**. Klik node/garis untuk alasan dan keterbatasannya.
5. **Network** memperlihatkan method, endpoint, HTTP status, content type, nama/tipe body parameters, query parameter names, dan initiator stack apabila tersedia.
6. **Audit dengan login → Buka browser audit** membuka context sementara khusus run kasus terpilih. Login/MFA sendiri di browser itu, pilih tab target, klik **Halaman siap**, lalu **Mulai capture snapshot** atau **Mulai crawl pilihan**. **Jeda koleksi** menghentikan pencatatan; **Tutup & simpan run** menyegel bukti. **Rekam interaksi** dari hasil audit tetap tersedia dan membuka alur sesi baru di kasus yang sama, dengan referensi ke run asal. Snapshot berikutnya menambah artefak, tidak menimpa artefak lama.
7. **Bukti & manifest** menampilkan artefak, sumber, waktu, peran, hash, observasi, dan riwayat penanganan. Klik artefak untuk pemeriksaan integritas sebelum preview; **Verifikasi integritas** memeriksa seluruh run. **Ekspor manifest** menghasilkan metadata, hash, hasil verifikasi, dan rantai custody kasus. **JSON** tetap mengunduh laporan audit tersensor. Ekspor ditolak jika bukti gagal diverifikasi. Riwayat difilter menurut kasus.
8. Setelah run selesai, **Pemeriksaan keamanan → Analisis bukti** menjalankan tujuh rule pasif atas artefak terverifikasi. Pilih finding → **Tinjau bukti request** / **Buka wiring** → pilih bukti pendukung atau penyangkal → **Review manual**. **Ekspor security + manifest** menyertakan assessment, keputusan, skenario, dan manifest run terkait. Capture lama yang belum merekam metadata header tetap dapat dianalisis dengan hasil **not-assessed** untuk input yang belum tersedia.

**Audit demo** menyediakan form demonstrasi request dan endpoint lokal. Akun demo: `demo@example.com`, password `demo`. Tombol demo mengaktifkan izin localhost. Demo lama tidak melindungi halaman memakai cookie. Untuk menguji autentikasi sungguhan gunakan fixture cookie tahap 2 di bawah.

## Pelaporan kasus — tahap 6

Pilih kasus → **Laporan, perbandingan & asisten** → muat ulang sumber → pilih versi artefak (maksimal 12) → **Buat draft**. Sumber yang tersedia: capture `run-report` atau snapshot `page-extraction`, versi `forensic-parse`, assessment keamanan, perbandingan tersimpan, dan hasil asisten yang referensinya lolos validasi. Tidak ada data simulasi yang ditambahkan ke kasus nyata. Dataset tes diberi label sintetis.

Draft membekukan tujuan/scope kasus, metode/versi, waktu, coverage, timeline, observasi, korelasi, hipotesis dan status temuan hasil review manusia. Tombol **Bukti** memverifikasi hash dan membuka JSON pointer sumber sebagai teks. Isi website/email/log tidak dieksekusi. Rekomendasi dan detail temuan privat tersedia dalam panel. Perubahan parsing/review/koreksi jam setelah draft dibuat tidak mengubah snapshot lama. Isi peninjau, alasan, dan konfirmasi review untuk **Tandai final sebagai versi baru**. Status final laporan tidak otomatis memvalidasi temuan di dalamnya.

**JSON / HTML / PDF / Paket + manifest** membuat artefak ekspor baru. Default memakai proyeksi struktural tersensor: teks sumber privat, nama file, URL, identitas, nilai field, catatan analis, screenshot dan asli tidak disertakan. ID/hash/waktu tetap dapat menghubungkan catatan; tersensor bukan anonim. Isi **Narasi yang boleh dibagikan** bila membutuhkan judul, tujuan, scope, rekomendasi dan identitas peninjau yang sudah diseleksi sendiri; centang persetujuannya sebelum membuat versi draft baru. Narasi ini adalah pernyataan analis dan harus diperiksa lagi sebelum berbagi.

Paket `.wipkg.json` adalah kontainer JSON/base64, bukan ZIP dan tidak mengekstrak atau mengeksekusi file. Manifest mencatat hash/ukuran tiap file yang disertakan dan lineage ke sumber. Referensi hash ke asli yang tidak disertakan hanya baseline; verifier tidak memverifikasi bytes yang tidak ada di paket. **Ekspor asli sensitif** memerlukan pilihan ID sumber laporan satu per satu dan checkbox eksplisit. Paket kemudian dienkripsi AES-256-GCM dengan kunci acak sekali ekspor, berbeda dari kunci penyimpanan aplikasi. Simpan unduhan kunci terpisah sebelum meninggalkan hasil ekspor; kunci tidak disimpan dalam laporan dan tidak dapat dipulihkan dari paket. Collector tidak menyimpan atau mengekspor state login. File impor asli bisa mengandung secret dan hanya ikut jika sengaja dipilih melalui jalur terenkripsi.

Unduh verifier lokal dari UI atau gunakan salinan tepercaya `tools/verify-package.mjs`:

```sh
node tools/verify-package.mjs paket.wipkg.json
node tools/verify-package.mjs paket.encrypted.wipkg.json --key-file export.key
# Bandingkan juga dengan digest yang disimpan melalui saluran tepercaya:
node tools/verify-package.mjs paket.wipkg.json --expected-sha256 DIGEST_YANG_DISIMPAN
```

**Bandingkan dua capture** membandingkan metadata halaman, selector/elemen, sumber aset, domain, endpoint/method, parameter dan assessment terakhir per run. Hasil: `newly-observed`, `not-observed-in-B`, `metadata-changed`, atau `same-observed-metadata`. Konteks identitas yang dinyatakan analis, scope/halaman, konfigurasi dan request gagal tersedia di panel. Tidak terlihat bukan bukti penghapusan/perbaikan; identitas berdasarkan deklarasi bukan verifikasi. URL tersensor/query dan selector berulang membuat pencocokan heuristik. Data/blob/inline tidak digabung hanya karena ID mirip. Tidak ada klaim byte aset/respons identik karena bytes tersebut tidak diarsipkan.

**Analisis lokal tanpa AI** menyediakan pencarian teks, ringkasan fakta, relasi dan bahan draft dengan referensi yang bisa dibuka. Graph/timeline forensik tahap 5 tetap tersedia. AI opsional hanya membantu memilih/mengurutkan fakta yang sudah ada dan mengutip field yang persis cocok; bukan chat bebas, penentu validasi, alat uji aktif atau atribusi pelaku.

Provider bawaan: `none` (default) atau `openai`. Set `WI_AI_PROVIDER=openai`, `WI_AI_MODEL` ke model yang mendukung Chat Completions JSON mode, dan `OPENAI_API_KEY` dalam environment proses di luar repo/laporan, lalu restart server. App tidak otomatis membaca `.env`. Tanpa konfigurasi, semua fitur inti tetap berjalan. Di UI: jalankan analisis lokal → pilih fakta → aktifkan pengiriman → opsional kutipan → **Pratinjau konteks sebelum kirim** → baca system instruction, query dan seluruh fakta/kutipan → setujui pengiriman. Pratinjau belum menghubungi provider. Tiap persetujuan terikat hash konteks/model/template, berlaku 10 menit dan sekali percobaan. Tidak ada callable tool. Respons dengan ID palsu, kutipan buatan, prose tambahan atau tool call ditolak. Hasil yang diterima dapat dipilih sebagai sumber draft baru dan tetap perlu review manusia.

Hanya query, fakta struktural dan kutipan yang disetujui dikirim; kutipan dapat memuat PII atau prompt injection sebagai **data**. Filter pola secret adalah bantuan terbatas, bukan jaminan anonimisasi; baca preview. Endpoint OpenAI tetap, redirect ditolak, `store:false`, tanpa retry otomatis. `store:false` **bukan** janji zero retention: periksa [kebijakan data provider](https://developers.openai.com/api/docs/guides/your-data). Pengujian integrasi model nyata belum dilakukan; mock deterministik dipakai untuk pengujian referensi/consent/injection. API key hanya digunakan untuk autentikasi provider.

```sh
npm run check
npm run smoke:stage6 # data/kunci sementara; loopback dan artefak sintetis
npm run verify:package -- paket.wipkg.json
```

Batas dan catatan kesiapan rilis ada di [handoff tahap 6](docs/handoff-stage-6.md). Tidak ada database/dependency baru, migrasi destruktif, deploy, atau klaim forensic-ready/production-ready. Verifikasi hash lokal bukan autentisitas, waktu tepercaya, perlindungan administrator host, ataupun pemenuhan pembuktian hukum.

## Forensik kasus — tahap 5

Pilih kasus → **Buka workspace forensik**. Tambahkan capture browser yang sudah tersegel, atau impor file lokal (maksimal 8 MiB). Impor tidak mengunjungi URL dalam file. Asli disimpan terenkripsi dan hanya diunduh melalui tindakan eksplisit; hasil parsing berversi menjadi artefak terpisah. Impor identik tetap menghasilkan salinan dengan provenance sendiri. Tidak ada database/dependency baru.

| Format        | Profil yang didukung                                                                                                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HAR           | `log.version: "1.2"` dan `log.entries[]`: waktu, URL tersensor, method/status, durasi, IP server dan X-Request-ID bila tersedia. Tidak menyalin cookie, Authorization, request/response body ke parsing.                       |
| JSON / NDJSON | Array objek atau `{events:[]}` / satu objek per baris UTF-8. Pilih key atau JSON pointer untuk `time`, `action`, `account`, `url`, `ip`, `requestId`, `session`, `hash`, `messageId`. Bukan parser universal semua format log. |
| CSV           | UTF-8, header unik, pemetaan nama kolom persis, separator koma/titik koma/tab; quoted field dan multiline. Formula tetap teks.                                                                                                 |
| EML           | Header terpilih, Date numerik, multipart MIME terbatas, metadata/hash bagian terdekode (base64/quoted-printable/7bit/8bit/binary), deklarasi URL teks. Tidak merender HTML, membuka lampiran, atau memuat gambar remote.       |
| File umum     | Nama file yang dinyatakan, ukuran dan SHA-256; tidak mengekstrak arsip atau membaca dokumen/macro/executable.                                                                                                                  |

Contoh CSV fixture: `time → when`, `action → operation`, `account → principal`, `ip → client`, `requestId → request`, `url → link`; kosongkan field lain. JSON fixture memakai `time → /meta/when`, `action → action`, `account → principal`, `requestId → rid`. Dataset sintetis tersedia di `tests/fixtures/forensics/`. Namespace `portal-fixture` mengizinkan pencocokan request/session ID lintas file; namespace adalah deklarasi analis, bukan bukti identitas.

Timeline membedakan waktu event yang dinyatakan sumber, klaim waktu pengumpulan, waktu impor, dan waktu parsing. Filter memakai UTC; raw timestamp dan zona tetap dapat diperiksa. Tanpa zona: **ambiguous**, kecuali analis memilih offset tetap (ditandai **assumed-zone**). `-0000` email / `-00:00` timestamp berarti UTC dinyatakan tetapi zona lokal unknown. Format epoch detik/milidetik harus dipilih eksplisit. Koreksi jam hanya transformasi tampilan ±24 jam, dengan analis/alasan dan undo.

Klik event → **Tinjau sumber event** untuk hash/provenance; pilih sumber untuk versi parsing, parse ulang, unduh asli atau manifest/custody privat. Graph menyimpan occurrence terpisah; shared IP/akun/domain/hash/request ID hanya **correlated**, tanpa edge kausal berdasarkan waktu berdekatan. Pilihan entitas bisa dikelompokkan manual dengan alasan lalu dibatalkan. Checkbox event dipakai untuk bookmark, catatan dan hipotesis dengan bukti pendukung/penyangkal. Hipotesis selalu **belum terverifikasi**; referensi sumber dan versi parser tetap tersimpan meskipun diparse ulang.

**Buat ekspor tersensor** menghasilkan artefak berbagi yang hanya berisi struktur, waktu normalisasi, hash/referensi dan relasi. Nama file, nilai field, URL/identitas/IP, namespace dan teks analis dihilangkan; asli tidak disertakan. Hash/timestamp/ID tetap dapat menghubungkan catatan. Parsing privat bukan penyamaran seluruh PII: field terpilih dapat berisi data pribadi. Jangan gunakan unduhan asli, hasil parsing privat atau manifest/custody sebagai pengganti ekspor berbagi.

Batas: 1.000 event per parsing, 5.000 event per tampilan kasus (pilih sumber untuk sisanya), 100 file impor/kasus, 20 reparses/sumber, budget impor/parsing 128 MiB termasuk reserve, 300 catatan/transformasi, worker 3 detik. Parser gagal/timeout atau restart menyisakan asli dan run partial. Tidak ada ekstraksi arsip, analisis disk/RAM/mobile, pembongkaran enkripsi, eksekusi malware, ataupun rekonstruksi sejarah dari capture saat ini. Detail profil, skema, batas MIME, keamanan dan hasil pengujian: [handoff tahap 5](docs/handoff-stage-5.md).

```sh
npm run check
npm run smoke:stage5 # server/data/kunci sementara; fixture sintetis saja
npm run smoke:stage4 # regresi audit, login, wiring dan review keamanan
```

## Apa yang dibuktikan

- Scan pasif membuka halaman dan merender JavaScript. Tidak mengeklik tombol atau mengirim form. Request selain GET/HEAD/OPTIONS diblokir; upaya request tetap dapat muncul dengan status blocked.
- Crawler mengikuti link pada origin halaman pertama (setelah redirect), tidak mengikuti tautan yang terlihat seperti logout/delete/checkout, dan berhenti pada batas halaman. Situs tertentu memerlukan POST untuk render; gunakan sesi manual jika scan pasif tidak cukup.
- Listener yang diinstrumentasi adalah listener DOM yang terdaftar setelah init script. React/event delegation tidak selalu bisa dipetakan langsung ke elemen. Nama state React, isi controller backend, validator, dan query database **tidak ditebak**.
- Kaitan event → request bersifat korelasi waktu (jendela 1,5 detik), dibantu kesamaan nama parameter. Ini **bukan** distributed tracing atau bukti kausalitas penuh.
- HTTP method, body key/type, dan status hanya berlabel teramati jika ada request nyata. HTML `action`/`method` selalu ditandai sebagai deklarasi karena JavaScript dapat mengubahnya.
- Laporan menyimpan nama/tipe parameter, ringkasan header kebijakan, atribut Set-Cookie, dan keberadaan Authorization; **nilai** cookie/Authorization, raw request body, dan nilai input tidak disimpan. Semua query values di URL laporan disamarkan. **Screenshot tetap merekam konten halaman yang terlihat**; jangan bagikan report/screenshot yang berisi data pribadi.
- Sesi rekam menggunakan profil browser kosong. Login dilakukan sendiri oleh pengguna. Sesi baru membuka route tanpa query values yang telah disamarkan.

## Batas versi ini

- Maks. 250 elemen interaktif terlihat ditambah hingga 300 pemilik aset visual per capture, 1500 request per audit, screenshot setinggi 4000px, dan satu proses audit/rekam dari UI. Pemilik visual yang juga interaktif tidak diduplikasi.
- Konten iframe, closed shadow DOM, canvas, source-map analysis, serta receiver/DB internal belum didukung. Bukan scanner kerentanan, Lighthouse, atau rekonstruksi source code.
- Crawl authenticated terbatas pada URL yang dipilih eksplisit, dalam scope, menggunakan context sesi aktif. Tidak ada auto-login, penyelesaian CAPTCHA, penyimpanan/reuse login, atau crawl semua link dalam akun.
- Server hanya bind ke `127.0.0.1`. Origin API diperiksa dan alamat privat/reserved ditolak secara default; opsi localhost hanya mengizinkan loopback. Pemeriksaan DNS ini **bukan jaminan isolasi egress** terhadap DNS rebinding. Ini developer tool lokal, belum layak dijadikan layanan multi-user yang menerima URL tidak tepercaya tanpa sandbox jaringan tambahan.
- Data lama tidak dihapus otomatis. SQLite dan sumber legacy dapat membesar. Tidak ada janji batas ukuran disk total; batas akuisisi diterapkan per artefak/run. Daftar metadata di sidebar menampilkan 30 run untuk kasus terpilih; semua run tetap tersimpan.

## Struktur

```text
src/App.jsx                 UI, inspector, React Flow
src/styles.css              Layout responsive
server/index.mjs            Local API + static frontend
server/audit.mjs            Crawl publik, instrumentasi, snapshot, checkpoint, impor legacy
server/sessions.mjs         Lifecycle, gating, tab, readiness, capture/crawl authenticated
server/session-policy.mjs   Scope URL pilihan dan izin endpoint baca
server/redirect-guard.mjs   Pemeriksaan response-stage redirect Chromium
src/AuthSession.jsx         Kontrol sesi login dan crawl
server/auth-fixture.mjs     Fixture cookie/MFA lokal opt-in untuk verifikasi
server/evidence.mjs         SQLite, kasus/run, enkripsi, artefak, custody, manifest
src/CaseEvidence.jsx        Case manager dan inspector bukti
server/browser-scripts.mjs  DOM extraction + observer injection
server/safety.mjs           URL checks and parameter redaction
public/demo.*               Local test website
tests/                     Unit tests + real-browser smoke test
```

## Verifikasi

```sh
npm test
npm run build
# Saat server sudah berjalan:
npm run smoke
```

Smoke test menjalankan crawl, capture screenshot, membaca listener dan form, mencoba POST pada demo lokal, memeriksa penyamaran input, lalu menguji React Flow, inspector, dan layout mobile. Screenshot hasil pemeriksaan ada di `output/playwright/`.

## Fondasi bukti tahap 1

- Server development Vite menolak akses file langsung ke database, direktori data, dan kunci, termasuk lewat `/@fs/`.
- SQLite (`node:sqlite`) dipilih untuk transaksi atomik dan foreign key antar case/run/artifact/observation. Tidak membutuhkan database server. Byte artefak dan working report dienkripsi AES-256-GCM, dengan associated data berisi identitas case/run/artifact. Metadata kasus, sumber, label, dan hash di database tidak dienkripsi.
- Screenshot adalah hasil akuisisi browser yang terenkripsi. Ekstraksi DOM dan laporan sudah disanitasi saat dikumpulkan, **bukan raw traffic**. Nilai password/cookie/Authorization, raw body, atau browser storage tidak disimpan. Tahap 4 hanya menambahkan ringkasan header terpilih dan atribut cookie tanpa nilai. Screenshot, teks DOM, dan URL path tetap dapat mengandung data pribadi.
- Artefak, observasi, dan custody event tidak punya API update/delete, dan trigger SQLite menolak perubahan/penghapusan. Laporan penutup dan manifest disimpan sebagai artefak baru; working report hanya cache yang berubah selama run aktif. `derivedFrom` merujuk artefak dalam kasus/run yang sama. Screenshot dan DOM adalah akuisisi bersaudara, bukan klaim DOM diekstrak dari gambar.
- Manifest memuat konfigurasi, scope navigasi, dependency origins yang teramati, batas, cakupan, request gagal/diblokir, error, tindakan collector, dan daftar artefak. Snapshot rekam berikutnya mempertahankan artefak snapshot sebelumnya. Run rekam terpisah dari audit pasif asal.
- SHA-256 dihitung atas byte plaintext artefak, bukan ciphertext. Read/preview dan ekspor memverifikasi autentikasi enkripsi, ukuran, serta hash. Custody event memiliki hash berantai per kasus. Pada ekspor, verifikasi tiap event dengan `SHA256(previousHash + canonicalPayload)` memakai string UTF-8 apa adanya; event pertama memakai 64 karakter `0`. Hash manifest merujuk byte manifest tersimpan, bukan keseluruhan wrapper ekspor yang menambahkan hasil verifikasi/custody terbaru.
- Ini baseline lokal: tidak menjamin keaslian sumber, ketepatan jam host, atau perlindungan terhadap administrator yang dapat mengganti database dan kunci. Operator adalah identitas yang dimasukkan pengguna lokal, bukan identitas yang diautentikasi. Pemisahan kasus bukan sistem otorisasi multi-user.
- Scope domain berarti origin HTTP(S) yang dinormalisasi. Scope URL berarti path tersebut beserta turunannya; port dan protokol harus sama. Query/token tidak diterima di scope. Crawl/akuisisi dibatasi scope. Sesi login manual dapat melewati origin login yang dinyatakan; kunjungan di luar scope dicatat sebagai transit, bukan tambahan scope capture. Resource dari origin lain dapat tercatat sebagai dependensi, tetap melalui kebijakan alamat jaringan; ini tidak mengizinkan crawl origin tersebut.
- Audit/capture dibatasi 3 menit, sesi login 1–120 menit (default 15, dapat diperpanjang), 10 halaman/tab, 1500 metadata request, 500 event, 250 elemen interaktif ditambah 300 pemilik visual per capture, screenshot 4000px, 20 MiB per artefak dan 128 MiB/150 artefak capture per run. Disediakan cadangan hingga dua artefak/40 MiB untuk laporan dan manifest penutup. Checkpoint working report dilakukan tiap 5 detik dan setelah snapshot; crash dapat kehilangan aktivitas sejak checkpoint terakhir. Run terputus dipulihkan sebagai partial, termasuk ketika belum sempat menulis checkpoint pertama.
- Batas byte adalah batas artefak tersimpan; bukan pembatas total traffic/memori browser. DNS validation belum melakukan socket pinning dan browser belum ditempatkan dalam sandbox egress khusus. Jangan mengekspos server sebagai layanan publik atau multi-user. Kebijakan lama `allowLocal` tetap hanya membuka loopback, bukan alamat privat lain.

## Riwayat lama, backup, dan pemulihan

Startup mengimpor folder UUID lama yang berisi `report.json` beserta screenshot yang dirujuk. Setiap laporan mendapat kasus legacy sendiri. Impor per laporan bersifat transaksional dan idempotent; kegagalan muncul melalui `/api/health` dan banner UI. Laporan baru tidak lagi ditulis ke folder legacy.

File asli lama **tetap utuh**, termasuk screenshot plaintext yang memang sudah ada. Byte laporan lama disalin sebagai artefak terenkripsi `original-imported` dengan keterangan bahwa laporan asal sudah tersensor. Waktu historis dipertahankan sebagai klaim sumber; baseline hash hanya dimulai saat impor. Sumber yang tidak valid/terlalu besar tidak dihapus. Tidak ada klaim perlindungan enkripsi retroaktif untuk file legacy.

Untuk backup yang konsisten, hentikan server secara normal, lalu salin seluruh `DATA_DIR` (termasuk file SQLite `-wal`/`-shm` jika masih ada dan folder legacy). Simpan salinan direktori kunci secara terpisah dengan akses terbatas. Untuk memulihkan, jalankan aplikasi dengan salinan `DATA_DIR` dan kunci yang pas. Kunci hilang/salah membuat startup gagal; aplikasi tidak membuat kunci pengganti untuk database yang sudah ada. Ekspor JSON/manifest bukan pengganti backup artefak/database.

Untuk kembali membaca data dengan versi lama, gunakan salinan folder legacy yang tidak berubah dan kode lama pada direktori pemulihan terpisah. Jangan menimpa database tahap 1 atau menganggap versi lama dapat membaca run SQLite baru.

## Pengujian tahap 1

```sh
npm run check
# Terminal terpisah, data fixture saja:
PORT=8788 DATA_DIR=/tmp/webintelligent-fixture npm start
# Terminal pengujian:
APP_URL=http://127.0.0.1:8788 npm run smoke
APP_URL=http://127.0.0.1:8788 npm run smoke:stage1
```

Unit/integration tests membuat database sementara; uji manipulasi hanya mengubah database fixture. Browser smoke menggunakan website demo lokal. `smoke:stage1` membuat kasus fixture pada server yang ditunjuk, memeriksa UI desktop/mobile, pemisahan kasus, ekspor, serta menghitung ulang hash artefak dan rantai custody. Output visual disimpan di `output/playwright/` dan tidak masuk Git.

Lihat [handoff tahap 1](docs/handoff-stage-1.md) untuk skema, hasil verifikasi, dan pekerjaan selanjutnya. Rujukan implementasi: [SQLite bawaan Node](https://nodejs.org/api/sqlite.html) dan [API crypto Node](https://nodejs.org/api/crypto.html).

## Audit dengan login — tahap 2

1. Buat/pilih kasus. Masukkan URL awal **dalam scope kasus**, lalu buka pengaturan **Audit dengan login**. Tentukan timeout absolut 1–120 menit; default 15. Untuk SSO lintas origin, masukkan origin login tambahan. Origin URL awal diizinkan untuk transit login manual; ini tidak menambahkan halaman lain ke scope capture. URL login opsional berfungsi sebagai indikator kembalinya browser ke login, bukan pembuktian autentikasi.
2. Klik **Buka browser audit**, login/MFA langsung di browser tersebut. App tidak meminta kredensial, tidak memakai cookie browser harian, dan tidak melewati CAPTCHA. Default belum mengumpulkan DOM, screenshot, event, atau request. Metadata lifecycle/tab/URL navigasi serta keputusan redirect/blokir tersanitasi tetap dicatat untuk scope dan penanganan sesi. **Opt-in observasi login** hanya menambahkan metadata request/event sejak browser dibuka; tidak mengambil screenshot otomatis atau nilai kredensial.
3. Pilih tab target setelah popup/SSO, lalu **Halaman siap**. Ini pernyataan pengguna (`readiness.basis=user-confirmed`), terpisah dari `authSignal`; respons 200 tidak pernah mengaktifkannya. Capture belum dimulai pada langkah ini.
4. **Mulai capture snapshot** menyimpan DOM terpilih dan screenshot dalam run tersebut. Sesudahnya, metadata request/event tab terpilih terus diamati sampai **Jeda koleksi**, sinyal akses hilang, timeout, atau penutupan. Permintaan pemuatan yang terjadi sebelum capture tidak direkonstruksi. Opsi muat ulang adalah tindakan eksplisit yang dapat mengulang efek samping. SPA yang sudah aktif dipotret tanpa membuka context baru.
5. Untuk crawl, buka **Crawl halaman pilihan dalam sesi ini**. Masukkan URL tambahan (satu per baris, maksimal `maxPages - 1`), lalu setujui cakupan. Tab terpilih dipotret dan URL pilihan dibuka berurutan pada tab sementara **dalam BrowserContext yang sama**. Tidak ada otomatis klik, submit form, transaksi, kirim pesan, atau mengikuti semua href. Hindari interaksi manual selama crawl; kebijakan crawl sementara berlaku untuk seluruh context. Popup hasil login bisa dipilih sendiri melalui daftar tab.
6. Browser manual mengizinkan metode HTTP normal, termasuk POST. Saat crawl, non-GET/HEAD/OPTIONS diblokir kecuali POST pada endpoint baca yang dinyatakan pengguna. Izin cocok pada origin+path tepat; nama operasi opsional, wajib untuk path GraphQL. Format UI: `https://example.com/api/profile ProfileRead`. Jika nama operasi ditentukan, body JSON harus cocok; query GraphQL yang berisi mutation/subscription ditolak. Tidak mendukung batch/persisted GraphQL tanpa deklarasi operasi yang cocok. URL aksi yang dikenali seperti logout/delete/checkout/transfer/send ditolak, termasuk GET dan target fragmen SPA. Ini heuristik dan deklarasi operator, bukan jaminan tidak ada efek samping. Hasil dapat tidak lengkap karena request diblokir; lihat Network, catatan run, dan manifest.
7. Gunakan **Tutup & simpan run**, verifikasi artefak/hash, lalu ekspor manifest. Autentikasi tidak dipersistenkan atau disertakan dalam laporan; sesi berikutnya harus login ulang. Semua snapshot tersimpan sebagai artefak baru. Tidak ada ekspor run yang masih aktif.

| Status           | Arti                                                                                      |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `opening`        | Browser/context khusus run sedang dibuka                                                  |
| `awaiting-login` | Menunggu pemeriksaan/login manual atau konfirmasi ulang; koleksi isi default belum aktif  |
| `ready`          | Pengguna menyatakan halaman siap; flag `collecting` menunjukkan apakah observasi berjalan |
| `capturing`      | Snapshot/crawl sedang berlangsung di context yang sama                                    |
| `expired`        | Timeout **collector** tercapai; bukan klaim sesi situs pasti kedaluwarsa                  |
| `closed`         | Operator menutup sesi; context dibuang dan run disegel                                    |
| `failed`         | Browser ditutup tak terduga, gagal dibuka, atau collector terputus                        |

Akses situs yang kedaluwarsa tidak punya deteksi universal. HTTP 401 navigasi/fetch/XHR pada origin tab terpilih, kembali ke URL login terkonfigurasi, atau tab terpilih keluar scope menjeda koleksi dan menghapus pernyataan siap. Pengguna dapat menekan **Login tidak berlaku**, login ulang pada browser yang sama, lalu menyatakan siap lagi. Tidak memakai 403/200 atau teks halaman untuk menebak login. Screenshot authenticated menutup kontrol password/OTP yang dikenali lewat type/autocomplete saat akuisisi; artefak diberi peran redacted, dan screenshot tanpa sensor tidak pernah disimpan. Screenshot masih dapat memuat informasi pribadi atau kredensial yang ditampilkan sebagai teks biasa; jangan capture halaman yang sedang memperlihatkannya.

Timeout menampilkan peringatan saat tersisa satu menit, dan **Perpanjang sesi** mengatur ulang batas dari saat itu. Satu sesi/audit aktif per server. Batas capture lain dari tahap 1 tetap berlaku; maksimal 100 operasi snapshot/crawl dan 100 entri riwayat navigasi tersanitasi per sesi. Penutupan tidak mengambil screenshot diam-diam. Browser tertutup, error jaringan, atau batas capture mempertahankan artefak yang sudah tersimpan; run dapat menjadi partial. Restart memulihkan checkpoint terakhir sebagai partial, bukan melanjutkan autentikasi. State autentikasi tidak ditulis sebagai storageState; tidak ada fitur simpan/pakai ulang sesi.

Manifest menambahkan daftar `redirects` (asal/tujuan tersanitasi, status, keputusan dan alasan) serta `session` berisi status akhir, timeout, opt-in, pernyataan siap, indikator akses, tab/riwayat URL tersanitasi, kebijakan, dan operasi capture (target/metode/izin/waktu/status/error). Custody mencatat perubahan status, deklarasi siap, perpanjangan, dan penutupan. Persistence SQLite/enkripsi tahap 1 tetap dipakai; tidak ada database, dependency npm, atau migrasi skema baru. Collector versi 1.2.0.

Redirect HTTP diperiksa per hop pada response stage Chromium, sebelum browser mengikutinya. Pemeriksaan hanya membaca Location/metode/status, tanpa mengambil body respons sebagai bukti. Request pertama popup dapat muncul sebelum frame Playwright tersedia: request itu direlay memakai context yang sama, auto-redirect dimatikan, respons diteruskan lalu dibuang dari cache relay. Redirect pada respons popup pertama diblokir secara konservatif; buka URL tujuan yang disetujui secara manual pada tab audit. Login popup tertentu dapat memerlukan langkah tambahan ini. Sesudah tab diinisialisasi, pemeriksaan per-hop normal berlaku. Ini mengubah jalur pengiriman request awal popup dan dicatat sebagai tindakan collector.

Batas tambahan: dukungan browser saat ini Chromium/Chrome (guard memakai CDP); screenshot/DOM hanya halaman utama; iframe lintas origin, service worker (diblokir), popup challenge dan mekanisme anti-bot dapat membuat situs tidak berjalan. Tab tidak terpilih tidak direkam isi/event-nya kecuali opt-in login saat fase login. Query/fragmen disamarkan pada laporan; snapshot route hash berbeda bisa tampil sebagai versi halaman yang sama, tetapi seluruh artefaknya tetap terpisah. Browser memakai viewport audit dan instrumentasi; hasil bukan salinan tanpa pengaruh collector. DNS check tetap bukan socket pinning/sandbox egress, dan tidak membatasi seluruh protokol/traffic browser seperti WebSocket. Izin localhost hanya loopback, tidak memperluas akses ke LAN. Belum diuji memakai Facebook atau akun pihak ketiga; tidak ada klaim kompatibilitas Facebook.

### Fixture dan verifikasi tahap 2

```sh
npm run check
# Menyiapkan server + data sementara sendiri, membuka browser fixture:
npm run smoke:stage2
# Opsional port uji berbeda:
STAGE2_TEST_PORT=8790 npm run smoke:stage2
```

`npm test` memerlukan browser Playwright (install sesuai langkah awal). Suite sesi menjalankan fixture lokal dan browser headless, mengisi form login/MFA melalui UI browser sebagai simulasi tindakan operator; tidak menyuntik cookie untuk meloloskan autentikasi. `smoke:stage2` mengendalikan UI app dan browser audit terpisah yang terlihat, memakai database/kunci sementara. Artefak visual disimpan di `output/playwright/stage2-session-{desktop,mobile}.png`. Jangan gunakan data bukti asli untuk tes manipulasi.

Untuk mencoba sendiri:

```sh
ENABLE_AUTH_FIXTURE=1 PORT=8788 DATA_DIR=/tmp/wi-auth-fixture npm start
```

Buat kasus scope `http://127.0.0.1:8788/auth-fixture`, masukkan URL `/auth-fixture/profile` lengkap, centang **Izinkan localhost**, konfigurasi URL login `/auth-fixture/login` lengkap. Halaman profile menolak akses sebelum login (401). Akun sintetis: `fixture@example.test`, password `fixture-password`, MFA `123456`. Sesudah login, profile/settings dan POST `/auth-fixture/api/read` benar-benar memerlukan cookie HttpOnly. Izin baca untuk crawl: `http://127.0.0.1:8788/auth-fixture/api/read ProfileRead`. Ada tombol SPA, popup, logout, dan simulasi expiry. Fixture dinonaktifkan secara default dan bukan fitur autentikasi production.

Lihat [handoff tahap 2](docs/handoff-stage-2.md). Rujukan: [isolasi BrowserContext Playwright](https://playwright.dev/docs/api/class-browsercontext), [autentikasi](https://playwright.dev/docs/auth), dan [kontrol network](https://playwright.dev/docs/network).

## Wiring elemen, request, dan aset — tahap 3

Jalankan capture baru lalu buka **Wiring & aset**. Pilih halaman lewat **Halaman audit**, pilih elemen, lalu aktifkan **Hanya aset elemen pilihan** bila perlu. Cari URL/selector/deklarasi atau filter tipe/domain. Klik aset untuk menyorot graph, elemen pemakai, dan screenshot; tombol request membuka metadata request dan referensi artefaknya. Klik garis graph untuk membaca jenis hubungan dan alasannya. Inventaris dimuat per capture halaman, 40 aset per halaman daftar; graph menampilkan hingga 80 node di sekitar pilihan. Pan/zoom untuk membaca rincian. Preview memakai potongan dan penanda pada **PNG screenshot yang hash-nya diverifikasi**, bukan mengunduh aset lagi atau menjalankan SVG/HTML/script.

Pada halaman setelah login, login sendiri seperti tahap 2, nyatakan siap, lalu mulai capture. Interaksi yang terjadi sesudah koleksi aktif akan masuk snapshot berikutnya. Request saat login atau pemuatan sebelum koleksi aktif tidak dibuat ulang sebagai request teramati. Resource Timing browser dapat menunjukkan pemuatan sebelumnya dan disimpan sebagai sumber berbeda. Opsi reload tetap eksplisit dan dapat mengulang efek samping. Capture/crawl memakai context autentikasi yang sama.

| Jalur                         | Data yang tersedia                                                                                                                                             | Batas kesimpulan                                                                                                                        |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Elemen → event / handler      | ID elemen per capture, identitas DOM per dokumen, selector, frame, halaman, waktu, registrasi listener dan event target                                        | Registrasi bukan bukti handler dijalankan; delegasi framework dan aliran nilai tidak terlacak                                           |
| Parameter → request → respons | Nama/tipe/lokasi query, JSON, form/multipart; method/endpoint, transport/stack fetch-XHR bila teramati; status/content type, timing, redirect object reference | Nilai/body mentah tidak disimpan; parameter path, controller, database dan state framework tetap unknown tanpa skema/trace              |
| `img` / `picture` / `srcset`  | Kandidat deklarasi terpisah dari `currentSrc`, dimensi tampil dan intrinsik CSS px, complete/loading/viewport                                                  | Pilihan browser bukan jaminan decode; lazy di luar viewport tidak dipaksa dimuat                                                        |
| CSS / pseudo / sprite         | Computed URL, posisi/ukuran/repeat, kandidat aturan CSSOM dengan stylesheet URL/rule index, metadata inline style                                              | Kandidat aturan bukan pemenang cascade yang terbukti; akses CSSOM ditolak diberi alasan unknown. Sprite adalah dugaan dari posisi       |
| SVG / font / resource halaman | Inline SVG metadata, `use` lokal/eksternal, kandidat font-face dan glyph ikon, favicon, stylesheet, script                                                     | Tidak menyalin markup SVG, font bytes, atau script. Font fallback aktual dan eksekusi script tidak disimpulkan dari request             |
| Data / blob / domain          | Jenis sumber khusus dan identitas opak; domain penyaji untuk URL jaringan                                                                                      | Payload data URL dan identifier blob tidak diekspor. Pembuat blob serta lokasi penyimpanan backend/CDN unknown; tidak wajib ada request |

Setiap node/edge graph capture menyertakan `relation`, `reason`, `limitation`, dan `evidence[]` (`caseId`, `runId`, `captureId`, `artifactId`, JSON pointer). Hubungan `observed` menyatakan observasi tertentu, `declared` deklarasi sumber, `correlated` kecocokan waktu/nama, `inferred` dugaan terbatas, dan `unknown` bagian yang tidak teramati. Request gambar dekat klik hanya korelasi. Kecocokan URL aset–request menggunakan identitas opak per run atas URL tepat sebelum redaksi, frame, dan epoch dokumen: dua URL dengan query rahasia berbeda tidak digabung hanya karena tampil sama. Rahasia HMAC hanya ada di memori dan tidak diekspor. Kecocokan itu membuktikan request untuk sumber yang sama, bukan elemen tertentu sebagai penyebabnya.

Persistence tetap SQLite/enkripsi/append-only tahap 1 tanpa migrasi atau dependency npm baru. Satu capture menambah hingga empat artefak: screenshot, `page-extraction` (DOM + visual metadata), `capture-observations` (metadata browser dibekukan), dan `wiring-graph` (turunan dua artefak metadata). `page.wiring.artifactId` menunjuk graph; manifest memuat ID capture, referensi graph, gap dan cakupan. Artefak sebelumnya tetap immutable. Riwayat lama tetap terbaca; tab baru menjelaskan bila graph tahap 3 belum tersedia. Ringkasan Alur halaman/Alur data tetap tersedia dengan referensi bukti jika data asal mendukungnya.

Batas tambahan: scan 4.000 elemen DOM, 300 pemilik visual, 1.200 penggunaan sumber, 80 stylesheet/2.000 aturan CSS, hingga 8 tingkat nested rules, URL sumber maksimal 8.192 karakter dan nilai CSS maksimal 64.000 karakter (lebih besar dihilangkan dengan gap, tanpa pencocokan request), 1.000 entri Resource Timing terakhir yang masih ada, dan 300 batch perubahan DOM/SPA per run (maksimal 20 target per batch). Metadata perubahan tidak menyimpan nilai atribut/teks/state. Iframe tidak diekstrak; shadow DOM tidak ditelusuri (host open root terhitung, closed root tidak bisa dienumerasi). Service worker tetap diblokir. Cache provenance, request yang terlewat, resource timing yang terhapus, pemenang CSS cascade, parser srcset/CSS kompleks, stylesheet adopted, canvas, dan tracing blob creator belum lengkap. Nilai timing `-1` berarti belum tersedia; transferSize nol bukan bukti cache. Screenshot dan DOM diambil berurutan sehingga halaman bergerak bisa menggeser posisi; screenshot dibatasi 4.000 px dan memakai dimensi PNG aktual. Situs juga dapat memodifikasi instrumentasi browser; hash lokal tidak membuktikan kebenaran situs atau kekebalan dari administrator host. Batas jaringan tahap 1–2 tetap berlaku, termasuk belum adanya sandbox egress/socket pinning.

### Fixture dan verifikasi tahap 3

```sh
npm run check
npm run smoke:stage3
# Port smoke alternatif jika 8790 dipakai:
STAGE3_TEST_PORT=8792 npm run smoke:stage3
```

Smoke membuat database/kunci sementara serta server lokal sendiri; mencakup halaman publik dan login cookie/MFA melalui browser fixture, tanpa akun sungguhan. Fixture berisi gambar responsif, CSS/pseudo/sprite, SVG, font ikon nyata, data/blob, sumber lazy yang tidak dimuat, dua query berbeda yang tampil tersensor sama, CSS lintas origin yang tidak bisa dibaca, request input, SPA, iframe, dan shadow host. Suite memeriksa referensi bukti, kerahasiaan nilai, selection UI, pagination inventaris, PNG preview tanpa refetch aset, hash dan ekspor. Font sintetis ada di `tests/fixtures/icon.ttf`; script Python `make-icon-font.py` opsional hanya untuk regenerasi memakai FontTools, tidak dibutuhkan saat menjalankan app/test.

Untuk mencoba fixture manual (dinonaktifkan secara default):

```sh
ENABLE_AUTH_FIXTURE=1 ENABLE_WIRING_FIXTURE=1 PORT=8788 DATA_DIR=/tmp/wi-wiring-fixture npm start
```

Gunakan `/wiring-fixture` untuk halaman publik atau `/auth-fixture/wiring` untuk halaman privat; URL dan scope harus lengkap dengan origin, serta centang **Izinkan localhost**. Login fixture sama seperti tahap 2. Tambahkan scope `/auth-fixture` untuk alur login dan halaman privat; domain resource tidak memperluas scope navigasi.

Lihat [handoff tahap 3](docs/handoff-stage-3.md). Referensi perilaku browser: [currentSrc](https://developer.mozilla.org/en-US/docs/Web/API/HTMLImageElement/currentSrc), [naturalWidth](https://developer.mozilla.org/en-US/docs/Web/API/HTMLImageElement/naturalWidth), [request timing/redirect Playwright](https://playwright.dev/docs/api/class-request), [Resource Timing](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceResourceTiming/transferSize), dan [FontFaceSet](https://developer.mozilla.org/en-US/docs/Web/API/FontFaceSet/check).

## Tahap 4: pemeriksaan keamanan berbasis bukti

Panel **Pemeriksaan keamanan** membaca capture tersimpan setelah run disegel. Rule awal memeriksa kebijakan header, HSTS, atribut Set-Cookie, mixed content teramati, nama query sensitif, potensi transfer cleartext dan penerima data lintas origin. Nilai cookie/token dan state autentikasi tidak disimpan. Header absen, domain berbeda atau HTTP error tidak otomatis menjadi kerentanan; bukti yang belum dikumpulkan ditandai `not-assessed`.

Analisis menyimpan assessment baru di kasus yang sama. Tinjau finding → sumber artefak/hash → wiring/elemen/request → pilih bukti pendukung/penyangkal → simpan review. Risk dan confidence terpisah. Riwayat keputusan tidak ditimpa; `validated` hanya dapat ditetapkan analis dari kandidat dengan alasan dan bukti. Deklarasi reviewer/ownership bersifat lokal, bukan identitas/kepemilikan yang dibuktikan sistem.

Skenario validasi manual mencatat rencana, nama parameter, dampak, hasil atau pembatalan. **Tidak ada runner aktif/request replay.** Aktivitas manual tambahan harus memakai run capture terpisah dari baseline. Untuk klaim otorisasi lintas identitas, isi objek, pemilik, kebijakan, expected/actual access dan bukti per identitas; beda status HTTP saja tidak cukup. `Ekspor security + manifest` memverifikasi run baseline, assessment, review dan bukti terkait sebelum menghasilkan JSON.

```sh
npm run check
npm run smoke:stage4
```

Keduanya memakai fixture terkontrol untuk pengujian; smoke membuat database/kunci sementara sendiri. Fixture manual tersedia melalui `ENABLE_SECURITY_FIXTURE=1`, route `/security-fixture/bad`, `/safe`, `/error`. Tetap gunakan direktori data terpisah dan izin localhost. Tidak ada dependency/database baru atau migrasi bukti lama; metadata baru hanya tersedia pada capture baru.

Detail model, tujuh rule beserta rujukan primer, cara menambah rule, hasil pengujian dan batas collector: [handoff tahap 4](docs/handoff-stage-4.md). Ini pemeriksaan kontekstual, bukan audit keamanan menyeluruh atau jaminan SSRF/otentisitas bukti. Hash lokal tidak melindungi dari administrator host; validasi DNS belum mengikat socket koneksi browser.
