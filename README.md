# Web Intelligent

App lokal untuk memetakan website dari URL: screenshot dengan penanda elemen, wiring navigasi, alur data, dan inspector network. Frontend **React 19 + React Flow**, backend **Node.js + Express + Playwright**.

## Jalankan

Gunakan Node **22.16+ pada seri 22, atau 24+**. Versi 1.1 memakai `node:sqlite` bawaan Node; tidak ada dependency npm baru. Pengujian pengembangan dilakukan pada Node 26.0.0.

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
4. **Alur data** memetakan elemen, event, parameter, method/endpoint, penerima server, dan respons. Setiap node diberi label **Teramati**, **Deklarasi HTML**, atau **Belum diketahui**.
5. **Network** memperlihatkan method, endpoint, HTTP status, content type, nama/tipe body parameters, query parameter names, dan initiator stack apabila tersedia.
6. **Rekam interaksi** membuka browser baru di komputer ini. Lakukan interaksi sendiri di browser tersebut untuk merekam request sebenarnya. Klik refresh di toolbar untuk snapshot terbaru, lalu **Selesai** untuk menutup sesi. Sesi otomatis berakhir setelah 10 menit. Rekaman dibuat sebagai run baru di kasus yang sama dengan referensi ke audit asal; snapshot ulang menambah artefak baru dalam run tersebut.
7. **Bukti & manifest** menampilkan artefak, sumber, waktu, peran, hash, observasi, dan riwayat penanganan. Klik artefak untuk pemeriksaan integritas sebelum preview; **Verifikasi integritas** memeriksa seluruh run. **Ekspor manifest** menghasilkan metadata, hash, hasil verifikasi, dan rantai custody kasus. **JSON** tetap mengunduh laporan audit tersensor. Ekspor ditolak jika bukti gagal diverifikasi. Riwayat difilter menurut kasus.

**Audit demo** menyediakan form login dan endpoint lokal sungguhan. Akun demo: `demo@example.com`, password `demo`. Tombol demo mengaktifkan izin localhost. Website demo bukan sistem autentikasi production.

## Apa yang dibuktikan

- Scan pasif membuka halaman dan merender JavaScript. Tidak mengeklik tombol atau mengirim form. Request selain GET/HEAD/OPTIONS diblokir; upaya request tetap dapat muncul dengan status blocked.
- Crawler mengikuti link pada origin halaman pertama (setelah redirect), tidak mengikuti tautan yang terlihat seperti logout/delete/checkout, dan berhenti pada batas halaman. Situs tertentu memerlukan POST untuk render; gunakan sesi manual jika scan pasif tidak cukup.
- Listener yang diinstrumentasi adalah listener DOM yang terdaftar setelah init script. React/event delegation tidak selalu bisa dipetakan langsung ke elemen. Nama state React, isi controller backend, validator, dan query database **tidak ditebak**.
- Kaitan event → request bersifat korelasi waktu (jendela 1,5 detik), dibantu kesamaan nama parameter. Ini **bukan** distributed tracing atau bukti kausalitas penuh.
- HTTP method, body key/type, dan status hanya berlabel teramati jika ada request nyata. HTML `action`/`method` selalu ditandai sebagai deklarasi karena JavaScript dapat mengubahnya.
- Laporan menyimpan nama/tipe parameter, bukan raw request body, cookie, Authorization, atau nilai input. Semua query values di URL laporan disamarkan. **Screenshot tetap merekam konten halaman yang terlihat**; jangan bagikan report/screenshot yang berisi data pribadi.
- Sesi rekam menggunakan profil browser kosong. Login dilakukan sendiri oleh pengguna. Sesi baru membuka route tanpa query values yang telah disamarkan.

## Batas versi ini

- Maks. 250 elemen interaktif terlihat per halaman, 1500 request per audit, screenshot setinggi 4000px, dan satu proses audit/rekam dari UI.
- Konten iframe, closed shadow DOM, canvas, source-map analysis, serta receiver/DB internal belum didukung. Bukan scanner kerentanan, Lighthouse, atau rekonstruksi source code.
- Scan authenticated / interaksi lanjutan dilakukan lewat browser rekam manual, bukan crawler otomatis dalam akun pengguna.
- Server hanya bind ke `127.0.0.1`. Origin API diperiksa dan alamat privat/reserved ditolak secara default; opsi localhost hanya mengizinkan loopback. Pemeriksaan DNS ini **bukan jaminan isolasi egress** terhadap DNS rebinding. Ini developer tool lokal, belum layak dijadikan layanan multi-user yang menerima URL tidak tepercaya tanpa sandbox jaringan tambahan.
- Data lama tidak dihapus otomatis. SQLite dan sumber legacy dapat membesar. Tidak ada janji batas ukuran disk total; batas akuisisi diterapkan per artefak/run. Daftar metadata di sidebar menampilkan 30 run untuk kasus terpilih; semua run tetap tersimpan.

## Struktur

```text
src/App.jsx                 UI, inspector, React Flow
src/styles.css              Layout responsive
server/index.mjs            Local API + static frontend
server/audit.mjs            Crawl, recording, checkpoint, dan impor legacy
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
- Screenshot adalah hasil akuisisi browser yang terenkripsi. Ekstraksi DOM dan laporan sudah disanitasi saat dikumpulkan, **bukan raw traffic**. Tidak ada perluasan koleksi menjadi password, cookie, Authorization, raw body, atau browser storage. Screenshot, teks DOM, dan URL path tetap dapat mengandung data pribadi.
- Artefak, observasi, dan custody event tidak punya API update/delete, dan trigger SQLite menolak perubahan/penghapusan. Laporan penutup dan manifest disimpan sebagai artefak baru; working report hanya cache yang berubah selama run aktif. `derivedFrom` merujuk artefak dalam kasus/run yang sama. Screenshot dan DOM adalah akuisisi bersaudara, bukan klaim DOM diekstrak dari gambar.
- Manifest memuat konfigurasi, scope navigasi, dependency origins yang teramati, batas, cakupan, request gagal/diblokir, error, tindakan collector, dan daftar artefak. Snapshot rekam berikutnya mempertahankan artefak snapshot sebelumnya. Run rekam terpisah dari audit pasif asal.
- SHA-256 dihitung atas byte plaintext artefak, bukan ciphertext. Read/preview dan ekspor memverifikasi autentikasi enkripsi, ukuran, serta hash. Custody event memiliki hash berantai per kasus. Pada ekspor, verifikasi tiap event dengan `SHA256(previousHash + canonicalPayload)` memakai string UTF-8 apa adanya; event pertama memakai 64 karakter `0`. Hash manifest merujuk byte manifest tersimpan, bukan keseluruhan wrapper ekspor yang menambahkan hasil verifikasi/custody terbaru.
- Ini baseline lokal: tidak menjamin keaslian sumber, ketepatan jam host, atau perlindungan terhadap administrator yang dapat mengganti database dan kunci. Operator adalah identitas yang dimasukkan pengguna lokal, bukan identitas yang diautentikasi. Pemisahan kasus bukan sistem otorisasi multi-user.
- Scope domain berarti origin HTTP(S) yang dinormalisasi. Scope URL berarti path tersebut beserta turunannya; port dan protokol harus sama. Query/token tidak diterima di scope. Redirect navigasi yang keluar scope diblokir. Resource dari origin lain dapat tercatat sebagai dependensi, tetap melalui kebijakan alamat jaringan; ini tidak mengizinkan crawl origin tersebut.
- Audit dibatasi 3 menit, rekam 10 menit, 10 halaman/tab, 1500 metadata request, 500 event, 250 elemen per halaman, screenshot 4000px, 20 MiB per artefak dan 128 MiB/150 artefak capture per run. Disediakan cadangan hingga dua artefak/40 MiB untuk laporan dan manifest penutup. Checkpoint working report dilakukan tiap 5 detik dan setelah snapshot; crash dapat kehilangan aktivitas sejak checkpoint terakhir. Run terputus dipulihkan sebagai partial, termasuk ketika belum sempat menulis checkpoint pertama.
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
