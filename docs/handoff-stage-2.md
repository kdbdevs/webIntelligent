# Handoff tahap 2 — Sesi audit authenticated

Tanggal selesai: 2026-09-30 (mulai 2026-09-29). Project: `/Users/devs/Developer/webIntelligent`. Branch kerja: `codex/stage-2`, berangkat dari fondasi tahap 1 yang sudah tersedia (`220498d`). Tidak ada AGENTS.md yang berlaku saat pemeriksaan; repo awal bersih. Tidak ada deploy/push tahap 2.

## Perubahan

- UI React/React Flow lama dipertahankan; panel **Audit dengan login** menambahkan pengaturan sesi, tab selector, deklarasi siap, snapshot, crawl URL pilihan, jeda, perpanjangan, dan tutup/simpan. Tombol **Rekam interaksi** tetap membuat run baru dengan referensi audit asal, sekarang memakai lifecycle yang sama.
- `server/sessions.mjs`: context Chromium baru khusus satu run, tetap sama selama login/MFA manual, popup, SPA, snapshot, dan crawl. Status opening/awaiting-login/ready/capturing/expired/closed/failed. Deklarasi pengguna berbeda dari indikator akses; 200 tidak membuktikan autentikasi.
- Koleksi DOM/screenshot/request/event default baru dimulai saat **Mulai capture**. **Halaman siap** saja belum mengumpulkan bukti. Setelah capture, metadata tab terpilih terus diamati sampai dijeda/ditutup. Observasi login adalah opt-in tersendiri, hanya metadata event/request; tanpa screenshot otomatis.
- Timeout absolut 1–120 menit, default 15, peringatan pada satu menit terakhir, perpanjangan eksplisit, dan penutupan manual. Kehilangan akses (indikator 401/URL login, atau laporan pengguna) menjeda koleksi. Browser tertutup, error jaringan, dan restart mempertahankan artefak sebelumnya sebagai partial.
- `server/session-policy.mjs`: crawler mengunjungi URL pilihan dalam scope, tidak mengeklik/submit form. POST baca membutuhkan izin endpoint tepat dan optional operationName (wajib untuk path GraphQL); mutation/subscription yang terlihat ditolak. GET dengan URL aksi yang dikenali juga ditolak. Ini heuristik/deklarasi operator, bukan pembuktian bebas efek samping.
- `server/redirect-guard.mjs`: pemeriksaan Location pada response stage Chromium per hop; request routing Playwright sendiri tidak cukup untuk redirect berantai. Tab collector disiapkan sebelum navigasi pertama. Tujuan di luar scope, logout, dan alamat privat tetap diblokir pada redirect. Request awal popup yang belum punya frame memakai relay context yang sama tanpa auto-redirect; redirect awal popup diblokir secara konservatif dan dicatat.
- Stage 1 SQLite/AES-GCM/artefak immutable/custody/hash/ekspor tetap digunakan, tanpa dependency npm/database atau migrasi skema tambahan. Collector menjadi 1.2.0. Artefak sebelumnya dan sumber legacy tidak ditimpa.
- Screenshot authenticated menyensor kontrol password/OTP yang dikenali lewat type/autocomplete saat akuisisi. Peran artefaknya `redacted`; metode dan keterbatasan dicatat. Screenshot tanpa sensor tidak diakuisisi. DOM/report tetap hanya ekstraksi tersanitasi, bukan raw evidence.

## Data dan API

- Run `mode=authenticated`; config menyimpan scope, izin localhost, batas halaman, timeout, opt-in login, origin transit login, URL indikator, kebijakan, dan sifat sesi sementara.
- `job.session` adalah ringkasan sesi aktif; `job.sessionInfo` mempertahankan ringkasan akhir. Tidak ada BrowserContext, cookie, password, token, localStorage, atau storageState yang diserialisasi. Context hanya runtime dan dibuang saat ditutup; tidak ada fitur simpan/reuse login.
- Manifest menambahkan `session` (status, readiness, authSignal, waktu, tab/riwayat tersanitasi, operasi beserta target/izin/status/error) dan `redirects` (asal/tujuan tersanitasi, status, keputusan/alasan). Custody mencatat deklarasi siap, perubahan status, perpanjangan, dan penutupan.
- Metadata tab/navigasi dan keputusan redirect/blokir diperlukan sebelum capture untuk mengendalikan scope. Tidak berarti seluruh traffic login dikumpulkan. Metode/source screenshot dan relay popup tercatat sebagai tindakan collector.
- API: `POST /api/sessions`, `GET /api/sessions/:id`, `POST /api/sessions/:id/{select,ready,capture,pause,extend,auth-lost,close}`. Capture menerima `kind`, `urls`, `readEndpoints`, `reload`. Endpoint lama record/capture/stop-recording tetap tersedia, dengan kewajiban konfirmasi siap sebelum capture. Guard Host/Origin/local bind tetap berlaku.

## Menjalankan dan memakai

```sh
npm install
npm run browser:install
npm run build
npm start
```

Node seri 22 minimal 22.16 atau 24+. Pengujian menggunakan Node 26 dan fallback Google Chrome pada macOS. Buka `http://127.0.0.1:8787`.

Pilih kasus → isi URL dalam scope → **Buka browser audit** → login/MFA sendiri → pilih tab → **Halaman siap** → snapshot atau crawl URL pilihan → **Tutup & simpan run** → **Bukti & manifest** → buka artefak → verifikasi → ekspor. Lihat README untuk format izin POST, scope transit login, dan rincian timeout. Untuk melihat request pemuatan yang terjadi sebelum capture, opsi reload harus dipilih eksplisit.

Fixture cookie tersedia hanya dengan `ENABLE_AUTH_FIXTURE=1`. Contoh server terpisah: `ENABLE_AUTH_FIXTURE=1 PORT=8788 DATA_DIR=/tmp/wi-auth-fixture npm start`. Scope `/auth-fixture`, target `/auth-fixture/profile`, URL indikator `/auth-fixture/login`, memakai URL localhost lengkap dan izin localhost. Kredensial sintetis: `fixture@example.test` / `fixture-password`, kode MFA `123456`. Izin POST baca: `http://127.0.0.1:8788/auth-fixture/api/read ProfileRead`. Demo lama `/demo` tetap untuk regresi wiring, bukan bukti autentikasi.

## Verifikasi

- `npm run check`: build produksi dan **23 tests** lulus. Termasuk 13 tests lama tentang integritas/manipulasi fixture, isolasi kasus, legacy import, recovery dan redaksi; suite baru menguji autentikasi cookie/MFA melalui form browser, gating sebelum capture, SPA, popup, POST baca/aksi diblokir, redirect berantai, logout/401, timeout/perpanjangan, dua sesi pada dua kasus, browser tertutup, jaringan gagal, dan recovery metadata sesi.
- `npm run smoke:stage2`: server/database/kunci sementara dibuat sendiri. Alur UI kasus → URL → browser audit terpisah → login/MFA → siap → snapshot → pilih popup → crawl context sama → preview artefak → verifikasi hash → download manifest lulus. Desktop/mobile tanpa overflow dan tanpa error runtime React.
- `APP_URL=http://127.0.0.1:8788 npm run smoke`: regresi audit publik empat halaman, screenshot/listener/form, POST demonstrasi tersanitasi, React Flow, inspector network, dan UI mobile.
- `APP_URL=http://127.0.0.1:8788 npm run smoke:stage1`: case UI, audit scoped, preview, perhitungan hash/custody independen, ekspor, isolasi kasus, path traversal, immutable API dan Origin guard.
- Password fixture, MFA, nilai cookie fixture, dan struktur state autentikasi diperiksa tidak ada dalam laporan/manifest/artefak JSON. Input login diisi lewat form browser sebagai simulasi tindakan operator, bukan injeksi cookie. Timeout diuji dengan memajukan deadline runtime fixture, bukan menunggu 15 menit.
- Redirect ke luar scope dan logout memiliki counter server untuk membuktikan target tidak dihubungi. Pengujian manipulasi hanya memakai fixture tahap 1; tidak ada akun Facebook/pihak ketiga atau bukti pengguna yang dipakai untuk eksperimen.
- Server utama 8787 dimuat ulang setelah dipastikan tanpa run aktif; health melaporkan 1.2.0 tanpa warning migrasi. Dua run legacy tetap lolos verifikasi, dan hash 11 file sumber lama cocok dengan baseline sebelum tahap ini. Fixture autentikasi tetap dinonaktifkan pada server utama.
- Screenshot visual: `output/playwright/stage2-session-desktop.png`, `stage2-session-mobile.png`, dan `stage2-setup-desktop.png` (diabaikan Git). UI desktop diperiksa secara visual; console awal hanya menunjukkan favicon lama yang tidak tersedia, bukan error React.

## Batas dukungan dan tahap berikutnya

- Satu audit/sesi aktif per server. Tidak ada session vault, reuse, profil harian, auto-login, atau bypass CAPTCHA. Semua sesi baru harus login ulang. Facebook belum diuji dan tidak diklaim kompatibel.
- Hanya Chromium/Chrome; redirect guard bergantung pada CDP. Popup yang respons pertamanya redirect memerlukan navigasi manual ke tujuan yang disetujui. SSO/anti-bot tertentu, iframe, service worker (diblokir), dan challenge dapat tidak berfungsi.
- Pengamatan akses tidak universal: 401 atau URL login hanyalah indikator. Aplikasi yang logout tanpa indikator tersebut membutuhkan laporan pengguna. Timeout collector tidak sama dengan expiry akun situs.
- Hanya URL yang dipilih eksplisit dicrawl. GET/izin POST tidak menjamin bebas efek samping; endpoint tersembunyi/operasi GraphQL persisten tidak dianalisis secara semantik. Hindari interaksi manual saat crawl karena kebijakan sementara berlaku pada context yang sama.
- Screenshot/teks DOM/URL path dapat memuat data pribadi atau kredensial yang ditampilkan sebagai teks biasa. Mask password/OTP hanya berdasarkan kontrol yang dikenali. Fragmen/query disamarkan; route hash berbeda dapat tampil sebagai snapshot terbaru halaman yang sama, sementara artefak lama tetap ada.
- Batas tahap 1 tetap berlaku: 10 halaman/tab, 1500 metadata request, 500 event, 250 elemen, screenshot 4000px, 20 MiB/artefak, 128 MiB/150 artefak ditambah cadangan penutupan. Capture maksimum 3 menit, 100 operasi dan 100 riwayat/redirect per sesi. Batas tersebut bukan pembatas seluruh traffic/memori browser atau disk total.
- Local single-user tool; DNS check belum socket pinning/sandbox egress dan belum mengendalikan semua protokol seperti WebSocket. Izin localhost tetap hanya loopback. Hash/custody lokal tidak membuktikan kebenaran sumber, jam asal, atau ketahanan terhadap administrator host.
- Tahap berikutnya: wiring asal aset/dependensi sesuai rencana tahap 3. Tidak menambahkan scanner kerentanan, AI, impor disk/RAM, atau pekerjaan tahap lanjut pada perubahan ini.
