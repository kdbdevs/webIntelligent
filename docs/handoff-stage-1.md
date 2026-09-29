# Handoff tahap 1 — Case dan evidence foundation

Tanggal: 2026-09-29. Scope: tahap 1 saja. Stack UI dipertahankan; tidak ada scanner, AI, akuisisi disk/RAM, persistent login, atau wiring aset baru.

## Hasil

- Case manager: judul, tujuan, operator, scope navigasi, catatan, status terbuka/ditutup. Scope dan operator tidak dapat diubah ketika run masih aktif. Edit setelahnya menyimpan sebelum/sesudah di custody.
- Setiap audit dan sesi rekam mendapat run tersendiri. Rekaman mengacu ke parent run; tiap snapshot menambahkan artefak baru meskipun tampilan explorer mengganti snapshot halaman yang sama.
- Inspector bukti menampilkan sumber, waktu/zona waktu, metode, versi collector, ukuran, MIME, SHA-256, lineage, serta status legacy. Preview memverifikasi byte. Riwayat run terlihat di UI; rantai custody kasus lengkap ikut ekspor manifest.
- Manifest mencakup scope/configuration, waktu, cakupan, collector actions, blocked/failed request, warning, artefak, dan observasi. Status run evidence `complete` atau `partial` terpisah dari status UI audit lama; `complete` tidak menjanjikan seluruh website tercakup.
- Audit URL, rekam interaksi, screenshot, React Flow, inspector network, riwayat, dan ekspor JSON lama tetap berfungsi. Endpoint gambar lama membaca salinan artefak yang diverifikasi, bukan menyajikan file legacy langsung.

## Struktur data dan keputusan persistence

`server/evidence.mjs` memakai `DatabaseSync` dari `node:sqlite`, WAL, synchronous FULL, transaksi, foreign key, dan prepared statements. Tidak ada dependency npm baru. Node yang didukung: seri 22 mulai 22.16, atau 24+. Pengujian nyata memakai Node 26.0.0 di macOS.

| Tabel        | Peran                                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| cases        | Metadata kasus yang dapat direvisi dengan custody event                                                 |
| runs         | Snapshot operator/scope/config, status, parent run, pointer artefak penutup, working report terenkripsi |
| artifacts    | Metadata dan BLOB terenkripsi immutable; ID sumber/turunan dalam case/run yang sama                     |
| observations | Observasi page snapshot, network summary, atau legacy import dengan artifact ID dan JSON pointer        |
| events       | Append-only event, waktu, operator yang dinyatakan, detail, hash sebelumnya dan hash payload            |
| meta         | Schema version dan fingerprint kunci untuk menolak kunci yang salah                                     |

BLOB artefak/working report memakai AES-256-GCM dengan nonce acak dan associated data case/run/artifact. Hash SHA-256 adalah hash byte plaintext yang dikumpulkan. Trigger SQLite menolak UPDATE/DELETE pada artifacts, observations, events; API tidak menyediakan operasi tersebut. Metadata source/title/operator/hash tetap plaintext di SQLite, dilindungi akses file lokal. Ini bukan enkripsi seluruh database.

Kunci default `.data.keys/master.key` berada di luar `.data`; permissions direktori kunci 0700, kunci/database 0600, server memakai umask 0077. `DATA_DIR` dan `EVIDENCE_KEY_DIR` dapat dikonfigurasi; direktori kunci harus di luar data. Git mengabaikan data, key, database, environment files, build, dan output browser.

## Jalankan dan gunakan

```sh
npm install
npm run browser:install
npm run build
npm start
```

Buka http://127.0.0.1:8787. Buat kasus dengan scope misalnya `http://127.0.0.1:8787/demo`; audit URL demo dan centang izin localhost. Setelah selesai, buka **Bukti & manifest**, pilih artefak, **Verifikasi integritas**, lalu **Ekspor manifest**. **Rekam interaksi** membuat run baru dalam kasus yang sama; login masih manual dan sesi belum reusable (pekerjaan tahap 2).

API tambahan: `/api/cases`, `PATCH /api/cases/:caseId`, `/api/cases/:caseId/runs`, `/api/cases/:caseId/custody`, `/api/cases/:caseId/runs/:runId`, `POST .../verify`, `GET .../manifest`, `GET .../artifacts/:artifactId`, dan `GET .../artifacts/:artifactId/content`. Semua lookup artefak mengikat case/run/artifact. Export run aktif ditolak; export dengan integritas gagal menghasilkan 409.

## Migrasi dan recovery

Impor legacy dilakukan per laporan dalam transaksi; file lama tidak diedit/dihapus. `original-imported` mempertahankan byte persis, termasuk redaksi yang dilakukan collector lama. Baseline dimulai ketika diimpor; tanggal lama diberi label claimedSourceTime. Impor ulang melewati run ID yang sudah ada. File yang tidak valid/terlalu besar dilaporkan, bukan dihapus.

Backup/pemulihan dijelaskan di README: hentikan server, salin DATA_DIR beserta sisa WAL/SHM, dan salin direktori kunci secara terpisah. JSON/manifest saja tidak cukup untuk memulihkan seluruh bukti. Working report memiliki checkpoint 5 detik; restart menyegel run aktif menjadi partial, termasuk run tanpa checkpoint pertama. Aktivitas setelah checkpoint terakhir mungkin hilang; artefak yang sudah masuk database tetap dipertahankan.

## Verifikasi yang dilakukan

- `npm run check`: build produksi dan 13 tests lulus, mencakup enkripsi, immutable record, perubahan byte fixture yang membuat read/verify/export gagal, isolasi kasus/lineage/path ID, batas ukuran, perubahan metadata kasus dengan custody, recovery setelah restart, run tanpa checkpoint, impor legacy idempotent, kunci salah/hilang, dan pemeriksaan keselamatan URL/redaksi sebelumnya.
- `APP_URL=http://127.0.0.1:8788 npm run smoke`: crawl 4 halaman demo, screenshot, listener/form, sesi rekam asli dengan run terpisah, POST JSON demo tanpa menyimpan nilai input di laporan request, navigasi, React Flow, network inspector, dan mobile tanpa overflow.
- `APP_URL=http://127.0.0.1:8788 npm run smoke:stage1`: membuat kasus melalui UI, audit dalam scope, membuka preview screenshot yang diverifikasi, verifikasi integritas, download manifest, menghitung ulang SHA-256 seluruh artefak dan rantai custody secara independen, isolasi dua kasus, path traversal/PUT ditolak, Origin guard, scope rejection, ekspor JSON kompatibel, serta UI desktop/mobile tanpa runtime error.
- Vite development: akses langsung dan `/@fs/` ke key/database ditolak 403, sementara halaman utama, source React, dan API kasus tetap merespons 200.
- Pembatalan saat browser baru diluncurkan diuji dengan manager dan data sementara; run menjadi partial dan manifest lolos verifikasi.
- Restart aplikasi utama pada port 8787 mengimpor 2 laporan legacy tanpa warning; verifikasi semua run impor lulus dan hash 11 file sumber lama identik sebelum/sesudah impor.
- Visual desktop diperiksa dari output screenshot. Tidak ada pengujian aktif terhadap website pihak ketiga, akun Facebook nyata, atau manipulasi bukti pengguna.

## Keterbatasan dan tahap berikutnya

- Local single-user tool; operator bukan akun terautentikasi, pemisahan kasus bukan RBAC. Hash dan rantai lokal tidak mencegah administrator host mengganti database/kunci, tidak membuktikan kebenaran sumber atau ketepatan waktu historis.
- Original screenshot adalah hasil render browser dengan instrumentasi dan pengaturan capture yang dicatat, bukan salinan website yang bebas efek pengamatan. DOM/report tersensor sejak akuisisi; raw traffic, password, cookie values, Authorization, browser storage, dan response bodies tidak dikumpulkan.
- Screenshot/teks/URL path dapat memuat data pribadi. Folder legacy tetap berisi plaintext lama. Database metadata belum terenkripsi; tidak ada key rotation, remote KMS, signed timestamp, atau external custody anchor.
- Batas: 20 MiB/artefak, 128 MiB/150 artefak capture ditambah cadangan penutupan 40 MiB/2 artefak, audit 3 menit, rekam 10 menit, 10 halaman/tab, 1500 request metadata, 500 event, 250 elemen/halaman, screenshot 4000px. Batas ini bukan batas total traffic/memori browser atau total disk/history.
- DNS lookup belum socket-pinned dan belum ada sandbox egress khusus; allowLocal tetap hanya loopback. Navigasi dibatasi scope, dependency origins tidak otomatis menjadi target crawl. Service workers tetap diblokir; iframe/shadow DOM dan backend internal belum dipetakan.
- Capture UI menyimpan beberapa snapshot di satu run rekam; tidak menjamin timeline aktivitas lengkap. Causal tracing belum ditambahkan.
- Tahap 2: login/MFA manual → halaman siap → capture/crawl di context yang sama, lifecycle sesi yang lebih jelas, dan kebijakan observasi yang tidak sekadar membedakan metode HTTP. Tahap 3: wiring aset. Jangan mencampurkan kedua tahap tersebut ke perubahan ini.
