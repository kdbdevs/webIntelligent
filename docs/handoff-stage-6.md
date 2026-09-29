# Handoff tahap 6 — WebIntelligent 1.6

Tanggal verifikasi: 30 September 2026 (Asia/Jakarta). Scope selesai: pelaporan kasus, paket terverifikasi, perbandingan metadata capture, asisten seleksi bukti opsional. Tidak ada push/deploy, scanner aktif, disk/RAM/mobile, atau perubahan bukti pengguna untuk pengujian.

## Kondisi awal dan penyimpanan

Repo awal bersih di commit `e8c4ba1` (`codex/stage-5`). AGENTS.md tidak ditemukan pada project/ancestor maupun subtree. README, handoff 1–5, model bukti, collector, sesi, graph, security dan parser yang ada diperiksa. Kerja tahap 6 berada di `codex/stage-6`; React/React Flow, Express, Playwright, Vite dan SQLite/AES-GCM yang ada dipertahankan. Tidak menambah dependency npm, database atau migrasi.

Empat mode offline baru: `case-report`, `capture-comparison`, `analysis-assistant`, `report-export`. Mode ini terpisah dari capture/history crawler dan memakai run/artifact/manifest/custody tahap 1. Asli tetap immutable lewat API/trigger; snapshot/ekspor menjadi artefak baru terenkripsi di storage. Pemilihan sumber, pemeriksaan dan ekspor memverifikasi run dan hash sumber; kasus lain, pointer/ID salah, run belum disegel, atau sumber rusak ditolak.

## Struktur kode/data

- `server/report-common.mjs`: reader bukti terverifikasi dengan cache JSON, referensi `{caseId,runId,artifactId,sha256,pointer}`, batas analisis, penyimpanan record offline.
- `server/reporting.mjs`: katalog sumber, draft/final, snapshot kasus/timeline/temuan/relasi/hipotesis, strict sharing projection, pembukaan sumber.
- `server/capture-comparison.mjs`: inventaris dan diff metadata, konteks scope/identitas/kebijakan/kegagalan serta evidence per baris.
- `server/report-render.mjs`: HTML escaped/self-contained, PDF Playwright dengan JavaScript mati, service worker diblokir dan seluruh request renderer dibatalkan.
- `server/report-export.mjs`: ekspor immutable JSON/HTML/PDF/container, manifest, original opt-in dan enkripsi kunci sekali ekspor.
- `tools/verify-package.mjs`: verifier independen Node built-ins; tidak bergantung aplikasi/database, tidak mengekstrak/mengunjungi/menjalankan isi paket.
- `server/analysis-assistant.mjs`: pencarian/ringkasan lokal, preview/consent terikat hash, adapter OpenAI dan kontrak keluaran terbatas.
- `src/ReportWorkspace.jsx`: panel tambahan kasus; UI audit dan graph sebelumnya tetap tersedia.

Report memiliki `id`, `seriesId`, `parentId`, `version`, `status`, `created`, engine/version, `snapshot`, `snapshotSha256`, `review`, dan reference artefak record. Snapshot memuat metadata kasus, sources, cards dengan classification/evidence, timeline multi-waktu, findings beserta history/rekomendasi, relations, hypotheses, gaps, limitations dan refs. Parsing yang dipilih eksplisit; satu versi per original dalam laporan. Operation aktif untuk sumber terpilih, termasuk transformasi jam, dibekukan. Perubahan berikutnya memerlukan draft baru. Nomor versi mengikuti parent (cabang dapat memiliki nomor sama; ID/parent membedakannya), tidak mengubah record lama.

Finalisasi membutuhkan peninjau, alasan, konfirmasi review dan hash draft yang tepat. Final menyalin snapshot yang sama dalam record baru; draft tetap ada. Final berarti peninjauan laporan, bukan validasi otomatis semua temuan. Validasi temuan tetap melalui layanan review tahap 4. Review terbaru saat penyusunan ikut dibekukan dan record review direferensikan, bukan menganggap status baru berasal dari assessment awal.

## Pemakaian dan ekspor

1. Pilih kasus terbuka dan selesai capture/impor/assessment. Buka **Laporan, perbandingan & asisten**, muat sumber, pilih hingga 12 versi.
2. Isi penulis/rekomendasi privat. Opsional tulis narasi berbagi yang aman dan setujui; tidak ada salin otomatis teks sumber ke narasi ini.
3. Buat draft, buka **Bukti** untuk JSON pointer/hash, tinjau timeline/status/gap/detail temuan. Unknown, source-claim, correlation, hypothesis, candidate, dismissed dan validated dibedakan.
4. Review manusia menghasilkan versi final baru. Untuk memperbarui analisis, pilih sumber dan buat versi baru dari laporan aktif.
5. Ekspor JSON/HTML/PDF/paket. Default berbagi menghilangkan nilai/teks sumber, screenshot, identitas/IP/URL/nama file dan teks analis privat. Narasi yang disetujui merupakan pernyataan analis. Hash/ID/waktu masih bisa menghubungkan catatan.
6. Asli sensitif hanya ID sumber yang dipilih eksplisit, dalam paket AES-256-GCM. Unduh kunci hex 32 byte secara terpisah, simpan di luar repo/laporan, jangan kirim bersama paket. Kehilangan kunci perlu ekspor baru. Tidak ada endpoint persist/retrieve kunci ekspor.

Container `.wipkg.json`: `format`, `manifest`, `manifestSha256`, `files[{path,base64}]`. Manifest mencatat path yang dihasilkan aplikasi, size/MIME/SHA-256, role dan sourceRefs. Report JSON memuat derivedFrom/originalRef parsing. Asli yang tidak disertakan tidak diperiksa verifier; hash-nya hanya referensi baseline. Paket encrypted membungkus seluruh container memakai AES-256-GCM, random IV/key, AAD format, tag, ciphertext digest. Master key storage tidak dipakai sebagai kunci ekspor dan tidak masuk paket.

Verifikasi: `node tools/verify-package.mjs PATH [--key-file PATH] [--expected-sha256 HASH]`. Verifier menolak traversal, duplikasi path, base64 noncanonical, ukuran/jumlah berlebih, mismatch manifest/file, dan kegagalan dekripsi. Tidak ada ekstraksi otomatis. Gunakan verifier/digest dari saluran tepercaya: mengganti paket sekaligus seluruh hash tidak dapat dideteksi tanpa trust anchor eksternal. Tidak ada signature, timestamp tepercaya atau klaim pembuktian hukum.

## Perbandingan

Pilih artefak dua `run-report` atau `page-extraction` dalam kasus yang sama. Kategori halaman, elemen, aset visual, domain, endpoint/method, parameter location/type dan temuan. Key adalah heuristik metadata URL origin/path + selector/type/method; query/fragment tersensor menurunkan keyakinan, repeated selector tidak menjamin identitas elemen lintas capture. Data/blob/inline tidak disamakan dari ID opaque. Temuan memakai assessment terakhir **tingkat run**, termasuk review, walau hanya satu snapshot dipilih; coverage ini ditampilkan.

Label `not-observed-in-B` tidak berarti removed/fixed. Ketidaksamaan halaman/kebijakan, request gagal/blocked dan deklarasi identitas ditampilkan. Identitas adalah pernyataan analis, bukan otentikasi terbukti. Tidak menginfer parameter path, asal penyimpanan CDN/backend, causal click→request, atau kesamaan bytes aset/respons yang tidak diarsipkan. Inventaris membandingkan set metadata, bukan frekuensi setiap request. Tidak mendukung diff DOM tree/source code/binary secara menyeluruh.

## Asisten dan batas kepercayaan

Tanpa key/provider: semua fungsi inti, pencarian substring lokal, ringkasan kartu fakta, relasi, timeline/graph, draft dan ekspor tetap berjalan. Hasil lokal adalah kompilasi fakta, bukan ringkasan prosa generatif. AI opsional untuk pemilihan/urutan fakta, kutipan exact dan pilihan pertanyaan/rekomendasi dari enum. Tidak menerima prosa klaim bebas dari model; ini pembatasan sengaja agar tiap fakta berasal dari bukti nyata.

Konfigurasi environment `WI_AI_PROVIDER=none|openai`, `WI_AI_MODEL`, `OPENAI_API_KEY`; environment di luar repo/laporan. Tidak ada dependency SDK atau endpoint kustom dari input pengguna. Endpoint tetap `https://api.openai.com/v1/chat/completions`, redirect error, timeout 20 detik, response maksimal 128 KiB, `store:false`, JSON mode dan `max_completion_tokens:1600`, tanpa retry/tool. Model harus mendukung bentuk API ini; interoperabilitas model nyata belum diuji.

Plan terenkripsi menyimpan reportRef, fakta terpilih, query, system instruction, payloadSha256, provider/model, template `evidence-selection-1.0.0`, waktu kedaluwarsa dan kutipan yang dikecualikan. Preview belum menghubungi provider. Execute memerlukan flag enabled/approved dan hash tepat; plan sekali percobaan, TTL 10 menit; perubahan template/model/sumber/konteks ditolak. Custody approval-attempt ditulis sebelum transport sehingga restart tidak mengulang plan diam-diam. Hasil menyimpan requested/returned model, versi template, sumber, fakta yang disetujui atau error generik tanpa raw respons provider/secret.

Keluaran hanya `factIds`, `quotes[{factId,text}]`, `questions`, `recommendationIds`. Unknown properties, ID di luar konteks, kutipan tidak persis cocok, refusal/truncation/tool call ditolak. Kutipan dicek terhadap field sumber terverifikasi ketika menyusun plan; hanya prefix terpilih hingga 500 karakter yang boleh dikutip persis. Artefak, termasuk kalimat prompt injection, diperlakukan sebagai data dan tidak dapat memanggil tool/memvalidasi temuan/mengubah asli/mengatribusikan pelaku. Kutipan opt-in dapat berisi PII; filter pola password/token bukan DLP universal. Pengguna tetap perlu meninjau konteks. Hasil lolos dapat menjadi sumber draft baru, tidak otomatis menjadi final.

Rujukan primer diperiksa saat implementasi:

- [OpenAI Structured Outputs / JSON mode](https://developers.openai.com/api/docs/guides/structured-outputs): JSON mode menjamin bentuk JSON pada kondisi didukung, bukan kebenaran semantik; validasi ID/kutipan aplikasi tetap wajib.
- [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat): kontrak message/response_format/store/token budget.
- [OpenAI data controls](https://developers.openai.com/api/docs/guides/your-data): `store:false` bukan jaminan zero retention; retensi/abuse monitoring bergantung layanan dan konfigurasi akun. UI menautkan rujukan ini sebelum egress.

## Verifikasi dan kesiapan rilis

Tes memakai dataset sintetis tahap 4–5 serta demo loopback; tidak memakai akun Facebook atau bukti pengguna untuk manipulasi.

- `npm run check`: build dan 53 tes (termasuk delapan tes tahap 6). Tes tahap 6 membuktikan freeze/reparse/review/skew-undo/hipotesis, kasus terpisah, referensi/pointer salah, sumber fixture rusak, private-data redaction, original opt-in/enkripsi, verifier CLI independen, file paket diubah, input rusak/besar, serta mock provider consent/ID/kutipan/prose/tool-injection rejection. Laporan legacy tetap source-claim dengan baseline impor, collection time unknown dan waktu historis yang hanya dinyatakan sumber.
- `npm run smoke:stage6`: browser UI memilih lima sumber (capture + HAR/log/email/file), 12 event timeline, membuka bukti, ringkasan lokal, review final, JSON/HTML/PDF/paket, verifikasi paket melalui proses Node terpisah, dan perbandingan capture nyata 1 vs 2 halaman demo. Tanpa provider/key. Foreign origin dan kasus lain ditolak; preview HTML tidak melakukan request atau mengandung script/img/iframe aktif. Stylesheet font app yang sudah ada diblokir dalam test.
- `npm run smoke:stage3`: fixture wiring lengkap, cookie-protected login, SPA, asset→request/elemen/screenshot dan desktop/mobile lolos.
- `npm run smoke:stage4`: pemeriksaan pasif, review manual, bukti/graph, login, batas scope dan ekspor lolos; tidak menambah target request.
- `npm run smoke:stage5`: enam format, 15 event awal, impor/provenance/graph/skew/undo/reparse/share dan current capture adapter lolos.
- PDF fixture enam halaman A4 diperiksa visual per halaman melalui Poppler, tanpa clipping/overlap; tidak mengandung JavaScript. Contoh dan screenshot lokal di `output/pdf/` dan `output/playwright/` (diabaikan Git).
- App lokal `http://127.0.0.1:8787` berjalan pada 1.6.0. Pemeriksaan pasca-restart: 42 artefak memiliki ciphertext dan hash baseline yang sama, 11 file legacy tidak berubah, empat laporan lama dapat dibaca dan seluruh run lolos verifikasi. Tidak ada run aktif saat restart; hanya event pemeriksaan custody baru yang ditambahkan.
- UI panel tahap 6 diperiksa pada desktop dan viewport 390 px, tanpa horizontal overflow.
- Integrasi OpenAI nyata **belum diuji**. Mock hanya membuktikan kontrak/guard deterministik, bukan kualitas atau kompatibilitas model nyata.

Batas operasional: 12 sumber, pembacaan sumber 64 MiB, deadline analisis 15 detik diperiksa di antara pembacaan (bukan worker hard timeout), snapshot 4 MiB, timeline 500, cards 700, inventaris 1.000 key per kategori, diff 2.000 baris, 200 record reporting/kasus, original terpilih 8 MiB, decoded package 16 MiB, encoded output 19 MiB, verifier input 32 MiB/64 file, PDF 5 MiB/satu renderer/15 detik setelah browser launch. Truncation dan limit terlihat atau menolak permintaan; kurangi sumber bila melampaui batas. Verifikasi seluruh run/custody dan daftar metadata dapat mahal pada kasus besar; belum ada benchmark skala besar atau pagination menyeluruh.

Tetap alat lokal dengan akses host penuh: hash/custody/key lokal bisa diganti administrator, host clock tidak terattestasi, tidak ada jaminan historical completeness. Collector scope/redirect/URL/private-network guards tidak dilonggarkan. Batas DNS-check vs actual connection tetap ada; ini bukan perlindungan SSRF/egress lengkap. Tidak ada isolasi multi-user, role access control, external signing/time authority, delivery audit ke penerima, WORM atau sertifikasi hukum. Build/test lolos tidak membuatnya forensic-ready atau production-ready.

Perluasan selanjutnya: evaluasi adapter model nyata dengan data sintetis dan izin eksplisit, review kualitas ringkasan/evidence retrieval, pagination/benchmark kasus besar, signed package dengan trust anchor eksternal bila dibutuhkan, dan controlled sharing profiles dengan redaksi terpilih. Jangan memperluas akuisisi atau active testing tanpa tahap terpisah.
