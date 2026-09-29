# Handoff tahap 4 — pemeriksaan berbasis bukti

Tanggal verifikasi: 30 September 2026 (Asia/Jakarta). Versi app 1.4.0, engine/rule 1.0.0. React/React Flow, Express, Playwright dan Vite dipertahankan. Fondasi case/run/artefak, sesi browser login, wiring serta handoff tahap 1–3 ditemukan dan digunakan. Tidak ditemukan AGENTS.md yang berlaku. Perubahan tahap 2–3 yang belum di-commit dipertahankan; branch kerja `codex/stage-4`. Tidak deploy/push dan tidak menambah AI atau runner pengujian aktif.

## Yang berubah

- `server/security-metadata.mjs`: ringkasan header yang diizinkan (CSP/enforcing vs report-only, HSTS, XFO, nosniff, Referrer-Policy), atribut instruksi Set-Cookie, serta keberadaan Authorization. Nilai cookie/token, nonce/hash/source CSP, raw headers, browser cookie jar dan storageState tidak ditulis. Pembacaan metadata hanya untuk request yang lolos gating koleksi sesi. `request.headerValue('authorization')` direduksi langsung menjadi boolean; `request.headers()` saja tidak cukup untuk memastikan absennya header keamanan.
- `server/security-rules.mjs`: fungsi murni atas metadata capture, katalog ID/versi/input/rujukan, evaluasi per request dengan evidence reference, counts termasuk not-assessed/not-applicable/no-indicator. Hasil otomatis berhenti pada observation/candidate. Risk dan confidence terpisah; CWE hanya bersyarat untuk URL/cleartext sensitif.
- `server/security.mjs`: verifikasi, assessment, proyeksi riwayat review, rencana/hasil manual, pemisahan kasus, validasi referensi dan ekspor. Membaca capture-observations terbaru per request ID, lalu report tersegel untuk request yang belum terwakili. Tidak mengirim HTTP, membuka browser, melakukan replay atau menulis ke baseline.
- `src/SecurityFindings.jsx`: panel pada hasil audit, konteks origin opsional, cakupan rule, filter status, evidence reader, graph per capture, review manual, skenario dan ekspor. Graph yang sama menampilkan relasi observed/declared/correlated/unknown dari tahap 3; pemilihan elemen menyorot PNG screenshot. Preview JSON adalah teks React; hanya PNG terverifikasi dirender sebagai gambar. Tidak refetch aset target.
- Collector menambahkan metadata di atas dan konteks dokumen/frame/navigation, menunggu metadata maksimal 2 detik sebelum membekukan capture; yang belum tersedia ditandai unavailable. Batas/redaksi/scope/redirect sebelumnya dipertahankan.
- Petunjuk sesi login menjelaskan metadata tambahan sebelum pengguna mulai mengumpulkan. Badge app menunjukkan 1.4.

## Struktur penyimpanan dan integritas

Tidak ada database/dependency baru atau migrasi destruktif. Menggunakan SQLite, enkripsi AES-256-GCM dan immutable artifact/event tahap 1. Kunci tetap di luar laporan. Tiga mode run baru, masing-masing mempunyai artefak record, run-report, manifest, parent baseline, dan custody event:

| Mode                  | Isi immutable                                                                                                                                                                                            |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `security-assessment` | ID, schema/engine version, baseline run, waktu host + zona, deklarasi origin, rule evaluations/input references, findings awal, cakupan/batas                                                            |
| `security-review`     | finding/assessment ID, revision sebelumnya, from/to, alasan, reviewer, waktu, evidence pendukung/penyangkal, risk/confidence, dampak/prasyarat/perbaikan/batas, jenis klaim                              |
| `manual-validation`   | rencana atau hasil/cancellation baru dengan test ID yang sama, revision, operator, scope baseline, langkah, nama parameter tanpa nilai, ekspektasi, dampak, evidence dan perbandingan identitas opsional |

Run offline dibuat/disegel dalam transaksi, tidak dimasukkan ke riwayat capture website. URL run offline hanya anchor scope kasus untuk persistence, bukan URL yang dikunjungi. Referensi lintas run di record berbentuk `{caseId, runId, artifactId, pointer, sha256}`; tidak melemahkan aturan `derivedFrom` sesama run. Pointer JSON diperiksa dan lintas kasus ditolak. Membaca assessment/review memverifikasi baseline dan record; ekspor memverifikasi seluruh run terkait. Ekspor security adalah JSON metadata/manifest, bukan paket bytes seluruh artefak.

Transisi manual: observation → candidate/dismissed; candidate → validated/dismissed; validated/dismissed → candidate untuk dibuka kembali. Reviewer, alasan dan konfirmasi pemeriksaan sumber wajib. Validasi/promosi membutuhkan evidence pendukung; dismissal membutuhkan evidence penyangkal dan alasan. `expectedRevision` mencegah keputusan berdasarkan revisi lama. Reviewer adalah identitas yang dinyatakan pengguna lokal, bukan autentikasi independen. Checkbox bukan bukti kriptografis bahwa seseorang membaca sumber.

Rencana manual tidak menjalankan langkahnya. Review bukti boleh memakai baseline; hasil `external-manual` dan `authorization-comparison` harus merujuk capture lain yang telah disegel dalam kasus sama. Perbandingan otorisasi membutuhkan objek, pemilik terdaftar, kebijakan yang diharapkan, 2–5 identitas unik/role, expected/actual access dan bukti per identitas, serta interpretasi selain HTTP. Klaim otorisasi validated memerlukan hasil perbandingan completed. Tidak ada rule yang menyimpulkan IDOR hanya dari perbedaan status/isi respons. Semantik kebijakan dan kecukupan bukti tetap keputusan analis.

## Rule tersedia dan rujukan primer

Rujukan dibaca pada pengembangan tahap ini; tautan juga tersedia pada katalog di UI. Ini cakupan tujuh pemeriksaan, bukan klaim seluruh CWE/OWASP diuji.

| ID v1.0.0        | Pemeriksaan / batas                                                                                                                                                                                                                                                                                                                                                         |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WI-HDR-001       | Header pada respons HTML sukses. Kekurangan CSP/framing/nosniff atau unsafe-url menghasilkan observation. Report-Only bukan enforcement; CSP framing menggantikan kebutuhan flag XFO absen. Ringkasan CSP bukan evaluator efektivitas policy; meta policy dan cascade tidak dievaluasi. Error/redirect/non-HTML bukan kandidat otomatis.                                    |
| WI-HSTS-001      | Positive max-age pada HTTPS hostname. HTTP, IP dan localhost dikecualikan; preload/inherited policy unknown. Duplikasi/metadata ambigu tidak dinilai. Header absen hanya observation.                                                                                                                                                                                       |
| WI-COOKIE-001    | Konsistensi Secure/SameSite=None/Partitioned/prefix. Konfigurasi tidak konsisten menjadi candidate risiko rendah; bisa ditolak browser, bukan bukti cookie diterima atau bocor. Deletion dilewati; duplikasi/partial/invalid attributes not-assessed. Nama menyerupai auth hanya heuristic observation; preference dan SameSite tidak ditentukan tidak otomatis bermasalah. |
| WI-MIXED-001     | Request HTTP subresource dari dokumen HTTPS dengan konteks frame/navigation tersedia. Respons teramati menghasilkan candidate; blocked/failed/no response hanya observation percobaan. Top-level navigation/loopback dikecualikan. Deklarasi HTML/CSS tanpa request tidak dinilai sebagai transfer.                                                                         |
| WI-URL-001       | Nama parameter query berpotensi sensitif, nilai sudah dihilangkan. Candidate confidence rendah; sensitivitas aktual perlu dibuktikan. Path tidak ditebak menjadi parameter; nama `code` umum tidak otomatis dianggap token. CWE-598 hanya bila nilai memang sensitif.                                                                                                       |
| WI-TRANSFER-001  | Nama field sensitif/Authorization presence pada HTTP non-loopback; respons teramati candidate, percobaan tanpa respons observation. HTTPS tidak diuji kualitas TLS-nya. Body unparsed/oversized/unsupported not-assessed. CWE-319 bersyarat.                                                                                                                                |
| WI-RECIPIENT-001 | Cross-origin dengan parameter/Authorization metadata. Kepemilikan domain dan persetujuan belum dibuktikan; origin bisa dideklarasikan first-party/approved oleh analis. Aset tanpa data terpilih tidak otomatis temuan. Unapproved sensitive-looking transfer candidate risiko rendah, yang lain observation. Tidak ada lookup registrable-domain/pemilik.                  |

Sumber semantik:

- [W3C CSP Level 3](https://www.w3.org/TR/CSP3/), [MDN X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options), [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options), [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).
- [MDN Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security), [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).
- [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1): sintaks max-age termasuk quoted value dan directive yang berulang; ringkasan collector tidak menilai policy HSTS browser secara menyeluruh.
- [W3C Mixed Content](https://www.w3.org/TR/mixed-content/), [W3C Secure Contexts: trustworthy origins](https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy).
- [MITRE CWE-598](https://cwe.mitre.org/data/definitions/598.html), [MITRE CWE-319](https://cwe.mitre.org/data/definitions/319.html), [OWASP Protect Data](https://devguide.owasp.org/en/04-design/02-web-app-checklist/08-protect-data/), [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
- [Playwright Request](https://playwright.dev/docs/api/class-request), [Playwright Response](https://playwright.dev/docs/api/class-response): batas `headers()`, API header terpilih, response header arrays, event request/response dan kegagalan.

## Menjalankan dan menggunakan

```sh
npm install
npm run browser:install
npm run build
npm start
```

Node 22.16+ seri 22 atau 24+; diuji Node 26.0.0, macOS, Playwright 1.63 dengan Chrome terpasang sebagai fallback. App lokal `http://127.0.0.1:8787`.

Pilih kasus → audit/capture → tutup dan simpan run → **Analisis bukti**. Pilih finding, buka request dan wiring. Pada evidence reader gunakan **pendukung**/**penyangkal**; untuk bukti tambahan pilih run capture/artefak dalam kasus sama, dengan JSON pointer opsional. Lengkapi review. Riwayat menyimpan keputusan sebelumnya. **Skenario validasi manual** menyimpan rencana, hasil atau pembatalan; buka capture baru bila melakukan aktivitas manual. Field JSON perbandingan identitas menyediakan struktur dan reference terpilih dapat dilihat di evidence reader. Jangan menempel password/token/nilai payload pada catatan.

Fixture manual opt-in dengan database terpisah:

```sh
ENABLE_SECURITY_FIXTURE=1 ENABLE_AUTH_FIXTURE=1 ENABLE_WIRING_FIXTURE=1 PORT=8791 DATA_DIR=/tmp/wi-stage4-manual npm start
```

Scope/URL `http://127.0.0.1:8791/security-fixture` dengan izin localhost. Halaman `/bad`, `/safe`, `/error`; contoh request asset/query dan Authorization sintetis. Gunakan `/auth-fixture/wiring` untuk halaman privat; login `/auth-fixture/login`, akun sintetis `fixture@example.test` / `fixture-password`, MFA `123456`. Fixture tidak aktif secara default. Izin localhost tidak memberikan akses seluruh jaringan privat.

## Verifikasi yang benar-benar dijalankan

| Pemeriksaan                    | Hasil                                                                                                                                                                                                                                                                                                            |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run check`                | Build Vite lulus; 34 test Node lulus, 0 gagal                                                                                                                                                                                                                                                                    |
| `npm run smoke:stage4`         | Lulus capture lokal bad/safe, metadata header/cookie/Authorization tanpa nilai, assessment, evidence reader, wiring/elemen/PNG, review menjadi validated, rencana manual/cancel, export dan tampilan desktop/mobile tanpa pageerror                                                                              |
| Counter HTTP fixture tahap 4   | Tidak bertambah saat analysis/review/manual record/export; hash/ID/bytes baseline tetap sama                                                                                                                                                                                                                     |
| Fixture login tahap 4          | Ditolak sebelum login; login+MFA lewat browser fixture lalu capture POST/query, finding terhubung ke graph privat; password/state autentikasi tidak ada pada ekspor                                                                                                                                              |
| `npm run smoke:stage3`         | Lulus responsive/lazy/CSS/SVG/font/data/blob, deklarasi tanpa request, correlated vs unknown, input/POST/SPA, login, pemilihan graph/aset/request/PNG, filter/pagination dan ekspor                                                                                                                              |
| Unit keamanan                  | Positif, safe/exception, missing/partial inputs untuk tujuh rule; redaksi; CSP report-only; HSTS ambigu; body tidak terurai; cookie preferensi/deletion; loopback; approved recipient; error bukan kerentanan; references valid; status/revision/history; isolasi kasus; legacy metadata; perbandingan identitas |
| Manipulasi                     | Byte terenkripsi dalam database fixture sengaja diubah setelah trigger fixture dilepas; assessment/review/export ditolak. Tidak mengubah bukti pengguna                                                                                                                                                          |
| Regresi tahap 1–2 (`npm test`) | Enkripsi/hash/immutability/legacy/recovery; URL/network guard; cookie login/MFA/POST/SPA/popup/scope redirect/expiry/isolasi/partial recovery lulus                                                                                                                                                              |

Transport HTTPS→HTTP dan domain publik dalam unit fixture adalah **metadata sintetis lokal, tidak di-fetch**. Tidak mengklaim telah menangkap mixed content jaringan publik nyata. UI smoke memblokir sumber eksternal kosmetik agar pengujian tidak tergantung Google Fonts. PNG hasil: `output/playwright/stage4-findings-{desktop,mobile}.png` (ignored Git), tampilan diperiksa. Tidak menguji Facebook atau layanan publik secara aktif.

Setelah restart lokal tanpa capture aktif, backend 1.4.0 terverifikasi. Empat run / 42 artefak yang sudah ada diverifikasi melalui API; ID dan hash sama dengan baseline sebelum restart. Sebelas file legacy tetap sama dengan hash baseline tahap 1. Playwright CLI membuka app utama dan hasil audit tersimpan tanpa menjalankan capture baru; console hanya mencatat favicon.ico 404 yang sudah ada.

## Batas dan tinjauan collector

- Pasif berarti **analisis** tanpa request tambahan; capture browser sendiri tetap menjalankan JavaScript situs. GET tidak menjamin tanpa efek samping, POST bukan selalu transaksi. Kebijakan crawl/sesi tahap 2 tetap berlaku.
- `validateDestination` tetap HTTP(S) tanpa credentials, resolusi seluruh alamat menolak privat/reserved, loopback hanya opt-in. Scope navigasi tetap berbeda dari dependensi. Response-stage redirect guard, pemeriksaan popup bootstrap, batas jumlah/waktu/bytes dan redaksi sebelumnya dipertahankan; tidak ada bypass baru untuk fixture. **DNS validation tidak mengikat koneksi socket browser**, sehingga bukan perlindungan SSRF/egress lengkap. WebRTC/kanal browser lain bukan sandbox jaringan terverifikasi.
- Metadata response: maksimal 200 fields yang diperiksa, 16.384 karakter per value terpilih, 40 instruksi cookie, 10 policy/64 directive CSP; cookie maksimal 32 attributes. Partial/ambiguity tidak menjadi bukti absence. Header values hanya sementara di memori untuk reduksi; tidak masuk artefak. Nama cookie/parameter yang diatur situs masih dapat mengandung teks sensitif.
- Maksimal 1.500 request diperiksa, 300 findings; counts/evaluations tetap menunjukkan hasil lain bila findings dipotong. Maksimal 30 assessment per baseline, 50 review per finding, 30 skenario/assessment dan 20 referensi per kelompok. Input API 16 KiB, catatan maksimal 3.000 karakter. Batas artefak/run tahap 1 tetap berlaku. Ekspor besar dapat memuat custody kasus berulang pada beberapa manifest.
- Capture-observations membekukan waktu pengamatan; metadata yang datang belakangan tidak memperbaiki artefak lama. Iframe, shadow DOM, service worker yang diblokir, cache, request sebelum start dan instrumentasi situs tetap memiliki gap tahap 3. Browser acceptance cookie, effective CSP/cascade, backend, response body, consent dan kepemilikan server tetap unknown.
- Tidak ada scanner aktif, fuzzing/brute force, exploit/replay otomatis, analisis menyeluruh OWASP, atau AI. Status validated adalah keputusan analis beserta bukti/alasannya, bukan jaminan mesin. Hash/custody lokal tidak menjamin autentisitas sumber, timestamp independen, atau kekebalan terhadap administrator host.
- Report lama tidak dimigrasikan untuk mengarang header/cookie yang dahulu tidak dikumpulkan. Capture baru diperlukan bila ingin mengamati metadata baru. Snapshot/URL path/DOM dan catatan analis tetap mungkin mengandung data pribadi.

## Menambah rule / tahap berikutnya

1. Tambah katalog `RULES`: ID stabil, versi, input yang betul-betul diperlukan, sumber primer dan status yang mungkin. Implementasi `evaluate()` harus murni tanpa network/browser/fs dan mengembalikan not-assessed untuk input kurang.
2. Nyatakan observasi, interpretasi, prasyarat, dampak kondisional, confidence, risk, rekomendasi dan keterbatasan. Jangan menghasilkan validated; jangan mengubah correlated menjadi sebab tanpa bukti. Jangan menambah kategori CWE demi kelengkapan semu.
3. Bila perlu metadata baru, tentukan schema/version/allowlist/redaksi/batas dan gating collector terlebih dahulu. Jangan memperluas koleksi payload atau autentikasi diam-diam. Tambah fixture positif, pengecualian, incomplete dan reference test.
4. Jalankan `npm run check`, `npm run smoke:stage4`, dan regresi capture/graph yang terdampak. Naikkan versi rule saat semantik berubah; assessment lama tetap immutable.

Pekerjaan lanjutan yang belum diimplementasikan: isolasi egress/socket yang lebih kuat, effective policy evaluator, kepemilikan/consent yang didukung bukti tambahan, comparison UI lebih terstruktur daripada JSON, serta alat validasi aktif khusus fixture bila kelak diminta secara eksplisit. Berhenti pada tahap 4.
