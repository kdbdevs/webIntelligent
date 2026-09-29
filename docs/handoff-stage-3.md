# Handoff tahap 3 — evidence wiring

Selesai pada 30 September 2026, collector/app **1.3.0**. Project tetap React + React Flow, Express, Playwright, Vite dan SQLite bawaan Node. Tidak ada dependency npm, database, atau migrasi baru. Tidak menambahkan scanner/AI, deploy, commit, atau push.

## Kondisi awal dan perubahan yang dipertahankan

- AGENTS.md tidak ditemukan pada project maupun ancestor yang berlaku. README, package, implementasi dan handoff 1–2 diperiksa.
- Fondasi kasus/run/artefak/enkripsi/hash/custody tahap 1 dan session manager tahap 2 tersedia. Tahap 2 berada sebagai perubahan belum di-commit pada `codex/stage-2`; pekerjaan ini dilanjutkan di `codex/stage-3` dengan perubahan tersebut tetap ada.
- Checkpoint sumber pra-tahap-3 disimpan di `/var/folders/ny/zqrxs53x32z8wq5g8z6ql6j40000gn/T/wi-pre-stage3-d7g53yh4` (bukan backup database/kunci). Modul session manager, policy, redirect guard, AuthSession, test sesi/UIS tahap 2, dan handoff tahap 2 tetap identik dengan checkpoint. UI tidak dibangun ulang.

## Implementasi

- `server/browser-scripts.mjs`: identitas dokumen/DOM node, registrasi listener, event target, metadata batch perubahan DOM, pushState/replaceState/popstate/hashchange. Tidak mengirim nilai input, isi perubahan teks/atribut, fungsi handler, atau state history. Form sekarang juga elemen yang dapat dipilih; labelnya nama/ID, bukan gabungan seluruh teks field.
- `server/visual-scripts.mjs`: ekstraksi main-frame untuk img/picture/srcset/currentSrc, dimensi dan lazy loading; computed CSS background/pseudo, posisi/ukuran sprite; kandidat aturan CSSOM dan alasan akses ditolak; metadata SVG/use, font-face/ikon, favicon, stylesheet, script; resource timing dan batas cakupan.
- `server/wiring.mjs`: sanitasi sumber dan identitas URL opak per run; model graph dan inventaris dengan referensi artefak. URL query berbeda yang tampil sama setelah redaksi tidak digabung. Data/blob tidak dijadikan request; pembuat blob dan lokasi penyimpanan server unknown.
- `server/audit.mjs`: metadata frame/epoch, query/JSON/form parameter location/type, status/content type/timing, redirectedFrom, fetch/XHR instrumentation ketika tersedia. Snapshot menyimpan empat jenis artefak di bawah. Context login dan gating tahap 2 tetap dipakai. Screenshot memakai koordinat dokumen, clip maksimal 4.000 px, scale CSS dan dimensi PNG aktual untuk penanda.
- `src/WiringExplorer.jsx`: tab **Wiring & aset**, pilihan elemen, inventaris/filter/pencarian, pagination 40 aset, graph lingkungan pilihan hingga 80 node, inspector node/edge, tautan sumber bukti, request terkait, preview potongan PNG dan penanda screenshot. Node unknown tidak memperluas pilihan ke seluruh request. Halaman audit memilih capture yang dimuat; tidak perlu memuat seluruh graph run sekaligus.
- `src/App.jsx`: tabs/graph navigasi dan alur data lama dipertahankan; referensi bukti ditambahkan bila tersedia. Ringkasan graph capture baru membaca request dari artefak observasi terverifikasi yang dibekukan, sehingga traffic sesudah capture tidak keliru dirujuk ke bukti sebelumnya. Hubungan heuristic/unknown tidak ditampilkan sebagai kepastian alur eksekusi. Nomor penanda memakai ordinal tampilan, terpisah dari ID bukti.
- `server/evidence.mjs`: manifest menambahkan capture/wiring, cakupan visual, batas/gap dan tindakan collector. API artefak/ekspor tetap memeriksa hash, batas case/run, enkripsi dan riwayat append-only.

## Struktur data

Tidak mengubah skema SQLite. Tambahan opsional pada laporan JSON lama tetap kompatibel:

| Data        | Struktur penting                                                                                                                                                  |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Snapshot    | `captureId`, `documentId`, `frameId`, `documentEpoch`, `capturedAt`, `visuals`, `wiring`                                                                          |
| Elemen      | `id = captureId:el:domNodeId`, ordinal UI, selector, tag/name, halaman/frame/dokumen, waktu observasi, bounds, registrasi listener/form                           |
| Request     | identitas source/frame/epoch, `parameters[]` nama/tipe/lokasi/nilai omitted, `pathParameters.status=unknown`, timing browser, fromServiceWorker, redirectedFromId |
| Sumber aset | kind network/data/blob/inline/unknown, identitas opak, URL tersensor/domain bila relevan, requestKey hanya bila URL jaringan lengkap tersedia                     |
| Node/edge   | ID per capture, tipe, `relation`, `reason`, `limitation`, `evidence[]` berisi caseId/runId/captureId/artifactId/JSON pointer                                      |
| Inventaris  | sumber, tipe, halaman, deklarasi/pemakaian, state load, request IDs, resource timing terpisah                                                                     |

Artefak per capture:

1. `screenshot`: akuisisi PNG asli atau redacted-at-acquisition untuk sesi authenticated sesuai tahap 2. Tidak menyimpan versi tanpa masking password/OTP.
2. `page-extraction`: DOM/visual metadata tersanitasi. Berperan extracted, bukan raw network evidence.
3. `capture-observations`: event, perubahan dan request yang dibekukan untuk dokumen/frame/epoch capture. Nilai query/body, cookies/auth headers/storage state tidak disimpan.
4. `wiring-graph`: turunan eksplisit `page-extraction` dan `capture-observations`. `snapshot.wiring.artifactId` menunjuk artefaknya. Semua graph sebelumnya tetap tersimpan meskipun daftar halaman menampilkan capture terbaru.

Sumber aset tidak diunduh ulang atau diarsipkan sebagai bytes. Preview bukan artefak gambar aset mandiri: ia potongan tampilan screenshot yang terverifikasi. Screenshot dan DOM adalah akuisisi saudara yang berurutan, bukan klaim bahwa DOM diekstrak dari gambar. Rahasia HMAC untuk identitas URL hanya berada di memori selama run, tidak menjadi bagian laporan. Tidak ada perubahan pada kunci enkripsi bukti.

## Alur penggunaan

```sh
npm install
npm run browser:install
npm run build
npm start
```

Node 22.16+ pada seri 22 atau 24+; diuji Node 26.0.0, macOS, Playwright 1.63.0 dengan Chrome terpasang. Fallback Chrome yang sudah tersedia tetap berfungsi. App lokal berjalan di `http://127.0.0.1:8787` dengan versi 1.3.0 setelah restart aman tanpa run aktif.

Pilih kasus → URL → audit publik, atau browser audit → login/MFA sendiri → nyatakan siap → mulai capture. Untuk merekam interaksi, lakukan aktivitas setelah koleksi aktif lalu capture kembali. Pada **Wiring & aset**, pilih halaman/elemen, filter aset, klik aset, lalu klik request atau garis graph untuk bukti dan alasan. Tutup sesi sebelum ekspor manifest. Run lama tanpa graph tahap 3 tetap dapat dibuka dan menampilkan petunjuk melakukan capture baru.

Fixture manual (data sintetis, gunakan direktori terpisah):

```sh
ENABLE_AUTH_FIXTURE=1 ENABLE_WIRING_FIXTURE=1 PORT=8788 DATA_DIR=/tmp/wi-wiring-fixture npm start
```

URL publik `/wiring-fixture`; privat `/auth-fixture/wiring`. Gunakan origin lengkap dalam URL/scope, izinkan localhost. Login `/auth-fixture/login`: `fixture@example.test` / `fixture-password`, MFA `123456`. Route privat menolak tanpa cookie; jangan memakai akun Facebook. Fixture default nonaktif. Font `tests/fixtures/icon.ttf` adalah glyph geometris sintetis; Python/FontTools hanya alat regenerasi opsional, bukan dependency runtime/test.

## Verifikasi yang dijalankan

| Perintah / pemeriksaan                               | Hasil                                                                                                                                                                                       |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run check`                                      | Build Vite lulus; 26 test Node lulus, 0 gagal                                                                                                                                               |
| `npm run smoke:stage3`                               | Lulus fixture publik + halaman cookie-protected setelah login/MFA browser, graph dan UI                                                                                                     |
| `npm run smoke:stage2`                               | Lulus alur UI kasus → browser → login/MFA → readiness → snapshot → popup → same-context crawl → artefak/hash/manifest                                                                       |
| `APP_URL=http://127.0.0.1:8788 npm run smoke`        | Lulus audit demo 4 halaman, screenshot/listener/form, POST JSON/navigasi tersensor, graph/data/network UI desktop/mobile                                                                    |
| `APP_URL=http://127.0.0.1:8788 npm run smoke:stage1` | Lulus case UI, isolasi dua kasus, traversal/Origin/immutable API, hash independen, custody dan ekspor                                                                                       |
| Integritas data yang telah ada                       | 3 run / 24 artefak diverifikasi setelah restart; ID/hash tidak berubah. 11 file legacy dibandingkan baseline tahap 1: tidak berubah                                                         |
| Pemeriksaan tampilan                                 | PNG desktop/mobile fixture diperiksa; app utama versi 1.3 terbuka melalui Playwright CLI. Tidak ada pageerror React pada smoke UI; CLI awal hanya melaporkan favicon.ico 404 yang sudah ada |

Smoke tahap 3 membuktikan: currentSrc sesuai request aktual; kandidat picture dan lazy yang belum dimuat tidak memiliki request (diperiksa juga melalui hit counter server); CSS/pseudo/sprite dan rule stylesheet; SVG inline/external/use; font benar-benar dilayani; data/blob tanpa request; source terlalu besar ditandai omitted; CSS lintas origin unknown; query tersensor berbeda tidak digabung; request JSON dan form body, redirect object reference dan path numerik tetap unknown; DOM/SPA; relasi gambar dekat klik tetap correlated; ID berbeda antar-capture, artefak sebelumnya tidak berubah; semua pointer graph dapat di-resolve dan endpoint edge valid; nilai rahasia tidak ada dalam metadata; UI elemen → aset → request, penanda PNG, pencarian/filter dan pagination lebih dari 40 aset; preview tidak mengirim request ulang ke sumber aset.

Tes manipulasi/korupsi bukti dan isolasi memakai database fixture sementara. Tidak memodifikasi bytes bukti pengguna untuk pengujian. Output visual lokal: `output/playwright/stage3-wiring-desktop.png` dan `stage3-wiring-mobile.png`, diabaikan Git.

## Batas dukungan

- Registrasi handler bukan trace eksekusi. Event→request dan kesamaan nama parameter tetap correlated; event→kemungkinan handler diberi unknown bila eksekusinya tidak teramati. Backend, state framework, parser/controller/database tetap unknown.
- URL sumber yang cocok dengan request dalam frame/epoch sama bukan bukti bahwa elemen tertentu menyebabkan request tersebut. Resource Timing tidak diubah menjadi request Playwright. `-1` timing berarti tidak tersedia; cache tidak ditebak dari transferSize nol.
- Main frame saja. Iframe dihitung, shadow root tidak ditelusuri; hanya open host yang terlihat bisa dihitung. Service worker tetap diblokir. Request sebelum koleksi atau sebelum hook terpasang bisa hilang. Cookie/login dari browser harian tidak dibaca.
- Matching CSS adalah kandidat aturan, bukan rekonstruksi cascade/media/variable/source map yang lengkap. Parser CSS URL/srcset terbatas; adopted stylesheets, canvas, font glyph fallback aktual, dan blob creation tracing belum tersedia. Inline SVG hanya metadata, bukan markup aktif.
- Batas visual: 4.000 DOM element diperiksa, 300 pemilik visual, 1.200 usages, 80 stylesheet/2.000 rules/depth 8; 1.000 Resource Timing entries yang masih tersedia. URL sumber lebih dari 8.192 karakter dan nilai CSS lebih dari 64.000 karakter dihilangkan, dengan gap dan tanpa pencocokan request. Maks. 300 batch DOM/SPA per run, 20 target per batch. Batas request/event/artefak/ukuran/waktu tahap 1–2 tetap berlaku; empat artefak per snapshot dapat mencapai batas run sebelum 100 operasi sesi.
- DOM dan screenshot berurutan; perubahan layout/animasi/scroll/fixed positioning dapat memengaruhi ketepatan penanda. Screenshot 4.000 px tidak mencakup seluruh halaman panjang dan dapat memuat data pribadi. Tidak memaksa scroll untuk memuat lazy asset.
- Hash dan custody lokal membuktikan baseline lokal, bukan autentisitas sumber/waktu atau ketahanan terhadap administrator host; situs juga dapat mengganggu hook instrumentasi. Tidak ada sandbox egress/socket pinning. Tidak memperluas izin jaringan privat; localhost opt-in tetap loopback saja.
- Tidak diuji pada Facebook atau akun/situs pihak ketiga. Tidak mengklaim dukungan universal terhadap SSO/anti-bot atau aplikasi/framework tertentu.

## Pekerjaan setelah tahap ini

Hanya untuk perencanaan lanjutan: strategi isolasi egress yang lebih kuat; akuisisi iframe/shadow yang terkontrol; sumber/cascade CSS dan font/blob tracing yang lebih kuat; arsip bytes aset opt-in dengan redaksi/enkripsi/preview inert; korelasi tambahan dari source map atau instrumentasi server dengan label bukti yang tepat; eksplorasi lintas capture tanpa menghilangkan identitas dokumen. Jangan menganggap catatan ini sebagai scanner/AI yang sudah diimplementasikan.
