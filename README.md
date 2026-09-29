# Web Intelligent

App lokal untuk memetakan website dari URL: screenshot dengan penanda elemen, wiring navigasi, alur data, dan inspector network. Frontend **React 19 + React Flow**, backend **Node.js + Express + Playwright**.

## Jalankan

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

Port berbeda: `PORT=8788 npm start`. Data audit disimpan dalam `.data/`; atur `DATA_DIR` untuk lokasi lain. `BROWSER_CHANNEL=chrome` memilih Chrome secara eksplisit.

## Pakai app

1. Isi URL, pilih batas 1–10 halaman, lalu **Audit website**. URL tanpa scheme memakai HTTPS.
2. **Elemen** menampilkan screenshot asli dengan penanda, selector, field name, form induk, deklarasi method/action/enctype, dan listener langsung yang terdeteksi.
3. **Alur halaman** menampilkan hubungan `href` melalui React Flow. Node bisa digeser; canvas bisa di-pan/zoom. URL yang belum dipindai dibedakan dari halaman yang sudah dipindai.
4. **Alur data** memetakan elemen, event, parameter, method/endpoint, penerima server, dan respons. Setiap node diberi label **Teramati**, **Deklarasi HTML**, atau **Belum diketahui**.
5. **Network** memperlihatkan method, endpoint, HTTP status, content type, nama/tipe body parameters, query parameter names, dan initiator stack apabila tersedia.
6. **Rekam interaksi** membuka browser baru di komputer ini. Lakukan interaksi sendiri di browser tersebut untuk merekam request sebenarnya. Klik refresh di toolbar untuk snapshot terbaru, lalu **Selesai** untuk menutup sesi. Sesi otomatis berakhir setelah 10 menit.
7. **JSON** mengunduh laporan. Riwayat audit tersimpan lokal dan tetap tersedia setelah restart.

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
- Data lama tidak dihapus otomatis. `.data/` dapat membesar setelah banyak screenshot. Restore riwayat dibatasi 50 folder audit.

## Struktur

```text
src/App.jsx                 UI, inspector, React Flow
src/styles.css              Layout responsive
server/index.mjs            Local API + static frontend
server/audit.mjs            Crawl, screenshot, recording, persistence
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
