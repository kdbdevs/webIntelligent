import { useEffect, useState } from 'react';

const lines = (text) =>
  text
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
export function AuthSession({ job, caseId, scope, disabled, pending, onOpen, onAction }) {
  const [timeoutMinutes, setTimeout] = useState(15),
    [observeLogin, setObserveLogin] = useState(false);
  const [origins, setOrigins] = useState(''),
    [loginUrl, setLoginUrl] = useState('');
  const [targets, setTargets] = useState(''),
    [endpoints, setEndpoints] = useState('');
  const [reload, setReload] = useState(false),
    [approved, setApproved] = useState(false);
  const live = job?.session,
    session = live || job?.sessionInfo;
  useEffect(() => {
    setTargets('');
    setEndpoints('');
    setApproved(false);
    setReload(false);
  }, [job?.id]);
  const blocked = pending || live?.status === 'opening' || live?.status === 'capturing';
  const capture = (kind) =>
    onAction('capture', {
      kind,
      reload,
      urls: lines(targets),
      readEndpoints: lines(endpoints).map((line) => {
        const [url, operationName] = line.split(/\s+/);
        return { method: 'POST', url, ...(operationName ? { operationName } : {}) };
      }),
    });
  return (
    <section className="auth-panel" aria-label="Audit dengan login">
      <div className="auth-heading">
        <div>
          <span className="eyebrow">AUTHENTICATED WORKSPACE</span>
          <h3>Audit dengan login</h3>
        </div>
        {session && (
          <span className={`auth-status ${live?.collecting ? 'observing' : ''}`}>
            {session.status}
          </span>
        )}
      </div>
      {!live && (
        <details className="auth-setup" open={!session}>
          <summary>Buka sesi browser baru</summary>
          <p>
            Pilih kasus dan isi URL di atas. Login/MFA dilakukan sendiri di browser audit. Tidak ada
            profil harian atau sesi tersimpan yang diambil.
          </p>
          <div className="auth-grid">
            <label>
              Timeout sesi (menit)
              <input
                aria-label="Timeout sesi (menit)"
                type="number"
                min="1"
                max="120"
                value={timeoutMinutes}
                onChange={(e) => setTimeout(Number(e.target.value))}
                disabled={disabled}
              />
            </label>
            <label>
              URL login sebagai indikator (opsional)
              <input
                aria-label="URL login sebagai indikator"
                value={loginUrl}
                onChange={(e) => setLoginUrl(e.target.value)}
                placeholder="https://example.com/login"
                disabled={disabled}
              />
            </label>
            <label className="auth-wide">
              Origin login tambahan (opsional, satu per baris)
              <textarea
                aria-label="Origin login tambahan"
                value={origins}
                onChange={(e) => setOrigins(e.target.value)}
                placeholder="https://accounts.example.com"
                disabled={disabled}
              />
            </label>
          </div>
          <p className="auth-note">
            Origin URL awal dan origin tambahan hanya mengizinkan navigasi login manual. Scope
            capture/crawl tetap scope kasus; domain aset tidak memperluasnya.
          </p>
          <label className="auth-check">
            <input
              type="checkbox"
              checked={observeLogin}
              onChange={(e) => setObserveLogin(e.target.checked)}
              disabled={disabled}
            />
            Opt-in: amati metadata request/event selama login (tanpa nilai input/cookie/token atau
            screenshot otomatis).
          </label>
          <p className="auth-note">
            Saat koleksi aktif, metadata mencakup ringkasan header keamanan, atribut Set-Cookie,
            dan keberadaan Authorization. Nilai cookie/token serta state autentikasi tidak disimpan.
          </p>
          <button
            className="button secondary"
            disabled={disabled || !caseId}
            onClick={() =>
              onOpen({
                timeoutMinutes,
                observeLogin,
                loginOrigins: lines(origins),
                loginUrl: loginUrl || null,
              })
            }
          >
            Buka browser audit
          </button>
          {!caseId && (
            <p className="auth-note">Buat atau pilih kasus terlebih dahulu untuk sesi login.</p>
          )}
        </details>
      )}
      {live && (
        <>
          <p>
            {live.collecting
              ? 'Koleksi metadata request/event aktif pada tab terpilih. Snapshot hanya dibuat saat diperintahkan.'
              : 'Koleksi isi halaman dijeda. Login/MFA dan pemeriksaan browser dilakukan pengguna.'}
          </p>
          <p className="auth-note">
            {live.observeLogin && !live.readiness
              ? 'Opt-in observasi login: metadata pada scope/origin login ikut tercatat.'
              : 'Default: DOM, screenshot, event, dan request mulai dikumpulkan saat Mulai capture.'}{' '}
            Screenshot memuat isi halaman yang terlihat, termasuk data pribadi. Sesi autentikasi
            hanya ada di memori untuk run ini.
          </p>
          <div
            className={`auth-time ${live.timeoutWarning ? 'warning' : ''}`}
            role={live.timeoutWarning ? 'alert' : undefined}
          >
            Sisa waktu: {Math.floor(live.remainingSeconds / 60)}m {live.remainingSeconds % 60}s ·
            batas absolut {live.timeoutMinutes} menit, dapat diperpanjang.
            <button
              className="button secondary small-button"
              onClick={() => onAction('extend')}
              disabled={pending}
            >
              Perpanjang sesi
            </button>
          </div>
          <label className="auth-tab">
            Tab browser audit
            <select
              aria-label="Tab browser audit"
              value={live.selectedTabId || ''}
              disabled={blocked}
              onChange={(e) => onAction('select', { tabId: e.target.value })}
            >
              <option value="" disabled>
                Pilih tab
              </option>
              {live.tabs.map((tab) => (
                <option key={tab.id} value={tab.id}>
                  {tab.url} {tab.inScope ? '· dalam scope' : '· di luar scope'}
                </option>
              ))}
            </select>
          </label>
          <p className="auth-note">
            Scope navigasi: {scope?.join(', ')}. Pilih tab hasil popup setelah login. Navigasi SPA
            pada tab yang sama tetap didukung.
          </p>
          <div className="auth-actions">
            <button
              className="button secondary"
              disabled={blocked || !live.selectedTabId}
              onClick={() => onAction('ready')}
            >
              Halaman siap
            </button>
            <button
              className="button secondary"
              disabled={blocked || !live.collecting}
              onClick={() => onAction('pause')}
            >
              Jeda koleksi
            </button>
            <button
              className="button secondary"
              disabled={blocked}
              onClick={() => onAction('auth-lost')}
            >
              Login tidak berlaku
            </button>
            <button className="button secondary" onClick={() => onAction('close')}>
              Tutup & simpan run
            </button>
          </div>
          <p className="auth-note">
            {live.readiness
              ? `Dinyatakan siap oleh pengguna pada ${new Date(live.readiness.at).toLocaleTimeString()}. Ini bukan hasil deteksi autentikasi.`
              : 'HTTP 200 bukan bukti autentikasi. Periksa halaman di browser lalu tandai siap.'}
          </p>
          {live.authSignal && (
            <p role="status" className="auth-signal">
              Indikator akses: {live.authSignal.detail}
            </p>
          )}
          <label className="auth-check">
            <input
              type="checkbox"
              checked={reload}
              onChange={(e) => setReload(e.target.checked)}
              disabled={blocked}
            />
            Muat ulang tab saat capture untuk merekam request pemuatan. Dapat mengulang request/efek
            samping halaman.
          </label>
          <button
            className="button primary"
            disabled={blocked || !live.readiness}
            onClick={() => capture('snapshot')}
          >
            Mulai capture snapshot
          </button>
          <details className="auth-crawl">
            <summary>Crawl halaman pilihan dalam sesi ini</summary>
            <p>
              Crawler memotret tab terpilih lalu mengunjungi daftar URL ini memakai context login
              yang sama. Tidak mengeklik tombol, submit form, atau mengikuti semua link otomatis.
              Hindari interaksi manual selama crawl karena kebijakan crawl berlaku pada context ini.
            </p>
            <div className="auth-grid">
              <label>
                URL tambahan (satu per baris, maks. {Math.max(0, job.maxPages - 1)})
                <textarea
                  aria-label="URL crawl pilihan"
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  disabled={blocked}
                />
              </label>
              <label>
                POST baca yang diizinkan (opsional)
                <textarea
                  aria-label="Endpoint POST baca"
                  value={endpoints}
                  onChange={(e) => setEndpoints(e.target.value)}
                  placeholder={
                    'https://example.com/api/profile\nhttps://example.com/graphql ProfileRead'
                  }
                  disabled={blocked}
                />
              </label>
            </div>
            <p className="auth-note">
              Format izin: URL tanpa query, opsional nama operasi. GraphQL wajib operationName. POST
              lain dan URL aksi yang dikenali diblokir saat crawl; halaman bisa tidak lengkap. GET
              dan deklarasi endpoint baca tidak menjamin bebas efek samping.
            </p>
            <label className="auth-check">
              <input
                type="checkbox"
                checked={approved}
                onChange={(e) => setApproved(e.target.checked)}
                disabled={blocked}
              />
              Saya memilih URL untuk dilihat dan menyatakan endpoint POST di atas hanya membaca
              data.
            </label>
            <button
              className="button primary"
              disabled={blocked || !live.readiness || !approved}
              onClick={() => capture('crawl')}
            >
              Mulai crawl pilihan
            </button>
          </details>
        </>
      )}
      {session && (
        <details className="auth-log">
          <summary>Riwayat sesi & kebijakan</summary>
          <p>{session.policy?.manual}</p>
          <p>{session.policy?.crawl}</p>
          <p>{session.policy?.limitation}</p>
          {!live && (
            <p>
              Sesi {session.status};{' '}
              {session.reason || 'browser ditutup dan state autentikasi dibuang.'}
            </p>
          )}
          <p>
            Deteksi kehilangan akses terbatas pada laporan pengguna, URL login terkonfigurasi, dan
            HTTP 401 yang relevan. Tidak mendeteksi semua bentuk logout/expiry.
          </p>
          <ul>
            {session.history?.slice(-20).map((item, i) => (
              <li key={i}>
                {item.url} · {item.outcome}
                {item.reason ? ` · ${item.reason}` : ''}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
