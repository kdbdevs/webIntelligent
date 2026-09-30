import { useEffect, useState } from 'react';
import { BookOpen, ShieldCheck, FlaskConical, MousePointer2, Layers3, Network } from 'lucide-react';

export const WORKSPACES = [
  {
    id: 'learn',
    href: '#/belajar-web',
    title: 'Belajar Web',
    short: 'Pahami cara website bekerja',
    eyebrow: 'DARI ELEMEN KE REQUEST',
    description: 'Jelajahi elemen, navigasi, sumber aset, dan perjalanan data dari browser.',
    icon: BookOpen,
  },
  {
    id: 'cyber',
    href: '#/cybersecurity',
    title: 'Cybersecurity',
    short: 'Audit dan tinjau keamanan',
    eyebrow: 'AUDIT BERBASIS BUKTI',
    description:
      'Capture halaman, periksa kandidat masalah, lalu tinjau bukti sebelum memvalidasi temuan.',
    icon: ShieldCheck,
  },
  {
    id: 'lab',
    href: '#/lab-forensik',
    title: 'Lab Forensik',
    short: 'Seluruh alat investigasi',
    eyebrow: 'SATUKAN SUMBER DAN KRONOLOGI',
    description:
      'Gunakan seluruh fitur: audit web, keamanan, impor artefak, timeline, graph, dan laporan kasus.',
    icon: FlaskConical,
  },
];
const resolve = (hash) => WORKSPACES.find((w) => w.href === hash)?.id || 'learn';
const storageKey = 'wi.workspace';
function initialWorkspace() {
  if (location.hash) return resolve(location.hash);
  try {
    const saved = localStorage.getItem(storageKey);
    return WORKSPACES.some((w) => w.id === saved) ? saved : 'learn';
  } catch {
    return 'learn';
  }
}
export function useWorkspace() {
  const [workspace, setWorkspace] = useState(initialWorkspace);
  const [visited, setVisited] = useState(() => new Set([workspace]));
  useEffect(() => {
    // Canonicalize the initial menu so Back returns to a saved preference correctly.
    if (!WORKSPACES.some((w) => w.href === location.hash)) {
      history.replaceState(history.state, '', WORKSPACES.find((w) => w.id === workspace).href);
    }
    const changed = () => {
      const next = resolve(location.hash);
      setWorkspace(next);
      setVisited((old) => new Set([...old, next]));
    };
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, workspace);
    } catch {
      /* Navigation also works without browser storage. */
    }
  }, [workspace]);
  const choose = (id) => {
    const target = WORKSPACES.find((w) => w.id === id);
    if (!target) return;
    setWorkspace(id);
    setVisited((old) => new Set([...old, id]));
    if (location.hash !== target.href) location.hash = target.href;
  };
  return { workspace, choose, config: WORKSPACES.find((w) => w.id === workspace), visited };
}
export function WorkspaceMenu({ workspace, onSelect }) {
  return (
    <nav className="workspace-menu" aria-label="Menu utama">
      {WORKSPACES.map(({ id, href, title, short, icon: Icon }, i) => (
        <a
          key={id}
          href={href}
          className={`workspace-link ${workspace === id ? 'active' : ''}`}
          aria-current={workspace === id ? 'page' : undefined}
          aria-label={title}
          onClick={(e) => {
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            e.preventDefault();
            onSelect(id);
          }}
        >
          <Icon size={19} />
          <span>
            <strong>{title}</strong>
            <small>{short}</small>
          </span>
          <span className="keycap">0{i + 1}</span>
        </a>
      ))}
    </nav>
  );
}
const learningSteps = [
  {
    tab: 'elements',
    title: 'Kenali elemen',
    text: 'Pilih input, tombol, atau tautan di screenshot. Lihat selector dan deklarasinya.',
    icon: MousePointer2,
  },
  {
    tab: 'wiring',
    title: 'Telusuri sumber aset',
    text: 'Hubungkan gambar, ikon, dan CSS dengan sumber yang teramati.',
    icon: Layers3,
  },
  {
    tab: 'data',
    title: 'Ikuti perjalanan data',
    text: 'Lihat event, nama parameter, method, endpoint, dan respons yang tersedia.',
    icon: Network,
  },
];
export function WorkspaceGuide({ workspace, hasCapture, onExplore, onChoose }) {
  if (workspace === 'learn')
    return (
      <section className="workspace-guide learning-guide" aria-label="Panduan belajar web">
        <div className="guide-heading">
          <BookOpen size={19} />
          <div>
            <h2>Mulai dari yang terlihat, lalu ikuti koneksinya.</h2>
            <p>
              Masukkan URL atau coba demo lokal. Audit tetap disimpan dalam kasus yang bisa dibuka
              di menu lain.
            </p>
          </div>
        </div>
        <div className="learning-steps">
          {learningSteps.map(({ tab, title, text, icon: Icon }, i) => (
            <div key={tab}>
              <small>0{i + 1}</small>
              <Icon size={19} />
              <h3>{title}</h3>
              <p>{text}</p>
              <button
                className="button secondary small-button"
                disabled={!hasCapture}
                onClick={() => onExplore(tab)}
              >
                {title}
              </button>
            </div>
          ))}
        </div>
        <details className="learning-glossary">
          <summary>Kenali istilah: event, parameter, method, endpoint, dan respons</summary>
          <dl>
            <div>
              <dt>Event</dt>
              <dd>
                Interaksi seperti klik atau input. Kedekatan dengan request masih berupa korelasi.
              </dd>
            </div>
            <div>
              <dt>Parameter</dt>
              <dd>Nama dan tipe data pada query atau body request. Nilai sensitif disamarkan.</dd>
            </div>
            <div>
              <dt>Method & endpoint</dt>
              <dd>Cara request dikirim, misalnya POST, dan URL tujuannya.</dd>
            </div>
            <div>
              <dt>Respons</dt>
              <dd>
                Status dan metadata jawaban server yang tersedia. Kode backend dan database tetap
                unknown tanpa bukti.
              </dd>
            </div>
          </dl>
        </details>
        <p className="workspace-switch-note">
          Perlu login atau pemeriksaan keamanan?{' '}
          <button onClick={() => onChoose('cyber')}>Buka Cybersecurity</button>
        </p>
      </section>
    );
  const cyber = workspace === 'cyber';
  return (
    <section
      className="workspace-guide professional-guide"
      aria-label={cyber ? 'Alur cybersecurity' : 'Alur lab forensik'}
    >
      <div className="guide-heading">
        {cyber ? <ShieldCheck size={20} /> : <FlaskConical size={20} />}
        <div>
          <h2>
            {cyber ? 'Dari capture baseline ke review temuan.' : 'Seluruh fitur, dalam satu kasus.'}
          </h2>
          <p>
            {cyber
              ? 'Tetapkan scope → capture publik atau setelah login → pemeriksaan pasif → review manusia → laporan. Kandidat masalah belum berarti kerentanan tervalidasi.'
              : 'Capture web atau impor HAR, log, CSV, email, dan file → telusuri timeline dan graph → susun hipotesis → review laporan. Hash memeriksa baseline, bukan membuktikan autentisitas.'}
          </p>
        </div>
      </div>
      <div className="workspace-capabilities">
        {(cyber
          ? ['Audit & sesi login', 'Bukti & temuan', 'Perbandingan & laporan']
          : [
              'Semua fitur Belajar Web',
              'Semua fitur Cybersecurity',
              'Impor & analisis lintas artefak',
            ]
        ).map((label) => (
          <span key={label}>{label}</span>
        ))}
      </div>
      <p className="workspace-shared-note">
        Kasus dan hasil audit tetap sama saat berpindah menu.
        {cyber && (
          <>
            {' '}
            Impor dan analisis lintas sumber tersedia di{' '}
            <button onClick={() => onChoose('lab')}>Lab Forensik</button>.
          </>
        )}
      </p>
    </section>
  );
}
