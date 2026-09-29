import { useEffect, useState } from 'react';

export async function evidenceApi(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request gagal (${response.status})`);
  return data;
}
const fresh = () => ({
  title: '',
  objective: '',
  operator: 'Local operator',
  navigation: '',
  notes: '',
  status: 'open',
});

export function CaseManager({ cases, selectedId, onSelect, onSaved, disabled, onError }) {
  const [editing, setEditing] = useState(false),
    [draft, setDraft] = useState(fresh),
    [saving, setSaving] = useState(false);
  const selected = cases.find((c) => c.id === selectedId);
  const [editId, setEditId] = useState(null);
  const open = (record) => {
    setEditId(record?.id || null);
    setDraft(record ? { ...record, navigation: record.scope.navigation.join('\n') } : fresh());
    setEditing(true);
  };
  const submit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const saved = await evidenceApi(editId ? `/api/cases/${editId}` : '/api/cases', {
        method: editId ? 'PATCH' : 'POST',
        body: JSON.stringify({
          ...draft,
          navigation: draft.navigation
            .split(/[\n,]/)
            .map((x) => x.trim())
            .filter(Boolean),
        }),
      });
      await onSaved(saved);
      setEditing(false);
    } catch (error) {
      onError(error.message);
    } finally {
      setSaving(false);
    }
  };
  return (
    <section className="case-manager" aria-label="Pengelolaan kasus">
      <div className="case-heading">
        <label>
          Kasus aktif
          <select
            aria-label="Kasus aktif"
            value={selectedId || ''}
            onChange={(e) => {
              onSelect(e.target.value || null);
              setEditing(false);
            }}
            disabled={disabled || saving}
          >
            <option value="">Kasus baru otomatis untuk audit berikutnya</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.title} · {c.status === 'open' ? 'Terbuka' : 'Ditutup'}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button secondary small-button"
          disabled={disabled || saving}
          onClick={() => open(null)}
        >
          Buat kasus
        </button>
        {selected && (
          <button
            className="button secondary small-button"
            disabled={disabled || saving}
            onClick={() => open(selected)}
          >
            Edit kasus
          </button>
        )}
      </div>
      {selected && !editing && (
        <div className="case-summary">
          <p>
            <strong>{selected.objective || 'Tujuan belum diisi'}</strong>
          </p>
          <p>
            Operator: {selected.operator} · Scope navigasi: {selected.scope.navigation.join(', ')}
          </p>
          <p>Domain aset dicatat sebagai dependensi; tidak otomatis menjadi scope navigasi.</p>
          {selected.notes && <p>{selected.notes}</p>}
        </div>
      )}
      {editing && (
        <form className="case-form" onSubmit={submit}>
          <label>
            Judul kasus
            <input
              aria-label="Judul kasus"
              required
              maxLength={160}
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            />
          </label>
          <label>
            Operator
            <input
              aria-label="Operator kasus"
              required
              maxLength={160}
              value={draft.operator}
              onChange={(e) => setDraft({ ...draft, operator: e.target.value })}
            />
          </label>
          <label className="case-wide">
            Tujuan investigasi
            <textarea
              aria-label="Tujuan investigasi"
              maxLength={3000}
              value={draft.objective}
              onChange={(e) => setDraft({ ...draft, objective: e.target.value })}
            />
          </label>
          <label className="case-wide">
            Scope navigasi — domain/URL per baris
            <textarea
              aria-label="Scope navigasi"
              required
              value={draft.navigation}
              placeholder="https://example.com\nhttp://127.0.0.1:8787/demo"
              onChange={(e) => setDraft({ ...draft, navigation: e.target.value })}
            />
            <small>
              URL membatasi path beserta turunannya. Tanpa query/token. Izin localhost tetap perlu
              diaktifkan pada audit.
            </small>
          </label>
          <label className="case-wide">
            Catatan
            <textarea
              aria-label="Catatan kasus"
              maxLength={10000}
              value={draft.notes}
              onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
            />
          </label>
          {editId && (
            <label>
              Status
              <select
                aria-label="Status kasus"
                value={draft.status}
                onChange={(e) => setDraft({ ...draft, status: e.target.value })}
              >
                <option value="open">Terbuka</option>
                <option value="closed">Ditutup</option>
              </select>
            </label>
          )}
          <div className="case-wide case-form-actions">
            <button className="button primary small-button" disabled={saving}>
              {saving ? 'Menyimpan…' : 'Simpan kasus'}
            </button>
            <button
              type="button"
              className="button secondary small-button"
              onClick={() => setEditing(false)}
            >
              Batal
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

export function EvidencePanel({ job, onError }) {
  const [open, setOpen] = useState(false),
    [data, setData] = useState(null),
    [verification, setVerification] = useState(null),
    [selected, setSelected] = useState(null),
    [preview, setPreview] = useState(null),
    [busy, setBusy] = useState(false);
  const base = `/api/cases/${job.caseId}/runs/${job.id}`;
  useEffect(() => {
    setData(null);
    setSelected(null);
    setPreview(null);
    setVerification(null);
  }, [job.id]);
  useEffect(() => {
    if (!open || !job.caseId) return;
    let stopped = false;
    evidenceApi(base)
      .then((result) => {
        if (!stopped) setData(result);
      })
      .catch((e) => {
        if (!stopped) onError(e.message);
      });
    return () => {
      stopped = true;
    };
  }, [open, job.id, job.status, job.pages.length, !!job.session]);
  if (!job.caseId) return null;
  const act = async (fn) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      onError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const inspect = (a) =>
    act(async () => {
      setSelected(null);
      setPreview(null);
      const checked = await evidenceApi(`${base}/artifacts/${a.id}`);
      setSelected(checked.artifact);
      if (a.mimeType === 'application/json') {
        const content = await evidenceApi(`${base}/artifacts/${a.id}/content`);
        setPreview(JSON.stringify(content, null, 2).slice(0, 30000));
      }
      setData(await evidenceApi(base));
    });
  return (
    <section className="evidence-panel" aria-label="Bukti dan manifest">
      <div className="evidence-heading">
        <button
          className="button secondary small-button"
          onClick={() => setOpen(!open)}
          aria-expanded={open}
        >
          {open ? 'Tutup bukti' : 'Bukti & manifest'}
        </button>
        <span>
          Run {job.id.slice(0, 8)} · {job.mode || 'passive'} {job.legacy ? '· Legacy/imported' : ''}
        </span>
      </div>
      {open && data && (
        <>
          <div className="evidence-intro">
            <strong>
              {data.run.status === 'running'
                ? 'Capture berjalan'
                : data.run.status === 'partial'
                  ? 'Capture parsial'
                  : 'Capture disegel'}
            </strong>
            <p>
              {data.run.partialReason ||
                'Setiap artefak memiliki baseline SHA-256 saat dikumpulkan atau diimpor.'}
            </p>
            <p>
              {data.artifacts.length} artefak · {data.observations.length} observasi · operator{' '}
              {data.run.operator}
            </p>
            <p>
              Hash memeriksa baseline lokal. Tidak membuktikan kebenaran sumber atau waktu asal.
              Screenshot/teks terlihat dapat memuat data pribadi.
            </p>
          </div>
          <div className="evidence-actions">
            <button
              className="button secondary small-button"
              disabled={busy}
              onClick={() =>
                act(async () => {
                  setVerification(await evidenceApi(`${base}/verify`, { method: 'POST' }));
                  setData(await evidenceApi(base));
                })
              }
            >
              Verifikasi integritas
            </button>
            {data.run.status !== 'running' && (
              <button
                className="button secondary small-button"
                disabled={busy}
                onClick={() =>
                  act(async () => {
                    const manifest = await evidenceApi(`${base}/manifest`);
                    const url = URL.createObjectURL(
                      new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' }),
                    );
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `manifest-${job.id}.json`;
                    a.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                    setData(await evidenceApi(base));
                  })
                }
              >
                Ekspor manifest
              </button>
            )}
            <button
              className="button secondary small-button"
              disabled={busy}
              onClick={() => act(async () => setData(await evidenceApi(base)))}
            >
              Refresh bukti
            </button>
          </div>
          {verification && (
            <p role="status" className={`integrity-result ${verification.ok ? 'good' : 'bad'}`}>
              {verification.ok ? 'Integritas terverifikasi' : 'Verifikasi gagal — periksa artefak'}{' '}
              · {verification.artifacts.length} artefak · rantai catatan{' '}
              {verification.custodyOk ? 'valid' : 'gagal'}
            </p>
          )}
          <div className="evidence-grid">
            <div className="artifact-list" aria-label="Daftar artefak">
              {data.artifacts.map((a) => (
                <button
                  key={a.id}
                  className={selected?.id === a.id ? 'selected' : ''}
                  disabled={busy}
                  onClick={() => inspect(a)}
                >
                  <strong>{a.label}</strong>
                  <span>
                    {a.role} · {(a.size / 1024).toFixed(1)} KB
                  </span>
                  <code>{a.sha256.slice(0, 20)}…</code>
                </button>
              ))}
            </div>
            <div className="artifact-inspector">
              {selected ? (
                <>
                  <strong>{selected.label}</strong>
                  <dl>
                    {[
                      ['ID', selected.id],
                      ['Sumber', selected.source],
                      ['Peran', selected.role],
                      [
                        'Waktu pengumpulan',
                        `${selected.collected.at} · ${selected.collected.timezone}`,
                      ],
                      ['Waktu asal (klaim)', selected.claimedSourceTime || 'Tidak dinyatakan'],
                      ['Metode', selected.method],
                      ['Collector', `${selected.collector.name} ${selected.collector.version}`],
                      ['MIME', selected.mimeType],
                      ['Ukuran', `${selected.size} byte`],
                      ['SHA-256', selected.sha256],
                      [
                        'Turunan dari',
                        selected.derivedFrom.join(', ') || 'Tidak ada artefak induk tersimpan',
                      ],
                      ['Baseline', selected.baseline],
                    ].map(([label, value]) => (
                      <div key={label}>
                        <dt>{label}</dt>
                        <dd>{value}</dd>
                      </div>
                    ))}
                  </dl>
                  {selected.mimeType === 'image/png' && (
                    <img
                      alt="Preview artefak screenshot terverifikasi"
                      src={`${base}/artifacts/${selected.id}/content`}
                    />
                  )}{' '}
                  {preview && (
                    <details>
                      <summary>Konten JSON (preview maks. 30.000 karakter)</summary>
                      <pre>{preview}</pre>
                    </details>
                  )}
                </>
              ) : (
                <p>Pilih artefak untuk memeriksa sumber dan hash sebelum membuka isinya.</p>
              )}
            </div>
          </div>
          <details className="custody">
            <summary>Riwayat penanganan run · {data.events.length} catatan</summary>
            {data.events
              .slice(-40)
              .reverse()
              .map((event) => (
                <p key={event.id}>
                  <time>{event.time.at}</time> · <strong>{event.type}</strong> · {event.operator}
                </p>
              ))}
            <small>
              Menampilkan 40 catatan terakhir. Ekspor manifest menyertakan rantai kasus lengkap.
            </small>
          </details>
        </>
      )}
    </section>
  );
}
