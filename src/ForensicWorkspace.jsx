import { useEffect, useMemo, useRef, useState } from 'react';
import { ReactFlow, Background, Controls, MarkerType } from '@xyflow/react';
import { evidenceApi as api } from './CaseEvidence';

const defaults = {
  time: 'timestamp',
  action: 'event',
  account: 'user',
  url: 'url',
  ip: 'ip',
  requestId: 'requestId',
  session: 'sessionId',
  hash: 'sha256',
  messageId: 'messageId',
};
const content = (r) => `/api/cases/${r.caseId}/runs/${r.runId}/artifacts/${r.artifactId}/content`;
const stampLabel = (t) => t?.at || t?.normalized || 'unknown';
export function ForensicWorkspace({ caseId, operator = 'Local analyst', disabled = false }) {
  const base = `/api/cases/${caseId}/forensics`;
  const [open, setOpen] = useState(false),
    [data, setData] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [file, setFile] = useState(null),
    [format, setFormat] = useState('har'),
    [mapping, setMapping] = useState(defaults),
    [zone, setZone] = useState('unknown'),
    [timeFormat, setTimeFormat] = useState('iso'),
    [namespace, setNamespace] = useState(''),
    [delimiter, setDelimiter] = useState(','),
    [collected, setCollected] = useState('');
  const [capture, setCapture] = useState(''),
    [source, setSource] = useState(''),
    [version, setVersion] = useState(''),
    [query, setQuery] = useState(''),
    [type, setType] = useState(''),
    [entityQuery, setEntityQuery] = useState(''),
    [status, setStatus] = useState(''),
    [from, setFrom] = useState(''),
    [to, setTo] = useState(''),
    [unknown, setUnknown] = useState(true),
    [bookmarksOnly, setBookmarksOnly] = useState(false),
    [count, setCount] = useState(100);
  const [selected, setSelected] = useState(null),
    [chosen, setChosen] = useState([]),
    [preview, setPreview] = useState(null),
    [focus, setFocus] = useState(null),
    [graphDetail, setGraphDetail] = useState(null),
    [entities, setEntities] = useState([]),
    [support, setSupport] = useState([]),
    [contra, setContra] = useState([]),
    [share, setShare] = useState(null);
  const [opKind, setOpKind] = useState('bookmark'),
    [actor, setActor] = useState(operator),
    [reason, setReason] = useState(''),
    [seconds, setSeconds] = useState(0);
  const inputRef = useRef();
  const options = () => ({
    format,
    mapping,
    zone,
    timeFormat,
    namespace,
    delimiter,
    claimedCollectedAt: collected,
  });
  const run = async (fn) => {
    setBusy(true);
    setError('');
    try {
      return await fn();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  const reload = async (s = source, v = version) => {
    const d = await api(
      base +
        `?${new URLSearchParams({ ...(s ? { source: s } : {}), ...(v ? { version: v } : {}) })}`,
    );
    setData(d);
    return d;
  };
  useEffect(() => {
    let alive = true;
    if (open && caseId) {
      setBusy(true);
      api(
        base +
          `?${new URLSearchParams({ ...(source ? { source } : {}), ...(version ? { version } : {}) })}`,
      )
        .then((d) => {
          if (alive) {
            setData(d);
            setSelected(null);
            setFocus(null);
            setPreview(null);
          }
        })
        .catch((e) => alive && setError(e.message))
        .finally(() => alive && setBusy(false));
    }
    return () => {
      alive = false;
    };
  }, [caseId, open, source, version]);
  const sourceItem = data?.sources.find((s) => s.id === source),
    event = data?.events.find((e) => e.id === selected);
  const filtered = useMemo(() => {
    const bookmarked = new Set(
      data?.operations
        .filter((o) => o.active && o.kind === 'bookmark')
        .flatMap((o) => o.eventIds) || [],
    );
    return (data?.events || []).filter(
      (e) =>
        (!type || e.type === type) &&
        (!status || e.evidenceStatus === status) &&
        (!bookmarksOnly || bookmarked.has(e.id)) &&
        (!entityQuery ||
          e.entities.some((n) => n.label.toLowerCase().includes(entityQuery.toLowerCase()))) &&
        (!query ||
          `${e.filename} ${e.type} ${e.fields.map((f) => f.value).join(' ')}`
            .toLowerCase()
            .includes(query.toLowerCase())) &&
        (e.displayTime
          ? (!from || e.displayTime >= new Date(from + 'Z').toISOString()) &&
            (!to || e.displayTime <= new Date(to + 'Z').toISOString())
          : unknown),
    );
  }, [data, type, status, bookmarksOnly, entityQuery, query, from, to, unknown]);
  const graph = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const center = focus || event?.id || data.graph.nodes[0]?.id,
      ids = new Set(center ? [center] : []);
    for (let depth = 0; depth < 2; depth++) {
      const before = new Set(ids);
      for (const e of data.graph.edges) {
        if (ids.size >= 80) break;
        if (before.has(e.source) || before.has(e.target)) {
          ids.add(e.source);
          ids.add(e.target);
        }
      }
    }
    const rows = {};
    const nodes = data.graph.nodes
      .filter((n) => ids.has(n.id))
      .map((n) => {
        const col =
          n.kind === 'file'
            ? 0
            : n.eventId === n.id
              ? 1
              : ['correlation', 'manual-association'].includes(n.kind)
                ? 3
                : 2;
        const row = rows[col] || 0;
        rows[col] = row + 1;
        return {
          id: n.id,
          position: { x: col * 270, y: row * 100 },
          data: {
            label: (
              <>
                <strong>{n.kind}</strong>
                <span>{n.label.slice(0, 100)}</span>
              </>
            ),
          },
          style: {
            width: 230,
            borderColor: n.kind === 'correlation' ? '#b17b27' : '#3c806d',
            background: n.id === center ? '#e5f5eb' : 'white',
          },
          sourcePosition: 'right',
          targetPosition: 'left',
        };
      });
    return {
      nodes,
      edges: data.graph.edges
        .filter((e) => ids.has(e.source) && ids.has(e.target))
        .map((e) => ({
          ...e,
          label: e.relation,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: {
            stroke: e.relation === 'correlated' ? '#b17b27' : '#467e70',
            strokeDasharray: e.relation === 'correlated' ? '5 4' : undefined,
          },
        })),
    };
  }, [data, focus, event?.id]);
  const importFile = (e) => {
    e.preventDefault();
    run(async () => {
      if (!file) throw new Error('Pilih file.');
      if (file.size > 8 * 1024 * 1024) throw new Error('Batas file 8 MiB.');
      await api(base + '/import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-WI-Import-Options': encodeURIComponent(
            JSON.stringify({ ...options(), filename: file.name }),
          ),
        },
        body: file,
      });
      setSource('');
      setVersion('');
      await reload('', '');
      setFile(null);
      inputRef.current.value = '';
    });
  };
  const inspect = (s) =>
    run(async () => {
      setPreview(
        await api(
          `${base}/sources/${s.id}/preview${s.parseRef ? `?version=${s.parseRef.artifactId}` : ''}`,
        ),
      );
    });
  const saveOperation = (e) => {
    e.preventDefault();
    run(async () => {
      await api(base + '/operations', {
        method: 'POST',
        body: JSON.stringify({
          kind: opKind,
          operator: actor,
          reason,
          eventIds: chosen,
          entityIds: entities,
          sourceId: source,
          seconds: Number(seconds),
          supporting: support,
          contradicting: contra,
        }),
      });
      setReason('');
      setChosen([]);
      setSupport([]);
      setContra([]);
      setEntities([]);
      await reload();
    });
  };
  const undo = (op) =>
    run(async () => {
      await api(base + '/operations', {
        method: 'POST',
        body: JSON.stringify({
          kind: 'revert',
          target: op.id,
          operator: actor,
          reason: reason || `Batalkan ${op.kind}; sumber asli tetap utuh`,
        }),
      });
      await reload();
    });
  return (
    <section aria-busy={busy} className="forensic-panel" aria-label="Forensik kasus">
      <div className="forensic-heading">
        <div>
          <h2>Forensik kasus</h2>
          <p>
            Gabungkan sumber, susun timeline, tinjau korelasi. Hash membuktikan baseline lokal,
            bukan keaslian sejarah.
          </p>
        </div>
        <button className="button secondary" disabled={!caseId} onClick={() => setOpen(!open)}>
          {open ? 'Tutup workspace forensik' : 'Buka workspace forensik'}
        </button>
      </div>
      {!caseId && (
        <p>
          Pilih atau buat kasus terlebih dahulu. Scope URL kasus mengatur capture, bukan izin
          mengakses URL yang ditemukan dalam file.
        </p>
      )}
      {open && (
        <>
          {error && (
            <p role="alert" className="forensic-error">
              {error}
            </p>
          )}
          <details className="forensic-import" open={!data?.sources.length}>
            <summary>Impor sumber / konfigurasi parser</summary>
            <p>
              Asli disimpan terenkripsi, terpisah dari parsing. Bisa memuat data sensitif. Maks. 8
              MiB; tidak ada ekstraksi arsip atau eksekusi konten. Impor identik tetap menjadi
              salinan akuisisi baru.
            </p>
            <form onSubmit={importFile}>
              <div className="forensic-grid">
                <label>
                  Format
                  <select
                    aria-label="Format impor"
                    value={format}
                    onChange={(e) => setFormat(e.target.value)}
                  >
                    {['har', 'json', 'ndjson', 'csv', 'eml', 'file'].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  File lokal
                  <input
                    aria-label="File impor"
                    type="file"
                    ref={inputRef}
                    onChange={(e) => setFile(e.target.files[0] || null)}
                  />
                </label>
                <label>
                  Namespace aplikasi/sumber
                  <input
                    aria-label="Namespace sumber"
                    value={namespace}
                    onChange={(e) => setNamespace(e.target.value)}
                    maxLength={160}
                    placeholder="portal-fixture (klaim operator)"
                  />
                </label>
                <label>
                  Zona untuk timestamp tanpa offset
                  <select
                    aria-label="Zona timestamp"
                    value={zone}
                    onChange={(e) => setZone(e.target.value)}
                  >
                    {['unknown', 'UTC', '+07:00', '+08:00', '+09:00', '-05:00', '+01:00'].map(
                      (s) => (
                        <option key={s}>{s}</option>
                      ),
                    )}
                  </select>
                </label>
                <label>
                  Interpretasi waktu log
                  <select
                    aria-label="Format waktu log"
                    value={timeFormat}
                    onChange={(e) => setTimeFormat(e.target.value)}
                  >
                    {['iso', 'unix-ms', 'unix-s'].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Waktu pengumpulan yang dinyatakan
                  <input
                    aria-label="Klaim waktu pengumpulan"
                    value={collected}
                    onChange={(e) => setCollected(e.target.value)}
                    placeholder="Kosong = unknown; bukan waktu impor"
                    maxLength={120}
                  />
                </label>
              </div>
              <p>
                HAR: log.version 1.2. JSON: array objek atau events[]. NDJSON: satu objek per baris.
                EML: header/MIME terpilih, isi HTML/lampiran tidak dirender. File umum:
                metadata/hash saja. Namespace mengizinkan korelasi request/session ID, bukan
                membuktikan identitas.
              </p>
              {['json', 'ndjson', 'csv'].includes(format) && (
                <>
                  <p>
                    Petakan field yang memang diketahui. CSV menggunakan nama kolom persis;
                    JSON/NDJSON menggunakan key atau JSON pointer relatif. Kosongkan field yang
                    tidak ada. Ini bukan parser universal semua log.
                  </p>
                  {format === 'csv' && (
                    <label>
                      Pemisah CSV
                      <select
                        aria-label="Pemisah CSV"
                        value={delimiter}
                        onChange={(e) => setDelimiter(e.target.value)}
                      >
                        <option value=",">Koma</option>
                        <option value=";">Titik koma</option>
                        <option value={'\t'}>Tab</option>
                      </select>
                    </label>
                  )}
                  <div className="forensic-grid">
                    {Object.keys(defaults).map((key) => (
                      <label key={key}>
                        Pemetaan {key}
                        <input
                          aria-label={`Pemetaan ${key}`}
                          value={mapping[key] || ''}
                          onChange={(e) => setMapping({ ...mapping, [key]: e.target.value })}
                          maxLength={120}
                        />
                      </label>
                    ))}
                  </div>
                </>
              )}
              <button className="button primary" disabled={busy || disabled || !file}>
                Impor dan parse
              </button>
            </form>
          </details>
          <div className="forensic-grid">
            <label>
              Capture browser kasus
              <select
                aria-label="Capture untuk forensik"
                value={capture}
                onChange={(e) => setCapture(e.target.value)}
              >
                <option value="">Pilih run tersegel</option>
                {data?.captures.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id.slice(0, 8)} · {c.mode} · {c.created.at}
                  </option>
                ))}
              </select>
            </label>
            <button
              disabled={busy || disabled || !capture}
              onClick={() =>
                run(async () => {
                  await api(`${base}/captures/${capture}`, { method: 'POST', body: '{}' });
                  setSource('');
                  setVersion('');
                  await reload('', '');
                })
              }
            >
              Tambahkan capture ke timeline
            </button>
          </div>
          <p>
            Capture merekam keadaan saat diamati. Penambahan ini membaca artefak tersimpan; tidak
            membuka website atau merekonstruksi kejadian lama.
          </p>
          <div className="forensic-actions">
            <button disabled={busy} onClick={() => run(() => reload())}>
              Muat ulang forensik
            </button>
            <button
              disabled={busy || disabled || !data?.sources.length}
              onClick={() =>
                run(async () =>
                  setShare((await api(base + '/share', { method: 'POST', body: '{}' })).ref),
                )
              }
            >
              Buat ekspor tersensor
            </button>
            {share && (
              <a className="button secondary" href={content(share)} download>
                Unduh ekspor tersensor
              </a>
            )}
          </div>
          <p>
            Ekspor berbagi hanya struktur, waktu normalisasi, hash/referensi dan relasi. Nama file,
            nilai field, URL/identitas/IP, namespace serta teks analis dihilangkan. Asli tidak
            disertakan.
          </p>
          {data && (
            <>
              {!!data.gaps.length && (
                <p className="forensic-error">Gap integritas: {data.gaps.join('; ')}</p>
              )}
              <div className="forensic-grid">
                <label>
                  Sumber timeline
                  <select
                    aria-label="Sumber timeline"
                    value={source}
                    onChange={(e) => {
                      setSource(e.target.value);
                      setVersion('');
                      setChosen([]);
                      setCount(100);
                    }}
                  >
                    <option value="">Semua sumber</option>
                    {data.sources.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.filename} · {s.id.slice(0, 8)} · {s.status}
                      </option>
                    ))}
                  </select>
                </label>
                {sourceItem && (
                  <label>
                    Versi parsing
                    <select
                      aria-label="Versi parsing"
                      value={version}
                      onChange={(e) => setVersion(e.target.value)}
                    >
                      <option value="">Terbaru</option>
                      {sourceItem.versions.map((v) => (
                        <option key={v.artifactId} value={v.artifactId}>
                          {v.parsedAt.at} · {v.parser.id} v{v.parser.version} · {v.status}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
              </div>
              {sourceItem && (
                <article className="forensic-source">
                  <h3>{sourceItem.filename}</h3>
                  <p>
                    {sourceItem.status} · integritas {sourceItem.integrity} · sumber {sourceItem.id}
                  </p>
                  <code>{sourceItem.originalRef.sha256}</code>
                  <p>
                    Impor: {stampLabel(sourceItem.importedAt)} · pengumpulan yang dinyatakan:{' '}
                    {stampLabel(sourceItem.parsed?.sourceCollectionTime)} · parsing:{' '}
                    {stampLabel(sourceItem.parsedAt)}
                  </p>
                  {!!sourceItem.duplicates.length && (
                    <p>
                      Hash sama dengan {sourceItem.duplicates.length} salinan lain; asal-usul setiap
                      salinan tetap terpisah.
                    </p>
                  )}
                  <p>
                    Parser {sourceItem.parsed?.parser.id} v{sourceItem.parsed?.parser.version}
                  </p>
                  <p>{sourceItem.parsed?.coverage.gaps.join('; ')}</p>
                  <p>Redaksi: {sourceItem.parsed?.redactions.join('; ')}</p>
                  <div className="forensic-actions">
                    <button disabled={busy} onClick={() => inspect(sourceItem)}>
                      Preview metadata aman
                    </button>
                    <a href={content(sourceItem.originalRef)} download>
                      Unduh asli — dapat memuat rahasia
                    </a>
                    <a
                      href={`/api/cases/${caseId}/runs/${sourceItem.originalRef.runId}/manifest`}
                      download
                    >
                      Manifest &amp; custody sumber (privat)
                    </a>
                    <button
                      disabled={busy || disabled}
                      onClick={() =>
                        run(async () => {
                          await api(`${base}/sources/${sourceItem.id}/reparse`, {
                            method: 'POST',
                            body: JSON.stringify(options()),
                          });
                          setVersion('');
                          await reload(sourceItem.id, '');
                        })
                      }
                    >
                      Parse ulang dengan konfigurasi di atas
                    </button>
                  </div>
                </article>
              )}
              <div className="forensic-filters">
                <label>
                  Cari teks
                  <input
                    aria-label="Cari timeline"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </label>
                <label>
                  Entitas
                  <input
                    aria-label="Filter entitas"
                    value={entityQuery}
                    onChange={(e) => setEntityQuery(e.target.value)}
                    placeholder="URL, akun, IP, hash"
                  />
                </label>
                <label>
                  Tipe event
                  <select
                    aria-label="Tipe event"
                    value={type}
                    onChange={(e) => setType(e.target.value)}
                  >
                    <option value="">Semua</option>
                    {[...new Set(data.events.map((e) => e.type))].map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Status bukti
                  <select
                    aria-label="Status bukti"
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                  >
                    <option value="">Semua</option>
                    <option>verified-baseline</option>
                    <option>partial</option>
                  </select>
                </label>
                <label>
                  Dari (UTC)
                  <input
                    aria-label="Dari UTC"
                    type="datetime-local"
                    value={from}
                    onChange={(e) => setFrom(e.target.value)}
                  />
                </label>
                <label>
                  Sampai (UTC)
                  <input
                    aria-label="Sampai UTC"
                    type="datetime-local"
                    value={to}
                    onChange={(e) => setTo(e.target.value)}
                  />
                </label>
              </div>
              <div className="forensic-actions">
                <label className="forensic-check">
                  <input
                    type="checkbox"
                    checked={unknown}
                    onChange={(e) => setUnknown(e.target.checked)}
                  />{' '}
                  Tetap tampilkan waktu unknown/ambigu
                </label>
                <label className="forensic-check">
                  <input
                    type="checkbox"
                    checked={bookmarksOnly}
                    onChange={(e) => setBookmarksOnly(e.target.checked)}
                  />{' '}
                  Bookmark aktif saja
                </label>
              </div>
              <p>
                {filtered.length} event cocok · {chosen.length} dipilih.{' '}
                {data.truncated
                  ? 'Batas 5.000 event tercapai; pilih sumber untuk menjelajahi sisanya.'
                  : ''}{' '}
                Urutan memakai waktu UTC yang dapat dinormalisasi; waktu unknown di akhir, tanpa
                menebak urutan kejadian.
              </p>
              <div className="forensic-table">
                <table>
                  <thead>
                    <tr>
                      <th>Pilih</th>
                      <th>Waktu event / sumber</th>
                      <th>Tipe / bukti</th>
                      <th>Ringkasan terpilih</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0, count).map((e) => (
                      <tr key={e.id} className={selected === e.id ? 'selected' : ''}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`Pilih event ${e.id}`}
                            checked={chosen.includes(e.id)}
                            onChange={(ev) =>
                              setChosen(
                                ev.target.checked
                                  ? [...chosen, e.id]
                                  : chosen.filter((id) => id !== e.id),
                              )
                            }
                          />
                        </td>
                        <td>
                          <button
                            onClick={() => {
                              setSelected(e.id);
                              setFocus(e.id);
                            }}
                          >
                            {e.displayTime || 'Waktu unknown/ambigu'}
                          </button>
                          <small>
                            {e.time.raw || 'Tidak ada timestamp'} ·{' '}
                            {e.time.zone || e.time.assumedZone || 'zona unknown'} · {e.time.status}
                            {e.clockTransform ? ' · CLOCK TRANSFORM' : ''}
                          </small>
                          <small>{e.filename}</small>
                        </td>
                        <td>
                          {e.type}
                          <small>{e.evidenceStatus}</small>
                          <small>{e.basis}</small>
                        </td>
                        <td>
                          {e.fields
                            .filter((f) =>
                              [
                                'action',
                                'account',
                                'url',
                                'status',
                                'subject',
                                'sha256',
                                'method',
                              ].includes(f.name),
                            )
                            .slice(0, 3)
                            .map((f) => (
                              <small key={f.name}>
                                {f.name}: {String(f.value).slice(0, 130)}
                              </small>
                            ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {filtered.length > count && (
                <button onClick={() => setCount(count + 100)}>Muat 100 event lagi</button>
              )}
              {event && (
                <article className="forensic-inspector">
                  <h3>Event → sumber</h3>
                  <p>
                    {event.id} · {event.provenance.parser.id} v{event.provenance.parser.version}
                  </p>
                  <p>
                    Event: {event.time.raw || 'unknown'} →{' '}
                    {event.time.normalized || 'tidak dinormalisasi'}; tampilan:{' '}
                    {event.displayTime || 'unknown'}
                  </p>
                  <p>
                    Pengumpulan: {stampLabel(event.collectedTime)} ({event.collectedTime?.status}) ·
                    impor: {stampLabel(event.importedTime)} · parsing:{' '}
                    {stampLabel(event.parsedTime)}
                  </p>
                  <p>{event.time.reason || event.time.basis}</p>
                  {event.clockTransform && (
                    <p>
                      Koreksi tampilan {event.clockTransform.seconds}s oleh{' '}
                      {event.clockTransform.operator}: {event.clockTransform.reason}. Nilai sumber
                      tidak diubah.
                    </p>
                  )}
                  <button
                    onClick={() => inspect(data.sources.find((s) => s.id === event.sourceId))}
                  >
                    Tinjau sumber event
                  </button>
                  <div className="forensic-fields">
                    {event.fields.map((f, i) => (
                      <div key={i}>
                        <b>{f.name}</b>
                        <span>{String(f.value)}</span>
                        <code>{JSON.stringify(f.evidence.location)}</code>
                        <small>
                          {f.evidence.artifactId} · {f.evidence.parser.id} v
                          {f.evidence.parser.version} · {f.evidence.method}
                        </small>
                      </div>
                    ))}
                  </div>
                  <div className="forensic-actions">
                    {data.graph.nodes
                      .filter((n) => n.eventId === event.id && n.matchKey)
                      .map((n) => (
                        <button
                          key={n.id}
                          onClick={() => {
                            setFocus(n.id);
                            setGraphDetail(n);
                          }}
                        >
                          {n.kind}: {n.label.slice(0, 60)}
                        </button>
                      ))}
                  </div>
                </article>
              )}
              {preview && (
                <details open className="forensic-preview">
                  <summary>Preview inert · hash diverifikasi</summary>
                  <p>{preview.previewPolicy}</p>
                  <p>
                    Asli {preview.source.originalRef.artifactId} · SHA-256{' '}
                    {preview.source.originalRef.sha256}
                  </p>
                  <pre>
                    {JSON.stringify(
                      {
                        filename: preview.source.filename,
                        parser: preview.source.parsed?.parser,
                        coverage: preview.source.parsed?.coverage,
                        events: preview.events.slice(0, 3),
                      },
                      null,
                      2,
                    ).slice(0, 22000)}
                  </pre>
                  <p>
                    Pratinjau ringkas maksimal 3 event/22.000 karakter; gunakan timeline/provenance
                    untuk event lainnya.
                  </p>
                  <button onClick={() => setPreview(null)}>Tutup preview</button>
                </details>
              )}
              <details className="forensic-graph" open={!!event}>
                <summary>Graph lintas sumber · occurrence tetap terpisah</summary>
                <p>
                  Garis correlated menunjukkan nilai cocok, bukan identitas atau sebab yang sama.
                  Tidak ada edge kausal hanya karena waktu berdekatan. Hingga 80 node di sekitar
                  pilihan.
                </p>
                <div className="forensic-flow">
                  <ReactFlow
                    nodes={graph.nodes}
                    edges={graph.edges}
                    fitView
                    key={focus || 'all'}
                    onNodeClick={(_, n) => {
                      const detail = data.graph.nodes.find((x) => x.id === n.id);
                      setGraphDetail(detail);
                      setFocus(n.id);
                      if (detail.eventId) setSelected(detail.eventId);
                    }}
                    onEdgeClick={(_, e) =>
                      setGraphDetail(data.graph.edges.find((x) => x.id === e.id))
                    }
                  >
                    <Background />
                    <Controls />
                  </ReactFlow>
                </div>
                {graphDetail && (
                  <div>
                    <p>
                      {graphDetail.kind || graphDetail.relation}:{' '}
                      {graphDetail.label || graphDetail.method}
                    </p>
                    <p>{graphDetail.method}</p>
                    <pre>{JSON.stringify(graphDetail.evidence, null, 2)}</pre>
                    {graphDetail.matchKey && (
                      <button
                        onClick={() =>
                          setEntities((prev) =>
                            prev.includes(graphDetail.id) ? prev : prev.concat(graphDetail.id),
                          )
                        }
                      >
                        Pilih occurrence untuk merge manual
                      </button>
                    )}
                  </div>
                )}
              </details>
              <details className="forensic-notes">
                <summary>Bookmark, catatan, hipotesis dan transformasi</summary>
                <p>
                  Hipotesis selalu belum terverifikasi. Pilih event melalui checkbox. Merge manual
                  mempertahankan node sumber; undo menambahkan catatan pembatalan.
                </p>
                <form onSubmit={saveOperation}>
                  <div className="forensic-grid">
                    <label>
                      Jenis catatan
                      <select
                        aria-label="Jenis catatan forensik"
                        value={opKind}
                        onChange={(e) => setOpKind(e.target.value)}
                      >
                        {['bookmark', 'note', 'hypothesis', 'clock-skew', 'merge'].map((s) => (
                          <option key={s}>{s}</option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Analis
                      <input
                        aria-label="Analis forensik"
                        required
                        maxLength={160}
                        value={actor}
                        onChange={(e) => setActor(e.target.value)}
                      />
                    </label>
                    {opKind === 'clock-skew' && (
                      <label>
                        Koreksi detik (pilih sumber di atas)
                        <input
                          aria-label="Clock skew detik"
                          type="number"
                          min={-86400}
                          max={86400}
                          value={seconds}
                          onChange={(e) => setSeconds(e.target.value)}
                        />
                      </label>
                    )}
                  </div>
                  <label>
                    Alasan / catatan
                    <textarea
                      aria-label="Catatan forensik"
                      required
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      maxLength={2000}
                    />
                  </label>
                  {opKind === 'hypothesis' && (
                    <div className="forensic-actions">
                      <button type="button" onClick={() => setSupport([...chosen])}>
                        Pilihan sebagai pendukung ({support.length})
                      </button>
                      <button type="button" onClick={() => setContra([...chosen])}>
                        Pilihan sebagai penyangkal ({contra.length})
                      </button>
                    </div>
                  )}
                  {opKind === 'merge' && (
                    <p>
                      {entities.length} occurrence dipilih.{' '}
                      <button type="button" onClick={() => setEntities([])}>
                        Kosongkan entitas
                      </button>
                    </p>
                  )}
                  <button disabled={busy || disabled}>Simpan catatan forensik</button>
                </form>
                {data.operations.map((o) => (
                  <article key={o.id}>
                    <b>
                      {o.kind} ·{' '}
                      {o.kind === 'hypothesis'
                        ? 'HIPOTESIS BELUM TERVERIFIKASI'
                        : o.active
                          ? 'aktif'
                          : 'dibatalkan / record undo'}
                    </b>
                    <p>
                      {o.operator} · {o.time.at} · {o.reason}
                    </p>
                    <p>
                      Bukti: {o.evidence.length}; pendukung {o.supporting.length}, penyangkal{' '}
                      {o.contradicting.length}
                    </p>
                    <details>
                      <summary>Telusuri referensi catatan</summary>
                      {['evidence', 'supporting', 'contradicting'].map((kind) => (
                        <div key={kind}>
                          <b>{kind}</b>
                          {o[kind].map((r, i) => (
                            <div key={i}>
                              <a href={content(r)} download>
                                Artefak {r.artifactId}
                              </a>
                              {r.extractionRef && (
                                <a href={content(r.extractionRef)} download>
                                  {' '}
                                  · Hasil parser
                                </a>
                              )}
                              <pre>{JSON.stringify(r, null, 2)}</pre>
                            </div>
                          ))}
                        </div>
                      ))}
                    </details>
                    {o.active && (
                      <button disabled={busy || disabled} onClick={() => undo(o)}>
                        Batalkan {o.kind}
                      </button>
                    )}
                  </article>
                ))}
              </details>
            </>
          )}
        </>
      )}
    </section>
  );
}
