import { useState, useEffect } from 'react';
import { evidenceApi as api } from './CaseEvidence';
const content = (r) => `/api/cases/${r.caseId}/runs/${r.runId}/artifacts/${r.artifactId}/content`;
const post = (url, body) => api(url, { method: 'POST', body: JSON.stringify(body) });
function download(text, name, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type })),
    a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function ReportWorkspace({ caseId, operator = '', disabled = false }) {
  const base = `/api/cases/${caseId}`;
  const [open, setOpen] = useState(false),
    [catalog, setCatalog] = useState(null),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [chosen, setChosen] = useState([]),
    [report, setReport] = useState(null),
    [author, setAuthor] = useState(operator),
    [recommendations, setRecommendations] = useState(''),
    [reviewer, setReviewer] = useState(operator),
    [reason, setReason] = useState(''),
    [ack, setAck] = useState(false),
    [evidence, setEvidence] = useState(null),
    [exported, setExported] = useState(null),
    [originals, setOriginals] = useState([]),
    [sensitive, setSensitive] = useState(false),
    [includePdf, setIncludePdf] = useState(false);
  const [shareNarrative, setShareNarrative] = useState({
      title: '',
      objective: '',
      scope: '',
      recommendations: '',
      reviewer: '',
    }),
    [shareNarrativeApproved, setShareNarrativeApproved] = useState(false);
  const [left, setLeft] = useState(''),
    [right, setRight] = useState(''),
    [leftIdentity, setLeftIdentity] = useState(''),
    [rightIdentity, setRightIdentity] = useState(''),
    [comparison, setComparison] = useState(null),
    [changeFilter, setChangeFilter] = useState(''),
    [query, setQuery] = useState(''),
    [task, setTask] = useState('search'),
    [assistant, setAssistant] = useState(null),
    [config, setConfig] = useState(null),
    [facts, setFacts] = useState([]),
    [plan, setPlan] = useState(null),
    [aiEnabled, setAiEnabled] = useState(false),
    [approved, setApproved] = useState(false),
    [quotes, setQuotes] = useState(false);
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
  const reload = async () => {
    const [c, a] = await Promise.all([api(base + '/reporting'), api('/api/assistant/config')]);
    setCatalog(c);
    setConfig(a);
  };
  useEffect(() => {
    if (open && caseId) run(reload);
  }, [open, caseId]);
  const selectReport = (r) => {
    setReport(r);
    setShareNarrative(
      r.snapshot.shareNarrative || {
        title: '',
        objective: '',
        scope: '',
        recommendations: '',
        reviewer: '',
      },
    );
    setShareNarrativeApproved(!!r.snapshot.shareNarrative);
    setAssistant(null);
    setPlan(null);
    setApproved(false);
    setAck(false);
    setFacts([]);
    setOriginals([]);
    setSensitive(false);
    setExported(null);
  };
  const refs = (items) => (
    <span className="report-refs">
      {(items || []).slice(0, 5).map((r, i) => (
        <button
          key={i}
          className="ghost"
          onClick={() => run(async () => setEvidence(await post(base + '/reporting/evidence', r)))}
        >
          Bukti {r.artifactId?.slice(0, 8)} {r.pointer}
        </button>
      ))}
      {items?.length > 5 && <small>+{items.length - 5} referensi di JSON sumber</small>}
    </span>
  );
  const toggle = (id, values, set) =>
    set(values.includes(id) ? values.filter((v) => v !== id) : [...values, id]);
  const captures =
    catalog?.sources.filter((s) => ['run-report', 'page-extraction'].includes(s.kind)) || [];
  const sourceLabel = (s) => `${s.kind} · ${s.id.slice(0, 8)} · ${s.collected?.at} · ${s.status}`;
  const originalOptions = report
    ? [
        ...new Map(
          [...report.snapshot.sources.map((s) => s.ref), ...report.snapshot.refs].map((r) => [
            r.artifactId,
            r,
          ]),
        ).values(),
      ]
    : [];
  return (
    <section className="report-workspace" aria-label="Pelaporan kasus" aria-busy={busy}>
      <button className="ghost" onClick={() => setOpen(!open)} disabled={!caseId}>
        Laporan, perbandingan & asisten {open ? '−' : '+'}
      </button>
      {open && (
        <>
          <p>
            Laporan membekukan bukti terpilih. Semua fungsi inti tersedia tanpa AI. Salinan berbagi
            hanya memuat struktur tersensor; hash tidak membuktikan autentisitas atau kelayakan
            hukum.
          </p>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
          <fieldset disabled={busy || disabled}>
            <button className="ghost" onClick={() => run(reload)}>
              Muat ulang sumber laporan
            </button>
            <details open>
              <summary>1. Susun laporan kasus</summary>
              <p>
                Pilih hingga 12 versi artefak. Hindari memilih run-report dan page-extraction yang
                sama jika tidak ingin observasi berulang.
              </p>
              <div className="report-scroll">
                {catalog?.sources.map((s) => (
                  <label key={s.id}>
                    <input
                      type="checkbox"
                      checked={chosen.includes(s.id)}
                      onChange={() => toggle(s.id, chosen, setChosen)}
                    />
                    {sourceLabel(s)}
                  </label>
                ))}
              </div>
              <div className="report-grid">
                <label>
                  Penulis
                  <input value={author} onChange={(e) => setAuthor(e.target.value)} />
                </label>
                <label>
                  Rekomendasi analis (privat)
                  <textarea
                    value={recommendations}
                    onChange={(e) => setRecommendations(e.target.value)}
                  />
                </label>
              </div>
              <details>
                <summary>Narasi yang boleh dibagikan (opsional)</summary>
                <p>
                  Tulis ulang tujuan, scope, rekomendasi dan nama peninjau yang aman dibagikan.
                  Narasi ini adalah pernyataan analis, bukan bukti tambahan. Tidak disalin otomatis
                  dari sumber.
                </p>
                {Object.keys(shareNarrative).map((k) => (
                  <label key={k}>
                    Narasi berbagi {k}
                    <textarea
                      value={shareNarrative[k]}
                      maxLength={2000}
                      onChange={(e) => {
                        setShareNarrative({ ...shareNarrative, [k]: e.target.value });
                        setShareNarrativeApproved(false);
                      }}
                    />
                  </label>
                ))}
                <label>
                  <input
                    type="checkbox"
                    checked={shareNarrativeApproved}
                    onChange={(e) => setShareNarrativeApproved(e.target.checked)}
                  />
                  Saya menyetujui narasi ini untuk disertakan dalam ekspor
                </label>
              </details>
              <button
                disabled={!chosen.length}
                onClick={() =>
                  run(async () => {
                    selectReport(
                      await post(base + '/reports', {
                        artifactIds: chosen,
                        shareNarrative,
                        shareNarrativeApproved,
                        author,
                        recommendations,
                        previousId: report?.id,
                      }),
                    );
                    await reload();
                  })
                }
              >
                Buat draft {report ? 'versi baru' : ''}
              </button>
              <label>
                Buka versi laporan
                <select
                  value={report?.id || ''}
                  onChange={(e) =>
                    e.target.value &&
                    run(async () => selectReport(await api(base + '/reports/' + e.target.value)))
                  }
                >
                  <option value="">Pilih laporan</option>
                  {catalog?.reports.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.status} v{r.version} · {r.id.slice(0, 8)}
                    </option>
                  ))}
                </select>
              </label>
            </details>
            {report && (
              <article className="report-preview" data-testid="report-preview">
                <h3>
                  {report.snapshot.case.title} · {report.status} v{report.version}
                </h3>
                <p>{report.snapshot.case.objective}</p>
                <p>Scope navigasi: {report.snapshot.case.scope.navigation.join(', ')}</p>
                <p>
                  Dependensi teramati berbeda dari izin navigasi. Snapshot SHA-256:{' '}
                  <code>{report.snapshotSha256}</code>
                </p>
                <p>
                  {report.snapshot.sources.length} sumber · {report.snapshot.timeline.length} event
                  · {report.snapshot.findings.length} temuan · {report.snapshot.gaps.length} gap
                </p>
                <details>
                  <summary>Metode, waktu dan cakupan sumber</summary>
                  {report.snapshot.sources.map((s) => (
                    <div key={s.ref.artifactId}>
                      <b>{s.kind}</b>
                      <p>
                        {s.method} · {s.collected?.at} ({s.collected?.timezone}) · {s.status}
                      </p>
                      {refs([s.ref])}
                      <pre>{JSON.stringify(s.coverage, null, 2)}</pre>
                    </div>
                  ))}
                </details>
                <details>
                  <summary>Timeline dan provenance</summary>
                  {report.snapshot.timeline.map((e) => (
                    <p key={e.id}>
                      {e.displayTime || e.eventTime.normalized || 'Waktu ambigu/tidak diketahui'} ·{' '}
                      {e.eventTime.status} · {e.classification}
                      <br />
                      {e.label}
                      {refs(e.evidence)}
                    </p>
                  ))}
                </details>
                <details open>
                  <summary>Observasi, korelasi, hipotesis & temuan</summary>
                  <div className="report-scroll">
                    {report.snapshot.cards.map((c) => (
                      <div className="report-card" key={c.id}>
                        <b>{c.classification}</b> · {c.text}
                        {refs(c.evidence)}
                      </div>
                    ))}
                  </div>
                </details>
                <details>
                  <summary>Gap, keterbatasan & rekomendasi</summary>
                  {report.snapshot.findings.map((f) => (
                    <details key={f.id}>
                      <summary>
                        {f.ruleId} · {f.status} · {f.title}
                      </summary>
                      <pre>{JSON.stringify(f, null, 2)}</pre>
                      {refs(f.evidence)}
                    </details>
                  ))}
                  {[...report.snapshot.gaps, ...report.snapshot.limitations].map((x, i) => (
                    <p key={i}>{x}</p>
                  ))}
                  <p>{report.snapshot.recommendations || 'Belum ada rekomendasi analis.'}</p>
                </details>
                {report.status === 'draft' ? (
                  <div className="report-review">
                    <h4>Review manusia sebelum final</h4>
                    <label>
                      Peninjau
                      <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} />
                    </label>
                    <label>
                      Alasan keputusan
                      <textarea value={reason} onChange={(e) => setReason(e.target.value)} />
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={ack}
                        onChange={(e) => setAck(e.target.checked)}
                      />
                      Saya sudah meninjau bukti, gap, redaksi dan status temuan pada snapshot ini.
                    </label>
                    <button
                      disabled={!ack || !reviewer || !reason}
                      onClick={() =>
                        run(async () => {
                          selectReport(
                            await post(base + '/reports/' + report.id + '/finalize', {
                              reviewer,
                              reason,
                              acknowledged: ack,
                              expectedSha256: report.snapshotSha256,
                            }),
                          );
                          await reload();
                        })
                      }
                    >
                      Tandai final sebagai versi baru
                    </button>
                  </div>
                ) : (
                  <p>
                    Ditinjau {report.review.reviewer} · {report.review.reviewedAt}.{' '}
                    {report.review.reason}
                  </p>
                )}
                <h4>Ekspor tersensor</h4>
                <p>
                  HTML/PDF/JSON berbagi menyembunyikan teks privat, URL, identitas, nama file, nilai
                  field dan screenshot. Buka unduhan untuk memeriksa isinya sebelum berbagi.
                </p>
                {['json', 'html', 'pdf', 'package'].map((format) => (
                  <button
                    className="ghost"
                    key={format}
                    onClick={() =>
                      run(async () =>
                        setExported(
                          await post(base + '/reports/' + report.id + '/export', {
                            format,
                            includePdf,
                            originalIds: format === 'package' && sensitive ? originals : [],
                            sensitiveConfirmed: sensitive,
                          }),
                        ),
                      )
                    }
                  >
                    {format === 'package' ? 'Paket + manifest' : format.toUpperCase()}
                  </button>
                ))}
                <label>
                  <input
                    type="checkbox"
                    checked={includePdf}
                    onChange={(e) => setIncludePdf(e.target.checked)}
                  />
                  Sertakan PDF dalam paket
                </label>
                <details>
                  <summary>Ekspor asli sensitif (opsional, terenkripsi)</summary>
                  <p>
                    Pilih ID sumber secara eksplisit. File impor asli mungkin memuat data pribadi
                    atau secret. Kunci paket diunduh terpisah dan hanya ditampilkan sekali; jangan
                    dikirim bersama paket. State login collector tidak diekspor.
                  </p>
                  <div className="report-scroll">
                    {originalOptions.map((r) => (
                      <label key={r.artifactId}>
                        <input
                          type="checkbox"
                          checked={originals.includes(r.artifactId)}
                          onChange={() => toggle(r.artifactId, originals, setOriginals)}
                        />
                        {r.artifactId}
                        {refs([r])}
                      </label>
                    ))}
                  </div>
                  <label>
                    <input
                      type="checkbox"
                      checked={sensitive}
                      onChange={(e) => setSensitive(e.target.checked)}
                    />
                    Saya memilih ekspor asli sensitif dan akan menyimpan kunci secara terpisah.
                  </label>
                </details>
                {exported && (
                  <div role="status">
                    <a href={content(exported.artifact)} download={exported.filename}>
                      Unduh {exported.filename}
                    </a>
                    <p>
                      SHA-256: <code>{exported.sha256}</code>
                    </p>
                    {exported.keyHex && (
                      <button
                        onClick={() =>
                          download(exported.keyHex + '\n', `export-${exported.id}.key`)
                        }
                      >
                        Simpan kunci terpisah (sekali ditampilkan)
                      </button>
                    )}
                    <a href="/api/report-verifier" download="verify-package.mjs">
                      Unduh verifier lokal
                    </a>
                    <pre>
                      node verify-package.mjs {exported.filename}
                      {exported.keyHex ? ' --key-file export-' + exported.id + '.key' : ''}
                    </pre>
                  </div>
                )}
                <h4>Asisten berbasis bukti</h4>
                <div className="report-grid">
                  <label>
                    Tugas
                    <select
                      aria-label="Tugas"
                      value={task}
                      onChange={(e) => {
                        setTask(e.target.value);
                        setPlan(null);
                        setApproved(false);
                      }}
                    >
                      {['search', 'summary', 'relations', 'draft'].map((x) => (
                        <option key={x}>{x}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Cari teks
                    <input
                      value={query}
                      onChange={(e) => {
                        setQuery(e.target.value);
                        setPlan(null);
                        setApproved(false);
                      }}
                    />
                  </label>
                </div>
                <button
                  onClick={() =>
                    run(async () => {
                      const a = await post(base + '/reports/' + report.id + '/assistant/local', {
                        task,
                        query,
                      });
                      setAssistant(a);
                      setFacts(a.facts.slice(0, 10).map((f) => f.id));
                      setPlan(null);
                    })
                  }
                >
                  Analisis lokal tanpa AI
                </button>
                {assistant && (
                  <div data-testid="assistant-result">
                    <p>
                      {assistant.insufficientData
                        ? 'Tidak cukup data yang cocok.'
                        : assistant.accepted === false
                          ? 'Keluaran model ditolak.'
                          : 'Hasil draft; validasi temuan tetap keputusan manusia.'}{' '}
                      {assistant.error}
                    </p>
                    {(assistant.quotes || []).map((q, i) => {
                      const f = assistant.facts.find((f) => f.id === q.factId);
                      return (
                        <blockquote key={i}>
                          Kutipan cocok dengan field sumber: {q.text}
                          {f?.quote && refs([f.quote.ref])}
                        </blockquote>
                      );
                    })}
                    {assistant.facts.map((f) => (
                      <div className="report-card" key={f.id}>
                        <label>
                          <input
                            type="checkbox"
                            checked={facts.includes(f.id)}
                            onChange={() => {
                              toggle(f.id, facts, setFacts);
                              setPlan(null);
                              setApproved(false);
                            }}
                          />
                          {f.classification} · {f.text}
                        </label>
                        {refs(f.evidence)}
                      </div>
                    ))}
                  </div>
                )}
                <details>
                  <summary>
                    Provider AI opsional · {config?.ready ? config.model : 'belum dikonfigurasi'}
                  </summary>
                  <p>
                    {config?.notice}{' '}
                    <a
                      href="https://developers.openai.com/api/docs/guides/your-data"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Kebijakan data provider
                    </a>
                  </p>
                  <label>
                    <input
                      type="checkbox"
                      checked={aiEnabled}
                      onChange={(e) => {
                        setAiEnabled(e.target.checked);
                        setApproved(false);
                      }}
                    />
                    Aktifkan pengiriman hanya untuk permintaan yang saya setujui
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={quotes}
                      onChange={(e) => {
                        setQuotes(e.target.checked);
                        setPlan(null);
                        setApproved(false);
                      }}
                    />
                    Sertakan kutipan field terpilih (mungkin berisi data pribadi atau instruksi
                    berbahaya sebagai data)
                  </label>
                  <button
                    disabled={!config?.ready || !aiEnabled || !facts.length}
                    onClick={() =>
                      run(async () => {
                        setApproved(false);
                        setPlan(
                          await post(base + '/reports/' + report.id + '/assistant/prepare', {
                            task,
                            query,
                            factIds: facts,
                            includeQuotes: quotes,
                          }),
                        );
                      })
                    }
                  >
                    Pratinjau konteks sebelum kirim
                  </button>
                  {plan && (
                    <>
                      <p>
                        Provider {plan.provider} · model {plan.model} · template{' '}
                        {plan.templateVersion}. Kutipan dikecualikan:{' '}
                        {plan.excludedQuotes.join(', ') || 'tidak ada'}
                      </p>
                      <pre>
                        {plan.systemInstruction}
                        {'\n'}
                        {JSON.stringify(plan.payload, null, 2)}
                      </pre>
                      <label>
                        <input
                          type="checkbox"
                          checked={approved}
                          onChange={(e) => setApproved(e.target.checked)}
                        />
                        Saya telah membaca konteks ini dan menyetujui pengiriman ke provider
                        eksternal.
                      </label>
                      <button
                        disabled={!approved || !aiEnabled}
                        onClick={() =>
                          run(async () => {
                            setAssistant(
                              await post(base + '/assistant/plans/' + plan.id + '/execute', {
                                enabled: aiEnabled,
                                approved,
                                payloadSha256: plan.payloadSha256,
                              }),
                            );
                            setPlan(null);
                            setApproved(false);
                            await reload();
                          })
                        }
                      >
                        Kirim konteks yang disetujui
                      </button>
                    </>
                  )}
                </details>
              </article>
            )}
            <details>
              <summary>2. Bandingkan dua capture dalam kasus</summary>
              <p>
                Tidak terlihat pada B tidak berarti dihapus atau diperbaiki. Identitas berikut
                adalah pernyataan analis.
              </p>
              <div className="report-grid">
                <label>
                  Capture A
                  <select
                    aria-label="Capture A"
                    value={left}
                    onChange={(e) => setLeft(e.target.value)}
                  >
                    <option value="">Pilih A</option>
                    {captures.map((s) => (
                      <option key={s.id} value={s.id}>
                        {sourceLabel(s)}
                      </option>
                    ))}
                  </select>
                  <input
                    placeholder="Identitas A (jika diketahui)"
                    value={leftIdentity}
                    onChange={(e) => setLeftIdentity(e.target.value)}
                  />
                </label>
                <label>
                  Capture B
                  <select
                    aria-label="Capture B"
                    value={right}
                    onChange={(e) => setRight(e.target.value)}
                  >
                    <option value="">Pilih B</option>
                    {captures.map((s) => (
                      <option key={s.id} value={s.id}>
                        {sourceLabel(s)}
                      </option>
                    ))}
                  </select>
                  <input
                    placeholder="Identitas B (jika diketahui)"
                    value={rightIdentity}
                    onChange={(e) => setRightIdentity(e.target.value)}
                  />
                </label>
              </div>
              <button
                disabled={!left || !right || left === right}
                onClick={() =>
                  run(async () => {
                    setComparison(
                      await post(base + '/comparisons', {
                        leftId: left,
                        rightId: right,
                        leftIdentity,
                        rightIdentity,
                      }),
                    );
                    await reload();
                  })
                }
              >
                Bandingkan metadata capture
              </button>
              <label>
                Perbandingan tersimpan
                <select
                  value={comparison?.id || ''}
                  onChange={(e) =>
                    e.target.value &&
                    run(async () =>
                      setComparison(await api(base + '/comparisons/' + e.target.value)),
                    )
                  }
                >
                  <option value="">Pilih</option>
                  {catalog?.comparisons.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.id.slice(0, 8)} · {c.created?.at}
                    </option>
                  ))}
                </select>
              </label>
              {comparison && (
                <div data-testid="capture-comparison">
                  {comparison.context.warnings.map((w, i) => (
                    <p key={i}>{w}</p>
                  ))}
                  <details>
                    <summary>Konteks identitas, halaman, kebijakan & kegagalan</summary>
                    <pre>{JSON.stringify(comparison.context, null, 2)}</pre>
                  </details>
                  <select
                    aria-label="Filter perubahan"
                    value={changeFilter}
                    onChange={(e) => setChangeFilter(e.target.value)}
                  >
                    <option value="">Semua ({comparison.rows.length})</option>
                    {Object.entries(comparison.counts).map(([k, n]) => (
                      <option key={k} value={k}>
                        {k} ({n})
                      </option>
                    ))}
                  </select>
                  <div className="report-scroll">
                    {comparison.rows
                      .filter((r) => !changeFilter || r.change === changeFilter)
                      .map((r) => (
                        <div className="report-card" key={r.id}>
                          <b>
                            {r.kind} · {r.change}
                          </b>
                          <p>{r.label}</p>
                          <p>
                            {r.reason} · {r.confidence}
                          </p>
                          {refs(r.evidence)}
                          <details>
                            <summary>Metadata A → B</summary>
                            <pre>
                              {JSON.stringify({ before: r.before, after: r.after }, null, 2)}
                            </pre>
                          </details>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </details>
          </fieldset>
          {evidence && (
            <aside className="report-evidence" data-testid="report-evidence">
              <button className="ghost" onClick={() => setEvidence(null)}>
                Tutup bukti
              </button>
              <h4>Sumber terverifikasi · {evidence.ref.artifactId}</h4>
              <p>
                {evidence.note} · pointer {evidence.ref.pointer || 'root'}
              </p>
              <pre>{JSON.stringify(evidence.value, null, 2)}</pre>
              <a href={content(evidence.ref)} target="_blank" rel="noreferrer">
                Buka artefak sumber
              </a>
            </aside>
          )}
        </>
      )}
    </section>
  );
}
