import { useEffect, useState, useId } from 'react';
import { evidenceApi as api } from './CaseEvidence';
import { WiringExplorer } from './WiringExplorer';

const offline = ['security-assessment', 'security-review', 'manual-validation', 'forensic-import', 'forensic-parse', 'forensic-operation', 'forensic-share'];
const root = (job) => `/api/cases/${job.caseId}`;
const assessmentUrl = (job, id) => `${root(job)}/security/assessments/${id}`;
const refUrl = (r) => `/api/cases/${r.caseId}/runs/${r.runId}/artifacts/${r.artifactId}`;
const tokens = (s) =>
  s
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
function pointerValue(data, pointer) {
  if (!pointer) return data;
  return pointer
    .slice(1)
    .split('/')
    .reduce((v, k) => v?.[k.replace(/~1/g, '/').replace(/~0/g, '~')], data);
}
function Field({ label, name, value, required = true }) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        name={name}
        defaultValue={value || ''}
        required={required}
        maxLength={3000}
        rows={2}
      />
    </div>
  );
}
export function SecurityFindings({ job }) {
  const [list, setList] = useState([]),
    [assessment, setAssessment] = useState(null),
    [selected, setSelected] = useState(''),
    [status, setStatus] = useState('');
  const [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [firstParty, setFirstParty] = useState(''),
    [approved, setApproved] = useState('');
  const [runs, setRuns] = useState([]),
    [runId, setRunId] = useState(''),
    [artifacts, setArtifacts] = useState([]),
    [artifactId, setArtifactId] = useState(''),
    [pointer, setPointer] = useState('');
  const [preview, setPreview] = useState(null),
    [supporting, setSupporting] = useState([]),
    [contradicting, setContradicting] = useState([]),
    [graph, setGraph] = useState(null),
    [element, setElement] = useState(null);
  const finding = assessment?.findings.find((f) => f.id === selected);
  const active = ['queued', 'running', 'awaiting-login', 'ready', 'capturing'].includes(job.status);
  const execute = async (fn) => {
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
  const resetEvidence = () => {
    setPreview(null);
    setSupporting([]);
    setContradicting([]);
    setGraph(null);
    setElement(null);
  };
  useEffect(() => {
    let alive = true;
    setAssessment(null);
    setSelected('');
    resetEvidence();
    setError('');
    setList([]);
    setRuns([]);
    setArtifacts([]);
    setRunId('');
    setArtifactId('');
    Promise.all([api(`${root(job)}/runs/${job.id}/security/assessments`), api(`${root(job)}/runs`)])
      .then(([l, r]) => {
        if (alive) {
          setList(l);
          setRuns(r.filter((r) => !offline.includes(r.mode) && r.status !== 'running'));
        }
      })
      .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [job.id, job.caseId, job.status]);
  useEffect(() => {
    let alive = true;
    setArtifacts([]);
    setArtifactId('');
    if (runId)
      api(`${root(job)}/runs/${runId}`)
        .then((r) => alive && setArtifacts(r.artifacts))
        .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [runId, job.caseId]);
  const inspect = (ref) =>
    execute(async () => {
      const meta = await api(refUrl(ref));
      let value = 'Preview dibatasi ke JSON inert atau PNG screenshot terverifikasi.';
      if (meta.artifact.mimeType === 'application/json')
        value = pointerValue(await api(refUrl(ref) + '/content'), ref.pointer);
      if (value === undefined) throw new Error('JSON pointer tidak ditemukan dalam artefak.');
      setPreview({ ref: { ...ref, sha256: meta.artifact.sha256 }, artifact: meta.artifact, value });
    });
  const attach = (kind) => {
    const setter = kind === 'supporting' ? setSupporting : setContradicting;
    setter((prev) =>
      prev.some((r) => JSON.stringify(r) === JSON.stringify(preview.ref))
        ? prev
        : [...prev, preview.ref],
    );
  };
  const load = (id) =>
    execute(async () => {
      const a = await api(assessmentUrl(job, id));
      setAssessment(a);
      setSelected(a.findings[0]?.id || '');
      resetEvidence();
    });
  const analyze = () =>
    execute(async () => {
      const a = await api(`${root(job)}/runs/${job.id}/security/assessments`, {
        method: 'POST',
        body: JSON.stringify({
          firstPartyOrigins: tokens(firstParty),
          approvedRecipients: tokens(approved),
        }),
      });
      setAssessment(a);
      setSelected(a.findings[0]?.id || '');
      resetEvidence();
      setList(await api(`${root(job)}/runs/${job.id}/security/assessments`));
    });
  const openGraph = (related) =>
    execute(async () => {
      if (!related.extractionArtifactId)
        throw new Error('Ekstraksi halaman tidak tersedia untuk graph ini.');
      const page = await api(
        `${root(job)}/runs/${job.id}/artifacts/${related.extractionArtifactId}/content`,
      );
      setGraph({
        page: { ...page, wiring: { artifactId: related.graphArtifactId } },
        focus: related.nodeId,
      });
      setElement(null);
    });
  const submitReview = (e) => {
    e.preventDefault();
    const form = e.currentTarget,
      data = Object.fromEntries(new FormData(form));
    execute(async () => {
      const next = await api(
        `${assessmentUrl(job, assessment.id)}/findings/${finding.id}/reviews`,
        {
          method: 'POST',
          body: JSON.stringify({
            ...data,
            expectedRevision: finding.revision,
            evidenceReviewed: data.evidenceReviewed === 'on',
            supporting,
            contradicting,
          }),
        },
      );
      setAssessment(next);
      resetEvidence();
    });
  };
  const plan = (e) => {
    e.preventDefault();
    const form = e.currentTarget,
      data = Object.fromEntries(new FormData(form));
    execute(async () => {
      setAssessment(
        await api(`${assessmentUrl(job, assessment.id)}/manual-tests`, {
          method: 'POST',
          body: JSON.stringify({ ...data, parameterNames: tokens(data.parameterNames) }),
        }),
      );
      form.reset();
    });
  };
  const recordResult = (e, t) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.currentTarget));
    execute(async () => {
      setAssessment(
        await api(`${assessmentUrl(job, assessment.id)}/manual-tests/${t.id}/results`, {
          method: 'POST',
          body: JSON.stringify({
            ...data,
            expectedRevision: t.revision,
            evidence: supporting,
            comparison: data.comparison ? JSON.parse(data.comparison) : null,
          }),
        }),
      );
      resetEvidence();
    });
  };
  return (
    <section className="security-panel" aria-label="Pemeriksaan keamanan">
      <div className="security-heading">
        <div>
          <h2>Pemeriksaan keamanan</h2>
          <p>
            Analisis pasif atas bukti tersimpan. Hasil berupa observasi atau kandidat; validasi
            adalah keputusan analis.
          </p>
        </div>
        <button className="button primary" onClick={analyze} disabled={busy || active}>
          Analisis bukti
        </button>
      </div>
      <p className="security-note">
        Tidak mengirim request pengujian. Capture lama tanpa metadata header akan berstatus
        not-assessed. Ini bukan audit keamanan menyeluruh.
      </p>
      <details>
        <summary>Konteks untuk assessment baru (opsional)</summary>
        <div className="security-grid">
          <label>
            Origin first-party, satu per baris
            <textarea
              value={firstParty}
              onChange={(e) => setFirstParty(e.target.value)}
              placeholder="https://api.example.com"
            />
          </label>
          <label>
            Penerima yang disetujui, satu per baris
            <textarea
              value={approved}
              onChange={(e) => setApproved(e.target.value)}
              placeholder="https://analytics.example.com"
            />
          </label>
        </div>
        <p>
          Deklarasi analis disimpan per assessment. Domain berbeda tidak membuktikan kepemilikan
          pihak ketiga atau kebocoran.
        </p>
      </details>
      {active && <p>Selesaikan sesi/capture terlebih dahulu agar baseline dapat diverifikasi.</p>}
      {error && (
        <p role="alert" className="security-error">
          {error}
        </p>
      )}
      <label>
        Assessment tersimpan
        <select
          aria-label="Assessment tersimpan"
          value={assessment?.id || ''}
          disabled={busy}
          onChange={(e) => e.target.value && load(e.target.value)}
        >
          <option value="">Pilih assessment</option>
          {list.map((a) => (
            <option key={a.id} value={a.id}>
              {a.created.at} · engine {a.engineVersion}
            </option>
          ))}
        </select>
      </label>
      {assessment && (
        <>
          <div className="security-heading">
            <p>
              {assessment.findings.length} findings · baseline {assessment.baselineStatus} ·{' '}
              {assessment.mode}
            </p>
            <a
              className="button secondary small-button"
              href={`${assessmentUrl(job, assessment.id)}/export`}
              download
            >
              Ekspor security + manifest
            </a>
          </div>
          <p className="security-note">
            Deklarasi pada assessment ini — first-party:{' '}
            {assessment.context.firstPartyOrigins.join(', ') || 'tidak ditentukan'}; penerima
            disetujui: {assessment.context.approvedRecipients.join(', ') || 'tidak ditentukan'}.{' '}
            Kepemilikan dan persetujuan tidak diverifikasi oleh engine.
          </p>
          {assessment.limits.truncated && (
            <p role="alert">
              Batas 300 findings tercapai; counts/evaluations dalam ekspor mencatat hasil lain.
            </p>
          )}
          <details className="security-coverage">
            <summary>
              Cakupan {assessment.results.length} rule dan bukti yang belum tersedia
            </summary>
            {assessment.results.map((r) => (
              <article key={r.id}>
                <b>
                  {r.id} v{r.version} · {r.title}
                </b>
                <p>Input: {r.input}</p>
                <p>
                  {Object.entries(r.counts)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(' · ')}
                </p>
                {r.notAssessedReasons.map((s) => (
                  <p key={s}>not-assessed: {s}</p>
                ))}
                <p>{r.exceptions.join('; ')}</p>
                <div>
                  {r.sources.map((s, i) => (
                    <a key={s} href={s} target="_blank" rel="noreferrer">
                      Rujukan {i + 1}{' '}
                    </a>
                  ))}
                </div>
              </article>
            ))}
          </details>
          <div className="security-layout">
            <div>
              <label>
                Filter status
                <select value={status} onChange={(e) => setStatus(e.target.value)}>
                  <option value="">Semua</option>
                  {['observation', 'candidate', 'validated', 'dismissed'].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </label>
              <div className="security-list">
                {assessment.findings
                  .filter((f) => !status || f.status === status)
                  .map((f) => (
                    <button
                      key={f.id}
                      className={selected === f.id ? 'selected' : ''}
                      onClick={() => {
                        setSelected(f.id);
                        resetEvidence();
                      }}
                    >
                      <strong>
                        {f.ruleId} · {f.status}
                      </strong>
                      <span>
                        Risk {f.risk} · confidence {f.confidence}
                      </span>
                      <span>{f.reason}</span>
                    </button>
                  ))}
              </div>
            </div>
            <div className="security-detail">
              {finding ? (
                <>
                  <h3>{finding.title}</h3>
                  <p>{finding.reason}</p>
                  <dl>
                    <dt>Dampak</dt>
                    <dd>{finding.impact}</dd>
                    <dt>Prasyarat</dt>
                    <dd>{finding.prerequisites}</dd>
                    <dt>Perbaikan</dt>
                    <dd>{finding.recommendation}</dd>
                    <dt>Batas keyakinan</dt>
                    <dd>{finding.limitations.join('; ')}</dd>
                  </dl>
                  {finding.cwe.map((c) => (
                    <p key={c.id}>
                      {c.id} bersyarat: {c.condition}
                    </p>
                  ))}
                  <div className="security-actions">
                    {finding.evidence.map((r, i) => (
                      <button key={i} onClick={() => inspect(r)} disabled={busy}>
                        Tinjau bukti request {i + 1}
                      </button>
                    ))}
                    {finding.related.map((r, i) => (
                      <button key={i} onClick={() => openGraph(r)} disabled={busy}>
                        Buka wiring {i + 1}
                      </button>
                    ))}
                  </div>
                  {!finding.related.length && (
                    <p>
                      Tidak ada graph yang mereferensikan request ini; relasi elemen tetap unknown.
                    </p>
                  )}
                </>
              ) : (
                <p>
                  Tidak ada finding untuk assessment ini. Lihat cakupan/not-assessed; hasil kosong
                  tidak membuktikan website aman.
                </p>
              )}
            </div>
          </div>
          <details open={!!preview} className="security-evidence">
            <summary>Evidence reader & pemilihan bukti pendukung/penyangkal</summary>
            <p>
              Hanya artefak dalam kasus ini. Pratinjau memverifikasi integritas; JSON ditampilkan
              sebagai teks, aset aktif tidak dieksekusi.
            </p>
            <div className="security-grid">
              <label>
                Run capture
                <select value={runId} onChange={(e) => setRunId(e.target.value)}>
                  <option value="">Pilih run</option>
                  {runs.map((r) => (
                    <option value={r.id} key={r.id}>
                      {r.id.slice(0, 8)} · {r.mode} · {r.started.at}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Artefak
                <select value={artifactId} onChange={(e) => setArtifactId(e.target.value)}>
                  <option value="">Pilih artefak</option>
                  {artifacts.map((a) => (
                    <option value={a.id} key={a.id}>
                      {a.kind} · {a.id.slice(0, 8)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                JSON pointer (opsional)
                <input
                  value={pointer}
                  onChange={(e) => setPointer(e.target.value)}
                  placeholder="/requests/0"
                  maxLength={500}
                />
              </label>
            </div>
            <button
              disabled={!artifactId || busy}
              onClick={() => inspect({ caseId: job.caseId, runId, artifactId, pointer })}
            >
              Buka artefak terpilih
            </button>
            {preview && (
              <div>
                <p>
                  <b>Hash terverifikasi</b> · {preview.artifact.kind}
                </p>
                <code className="security-hash">{preview.artifact.sha256}</code>
                <p>
                  Sumber: {preview.artifact.source} · {preview.ref.pointer || '(seluruh artefak)'}
                </p>
                {preview.artifact.mimeType === 'image/png' ? (
                  <img
                    className="security-preview"
                    alt="Screenshot bukti terverifikasi"
                    src={refUrl(preview.ref) + '/content'}
                  />
                ) : (
                  <pre data-testid="security-evidence-preview">
                    {JSON.stringify(preview.value, null, 2)?.slice(0, 18000)}
                    {JSON.stringify(preview.value)?.length > 18000
                      ? '\n[Pratinjau dipotong; unduh artefak untuk isi lengkap]'
                      : ''}
                  </pre>
                )}
                <a href={refUrl(preview.ref) + '/content'} target="_blank" rel="noreferrer">
                  Buka sumber terverifikasi
                </a>
                <div className="security-actions">
                  <button onClick={() => attach('supporting')}>Gunakan sebagai pendukung</button>
                  <button onClick={() => attach('contradicting')}>
                    Gunakan sebagai penyangkal
                  </button>
                </div>
              </div>
            )}
            <p>
              Pendukung: {supporting.length} · Penyangkal: {contradicting.length}{' '}
              <button
                onClick={() => {
                  setSupporting([]);
                  setContradicting([]);
                }}
              >
                Kosongkan pilihan
              </button>
            </p>
            <details>
              <summary>Reference terpilih (untuk perbandingan identitas)</summary>
              <pre>{JSON.stringify(supporting, null, 2)}</pre>
            </details>
          </details>
          {graph && (
            <div className="security-wiring">
              <button onClick={() => setGraph(null)}>Tutup wiring</button>
              <WiringExplorer
                job={job}
                page={graph.page}
                element={element}
                initialFocus={graph.focus}
                onElementSelect={(id) =>
                  setElement(graph.page.elements.find((e) => e.id === id) || null)
                }
                onPageSelect={() => {}}
              />
            </div>
          )}
          {finding && (
            <details className="security-review">
              <summary>
                Review manual · {finding.status} · revisi {finding.revision}
              </summary>
              <form
                key={`${assessment.id}:${finding.id}:${finding.revision}`}
                onSubmit={submitReview}
              >
                <p>
                  Identitas reviewer adalah pernyataan lokal. Jangan masukkan password, token atau
                  nilai payload ke catatan. Dismissal perlu bukti penyangkal; keputusan lain perlu
                  bukti pendukung.
                </p>
                <div className="security-grid">
                  <label>
                    Reviewer
                    <input name="reviewer" required maxLength={160} />
                  </label>
                  <label>
                    Status baru
                    <select name="status">
                      {{
                        observation: ['candidate', 'dismissed'],
                        candidate: ['validated', 'dismissed'],
                        validated: ['candidate'],
                        dismissed: ['candidate'],
                      }[finding.status].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Risk
                    <select name="risk" defaultValue={finding.risk}>
                      {['info', 'low', 'medium', 'high'].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Confidence
                    <select name="confidence" defaultValue={finding.confidence}>
                      {['low', 'medium', 'high'].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Jenis klaim
                    <select name="claimType">
                      <option value="configuration">Konfigurasi</option>
                      <option value="exposure">Paparan data</option>
                      <option value="authorization">Otorisasi lintas identitas</option>
                    </select>
                  </label>
                  <label>
                    Hasil skenario terkait
                    <select name="manualTestId">
                      <option value="">Tidak ada</option>
                      {assessment.manualTests
                        .filter((t) => t.status === 'completed')
                        .map((t) => (
                          <option key={t.id} value={t.id}>
                            {t.title}
                          </option>
                        ))}
                    </select>
                  </label>
                </div>
                <Field name="reason" label="Alasan perubahan status" />
                <Field name="impact" label="Dampak yang dinilai" value={finding.impact} />
                <Field
                  name="prerequisites"
                  label="Prasyarat validasi"
                  value={finding.prerequisites}
                />
                <Field name="recommendation" label="Rekomendasi" value={finding.recommendation} />
                <Field
                  name="limitations"
                  label="Keterbatasan validasi"
                  value={finding.limitations.join('; ')}
                />
                <label className="security-check">
                  <input type="checkbox" name="evidenceReviewed" required /> Saya telah meninjau
                  artefak sumber dan menjelaskan bukti pendukung/penyangkal.
                </label>
                <button
                  className="button primary"
                  disabled={busy || !(supporting.length || contradicting.length)}
                >
                  Simpan review
                </button>
              </form>
              <details>
                <summary>Riwayat keputusan</summary>
                {finding.history.map((h, i) => (
                  <article key={i}>
                    <b>
                      {h.from} → {h.to}
                    </b>
                    <p>
                      {h.reviewer || h.actor} · {h.time?.at} · {h.reason}
                    </p>
                    {[...(h.supporting || []), ...(h.contradicting || [])].map((r, i) => (
                      <button key={i} onClick={() => inspect(r)}>
                        Tinjau bukti riwayat {i + 1}
                      </button>
                    ))}
                  </article>
                ))}
              </details>
            </details>
          )}
          <details className="security-tests">
            <summary>Skenario validasi manual ({assessment.manualTests.length})</summary>
            <p>
              Fitur ini mencatat rencana dan hasil; tidak menjalankan request. Aktivitas manual di
              luar analisis wajib direkam pada run capture baru. Kepemilikan akun bukan izin menguji
              platform pihak ketiga.
            </p>
            <form onSubmit={plan}>
              <div className="security-grid">
                <label>
                  Judul skenario
                  <input name="title" required maxLength={160} />
                </label>
                <label>
                  Operator
                  <input name="operator" required maxLength={160} />
                </label>
                <label>
                  Jenis
                  <select name="kind">
                    <option value="evidence-review">Review bukti tersimpan</option>
                    <option value="external-manual">Aktivitas manual terpisah</option>
                    <option value="authorization-comparison">Perbandingan identitas/role</option>
                  </select>
                </label>
                <label>
                  Nama parameter, tanpa nilai
                  <input name="parameterNames" placeholder="objectId, role" />
                </label>
              </div>
              <Field name="objective" label="Tujuan skenario" />
              <Field name="steps" label="Langkah yang direncanakan" />
              <Field name="expectedBehavior" label="Hasil yang diharapkan" />
              <Field name="knownImpact" label="Dampak yang diketahui" />
              <button disabled={busy}>Simpan rencana manual</button>
            </form>
            {assessment.manualTests.map((t) => (
              <article key={t.id}>
                <h3>
                  {t.title} · {t.status}
                </h3>
                <p>
                  {t.objective} · {t.operator} · {t.time.at}
                </p>
                <p>{t.steps}</p>
                <p>
                  Parameter: {t.parameterNames.join(', ') || 'tidak ada'} · Dampak: {t.knownImpact}
                </p>
                {t.result && <p>Hasil: {t.result}</p>}
                {t.comparison && <pre>{JSON.stringify(t.comparison, null, 2)}</pre>}
                {t.status === 'planned' && (
                  <form onSubmit={(e) => recordResult(e, t)}>
                    <label>
                      Keputusan
                      <select aria-label="Keputusan" name="status">
                        <option>completed</option>
                        <option>cancelled</option>
                      </select>
                    </label>
                    <label>
                      Reviewer hasil
                      <input name="operator" required maxLength={160} />
                    </label>
                    <Field name="result" label="Hasil atau alasan pembatalan" />
                    <Field name="knownImpact" label="Dampak teramati" />
                    <p>
                      Hasil menggunakan {supporting.length} bukti pendukung yang dipilih di Evidence
                      reader.
                    </p>
                    {t.kind === 'authorization-comparison' && (
                      <>
                        <p>
                          Isi objek, pemilik, kebijakan, interpretasi selain perbedaan HTTP, serta
                          bukti per identitas. Gunakan reference dari capture pengujian terpisah.
                        </p>
                        <Field
                          name="comparison"
                          label="Perbandingan identitas (JSON)"
                          required={false}
                          value={JSON.stringify(
                            {
                              object: '',
                              ownerIdentity: 'owner',
                              expectedPolicy: '',
                              interpretation: '',
                              identities: [
                                {
                                  id: 'owner',
                                  role: '',
                                  expectedAccess: '',
                                  actualAccess: '',
                                  evidence: [],
                                },
                                {
                                  id: 'other',
                                  role: '',
                                  expectedAccess: '',
                                  actualAccess: '',
                                  evidence: [],
                                },
                              ],
                            },
                            null,
                            2,
                          )}
                        />
                      </>
                    )}
                    <button disabled={busy}>Catat hasil manual</button>
                  </form>
                )}
              </article>
            ))}
          </details>
        </>
      )}
    </section>
  );
}
