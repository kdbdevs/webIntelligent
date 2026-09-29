import { randomUUID } from 'node:crypto';
import { fail, stamp, digest, validId, isOfflineMode, COLLECTOR } from './evidence.mjs';
import { atPointer } from './security.mjs';
export const REPORT_VERSION = '1.0.0';
export const REPORT_MODES = [
  'case-report',
  'capture-comparison',
  'analysis-assistant',
  'report-export',
];
export const REPORT_LIMITS = {
  sources: 12,
  readBytes: 64 * 1024 * 1024,
  snapshotBytes: 4 * 1024 * 1024,
  timeline: 500,
  cards: 700,
  comparisonRows: 2000,
  records: 200,
  originalBytes: 8 * 1024 * 1024,
  packageBytes: 16 * 1024 * 1024,
};
export const INTEGRITY_NOTE =
  'Hashes verify the included bytes against a local baseline. They do not attest authenticity, historical completeness, host clock, administrator integrity or legal admissibility.';
export function short(v, n = 1000) {
  return String(v ?? '').slice(0, n);
}
export function required(v, label, max = 2000) {
  if (typeof v !== 'string' || !v.trim() || v.length > max)
    throw fail(`${label} wajib diisi (maks. ${max}).`);
  return v.trim();
}
export function uniqueIds(ids, max = REPORT_LIMITS.sources) {
  if (!Array.isArray(ids) || !ids.length || ids.length > max || new Set(ids).size !== ids.length)
    throw fail(`Pilih 1–${max} ID unik.`);
  ids.forEach(validId);
  return ids;
}
export function refOf(caseId, runId, a, pointer = '') {
  return { caseId, runId, artifactId: a.id, sha256: a.sha256, pointer };
}
export class EvidenceReader {
  constructor(store, caseId) {
    this.store = store;
    this.caseId = caseId;
    store.getCase(caseId);
    this.cache = new Map();
    this.parsed = new Map();
    this.deadline = Date.now() + 15000;
    this.checked = new Set();
    this.used = 0;
  }
  find(id) {
    validId(id);
    for (const run of this.store.listRuns(this.caseId)) {
      const artifact = this.store.artifacts(this.caseId, run.id).find((a) => a.id === id);
      if (artifact) return { run, artifact, ref: refOf(this.caseId, run.id, artifact) };
    }
    throw fail('Artefak tidak ditemukan dalam kasus ini.', 404);
  }
  verifyRun(run) {
    if (run.status === 'running') throw fail('Selesaikan run dahulu.', 409);
    if (!this.checked.has(run.id)) {
      if (!this.store.verifyRun(this.caseId, run.id).ok)
        throw fail('Integritas sumber gagal.', 409);
      this.checked.add(run.id);
    }
  }
  read(ref) {
    if (Date.now() > this.deadline)
      throw fail('Batas waktu analisis 15 detik; kurangi sumber.', 413);
    if (ref?.caseId !== this.caseId) throw fail('Referensi lintas kasus ditolak.');
    const run = this.store.getRun(this.caseId, ref.runId);
    this.verifyRun(run);
    const a = this.store.artifact(this.caseId, run.id, ref.artifactId);
    if (ref.sha256 && ref.sha256 !== a.sha256) throw fail('Hash referensi tidak cocok.', 409);
    let bytes = this.cache.get(a.id);
    if (!bytes) {
      if (this.used + a.size > REPORT_LIMITS.readBytes)
        throw fail('Batas pembacaan 64 MiB; pilih lebih sedikit sumber.', 413);
      bytes = this.store.readArtifact(this.caseId, run.id, a.id, { log: false });
      this.used += bytes.length;
      this.cache.set(a.id, bytes);
    }
    return { artifact: a, run, bytes, ref: refOf(this.caseId, run.id, a, ref.pointer || '') };
  }
  json(ref) {
    const r = this.read(ref);
    if (r.artifact.mimeType !== 'application/json') throw fail('Referensi JSON diperlukan.');
    if (!this.parsed.has(r.artifact.id)) this.parsed.set(r.artifact.id, JSON.parse(r.bytes));
    return this.parsed.get(r.artifact.id);
  }
  reference(ref) {
    const r = this.read(ref);
    if (r.ref.pointer) {
      if (r.artifact.mimeType !== 'application/json') throw fail('Pointer hanya untuk JSON.');
      atPointer(this.json(ref), r.ref.pointer);
    }
    return r.ref;
  }
  value(ref) {
    const r = this.read(ref);
    return r.ref.pointer
      ? atPointer(this.json(ref), r.ref.pointer)
      : r.artifact.mimeType === 'application/json'
        ? this.json(ref)
        : null;
  }
}
export function saveRecord(
  store,
  caseId,
  mode,
  body,
  { parentRunId = null, config = {}, files = [] } = {},
) {
  if (!REPORT_MODES.includes(mode)) throw fail('Mode record tidak didukung.');
  if (
    store.listRuns(caseId).filter((r) => REPORT_MODES.includes(r.mode)).length >=
    REPORT_LIMITS.records
  )
    throw fail('Batas 200 record pelaporan per kasus.', 413);
  if (Buffer.byteLength(JSON.stringify(body)) > REPORT_LIMITS.snapshotBytes)
    throw fail('Snapshot melebihi 4 MiB; kurangi sumber.', 413);
  return store.transaction(() => {
    const c = store.getCase(caseId);
    const run = store.createRun(caseId, {
      mode,
      url: c.scope.navigation[0],
      parentRunId,
      config: {
        ...config,
        recordId: body.id,
        reportVersion: REPORT_VERSION,
        networkActivity: body.networkActivity || 'none',
      },
    });
    const a = store.addArtifact(caseId, run.id, JSON.stringify(body), {
      kind: mode,
      role: 'extracted',
      label: mode,
      source: `analysis:${run.id}`,
      method: 'versioned-case-reporting',
      mimeType: 'application/json',
      redaction:
        'Private encrypted analysis snapshot; sharing uses a separate strict redacted projection',
    });
    const outputs = files.map((f) => {
      const b = store.addArtifact(caseId, run.id, f.bytes, {
        kind: f.kind,
        role: f.role || 'redacted',
        label: f.kind,
        source: `report:${body.reportId || body.id}`,
        method: 'explicit-report-export',
        mimeType: f.mimeType,
        derivedFrom: [a.id],
        redaction:
          f.redaction || 'Structural sharing copy; originals and private source values excluded',
      });
      return refOf(caseId, run.id, b);
    });
    store.seal({
      id: run.id,
      caseId,
      mode,
      url: run.url,
      status: 'complete',
      pages: [],
      requests: [],
      events: [],
      edges: [],
      warnings: [],
      createdAt: run.started.at,
      analysis: {
        recordRef: refOf(caseId, run.id, a),
        outputRefs: outputs,
        networkActivity: body.networkActivity || 'none',
        privacy: {
          note: 'Encrypted private analysis; export originals only through explicit encrypted package. Model receives only approved bounded context.',
        },
        actions: [
          'Frozen verified evidence snapshot or explicit analyst review; source artifacts unchanged',
          ...(body.networkActivity === 'external-model'
            ? [
                'Explicit reviewed bounded context sent to configured provider; no tools or active target requests',
              ]
            : ['No target network activity; local deterministic analysis/rendering']),
        ],
      },
    });
    return { ...body, recordRef: refOf(caseId, run.id, a), outputs };
  });
}
export function loadRecord(store, caseId, id, mode) {
  validId(id);
  const run = store.listRuns(caseId).find((r) => r.mode === mode && r.config.recordId === id);
  if (!run) throw fail('Record tidak ditemukan dalam kasus ini.', 404);
  const reader = new EvidenceReader(store, caseId);
  const a = store.artifacts(caseId, run.id).find((a) => a.kind === mode);
  if (!a) throw fail('Record tidak lengkap.', 409);
  const ref = refOf(caseId, run.id, a);
  const data = reader.json(ref);
  return { ...data, recordRef: ref };
}
export function stampRecord(data) {
  return {
    schemaVersion: 1,
    id: randomUUID(),
    created: stamp(),
    engine: { name: 'WebIntelligent Reporting', version: REPORT_VERSION, collector: COLLECTOR },
    ...data,
  };
}
export function verifyRefs(reader, refs) {
  return refs.map((r) => reader.reference(r));
}
export function uniqueRefs(refs) {
  return [
    ...new Map(refs.map((r) => [`${r.runId}:${r.artifactId}:${r.pointer || ''}`, r])).values(),
  ];
}
export function captureData(reader, id) {
  const { artifact: a, run, ref } = reader.find(id);
  if (isOfflineMode(run.mode) || !['run-report', 'page-extraction'].includes(a.kind))
    throw fail('Pilih artefak capture browser.');
  const data = reader.json(ref);
  let pages,
    requests,
    requestRef = ref,
    report;
  if (a.kind === 'run-report') {
    report = data;
    pages = data.pages || [];
    requests = data.requests || [];
  } else {
    report = reader.json(
      refOf(
        reader.caseId,
        run.id,
        reader.store.artifact(reader.caseId, run.id, run.reportArtifactId),
      ),
    );
    pages = [data];
    const match = reader.store
      .artifacts(reader.caseId, run.id)
      .filter((a) => a.kind === 'capture-observations')
      .find((a) => reader.json(refOf(reader.caseId, run.id, a)).captureId === data.captureId);
    if (match) {
      requestRef = refOf(reader.caseId, run.id, match);
      requests = reader.json(requestRef).requests || [];
    } else requests = [];
  }
  const pageRef = (i) => ({ ...ref, pointer: a.kind === 'page-extraction' ? '' : `/pages/${i}` });
  return {
    run,
    ref,
    artifact: a,
    pages,
    requests,
    requestRef,
    pageRef,
    report,
    coverage: {
      mode: run.mode,
      status: run.status,
      scope: run.scope,
      policy: report.sessionInfo?.policy || run.config,
      identity: 'Unknown; collector context is not a proven user identity',
      session: report.sessionInfo
        ? { readiness: report.sessionInfo.readiness, authSignal: report.sessionInfo.authSignal }
        : null,
      visited: pages.map((p) => p.url),
      failedRequests: requests.filter((r) => r.failure || r.blocked || !r.status || r.status >= 400)
        .length,
      warnings: [...(report.warnings || []), ...pages.flatMap((p) => p.warnings || [])].map((v) =>
        short(v),
      ),
      legacy: !!run.legacy,
      byteComparison: 'Asset/response bytes are not archived; metadata comparison only',
    },
  };
}
