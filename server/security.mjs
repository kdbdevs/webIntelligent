import { randomUUID } from 'node:crypto';
import { fail, stamp, validId, OFFLINE_MODES } from './evidence.mjs';
import { ENGINE_VERSION, runRules, urlOf } from './security-rules.mjs';

export { OFFLINE_MODES };
const text = (v, name, max = 3000, required = true) => {
  if (typeof v !== 'string' || v.length > max || (required && !v.trim()))
    throw fail(`${name} wajib diisi (maks. ${max} karakter).`);
  return v.trim();
};
export function atPointer(value, pointer = '') {
  if (pointer === '') return value;
  if (typeof pointer !== 'string' || pointer.length > 500 || !pointer.startsWith('/'))
    throw fail('Evidence pointer tidak valid.');
  for (const part of pointer.slice(1).split('/')) {
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, key))
      throw fail('Evidence pointer tidak ditemukan.');
    value = value[key];
  }
  return value;
}
const origins = (input) => {
  if (!Array.isArray(input) || input.length > 30) throw fail('Maks. 30 deklarasi origin.');
  return [
    ...new Set(
      input.map((v) => {
        const u = urlOf(v);
        if (
          typeof v !== 'string' ||
          v.length > 300 ||
          !u ||
          u.username ||
          u.password ||
          u.search ||
          u.hash ||
          u.pathname !== '/'
        )
          throw fail('Gunakan origin HTTP(S) tanpa path, kredensial atau query.');
        return u.origin;
      }),
    ),
  ];
};
export class SecurityService {
  constructor(store) {
    this.store = store;
  }
  verified(caseId, runId) {
    const run = this.store.getRun(caseId, runId);
    if (run.status === 'running') throw fail('Selesaikan run sebelum analisis/review.', 409);
    if (!this.store.verifyRun(caseId, runId).ok)
      throw fail('Integritas bukti gagal; analisis/review/ekspor diblokir.', 409);
    return run;
  }
  reference(caseId, ref, { captureOnly = true } = {}) {
    if (!ref || ref.caseId !== caseId) throw fail('Evidence harus berasal dari kasus yang sama.');
    const run = this.store.getRun(caseId, ref.runId);
    if (run.status === 'running' || (captureOnly && OFFLINE_MODES.includes(run.mode)))
      throw fail('Gunakan bukti capture yang sudah disegel.');
    const artifact = this.store.artifact(caseId, ref.runId, ref.artifactId);
    const bytes = this.store.readArtifact(caseId, ref.runId, ref.artifactId, { log: false });
    const pointer = ref.pointer || '';
    if (pointer) {
      if (artifact.mimeType !== 'application/json') throw fail('Pointer hanya untuk JSON.');
      atPointer(JSON.parse(bytes), pointer);
    }
    if (ref.sha256 && ref.sha256 !== artifact.sha256)
      throw fail('Evidence baseline hash tidak cocok.', 409);
    return { caseId, runId: ref.runId, artifactId: artifact.id, pointer, sha256: artifact.sha256 };
  }
  refs(caseId, refs, required = false) {
    if (!Array.isArray(refs) || refs.length > 20 || (required && !refs.length))
      throw fail('Pilih 1–20 evidence reference yang relevan.');
    return refs.map((ref) => this.reference(caseId, ref));
  }
  record(caseId, baselineId, mode, body, config = {}) {
    return this.store.transaction(() => {
      const c = this.store.getCase(caseId);
      const run = this.store.createRun(caseId, {
        mode,
        url: c.scope.navigation[0],
        parentRunId: baselineId,
        config: {
          ...config,
          baselineRunId: baselineId,
          engineVersion: ENGINE_VERSION,
          networkActivity: 'none',
        },
      });
      const artifact = this.store.addArtifact(caseId, run.id, JSON.stringify(body), {
        kind: mode,
        role: 'extracted',
        label: `${mode} · ${body.id || body.findingId}`,
        source: `run:${baselineId}`,
        mimeType: 'application/json',
        method: 'offline-evidence-analysis-or-analyst-declaration',
        redaction:
          'No payload/token/cookie values acquired; analyst notes are encrypted at rest. Never paste secrets into notes.',
      });
      this.store.seal({
        id: run.id,
        caseId,
        mode,
        status: 'complete',
        url: run.url,
        pages: [],
        requests: [],
        events: [],
        edges: [],
        warnings: [],
        analysis: {
          recordArtifactId: artifact.id,
          baselineRunId: baselineId,
          networkActivity: 'none',
          kind: mode,
        },
        createdAt: run.started.at,
      });
      return { runId: run.id, artifactId: artifact.id, sha256: artifact.sha256 };
    });
  }
  readRecord(caseId, run, kind = run.mode) {
    this.verified(caseId, run.id);
    const artifact = this.store.artifacts(caseId, run.id).find((a) => a.kind === kind);
    if (!artifact) throw fail('Record analisis tidak tersedia.', 409);
    return {
      ...JSON.parse(this.store.readArtifact(caseId, run.id, artifact.id, { log: false })),
      record: { runId: run.id, artifactId: artifact.id, sha256: artifact.sha256 },
    };
  }
  list(caseId, baselineId) {
    this.store.getRun(caseId, baselineId);
    return this.store
      .listRuns(caseId)
      .filter((r) => r.mode === 'security-assessment' && r.parentRunId === baselineId)
      .map((r) => ({
        id: r.config.assessmentId,
        runId: r.id,
        created: r.started,
        engineVersion: r.config.engineVersion,
      }));
  }
  assess(caseId, baselineId, input = {}) {
    const baseline = this.verified(caseId, baselineId);
    if (OFFLINE_MODES.includes(baseline.mode)) throw fail('Pilih run capture sebagai baseline.');
    if (this.list(caseId, baselineId).length >= 30)
      throw fail('Batas 30 assessment per baseline tercapai.', 413);
    const context = {
      firstPartyOrigins: origins(input.firstPartyOrigins || []),
      approvedRecipients: origins(input.approvedRecipients || []),
      declaration: 'Analyst supplied; ownership and consent not verified',
    };
    const artifacts = this.store.artifacts(caseId, baselineId),
      requests = [],
      seen = new Set(),
      refs = [];
    const read = (a) =>
      JSON.parse(this.store.readArtifact(caseId, baselineId, a.id, { log: false }));
    const graphArtifacts = artifacts.filter((a) => a.kind === 'wiring-graph');
    const graphs = graphArtifacts.map((a) => ({ artifact: a, value: read(a) }));
    const captures = artifacts.filter((a) => a.kind === 'capture-observations').reverse();
    const report = artifacts.find((a) => a.id === baseline.reportArtifactId);
    for (const a of [...captures, ...(report ? [report] : [])]) {
      const data = read(a);
      refs.push({ caseId, runId: baselineId, artifactId: a.id, pointer: '', sha256: a.sha256 });
      for (const [index, r] of (data.requests || []).entries()) {
        if (requests.length >= 1500 || seen.has(r.id)) continue;
        seen.add(r.id);
        const related = [];
        for (const g of graphs) {
          if (data.captureId && g.value.captureId !== data.captureId) continue;
          const node = g.value.nodes.find((n) => n.type === 'request' && n.details?.id === r.id);
          if (node)
            related.push({
              graphArtifactId: g.artifact.id,
              nodeId: node.id,
              captureId: g.value.captureId,
              extractionArtifactId:
                artifacts.find(
                  (a) => a.kind === 'page-extraction' && g.artifact.derivedFrom.includes(a.id),
                )?.id || null,
            });
        }
        requests.push({
          ...r,
          evidenceRef: {
            caseId,
            runId: baselineId,
            artifactId: a.id,
            pointer: `/requests/${index}`,
            sha256: a.sha256,
          },
          related: related.slice(0, 10),
        });
      }
    }
    const assessment = {
      id: randomUUID(),
      schemaVersion: 1,
      caseId,
      baselineRunId: baselineId,
      created: stamp(),
      mode: 'passive-offline',
      context,
      inputArtifacts: refs,
      baselineStatus: baseline.status,
      baselinePartialReason: baseline.partialReason,
      ...runRules(requests, context),
      limitations: [
        'Not a comprehensive security audit',
        'Only selected response headers/attributes and parameter metadata; values and response bodies omitted',
        'Hashes/local history establish a baseline, not authenticity, trusted time or protection from host administrator tampering',
      ],
    };
    assessment.findings.forEach((f) => f.history.forEach((h) => (h.time = assessment.created)));
    this.record(caseId, baselineId, 'security-assessment', assessment, {
      assessmentId: assessment.id,
    });
    return this.get(caseId, assessment.id);
  }
  get(caseId, id) {
    validId(id);
    const runs = this.store.listRuns(caseId);
    const run = runs.find((r) => r.mode === 'security-assessment' && r.config.assessmentId === id);
    if (!run) throw fail('Assessment tidak ditemukan dalam kasus ini.', 404);
    const assessment = this.readRecord(caseId, run);
    this.verified(caseId, assessment.baselineRunId);
    const reviews = runs
      .filter((r) => r.mode === 'security-review' && r.config.assessmentId === id)
      .reverse()
      .map((r) => this.readRecord(caseId, r));
    const tests = runs
      .filter((r) => r.mode === 'manual-validation' && r.config.assessmentId === id)
      .reverse()
      .map((r) => this.readRecord(caseId, r));
    for (const review of reviews) {
      const f = assessment.findings.find((f) => f.id === review.findingId);
      if (!f || f.revision !== review.expectedRevision)
        throw fail('Riwayat review tidak konsisten.', 409);
      for (const ref of [...review.supporting, ...review.contradicting])
        this.reference(caseId, ref);
      Object.assign(f, review.decision, { revision: f.revision + 1 });
      f.history.push(review);
    }
    assessment.manualTests = [];
    for (const record of tests) {
      for (const ref of record.evidence || []) this.reference(caseId, ref);
      for (const identity of record.comparison?.identities || [])
        for (const ref of identity.evidence) this.reference(caseId, ref);
      const previous = assessment.manualTests.find((t) => t.id === record.id);
      if (previous) {
        if (record.revision !== previous.revision + 1)
          throw fail('Riwayat skenario tidak konsisten.', 409);
        Object.assign(previous, record, { history: [...previous.history, record] });
      } else assessment.manualTests.push({ ...record, history: [record] });
    }
    assessment.recordRuns = [
      run.id,
      ...reviews.map((r) => r.record.runId),
      ...tests.map((r) => r.record.runId),
    ];
    return assessment;
  }
  review(caseId, id, findingId, input) {
    const a = this.get(caseId, id),
      f = a.findings.find((f) => f.id === findingId);
    if (!f) throw fail('Finding tidak ditemukan.', 404);
    if (input.expectedRevision !== f.revision)
      throw fail('Review berubah; muat ulang sebelum menyimpan.', 409);
    if (f.revision >= 50) throw fail('Batas 50 review per finding tercapai.', 413);
    const allowed = {
      observation: ['candidate', 'dismissed'],
      candidate: ['validated', 'dismissed'],
      validated: ['candidate'],
      dismissed: ['candidate'],
    };
    if (!allowed[f.status]?.includes(input.status))
      throw fail('Transisi status tidak diizinkan. Validasi harus melewati candidate.');
    if (input.evidenceReviewed !== true)
      throw fail('Tinjau artefak sumber dan konfirmasi pemeriksaan bukti terlebih dahulu.');
    const supporting = this.refs(caseId, input.supporting || [], input.status !== 'dismissed'),
      contradicting = this.refs(caseId, input.contradicting || [], input.status === 'dismissed');
    if (
      !['info', 'low', 'medium', 'high'].includes(input.risk) ||
      !['low', 'medium', 'high'].includes(input.confidence)
    )
      throw fail('Risk/confidence tidak valid.');
    const claimType = input.claimType || 'configuration';
    if (!['configuration', 'exposure', 'authorization'].includes(claimType))
      throw fail('Jenis klaim tidak valid.');
    if (
      input.manualTestId &&
      !a.manualTests.some((t) => t.id === input.manualTestId && t.status === 'completed')
    )
      throw fail('Hasil skenario harus completed dan berasal dari assessment ini.');
    if (input.status === 'validated' && claimType === 'authorization') {
      const comparison = a.manualTests.find(
        (t) => t.id === input.manualTestId && t.status === 'completed' && t.comparison,
      );
      if (!comparison)
        throw fail(
          'Validasi otorisasi memerlukan hasil perbandingan identitas, objek, kebijakan akses dan bukti per identitas.',
        );
    }
    const record = {
      findingId,
      assessmentId: id,
      expectedRevision: f.revision,
      from: f.status,
      to: input.status,
      reviewer: text(input.reviewer, 'Reviewer', 160),
      reason: text(input.reason, 'Alasan'),
      time: stamp(),
      supporting,
      contradicting,
      manualTestId: input.manualTestId || null,
      decision: {
        status: input.status,
        risk: input.risk,
        confidence: input.confidence,
        claimType,
        impact: text(input.impact, 'Dampak'),
        prerequisites: text(input.prerequisites, 'Prasyarat'),
        recommendation: text(input.recommendation, 'Perbaikan'),
        limitations: [text(input.limitations, 'Batas validasi')],
      },
      reviewerIdentity: 'Self-declared local analyst; not independently authenticated',
      evidenceReviewed: true,
    };
    this.record(caseId, a.baselineRunId, 'security-review', record, {
      assessmentId: id,
      findingId,
    });
    return this.get(caseId, id);
  }
  plan(caseId, id, input) {
    const a = this.get(caseId, id);
    if (a.manualTests.length >= 30) throw fail('Batas 30 skenario per assessment.', 413);
    if (!['evidence-review', 'external-manual', 'authorization-comparison'].includes(input.kind))
      throw fail('Jenis skenario tidak valid.');
    const names = input.parameterNames || [];
    if (
      !Array.isArray(names) ||
      names.length > 30 ||
      names.some((n) => typeof n !== 'string' || !/^[\w.[\]-]{1,80}$/.test(n))
    )
      throw fail('Parameter skenario hanya nama, tanpa nilai.');
    const plan = {
      id: randomUUID(),
      assessmentId: id,
      revision: 0,
      status: 'planned',
      kind: input.kind,
      title: text(input.title, 'Judul', 160),
      objective: text(input.objective, 'Tujuan'),
      steps: text(input.steps, 'Langkah'),
      expectedBehavior: text(input.expectedBehavior, 'Perilaku yang diharapkan'),
      knownImpact: text(input.knownImpact, 'Dampak yang diketahui'),
      operator: text(input.operator, 'Operator', 160),
      parameterNames: names,
      time: stamp(),
      scope: this.store.getRun(caseId, a.baselineRunId).scope,
      networkActivity: 'none; plan recorded only; external work must use a separate capture run',
    };
    this.record(caseId, a.baselineRunId, 'manual-validation', plan, {
      assessmentId: id,
      testId: plan.id,
    });
    return this.get(caseId, id);
  }
  testResult(caseId, id, testId, input) {
    const a = this.get(caseId, id),
      t = a.manualTests.find((t) => t.id === testId);
    if (!t) throw fail('Skenario tidak ditemukan.', 404);
    if (t.status !== 'planned' || input.expectedRevision !== t.revision)
      throw fail('Skenario sudah ditutup atau berubah.', 409);
    if (!['completed', 'cancelled'].includes(input.status))
      throw fail('Pilih completed/cancelled.');
    const evidence = this.refs(caseId, input.evidence || [], input.status === 'completed');
    if (t.kind !== 'evidence-review' && evidence.some((r) => r.runId === a.baselineRunId))
      throw fail('Hasil aktivitas pengujian harus memakai capture terpisah dari baseline.');
    let comparison = null;
    if (t.kind === 'authorization-comparison' && input.status === 'completed') {
      const c = input.comparison;
      if (!c || !Array.isArray(c.identities) || c.identities.length < 2 || c.identities.length > 5)
        throw fail('Isi 2–5 identitas penguji.');
      comparison = {
        object: text(c.object, 'Objek', 400),
        ownerIdentity: text(c.ownerIdentity, 'Pemilik', 160),
        expectedPolicy: text(c.expectedPolicy, 'Kebijakan akses'),
        interpretation: text(c.interpretation, 'Penjelasan hasil selain status HTTP'),
        identities: c.identities.map((i) => ({
          id: text(i.id, 'Identitas', 160),
          role: text(i.role, 'Role', 160),
          expectedAccess: text(i.expectedAccess, 'Akses yang diharapkan', 1000),
          actualAccess: text(i.actualAccess, 'Akses teramati', 1000),
          evidence: this.refs(caseId, i.evidence, true),
        })),
      };
      if (
        new Set(comparison.identities.map((i) => i.id)).size !== comparison.identities.length ||
        !comparison.identities.some((i) => i.id === comparison.ownerIdentity)
      )
        throw fail('Identitas harus unik dan pemilik objek harus terdaftar.');
      if (comparison.identities.some((i) => i.evidence.some((r) => r.runId === a.baselineRunId)))
        throw fail('Perbandingan akses harus memakai capture pengujian terpisah.');
    }
    const record = {
      ...t,
      history: undefined,
      record: undefined,
      id: testId,
      revision: t.revision + 1,
      status: input.status,
      result: text(input.result, 'Hasil/alasan pembatalan'),
      knownImpact: text(input.knownImpact, 'Dampak yang teramati'),
      operator: text(input.operator, 'Reviewer hasil', 160),
      time: stamp(),
      evidence,
      comparison,
      limitation:
        'Analyst-declared result. HTTP/content differences alone do not establish an authorization violation.',
    };
    this.record(caseId, a.baselineRunId, 'manual-validation', record, { assessmentId: id, testId });
    return this.get(caseId, id);
  }
  export(caseId, id) {
    const a = this.get(caseId, id),
      ids = new Set([a.baselineRunId, ...a.recordRuns]);
    for (const f of a.findings)
      for (const h of f.history)
        for (const r of [...(h.supporting || []), ...(h.contradicting || [])]) ids.add(r.runId);
    for (const t of a.manualTests) {
      for (const r of t.evidence || []) ids.add(r.runId);
      for (const i of t.comparison?.identities || []) for (const r of i.evidence) ids.add(r.runId);
    }
    return {
      schemaVersion: 1,
      exported: stamp(),
      assessment: a,
      manifests: [...ids].map((id) => this.store.exportManifest(caseId, id)),
      limitation:
        'Export verifies local integrity, not source authenticity, trusted time, reviewer identity or host-administrator resistance. No authentication state included.',
    };
  }
}
