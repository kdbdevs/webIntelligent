import { Worker } from 'node:worker_threads';
import { createHmac, randomUUID } from 'node:crypto';
import { fail, stamp, validId, isOfflineMode } from './evidence.mjs';
import { FORENSIC_LIMITS, PARSER_VERSION, validateOptions } from './forensic-parsers.mjs';
import { projectCase, redactCaseView } from './forensic-model.mjs';

export async function parseInWorker(bytes, options, context, timeoutMs = FORENSIC_LIMITS.workerMs) {
  return new Promise((resolve) => {
    let done = false;
    const worker = new Worker(new URL('./forensic-worker.mjs', import.meta.url), {
      workerData: { bytes, options, context },
      resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
      execArgv: [],
    });
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      worker.terminate().catch(() => {});
      resolve(result);
    };
    const timer = setTimeout(
      () => finish({ ok: false, error: 'Parser timeout; original preserved' }),
      timeoutMs,
    );
    worker.on('message', finish);
    worker.on('error', () =>
      finish({ ok: false, error: 'Parser worker/resource failure; original preserved' }),
    );
    worker.on('exit', () =>
      finish({ ok: false, error: 'Parser exited without a result; original preserved' }),
    );
  });
}
const text = (v, label, max = 2000) => {
  if (typeof v !== 'string' || !v.trim() || v.length > max)
    throw fail(`${label} wajib diisi (maks. ${max}).`);
  return v.trim();
};
export class ForensicService {
  constructor(store, { parser = parseInWorker } = {}) {
    this.store = store;
    this.parser = parser;
    this.busy = new Set();
  }
  key(caseId) {
    return createHmac('sha256', this.store.key)
      .update('forensic-correlation-v1:' + caseId)
      .digest();
  }
  refsFor(caseId, runId, artifact) {
    return { caseId, runId, artifactId: artifact.id, sha256: artifact.sha256 };
  }
  original(caseId, sourceId) {
    validId(sourceId);
    for (const run of this.store.listRuns(caseId)) {
      const a = this.store
        .artifacts(caseId, run.id)
        .find((a) => a.id === sourceId && ['forensic-original', 'run-report'].includes(a.kind));
      if (a) {
        if (a.kind === 'run-report' && isOfflineMode(run.mode))
          throw fail('Pilih capture browser sebagai sumber.', 400);
        return { run, artifact: a, ref: this.refsFor(caseId, run.id, a) };
      }
    }
    throw fail('Sumber tidak ditemukan dalam kasus ini.', 404);
  }
  verify(ref) {
    const a = this.store.artifact(ref.caseId, ref.runId, ref.artifactId);
    const bytes = this.store.readArtifact(ref.caseId, ref.runId, ref.artifactId, { log: false });
    if (a.sha256 !== ref.sha256) throw fail('Baseline hash reference tidak cocok.', 409);
    return bytes;
  }
  rawRecord(caseId, run, kind) {
    const a = this.store.artifacts(caseId, run.id).find((a) => a.kind === kind);
    if (!a) return null;
    return {
      data: JSON.parse(this.store.readArtifact(caseId, run.id, a.id, { log: false })),
      ref: this.refsFor(caseId, run.id, a),
    };
  }
  newRun(caseId, mode, parentRunId = null, config = {}) {
    const c = this.store.getCase(caseId);
    if (['forensic-import', 'forensic-parse'].includes(mode)) {
      const used = this.store
        .listRuns(caseId)
        .filter((r) => ['forensic-import', 'forensic-parse'].includes(r.mode))
        .flatMap((r) => this.store.artifacts(caseId, r.id))
        .reduce((n, a) => n + a.size, 0);
      const reserve = FORENSIC_LIMITS.inputBytes + FORENSIC_LIMITS.outputBytes + 1024 * 1024;
      if (used + reserve > FORENSIC_LIMITS.caseAnalysisBytes)
        throw fail('Budget analisis kasus 128 MiB (termasuk reserve input/output) tercapai.', 413);
    }
    return this.store.createRun(caseId, {
      mode,
      url: c.scope.navigation[0],
      parentRunId,
      config: { ...config, parserVersion: PARSER_VERSION, networkActivity: 'none' },
    });
  }
  artifact(caseId, runId, kind, data, derivedFrom = [], role = 'extracted') {
    return this.store.addArtifact(caseId, runId, JSON.stringify(data), {
      kind,
      role,
      label: kind,
      source: `offline:${runId}`,
      mimeType: 'application/json',
      method: 'versioned-offline-forensic-analysis',
      derivedFrom,
      redaction:
        role === 'redacted'
          ? 'Strict structural sharing copy; labels/values/analyst text omitted'
          : 'Selected fields only; encrypted private analysis, may contain personal data; not a sharing copy',
    });
  }
  seal(run, analysis, reason = null) {
    return this.store.seal(
      {
        id: run.id,
        caseId: run.caseId,
        mode: run.mode,
        url: run.url,
        status: reason ? 'interrupted' : 'complete',
        createdAt: run.started.at,
        pages: [],
        requests: [],
        events: [],
        edges: [],
        warnings: reason ? [reason] : [],
        analysis: {
          ...analysis,
          privacy: {
            collected: [
              'Explicitly uploaded original bytes may contain sensitive data; stored encrypted, download only',
              'Private mapped-field extraction and analyst declarations',
            ],
            omitted: [
              'No automatic additional network, payload, browser auth-state collection or archive extraction',
            ],
            redacted: [
              'Sharing copy omits labels, field values, analyst text, raw timestamps and originals',
            ],
            note: 'Original and private analysis are not sanitized sharing reports. Only forensic-share uses strict structural redaction.',
          },
          actions: [
            'Uploaded/original evidence read locally; no network acquisition, archive extraction or content execution',
            'Versioned bounded parsing/analyst transformation; original artifacts unchanged; times/identity statements unverified',
          ],
        },
      },
      reason,
    );
  }
  reject(caseId, reason) {
    this.store.event(
      caseId,
      null,
      'forensic.import-rejected',
      this.store.getCase(caseId).operator,
      { reason: String(reason).slice(0, 160), originalStored: false },
    );
  }
  async import(caseId, bytes, input = {}) {
    this.store.getCase(caseId);
    if (!Buffer.isBuffer(bytes) || bytes.length > FORENSIC_LIMITS.inputBytes) {
      this.reject(caseId, 'Invalid body or file size limit');
      throw fail('Gunakan octet-stream file maksimal 8 MiB.', 413);
    }
    const filename = text(input.filename, 'Nama file', 200);
    if (/[\/\\:\u0000-\u001f]/.test(filename) || ['.', '..'].includes(filename)) {
      this.reject(caseId, 'Path-like filename rejected');
      throw fail('Nama file harus basename, tanpa path.');
    }
    let options;
    try {
      options = validateOptions(input);
    } catch (error) {
      this.reject(caseId, 'Invalid parser options');
      throw fail(error.message);
    }
    if (this.busy.size >= 2 || this.busy.has(caseId))
      throw fail('Parser masih bekerja; tunggu impor selesai.', 409);
    if (
      this.store.listRuns(caseId).filter((r) => r.mode === 'forensic-import').length >=
      FORENSIC_LIMITS.caseSources
    )
      throw fail('Batas 100 file impor per kasus tercapai.', 413);
    let run, original, metadata;
    this.store.transaction(() => {
      run = this.newRun(caseId, 'forensic-import', null, { format: options.format });
      original = this.store.addArtifact(caseId, run.id, bytes, {
        kind: 'forensic-original',
        role: 'original-imported',
        label: 'Uploaded original (sensitive; download only)',
        source: `upload:${run.id}`,
        mimeType: 'application/octet-stream',
        method: 'explicit-local-file-upload',
        redaction:
          'None. Original may contain passwords, cookie/token values or personal data. Encrypted; excluded from sharing exports.',
      });
      metadata = {
        filename,
        options,
        originalRef: this.refsFor(caseId, run.id, original),
        importedAt: run.started,
        originalTimeClaim:
          'Unknown unless explicitly declared by source/operator; hash baseline begins at import',
      };
      this.artifact(caseId, run.id, 'forensic-import-metadata', metadata, [original.id]);
      this.store.saveJob({
        id: run.id,
        caseId,
        mode: run.mode,
        url: run.url,
        status: 'running',
        pages: [],
        requests: [],
        events: [],
        edges: [],
        warnings: [],
        analysis: { originalRef: metadata.originalRef },
        createdAt: run.started.at,
      });
    });
    return this.perform(run, original, bytes, metadata);
  }
  async perform(run, original, bytes, metadata) {
    this.busy.add(run.caseId);
    let result;
    try {
      result = await this.parser(bytes, metadata.options, {
        sourceId: original.id,
        sourceRunId: metadata.originalRef.runId,
        correlationKey: this.key(run.caseId),
        legacy: metadata.legacy,
        browserSession: metadata.browserSession,
      });
      if (!result.ok)
        result = {
          ok: false,
          result: {
            schemaVersion: 1,
            parser: { id: `wi-${metadata.options.format}`, version: PARSER_VERSION },
            options: metadata.options,
            events: [],
            coverage: { status: 'parse-failed', events: 0, gaps: [result.error], gapCount: 1 },
            redactions: [],
            limitations: ['Parsing failed; original preserved. No events inferred.'],
          },
        };
      const data = {
        ...result.result,
        originalRef: metadata.originalRef,
        filename: metadata.filename,
        importedAt: metadata.importedAt,
        parsedAt: stamp(),
        sourceCollectionTime: result.result.sourceCollectionTime || {
          status: 'unknown',
          raw: null,
          normalized: null,
        },
        sourceKind: metadata.sourceKind || 'uploaded',
        legacy: !!metadata.legacy,
        originalCollected: original.collected,
      };
      const record = this.artifact(
        run.caseId,
        run.id,
        'forensic-parse',
        data,
        run.id === original.runId ? [original.id] : [],
      );
      this.seal(
        run,
        {
          originalRef: metadata.originalRef,
          parseRef: this.refsFor(run.caseId, run.id, record),
          coverage: data.coverage,
        },
        data.coverage.status === 'parse-failed'
          ? 'Parsing failed; original retained'
          : data.coverage.status === 'partial'
            ? 'Parsing partial; see coverage gaps'
            : null,
      );
      this.store.event(run.caseId, run.id, 'forensic.parsed', run.operator, {
        parser: data.parser,
        status: data.coverage.status,
        originalArtifactId: original.id,
        parsedArtifactId: record.id,
      });
      return {
        sourceId: original.id,
        runId: run.id,
        parseRef: this.refsFor(run.caseId, run.id, record),
        coverage: data.coverage,
      };
    } catch (error) {
      this.seal(
        run,
        { originalRef: metadata.originalRef },
        'Analysis storage/parser interrupted; original retained',
      );
      throw error;
    } finally {
      this.busy.delete(run.caseId);
    }
  }
  async reparse(caseId, sourceId, input = {}) {
    if (this.busy.size >= 2 || this.busy.has(caseId)) throw fail('Parser masih bekerja.', 409);
    const { run: sourceRun, artifact, ref } = this.original(caseId, sourceId);
    if (sourceRun.status === 'running') throw fail('Selesaikan source run dahulu.', 409);
    if (!this.store.verifyRun(caseId, sourceRun.id).ok) throw fail('Integritas sumber gagal.', 409);
    if (
      this.store
        .listRuns(caseId)
        .filter((r) => r.mode === 'forensic-parse' && r.config.sourceId === sourceId).length >= 20
    )
      throw fail('Batas 20 reparses per sumber.', 413);
    const metadata = this.rawRecord(caseId, sourceRun, 'forensic-import-metadata')?.data;
    const report = artifact.kind === 'run-report' ? JSON.parse(this.verify(ref)) : null;
    let options;
    try {
      options = validateOptions(
        report
          ? { ...input, format: 'web-capture', namespace: `collector:${sourceRun.id}` }
          : { ...metadata?.options, ...input },
        !!report,
      );
    } catch (error) {
      throw fail(error.message);
    }
    const run = this.newRun(caseId, 'forensic-parse', sourceRun.id, {
      sourceId,
      format: options.format,
    });
    return this.perform(run, artifact, this.verify(ref), {
      options,
      filename: metadata?.filename || `Capture ${sourceRun.id.slice(0, 8)}`,
      originalRef: ref,
      importedAt: metadata?.importedAt || (sourceRun.legacy ? sourceRun.started : null),
      legacy: sourceRun.legacy,
      browserSession: sourceRun.mode === 'authenticated' && !!report?.sessionInfo,
      sourceKind: report ? 'browser-capture' : 'uploaded',
    });
  }
  async addCapture(caseId, runId) {
    const run = this.store.getRun(caseId, runId);
    if (isOfflineMode(run.mode) || !run.reportArtifactId) throw fail('Run bukan capture browser.');
    return this.reparse(caseId, run.reportArtifactId, {});
  }
  view(caseId, { sourceId, version } = {}) {
    const runs = this.store.listRuns(caseId),
      sources = new Map(),
      operations = [],
      gaps = [];
    const integrity = new Map();
    const verified = (run) => {
      if (!integrity.has(run.id))
        integrity.set(run.id, run.status !== 'running' && this.store.verifyRun(caseId, run.id).ok);
      return integrity.get(run.id);
    };
    for (const run of runs.slice().reverse()) {
      if (!['forensic-import', 'forensic-parse', 'forensic-operation'].includes(run.mode)) continue;
      if (run.mode === 'forensic-operation') {
        if (!verified(run)) {
          gaps.push('Analyst operation integrity failed/unavailable');
          continue;
        }
        const record = this.rawRecord(caseId, run, 'forensic-operation');
        if (record) operations.push({ ...record.data, recordRef: record.ref });
        continue;
      }
      const artifacts = this.store.artifacts(caseId, run.id),
        original = artifacts.find((a) => a.kind === 'forensic-original');
      if (original && !sources.has(original.id))
        sources.set(original.id, {
          id: original.id,
          filename: '[import metadata unavailable]',
          format: run.config.format,
          originalRef: this.refsFor(caseId, run.id, original),
          originalCollected: original.collected,
          importedAt: run.started,
          versions: [],
          status: run.status === 'running' ? 'parsing' : 'parse-interrupted',
          integrity: verified(run) ? 'verified' : 'failed',
          parsed: null,
        });
      if (!verified(run)) {
        if (original)
          sources.get(original.id).integrity = run.status === 'running' ? 'pending' : 'failed';
        else if (run.config.sourceId && sources.has(run.config.sourceId))
          sources.get(run.config.sourceId).integrity = 'failed';
        gaps.push(`Unverified forensic run ${run.id}`);
        continue;
      }
      const metadata = this.rawRecord(caseId, run, 'forensic-import-metadata');
      if (original && metadata) sources.get(original.id).filename = metadata.data.filename;
      const p = this.rawRecord(caseId, run, 'forensic-parse');
      if (!p) continue;
      const data = p.data,
        id = data.originalRef.artifactId;
      let source = sources.get(id);
      if (!source) {
        source = { id, versions: [] };
        sources.set(id, source);
      }
      source.versions.push({
        runId: run.id,
        artifactId: p.ref.artifactId,
        parser: data.parser,
        parsedAt: data.parsedAt,
        status: data.coverage.status,
      });
      if (sourceId === id && version && p.ref.artifactId !== version) continue;
      Object.assign(source, {
        filename: data.filename,
        format: data.options.format,
        originalRef: data.originalRef,
        originalCollected: data.originalCollected,
        importedAt: data.importedAt,
        parsedAt: data.parsedAt,
        parseRef: p.ref,
        parsed: data,
        status: data.coverage.status,
        integrity: 'verified',
      });
      try {
        this.verify(data.originalRef);
        if (!verified(this.store.getRun(caseId, data.originalRef.runId))) throw new Error();
      } catch {
        source.integrity = 'failed';
        source.parsed = null;
        gaps.push(`Source integrity failed ${id}`);
      }
    }
    if (sourceId && !sources.has(sourceId)) throw fail('Sumber bukan anggota kasus ini.', 404);
    if (version && !sources.get(sourceId)?.versions.some((v) => v.artifactId === version))
      throw fail('Versi parser tidak ditemukan untuk sumber ini.', 404);
    const selected = [...sources.values()].filter((s) => !sourceId || s.id === sourceId);
    const projection = projectCase(selected, operations);
    return {
      caseId,
      sources: [...sources.values()].map((s) => ({
        ...s,
        duplicates: [...sources.values()]
          .filter((x) => x.id !== s.id && x.originalRef.sha256 === s.originalRef.sha256)
          .map((x) => x.id),
      })),
      ...projection,
      gaps,
      captures: runs
        .filter((r) => !isOfflineMode(r.mode) && r.status !== 'running')
        .map((r) => ({ id: r.id, mode: r.mode, url: r.url, created: r.started })),
      limits: FORENSIC_LIMITS,
    };
  }
  operation(caseId, input) {
    const view = this.view(caseId);
    if (view.operations.length >= 300) throw fail('Batas 300 catatan/transformasi kasus.', 413);
    const kind = input.kind;
    if (!['bookmark', 'note', 'hypothesis', 'clock-skew', 'merge', 'revert'].includes(kind))
      throw fail('Jenis operasi tidak didukung.');
    const op = {
      id: randomUUID(),
      kind,
      operator: text(input.operator, 'Analis', 160),
      reason: text(input.reason, 'Alasan/catatan'),
      time: stamp(),
      evidence: [],
      supporting: [],
      contradicting: [],
    };
    const oldVersions = new Map();
    const versionProjection = (id) => {
      if (typeof id !== 'string' || id.length > 160) return null;
      const artifactId = id.split(':')[0];
      if (oldVersions.has(artifactId)) return oldVersions.get(artifactId);
      const source = view.sources.find(
        (s) => s.integrity === 'verified' && s.versions.some((v) => v.artifactId === artifactId),
      );
      if (!source) return null;
      const version = source.versions.find((v) => v.artifactId === artifactId);
      if (!this.store.verifyRun(caseId, version.runId).ok)
        throw fail('Integritas versi analisis gagal.', 409);
      const record = this.rawRecord(
        caseId,
        this.store.getRun(caseId, version.runId),
        'forensic-parse',
      );
      this.verify(record.data.originalRef);
      const projected = projectCase([
        { ...source, parsed: record.data, parseRef: record.ref, parsedAt: record.data.parsedAt },
      ]);
      oldVersions.set(artifactId, projected);
      return projected;
    };
    const selectEvents = (ids) => {
      if (!Array.isArray(ids) || ids.length > 20) throw fail('Maksimal 20 event references.');
      return ids.map((id) => {
        const e =
          view.events.find((e) => e.id === id) ||
          versionProjection(id)?.events.find((e) => e.id === id);
        if (!e) throw fail('Event tidak tersedia/terverifikasi dalam kasus ini.');
        this.verify(e.evidence);
        return e;
      });
    };
    if (kind === 'revert') {
      const target = view.operations.find((o) => o.id === input.target && o.active);
      if (!target) throw fail('Operasi tidak aktif atau tidak ditemukan.', 409);
      op.target = target.id;
      op.evidence = [target.recordRef];
    } else if (kind === 'clock-skew') {
      const source = view.sources.find(
        (s) => s.id === input.sourceId && s.integrity === 'verified',
      );
      if (!source) throw fail('Sumber tidak terverifikasi.');
      if (
        view.operations.some((o) => o.kind === 'clock-skew' && o.sourceId === source.id && o.active)
      )
        throw fail('Batalkan koreksi lama terlebih dahulu.', 409);
      if (!Number.isInteger(input.seconds) || Math.abs(input.seconds) > 86400)
        throw fail('Clock skew harus detik bulat ±86400.');
      if (
        source.parsed.events.some(
          (e) =>
            e.time.normalized &&
            Math.abs(Date.parse(e.time.normalized) + input.seconds * 1000) > 8640000000000000,
        )
      )
        throw fail('Clock transform melampaui rentang waktu yang didukung.');
      op.sourceId = source.id;
      op.seconds = input.seconds;
      op.evidence = [source.originalRef];
    } else if (kind === 'merge') {
      if (
        !Array.isArray(input.entityIds) ||
        input.entityIds.length < 2 ||
        input.entityIds.length > 10 ||
        new Set(input.entityIds).size !== input.entityIds.length
      )
        throw fail('Pilih 2–10 occurrence entitas unik.');
      const entities = input.entityIds.map(
        (id) =>
          view.graph.nodes.find((n) => n.id === id && n.matchKey) ||
          versionProjection(id)?.graph.nodes.find((n) => n.id === id && n.matchKey),
      );
      if (entities.some((n) => !n) || new Set(entities.map((n) => n.kind)).size !== 1)
        throw fail('Entitas harus bertipe sama, terverifikasi, dan berada dalam kasus ini.');
      op.entityIds = input.entityIds;
      op.evidence = entities.flatMap((n) => n.evidence);
      op.status = 'analyst-association-not-verified-identity';
    } else {
      const selected = selectEvents(input.eventIds || []);
      if (!selected.length) throw fail('Pilih setidaknya satu event sumber.');
      op.eventIds = selected.map((e) => e.id);
      op.evidence = selected.map((e) => e.evidence);
      if (kind === 'hypothesis') {
        op.status = 'unverified-hypothesis';
        op.supporting = selectEvents(input.supporting || []).map((e) => e.evidence);
        op.contradicting = selectEvents(input.contradicting || []).map((e) => e.evidence);
      }
    }
    this.store.transaction(() => {
      const run = this.newRun(caseId, 'forensic-operation');
      const a = this.artifact(caseId, run.id, 'forensic-operation', op);
      this.seal(run, { recordRef: this.refsFor(caseId, run.id, a), operationKind: kind });
    });
    return op;
  }
  preview(caseId, sourceId, version) {
    const view = this.view(caseId, { sourceId, version }),
      source = view.sources.find((s) => s.id === sourceId);
    if (source.integrity !== 'verified')
      throw fail('Integritas sumber gagal atau impor belum selesai.', 409);
    this.verify(source.originalRef);
    if (source.parseRef) this.verify(source.parseRef);
    this.store.event(
      caseId,
      source.originalRef.runId,
      'forensic.previewed',
      this.store.getCase(caseId).operator,
      {
        originalArtifactId: sourceId,
        parseArtifactId: source.parseRef?.artifactId,
        activeContentExecuted: false,
      },
    );
    return {
      source,
      events: view.events.slice(0, 100),
      previewPolicy:
        'Parsed metadata only, React text preview. No original payload/HTML/email images/attachments executed or fetched.',
      truncated: view.events.length > 100,
    };
  }
  share(caseId, { sourceId, version } = {}) {
    const view = this.view(caseId, { sourceId, version });
    if (view.gaps.length || view.sources.some((s) => s.integrity !== 'verified'))
      throw fail('Selesaikan/periksa integritas seluruh sumber sebelum berbagi.', 409);
    const share = redactCaseView(view);
    let ref;
    this.store.transaction(() => {
      const run = this.newRun(caseId, 'forensic-share');
      const a = this.artifact(caseId, run.id, 'forensic-share', share, [], 'redacted');
      ref = this.refsFor(caseId, run.id, a);
      this.seal(run, { redactedShareRef: ref, originalsExcluded: true });
    });
    return { ref, share };
  }
}
