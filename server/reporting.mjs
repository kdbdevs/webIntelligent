import { fail, digest, isOfflineMode } from './evidence.mjs';
import { SecurityService } from './security.mjs';
import { projectCase } from './forensic-model.mjs';
import {
  EvidenceReader,
  refOf,
  saveRecord,
  loadRecord,
  stampRecord,
  uniqueIds,
  uniqueRefs,
  required,
  short,
  REPORT_LIMITS,
  INTEGRITY_NOTE,
  REPORT_MODES,
} from './report-common.mjs';
import { captureData } from './report-common.mjs';

const selectable = new Set([
  'run-report',
  'page-extraction',
  'forensic-parse',
  'security-assessment',
  'capture-comparison',
  'analysis-assistant',
]);
export class ReportService {
  constructor(store) {
    this.store = store;
  }
  catalog(caseId) {
    this.store.getCase(caseId);
    const sources = [],
      reports = [],
      comparisons = [];
    for (const run of this.store.listRuns(caseId)) {
      if (run.status === 'running') continue;
      for (const a of this.store.artifacts(caseId, run.id)) {
        if (
          (a.kind !== 'analysis-assistant' || run.config.accepted === true) &&
          selectable.has(a.kind) &&
          (!isOfflineMode(run.mode) || a.kind !== 'run-report')
        )
          sources.push({
            id: a.id,
            runId: run.id,
            kind: a.kind,
            label: a.label,
            collected: a.collected,
            status: run.status,
          });
        if (a.kind === 'case-report')
          reports.push({
            id: run.config.recordId,
            runId: run.id,
            artifactId: a.id,
            status: run.config.reportStatus,
            version: run.config.version,
            created: a.collected,
          });
        if (a.kind === 'capture-comparison')
          comparisons.push({ id: run.config.recordId, artifactId: a.id, created: a.collected });
      }
    }
    return { sources, reports, comparisons, limits: REPORT_LIMITS };
  }
  build(caseId, input) {
    const reader = new EvidenceReader(this.store, caseId),
      c = this.store.getCase(caseId),
      ids = uniqueIds(input.artifactIds),
      sources = [],
      cards = [],
      timeline = [],
      findings = [],
      relations = [],
      hypotheses = [],
      gaps = [],
      refs = [],
      forensic = [];
    let cardOmitted = 0;
    const add = (classification, text, evidence, extra = {}) => {
      const valid = uniqueRefs(evidence.map((r) => reader.reference(r)));
      refs.push(...valid);
      if (cards.length >= REPORT_LIMITS.cards) {
        cardOmitted++;
        return;
      }
      cards.push({
        id: `fact-${cards.length + 1}`,
        classification,
        text: short(text, 1800),
        publicText:
          extra.publicText ||
          `${classification}: selected evidence record observed; source values withheld.`,
        evidence: valid,
        ...extra,
      });
    };
    for (const id of ids) {
      const found = reader.find(id),
        { artifact: a, run, ref } = found;
      if (!selectable.has(a.kind) || (a.kind === 'run-report' && isOfflineMode(run.mode)))
        throw fail('Jenis sumber laporan tidak didukung.');
      const data = reader.json(ref);
      refs.push(ref);
      sources.push({
        ref,
        kind: a.kind,
        role: a.role,
        source: a.source,
        collected: a.collected,
        method: a.method,
        collector: a.collector,
        size: a.size,
        mimeType: a.mimeType,
        sha256: a.sha256,
        baseline: a.baseline,
        redaction: a.redaction,
        status: run.status,
        started: run.started,
        finished: run.ended || null,
        derivedFrom: a.derivedFrom,
      });
      if (['run-report', 'page-extraction'].includes(a.kind)) {
        const cap = captureData(reader, id);
        const basis = run.legacy ? 'source-claim' : 'observation';
        if (run.legacy)
          gaps.push(
            'Legacy/imported capture: original collection time and historical integrity unverified; hash baseline begins at import.',
          );
        sources.at(-1).coverage = cap.coverage;
        gaps.push(
          ...cap.coverage.warnings,
          run.legacy
            ? 'Imported records are source statements, not an established historical reconstruction.'
            : 'Capture describes the observed present, not historical events without historical sources.',
        );
        add(
          basis,
          `${cap.pages.length} pages and ${cap.requests.length} requests in selected capture.`,
          [ref],
          {
            publicText: `Capture contains ${cap.pages.length} pages and ${cap.requests.length} request records.`,
          },
        );
        cap.pages.forEach((p, i) => {
          const pRef = cap.pageRef(i);
          if (p.screenshotArtifactId) {
            const image = reader.find(p.screenshotArtifactId);
            if (image.run.id !== cap.run.id || image.artifact.kind !== 'screenshot')
              throw fail('Referensi screenshot capture tidak valid.');
            refs.push(reader.reference(image.ref));
          }
          add(
            basis,
            `Page ${p.url}; title ${p.title || 'unknown'}; ${p.elements?.length || 0} elements.`,
            [pRef],
            {
              publicText: `Page record with ${p.elements?.length || 0} observed elements.`,
              quote:
                typeof p.title === 'string'
                  ? {
                      text: p.title.slice(0, 500),
                      ref: { ...pRef, pointer: pRef.pointer + '/title' },
                    }
                  : null,
            },
          );
          timeline.push({
            id: `${id}:page:${i}`,
            classification: basis,
            eventTime: {
              raw: p.capturedAt || null,
              normalized: safeTime(p.capturedAt) ? new Date(p.capturedAt).toISOString() : null,
              zone: safeTime(p.capturedAt) ? p.capturedAt.match(/(Z|[+-]\d\d:\d\d)$/)?.[0] : null,
              status: safeTime(p.capturedAt)
                ? run.legacy
                  ? 'legacy-source-claim'
                  : 'collector-clock'
                : 'unknown',
            },
            collectedTime: run.legacy ? null : a.collected,
            importedTime: run.legacy ? run.started : null,
            label: short(p.url),
            evidence: [pRef],
          });
          if (p.wiring?.artifactId) {
            const w = reader.find(p.wiring.artifactId),
              wd = reader.json(w.ref);
            refs.push(w.ref);
            for (const [j, e] of (wd.edges || []).slice(0, 100).entries())
              if (['correlated', 'inferred', 'unknown'].includes(e.relation)) {
                const r = { ...w.ref, pointer: `/edges/${j}` };
                relations.push({
                  classification: e.relation,
                  method: e.reason || e.method,
                  evidence: [r],
                });
                add(e.relation, `Wiring relation: ${e.reason || e.method || e.relation}`, [r]);
              }
          }
        });
        cap.requests.slice(0, 100).forEach((r, i) =>
          add(
            basis,
            `${r.method} ${r.url}; status ${r.status ?? 'unavailable'}`,
            [{ ...cap.requestRef, pointer: `/requests/${i}` }],
            {
              publicText: `Request record: response ${Number.isInteger(r.status) ? r.status : 'unavailable'}.`,
            },
          ),
        );
        if (cap.requests.length > 100)
          gaps.push(
            'Report request cards limited to 100 per capture; complete selected capture remains referenced.',
          );
      } else if (a.kind === 'forensic-parse') {
        reader.reference(data.originalRef);
        refs.push(data.originalRef);
        forensic.push({
          id: data.originalRef.artifactId,
          filename: data.filename,
          format: data.options.format,
          originalRef: data.originalRef,
          originalCollected: data.originalCollected,
          importedAt: data.importedAt,
          parsedAt: data.parsedAt,
          parseRef: ref,
          parsed: data,
        });
        gaps.push(...data.coverage.gaps);
        sources.at(-1).coverage = data.coverage;
        sources.at(-1).parser = data.parser;
        sources.at(-1).originalRef = reader.reference(data.originalRef);
      } else if (a.kind === 'security-assessment') {
        const assessment = new SecurityService(this.store).get(caseId, data.id);
        sources.at(-1).analysisEngineVersion = assessment.engineVersion;
        const notAssessed = assessment.results.filter((r) => r.counts?.['not-assessed'] > 0).length;
        if (notAssessed)
          gaps.push(
            `${notAssessed} security rules have not-assessed evaluations due to incomplete evidence.`,
          );
        const reviewRefs = assessment.recordRuns.map((runId) => {
          const rr = this.store.getRun(caseId, runId),
            aa = this.store.artifacts(caseId, runId).find((x) => x.kind === rr.mode);
          return reader.reference(refOf(caseId, runId, aa));
        });
        refs.push(...reviewRefs);
        for (const [i, f] of assessment.findings.entries()) {
          const evidence = uniqueRefs([
            { ...ref, pointer: `/findings/${i}` },
            ...reviewRefs,
            ...(f.evidence || []),
          ]);
          evidence.forEach((r) => reader.reference(r));
          findings.push({ ...f, evidence });
          add(
            f.status === 'validated'
              ? 'validated-finding'
              : f.status === 'candidate'
                ? 'candidate'
                : f.status === 'dismissed'
                  ? 'dismissed'
                  : 'observation',
            `${f.ruleId}: ${f.title}. Status ${f.status}, risk ${f.risk}, confidence ${f.confidence}.`,
            evidence,
            {
              publicText: `Rule ${f.ruleId}: ${f.status}; risk ${f.risk}; confidence ${f.confidence}.`,
            },
          );
        }
        gaps.push(...(assessment.limitations || []));
      } else if (a.kind === 'analysis-assistant') {
        if (data.kind !== 'assistant-result' || data.accepted !== true)
          throw fail('Pilih hasil asisten yang telah lolos validasi referensi.');
        reader.reference(data.reportRef);
        reader.reference(data.planRef);
        refs.push(data.reportRef, data.planRef);
        for (const fact of data.facts)
          add(fact.classification, fact.text, [ref, ...fact.evidence], {
            publicText: fact.publicText,
          });
        gaps.push(
          'Assistant contribution only selects existing facts; no automatic finding validation or attribution.',
        );
      } else if (a.kind === 'capture-comparison') {
        for (const r of data.refs) reader.reference(r);
        refs.push(...data.refs);
        sources.at(-1).coverage = data.context;
        for (const [i, row] of data.rows.slice(0, 100).entries())
          add(
            'correlation',
            `${row.kind}: ${row.change}: ${row.label}`,
            [{ ...ref, pointer: `/rows/${i}` }, ...row.evidence],
            { publicText: `Capture comparison ${row.kind}: ${row.change}; metadata only.` },
          );
        gaps.push(...data.context.warnings);
      }
    }
    if (new Set(forensic.map((s) => s.id)).size !== forensic.length)
      throw fail('Pilih satu versi parsing per file asli untuk satu laporan.');
    const operations = [];
    if (forensic.length) {
      const selected = new Set(forensic.map((s) => s.id));
      for (const run of this.store.listRuns(caseId).slice().reverse()) {
        if (run.mode !== 'forensic-operation' || run.status === 'running') continue;
        const a = this.store.artifacts(caseId, run.id).find((a) => a.kind === 'forensic-operation');
        if (!a) continue;
        const ref = refOf(caseId, run.id, a),
          op = reader.json(ref);
        if (
          op.kind === 'revert' ||
          selected.has(op.sourceId) ||
          (op.evidence || []).some((r) => selected.has(r.artifactId))
        )
          operations.push({ ...op, recordRef: ref });
      }
      const projection = projectCase(forensic, operations);
      for (const event of projection.events) {
        const source = forensic.find((s) => s.id === event.sourceId),
          i = source.parsed.events.findIndex((e) => e.localId === event.localId),
          r = { ...source.parseRef, pointer: `/events/${i}` };
        const evidence = [
          r,
          event.evidence,
          ...(event.clockTransform
            ? operations.filter((o) => o.id === event.clockTransform.id).map((o) => o.recordRef)
            : []),
        ];
        timeline.push({
          id: event.id,
          classification:
            event.basis === 'browser-observation-at-capture' ? 'observation' : 'source-claim',
          eventTime: event.time,
          displayTime: event.displayTime,
          clockTransform: event.clockTransform,
          collectedTime: event.collectedTime,
          importedTime: event.importedTime,
          parsedTime: event.parsedTime,
          label: `${event.type}: ${event.fields.map((f) => `${f.name}=${f.value}`).join('; ')}`,
          evidence,
        });
        const field = event.fields.find(
          (f) => typeof f.value === 'string' && f.value.length <= 500,
        );
        const index = field ? event.fields.indexOf(field) : -1;
        add('source-claim', timeline.at(-1).label, evidence, {
          publicText:
            'Source-declared event; historical authenticity and attribution not established.',
          quote: field
            ? {
                text: field.value,
                ref: { ...source.parseRef, pointer: `/events/${i}/fields/${index}/value` },
              }
            : null,
        });
      }
      for (const edge of projection.graph.edges
        .filter((e) => ['correlated', 'inferred'].includes(e.relation))
        .slice(0, 100)) {
        relations.push({
          classification: edge.relation,
          method: edge.method,
          evidence: edge.evidence,
        });
        add('correlation', edge.method, edge.evidence);
      }
      for (const op of projection.operations.filter((o) => o.active)) {
        refs.push(op.recordRef);
        if (op.kind === 'hypothesis') {
          hypotheses.push(op);
          add('hypothesis', op.text || op.reason || 'Analyst hypothesis', [op.recordRef]);
        }
      }
      if (projection.truncated) gaps.push('Case projection truncated.');
    }
    timeline.sort((a, b) =>
      (a.displayTime || a.eventTime.normalized || '9999').localeCompare(
        b.displayTime || b.eventTime.normalized || '9999',
      ),
    );
    if (timeline.length > REPORT_LIMITS.timeline)
      gaps.push('Report timeline limited to 500 events.');
    if (cardOmitted) gaps.push(`${cardOmitted} evidence cards omitted by report limit.`);
    const previous = input.previousId ? this.get(caseId, input.previousId) : null;
    const narrative =
      input.shareNarrativeApproved === true
        ? Object.fromEntries(
            ['title', 'objective', 'scope', 'recommendations', 'reviewer'].map((k) => [
              k,
              short(input.shareNarrative?.[k], 2000),
            ]),
          )
        : null;
    const snapshot = {
      shareNarrative: narrative,
      case: {
        id: c.id,
        title: c.title,
        objective: c.objective,
        scope: c.scope,
        operator: c.operator,
        notes: c.notes,
      },
      author: required(input.author || c.operator, 'Penulis', 200),
      recommendations: short(input.recommendations, 4000),
      sources,
      cards,
      timeline: timeline.slice(0, REPORT_LIMITS.timeline),
      findings,
      relations,
      hypotheses,
      gaps: [...new Set(gaps)],
      limitations: [
        INTEGRITY_NOTE,
        'Observations, source claims, correlations and hypotheses are distinct from human-validated findings. A matching IP/name/time alone does not establish identity or cause.',
        'Shared copies omit private text, filenames, URL paths, identities, field values and screenshots; detailed private snapshot remains local.',
        'Source-selected versions and current reviews are frozen; later changes require a new report.',
      ],
      refs: uniqueRefs(refs),
    };
    const body = stampRecord({
      kind: 'case-report',
      caseId,
      status: 'draft',
      seriesId: previous?.seriesId || null,
      parentId: previous?.id || null,
      version: previous ? previous.version + 1 : 1,
      snapshot,
      snapshotSha256: digest(JSON.stringify(snapshot)),
      review: null,
    });
    body.seriesId ||= body.id;
    return saveRecord(this.store, caseId, 'case-report', body, {
      config: { reportStatus: 'draft', version: body.version },
    });
  }
  get(caseId, id) {
    const r = loadRecord(this.store, caseId, id, 'case-report');
    if (digest(JSON.stringify(r.snapshot)) !== r.snapshotSha256)
      throw fail('Snapshot hash mismatch.', 409);
    const reader = new EvidenceReader(this.store, caseId);
    r.snapshot.refs.forEach((ref) => reader.reference(ref));
    return r;
  }
  finalize(caseId, id, input) {
    const d = this.get(caseId, id);
    if (
      d.status !== 'draft' ||
      input.expectedSha256 !== d.snapshotSha256 ||
      input.acknowledged !== true
    )
      throw fail('Review draft dan hash snapshot wajib dikonfirmasi.', 409);
    const body = stampRecord({
      kind: 'case-report',
      caseId,
      status: 'final',
      seriesId: d.seriesId,
      parentId: d.id,
      version: d.version + 1,
      snapshot: d.snapshot,
      snapshotSha256: d.snapshotSha256,
      review: {
        reviewer: required(input.reviewer, 'Peninjau', 200),
        reason: required(input.reason, 'Alasan review', 2000),
        reviewedAt: new Date().toISOString(),
        draftRef: d.recordRef,
      },
    });
    return saveRecord(this.store, caseId, 'case-report', body, {
      parentRunId: d.recordRef.runId,
      config: { reportStatus: 'final', version: body.version },
    });
  }
  evidence(caseId, ref) {
    const reader = new EvidenceReader(this.store, caseId),
      r = reader.read(ref);
    return {
      ref: reader.reference(ref),
      metadata: r.artifact,
      value:
        r.artifact.mimeType === 'application/json'
          ? reader.value(ref)
          : '[Binary content; use existing evidence viewer/download]',
      note: 'Untrusted content shown as text only.',
    };
  }
}
// Allowlist, not a keyword filter: arbitrary source/analyst strings are never copied into sharing output.
const safeTime = (v) =>
  typeof v === 'string' &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(v) &&
  Number.isFinite(Date.parse(v))
    ? v
    : null;
export function shareReport(r) {
  const s = r.snapshot;
  return {
    schemaVersion: 1,
    engine: r.engine,
    id: r.id,
    caseId: r.caseId,
    seriesId: r.seriesId,
    parentId: r.parentId,
    version: r.version,
    status: r.status,
    created: r.created,
    snapshotSha256: r.snapshotSha256,
    redaction:
      'Structural sharing projection; private source and analyst text withheld. Hash above describes private snapshot, not this projection.',
    case: {
      id: r.caseId,
      title: s.shareNarrative?.title || 'Selected case report',
      objective: s.shareNarrative?.objective || 'Private objective withheld',
      scope:
        s.shareNarrative?.scope ||
        'Selected evidence only; navigation scope and dependency names withheld',
    },
    review: r.review
      ? {
          completed: true,
          reviewedAt: r.review.reviewedAt,
          reviewer: s.shareNarrative?.reviewer || 'Identity withheld',
          draftRef: r.review.draftRef,
        }
      : null,
    sources: s.sources.map((x) => ({
      ref: x.ref,
      kind: x.kind,
      role: x.role,
      baseline: x.baseline,
      collected: x.collected,
      size: x.size,
      mimeType: x.mimeType,
      sha256: x.sha256,
      method: x.method,
      collector: x.collector,
      parser: x.parser,
      analysisEngineVersion: x.analysisEngineVersion,
      coverageSummary: {
        visitedPages: x.coverage?.visited?.length ?? null,
        failedRequests: x.coverage?.failedRequests ?? null,
        sourceStatus: x.coverage?.status || x.status,
        limitsApplied: true,
      },
      derivedFrom: x.derivedFrom,
      originalRef: x.originalRef ? cleanRef(x.originalRef) : null,
      status: x.status,
      source: 'Withheld',
      coverage: 'See local private snapshot; coverage is bounded',
    })),
    timeline: s.timeline.map((e) => ({
      id: e.id,
      classification: e.classification,
      eventTime: {
        normalized: safeTime(e.eventTime.normalized),
        status: e.eventTime.status,
        raw: 'withheld',
        zone: 'withheld',
      },
      displayTime: safeTime(e.displayTime),
      collectedTime: e.collectedTime?.at || e.collectedTime?.normalized || null,
      importedTime: e.importedTime?.at || null,
      clockTransform: e.clockTransform
        ? { id: e.clockTransform.id, seconds: e.clockTransform.seconds, sourceUnchanged: true }
        : null,
      evidence: e.evidence.map(cleanRef),
    })),
    cards: s.cards.map((c) => ({
      id: c.id,
      classification: c.classification,
      text: c.publicText,
      evidence: c.evidence.map(cleanRef),
    })),
    findings: s.findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      status: f.status,
      risk: f.risk,
      confidence: f.confidence,
      evidence: f.evidence.map(cleanRef),
    })),
    relations: s.relations.map((e) => ({
      classification: e.classification,
      method: 'Evidence-based correlation; source values withheld',
      evidence: e.evidence.map(cleanRef),
    })),
    hypotheses: s.hypotheses.map((h) => ({
      id: h.id,
      classification: 'hypothesis',
      text: 'Private analyst hypothesis withheld',
      evidence: [cleanRef(h.recordRef)],
    })),
    coverageGaps: {
      count: s.gaps.length,
      detail: 'Private gap text withheld; incomplete evidence must not imply complete coverage',
    },
    limitations: s.limitations,
    recommendations: [
      ...(s.shareNarrative?.recommendations ? [s.shareNarrative.recommendations] : []),
      'Review source evidence and capture scope before acting.',
      'Validate candidates manually; absence from a later capture does not establish remediation.',
    ],
    refs: s.refs.map(cleanRef),
  };
}
function cleanRef(r) {
  return {
    caseId: r.caseId,
    runId: r.runId,
    artifactId: r.artifactId,
    sha256: r.sha256,
    pointer: r.pointer || '',
  };
}
