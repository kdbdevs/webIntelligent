import { FORENSIC_LIMITS } from './forensic-parsers.mjs';

export function projectCase(sources, operations = []) {
  const undone = new Set(operations.filter((o) => o.kind === 'revert').map((o) => o.target));
  const active = operations.filter((o) => o.kind !== 'revert' && !undone.has(o.id));
  const events = [],
    nodes = [],
    edges = [],
    groups = new Map();
  let truncated = false;
  const node = (n) => {
    nodes.push(n);
    return n.id;
  };
  const edge = (source, target, relation, method, evidence) =>
    edges.push({
      id: `edge-${edges.length}`,
      source,
      target,
      relation,
      method,
      evidence,
      limitation: 'A relationship is not proof of causation or source authenticity',
    });
  for (const source of sources) {
    node({
      id: `source:${source.id}`,
      kind: 'file',
      label: source.filename || source.id,
      sourceId: source.id,
      evidence: [source.originalRef],
      method: 'separate acquisition/import copy; original hash baseline is local',
    });
    if (!source.parsed || source.integrity === 'failed') continue;
    const skew = active.find((o) => o.kind === 'clock-skew' && o.sourceId === source.id);
    for (const original of source.parsed.events) {
      if (events.length >= FORENSIC_LIMITS.caseEvents) {
        truncated = true;
        break;
      }
      const id = `${source.parseRef.artifactId}:${original.localId}`;
      const evidence = {
        ...source.originalRef,
        location: original.provenance.location,
        parser: source.parsed.parser,
        extractionRef: source.parseRef,
      };
      const event = {
        ...original,
        id,
        sourceId: source.id,
        filename: source.filename,
        sourceFormat: source.format,
        parseRef: source.parseRef,
        evidence,
        collectedTime: source.parsed.legacy
          ? {
              normalized: null,
              raw: null,
              zone: null,
              status: 'unknown',
              reason:
                'Historical collection unknown; host timestamp only establishes legacy import baseline',
            }
          : source.format === 'web-capture'
            ? {
                normalized: source.originalCollected.at,
                zone: source.originalCollected.timezone,
                status: 'collector-clock',
                raw: source.originalCollected.at,
              }
            : source.parsed.sourceCollectionTime,
        importedTime: source.importedAt || null,
        parsedTime: source.parsedAt,
        evidenceStatus:
          source.parsed.coverage.status === 'parsed' ? 'verified-baseline' : 'partial',
        displayTime: original.time.normalized
          ? new Date(
              Date.parse(original.time.normalized) + (skew?.seconds || 0) * 1000,
            ).toISOString()
          : null,
        clockTransform: skew
          ? {
              id: skew.id,
              seconds: skew.seconds,
              reason: skew.reason,
              operator: skew.operator,
              sourceUnchanged: true,
            }
          : null,
        fields: original.fields.map((f) => ({
          ...f,
          evidence: { ...source.originalRef, ...f.provenance, extractionRef: source.parseRef },
        })),
      };
      events.push(event);
      node({
        id,
        kind: original.type,
        label: `${original.type} · ${original.time.raw || 'time unknown'}`,
        eventId: id,
        sourceId: source.id,
        evidence: [evidence],
      });
      edge(
        `source:${source.id}`,
        id,
        original.basis === 'browser-observation-at-capture' ? 'observed' : 'declared',
        'versioned parser extracted this source statement',
        [evidence],
      );
      for (const [i, entity] of original.entities.entries()) {
        const enode = {
          ...entity,
          id: `${id}:entity:${i}`,
          eventId: id,
          sourceId: source.id,
          evidence: [event.fields.find((f) => f.name === entity.field)?.evidence || evidence],
        };
        node(enode);
        edge(
          id,
          enode.id,
          entity.kind === 'session' ? 'observed' : 'declared',
          entity.method,
          enode.evidence,
        );
        const groupKey = `${entity.kind}:${entity.matchKey}`;
        if (!groups.has(groupKey)) groups.set(groupKey, []);
        groups.get(groupKey).push(enode);
      }
    }
    // Whole-file hash also relates a standalone file to a decoded MIME part, without merging copies.
    const hnode = {
      id: `hash:${source.id}`,
      kind: 'hash',
      label: source.originalRef.sha256,
      sourceId: source.id,
      evidence: [source.originalRef],
      method: 'computed SHA-256 of original acquired bytes',
    };
    node(hnode);
    edge(`source:${source.id}`, hnode.id, 'observed', 'computed original file hash', [
      source.originalRef,
    ]);
    const hashKey = `file-hash:${source.originalRef.sha256}`;
    if (!groups.has(hashKey)) groups.set(hashKey, []);
    groups.get(hashKey).push(hnode);
  }
  // A shared-value hub expresses correlation while every occurrence remains separate.
  // No time-nearness edges and no username/IP/domain auto-identity merge.
  const hashOccurrences = new Map();
  for (const n of nodes.filter((n) => n.kind === 'hash')) {
    if (!hashOccurrences.has(n.label)) hashOccurrences.set(n.label, []);
    hashOccurrences.get(n.label).push(n);
  }
  for (const [k, v] of hashOccurrences) groups.set(`file-hash:${k}`, v);
  for (const [key, members] of groups) {
    if (members.length < 2 || (key.startsWith('hash:') && members[0].kind === 'hash')) continue;
    const id = `correlation:${members[0].id}`;
    node({
      id,
      kind: 'correlation',
      label: `Shared ${members[0].kind} value · ${members.length} occurrences`,
      evidence: members.slice(0, 20).flatMap((n) => n.evidence),
      method: 'exact normalized/opaque-key equality; sources/occurrences remain distinct',
    });
    for (const m of members)
      edge(
        id,
        m.id,
        'correlated',
        m.kind === 'hash'
          ? 'SHA-256 matches; computed bytes vs declared hashes distinguished in source metadata, not shared origin'
          : m.method,
        m.evidence,
      );
  }
  const available = new Set(nodes.map((n) => n.id));
  for (const op of active.filter((o) => o.kind === 'merge')) {
    const present = op.entityIds.filter((id) => available.has(id));
    if (present.length < 2) continue;
    const id = `manual:${op.id}`;
    node({
      id,
      kind: 'manual-association',
      label: `Manual group · ${op.operator}`,
      evidence: op.evidence,
      method: op.reason,
      operationId: op.id,
    });
    for (const target of present)
      edge(
        id,
        target,
        'inferred',
        `Analyst merge/association: ${op.reason}; reversible, source nodes retained`,
        op.evidence,
      );
  }
  events.sort(
    (a, b) =>
      (a.displayTime || '9999').localeCompare(b.displayTime || '9999') || a.id.localeCompare(b.id),
  );
  return {
    events,
    graph: { nodes, edges },
    operations: operations.map((o) => ({ ...o, active: o.kind !== 'revert' && !undone.has(o.id) })),
    truncated,
    limitations: [
      'Equal IP, account, domain or timestamps do not prove identity or cause',
      'No automatic chronological causal chain, authenticated email sender inference, or historical reconstruction from current capture',
      'Manual hypotheses/merges/clock transforms are analyst declarations, not validated findings',
    ],
  };
}
export function redactCaseView(view) {
  const labels = new Map(view.graph.nodes.map((n, i) => [n.id, `${n.kind}-${i + 1}`]));
  const ref = (r) => ({
    caseId: r.caseId,
    runId: r.runId,
    artifactId: r.artifactId,
    sha256: r.sha256,
    location: r.location
      ? {
          kind: r.location.kind,
          line: r.location.line,
          lineStart: r.location.lineStart,
          lineEnd: r.location.lineEnd,
          part: r.location.part,
          column: r.location.column,
        }
      : undefined,
    parser: r.parser,
    extractionRef: r.extractionRef ? ref(r.extractionRef) : undefined,
  });
  return {
    schemaVersion: 1,
    sharePolicy: 'strict-structural-v1',
    caseId: view.caseId,
    redactions: [
      'All filenames, URLs/domains/IP/account/session/request/email labels and matching keys omitted',
      'All field values, raw timestamps, mapping/namespace details and analyst text omitted',
      'No originals, MIME contents, secrets, custody details or authentication state included',
      'Evidence IDs/hashes and normalized times retained for traceability; these can still link records',
    ],
    sources: view.sources.map((s, i) => ({
      id: s.id,
      label: `source-${i + 1}`,
      format: s.format,
      integrity: s.integrity,
      coverage: {
        status: s.parsed?.coverage.status || s.status,
        gapCount: s.parsed?.coverage.gapCount || 0,
        detailPolicy:
          'Full reasons retained in referenced private parsing artifact; details omitted from sharing',
      },
      originalRef: ref(s.originalRef),
      parseRef: s.parseRef ? ref(s.parseRef) : null,
      importedAt: s.importedAt,
      parser: s.parsed?.parser,
    })),
    events: view.events.map((e) => ({
      id: e.id,
      sourceId: e.sourceId,
      type: e.type,
      basis: e.basis,
      evidenceStatus: e.evidenceStatus,
      eventTime: { normalized: e.time.normalized, status: e.time.status },
      displayTime: e.displayTime,
      clockTransform: e.clockTransform
        ? { id: e.clockTransform.id, seconds: e.clockTransform.seconds }
        : null,
      importedTime: e.importedTime,
      collectedTime: {
        normalized: e.collectedTime?.normalized || null,
        status: e.collectedTime?.status || 'unknown',
      },
      evidence: ref(e.evidence),
      fields: e.fields.map((f) => ({ name: '[field omitted]', evidence: ref(f.evidence) })),
    })),
    graph: {
      nodes: view.graph.nodes.map((n) => ({
        id: n.id,
        kind: n.kind,
        label:
          n.kind === 'hash' && /^computed SHA-256/.test(n.method || '')
            ? n.label
            : labels.get(n.id),
        evidence: (n.evidence || []).map(ref),
      })),
      edges: view.graph.edges.map((e) => ({
        ...e,
        method: '[consult local analysis for correlation method]',
        evidence: e.evidence.map(ref),
      })),
    },
    operations: view.operations.map((o) => ({
      id: o.id,
      kind: o.kind,
      active: o.active,
      target: o.target,
      eventIds: o.eventIds,
      entityIds: o.entityIds,
      sourceId: o.sourceId,
      seconds: o.seconds,
      status: o.kind === 'hypothesis' ? 'unverified-hypothesis' : undefined,
      time: o.time,
      evidence: (o.evidence || []).map(ref),
      supporting: (o.supporting || []).map(ref),
      contradicting: (o.contradicting || []).map(ref),
    })),
    limitations: view.limitations,
    truncated: view.truncated,
  };
}
