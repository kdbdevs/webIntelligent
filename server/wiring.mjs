import { createHmac, randomBytes } from 'node:crypto';
import { displayUrl } from './safety.mjs';

// A per-run secret avoids joining different redacted URLs or exporting a dictionary-testable
// hash of a short secret query value. No raw URL lookup table or secret is persisted.
export class SourceCatalog {
  #key = randomBytes(32);
  key(value) {
    return createHmac('sha256', this.#key).update(String(value)).digest('hex');
  }
  source(value, inlineId = '') {
    if (!value)
      return {
        kind: 'inline',
        key: this.key(`inline:${inlineId}`),
        requestKey: null,
        url: null,
        domain: null,
        storageOrigin: 'unknown',
      };
    const raw = String(value);
    if (raw.startsWith('wi-truncated:'))
      return {
        kind: raw.split(':')[1],
        key: this.key(raw),
        requestKey: null,
        url: '[source omitted: collection size limit]',
        domain: null,
        truncated: true,
        storageOrigin: 'unknown',
        creator: 'unknown',
      };
    if (raw.startsWith('data:'))
      return {
        kind: 'data',
        key: this.key(raw),
        requestKey: null,
        url: 'data:[payload omitted]',
        mimeType: raw.slice(5, raw.indexOf(',')).split(';')[0].slice(0, 120) || 'text/plain',
        domain: null,
        storageOrigin: 'unknown',
      };
    if (raw.startsWith('blob:')) {
      let origin = null;
      try {
        origin = new URL(raw.slice(5)).origin;
      } catch {}
      return {
        kind: 'blob',
        key: this.key(raw),
        requestKey: null,
        url: 'blob:[identifier omitted]',
        domain: origin,
        creator: 'unknown: creation stack was not traced',
        storageOrigin: 'unknown',
      };
    }
    try {
      const u = new URL(raw);
      if (!['http:', 'https:'].includes(u.protocol))
        return {
          kind: 'unsupported',
          key: this.key(raw),
          requestKey: null,
          url: '[unsupported scheme]',
          domain: null,
          storageOrigin: 'unknown',
        };
      const key = this.key(u.href);
      u.hash = '';
      return {
        kind: 'network',
        key,
        requestKey: this.key(u.href),
        url: displayUrl(u.href),
        domain: u.host,
        storageOrigin: 'unknown; this is the observed serving domain, possibly a CDN',
      };
    } catch {
      return {
        kind: 'unknown',
        key: this.key(raw),
        requestKey: null,
        url: null,
        domain: null,
        storageOrigin: 'unknown',
      };
    }
  }
}

export function sanitizeVisuals(raw, catalog) {
  return {
    ...raw,
    sheets: raw.sheets.map((s) => ({ ...s, source: s.source ? catalog.source(s.source) : null })),
    usages: raw.usages.map(({ url, rules, ruleSource, fontFaces, inlineDeclaration, ...u }) => ({
      ...u,
      source: catalog.source(url, `${raw.documentId}:${u.inlineId || u.elementId}`),
      ...(rules
        ? {
            rules: rules.map(({ url, source, ...r }) => ({
              ...r,
              source: source ? catalog.source(source) : null,
              asset: catalog.source(url),
            })),
          }
        : {}),
      ...(ruleSource ? { ruleSource: catalog.source(ruleSource) } : {}),
      ...(inlineDeclaration
        ? {
            inlineDeclaration: {
              ...inlineDeclaration,
              assets: inlineDeclaration.assets.map((s) => catalog.source(s)),
            },
          }
        : {}),
      ...(fontFaces
        ? {
            fontFaces: fontFaces.map((f) => ({
              ...f,
              source: f.source ? catalog.source(f.source) : null,
              sources: f.sources.map((s) => catalog.source(s)),
            })),
          }
        : {}),
    })),
    performanceEntries: raw.performanceEntries.map(({ url, ...e }) => ({
      ...e,
      source: catalog.source(url),
    })),
  };
}

export function requestParameters(request) {
  return [
    ...request.queryParameters.map((name) => ({
      name,
      type: 'string',
      location: 'query',
      value: '[omitted]',
    })),
    ...request.body.fields.map((field) => ({
      ...field,
      location:
        request.body.format === 'JSON'
          ? 'JSON body'
          : request.body.format === 'Multipart form'
            ? 'multipart body'
            : 'form body',
      value: '[omitted]',
    })),
  ];
}

export function buildWiring({
  caseId,
  runId,
  snapshot,
  observations,
  extractionId,
  observationsId,
}) {
  const { captureId } = snapshot,
    visuals = snapshot.visuals;
  const nodes = [],
    edges = [],
    assets = [],
    nodeIds = new Set();
  const ref = (artifactId, pointer) => ({ caseId, runId, captureId, artifactId, pointer });
  const domRef = (pointer) => ref(extractionId, pointer),
    obsRef = (pointer) => ref(observationsId, pointer);
  const addNode = (id, type, label, relation, reason, evidence, details = {}, limitation = '') => {
    if (!nodeIds.has(id)) {
      nodes.push({ id, type, label, relation, reason, limitation, evidence: [evidence], details });
      nodeIds.add(id);
    }
    return id;
  };
  const edge = (source, target, relation, reason, evidence, limitation = '') =>
    edges.push({
      id: `${captureId}:edge:${edges.length}`,
      source,
      target,
      relation,
      reason,
      limitation,
      evidence: [evidence],
    });
  snapshot.elements.forEach((el, i) => {
    const evidence = domRef(`/elements/${i}`);
    addNode(
      el.id,
      'element',
      `${el.tag} ${el.label}`,
      'observed',
      'DOM node extracted in this capture/document',
      evidence,
      el,
      'Main frame only; capture is a sequential observation, not an atomic browser snapshot',
    );
    [...el.listeners, ...el.delegated].forEach((listener, index) => {
      const direct = index < el.listeners.length;
      const lr = domRef(
        `/elements/${i}/${direct ? 'listeners' : 'delegated'}/${direct ? index : index - el.listeners.length}`,
      );
      const id = addNode(
        `${el.id}:handler:${index}`,
        'handler',
        `${listener.event}: ${listener.handler}`,
        direct ? 'observed' : 'correlated',
        direct
          ? 'Listener registration/property observed on this element'
          : 'Listener registered on an ancestor',
        lr,
        listener,
        'Registration does not prove execution, delegation target, or complete framework handler coverage',
      );
      edge(
        el.id,
        id,
        direct ? 'observed' : 'correlated',
        'Listener registration metadata',
        lr,
        'Handler invocation and internal application state were not traced',
      );
    });
    if (el.href || el.form) {
      const id = addNode(
        `${el.id}:destination`,
        'navigation',
        el.href || `${el.form.method} ${el.form.action}`,
        'declared',
        'HTML href/form declaration',
        evidence,
        { href: el.href, form: el.form },
        'JavaScript may intercept or change the destination',
      );
      edge(
        el.id,
        id,
        'declared',
        'Declared destination; not proof of navigation or submission',
        evidence,
      );
    }
  });
  observations.events.forEach((event, i) => {
    const evidence = obsRef(`/events/${i}`),
      id = `${captureId}:event:${event.id}`;
    addNode(
      id,
      'event',
      `${event.type} ${event.selector}`,
      'observed',
      'Capture-phase DOM event observed',
      evidence,
      event,
      'No handler execution trace; synthetic events can also be observed',
    );
    const el = snapshot.elements.find(
      (x) => x.domNodeId === event.domNodeId && event.documentId === snapshot.documentId,
    );
    if (el) {
      edge(
        el.id,
        id,
        'observed',
        'Same runtime DOM identity within the captured document',
        evidence,
      );
      [...el.listeners, ...el.delegated].forEach((listener, li) => {
        if (listener.event === event.type)
          edge(
            id,
            `${el.id}:handler:${li}`,
            'unknown',
            'An observed event and a registration share an event type',
            evidence,
            'Handler execution was not traced; registration does not prove invocation',
          );
      });
    }
  });
  observations.changes.forEach((change, i) => {
    const evidence = obsRef(`/changes/${i}`),
      id = `${captureId}:change:${i}`;
    addNode(
      id,
      'change',
      change.type,
      'observed',
      'DOM mutation or browser history API event observed',
      evidence,
      change,
      'No assertion about which handler caused the change; state and changed content omitted',
    );
    for (const item of change.changes || []) {
      const el = snapshot.elements.find(
        (x) => x.domNodeId === item.domNodeId && change.documentId === snapshot.documentId,
      );
      if (el) edge(el.id, id, 'observed', 'Mutation target has the same DOM identity', evidence);
    }
    const near = observations.events.findLast((e) => e.at <= change.at && change.at - e.at < 1500);
    if (near)
      edge(
        `${captureId}:event:${near.id}`,
        id,
        'correlated',
        'Observed shortly after this event',
        evidence,
        'Temporal proximity does not establish causation',
      );
  });
  observations.requests.forEach((r, i) => {
    const evidence = obsRef(`/requests/${i}`),
      id = `${captureId}:request:${r.id}`;
    addNode(
      id,
      'request',
      `${r.method} ${r.url}`,
      'observed',
      'Playwright request event observed during collection',
      evidence,
      r,
      'Endpoint path is literal; path parameters/backend/controller/database unknown',
    );
    const response = addNode(
      `${id}:response`,
      'response',
      r.status == null ? 'Response unavailable' : `${r.status} ${r.responseType || ''}`,
      r.status == null ? 'unknown' : 'observed',
      r.status == null
        ? 'No response headers available'
        : 'Response status/headers metadata observed',
      evidence,
      {
        status: r.status,
        contentType: r.responseType,
        timing: r.timing,
        duration: r.duration,
        fromServiceWorker: r.fromServiceWorker,
        failure: r.failure,
        body: 'not collected',
      },
      'Response body and server-side processing not collected',
    );
    edge(
      id,
      response,
      r.status == null ? 'unknown' : 'observed',
      'Response attached to the same Playwright Request object',
      evidence,
    );
    for (const [p, parameter] of (r.parameters || []).entries()) {
      const pr = obsRef(`/requests/${i}/parameters/${p}`),
        pid = `${id}:parameter:${p}`;
      addNode(
        pid,
        'parameter',
        `${parameter.name} · ${parameter.location} · ${parameter.type}`,
        'observed',
        'Parameter name/type parsed from this request; values omitted',
        pr,
        parameter,
      );
      edge(pid, id, 'observed', 'Parameter belongs to this request', pr);
      for (const el of snapshot.elements
        .filter((e) => e.name && e.name === parameter.name)
        .slice(0, 20))
        edge(
          el.id,
          pid,
          'correlated',
          'Element name equals parameter name',
          pr,
          'Matching names do not prove the field supplied the value',
        );
      const eventId = r.initiator?.eventId || r.event?.id;
      if (observations.events.some((e) => e.id === eventId))
        edge(
          `${captureId}:event:${eventId}`,
          pid,
          'correlated',
          'Parameter belongs to a request near this event',
          pr,
          'No value propagation or handler execution trace; event does not prove parameter origin',
        );
    }
    const eventId = r.initiator?.eventId || r.event?.id;
    if (observations.events.some((e) => e.id === eventId))
      edge(
        `${captureId}:event:${eventId}`,
        id,
        'correlated',
        r.initiator
          ? 'Same URL/method and nearby fetch/XHR instrumentation event'
          : 'Request occurred near this event',
        evidence,
        'Time/URL matching is heuristic, including for images; no causal handler/request trace',
      );
    if (r.redirectedFromId && observations.requests.some((q) => q.id === r.redirectedFromId))
      edge(
        `${captureId}:request:${r.redirectedFromId}`,
        id,
        'observed',
        'Playwright redirectedFrom object reference',
        evidence,
      );
  });
  visuals.usages.forEach((usage, i) => {
    const evidence = domRef(`/visuals/usages/${i}`),
      id = `${captureId}:asset:${usage.type}:${usage.source.key}`;
    let asset = assets.find((x) => x.id === id);
    if (!asset) {
      asset = {
        id,
        type: usage.type,
        source: usage.source,
        page: snapshot.url,
        uses: [],
        requestIds: [],
        status: 'declaration only; no request observed',
      };
      assets.push(asset);
      addNode(
        id,
        'asset',
        `${usage.type}: ${usage.source.url || usage.declaration}`,
        'observed',
        'Source metadata observed in DOM/CSS; loading tracked separately',
        evidence,
        asset,
        'Serving domain does not identify original server storage; declaration/computed choice does not prove visible pixels',
      );
    }
    asset.uses.push({ ...usage, evidence: [evidence] });
    const declaration = `${captureId}:declaration:${i}`;
    const relation =
      usage.role === 'declared' ? 'declared' : usage.role === 'inferred' ? 'inferred' : 'observed';
    const reason =
      usage.role === 'selected'
        ? 'Browser currentSrc selection observed; completion/dimensions recorded separately'
        : usage.role === 'computed'
          ? 'Computed CSS value observed; does not prove rendering/loading'
          : usage.role === 'inline'
            ? 'Inline SVG DOM present'
            : usage.role === 'inferred'
              ? 'Possible icon based on glyph/markup; actual painted face unknown'
              : 'HTML/CSS source declaration';
    addNode(
      declaration,
      'declaration',
      usage.declaration,
      relation,
      reason,
      evidence,
      usage,
      'CSS rule matches are candidates, not proof of cascade winner',
    );
    edge(usage.elementId, declaration, relation, reason, evidence);
    edge(declaration, id, relation, reason, evidence);
    if (
      usage.source.kind === 'data' ||
      usage.source.kind === 'blob' ||
      usage.source.kind === 'inline'
    )
      asset.status = `${usage.source.kind} source; network request not required`;
    if (usage.role === 'selected')
      asset.status =
        usage.state?.complete && usage.state?.naturalWidth > 0
          ? 'browser selected and decoded'
          : 'browser selected; pending/failed/unknown';
    const timing = visuals.performanceEntries.filter(
      (p) => p.source.requestKey && p.source.requestKey === usage.source.requestKey,
    );
    if (timing.length) asset.resourceTiming = timing;
    for (const [ri, request] of observations.requests.entries()) {
      if (
        !usage.source.requestKey ||
        usage.source.requestKey !== request.sourceKey ||
        request.frameId !== snapshot.frameId
      )
        continue;
      const rid = `${captureId}:request:${request.id}`;
      if (asset.requestIds.includes(rid)) continue;
      asset.requestIds.push(rid);
      edge(
        id,
        rid,
        'observed',
        'Exact source URL identity equals an observed request in this main-frame document epoch',
        obsRef(`/requests/${ri}`),
        'Proves a request for the same source, not that this particular element initiated it',
      );
      asset.status =
        request.failure || request.blocked
          ? 'request failed/blocked'
          : request.status != null
            ? `request observed: ${request.status}`
            : 'request observed: response unavailable';
    }
    if (usage.source.domain) {
      const domainId = `${id}:domain`;
      addNode(
        domainId,
        'domain',
        usage.source.domain,
        usage.source.kind === 'blob' ? 'declared' : 'observed',
        'Domain/origin embedded in source URL',
        evidence,
        { storageOrigin: 'unknown' },
        'CDN host or blob origin is not a storage location or creator trace',
      );
      if (!edges.some((e) => e.source === id && e.target === domainId))
        edge(id, domainId, 'declared', 'Source URL contains this domain', evidence);
    }
  });
  const coverageRef = domRef('/visuals/coverage');
  const unknown = addNode(
    `${captureId}:unknown`,
    'unknown',
    'Backend / framework state / database: unknown',
    'unknown',
    'No source-code or server-side trace acquired',
    coverageRef,
    visuals.coverage,
    'Browser observations cannot establish these internals',
  );
  // An explicit unknown relation prevents the endpoint from being mistaken for backend proof.
  for (const n of nodes.filter((n) => n.type === 'request'))
    edge(
      n.id,
      unknown,
      'unknown',
      'Server processing not observable with this collector',
      coverageRef,
    );
  return {
    schemaVersion: 1,
    captureId,
    caseId,
    runId,
    documentId: snapshot.documentId,
    frameId: snapshot.frameId,
    capturedAt: snapshot.capturedAt,
    nodes,
    edges,
    assets,
    coverage: visuals.coverage,
    gaps: visuals.gaps,
    limits: visuals.limits,
  };
}
