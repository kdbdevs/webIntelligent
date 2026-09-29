import { SecurityService } from './security.mjs';
import { fail, digest } from './evidence.mjs';
import {
  EvidenceReader,
  captureData,
  saveRecord,
  stampRecord,
  short,
  uniqueRefs,
  REPORT_LIMITS,
} from './report-common.mjs';
const canonical = (v) => JSON.stringify(v);
const endpoint = (value) => {
  try {
    const u = new URL(value);
    return { key: u.origin + u.pathname, domain: u.host, queryUnknown: !!(u.search || u.hash) };
  } catch {
    return { key: short(value), domain: 'unknown', queryUnknown: true };
  }
};
function inventory(reader, capture) {
  const buckets = Object.fromEntries(
    ['pages', 'elements', 'assets', 'domains', 'endpoints', 'parameters', 'findings'].map((k) => [
      k,
      new Map(),
    ]),
  );
  let omitted = 0;
  const add = (kind, key, label, value, ref, ambiguous = false) => {
    const map = buckets[kind];
    if (map.size >= 1000) {
      omitted++;
      return;
    }
    let row = map.get(key);
    if (!row) {
      row = { key, label: short(label, 500), values: [], refs: [], ambiguous };
      map.set(key, row);
    }
    row.values.push(value);
    row.refs.push(reader.reference(ref));
    row.ambiguous ||= ambiguous;
  };
  capture.pages.forEach((p, i) => {
    const pref = capture.pageRef(i),
      page = endpoint(p.url),
      key = page.key;
    add(
      'pages',
      key,
      p.url,
      {
        title: p.title,
        status: p.status,
        elementCount: p.elements?.length || 0,
        truncated: !!p.truncated,
      },
      pref,
      page.queryUnknown,
    );
    (p.elements || []).forEach((el, j) =>
      add(
        'elements',
        `${key}|${el.selector}`,
        `${p.url} · ${el.selector}`,
        {
          tag: el.tag,
          type: el.type,
          name: el.name,
          label: el.label,
          href: el.href,
          action: el.action,
        },
        { ...pref, pointer: pref.pointer + `/elements/${j}` },
        page.queryUnknown,
      ),
    );
    const visual = p.visuals;
    for (const [j, use] of (visual?.usages || []).entries()) {
      const s = use.source || {};
      const url = s.url || s.kind || 'unknown';
      const e = endpoint(url);
      const kind = s.kind || 'unknown';
      const nonNetwork = kind !== 'network';
      add(
        'assets',
        `${key}|${use.type || use.kind}|${nonNetwork ? capture.ref.artifactId + ':' + j : e.key}`,
        url,
        {
          kind,
          type: use.type,
          role: use.role,
          declaration: use.declaration,
          state: use.state,
          position: use.position,
          size: use.size,
        },
        { ...pref, pointer: pref.pointer + `/visuals/usages/${j}` },
        nonNetwork || e.queryUnknown,
      );
      if (s.domain) add('domains', s.domain, s.domain, { basis: 'visual-source' }, pref);
    }
  });
  capture.requests.forEach((r, i) => {
    const ep = endpoint(r.url),
      ref = { ...capture.requestRef, pointer: `/requests/${i}` },
      key = `${r.method || 'unknown'} ${ep.key}`;
    add(
      'endpoints',
      key,
      key,
      {
        status: r.status ?? null,
        contentType: r.responseType ?? null,
        blocked: !!r.blocked,
        failed: !!r.failure,
        resourceType: r.resourceType,
      },
      ref,
      ep.queryUnknown,
    );
    add('domains', ep.domain, ep.domain, { basis: 'observed-request' }, ref);
    const params = Array.isArray(r.parameters)
      ? r.parameters
      : (r.queryParameters || []).map((name) => ({ name, location: 'query', type: 'unknown' }));
    params.forEach((p, j) =>
      add(
        'parameters',
        `${key}|${p.location}|${p.name}`,
        `${key} · ${p.location}: ${p.name}`,
        { type: p.type },
        ref,
        ep.queryUnknown,
      ),
    );
  });
  const security = new SecurityService(reader.store);
  const latest = security.list(reader.caseId, capture.run.id)[0];
  let findingBasis = 'not-assessed';
  if (latest) {
    const a = security.get(reader.caseId, latest.id);
    findingBasis =
      'latest run-level assessment snapshot; page selection does not narrow assessment coverage';
    a.findings.forEach((f, i) => {
      const req = capture.requests.find((r) => r.id === f.requestId);
      const exactRef = { caseId: reader.caseId, ...a.record, pointer: `/findings/${i}` };
      add(
        'findings',
        `${f.ruleId}|${req ? endpoint(req.url).key : f.requestId}`,
        `${f.ruleId} · ${f.title}`,
        { status: f.status, risk: f.risk, confidence: f.confidence, revision: f.revision },
        exactRef,
        !req,
      );
    });
    for (const recordRun of a.recordRuns) {
      const run = reader.store.getRun(reader.caseId, recordRun);
      const artifact = reader.store
        .artifacts(reader.caseId, recordRun)
        .find((x) => x.kind === run.mode);
      if (artifact)
        Array.from(buckets.findings.values()).forEach((row) =>
          row.refs.push({
            caseId: reader.caseId,
            runId: run.id,
            artifactId: artifact.id,
            sha256: artifact.sha256,
            pointer: '',
          }),
        );
    }
  }
  return { buckets, omitted, findingBasis };
}
export function compareCaptures(store, caseId, input) {
  if (input.leftId === input.rightId) throw fail('Pilih dua capture yang berbeda.');
  const reader = new EvidenceReader(store, caseId),
    left = captureData(reader, input.leftId),
    right = captureData(reader, input.rightId);
  const li = inventory(reader, left),
    ri = inventory(reader, right),
    differences = [];
  const context = {
    left: left.coverage,
    right: right.coverage,
    identityDeclaration: {
      left: short(input.leftIdentity || 'unknown', 200),
      right: short(input.rightIdentity || 'unknown', 200),
      basis: 'Analyst declaration only; identity equality not verified',
    },
    findingBasis: { left: li.findingBasis, right: ri.findingBasis },
    warnings: [
      'Not observed in B does not establish deletion or remediation. Differences can reflect coverage, policy, identity, rendering, timing or failures.',
      'Matching uses visible page/path+selector or endpoint+method; query/fragment redaction and repeated selectors reduce identity confidence.',
      'Data/blob/inline assets cannot be matched across capture solely from opaque per-run IDs. Byte equality is not assessed.',
    ],
  };
  if (canonical(left.coverage.visited) !== canonical(right.coverage.visited))
    context.warnings.push('Visited page sets differ.');
  if (canonical(left.coverage.policy) !== canonical(right.coverage.policy))
    context.warnings.push('Capture configurations/policies differ.');
  if (left.coverage.failedRequests || right.coverage.failedRequests)
    context.warnings.push('Failed, blocked or incomplete responses may explain differences.');
  if (li.omitted || ri.omitted)
    context.warnings.push('Inventory limit reached; incomplete comparison.');
  for (const kind of Object.keys(li.buckets)) {
    const a = li.buckets[kind],
      b = ri.buckets[kind];
    for (const key of new Set([...a.keys(), ...b.keys()])) {
      const old = a.get(key),
        next = b.get(key);
      const summarize = (row) => (row ? [...new Set(row.values.map(canonical))].sort() : null);
      const before = summarize(old),
        after = summarize(next);
      const change = !old
        ? 'newly-observed'
        : !next
          ? 'not-observed-in-B'
          : canonical(before) !== canonical(after)
            ? 'metadata-changed'
            : 'same-observed-metadata';
      differences.push({
        id: `diff-${differences.length + 1}`,
        kind,
        change,
        label: (next || old).label,
        before: old?.values || [],
        after: next?.values || [],
        matching: 'heuristic-metadata-key',
        confidence: old?.ambiguous || next?.ambiguous ? 'limited' : 'metadata-match-only',
        reason:
          change === 'not-observed-in-B'
            ? 'Absence from the selected evidence; deletion/fix not established'
            : 'Observed metadata sets compared, not underlying content bytes',
        evidence: uniqueRefs([...(old?.refs || []), ...(next?.refs || [])]),
        keyDigest: digest(key),
      });
    }
  }
  const body = stampRecord({
    kind: 'capture-comparison',
    caseId,
    leftRef: left.ref,
    rightRef: right.ref,
    context,
    counts: Object.fromEntries(
      ['newly-observed', 'not-observed-in-B', 'metadata-changed', 'same-observed-metadata'].map(
        (k) => [k, differences.filter((d) => d.change === k).length],
      ),
    ),
    rows: differences.slice(0, REPORT_LIMITS.comparisonRows),
    truncated: differences.length > REPORT_LIMITS.comparisonRows,
    refs: uniqueRefs([left.ref, right.ref, ...differences.flatMap((d) => d.evidence)]),
  });
  return saveRecord(store, caseId, 'capture-comparison', body);
}
