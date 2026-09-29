import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { EvidenceStore } from '../server/evidence.mjs';
import { ForensicService, parseInWorker } from '../server/forensics.mjs';
import { parseArtifact, normalizeTime, FORENSIC_LIMITS } from '../server/forensic-parsers.mjs';
const fixture = (name) => readFile(new URL(`./fixtures/forensics/${name}`, import.meta.url));
const hash = (b) => createHash('sha256').update(b).digest('hex');
const ctx = { sourceId: 'test-original', correlationKey: 'synthetic-key' };
const opts = (format) => ({ format, namespace: 'portal-fixture' });
const csvMapping = {
  time: 'when',
  action: 'operation',
  account: 'principal',
  ip: 'client',
  requestId: 'request',
  url: 'link',
};
const appMapping = { time: '/meta/when', action: 'action', account: 'principal', requestId: 'rid' };
async function setup(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'wi-forensic-'));
  const store = new EvidenceStore(path.join(directory, 'data'));
  await store.init();
  t.after(() => store.close());
  const c = store.createCase({
    title: 'Synthetic forensic case',
    operator: 'Fixture analyst',
    navigation: ['https://portal.example.test'],
  });
  return { store, c, service: new ForensicService(store) };
}
async function upload(service, c, name, format, extra = {}) {
  return service.import(c.id, await fixture(name), { filename: name, ...opts(format), ...extra });
}

test('time preserves source values: explicit offsets, assumptions, ambiguity, invalid calendar and explicit epoch', () => {
  const t = normalizeTime('2025-05-10T09:00:00+07:00');
  assert.equal(t.normalized, '2025-05-10T02:00:00.000Z');
  assert.equal(t.zone, '+07:00');
  assert.equal(t.raw, '2025-05-10T09:00:00+07:00');
  assert.equal(normalizeTime('2025-05-10T09:00:00').status, 'ambiguous');
  const assumed = normalizeTime('2025-05-10T09:00:00', { zone: '+07:00' });
  assert.equal(assumed.status, 'assumed-zone');
  assert.equal(assumed.normalized, t.normalized);
  for (const value of ['Sat, 10 May 2025 09:00:00 CST'])
    assert.equal(normalizeTime(value, { timeFormat: 'rfc5322' }).status, 'ambiguous');
  assert.equal(
    normalizeTime('Sat, 10 May 2025 09:00:00 +0700', { timeFormat: 'rfc5322' }).normalized,
    t.normalized,
  );
  const negativeZero = normalizeTime('Sat, 10 May 2025 09:00:00 -0000', { timeFormat: 'rfc5322' });
  assert.equal(negativeZero.status, 'unknown-local-offset');
  assert.equal(negativeZero.normalized, '2025-05-10T09:00:00.000Z');
  assert.equal(normalizeTime('2025-05-10T09:00:00-00:00').status, 'unknown-local-offset');
  assert.equal(normalizeTime('2025-02-30T09:00:00Z').status, 'invalid');
  assert.equal(normalizeTime(null).status, 'unknown');
  assert.equal(normalizeTime('05/10/25').status, 'ambiguous');
  assert.equal(normalizeTime(0, { timeFormat: 'unix-ms' }).normalized, '1970-01-01T00:00:00.000Z');
  assert.equal(normalizeTime(0).status, 'ambiguous');
});

test('all supported formats produce field-level locations; HAR and log secrets omitted, MIME decoded hash matches file', async () => {
  const har = parseArtifact(
    await fixture('transfer.har'),
    { ...opts('har'), timeFormat: 'unix-ms' },
    ctx,
  );
  assert.equal(har.events[0].time.normalized, '2025-05-10T02:00:00.000Z');
  assert(!JSON.stringify(har).includes('SECRET_'));
  assert.equal(
    har.events[0].fields.find((f) => f.name === 'url').provenance.location.pointer,
    '/log/entries/0/request/url',
  );
  const logs = parseArtifact(await fixture('auth.ndjson'), opts('ndjson'), ctx);
  assert.equal(logs.events.length, 4);
  assert.equal(logs.events[2].time.status, 'ambiguous');
  assert.equal(logs.events[0].fields[0].provenance.location.line, 1);
  assert.equal(logs.events[3].provenance.location.line, 5);
  assert(logs.coverage.gaps.some((g) => g.includes('Line 4')));
  assert(!JSON.stringify(logs).includes('SECRET_'));
  const app = parseArtifact(
    await fixture('application.json'),
    { ...opts('json'), mapping: appMapping },
    ctx,
  );
  assert.equal(app.events[0].time.normalized, har.events[0].time.normalized);
  assert.equal(app.events[0].fields[0].provenance.location.pointer, '/events/0/meta/when');
  const csv = parseArtifact(
    await fixture('audit.csv'),
    { ...opts('csv'), mapping: csvMapping },
    ctx,
  );
  assert.equal(csv.events.length, 3);
  assert.equal(csv.events[1].fields.find((f) => f.name === 'action').value, 'two\nlines');
  assert.equal(csv.events[1].provenance.location.lineStart, 3);
  assert.equal(csv.events[1].provenance.location.lineEnd, 4);
  assert(csv.events[2].fields.find((f) => f.name === 'action').value.startsWith('=WEBSERVICE'));
  const eml = parseArtifact(await fixture('message.eml'), opts('eml'), ctx);
  assert.equal(eml.events[0].time.normalized, '2025-05-10T02:00:05.000Z');
  assert.equal(eml.events[0].fields.find((f) => f.name === 'from-1').provenance.location.part, '1');
  assert(!JSON.stringify(eml).includes('SECRET_'));
  const part = eml.events.find((e) => e.provenance.location.part === '1.3');
  assert.equal(
    part.fields.find((f) => f.name === 'sha256').value,
    hash(await fixture('export.txt')),
  );
  assert(part.fields.find((f) => f.name === 'filename').value.includes('../'));
  const file = parseArtifact(await fixture('export.txt'), opts('file'), ctx);
  assert.equal(file.events[0].fields[0].value, hash(await fixture('export.txt')));
  assert.equal(file.events[0].time.status, 'unknown');
  for (const parsed of [har, logs, app, csv, eml, file])
    for (const e of parsed.events)
      for (const f of e.fields) {
        assert(f.provenance.parser.version);
        assert(f.provenance.location.kind);
      }
});

test('malformed, oversized, depth/node/resource limits and worker timeout produce bounded failures', async () => {
  for (const [bytes, format] of [
    ['{', 'json'],
    ['{}', 'har'],
    ['x\n"unterminated', 'csv'],
    ['nonsense', 'eml'],
  ])
    assert.equal((await parseInWorker(Buffer.from(bytes), opts(format), ctx)).ok, false);
  assert.throws(
    () => parseArtifact(Buffer.alloc(FORENSIC_LIMITS.inputBytes + 1), opts('file'), ctx),
    /byte limit/,
  );
  assert.throws(
    () => parseArtifact(Buffer.from('['.repeat(30) + '0' + ']'.repeat(30)), opts('json'), ctx),
    /depth/,
  );
  assert.throws(
    () => parseArtifact(Buffer.from(JSON.stringify(Array(51000).fill(0))), opts('json'), ctx),
    /node/,
  );
  const many = parseArtifact(
    Buffer.from(JSON.stringify(Array.from({ length: 1002 }, () => ({ event: 'fixture' })))),
    opts('json'),
    ctx,
  );
  assert.equal(many.events.length, 1000);
  assert(many.coverage.gaps.includes('Event limit reached'));
  const timed = await parseInWorker(await fixture('transfer.har'), opts('har'), ctx, 1);
  assert.equal(timed.ok, false);
  assert.match(timed.error, /timeout/);
});

test('encrypted original, repeated copies, case isolation, reparse history, failed parsing and provenance stay intact', async (t) => {
  const { store, c, service } = await setup(t);
  const bytes = await fixture('auth.ndjson');
  const a = await upload(service, c, 'auth.ndjson', 'ndjson');
  const b = await upload(service, c, 'auth.ndjson', 'ndjson');
  assert.notEqual(a.sourceId, b.sourceId);
  let view = service.view(c.id);
  assert.equal(view.sources.length, 2);
  assert(view.sources.every((s) => s.duplicates.length === 1));
  const ref = view.sources[0].originalRef;
  assert.deepEqual(service.verify(ref), bytes);
  assert(
    !Buffer.from(
      store.db.prepare('SELECT bytes FROM artifacts WHERE id=?').get(ref.artifactId).bytes,
    ).includes(Buffer.from('SECRET_PASSWORD')),
  );
  assert.match(store.artifact(c.id, ref.runId, ref.artifactId).baseline, /import only/);
  const prior = service.view(c.id, { sourceId: a.sourceId, version: a.parseRef.artifactId });
  assert.equal(
    prior.events.find((e) => e.time.raw === '2025-05-10T09:02:00').time.status,
    'ambiguous',
  );
  await service.reparse(c.id, a.sourceId, { zone: '+07:00' });
  view = service.view(c.id, { sourceId: a.sourceId });
  assert.equal(view.sources.find((s) => s.id === a.sourceId).versions.length, 2);
  assert.equal(
    view.events.find((e) => e.time.raw === '2025-05-10T09:02:00').time.status,
    'assumed-zone',
  );
  assert.equal(
    service
      .view(c.id, { sourceId: a.sourceId, version: a.parseRef.artifactId })
      .events.find((e) => e.time.raw === '2025-05-10T09:02:00').time.status,
    'ambiguous',
  );
  assert.deepEqual(service.verify(ref), bytes);
  for (const e of view.events) {
    assert.equal(e.evidence.artifactId, a.sourceId);
    assert.equal(e.evidence.extractionRef.artifactId, e.parseRef.artifactId);
    assert(e.importedTime.at !== e.time.normalized);
    assert.equal(e.collectedTime.status, 'unknown');
  }
  const other = store.createCase({
    title: 'Other fixture',
    operator: 'Other',
    navigation: ['https://portal.example.test'],
  });
  assert.throws(() => service.preview(other.id, a.sourceId), /kasus/);
  await assert.rejects(() => service.reparse(other.id, a.sourceId), /kasus/);
  assert.throws(() => service.preview(c.id, '../../keys'), /kasus/);
  await assert.rejects(
    () => service.import(c.id, bytes, { filename: '../x', format: 'ndjson' }),
    /basename/,
  );
  await assert.rejects(
    () =>
      service.import(c.id, Buffer.alloc(8 * 1024 * 1024 + 1), { filename: 'big', format: 'file' }),
    /8 MiB/,
  );
  const broken = await upload(service, c, 'broken.har', 'har');
  assert.equal(broken.coverage.status, 'parse-failed');
  assert.equal(store.getRun(c.id, broken.runId).status, 'partial');
  assert.deepEqual(
    service.verify(service.view(c.id).sources.find((s) => s.id === broken.sourceId).originalRef),
    await fixture('broken.har'),
  );
  assert(store.events(c.id).some((e) => e.type === 'forensic.import-rejected'));
  assert(store.verifyRun(c.id, a.runId).ok);
});

test('cross-source equal values remain correlations; namespace isolation, misleading IP/time, computed/claimed hashes', async (t) => {
  const { c, service } = await setup(t);
  for (const [name, format, extra] of [
    ['transfer.har', 'har', {}],
    ['auth.ndjson', 'ndjson', {}],
    ['application.json', 'json', { mapping: appMapping }],
    ['audit.csv', 'csv', { mapping: csvMapping }],
    ['message.eml', 'eml', {}],
    ['export.txt', 'file', {}],
  ])
    await upload(service, c, name, format, extra);
  let view = service.view(c.id);
  assert(view.graph.edges.every((e) => e.evidence.length));
  assert(view.graph.edges.some((e) => e.relation === 'correlated'));
  assert(!view.graph.edges.some((e) => /caus/.test(e.relation)));
  const request = view.graph.nodes.filter((n) => n.kind === 'request' && n.label === 'req-42');
  assert(request.length >= 4);
  assert.equal(new Set(request.map((n) => n.matchKey)).size, 1);
  const sharedIP = view.graph.nodes.filter((n) => n.kind === 'ip' && n.label === '198.51.100.24');
  assert(sharedIP.length >= 4);
  assert.equal(new Set(sharedIP.map((n) => n.id)).size, sharedIP.length);
  assert(view.graph.nodes.some((n) => n.kind === 'account' && n.label === 'bob@example.test'));
  assert(view.graph.nodes.some((n) => n.kind === 'account' && n.label === 'alice@example.test'));
  const digest = hash(await fixture('export.txt'));
  const h = view.graph.nodes.filter((n) => n.kind === 'hash' && n.label === digest);
  assert(new Set(h.map((n) => n.sourceId)).size >= 2);
  assert(h.some((n) => n.method === 'computed SHA-256 of these bytes'));
  assert(view.events.some((e) => e.time.status === 'ambiguous'));
  assert(view.events.every((e) => e.basis === 'imported-source-claim'));
  const isolated = await upload(service, c, 'transfer.har', 'har', { namespace: '' });
  view = service.view(c.id);
  assert.notEqual(
    view.graph.nodes.find((n) => n.sourceId === isolated.sourceId && n.kind === 'request').matchKey,
    request[0].matchKey,
  );
  assert(!view.graph.nodes.some((n) => n.kind === 'session'));
  assert(view.graph.nodes.some((n) => n.kind === 'session-claim'));
});

test('notes, support/contradiction, reversible skew and manual merge; strict share cannot expose originals or analyst text', async (t) => {
  const { store, c, service } = await setup(t);
  const a = await upload(service, c, 'auth.ndjson', 'ndjson');
  await upload(service, c, 'transfer.har', 'har');
  let view = service.view(c.id);
  const ids = view.events.filter((e) => e.sourceId === a.sourceId).map((e) => e.id);
  const actor = { operator: 'Private analyst', reason: 'SECRET_ANALYST_TEXT' };
  const bookmark = service.operation(c.id, { ...actor, kind: 'bookmark', eventIds: [ids[0]] });
  service.operation(c.id, {
    ...actor,
    kind: 'hypothesis',
    eventIds: ids.slice(0, 2),
    supporting: [ids[0]],
    contradicting: [ids[1]],
  });
  const originalTime = view.events.find((e) => e.id === ids[0]).time.normalized;
  const skew = service.operation(c.id, {
    ...actor,
    kind: 'clock-skew',
    sourceId: a.sourceId,
    seconds: 60,
  });
  view = service.view(c.id);
  const shifted = view.events.find((e) => e.id === ids[0]);
  assert.equal(shifted.time.normalized, originalTime);
  assert.equal(Date.parse(shifted.displayTime) - Date.parse(originalTime), 60000);
  assert.equal(shifted.clockTransform.id, skew.id);
  const ips = view.graph.nodes.filter((n) => n.kind === 'ip').slice(0, 2);
  const merge = service.operation(c.id, {
    ...actor,
    kind: 'merge',
    entityIds: ips.map((n) => n.id),
  });
  assert(
    service
      .view(c.id)
      .graph.edges.some((e) => e.source === 'manual:' + merge.id && e.relation === 'inferred'),
  );
  for (const target of [skew, merge, bookmark])
    service.operation(c.id, { ...actor, kind: 'revert', target: target.id });
  view = service.view(c.id);
  assert.equal(view.events.find((e) => e.id === ids[0]).displayTime, originalTime);
  assert(!view.graph.nodes.some((n) => n.kind === 'manual-association'));
  assert(view.operations.find((o) => o.id === bookmark.id).active === false);
  const hypothesis = view.operations.find((o) => o.kind === 'hypothesis');
  assert.equal(hypothesis.status, 'unverified-hypothesis');
  assert.equal(hypothesis.supporting.length, 1);
  assert.equal(hypothesis.contradicting.length, 1);
  await service.import(c.id, Buffer.from(JSON.stringify([{ sha256: 'c'.repeat(64) }])), {
    filename: 'claimed-hash.json',
    format: 'json',
  });
  const shared = service.share(c.id);
  const json = JSON.stringify(shared.share);
  assert(
    !json.includes('c'.repeat(64)),
    'Only computed hashes, not arbitrary source-declared hash field values, survive strict sharing',
  );
  for (const secret of [
    'SECRET_',
    'alice@example.test',
    '198.51.100.24',
    'portal.example.test',
    'auth.ndjson',
    'Private analyst',
    'portal-fixture',
  ])
    assert(!json.includes(secret), secret);
  assert.equal(
    shared.share.operations.find((o) => o.kind === 'hypothesis').status,
    'unverified-hypothesis',
  );
  assert.equal(service.verify(shared.ref).toString(), JSON.stringify(shared.share));
  assert(store.verifyRun(c.id, shared.ref.runId).ok);
});

test('tampered synthetic original blocks preview/reparse/share and removes untrusted events', async (t) => {
  const { store, c, service } = await setup(t);
  const a = await upload(service, c, 'transfer.har', 'har');
  store.db.exec('DROP TRIGGER immutable_artifacts_UPDATE');
  const bytes = Buffer.from(
    store.db.prepare('SELECT bytes FROM artifacts WHERE id=?').get(a.sourceId).bytes,
  );
  bytes[bytes.length - 1] ^= 1;
  store.db.prepare('UPDATE artifacts SET bytes=? WHERE id=?').run(bytes, a.sourceId);
  assert(!store.verifyRun(c.id, a.runId).ok);
  assert.equal(service.view(c.id).events.length, 0);
  assert.throws(() => service.preview(c.id, a.sourceId), /Integritas/);
  assert.throws(() => service.share(c.id), /integritas/);
  await assert.rejects(() => service.reparse(c.id, a.sourceId), /Integritas/);
});

test('browser report adapter retains collection basis/session continuity; legacy remains a claim', async (t) => {
  const { store, c, service } = await setup(t);
  const run = store.createRun(c.id, { mode: 'authenticated', url: 'https://portal.example.test' });
  store.seal({
    id: run.id,
    caseId: c.id,
    url: run.url,
    mode: run.mode,
    status: 'complete',
    pages: [],
    events: [],
    edges: [],
    warnings: [],
    requests: [{ id: 'r1', url: run.url, method: 'GET', status: 200, startedAt: Date.now() }],
    sessionInfo: { id: 'context-fixture' },
  });
  await service.addCapture(c.id, run.id);
  const view = service.view(c.id);
  assert.equal(view.events[0].basis, 'browser-observation-at-capture');
  assert.equal(view.events[0].importedTime, null);
  assert.equal(view.events[0].collectedTime.status, 'collector-clock');
  assert(view.graph.nodes.some((n) => n.kind === 'session'));
  assert(view.limitations.some((x) => x.includes('historical reconstruction')));
  const parsed = parseArtifact(
    Buffer.from(JSON.stringify({ requests: [{ startedAt: 0, id: 'legacy' }] })),
    { format: 'web-capture' },
    { ...ctx, legacy: true, browserSession: true, sourceRunId: run.id },
  );
  const legacyRun = store.createRun(c.id, { mode: 'passive', url: run.url, legacy: true });
  store.seal({
    id: legacyRun.id,
    caseId: c.id,
    url: run.url,
    mode: 'passive',
    status: 'complete',
    pages: [],
    events: [],
    edges: [],
    warnings: [],
    requests: [{ startedAt: 0, id: 'old' }],
  });
  await service.addCapture(c.id, legacyRun.id);
  const legacyEvent = service.view(c.id).events.find((e) => e.basis === 'legacy-source-claim');
  assert.equal(legacyEvent.collectedTime.status, 'unknown');
  assert.equal(legacyEvent.collectedTime.normalized, null);
  assert(legacyEvent.importedTime.at);
  assert.equal(parsed.events[0].basis, 'legacy-source-claim');
  assert(!parsed.events[0].entities.some((e) => e.kind === 'session'));
});

test('timeout and interrupted imports preserve originals with partial manifests and accurate privacy', async (t) => {
  const { store, c } = await setup(t);
  const service = new ForensicService(store, {
    parser: (bytes, options, context) => parseInWorker(bytes, options, context, 1),
  });
  const a = await upload(service, c, 'transfer.har', 'har');
  assert.equal(a.coverage.status, 'parse-failed');
  assert.match(a.coverage.gaps[0], /timeout/);
  assert.equal(store.getRun(c.id, a.runId).status, 'partial');
  const view = service.view(c.id);
  assert.deepEqual(service.verify(view.sources[0].originalRef), await fixture('transfer.har'));
  const artifacts = store.artifacts(c.id, a.runId);
  const manifest = JSON.parse(
    store.readArtifact(c.id, a.runId, artifacts.find((a) => a.kind === 'capture-manifest').id),
  );
  assert(manifest.analysis.privacy.collected.some((x) => x.includes('sensitive')));
  assert(manifest.collectorActions.every((x) => !x.includes('Browser rendered')));
  assert(manifest.errors.some((x) => x.includes('Parsing failed')));
  const { AuditManager } = await import('../server/audit.mjs');
  const directory = await mkdtemp(path.join(tmpdir(), 'wi-forensic-recovery-'));
  const pending = new EvidenceStore(path.join(directory, 'data'));
  await pending.init();
  const pc = pending.createCase({
    title: 'Recovery fixture',
    operator: 'Fixture',
    navigation: ['https://portal.example.test'],
  });
  const run = pending.createRun(pc.id, {
    mode: 'forensic-import',
    url: 'https://portal.example.test',
    config: { format: 'file' },
  });
  const original = pending.addArtifact(pc.id, run.id, Buffer.from('synthetic pending'), {
    kind: 'forensic-original',
    source: 'upload:fixture',
    label: 'Fixture',
    mimeType: 'application/octet-stream',
  });
  pending.close();
  const manager = new AuditManager(path.join(directory, 'data'));
  await manager.init();
  t.after(async () => {
    await manager.close();
    manager.store.close();
  });
  assert.equal(manager.store.getRun(pc.id, run.id).status, 'partial');
  assert.equal(
    manager.store.readArtifact(pc.id, run.id, original.id).toString(),
    'synthetic pending',
  );
  assert.equal(manager.jobs.size, 0);
  const recovered = new ForensicService(manager.store);
  await recovered.reparse(pc.id, original.id, { format: 'file' });
  assert.equal(recovered.view(pc.id).events.length, 1);
});

test('analyst references older parse versions; CSV slash headers and MIME LF bytes do not lose provenance', async (t) => {
  const { c, service } = await setup(t);
  const a = await upload(service, c, 'auth.ndjson', 'ndjson');
  const old = service.view(c.id).events[0];
  await service.reparse(c.id, a.sourceId, { zone: '+07:00' });
  const note = service.operation(c.id, {
    kind: 'note',
    operator: 'Fixture',
    reason: 'Inspect the original parser interpretation',
    eventIds: [old.id],
  });
  assert.equal(note.evidence[0].extractionRef.artifactId, old.parseRef.artifactId);
  const csv = parseArtifact(
    Buffer.from('/when,name\n2025-05-10T02:00:00Z,alice\n'),
    { format: 'csv', mapping: { time: '/when', account: 'name' } },
    ctx,
  );
  assert.equal(csv.events[0].time.normalized, '2025-05-10T02:00:00.000Z');
  const mime = parseArtifact(
    Buffer.from(
      'Content-Type: multipart/mixed; boundary="b"\n\n--b\nContent-Type: application/octet-stream\n\none\ntwo\n--b--\n',
    ),
    opts('eml'),
    ctx,
  );
  assert.equal(
    mime.events.find((e) => e.type === 'mime-part').fields.find((f) => f.name === 'sha256').value,
    hash(Buffer.from('one\ntwo')),
  );
});

test('case storage budget rejects new acquisition without dropping existing evidence', async (t) => {
  const { c, service, store } = await setup(t);
  await upload(service, c, 'export.txt', 'file');
  const before = store.listRuns(c.id).length;
  const budget = FORENSIC_LIMITS.caseAnalysisBytes;
  try {
    FORENSIC_LIMITS.caseAnalysisBytes = 1;
    await assert.rejects(() => upload(service, c, 'export.txt', 'file'), /Budget analisis/);
  } finally {
    FORENSIC_LIMITS.caseAnalysisBytes = budget;
  }
  assert.equal(store.listRuns(c.id).length, before);
  assert(store.verifyRun(c.id, store.listRuns(c.id)[0].id).ok);
});
