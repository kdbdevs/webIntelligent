import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { EvidenceStore, LIMITS, digest, inScope } from '../server/evidence.mjs';
import { AuditManager } from '../server/audit.mjs';

async function setup(t) {
  const base = await mkdtemp(path.join(tmpdir(), 'wi-evidence-test-'));
  const directory = path.join(base, 'data');
  const store = new EvidenceStore(directory);
  await store.init();
  t.after(() => {
    if (store.db.isOpen) store.close();
  });
  const c = store.createCase({
    title: 'Fixture case',
    objective: 'Test evidence',
    operator: 'Synthetic analyst',
    navigation: ['https://example.com/app'],
  });
  const run = store.createRun(c.id, { url: 'https://example.com/app', config: { maxPages: 1 } });
  const job = {
    id: run.id,
    caseId: c.id,
    mode: 'passive',
    url: run.url,
    createdAt: run.started.at,
    status: 'running',
    pages: [],
    requests: [],
    events: [],
    edges: [],
    warnings: [],
    session: null,
  };
  return { directory, store, c, run, job };
}
function add(store, c, run, value = 'sensitive-fixture-payload') {
  return store.addArtifact(c.id, run.id, value, {
    kind: 'fixture',
    role: 'original',
    label: 'Fixture',
    source: run.url,
    mimeType: 'text/plain',
  });
}

test('encrypted acquisition, immutable bytes, verified inspection and reproducible manifest', async (t) => {
  const { store, c, run, job } = await setup(t);
  const a = add(store, c, run);
  assert.equal(a.sha256, digest('sensitive-fixture-payload'));
  const bytes = store.db.prepare('SELECT bytes FROM artifacts WHERE id=?').get(a.id).bytes;
  assert(!Buffer.from(bytes).includes(Buffer.from('sensitive-fixture-payload')));
  assert.equal(store.readArtifact(c.id, run.id, a.id).toString(), 'sensitive-fixture-payload');
  assert.throws(
    () =>
      store.db
        .prepare('UPDATE artifacts SET bytes=? WHERE id=?')
        .run(Buffer.from('replacement'), a.id),
    /Immutable/,
  );
  assert.throws(() => store.db.prepare('DELETE FROM artifacts WHERE id=?').run(a.id), /Immutable/);
  assert.throws(() => store.db.exec('DELETE FROM events'), /Immutable/);
  job.status = 'complete';
  const sealed = store.seal(job);
  assert.equal(sealed.status, 'complete');
  assert.throws(() => add(store, c, run), /disegel/);
  const manifest = store.exportManifest(c.id, run.id);
  assert(manifest.verification.ok);
  assert.equal(manifest.run.id, run.id);
  assert(manifest.artifacts.some((x) => x.id === a.id));
  assert(!JSON.stringify(manifest).includes(store.key.toString('hex')));
  assert(manifest.custody.some((e) => e.type === 'manifest.exported'));
  assert.equal(store.loadJobs()[0].status, 'complete');
});

test('corrupt fixture bytes fail verification, reading, and export', async (t) => {
  const { store, c, run, job } = await setup(t);
  const a = add(store, c, run);
  job.status = 'complete';
  store.seal(job);
  // Deliberately simulate a host administrator corrupting this disposable fixture DB.
  store.db.exec('DROP TRIGGER immutable_artifacts_UPDATE');
  const bytes = Buffer.from(
    store.db.prepare('SELECT bytes FROM artifacts WHERE id=?').get(a.id).bytes,
  );
  bytes[bytes.length - 1] ^= 1;
  store.db.prepare('UPDATE artifacts SET bytes=? WHERE id=?').run(bytes, a.id);
  assert.equal(store.verifyRun(c.id, run.id).ok, false);
  assert.throws(() => store.readArtifact(c.id, run.id, a.id), /Integritas/);
  assert.throws(() => store.exportManifest(c.id, run.id), /integritas/);
});

test('case isolation, navigation scope, lineage and path-like IDs', async (t) => {
  const { store, c, run } = await setup(t);
  const second = store.createCase({
    title: 'Other',
    operator: 'Other analyst',
    navigation: ['https://other.example'],
  });
  const r2 = store.createRun(second.id, { url: 'https://other.example/' });
  const a = add(store, c, run);
  assert.throws(() => store.getRun(second.id, run.id), /tidak ditemukan/);
  assert.throws(() => store.readArtifact(second.id, r2.id, a.id), /tidak ditemukan/);
  assert.throws(
    () => store.addArtifact(second.id, r2.id, '{}', { kind: 'derived', derivedFrom: [a.id] }),
    /tidak ditemukan/,
  );
  assert.throws(() => store.artifact(c.id, run.id, '../../master.key'), /ID tidak valid/);
  assert.throws(() => store.createRun(c.id, { url: 'https://example.com/outside' }), /scope/);
  assert(inScope('https://example.com/app/child?x=1', c.scope.navigation));
  assert(!inScope('https://example.com/apple', c.scope.navigation));
  assert(!inScope('https://example.com:8443/app', c.scope.navigation));
  assert.throws(() => store.updateCase(c.id, { operator: 'Changed during run' }), /run aktif/);
});

test('limits reject oversized evidence; case edits preserve before/after custody', async (t) => {
  const { store, c, run, job } = await setup(t);
  assert.throws(() => add(store, c, run, Buffer.alloc(LIMITS.artifactBytes + 1)), /Batas/);
  job.status = 'cancelled';
  store.seal(job, 'Cancelled by fixture');
  store.updateCase(c.id, { title: 'Renamed', notes: 'Reviewed', status: 'closed' });
  const changed = store.events(c.id).find((e) => e.type === 'case.updated');
  assert.equal(changed.details.before.title, 'Fixture case');
  assert.equal(changed.details.after.title, 'Renamed');
  assert.throws(() => store.createRun(c.id, { url: run.url }), /ditutup/);
  assert.equal(store.getRun(c.id, run.id).status, 'partial');
});

test('restart seals interrupted capture and preserves saved evidence', async (t) => {
  const { directory, store, c, run, job } = await setup(t);
  const a = add(store, c, run);
  store.saveJob(job);
  store.close();
  const manager = new AuditManager(directory);
  await manager.init();
  t.after(() => manager.store.close());
  const restored = manager.jobs.get(run.id);
  assert.equal(restored.status, 'interrupted');
  assert.equal(manager.store.getRun(c.id, run.id).status, 'partial');
  assert.equal(
    manager.store.readArtifact(c.id, run.id, a.id).toString(),
    'sensitive-fixture-payload',
  );
  assert(manager.store.exportManifest(c.id, run.id).verification.ok);
});

test('legacy import leaves source bytes intact, labels baseline and is idempotent', async (t) => {
  const base = await mkdtemp(path.join(tmpdir(), 'wi-legacy-test-'));
  const directory = path.join(base, 'data'),
    id = randomUUID(),
    folder = path.join(directory, id);
  await mkdir(folder, { recursive: true });
  const legacy = {
    id,
    url: 'https://example.com/',
    createdAt: '2020-01-01T00:00:00Z',
    status: 'complete',
    pages: [],
    requests: [],
    warnings: [],
    events: [],
    edges: [],
  };
  const bytes = Buffer.from(JSON.stringify(legacy));
  await writeFile(path.join(folder, 'report.json'), bytes);
  const manager = new AuditManager(directory);
  await manager.init();
  assert.equal(manager.migrationWarnings.length, 0);
  const job = manager.jobs.get(id),
    artifacts = manager.store.artifacts(job.caseId, id);
  const source = artifacts.find((a) => a.kind === 'legacy-report');
  assert(job.legacy);
  assert.equal(source.sha256, digest(bytes));
  assert(source.baseline.includes('import'));
  assert.equal(source.claimedSourceTime, legacy.createdAt);
  assert.deepEqual(await readFile(path.join(folder, 'report.json')), bytes);
  assert.equal(manager.store.readArtifact(job.caseId, id, source.id).toString(), bytes.toString());
  manager.store.close();
  const reloaded = new AuditManager(directory);
  await reloaded.init();
  t.after(() => reloaded.store.close());
  assert.equal(reloaded.store.listCases().length, 1);
  assert.equal(reloaded.jobs.size, 1);
  assert.equal(reloaded.store.artifacts(job.caseId, id).length, artifacts.length);
});

test('missing or incorrect key fails closed; never silently creates a replacement', async (t) => {
  const { directory, store } = await setup(t);
  store.close();
  const original = await readFile(path.join(`${directory}.keys`, 'master.key'));
  await writeFile(path.join(`${directory}.keys`, 'master.key'), Buffer.alloc(32));
  const wrong = new EvidenceStore(directory);
  await assert.rejects(wrong.init(), /tidak cocok/);
  const missing = new EvidenceStore(directory, {
    keyDirectory: path.join(directory, '..', 'missing-key'),
  });
  await assert.rejects(missing.init(), /Kunci bukti hilang/);
  await writeFile(path.join(`${directory}.keys`, 'master.key'), original);
});

test('restart recovers a run created before its first checkpoint', async (t) => {
  const { directory, store, c, run } = await setup(t);
  store.close();
  const manager = new AuditManager(directory);
  await manager.init();
  t.after(() => manager.store.close());
  assert.equal(manager.store.getRun(c.id, run.id).status, 'partial');
  assert(manager.jobs.get(run.id).warnings.some((w) => w.includes('working report')));
  assert(manager.store.exportManifest(c.id, run.id).verification.ok);
});
