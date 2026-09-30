import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { launchBrowser } from '../server/audit.mjs';
import { ForensicService } from '../server/forensics.mjs';
process.env.PORT = process.env.STAGE5_TEST_PORT || '8792';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-stage5-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
const { server, manager } = await import('../server/index.mjs');
if (!server.listening) await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${process.env.PORT}`,
  service = new ForensicService(manager.store);
const fixtures = path.resolve('tests/fixtures/forensics');
let trap = 0,
  browser;
server.on('request', (req) => {
  if (req.url.startsWith('/forensic-trap')) trap++;
});
async function waitUntil(fn) {
  for (let i = 0; i < 150; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Condition timed out');
}
async function api(url, options = {}) {
  const r = await fetch(base + url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  assert(r.ok, `${r.status}: ${await r.clone().text()}`);
  return r.json();
}
const errors = [],
  external = [];
try {
  const c = await api('/api/cases', {
    method: 'POST',
    body: JSON.stringify({
      title: 'Stage 5 synthetic investigation',
      operator: 'Fixture analyst',
      navigation: [base + '/demo'],
    }),
  });
  const caseId = c.id || c.case?.id;
  assert(caseId, JSON.stringify(c));
  const forensic = `/api/cases/${caseId}/forensics`;
  browser = await launchBrowser(true);
  const ui = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  await ui.route('**/*', (route) => {
    if (new URL(route.request().url()).origin !== base) {
      external.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  ui.on('pageerror', (e) => errors.push(e.message));
  await ui.goto(base + '/#/lab-forensik', { waitUntil: 'domcontentloaded' });
  await ui.getByLabel('Kasus aktif', { exact: true }).selectOption(caseId);
  const panel = ui.getByRole('region', { name: 'Forensik kasus' });
  await panel.getByRole('button', { name: 'Buka workspace forensik' }).click();
  async function idle() {
    await waitUntil(async () => (await panel.getAttribute('aria-busy')) === 'false');
    const alerts = await panel.getByRole('alert').allTextContents();
    assert.deepEqual(alerts, []);
  }
  await idle();
  async function upload(name, format, mapping) {
    const details = panel.locator('.forensic-import');
    if ((await details.getAttribute('open')) === null) await details.locator('summary').click();
    await panel.getByLabel('Format impor', { exact: true }).selectOption(format);
    await panel.getByLabel('Namespace sumber', { exact: true }).fill('portal-fixture');
    if (mapping)
      for (const key of [
        'time',
        'action',
        'account',
        'url',
        'ip',
        'requestId',
        'session',
        'hash',
        'messageId',
      ])
        await panel.getByLabel(`Pemetaan ${key}`, { exact: true }).fill(mapping[key] || '');
    await panel.getByLabel('File impor', { exact: true }).setInputFiles(path.join(fixtures, name));
    const response = ui.waitForResponse(
      (r) => r.url() === base + forensic + '/import' && r.request().method() === 'POST',
    );
    await panel.getByRole('button', { name: 'Impor dan parse', exact: true }).click();
    assert.equal((await response).status(), 201);
    await idle();
  }
  await upload('transfer.har', 'har');
  await upload('auth.ndjson', 'ndjson');
  await upload('application.json', 'json', {
    time: '/meta/when',
    action: 'action',
    account: 'principal',
    requestId: 'rid',
  });
  await upload('audit.csv', 'csv', {
    time: 'when',
    action: 'operation',
    account: 'principal',
    ip: 'client',
    requestId: 'request',
    url: 'link',
  });
  await upload('message.eml', 'eml');
  await upload('export.txt', 'file');
  let view = await api(forensic);
  assert.equal(view.sources.length, 6);
  assert.equal(view.events.length, 15);
  await panel.getByLabel('Cari timeline', { exact: true }).fill('bob@example.test');
  assert.equal(await panel.locator('tbody tr').count(), 2);
  await panel.getByLabel('Cari timeline', { exact: true }).fill('');
  await panel.getByLabel('Dari UTC', { exact: true }).fill('2025-05-10T02:00');
  await panel.getByLabel('Sampai UTC', { exact: true }).fill('2025-05-10T02:00');
  await panel.getByLabel('Tetap tampilkan waktu unknown/ambigu', { exact: true }).uncheck();
  assert.equal(await panel.locator('tbody tr').count(), 4);
  await panel.getByLabel('Dari UTC', { exact: true }).fill('');
  await panel.getByLabel('Sampai UTC', { exact: true }).fill('');
  await panel.getByLabel('Tetap tampilkan waktu unknown/ambigu', { exact: true }).check();
  const eml = view.sources.find((s) => s.format === 'eml');
  await panel.getByLabel('Sumber timeline', { exact: true }).selectOption(eml.id);
  await idle();
  await panel.getByRole('button', { name: 'Preview metadata aman', exact: true }).click();
  await idle();
  assert(
    (await panel.locator('.forensic-preview').textContent()).includes('window.__forensicExecuted'),
  );
  assert.equal(await ui.evaluate(() => window.__forensicExecuted), undefined);
  assert.equal(
    await panel
      .locator('.forensic-preview img, .forensic-preview iframe, .forensic-preview script')
      .count(),
    0,
  );
  assert.equal(trap, 0);
  const original = await fetch(
    base + `/api/cases/${caseId}/runs/${eml.originalRef.runId}/artifacts/${eml.id}/content`,
  );
  assert.match(original.headers.get('content-disposition'), /^attachment/);
  assert.match(original.headers.get('content-security-policy'), /sandbox/);
  assert.equal(original.headers.get('content-type'), 'application/octet-stream');
  assert.deepEqual(
    Buffer.from(await original.arrayBuffer()),
    await readFile(path.join(fixtures, 'message.eml')),
  );
  const auth = view.sources.find((s) => s.format === 'ndjson');
  await panel.getByLabel('Sumber timeline', { exact: true }).selectOption(auth.id);
  await idle();
  await panel.locator('tbody tr button').first().click();
  await panel.locator('.forensic-inspector').waitFor();
  assert((await panel.locator('.forensic-inspector').textContent()).includes('"line":1'));
  await panel.locator('.forensic-flow .react-flow__node').first().waitFor();
  await panel.getByRole('button', { name: 'ip: 198.51.100.24', exact: true }).click();
  await panel
    .locator('.forensic-flow .react-flow__node')
    .filter({ hasText: 'Shared ip value' })
    .waitFor();
  await panel.locator('tbody input[type=checkbox]').first().check();
  await panel.locator('.forensic-notes > summary').click();
  await panel
    .getByLabel('Catatan forensik', { exact: true })
    .fill('Synthetic bookmark with provenance');
  await panel.getByRole('button', { name: 'Simpan catatan forensik', exact: true }).click();
  await idle();
  assert(service.view(caseId).operations.some((o) => o.kind === 'bookmark'));
  await panel.getByLabel('Bookmark aktif saja', { exact: true }).check();
  assert.equal(await panel.locator('tbody tr').count(), 1);
  await panel.getByLabel('Bookmark aktif saja', { exact: true }).uncheck();
  await panel.getByLabel('Jenis catatan forensik', { exact: true }).selectOption('clock-skew');
  await panel.getByLabel('Clock skew detik', { exact: true }).fill('60');
  await panel
    .getByLabel('Catatan forensik', { exact: true })
    .fill('Synthetic clock is 60 seconds slow');
  await panel.getByRole('button', { name: 'Simpan catatan forensik', exact: true }).click();
  await idle();
  assert((await panel.locator('tbody').textContent()).includes('CLOCK TRANSFORM'));
  await panel.getByRole('button', { name: 'Batalkan clock-skew', exact: true }).click();
  await idle();
  assert(!(await panel.locator('tbody').textContent()).includes('CLOCK TRANSFORM'));
  // Reparse the same original with a documented zone assumption, then inspect prior version.
  const details = panel.locator('.forensic-import');
  if ((await details.getAttribute('open')) === null) await details.locator('summary').click();
  await panel.getByLabel('Format impor', { exact: true }).selectOption('ndjson');
  const defaults = {
    time: 'timestamp',
    action: 'event',
    account: 'user',
    url: 'url',
    ip: 'ip',
    requestId: 'requestId',
    session: 'sessionId',
    hash: 'sha256',
    messageId: 'messageId',
  };
  for (const [k, v] of Object.entries(defaults))
    await panel.getByLabel(`Pemetaan ${k}`, { exact: true }).fill(v);
  await panel.getByLabel('Zona timestamp', { exact: true }).selectOption('+07:00');
  await panel
    .getByRole('button', { name: 'Parse ulang dengan konfigurasi di atas', exact: true })
    .click();
  await idle();
  assert((await panel.locator('tbody').textContent()).includes('assumed-zone'));
  await panel.getByLabel('Versi parsing', { exact: true }).selectOption(auth.parseRef.artifactId);
  await idle();
  assert((await panel.locator('tbody').textContent()).includes('ambiguous'));
  // Capture remains a separate current observation; this is a loopback demo audit only.
  const capture = await manager.create({
    caseId,
    url: base + '/demo',
    allowLocal: true,
    maxPages: 1,
  });
  await waitUntil(() => !['queued', 'running'].includes(capture.status));
  assert.equal(capture.status, 'complete', JSON.stringify(capture.warnings));
  await panel.getByRole('button', { name: 'Muat ulang forensik', exact: true }).click();
  await idle();
  await panel.getByLabel('Capture untuk forensik', { exact: true }).selectOption(capture.id);
  await panel.getByRole('button', { name: 'Tambahkan capture ke timeline', exact: true }).click();
  await idle();
  view = service.view(caseId);
  const browserEvents = view.events.filter((e) => e.basis === 'browser-observation-at-capture');
  assert(browserEvents.length);
  assert(
    browserEvents.every((e) =>
      e.time.normalized.startsWith(new Date().getUTCFullYear().toString()),
    ),
  );
  assert(view.events.some((e) => e.time.normalized?.startsWith('2025')));
  await panel.getByRole('button', { name: 'Buat ekspor tersensor', exact: true }).click();
  await idle();
  const shareLink = panel.getByRole('link', { name: 'Unduh ekspor tersensor', exact: true });
  await shareLink.waitFor();
  const share = await (await fetch(base + (await shareLink.getAttribute('href')))).json();
  assert.equal(share.sharePolicy, 'strict-structural-v1');
  assert(!JSON.stringify(share).includes('SECRET_'));
  assert(!JSON.stringify(share).includes('alice@example.test'));
  assert(share.graph.edges.some((e) => e.relation === 'correlated'));
  const other = await api('/api/cases', {
    method: 'POST',
    body: JSON.stringify({
      title: 'Second synthetic case',
      operator: 'Other',
      navigation: [base + '/demo'],
    }),
  });
  const cross = await fetch(base + `/api/cases/${other.id}/forensics/sources/${auth.id}/preview`);
  assert.equal(cross.status, 404);
  const over = await fetch(base + forensic + '/import', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-WI-Import-Options': JSON.stringify({ format: 'file', filename: 'too-big.bin' }),
    },
    body: Buffer.alloc(8 * 1024 * 1024 + 1),
  });
  assert.equal(over.status, 413);
  const traversal = await fetch(base + forensic + '/import', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-WI-Import-Options': JSON.stringify({ format: 'file', filename: '../escape' }),
    },
    body: 'synthetic',
  });
  assert.equal(traversal.status, 400);
  const origin = await fetch(base + forensic + '/share', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://untrusted.example.test' },
    body: '{}',
  });
  assert.equal(origin.status, 403);
  assert.equal(trap, 0);
  assert.deepEqual(errors, []);
  assert(
    external.every((url) => new URL(url).hostname === 'fonts.googleapis.com'),
    'Only the existing app font stylesheet may be attempted; blocked before network',
  );
  assert(manager.store.listRuns(caseId).every((r) => manager.store.verifyRun(caseId, r.id).ok));
  await mkdir('output/playwright', { recursive: true });
  await panel.getByLabel('Tipe event', { exact: true }).selectOption('email-message');
  await ui.screenshot({ path: 'output/playwright/stage5-forensics.png', fullPage: true });
  const result = {
    passed: true,
    formats: 6,
    initialEvents: 15,
    liveCaptureRequests: browserEvents.length,
    sources: view.sources.length,
    ui: [
      'import/mapping',
      'UTC search/filter',
      'source/field provenance',
      'inert email preview',
      'occurrence correlation graph',
      'bookmark',
      'skew/undo',
      'reparse/prior version',
      'current capture adapter',
      'redacted share',
    ],
    guards: [
      '413 oversized',
      '400 traversal',
      '404 other case',
      '403 foreign origin',
      'download-only originals',
    ],
    existingAppFontRequestsBlocked: external.length,
    artifactRemoteRequests: 0,
    activeContentRequests: trap,
    browserErrors: errors.length,
    allRunHashesVerified: true,
    dataDirectory: process.env.DATA_DIR,
  };
  await writeFile('output/playwright/stage5-results.json', JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  manager.store.close();
}
