import assert from 'node:assert/strict';
import { mkdtemp, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { AuditManager, launchBrowser } from '../server/audit.mjs';

const base = process.env.APP_URL || 'http://127.0.0.1:8787';
const output = path.resolve('output/playwright');
await mkdir(output, { recursive: true });
const directory = await mkdtemp(path.join(tmpdir(), 'webintelligent-smoke-'));
const manager = new AuditManager(directory);
await manager.init();
let browser;
try {
  assert((await fetch(base + '/api/health')).ok, 'server is reachable');
  assert.equal(
    (await fetch(base + '/api/audits', { headers: { Origin: 'https://untrusted.example' } }))
      .status,
    403,
  );
  const job = await manager.create({ url: base + '/demo', maxPages: 4, allowLocal: true });
  const started = Date.now();
  while (['queued', 'running'].includes(job.status)) {
    assert(Date.now() - started < 90000, 'audit completes within timeout');
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.equal(job.status, 'complete', JSON.stringify(job.warnings));
  assert.equal(manager.runners.size, 0, 'completion is published only after browser cleanup');
  assert.equal(job.pages.length, 4);
  assert.equal(new Set(job.pages.map((p) => p.id)).size, job.pages.length);
  const login = job.pages.find((p) => new URL(p.url).pathname === '/demo');
  const email = login.elements.find((el) => el.name === 'email');
  assert(email, 'email element extracted');
  assert.equal(email.form.method, 'POST');
  assert(email.listeners.some((l) => l.handler === 'onEmailInput'));
  assert(job.requests.some((r) => r.url.endsWith('/demo/api/status') && r.status === 200));
  assert(job.pages.every((p) => p.screenshot));
  assert(
    !job.requests.some((r) => r.url.endsWith('/demo/api/login')),
    'passive scan does not submit login',
  );
  console.log(
    'PASS: multi-page crawl, screenshot, elements, direct listeners, declared form, passive network.',
  );

  // Use the real recording lifecycle on our own local fixture.
  const recordJob = await manager.startSession(job.id, login.id, { observeLogin: true });
  assert.notEqual(recordJob.id, job.id, 'recording has a separate evidence run');
  assert.equal(recordJob.caseId, job.caseId);
  const session = manager.sessions.get(recordJob.id);
  await session.openTask;
  browser = session.browser;
  const demo = session.page;
  await demo.locator('#email').fill('demo@example.com');
  await demo.locator('#password').fill('demo');
  await Promise.all([demo.waitForURL('**/demo/dashboard'), demo.locator('#login-button').click()]);
  await demo.waitForTimeout(400);
  manager.sessionManager.ready(recordJob.id);
  await manager.captureSession(recordJob.id);
  const loginRequest = recordJob.requests.find(
    (r) => r.url.endsWith('/demo/api/login') && r.method === 'POST',
  );
  assert(loginRequest);
  assert.equal(loginRequest.status, 200);
  assert.deepEqual(
    loginRequest.body.fields.map((f) => f.name),
    ['email', 'password'],
  );
  assert(loginRequest.event, 'request correlated with actual submit event');
  assert(loginRequest.initiator?.transport === 'fetch', 'fetch initiator recorded');
  assert(recordJob.events.some((e) => e.type === 'submit'));
  assert(
    !JSON.stringify(loginRequest).includes('demo@example.com'),
    'input value not retained in request report',
  );
  assert.equal(
    new Set(job.pages.map((p) => p.id)).size,
    job.pages.length,
    'navigation snapshots have unique IDs',
  );
  console.log(
    'PASS: real form input → submit → POST JSON → response → navigation with redacted values.',
  );

  await manager.stopSession(recordJob.id);
  assert(manager.store.verifyRun(recordJob.caseId, recordJob.id).ok);
  assert.equal(manager.store.getRun(job.caseId, job.id).mode, 'passive');
  browser = await launchBrowser(true);
  const context = await browser.newContext({ viewport: { width: 1365, height: 900 } });
  const ui = await context.newPage();
  const errors = [];
  ui.on('pageerror', (error) => errors.push(error.message));
  await ui.goto(base);
  await ui.getByRole('button', { name: 'Audit demo' }).click();
  await ui.getByRole('button', { name: 'Rekam interaksi' }).waitFor({ timeout: 60000 });
  await ui.waitForFunction(() =>
    document.querySelector('.audit-title')?.textContent.includes('berhasil'),
  );
  await ui.getByRole('button', { name: 'Alur halaman', exact: true }).click();
  await ui.locator('.react-flow__node').first().waitFor();
  await ui.getByRole('button', { name: 'Alur data', exact: true }).click();
  await ui.getByLabel('Elemen untuk alur data').selectOption({ label: 'Email (email)' });
  await ui.getByText('Handler internal belum diketahui', { exact: true }).waitFor();
  await ui.screenshot({ path: path.join(output, 'data-flow-desktop.png'), fullPage: true });
  await ui.getByRole('button', { name: 'Network', exact: true }).click();
  await ui.getByText('/demo/api/status', { exact: true }).first().waitFor();
  await ui.getByRole('button', { name: 'Elemen', exact: true }).click();
  await ui.waitForFunction(() => {
    const img = document.querySelector('.screenshot-image img');
    return img && img.complete && img.naturalWidth > 0;
  });
  await ui.locator('.element-row').filter({ hasText: 'Email' }).click();
  await ui.getByText('input → onEmailInput', { exact: true }).waitFor();
  await ui.screenshot({ path: path.join(output, 'elements-desktop.png'), fullPage: true });
  await ui.setViewportSize({ width: 390, height: 844 });
  await ui.waitForFunction(
    () => getComputedStyle(document.querySelector('.sidebar')).visibility === 'hidden',
  );
  await ui.screenshot({
    path: path.join(output, 'elements-mobile.png'),
    fullPage: true,
    animations: 'disabled',
  });
  assert(
    await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    'no mobile horizontal overflow',
  );
  assert.deepEqual(errors, [], 'no browser runtime errors');
  console.log(
    'PASS: React UI audit, React Flow routes/data, network inspector, element selection, mobile layout.',
  );
} finally {
  await browser?.close().catch(() => {});
  await manager.close();
  manager.store.close();
}
