import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { launchBrowser } from '../server/audit.mjs';

// Own process/server/database. Never touches the user's case store or daily browser.
process.env.PORT = process.env.STAGE2_TEST_PORT || '8789';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-stage2-ui-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
process.env.ENABLE_AUTH_FIXTURE = '1';
const { server, manager } = await import('../server/index.mjs');
if (!server.listening)
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
const base = `http://127.0.0.1:${process.env.PORT}`;
let browser;
const api = async (route, body) => {
  const r = await fetch(base + route, {
    method: body ? 'POST' : 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  assert(r.ok, data.error);
  return data;
};
try {
  browser = await launchBrowser(true);
  const ui = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors = [];
  ui.on('pageerror', (e) => errors.push(e.message));
  await ui.goto(base + '/#/cybersecurity');
  await ui.getByRole('button', { name: 'Buat kasus', exact: true }).click();
  await ui.getByLabel('Judul kasus', { exact: true }).fill('Stage 2 UI fixture');
  await ui.getByLabel('Operator kasus', { exact: true }).fill('Synthetic investigator');
  await ui.getByLabel('Scope navigasi', { exact: true }).fill(base + '/auth-fixture');
  await ui.getByRole('button', { name: 'Simpan kasus', exact: true }).click();
  await ui.getByText('Operator: Synthetic investigator', { exact: false }).waitFor();
  const caseId = await ui.getByLabel('Kasus aktif', { exact: true }).inputValue();
  await ui.getByLabel('URL website yang akan diaudit').fill(base + '/auth-fixture/profile');
  await ui.getByLabel('Izinkan localhost', { exact: true }).check();
  await ui
    .getByLabel('URL login sebagai indikator', { exact: true })
    .fill(base + '/auth-fixture/login');
  const opened = ui.waitForResponse(
    (r) => r.url() === base + '/api/sessions' && r.request().method() === 'POST',
  );
  await ui.getByRole('button', { name: 'Buka browser audit', exact: true }).click();
  const job = await (await opened).json(),
    session = manager.sessions.get(job.id);
  await session.openTask;
  const audit = session.page;
  assert.equal((await audit.reload()).status(), 401);
  // Switching menus must neither close the live browser nor hide its controls.
  await ui.getByRole('link', { name: 'Belajar Web', exact: true }).click();
  await ui.getByRole('region', { name: 'Audit dengan login', exact: true }).waitFor();
  assert(await ui.getByRole('button', { name: 'Tutup & simpan run', exact: true }).isVisible());
  assert.equal(manager.sessions.get(job.id), session);
  assert.equal(audit.isClosed(), false);
  assert.equal(await ui.getByLabel('Kasus aktif', { exact: true }).inputValue(), caseId);
  await ui.getByRole('link', { name: 'Cybersecurity', exact: true }).click();

  await audit.getByRole('link', { name: 'Login fixture' }).click();
  await audit.getByLabel('Email', { exact: true }).fill('fixture@example.test');
  await audit.getByLabel('Password', { exact: true }).fill('fixture-password');
  await Promise.all([
    audit.waitForURL('**/mfa'),
    audit.getByRole('button', { name: 'Login', exact: true }).click(),
  ]);
  await audit.getByLabel('Kode', { exact: true }).fill('123456');
  await Promise.all([
    audit.waitForURL('**/profile'),
    audit.getByRole('button', { name: 'Verifikasi', exact: true }).click(),
  ]);
  await audit.getByText('Private fixture profile', { exact: true }).waitFor();
  assert.equal(manager.store.artifacts(caseId, job.id).length, 0);
  assert.equal(session.job.requests.length, 0);
  await ui.getByRole('button', { name: 'Halaman siap', exact: true }).click();
  await ui.getByText(/^Dinyatakan siap oleh pengguna pada/).waitFor();
  const captureResponse = ui.waitForResponse((r) =>
    r.url().endsWith(`/sessions/${job.id}/capture`),
  );
  await ui.getByRole('button', { name: 'Mulai capture snapshot', exact: true }).click();
  assert((await captureResponse).ok());
  await ui.waitForFunction(
    () => document.querySelector('.audit-counts strong')?.textContent === '1',
  );
  const popupEvent = audit.waitForEvent('popup');
  await audit.getByRole('link', { name: 'Buka popup pengaturan' }).click();
  const popup = await popupEvent;
  await popup.getByText('Private fixture profile', { exact: true }).waitFor();
  const popupId = [...session.tabs].find(([, p]) => p === popup)[0];
  await ui
    .locator(`select[aria-label="Tab browser audit"] option[value="${popupId}"]`)
    .waitFor({ state: 'attached' });
  await ui.getByLabel('Tab browser audit', { exact: true }).selectOption(popupId);
  await ui.getByText('HTTP 200 bukan bukti autentikasi.', { exact: false }).waitFor();
  await ui.getByRole('button', { name: 'Halaman siap', exact: true }).click();
  await ui.getByText(/^Dinyatakan siap oleh pengguna pada/).waitFor();
  await ui.getByText('Crawl halaman pilihan dalam sesi ini', { exact: true }).click();
  await ui
    .getByLabel('URL crawl pilihan', { exact: true })
    .fill(base + '/auth-fixture/profile/activity');
  await ui
    .getByLabel('Endpoint POST baca', { exact: true })
    .fill(base + '/auth-fixture/api/read ProfileRead');
  await ui.getByLabel('Saya memilih URL', { exact: false }).check();
  const crawlResponse = ui.waitForResponse((r) => r.url().endsWith(`/sessions/${job.id}/capture`));
  await ui.getByRole('button', { name: 'Mulai crawl pilihan', exact: true }).click();
  assert((await crawlResponse).ok());
  assert(session.job.requests.some((r) => r.url.endsWith('/api/read') && r.status === 200));
  await mkdir('output/playwright', { recursive: true });
  await ui.screenshot({ path: 'output/playwright/stage2-session-desktop.png', fullPage: true });
  await ui.setViewportSize({ width: 390, height: 844 });
  assert(
    await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    'mobile has no horizontal overflow',
  );
  await ui.screenshot({ path: 'output/playwright/stage2-session-mobile.png', fullPage: true });
  await ui.setViewportSize({ width: 1440, height: 1100 });
  const closeResponse = ui.waitForResponse((r) => r.url().endsWith(`/sessions/${job.id}/close`));
  await ui.getByRole('button', { name: 'Tutup & simpan run', exact: true }).click();
  assert((await closeResponse).ok());
  await ui.getByRole('button', { name: 'Bukti & manifest', exact: true }).click();
  await ui.getByRole('button', { name: 'Verifikasi integritas', exact: true }).click();
  await ui.getByText('Integritas terverifikasi', { exact: false }).waitFor();
  await ui.locator('.artifact-list button').first().click();
  await ui.getByAltText('Preview artefak screenshot terverifikasi').waitFor();
  const downloaded = ui.waitForEvent('download');
  await ui.getByRole('button', { name: 'Ekspor manifest', exact: true }).click();
  const manifest = JSON.parse(await readFile(await (await downloaded).path(), 'utf8'));
  assert.equal(manifest.run.caseId, caseId);
  assert(manifest.verification.ok);
  assert.equal(manifest.session.status, 'closed');
  assert.equal(manifest.session.retainedAuthentication, false);
  assert(manifest.session.operations.some((o) => o.kind === 'crawl'));
  assert.deepEqual(errors, []);
  // Same local access boundaries apply to new session endpoints.
  assert.equal(
    (
      await fetch(base + '/api/sessions', {
        method: 'POST',
        headers: { Origin: 'https://untrusted.example', 'Content-Type': 'application/json' },
        body: '{}',
      })
    ).status,
    403,
  );
  assert.equal((await fetch(base + '/api/sessions/%2e%2e%2fmaster.key')).status, 404);
  assert.equal((await api(`/api/cases/${caseId}/runs`)).length, 1);
  console.log(
    'PASS: UI case → URL → browser → cookie login/MFA → ready → snapshot → popup selection → same-context crawl → artifact preview → hash verification → manifest export.',
  );
  console.log(
    'PASS: collection gate, POST read policy, local API guard, desktop/mobile layout, no React runtime errors. Fixture data only.',
  );
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  manager.store.close();
}
