import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { launchBrowser } from '../server/audit.mjs';

const base = process.env.APP_URL || 'http://127.0.0.1:8788';
assert(
  ['127.0.0.1', 'localhost'].includes(new URL(base).hostname),
  'Fixture tests require local server',
);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const api = async (url, body, method = body ? 'POST' : 'GET') => {
  const response = await fetch(base + url, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  const data = await response.json();
  assert(response.ok, data.error || response.status);
  return data;
};
async function completed(id) {
  for (let i = 0; i < 160; i++) {
    const job = await api(`/api/audits/${id}`);
    if (!['queued', 'running'].includes(job.status)) return job;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Capture timed out');
}
const other = await api('/api/cases', {
  title: 'Isolated case fixture',
  operator: 'Fixture B',
  navigation: [base + '/demo'],
});
let browser;
try {
  browser = await launchBrowser(true);
  const page = await browser.newPage({ viewport: { width: 1365, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(base + '/#/lab-forensik');
  await page.getByRole('button', { name: 'Buat kasus', exact: true }).click();
  await page.getByLabel('Judul kasus', { exact: true }).fill('Stage 1 browser fixture');
  await page.getByLabel('Operator kasus', { exact: true }).fill('Fixture analyst');
  await page
    .getByLabel('Tujuan investigasi', { exact: true })
    .fill('Verify case → capture → evidence → manifest');
  await page.getByLabel('Scope navigasi', { exact: true }).fill(base + '/demo');
  await page.getByLabel('Catatan kasus', { exact: true }).fill('Synthetic fixture only');
  await page.getByRole('button', { name: 'Simpan kasus', exact: true }).click();
  await page.getByText('Operator: Fixture analyst', { exact: false }).waitFor();
  const caseId = await page.getByLabel('Kasus aktif', { exact: true }).inputValue();
  await page.getByLabel('URL website yang akan diaudit').fill(base + '/demo');
  await page.getByLabel('Izinkan localhost').check();
  await page.getByRole('button', { name: 'Audit website', exact: true }).click();
  await page.waitForFunction(() =>
    document.querySelector('.audit-title')?.textContent.includes('berhasil'),
  );
  const runs = await api(`/api/cases/${caseId}/runs`);
  assert.equal(runs.length, 1);
  const run = runs[0],
    prefix = `/api/cases/${caseId}/runs/${run.id}`;
  const job = await completed(run.id);
  assert.equal(job.caseId, caseId);
  assert.equal(job.pages.length, 4);
  await page.getByRole('button', { name: 'Bukti & manifest', exact: true }).click();
  await page.getByRole('button', { name: 'Verifikasi integritas', exact: true }).click();
  await page.getByText('Integritas terverifikasi', { exact: false }).waitFor();
  await page.locator('.artifact-list button').first().click();
  await page.getByAltText('Preview artefak screenshot terverifikasi').waitFor();
  await page.waitForFunction(() => {
    const img = document.querySelector('.artifact-inspector img');
    return img?.complete && img.naturalWidth > 0;
  });
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Ekspor manifest', exact: true }).click();
  const download = await downloadEvent;
  const manifest = JSON.parse(await readFile(await download.path(), 'utf8'));
  assert(manifest.verification.ok);
  assert.equal(manifest.run.id, run.id);
  assert(manifest.run.config.limits.artifactBytes > 0);
  assert.deepEqual(manifest.scope.navigation, [base + '/demo']);
  assert(manifest.observedDependencyOrigins.includes(base));
  let previous = '0'.repeat(64);
  for (const event of manifest.custody) {
    assert.equal(event.previousHash, previous);
    assert.equal(event.hash, hash(previous + event.canonicalPayload));
    previous = event.hash;
  }
  for (const a of manifest.artifacts) {
    const response = await fetch(base + `${prefix}/artifacts/${a.id}/content`);
    assert(response.ok);
    assert.equal(
      hash(Buffer.from(await response.arrayBuffer())),
      a.sha256,
      'independent SHA-256 matches manifest',
    );
  }
  const artifact = manifest.artifacts[0];
  assert.equal((await fetch(base + `/api/cases/${other.id}/runs/${run.id}`)).status, 404);
  assert.equal(
    (await fetch(base + `/api/cases/${other.id}/runs/${run.id}/artifacts/${artifact.id}/content`))
      .status,
    404,
  );
  assert.equal((await fetch(base + `${prefix}/artifacts/%2e%2e%2fmaster.key/content`)).status, 404);
  assert.equal(
    (
      await fetch(base + `${prefix}/artifacts/${artifact.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
    ).status,
    404,
  );
  assert.equal(
    (
      await fetch(base + '/api/cases', {
        method: 'POST',
        headers: { Origin: 'https://untrusted.example', 'Content-Type': 'application/json' },
        body: '{}',
      })
    ).status,
    403,
  );
  const outOfScope = await fetch(base + '/api/audits', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caseId, url: base + '/', allowLocal: true }),
  });
  assert.equal(outOfScope.status, 400);
  assert.equal((await api(`/api/cases/${other.id}/runs`)).length, 0);
  const report = await fetch(base + `/api/audits/${run.id}/export`);
  assert.equal(report.status, 200);
  assert.equal((await report.json()).id, run.id);
  await mkdir('output/playwright', { recursive: true });
  await page.screenshot({ path: 'output/playwright/stage1-evidence-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await page.screenshot({ path: 'output/playwright/stage1-evidence-mobile.png', fullPage: true });
  await page.getByLabel('Kasus aktif', { exact: true }).selectOption(other.id);
  assert.equal(await page.locator('.history-item').count(), 0, 'history isolated to selected case');
  assert.equal(await page.locator('.evidence-panel').count(), 0);
  assert.deepEqual(errors, []);
  console.log(
    'PASS: case UI, scoped local audit, artifact inspector, encrypted screenshot delivery, hash verification, manifest download and independent hashes/custody verification.',
  );
  console.log(
    'PASS: two-case isolation, path traversal rejection, immutable API, Origin guard, navigation scope, legacy-compatible JSON export, desktop/mobile layout.',
  );
} finally {
  await browser?.close();
}
