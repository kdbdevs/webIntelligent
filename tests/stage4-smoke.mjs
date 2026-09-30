import assert from 'node:assert/strict';
import { mkdtemp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { launchBrowser } from '../server/audit.mjs';
import { SecurityService } from '../server/security.mjs';

process.env.PORT = process.env.STAGE4_TEST_PORT || '8791';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-stage4-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
process.env.ENABLE_SECURITY_FIXTURE = '1';
process.env.ENABLE_AUTH_FIXTURE = '1';
process.env.ENABLE_WIRING_FIXTURE = '1';
const { server, manager } = await import('../server/index.mjs');
if (!server.listening) await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${process.env.PORT}`,
  service = new SecurityService(manager.store);
let fixtureRequests = 0;
server.on('request', (req) => {
  if (req.url.startsWith('/security-fixture') || req.url.startsWith('/auth-fixture'))
    fixtureRequests++;
});
async function waitUntil(fn) {
  for (let i = 0; i < 300; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Condition timed out');
}
let browser;
try {
  const c = manager.store.createCase({
    title: 'Security stage 4 fixture',
    operator: 'Synthetic analyst',
    navigation: [base + '/security-fixture', base + '/auth-fixture'],
  });
  const bad = await manager.create({
    caseId: c.id,
    url: base + '/security-fixture/bad',
    allowLocal: true,
    maxPages: 1,
  });
  await waitUntil(() => !['running', 'queued'].includes(bad.status));
  assert.equal(bad.status, 'complete', JSON.stringify(bad.warnings));
  const doc = bad.requests.find((r) => r.resourceType === 'document');
  assert.equal(doc.security.status, 'complete');
  assert(doc.security.cookieAttributes.some((c) => c.prefix === '__Host-'));
  assert.equal(doc.requestSecurity.status, 'complete');
  for (const artifact of manager.store
    .artifacts(c.id, bad.id)
    .filter((a) => a.mimeType === 'application/json')) {
    const content = manager.store.readArtifact(c.id, bad.id, artifact.id).toString();
    for (const secret of [
      'FIXTURE_COOKIE_SECRET',
      'FIXTURE_HINT_SECRET',
      'FIXTURE_NONCE_SECRET',
      'FIXTURE_AUTH_SECRET',
      'FIXTURE_QUERY_SECRET',
    ])
      assert(
        !content.includes(secret),
        `Capture artifact must omit sensitive fixture values: ${artifact.kind}`,
      );
  }
  assert(
    bad.requests.some(
      (r) => r.url.endsWith('/transfer') && r.requestSecurity.authorizationPresent === true,
    ),
  );
  const original = manager.store
    .artifacts(c.id, bad.id)
    .map((a) => ({ id: a.id, sha256: a.sha256 }));
  const countBefore = fixtureRequests;
  browser = await launchBrowser(true);
  const ui = await browser.newPage({ viewport: { width: 1440, height: 1050 } }),
    errors = [];
  await ui.route('**/*', (route) =>
    new URL(route.request().url()).origin === base ? route.continue() : route.abort(),
  );
  ui.on('pageerror', (e) => errors.push(e.message));
  await ui.goto(base + '/#/cybersecurity', { waitUntil: 'domcontentloaded' });
  await ui.locator('.history-item').first().click();
  const panel = ui.getByRole('region', { name: 'Pemeriksaan keamanan' });
  await panel.getByRole('button', { name: 'Analisis bukti', exact: true }).click();
  await panel.locator('.security-list button').first().waitFor();
  assert.equal(fixtureRequests, countBefore, 'offline analysis and UI do not send target requests');
  const assessments = service.list(c.id, bad.id);
  assert.equal(assessments.length, 1);
  let a = service.get(c.id, assessments[0].id);
  assert(a.findings.some((f) => f.ruleId === 'WI-COOKIE-001'));
  const urlFinding = a.findings.find((f) => f.ruleId === 'WI-URL-001');
  assert(urlFinding?.related.length);
  await panel.locator('.security-list button').filter({ hasText: 'WI-URL-001' }).click();
  await panel.getByRole('button', { name: 'Tinjau bukti request 1', exact: true }).click();
  await panel.getByText('Hash terverifikasi', { exact: true }).waitFor();
  assert((await panel.getByTestId('security-evidence-preview').textContent()).includes('token'));
  assert(
    !(await panel.getByTestId('security-evidence-preview').textContent()).includes(
      'FIXTURE_QUERY_SECRET',
    ),
  );
  await panel.getByRole('button', { name: 'Gunakan sebagai pendukung', exact: true }).click();
  await panel.getByRole('button', { name: 'Buka wiring 1', exact: true }).click();
  await panel.locator('.security-wiring .react-flow__node').first().waitFor();
  assert((await panel.locator('.security-wiring').textContent()).includes('token'));
  const sourceElement = bad.pages[0].elements.find((e) => e.selector === '#sensitive-asset');
  await panel
    .locator('.security-wiring')
    .getByLabel('Elemen wiring', { exact: true })
    .selectOption(sourceElement.id);
  await panel
    .locator('.security-wiring')
    .getByLabel('Sorot #sensitive-asset', { exact: true })
    .waitFor();
  await panel.getByRole('button', { name: 'Tutup wiring', exact: true }).click();
  await panel.locator('.security-review > summary').click();
  const review = panel.locator('.security-review form');
  await review.getByLabel('Reviewer', { exact: true }).fill('Fixture reviewer');
  await review
    .getByLabel('Alasan perubahan status', { exact: true })
    .fill(
      'Confirmed configured fixture sends a synthetic token name; this validates only the local fixture behavior.',
    );
  await review
    .getByLabel('Dampak yang dinilai', { exact: true })
    .fill('Synthetic token in controlled URL metadata; no real account exposure tested.');
  await review.locator('input[type=checkbox]').check();
  await review.getByRole('button', { name: 'Simpan review', exact: true }).click();
  await waitUntil(
    async () =>
      service.get(c.id, a.id).findings.find((f) => f.id === urlFinding.id).status === 'validated',
  );
  await panel.locator('.security-tests > summary').click();
  const plan = panel.locator('.security-tests > form');
  await plan.getByLabel('Judul skenario', { exact: true }).fill('Review fixture evidence');
  await plan.getByLabel('Operator', { exact: true }).fill('Fixture analyst');
  await plan.getByLabel('Tujuan skenario', { exact: true }).fill('Check baseline metadata');
  await plan
    .getByLabel('Langkah yang direncanakan', { exact: true })
    .fill('Inspect verified artifact; no target request');
  await plan.getByLabel('Hasil yang diharapkan', { exact: true }).fill('Token value omitted');
  await plan.getByLabel('Dampak yang diketahui', { exact: true }).fill('None; offline');
  await plan.getByRole('button', { name: 'Simpan rencana manual', exact: true }).click();
  const manual = panel
    .locator('.security-tests article')
    .filter({ hasText: 'Review fixture evidence' });
  await manual.getByLabel('Keputusan', { exact: true }).selectOption('cancelled');
  await manual.getByLabel('Reviewer hasil', { exact: true }).fill('Fixture reviewer');
  await manual
    .getByLabel('Hasil atau alasan pembatalan', { exact: true })
    .fill('Already verified in review');
  await manual.getByLabel('Dampak teramati', { exact: true }).fill('No activity');
  await manual.getByRole('button', { name: 'Catat hasil manual', exact: true }).click();
  await waitUntil(() => service.get(c.id, a.id).manualTests[0]?.status === 'cancelled');
  const exported = await fetch(`${base}/api/cases/${c.id}/security/assessments/${a.id}/export`);
  assert.equal(exported.status, 200);
  const exportedBody = await exported.json();
  assert(exportedBody.manifests.every((m) => m.verification.ok));
  assert(!JSON.stringify(exportedBody).includes('FIXTURE_COOKIE_SECRET'));
  assert(!JSON.stringify(exportedBody).includes('FIXTURE_NONCE_SECRET'));
  assert(!JSON.stringify(exportedBody).includes('FIXTURE_AUTH_SECRET'));
  assert.equal(
    fixtureRequests,
    countBefore,
    'analysis/review/manual plan/result/export remain offline',
  );
  assert.deepEqual(
    manager.store.artifacts(c.id, bad.id).map((a) => ({ id: a.id, sha256: a.sha256 })),
    original,
  );
  assert(manager.store.verifyRun(c.id, bad.id).ok);
  await mkdir('output/playwright', { recursive: true });
  await panel.screenshot({ path: 'output/playwright/stage4-findings-desktop.png' });
  await ui.setViewportSize({ width: 390, height: 844 });
  await panel.screenshot({ path: 'output/playwright/stage4-findings-mobile.png' });
  assert(
    await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    'mobile overflow',
  );
  assert.deepEqual(errors, []);
  console.log(
    'PASS: local capture → passive assessment → finding/request/artifact/graph → manual validation → scenario cancellation → verified export; zero additional target requests; immutable baseline; desktop/mobile UI.',
  );

  const safe = await manager.create({
    caseId: c.id,
    url: base + '/security-fixture/safe',
    allowLocal: true,
    maxPages: 1,
  });
  await waitUntil(() => !['running', 'queued'].includes(safe.status));
  assert.equal(safe.status, 'complete');
  const safeAssessment = service.assess(c.id, safe.id);
  assert(
    !safeAssessment.findings.some((f) =>
      ['WI-HDR-001', 'WI-COOKIE-001', 'WI-HSTS-001'].includes(f.ruleId),
    ),
    JSON.stringify(safeAssessment.findings),
  );
  const sm = manager.sessionManager;
  const auth = await sm.open({
    caseId: c.id,
    url: base + '/auth-fixture/wiring',
    allowLocal: true,
    maxPages: 2,
  });
  const session = sm.get(auth.id);
  await session.openTask;
  const page = session.page;
  assert.equal((await page.reload()).status(), 401);
  await page.goto(base + '/auth-fixture/login');
  await page.getByLabel('Email', { exact: true }).fill('fixture@example.test');
  await page.getByLabel('Password', { exact: true }).fill('fixture-password');
  await Promise.all([
    page.waitForURL('**/mfa'),
    page.getByRole('button', { name: 'Login', exact: true }).click(),
  ]);
  await page.getByLabel('Kode', { exact: true }).fill('123456');
  await Promise.all([
    page.waitForURL('**/profile'),
    page.getByRole('button', { name: 'Verifikasi', exact: true }).click(),
  ]);
  await page.goto(base + '/auth-fixture/wiring');
  assert.equal(auth.requests.length, 0, 'no login metadata collected by default');
  sm.ready(auth.id);
  await sm.capture(auth.id, { reload: true });
  await page.getByLabel('Email', { exact: true }).fill('private@example.test');
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await page.getByText('Lookup complete', { exact: true }).waitFor();
  await sm.capture(auth.id);
  await sm.stop(auth.id);
  const authAssessment = service.assess(c.id, auth.id);
  const authFinding = authAssessment.findings.find((f) => f.ruleId === 'WI-URL-001');
  assert(authFinding?.related.length);
  const payload = JSON.stringify(service.export(c.id, authAssessment.id));
  for (const secret of [
    'fixture-password',
    'private@example.test',
    '"storageState"',
    '"cookies":[{"name":"wi_session","value"',
  ])
    assert(!payload.includes(secret), secret);
  await ui.setViewportSize({ width: 1440, height: 1050 });
  await ui.reload();
  await ui.locator('.history-item').first().click();
  await panel.getByLabel('Assessment tersimpan', { exact: true }).selectOption(authAssessment.id);
  await panel.locator('.security-list button').filter({ hasText: 'WI-URL-001' }).first().click();
  await panel.getByRole('button', { name: 'Buka wiring 1', exact: true }).click();
  await panel.locator('.security-wiring .react-flow__node').first().waitFor();
  assert.deepEqual(errors, []);
  console.log(
    'PASS: safe fixture exceptions; authenticated cookie-protected fixture denied before login, findings linked to POST/query evidence and graph after login; login secrets/state excluded.',
  );
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  manager.store.close();
}
