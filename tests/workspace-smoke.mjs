import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { launchBrowser } from '../server/audit.mjs';

// Isolated synthetic data only. This script never opens the user's case store.
process.env.PORT = process.env.WORKSPACE_TEST_PORT || '8794';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-workspaces-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
process.env.WI_AI_PROVIDER = 'none';
const { server, manager } = await import('../server/index.mjs');
if (!server.listening)
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
const base = `http://127.0.0.1:${process.env.PORT}`;
let browser, ui;
const errors = [],
  mutations = [];
try {
  browser = await launchBrowser(true);
  ui = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  ui.on('pageerror', (e) => errors.push(e.message));
  ui.on('request', (r) => {
    if (r.url().startsWith(base + '/api/') && !['GET', 'HEAD'].includes(r.method()))
      mutations.push(r.url());
  });
  await ui.route('**/*', (route) =>
    new URL(route.request().url()).origin === base ? route.continue() : route.abort(),
  );
  const heading = (name) => ui.getByRole('heading', { level: 1, name: name + '.', exact: true });
  const select = async (name) => {
    if (ui.viewportSize().width <= 760)
      await ui.getByRole('button', { name: 'Buka sidebar', exact: true }).click();
    await ui
      .getByRole('navigation', { name: 'Menu utama' })
      .getByRole('link', { name, exact: true })
      .click();
    await heading(name).waitFor();
    assert.equal(
      await ui
        .getByRole('link', { name, exact: true, includeHidden: true })
        .getAttribute('aria-current'),
      'page',
    );
  };
  const region = (name) => ui.getByRole('region', { name, exact: true });
  await ui.goto(base);
  await heading('Belajar Web').waitFor();
  assert.equal(
    await ui.getByRole('navigation', { name: 'Menu utama' }).getByRole('link').count(),
    3,
  );
  assert.equal(await region('Audit dengan login').isVisible(), false);
  assert.equal(await region('Forensik kasus').isVisible(), false);
  assert.equal(await region('Pelaporan kasus').isVisible(), false);
  assert.equal(
    await ui.getByRole('button', { name: 'Kenali elemen', exact: true }).isDisabled(),
    true,
  );
  // An unfinished case form and URL survive all three menus.
  await ui.getByRole('button', { name: 'Buat kasus', exact: true }).click();
  await ui.getByLabel('Judul kasus', { exact: true }).fill('Workspace synthetic case');
  await ui.getByLabel('Scope navigasi', { exact: true }).fill(base + '/demo');
  await ui.getByLabel('URL website yang akan diaudit').fill(base + '/demo');
  await select('Cybersecurity');
  await region('Audit dengan login').waitFor();
  await region('Pelaporan kasus').waitFor();
  assert.equal(await region('Forensik kasus').isVisible(), false);
  await ui.getByLabel('URL login sebagai indikator', { exact: true }).fill(base + '/demo/login');
  await select('Lab Forensik');
  await region('Forensik kasus').waitFor();
  await select('Belajar Web');
  assert.equal(
    await ui.getByLabel('Judul kasus', { exact: true }).inputValue(),
    'Workspace synthetic case',
  );
  assert.equal(await ui.getByLabel('URL website yang akan diaudit').inputValue(), base + '/demo');
  assert.deepEqual(
    mutations,
    [],
    'menu navigation must not create captures, imports, assessments or AI calls',
  );
  await ui.getByRole('button', { name: 'Simpan kasus', exact: true }).click();
  await ui.getByRole('button', { name: 'Edit kasus', exact: true }).waitFor();
  const caseId = await ui.getByLabel('Kasus aktif', { exact: true }).inputValue();
  await ui.getByLabel('Izinkan localhost', { exact: true }).check();
  await ui.getByLabel('Maks. halaman', { exact: false }).selectOption('1');
  const created = ui.waitForResponse(
    (r) => r.url() === base + '/api/audits' && r.request().method() === 'POST',
  );
  await ui.getByRole('button', { name: 'Audit website', exact: true }).click();
  const job = await (await created).json();
  await select('Cybersecurity');
  await select('Lab Forensik');
  await select('Belajar Web');
  await ui.waitForFunction(
    () => document.querySelector('.audit-title')?.textContent.includes('berhasil'),
    null,
    { timeout: 60000 },
  );
  assert.equal(
    manager.store.listRuns(caseId).length,
    1,
    'switching menu during capture retains exactly one run',
  );
  const captured = await (await fetch(base + '/api/audits/' + job.id)).json();
  assert.equal(captured.pages.length, 1);
  assert.equal(captured.caseId, caseId);
  await ui.getByRole('button', { name: 'Telusuri sumber aset', exact: true }).click();
  assert.equal(
    await ui
      .getByRole('button', { name: 'Wiring & aset', exact: true })
      .getAttribute('aria-pressed'),
    'true',
  );
  await ui.getByRole('button', { name: 'Ikuti perjalanan data', exact: true }).click();
  assert.equal(
    await ui.getByRole('button', { name: 'Alur data', exact: true }).getAttribute('aria-pressed'),
    'true',
  );
  await select('Cybersecurity');
  assert.equal(
    await ui.getByLabel('URL login sebagai indikator', { exact: true }).inputValue(),
    base + '/demo/login',
  );
  assert.equal(
    await ui.getByRole('button', { name: 'Alur data', exact: true }).getAttribute('aria-pressed'),
    'true',
  );
  assert.equal(await ui.getByLabel('Kasus aktif', { exact: true }).inputValue(), caseId);
  await ui.getByRole('button', { name: 'Bukti & manifest', exact: true }).click();
  await ui.getByRole('button', { name: 'Verifikasi integritas', exact: true }).click();
  await ui.getByText('Integritas terverifikasi', { exact: false }).waitFor();
  const report = region('Pelaporan kasus');
  await report.getByRole('button', { name: /Laporan, perbandingan/ }).click();
  await report.getByText('Narasi yang boleh dibagikan (opsional)', { exact: true }).click();
  await report.getByLabel(/^Narasi berbagi title/).fill('Unfinished report title');
  await select('Lab Forensik');
  const forensic = region('Forensik kasus');
  await forensic.getByRole('button', { name: 'Buka workspace forensik', exact: true }).click();
  await forensic.getByLabel('Namespace sumber', { exact: true }).fill('synthetic-namespace');
  await forensic.getByLabel('File impor', { exact: true }).setInputFiles({
    name: 'not-imported.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('Synthetic content'),
  });
  const before = [...mutations];
  await select('Belajar Web');
  assert.equal(await region('Pelaporan kasus').isVisible(), false);
  assert.equal(await region('Forensik kasus').isVisible(), false);
  assert.equal(
    await ui.getByRole('button', { name: 'Bukti & manifest', exact: true }).isVisible(),
    false,
  );
  await ui.goBack();
  await heading('Lab Forensik').waitFor();
  assert.equal(
    await forensic.getByLabel('Namespace sumber', { exact: true }).inputValue(),
    'synthetic-namespace',
  );
  assert.equal(
    await forensic.getByLabel('File impor', { exact: true }).evaluate((el) => el.files[0]?.name),
    'not-imported.txt',
  );
  assert.equal(
    await report.getByLabel(/^Narasi berbagi title/).inputValue(),
    'Unfinished report title',
  );
  await ui.goForward();
  await heading('Belajar Web').waitFor();
  assert.deepEqual(mutations, before, 'switching with pending drafts must not submit them');
  await mkdir('output/playwright', { recursive: true });
  await ui.screenshot({ path: 'output/playwright/workspace-learn-desktop.png', fullPage: true });
  await ui.setViewportSize({ width: 390, height: 844 });
  for (const [name, slug] of [
    ['Cybersecurity', 'cyber'],
    ['Lab Forensik', 'lab'],
    ['Belajar Web', 'learn'],
  ]) {
    await select(name);
    assert.equal((await ui.locator('.sidebar').getAttribute('class')).trim(), 'sidebar');
    assert(
      await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
      name + ' mobile overflow',
    );
    await ui.screenshot({ path: `output/playwright/workspace-${slug}-mobile.png`, fullPage: true });
  }
  // Only the menu preference is persisted. Deep links override it, including after reload.
  await ui.goto(base + '/#/lab-forensik');
  await heading('Lab Forensik').waitFor();
  await ui.reload();
  await heading('Lab Forensik').waitFor();
  await ui.goto(base);
  await heading('Lab Forensik').waitFor();
  await select('Cybersecurity');
  await ui.goBack();
  await heading('Lab Forensik').waitFor();
  await ui.goto(base + '/#/invalid-menu');
  await heading('Belajar Web').waitFor();
  const storage = await ui.evaluate(() => Object.fromEntries(Object.entries(localStorage)));
  assert.deepEqual(storage, { 'wi.workspace': 'learn' });
  assert.deepEqual(errors, []);
  await writeFile(
    'output/playwright/workspace-checks.json',
    JSON.stringify(
      {
        menus: 3,
        caseId,
        runId: job.id,
        checks: [
          'progressive feature visibility',
          'no automatic mutations',
          'drafts and file retained',
          'same run across menus',
          'guide navigation',
          'integrity verification',
          'browser Back/Forward',
          'deep links and preference',
          '390px mobile',
        ],
        runtimeErrors: errors,
      },
      null,
      2,
    ),
  );
  console.log(
    'PASS: three menus, shared case/capture, retained drafts/file, guide links, evidence verification, no navigation mutations, Back/Forward, deep links, preference, mobile and runtime checks. Synthetic data only.',
  );
} catch (error) {
  console.error('Workspace test failure:', ui?.url());
  await mkdir('output/playwright', { recursive: true });
  await ui?.screenshot({ path: 'output/playwright/workspace-failure.png', fullPage: true });
  throw error;
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  manager.store.close();
}
