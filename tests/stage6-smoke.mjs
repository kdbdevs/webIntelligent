import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { launchBrowser } from '../server/audit.mjs';
import { ForensicService } from '../server/forensics.mjs';
process.env.PORT = process.env.STAGE6_TEST_PORT || '8793';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-stage6-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
process.env.WI_AI_PROVIDER = 'none';
const { server, manager } = await import('../server/index.mjs');
if (!server.listening) await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${process.env.PORT}`;
const api = async (url, body) => {
  const r = await fetch(
    base + url,
    body
      ? {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }
      : {},
  );
  assert(r.ok, `${r.status} ${await r.clone().text()}`);
  return r.json();
};
const wait = async (fn) => {
  for (let i = 0; i < 300; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw Error('Timed out');
};
let browser;
const errors = [],
  external = [];
let trap = 0;
server.on('request', (req) => {
  if (req.url.startsWith('/forensic-trap')) trap++;
});
try {
  const c = await api('/api/cases', {
    title: 'Stage 6 synthetic investigation',
    objective: 'Relate selected web observations and imported fixture records.',
    operator: 'Fixture analyst',
    navigation: [base + '/demo'],
  });
  const fs = new ForensicService(manager.store),
    imports = [];
  for (const [name, format] of [
    ['auth.ndjson', 'ndjson'],
    ['transfer.har', 'har'],
    ['message.eml', 'eml'],
    ['export.txt', 'file'],
  ])
    imports.push(
      await fs.import(c.id, await readFile(`tests/fixtures/forensics/${name}`), {
        filename: name,
        format,
        namespace: 'portal-fixture',
      }),
    );
  const captures = [];
  for (const maxPages of [1, 2]) {
    const capture = await manager.create({
      caseId: c.id,
      url: base + '/demo',
      allowLocal: true,
      maxPages,
    });
    await wait(() => !['queued', 'running'].includes(capture.status));
    assert.equal(capture.status, 'complete', JSON.stringify(capture.warnings));
    captures.push(manager.store.getRun(c.id, capture.id));
  }
  browser = await launchBrowser(true);
  const ui = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  ui.on('pageerror', (e) => errors.push(e.message));
  await ui.route('**/*', (route) => {
    if (new URL(route.request().url()).origin !== base) {
      external.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  await ui.goto(base);
  await ui.getByLabel('Kasus aktif', { exact: true }).selectOption(c.id);
  const panel = ui.getByRole('region', { name: 'Pelaporan kasus' });
  await panel.getByRole('button', { name: /Laporan, perbandingan/ }).click();
  const idle = async () => {
    await wait(async () => (await panel.getAttribute('aria-busy')) === 'false');
    assert.deepEqual(await panel.getByRole('alert').allTextContents(), []);
  };
  await idle();
  for (const id of [captures[0].reportArtifactId, ...imports.map((i) => i.parseRef.artifactId)])
    await panel.getByRole('checkbox', { name: new RegExp(id.slice(0, 8)) }).check();
  await panel.getByText('Narasi yang boleh dibagikan (opsional)', { exact: true }).click();
  for (const [k, v] of Object.entries({
    title: 'Synthetic case review',
    objective: 'Compare current observations with synthetic historical source claims.',
    scope: 'Local demo capture and selected synthetic HAR, log, email and file records.',
    recommendations: 'Review the ambiguous source timezone before drawing a chronology.',
    reviewer: 'Fixture reviewer',
  }))
    await panel.getByLabel('Narasi berbagi ' + k, { exact: true }).fill(v);
  await panel.getByLabel('Saya menyetujui narasi ini untuk disertakan dalam ekspor').check();
  await panel.getByRole('button', { name: 'Buat draft', exact: true }).click();
  await idle();
  assert(await panel.getByTestId('report-preview').count());
  await panel
    .getByRole('button', { name: /^Bukti / })
    .first()
    .click();
  await idle();
  assert(await panel.getByTestId('report-evidence').count());
  await panel.getByRole('button', { name: 'Tutup bukti' }).click();
  await panel.getByLabel('Tugas', { exact: true }).selectOption('summary');
  await panel.getByRole('button', { name: 'Analisis lokal tanpa AI' }).click();
  await idle();
  assert(await panel.getByTestId('assistant-result').count());
  assert((await panel.getByTestId('assistant-result').textContent()).includes('observation'));
  await panel
    .getByLabel('Alasan keputusan')
    .fill('Reviewed synthetic sources, scope gaps, classifications and sharing narrative.');
  await panel
    .getByLabel('Saya sudah meninjau bukti, gap, redaksi dan status temuan pada snapshot ini.')
    .check();
  await panel.getByRole('button', { name: 'Tandai final sebagai versi baru' }).click();
  await idle();
  assert((await panel.getByTestId('report-preview').textContent()).includes('final v2'));
  const catalog = await api(`/api/cases/${c.id}/reporting`),
    finalId = catalog.reports.find((r) => r.status === 'final').id;
  await mkdir('output/pdf', { recursive: true });
  await mkdir('output/playwright', { recursive: true });
  for (const format of ['json', 'html', 'pdf', 'package']) {
    const promise = ui.waitForResponse(
      (r) => r.url().endsWith('/export') && r.request().method() === 'POST',
    );
    await panel
      .getByRole('button', {
        name: format === 'package' ? 'Paket + manifest' : format.toUpperCase(),
        exact: true,
      })
      .click();
    const response = await promise;
    assert.equal(response.status(), 200);
    const ex = await response.json();
    await idle();
    const bytes = Buffer.from(
      await (
        await fetch(
          base +
            `/api/cases/${c.id}/runs/${ex.artifact.runId}/artifacts/${ex.artifact.artifactId}/content`,
        )
      ).arrayBuffer(),
    );
    const dest =
      format === 'pdf'
        ? 'output/pdf/stage6-synthetic-report.pdf'
        : `output/playwright/stage6-report.${format === 'package' ? 'wipkg.json' : format}`;
    await writeFile(dest, bytes);
    if (format === 'pdf') assert(bytes.subarray(0, 4).equals(Buffer.from('%PDF')));
    else assert(!bytes.toString().includes('SECRET_'));
    if (format === 'package') {
      const check = spawnSync(
        process.execPath,
        ['tools/verify-package.mjs', dest, '--expected-sha256', ex.sha256],
        { encoding: 'utf8' },
      );
      assert.equal(check.status, 0, check.stderr);
      await writeFile('output/playwright/stage6-package-verification.json', check.stdout);
    }
    if (format === 'html') {
      const preview = await browser.newPage();
      const requests = [];
      await preview.route('**/*', (r) => {
        requests.push(r.request().url());
        return r.abort();
      });
      await preview.setContent(bytes.toString());
      assert.equal(await preview.locator('script,img,iframe').count(), 0);
      assert.equal(requests.length, 0);
      assert((await preview.locator('body').textContent()).includes('Synthetic case review'));
      await preview.close();
    }
  }
  await panel.getByText('2. Bandingkan dua capture dalam kasus', { exact: true }).click();
  await panel.getByLabel('Capture A', { exact: true }).selectOption(captures[0].reportArtifactId);
  await panel.getByLabel('Capture B', { exact: true }).selectOption(captures[1].reportArtifactId);
  await panel.getByRole('button', { name: 'Bandingkan metadata capture' }).click();
  await idle();
  assert(await panel.getByTestId('capture-comparison').count());
  assert(
    (await panel.getByTestId('capture-comparison').textContent()).includes(
      'Visited page sets differ',
    ),
  );
  const foreign = await api('/api/cases', {
    title: 'Separate synthetic case',
    operator: 'Other',
    navigation: [base + '/demo'],
  });
  assert.equal((await fetch(base + `/api/cases/${foreign.id}/reports/${finalId}`)).status, 404);
  const origin = await fetch(base + `/api/cases/${c.id}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://untrusted.example.test' },
    body: '{}',
  });
  assert.equal(origin.status, 403);
  assert.equal(trap, 0);
  assert.deepEqual(errors, []);
  assert(external.every((x) => new URL(x).hostname === 'fonts.googleapis.com'));
  await panel.scrollIntoViewIfNeeded();
  await ui.screenshot({ path: 'output/playwright/stage6-reporting.png', fullPage: true });
  await panel.locator('summary').first().scrollIntoViewIfNeeded();
  await ui.screenshot({ path: 'output/playwright/stage6-panel-desktop.png' });
  await ui.setViewportSize({ width: 390, height: 844 });
  await panel.scrollIntoViewIfNeeded();
  assert((await panel.boundingBox()).width <= 390, 'Reporting panel fits mobile viewport');
  assert(
    await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    'No horizontal overflow on mobile',
  );
  await ui.screenshot({ path: 'output/playwright/stage6-panel-mobile.png' });
  const report = await api(`/api/cases/${c.id}/reports/${finalId}`);
  const results = {
    passed: true,
    provider: 'none',
    realModelTested: false,
    capturePages: captures.map(
      (r) => JSON.parse(manager.store.readArtifact(c.id, r.id, r.reportArtifactId)).pages.length,
    ),
    reportId: finalId,
    sourceCount: report.snapshot.sources.length,
    timelineEvents: report.snapshot.timeline.length,
    uiActions: [
      'select sources',
      'curate shared narrative',
      'draft',
      'open verified evidence',
      'local summary',
      'human final review',
      'JSON/HTML/PDF/package export',
      'capture comparison',
    ],
    independentPackageVerification: true,
    noActivePreviewContent: true,
    errors,
    externalBlocked: external,
  };
  await writeFile('output/playwright/stage6-results.json', JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  manager.store.close();
}
