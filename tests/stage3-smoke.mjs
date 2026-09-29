import assert from 'node:assert/strict';
import { mkdtemp, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { launchBrowser } from '../server/audit.mjs';

// All acquisition and corruption tests use disposable stores, never user evidence.
process.env.PORT = process.env.STAGE3_TEST_PORT || '8790';
process.env.DATA_DIR = path.join(await mkdtemp(path.join(tmpdir(), 'wi-stage3-')), 'data');
process.env.EVIDENCE_KEY_DIR = process.env.DATA_DIR + '.keys';
process.env.ENABLE_AUTH_FIXTURE = '1';
process.env.ENABLE_WIRING_FIXTURE = '1';
const cssServer = http.createServer((req, res) => {
  if (req.url === '/cross.css') {
    res.setHeader('Content-Type', 'text/css');
    res.end('.cross-style{width:90px;height:40px;background-image:url(/cross.svg)}');
  } else {
    res.setHeader('Content-Type', 'image/svg+xml');
    res.end(
      '<svg xmlns="http://www.w3.org/2000/svg" width="90" height="40"><rect width="90" height="40" fill="pink"/></svg>',
    );
  }
});
cssServer.listen(0, '127.0.0.1');
await new Promise((r) => cssServer.once('listening', r));
process.env.WIRING_FIXTURE_CSS_ORIGIN = `http://127.0.0.1:${cssServer.address().port}`;
const { server, manager } = await import('../server/index.mjs');
if (!server.listening) await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${process.env.PORT}`;
const sm = manager.sessionManager;
const waitUntil = async (fn) => {
  for (let i = 0; i < 300; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('Condition timed out');
};
const read = (job, id) => JSON.parse(manager.store.readArtifact(job.caseId, job.id, id));
const graphOf = (job, p = job.pages.at(-1)) => read(job, p.wiring.artifactId);
let browser;
try {
  const c = manager.store.createCase({
    title: 'Wiring visual fixture',
    operator: 'Synthetic operator',
    navigation: [base + '/wiring-fixture', base + '/auth-fixture'],
  });
  const passive = await manager.create({
    caseId: c.id,
    url: base + '/wiring-fixture',
    allowLocal: true,
    maxPages: 1,
  });
  await waitUntil(() => !['queued', 'running'].includes(passive.status));
  assert.equal(passive.status, 'complete', JSON.stringify(passive.warnings));
  const publicPage = passive.pages[0],
    publicGraph = graphOf(passive, publicPage);
  const png = manager.store.readArtifact(c.id, passive.id, publicPage.screenshotArtifactId);
  assert.equal(
    png.readUInt32BE(20),
    4000,
    'bounded full-page screenshot covers document coordinates',
  );
  assert.equal(publicPage.screenshotHeight, png.readUInt32BE(20));
  assert.equal(publicPage.screenshotWidth, png.readUInt32BE(16));
  assert(publicGraph.assets.length >= 16, `assets:${publicGraph.assets.length}`);
  assert(
    publicGraph.assets.some(
      (a) => a.source.kind === 'data' && a.source.truncated && !a.requestIds.length,
    ),
  );
  assert(publicGraph.gaps.some((g) => g.includes('size limits')));
  const responsive = publicPage.elements.find((e) => e.selector === '#responsive');
  const choices = publicGraph.assets.filter((a) =>
    a.uses.some((u) => u.elementId === responsive.id),
  );
  const selected = choices.find((a) => a.uses.some((u) => u.role === 'selected'));
  assert(selected?.requestIds.length > 0, 'browser currentSrc has an exact observed request');
  assert(selected.uses.find((u) => u.role === 'selected').state.naturalWidth > 0);
  const never = choices.find((a) => a.source.url?.endsWith('/never.svg'));
  assert(never);
  assert.equal(never.requestIds.length, 0);
  assert(never.uses.every((u) => u.role === 'declared'));
  const lazy = publicGraph.assets.find((a) => a.source.url?.endsWith('/lazy.svg'));
  assert(lazy);
  assert.equal(lazy.requestIds.length, 0, 'offscreen lazy declaration is not a network request');
  assert.equal(lazy.uses[0].state.loading, 'lazy');
  const metrics = await (await fetch(base + '/wiring-fixture/metrics')).json();
  assert.equal(metrics['/never.svg'], undefined);
  assert.equal(metrics['/lazy.svg'], undefined);
  const background = publicGraph.assets.find((a) => a.source.url?.endsWith('/background.svg'));
  assert(background.requestIds.length);
  assert(background.uses.some((u) => u.position === '-30px -20px' && u.size === '520px 160px'));
  assert(background.uses.some((u) => u.rules?.some((r) => r.source?.url.endsWith('/style.css'))));
  assert(publicGraph.assets.some((a) => a.uses.some((u) => u.pseudo === '::before')));
  assert(publicGraph.assets.some((a) => a.type === 'svg' && a.source.kind === 'inline'));
  assert(
    publicGraph.assets.some((a) => a.source.url?.endsWith('/symbols.svg') && a.requestIds.length),
  );
  assert(
    publicGraph.assets.some((a) => a.source.url?.endsWith('/external.svg') && a.requestIds.length),
  );
  assert(publicGraph.assets.some((a) => a.type === 'font' && a.requestIds.length));
  assert(
    publicGraph.assets.some(
      (a) => a.type === 'font' && a.uses.some((u) => u.actualPaintedFont?.startsWith('unknown')),
    ),
  );
  assert(publicGraph.assets.some((a) => a.type === 'script' && a.requestIds.length));
  assert(publicGraph.assets.some((a) => a.type === 'stylesheet' && a.requestIds.length));
  assert(publicGraph.assets.some((a) => a.type === 'favicon'));
  for (const kind of ['data', 'blob']) {
    const a = publicGraph.assets.find((a) => a.source.kind === kind);
    assert(a);
    assert.equal(a.requestIds.length, 0);
  }
  assert(
    publicGraph.assets.find((a) => a.source.kind === 'blob').source.creator.startsWith('unknown'),
  );
  assert(
    publicPage.visuals.sheets.some((s) => s.accessible === false && s.reason.includes('CSSOM')),
  );
  const cross = publicGraph.assets.find((a) => a.source.url?.endsWith('/cross.svg'));
  assert(cross.uses.some((u) => u.ruleSourceStatus.startsWith('unknown')));
  assert.equal(publicGraph.coverage.iframeCount, 1);
  assert.equal(publicGraph.coverage.openShadowHosts, 1);
  const secretSources = publicGraph.assets.filter((a) => a.source.url?.includes('/private.svg'));
  assert.equal(secretSources.length, 2);
  assert.equal(secretSources[0].source.url, secretSources[1].source.url);
  assert.notEqual(
    secretSources[0].requestIds[0],
    secretSources[1].requestIds[0],
    'redacted query collision does not merge requests',
  );
  console.log(
    'PASS: responsive currentSrc vs unused declarations, lazy source not requested, CSS/pseudo/sprite, SVG, real icon font, data/blob, inaccessible CSS and capture gaps.',
  );

  const job = await sm.open({
    caseId: c.id,
    url: base + '/auth-fixture/wiring',
    allowLocal: true,
    maxPages: 4,
  });
  const session = sm.get(job.id);
  await session.openTask;
  const audit = session.page;
  assert.equal((await audit.reload()).status(), 401);
  await audit.goto(base + '/auth-fixture/login');
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
  await audit.goto(base + '/auth-fixture/wiring');
  assert.equal(job.requests.length, 0);
  assert.equal(job.pages.length, 0);
  sm.ready(job.id);
  await sm.capture(job.id);
  const before = job.pages.at(-1),
    beforeGraph = graphOf(job, before),
    beforeBytes = manager.store.readArtifact(c.id, job.id, before.wiring.artifactId);
  assert(
    beforeGraph.assets.some(
      (a) => a.uses.some((u) => u.role === 'selected') && !a.requestIds.length,
    ),
    'already-loaded page does not invent missed requests',
  );
  await sm.capture(job.id, { reload: true });
  await audit.getByLabel('Email', { exact: true }).fill('private-value@example.test');
  await audit.getByRole('button', { name: 'Lookup', exact: true }).click();
  await audit.getByText('Lookup complete', { exact: true }).waitFor();
  await audit.getByRole('button', { name: 'Form encoded request', exact: true }).click();
  await waitUntil(() =>
    job.requests.some((r) => r.url.endsWith('/api/items/42') && r.status === 200),
  );
  await audit.getByRole('button', { name: 'SPA route', exact: true }).click();
  await waitUntil(() => job.requests.some((r) => r.url.endsWith('/near.svg') && r.status === 200));
  await sm.capture(job.id);
  const p = job.pages.at(-1),
    graph = graphOf(job, p);
  const lookup = graph.nodes.find(
    (n) => n.type === 'request' && n.details.url.includes('/api/read?'),
  );
  assert(lookup);
  assert.equal(lookup.details.status, 200);
  assert.equal(lookup.details.method, 'POST');
  assert(lookup.details.parameters.some((v) => v.name === 'email' && v.location === 'JSON body'));
  assert(lookup.details.parameters.some((v) => v.name === 'token' && v.location === 'query'));
  assert.equal(lookup.details.pathParameters.status, 'unknown');
  const formRequest = graph.nodes.find(
    (n) => n.type === 'request' && n.details.url.endsWith('/wiring-fixture/api/lookup'),
  );
  assert(
    formRequest.details.parameters.some((p) => p.name === 'email' && p.location === 'form body'),
  );
  const redirected = graph.nodes.find(
    (n) => n.type === 'request' && n.details.url.endsWith('/api/items/42'),
  );
  assert(redirected.details.redirectedFromId);
  assert.equal(
    redirected.details.pathParameters.status,
    'unknown',
    'numeric path is not a proven parameter',
  );
  assert(
    graph.edges.some(
      (e) =>
        e.target === redirected.id &&
        e.relation === 'observed' &&
        e.reason.includes('redirectedFrom'),
    ),
  );
  assert(lookup.details.timing && lookup.details.timing.responseEnd >= 0);
  assert(graph.edges.some((e) => e.target === lookup.id && e.relation === 'correlated'));
  const near = graph.nodes.find((n) => n.type === 'request' && n.details.url.endsWith('/near.svg'));
  assert(near);
  assert(
    graph.edges.some((e) => e.target === near.id && e.source.includes(':event:')),
    'near-click image has an explicitly classified event correlation',
  );
  assert(
    graph.edges
      .filter((e) => e.target === near.id && e.source.includes(':event:'))
      .every((e) => e.relation === 'correlated'),
  );
  assert(graph.nodes.some((n) => n.type === 'change' && n.details.type === 'pushState'));
  assert(graph.nodes.some((n) => n.type === 'change' && n.details.type === 'DOM mutation batch'));
  assert.notEqual(before.captureId, p.captureId);
  assert.notEqual(before.documentId, p.documentId);
  assert(
    !p.elements.some((e) => before.elements.some((b) => b.id === e.id)),
    'same selectors never reuse capture identities',
  );
  assert.deepEqual(
    manager.store.readArtifact(c.id, job.id, before.wiring.artifactId),
    beforeBytes,
    'prior graph immutable',
  );
  const cache = new Map();
  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  for (const e of graph.edges) {
    assert(nodeIds.has(e.source));
    assert(nodeIds.has(e.target));
  }
  for (const item of [...graph.nodes, ...graph.edges]) {
    assert(['observed', 'declared', 'correlated', 'inferred', 'unknown'].includes(item.relation));
    assert(item.reason);
    assert(item.evidence.length);
    for (const ref of item.evidence) {
      assert.equal(ref.caseId, c.id);
      assert.equal(ref.runId, job.id);
      assert.equal(ref.captureId, p.captureId);
      if (!cache.has(ref.artifactId)) cache.set(ref.artifactId, read(job, ref.artifactId));
      let value = cache.get(ref.artifactId);
      for (const key of ref.pointer.split('/').slice(1))
        value = value?.[key.replace(/~1/g, '/').replace(/~0/g, '~')];
      assert.notEqual(value, undefined, `resolvable evidence ${ref.pointer}`);
    }
  }
  const serialized = JSON.stringify(graph);
  for (const secret of [
    'private-value@example.test',
    'never-export-this',
    'query-secret',
    'secret-one',
    'secret-two',
    'fixture-password',
    'wi_fixture_sid',
    'storageState',
    'form-secret',
  ])
    assert(!serialized.includes(secret), `excluded ${secret}`);
  console.log(
    'PASS: protected page rejects before login; same context after manual fixture login; reload capture, input → parameter → POST → response, SPA/DOM changes, immutable capture identity, all graph references resolvable, sensitive values omitted.',
  );

  // UI selection on a completed authenticated run, using the actual production build.
  await sm.stop(job.id);
  assert(manager.store.verifyRun(c.id, job.id).ok);
  browser = await launchBrowser(true);
  const ui = await browser.newPage({ viewport: { width: 1600, height: 1100 } }),
    errors = [],
    assetFetches = [];
  ui.on('pageerror', (e) => errors.push(e.message));
  ui.on('request', (r) => {
    if (
      r.url().includes('/wiring-fixture/') ||
      r.url().startsWith(process.env.WIRING_FIXTURE_CSS_ORIGIN)
    )
      assetFetches.push(r.url());
  });
  // App fonts are cosmetic; keep the verification independent of external networks.
  await ui.route('**/*', (route) =>
    new URL(route.request().url()).origin === base ? route.continue() : route.abort(),
  );
  await ui.goto(base, { waitUntil: 'domcontentloaded' });
  await ui.getByLabel('Kasus aktif', { exact: true }).selectOption(c.id);
  await ui.locator('.history-item').filter({ hasText: 'Sesi' }).first().click();
  await ui.getByRole('button', { name: 'Wiring & aset', exact: true }).click();
  const privateResponsive = p.elements.find((e) => e.selector === '#responsive');
  await ui.getByLabel('Halaman audit', { exact: true }).selectOption(p.id);
  await ui.getByLabel('Elemen wiring', { exact: true }).selectOption(privateResponsive.id);
  await ui.getByLabel('Hanya aset elemen pilihan', { exact: true }).check();
  const chosen = graph.assets.find((a) =>
    a.uses.some((u) => u.elementId === privateResponsive.id && u.role === 'selected'),
  );
  await ui.locator(`[data-asset-id="${chosen.id}"]`).click();
  await ui.getByLabel('Sorot #responsive', { exact: true }).waitFor();
  assert((await ui.locator('.wiring-flow .react-flow__node').count()) > 0);
  const requestNode = graph.nodes.find((n) => n.id === chosen.requestIds[0]);
  await ui
    .locator('.wiring-uses')
    .getByRole('button', { name: requestNode.label, exact: true })
    .click();
  assert(
    (await ui.locator('.wiring-flow .react-flow__node').count()) < 25,
    'unknown boundary must not expand to every request',
  );
  await ui
    .getByLabel('Detail relasi wiring')
    .getByText(/Playwright request event observed/)
    .waitFor();
  await ui.getByLabel('Detail relasi wiring').getByRole('link').first().waitFor();
  await ui.getByLabel('Hanya aset elemen pilihan', { exact: true }).uncheck();
  assert.equal(
    await ui.locator('.wiring-asset-list button').count(),
    40,
    'inventory paginates a larger site',
  );
  await ui.getByRole('button', { name: 'Muat 40 aset lagi', exact: true }).click();
  assert((await ui.locator('.wiring-asset-list button').count()) > 40);
  await ui.getByLabel('Tipe aset', { exact: true }).selectOption('font');
  assert((await ui.locator('.wiring-asset-list button').count()) >= 1);
  await ui.getByLabel('Cari aset', { exact: true }).fill('no-such-asset');
  assert.equal(await ui.locator('.wiring-asset-list button').count(), 0);
  await ui.getByLabel('Cari aset', { exact: true }).fill('');
  await ui.getByLabel('Tipe aset', { exact: true }).selectOption('');
  await ui.waitForFunction(() => {
    const img = document.querySelector('.wiring-screenshot img');
    return img?.complete && img.naturalWidth > 0;
  });
  assert.deepEqual(assetFetches, [], 'preview never fetches active asset content');
  await mkdir('output/playwright', { recursive: true });
  await ui.screenshot({ path: 'output/playwright/stage3-wiring-desktop.png', fullPage: true });
  await ui.setViewportSize({ width: 390, height: 844 });
  await ui.screenshot({ path: 'output/playwright/stage3-wiring-mobile.png', fullPage: true });
  assert(
    await ui.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    'no mobile horizontal overflow',
  );
  assert.deepEqual(errors, []);
  const exportResponse = await fetch(`${base}/api/cases/${c.id}/runs/${job.id}/manifest`);
  assert.equal(exportResponse.status, 200);
  const manifest = await exportResponse.json();
  assert(JSON.stringify(manifest).includes('wiring-graph'));
  console.log(
    'PASS: authenticated UI element → asset → request, screenshot highlight, source evidence links, filters, safe PNG preview (zero asset refetch), desktop/mobile, hash verification and manifest export.',
  );
} finally {
  await browser?.close();
  await manager.close();
  await new Promise((r) => server.close(r));
  await new Promise((r) => cssServer.close(r));
  manager.store.close();
}
