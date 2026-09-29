import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { AuditManager, launchBrowser } from '../server/audit.mjs';
import { createAuthFixture } from '../server/auth-fixture.mjs';
import { readRules, selectedTargets, crawlRequestReason } from '../server/session-policy.mjs';

const req = (url, method = 'GET', body = null, navigation = false) => ({
  url: () => url,
  method: () => method,
  postData: () => body && JSON.stringify(body),
  isNavigationRequest: () => navigation,
});
test('crawl policy separates HTTP method from declared read operations and navigation scope', () => {
  const base = 'https://example.test';
  const rules = readRules([
    { method: 'POST', url: base + '/graphql', operationName: 'ProfileRead' },
  ]);
  assert(crawlRequestReason(req(base + '/logout'), rules));
  assert(crawlRequestReason(req(base + '/delete?id=1'), rules));
  assert(crawlRequestReason(req(base + '/api/message', 'POST'), rules));
  assert(crawlRequestReason(req(base + '/graphql', 'POST', { operationName: 'Other' }), rules));
  assert(
    crawlRequestReason(
      req(base + '/graphql', 'POST', {
        operationName: 'ProfileRead',
        query: 'mutation ProfileRead { remove }',
      }),
      rules,
    ),
  );
  assert(
    crawlRequestReason(
      req(base + '/graphql', 'POST', { operationName: 'ProfileRead' }, true),
      rules,
    ),
  );
  assert.equal(
    crawlRequestReason(
      req(base + '/graphql', 'POST', {
        operationName: 'ProfileRead',
        query: 'query ProfileRead { profile }',
      }),
      rules,
    ),
    null,
  );
  assert.throws(() => readRules([{ method: 'POST', url: base + '/graphql' }]));
  assert.throws(() => readRules([{ method: 'POST', url: base + '/api/read?token=secret' }]));
  assert.throws(() => selectedTargets([base + '/outside'], [base + '/app'], 2));
  assert.throws(() => selectedTargets([base + '/app/logout'], [base + '/app'], 2));
  assert.throws(() => selectedTargets([base + '/app#logout'], [base + '/app'], 2));
  assert.throws(() => selectedTargets([base + '/app/a', base + '/app/b'], [base + '/app'], 1));
  assert.deepEqual(selectedTargets([base + '/app#activity'], [base + '/app'], 2), [
    base + '/app#activity',
  ]);
});

async function loginFixture(page, base) {
  await page.goto(base + '/auth-fixture/login');
  await page.getByLabel('Email', { exact: true }).fill('fixture@example.test');
  await page.getByLabel('Password', { exact: true }).fill('fixture-password');
  await Promise.all([
    page.waitForURL('**/auth-fixture/mfa'),
    page.getByRole('button', { name: 'Login', exact: true }).click(),
  ]);
  await page.getByLabel('Kode', { exact: true }).fill('123456');
  await Promise.all([
    page.waitForURL('**/auth-fixture/profile'),
    page.getByRole('button', { name: 'Verifikasi', exact: true }).click(),
  ]);
  await page.getByText('Private fixture profile', { exact: true }).waitFor();
}
async function until(fn) {
  for (let n = 0; n < 160; n++) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error('Condition timed out');
}

test(
  'cookie-protected authenticated acquisition, SPA/popup, policies, lifecycle and isolation',
  { timeout: 120000 },
  async (t) => {
    const app = express();
    app.use('/auth-fixture', createAuthFixture());
    let outsideHits = 0;
    app.get('/outside-fixture', (req, res) => {
      outsideHits++;
      res.send('outside');
    });
    app.get('/auth-fixture/redirect-logout', (req, res) => res.redirect('/auth-fixture/logout'));
    app.get('/auth-fixture/redirect-private', (req, res) =>
      res.redirect('http://10.0.0.1/never-contact'),
    );
    const server = app.listen(0, '127.0.0.1');
    await new Promise((r) => server.once('listening', r));
    const base = `http://127.0.0.1:${server.address().port}`;
    const directory = path.join(await mkdtemp(path.join(tmpdir(), 'wi-session-test-')), 'data');
    const manager = new AuditManager(directory, { sessionLauncher: () => launchBrowser(true) });
    await manager.init();
    t.after(async () => {
      await manager.close();
      manager.store.close();
      await new Promise((r) => server.close(r));
    });
    const sm = manager.sessionManager;
    const a = manager.store.createCase({
      title: 'Session fixture A',
      operator: 'Fixture operator',
      navigation: [base + '/auth-fixture'],
    });
    const b = manager.store.createCase({
      title: 'Session fixture B',
      operator: 'Other operator',
      navigation: [base + '/auth-fixture'],
    });
    const open = async (caseId, extra = {}) => {
      const job = await sm.open({
        caseId,
        url: base + '/auth-fixture/profile',
        allowLocal: true,
        loginUrl: base + '/auth-fixture/login',
        maxPages: 10,
        ...extra,
      });
      const session = sm.get(job.id);
      await session.openTask;
      assert.equal(session.status, 'awaiting-login');
      return { job, session, page: session.page };
    };
    await assert.rejects(sm.open({ caseId: a.id, url: base + '/auth-fixture/profile' }), /privat/);
    await assert.rejects(
      sm.open({ caseId: a.id, url: base + '/outside-fixture', allowLocal: true }),
      /scope/,
    );
    await assert.rejects(
      sm.open({
        caseId: a.id,
        url: base + '/auth-fixture/profile',
        allowLocal: true,
        timeoutMinutes: 0,
      }),
      /Timeout/,
    );
    const { job, session, page } = await open(a.id);
    await t.test(
      'protected page rejects before login; login + MFA do not collect content by default',
      async () => {
        assert.equal((await page.reload()).status(), 401);
        await page.getByRole('heading', { name: 'Akses ditolak' }).waitFor();
        assert.equal(session.readiness, null);
        await assert.rejects(sm.capture(job.id), /siap/);
        await loginFixture(page, base);
        assert.equal(
          session.status,
          'awaiting-login',
          '200 does not automatically declare authentication',
        );
        assert.equal(job.requests.length, 0);
        assert.equal(job.events.length, 0);
        assert.equal(manager.store.artifacts(a.id, job.id).length, 0);
        sm.ready(job.id);
        assert.equal(session.readiness.basis, 'user-confirmed');
        assert.equal(session.collecting, false);
        assert.equal(manager.store.artifacts(a.id, job.id).length, 0);
      },
    );
    const sid = (await session.context.cookies()).find((c) => c.name === 'wi_fixture_sid').value;
    await t.test(
      'capture uses current SPA state; POST reads and popup tabs retain same authenticated context',
      async () => {
        await page.locator('#activity').click();
        await sm.capture(job.id);
        assert(job.pages.some((p) => p.url.endsWith('/profile/activity')));
        const firstArtifact = manager.store.artifacts(a.id, job.id)[0];
        assert.equal(firstArtifact.role, 'redacted');
        assert(firstArtifact.method.includes('password/OTP'));
        assert(firstArtifact.redaction.includes('Unmasked original was not acquired'));
        await page.locator('#refresh-data').click();
        await until(() =>
          job.requests.some((r) => r.url.endsWith('/api/read') && r.status === 200),
        );
        const popupEvent = page.waitForEvent('popup');
        await page.getByRole('link', { name: 'Buka popup pengaturan' }).click();
        const popup = await popupEvent;
        await popup.getByText('Private fixture profile', { exact: true }).waitFor();
        const popupId = [...session.tabs].find(([, p]) => p === popup)[0];
        sm.select(job.id, popupId);
        assert.equal(session.readiness, null);
        sm.ready(job.id);
        await sm.capture(job.id);
        assert(
          job.pages.some((p) => p.url.endsWith('/settings') && p.title === 'Private settings'),
        );
        assert.equal(popup.context(), page.context());
        sm.select(job.id, [...session.tabs].find(([, p]) => p === page)[0]);
        sm.ready(job.id);
        await sm.capture(job.id, {
          kind: 'crawl',
          urls: [base + '/auth-fixture/settings', base + '/auth-fixture/action-probe'],
          readEndpoints: [
            { method: 'POST', url: base + '/auth-fixture/api/read', operationName: 'ProfileRead' },
          ],
        });
        assert(
          job.requests.some(
            (r) =>
              r.pageUrl.endsWith('/settings') && r.url.endsWith('/api/read') && r.status === 200,
          ),
        );
        assert(job.requests.some((r) => r.url.endsWith('/delete') && r.blocked));
        assert(job.requests.some((r) => r.url.endsWith('/api/messages') && r.blocked));
        const metrics = await (await fetch(base + '/auth-fixture/metrics')).json();
        assert.equal(metrics.deletes, 0);
        assert.equal(metrics.messages, 0);
        assert.equal(metrics.logouts, 0);
        assert(
          manager.store.readArtifact(a.id, job.id, firstArtifact.id).length > 0,
          'earlier snapshot still exists',
        );
        await assert.rejects(
          sm.capture(job.id, { kind: 'crawl', urls: [base + '/auth-fixture/logout'] }),
        );
        await assert.rejects(
          sm.capture(job.id, { kind: 'crawl', urls: [base + '/outside-fixture'] }),
        );
        assert.equal(outsideHits, 0);
        sm.pause(job.id);
        const counts = [job.requests.length, job.events.length];
        await page.locator('#refresh-data').click();
        await page.waitForTimeout(100);
        assert.deepEqual([job.requests.length, job.events.length], counts);
      },
    );
    await t.test(
      'missing POST permission is reported; logout/401 pause collection and relogin preserves prior evidence',
      async () => {
        await sm.capture(job.id, { kind: 'crawl', urls: [base + '/auth-fixture/settings'] });
        assert(
          job.requests.some((r) => r.url.endsWith('/api/read') && r.blocked?.includes('izin')),
        );
        const before = manager.store.artifacts(a.id, job.id).length;
        await page.getByRole('link', { name: 'Logout', exact: true }).click();
        await until(() => session.status === 'awaiting-login');
        assert.equal(session.collecting, false);
        assert.equal(session.authSignal.type, 'configured-login-route');
        await loginFixture(page, base);
        sm.ready(job.id);
        await sm.capture(job.id);
        await page.locator('#expire').click();
        await until(() => session.authSignal?.type === 'http-401');
        assert.equal(session.collecting, false);
        await assert.rejects(sm.capture(job.id), /siap/);
        assert(manager.store.artifacts(a.id, job.id).length > before);
        await loginFixture(page, base);
        sm.ready(job.id);
        sm.markExpired(job.id);
        assert.equal(session.authSignal.type, 'user-reported');
        assert.equal(session.readiness, null);
      },
    );
    await t.test(
      'close seals immutable evidence without passwords or auth state; other case/run is isolated',
      async () => {
        await sm.stop(job.id);
        const manifest = manager.store.exportManifest(a.id, job.id);
        assert(manifest.verification.ok);
        assert.equal(manifest.session.status, 'closed');
        assert.equal(manifest.session.retainedAuthentication, false);
        assert(manifest.session.operations.some((o) => o.kind === 'crawl'));
        const text =
          JSON.stringify(job) +
          JSON.stringify(manifest) +
          manager.store
            .artifacts(a.id, job.id)
            .filter((art) => art.mimeType === 'application/json')
            .map((art) => manager.store.readArtifact(a.id, job.id, art.id).toString())
            .join('');
        for (const value of [
          'fixture-password',
          '123456',
          sid,
          '"cookies":',
          '"origins":',
          '"storageState":',
        ])
          assert(!text.includes(value), `secret/state omitted: ${value.slice(0, 15)}`);
        const second = await open(b.id);
        assert.equal(
          (await second.page.reload()).status(),
          401,
          'new run cannot reuse first run cookie',
        );
        assert.equal((await second.session.context.cookies()).length, 0);
        assert.equal(second.job.requests.length, 0);
        assert.notEqual(second.job.id, job.id);
        assert.throws(() => manager.store.getRun(b.id, job.id), /tidak ditemukan/);
        second.session.deadline = Date.now() + 30000;
        sm.refresh(second.job.id);
        assert(second.job.session.timeoutWarning);
        sm.extend(second.job.id);
        assert(!second.job.session.timeoutWarning);
        second.session.deadline = Date.now() - 1;
        await sm.tick(second.session);
        assert.equal(second.job.sessionInfo.status, 'expired');
        assert.equal(manager.store.getRun(b.id, second.job.id).status, 'partial');
      },
    );
    await t.test(
      'redirect chains cannot expand crawl scope or bypass action/private-address policy',
      async () => {
        const redirected = await open(a.id, { loginOrigins: ['http://10.0.0.1'] });
        await loginFixture(redirected.page, base);
        sm.ready(redirected.job.id);
        const metricsBefore = await (await fetch(base + '/auth-fixture/metrics')).json();
        await assert.rejects(
          sm.capture(redirected.job.id, {
            kind: 'crawl',
            urls: [base + '/auth-fixture/redirect-one'],
          }),
        );
        assert.equal(
          outsideHits,
          0,
          JSON.stringify({
            redirects: redirected.job.redirects,
            warnings: redirected.job.warnings,
          }),
        );
        assert(
          redirected.job.redirects.some(
            (r) =>
              r.from.endsWith('/redirect-two') &&
              r.to.endsWith('/outside-fixture') &&
              r.outcome === 'blocked',
          ),
        );
        await assert.rejects(
          sm.capture(redirected.job.id, {
            kind: 'crawl',
            urls: [base + '/auth-fixture/redirect-logout'],
          }),
        );
        const metricsAfter = await (await fetch(base + '/auth-fixture/metrics')).json();
        assert.equal(metricsAfter.logouts, metricsBefore.logouts);
        const popupEvent = redirected.page.waitForEvent('popup');
        await redirected.page.getByRole('link', { name: 'Popup redirect fixture' }).click();
        await popupEvent;
        await until(() =>
          redirected.job.redirects.some((r) => r.reason?.startsWith('Initial popup')),
        );
        assert.equal(outsideHits, 0);
        await redirected.page.goto(base + '/auth-fixture/redirect-private').catch(() => {});
        assert(
          redirected.job.redirects.some(
            (r) =>
              r.to === 'http://10.0.0.1/never-contact' &&
              r.outcome === 'blocked' &&
              r.reason.includes('tidak diizinkan'),
          ),
        );
        await sm.stop(redirected.job.id);
        assert(
          manager.store
            .exportManifest(a.id, redirected.job.id)
            .redirects.some((r) => r.outcome === 'blocked'),
        );
        const passive = await manager.create({
          caseId: a.id,
          url: base + '/auth-fixture/redirect-one',
          maxPages: 1,
          allowLocal: true,
        });
        await manager.runners.get(passive.id).task;
        assert.equal(outsideHits, 0, 'public audit redirect guard also honors case scope');
        assert(passive.redirects.some((r) => r.outcome === 'blocked'));
      },
    );
    await t.test(
      'network failure and interrupted crawl preserve already acquired artifacts',
      async () => {
        const failing = await open(b.id);
        await loginFixture(failing.page, base);
        sm.ready(failing.job.id);
        await sm.capture(failing.job.id);
        await failing.session.context.route('**/auth-fixture/unreachable', (route) =>
          route.abort('connectionrefused'),
        );
        await assert.rejects(
          sm.capture(failing.job.id, { kind: 'crawl', urls: [base + '/auth-fixture/unreachable'] }),
        );
        assert.equal(failing.session.operations.at(-1).status, 'partial');
        assert(failing.job.pages.length > 0);
        await sm.stop(failing.job.id);
        assert.equal(manager.store.getRun(b.id, failing.job.id).status, 'partial');
        assert(manager.store.verifyRun(b.id, failing.job.id).ok);
      },
    );
    await t.test(
      'explicit login observation captures only metadata; browser closure preserves partial capture',
      async () => {
        const third = await open(a.id, { observeLogin: true });
        await loginFixture(third.page, base);
        const loginRequest = third.job.requests.find(
          (r) => r.url.endsWith('/login') && r.method === 'POST',
        );
        assert(loginRequest);
        assert.deepEqual(
          loginRequest.body.fields.map((f) => f.name),
          ['email', 'password'],
        );
        assert(third.job.events.some((e) => e.type === 'submit'));
        assert.equal(manager.store.artifacts(a.id, third.job.id).length, 0);
        sm.ready(third.job.id);
        await sm.capture(third.job.id);
        await third.session.browser.close();
        await until(() => !manager.sessions.has(third.job.id));
        assert.equal(third.job.sessionInfo.status, 'failed');
        assert.equal(manager.store.getRun(a.id, third.job.id).status, 'partial');
        assert(manager.store.verifyRun(a.id, third.job.id).ok);
        const report = manager.store
          .readArtifact(
            a.id,
            third.job.id,
            manager.store.getRun(a.id, third.job.id).reportArtifactId,
          )
          .toString();
        assert(!report.includes('fixture-password'));
        assert(!report.includes('123456'));
        assert(!report.includes('fixture@example.test'));
      },
    );
  },
);

test('restart recovers session metadata and artifacts but cannot resume discarded authentication', async (t) => {
  const directory = path.join(await mkdtemp(path.join(tmpdir(), 'wi-session-recovery-')), 'data');
  const original = new AuditManager(directory);
  await original.init();
  const c = original.store.createCase({
    title: 'Interrupted session',
    operator: 'Fixture',
    navigation: ['https://example.test'],
  });
  const run = original.store.createRun(c.id, {
    mode: 'authenticated',
    url: 'https://example.test/profile',
  });
  const art = original.store.addArtifact(c.id, run.id, 'Fixture acquisition', {
    kind: 'fixture',
    mimeType: 'text/plain',
    source: run.url,
  });
  original.store.saveJob({
    id: run.id,
    caseId: c.id,
    mode: 'authenticated',
    status: 'running',
    url: run.url,
    pages: [],
    requests: [],
    events: [],
    edges: [],
    warnings: [],
    session: { status: 'capturing' },
    sessionInfo: { status: 'capturing', collecting: true, retainedAuthentication: false },
  });
  original.store.close();
  const recovered = new AuditManager(directory);
  await recovered.init();
  t.after(() => recovered.store.close());
  const job = recovered.jobs.get(run.id);
  assert.equal(job.session, null);
  assert.equal(job.sessionInfo.status, 'failed');
  assert.equal(job.sessionInfo.collecting, false);
  assert.equal(recovered.sessions.size, 0);
  assert.equal(recovered.store.getRun(c.id, run.id).status, 'partial');
  assert.equal(
    recovered.store.readArtifact(c.id, run.id, art.id).toString(),
    'Fixture acquisition',
  );
  assert(recovered.store.exportManifest(c.id, run.id).verification.ok);
});
