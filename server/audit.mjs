import { chromium } from 'playwright';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { installObserver, extractPage } from './browser-scripts.mjs';
import { extractVisuals } from './visual-scripts.mjs';
import { SourceCatalog, sanitizeVisuals, requestParameters, buildWiring } from './wiring.mjs';
import { EvidenceStore, LIMITS, PRIVACY, inScope, fail, isOfflineMode } from './evidence.mjs';
import { SessionManager } from './sessions.mjs';
import { redirectGuard } from './redirect-guard.mjs';
import { requestSecurityMetadata, responseSecurityMetadata } from './security-metadata.mjs';
import {
  validateDestination,
  displayUrl,
  summarizeBody,
  crawlable,
  cleanStack,
} from './safety.mjs';

export async function launchBrowser(headless = true) {
  const options = {
    headless,
    timeout: 30000,
    ...(process.env.BROWSER_CHANNEL ? { channel: process.env.BROWSER_CHANNEL } : {}),
  };
  try {
    return await chromium.launch(options);
  } catch (error) {
    if (!process.env.BROWSER_CHANNEL && process.platform === 'darwin')
      return chromium.launch({ headless, channel: 'chrome' });
    throw new Error(
      `Browser tidak tersedia. Jalankan npm run browser:install. ${error.message.split('\n')[0]}`,
    );
  }
}

export class AuditManager {
  constructor(directory, { sessionLauncher = launchBrowser } = {}) {
    this.directory = directory;
    this.store = new EvidenceStore(directory);
    this.migrationWarnings = [];
    this.jobs = new Map();
    this.runners = new Map();
    this.sessions = new Map();
    this.sessionOpening = false;
    this.sourceCatalogs = new WeakMap();
    this.securityPending = new WeakMap();
    this.sessionManager = new SessionManager(this, sessionLauncher);
  }
  async init() {
    await this.store.init();
    await this.importLegacy();
    for (const job of this.store.loadJobs()) {
      const run = this.store.getRun(job.caseId, job.id);
      job.session = null;
      if (run.status === 'running') {
        if (job.sessionInfo)
          job.sessionInfo = {
            ...job.sessionInfo,
            status: 'failed',
            collecting: false,
            reason:
              'Server stopped; last checkpoint recovered. Authentication context was not persisted.',
          };
        job.status = 'interrupted';
        job.message = 'Capture terputus saat server berhenti; data terakhir dipertahankan.';
        job.warnings.push(job.message);
        this.store.seal(job, job.message);
      }
      if (!isOfflineMode(run.mode))
        this.jobs.set(job.id, job);
    }
  }
  async importLegacy() {
    for (const name of (await readdir(this.directory)).filter((x) => /^[0-9a-f-]{36}$/.test(x))) {
      if (this.store.db.prepare('SELECT id FROM runs WHERE id=?').get(name)) continue;
      try {
        const folder = path.join(this.directory, name);
        if (!(await lstat(folder)).isDirectory()) continue;
        const reportPath = path.join(folder, 'report.json');
        const info = await lstat(reportPath);
        if (!info.isFile() || info.size > LIMITS.artifactBytes)
          throw new Error('File report tidak valid atau melebihi batas.');
        const bytes = await readFile(reportPath),
          old = JSON.parse(bytes);
        if (old.id !== name || !Array.isArray(old.pages) || !Array.isArray(old.requests))
          throw new Error('Struktur laporan lama tidak valid.');
        const origin = new URL(old.url).origin;
        if (old.pages.length > LIMITS.artifacts - 3)
          throw new Error('Jumlah halaman legacy melebihi batas impor.');
        let importedBytes = bytes.length;
        const screenshots = [];
        for (const page of old.pages) {
          if (!page.screenshot) continue;
          const file = page.screenshot.split('/').at(-1);
          if (!/^p-[a-f0-9-]+-\d+\.png$/.test(file)) continue;
          try {
            const location = path.join(folder, file),
              st = await lstat(location);
            if (!st.isFile() || st.size > LIMITS.artifactBytes)
              throw new Error('Screenshot tidak valid/terlalu besar.');
            importedBytes += st.size;
            if (importedBytes > LIMITS.runBytes) throw new Error('Batas ukuran impor tercapai.');
            screenshots.push({ page, file, bytes: await readFile(location) });
          } catch {
            screenshots.push({ page, file, error: true });
          }
        }
        this.store.transaction(() => {
          const c = this.store.createCase({
            title: `Legacy · ${new URL(old.url).hostname}`,
            objective: 'Impor laporan lama. Integritas sebelum impor tidak dapat diverifikasi.',
            operator: 'Local operator (legacy import)',
            navigation: [origin],
            notes:
              'Folder laporan lama tetap utuh sebagai sumber pemulihan. Sumber lama dapat masih berisi screenshot plaintext.',
          });
          this.store.createRun(c.id, {
            id: name,
            mode: 'legacy-import',
            url: old.url,
            legacy: true,
            config: { claimedCreatedAt: old.createdAt, reportedStatus: old.status },
          });
          const original = this.store.addArtifact(c.id, name, bytes, {
            kind: 'legacy-report',
            role: 'original-imported',
            label: 'Laporan lama (sudah tersensor pada collector lama)',
            source: `legacy://${name}/report.json`,
            mimeType: 'application/json',
            method: 'local-file-import',
            claimedSourceTime: old.createdAt,
            redaction: 'Pre-existing redaction; not raw evidence. Baseline begins at import.',
          });
          const job = {
            ...old,
            caseId: c.id,
            mode: 'legacy-import',
            legacy: true,
            session: null,
            warnings: [...(old.warnings || [])],
            events: old.events || [],
            edges: old.edges || [],
          };
          for (const item of screenshots) {
            const page = job.pages.find((p) => p.id === item.page.id);
            page.screenshot = null;
            if (item.error) {
              job.warnings.push(`Screenshot lama tidak tersedia: ${item.file}`);
              continue;
            }
            const a = this.store.addArtifact(c.id, name, item.bytes, {
              kind: 'screenshot',
              role: 'original-imported',
              label: item.file,
              source: `legacy://${name}/${item.file}`,
              mimeType: 'image/png',
              claimedSourceTime: page.capturedAt,
            });
            page.screenshotArtifactId = a.id;
            page.screenshot = `/api/cases/${c.id}/runs/${name}/artifacts/${a.id}/content`;
          }
          this.store.observe(c.id, name, original.id, {
            type: 'legacy-import',
            pointer: '/',
            evidence:
              'Imported report claims; historical timestamps and collection not independently verified',
          });
          const partial = !['complete'].includes(old.status) || screenshots.some((s) => s.error);
          if (partial) job.status = 'interrupted';
          this.store.seal(
            job,
            partial ? 'Laporan lama tidak lengkap atau sebagian screenshot tidak tersedia.' : null,
          );
        });
      } catch (error) {
        this.migrationWarnings.push(`${name}: ${error.message}`);
      }
    }
  }
  async persist(job) {
    this.store.saveJob(job);
  }
  async finish(job, reason = null) {
    this.store.saveJob(job);
    return this.store.seal(job, reason);
  }
  list() {
    return [...this.jobs.values()]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(({ id, caseId, mode, legacy, url, status, createdAt, pages, message }) => ({
        id,
        caseId,
        mode,
        legacy: !!legacy,
        url,
        status,
        createdAt,
        pageCount: pages.length,
        message,
      }));
  }
  async create({ url, caseId, maxPages = 4, allowLocal = false }) {
    if (this.runners.size || this.sessions.size || this.sessionOpening)
      throw Object.assign(new Error('Selesaikan atau hentikan audit/sesi yang sedang berjalan.'), {
        status: 409,
      });
    const destination = await validateDestination(url, allowLocal === true);
    if (this.runners.size || this.sessions.size || this.sessionOpening)
      throw fail('Masih ada audit/sesi aktif.', 409);
    const c = caseId
      ? this.store.getCase(caseId)
      : this.store.createCase({
          title: `Audit · ${destination.hostname}`,
          objective: 'Audit URL langsung',
          operator: 'Local operator',
          navigation: [destination.origin],
        });
    const id = randomUUID();
    this.store.createRun(c.id, {
      id,
      url: destination.href,
      config: {
        maxPages: Math.min(10, Math.max(1, Number(maxPages) || 4)),
        allowLocal: allowLocal === true,
      },
    });
    const job = {
      id,
      caseId: c.id,
      mode: 'passive',
      url: displayUrl(destination.href),
      createdAt: new Date().toISOString(),
      status: 'queued',
      maxPages: Math.min(10, Math.max(1, Number(maxPages) || 4)),
      allowLocal: allowLocal === true,
      pages: [],
      requests: [],
      events: [],
      edges: [],
      warnings: [],
      message: 'Menyiapkan browser…',
      session: null,
    };
    this.jobs.set(id, job);
    const runner = { cancelled: false, browser: null };
    this.runners.set(id, runner);
    await this.persist(job);
    runner.task = this.run(job, destination.href, runner)
      .catch(async (error) => {
        job.status = runner.cancelled ? 'cancelled' : 'failed';
        job.message = cleanStack(error.message);
        job.warnings.push(job.message);
        await this.finish(job, job.message).catch(() => {});
      })
      .finally(() => this.runners.delete(id));
    return job;
  }
  async instrument(context, job, mode, controls = {}) {
    const scope = this.store.getRun(job.caseId, job.id).scope.navigation;
    const pageIds = new WeakMap();
    const initiators = new WeakMap();
    const recentEvents = new WeakMap();
    const requests = new WeakMap();
    const checked = new Map();
    const catalog = new SourceCatalog();
    this.sourceCatalogs.set(job, catalog);
    const epochs = new WeakMap(),
      frameIds = new WeakMap();
    const frameId = (frame) => {
      if (!frameIds.has(frame)) frameIds.set(frame, `f-${randomUUID()}`);
      return frameIds.get(frame);
    };
    const metadata = (page) => ({
      frameId: frameId(page.mainFrame()),
      documentEpoch: epochs.get(page) || 0,
    });
    const warn = (text) => {
      if (job.warnings.length < 50 && !job.warnings.includes(text)) job.warnings.push(text);
    };
    const policyReason = (request) =>
      controls.routeReason
        ? controls.routeReason(request)
        : request.isNavigationRequest() && !inScope(request.url(), scope)
          ? 'Tujuan di luar scope navigasi kasus.'
          : null;
    const ensureRedirectGuard = redirectGuard(
      context,
      async ({ page, source, url, status, request }) => {
        let reason = policyReason(request);
        if (!reason) {
          try {
            await validateDestination(url, job.allowLocal);
          } catch {
            reason = 'Tujuan redirect tidak diizinkan atau gagal di-resolve.';
          }
        }
        if (!reason && mode === 'passive' && !['GET', 'HEAD', 'OPTIONS'].includes(request.method()))
          reason = 'Redirect metode non-GET/HEAD/OPTIONS diblokir pada audit pasif.';
        if (
          request.isNavigationRequest() ||
          reason ||
          !controls.canObserve ||
          controls.canObserve(page)
        ) {
          job.redirects ||= [];
          if (job.redirects.length < 100)
            job.redirects.push({
              from: displayUrl(source),
              to: displayUrl(url),
              status,
              method: request.method(),
              at: new Date().toISOString(),
              outcome: reason ? 'blocked' : 'allowed',
              reason,
            });
          else warn('Batas 100 catatan redirect tercapai.');
        }
        if (reason) warn(reason);
        return reason;
      },
      () => warn('Pemeriksaan redirect gagal; respons dihentikan.'),
    );
    await context.exposeBinding('__wiReport', ({ page, frame }, payload) => {
      if (!payload || typeof payload !== 'object' || frame !== page.mainFrame()) return;
      if (controls.canObserve && !controls.canObserve(page)) return;
      const now = Date.now();
      if (payload.kind === 'event' && mode === 'record' && job.events.length >= LIMITS.events)
        warn('Batas 500 event tercapai; sebagian event tidak dicatat.');
      if (payload.kind === 'event' && mode === 'record' && job.events.length < 500) {
        const event = {
          id: String(payload.id || randomUUID()).slice(0, 80),
          pageId: pageIds.get(page) || null,
          pageUrl: displayUrl(page.url()),
          ...metadata(page),
          documentId: String(payload.documentId || '').slice(0, 80),
          domNodeId: String(payload.domNodeId || '').slice(0, 80),
          formNodeId: payload.formNodeId ? String(payload.formNodeId).slice(0, 80) : null,
          type: String(payload.event).slice(0, 30),
          selector: String(payload.selector).slice(0, 600),
          name: String(payload.name || '').slice(0, 120),
          formSelector: payload.formSelector ? String(payload.formSelector).slice(0, 600) : null,
          at: now,
        };
        job.events.push(event);
        recentEvents.set(page, event);
      }
      if (payload.kind === 'change') {
        job.changes ||= [];
        if (job.changes.length >= 300) {
          warn('Batas 300 batch perubahan DOM/SPA tercapai.');
          return;
        }
        job.changes.push({
          id: randomUUID(),
          ...metadata(page),
          documentId: String(payload.documentId || '').slice(0, 80),
          type: String(payload.type).slice(0, 60),
          at: now,
          url: payload.url ? displayUrl(String(payload.url)) : null,
          count: Number(payload.count) || 0,
          changes: Array.isArray(payload.changes)
            ? payload.changes.slice(0, 20).map((c) => ({
                domNodeId: String(c.domNodeId).slice(0, 80),
                selector: String(c.selector).slice(0, 600),
                type: String(c.type).slice(0, 40),
                attribute: c.attribute ? String(c.attribute).slice(0, 80) : null,
                added: Number(c.added) || 0,
                removed: Number(c.removed) || 0,
              }))
            : [],
        });
      }
      if (payload.kind === 'initiator') {
        let url;
        try {
          url = new URL(String(payload.url), frame.url()).href;
        } catch {
          return;
        }
        const recent = initiators.get(page) || [];
        recent.push({
          url: displayUrl(url),
          sourceKey: catalog.source(url).requestKey,
          documentId: String(payload.documentId || '').slice(0, 80),
          method: String(payload.method).slice(0, 20),
          transport: String(payload.transport).slice(0, 30),
          stack: cleanStack(payload.stack),
          eventId: typeof payload.eventId === 'string' ? payload.eventId.slice(0, 80) : null,
          at: now,
        });
        initiators.set(page, recent.slice(-50));
      }
    });
    await context.addInitScript(installObserver);
    await context.route('**/*', async (route) => {
      const request = route.request();
      try {
        const u = new URL(request.url());
        if (!['http:', 'https:'].includes(u.protocol)) return route.abort('blockedbyclient');
        const reason = policyReason(request);
        if (reason) {
          const item = requests.get(request);
          if (item) item.blocked = reason;
          warn(reason);
          return route.abort('blockedbyclient');
        }
        // DNS lookup is not socket pinning; this is still a local developer tool.
        const key = u.origin;
        if (!checked.has(key)) checked.set(key, validateDestination(u.href, job.allowLocal));
        await checked.get(key);
        if (mode === 'passive' && !['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
          const item = requests.get(request);
          if (item)
            item.blocked =
              'Kebijakan audit pasif memblokir metode selain GET/HEAD/OPTIONS; metode HTTP bukan bukti bebas efek samping.';
          return route.abort('blockedbyclient');
        }
        let page;
        try {
          page = request.frame().page();
        } catch {
          /* Initial popup has no initialized frame yet. */
        }
        if (!page || !ensureRedirectGuard.ready(page)) {
          // A popup's first request precedes Playwright's page/frame event. Do not allow
          // a redirect chain before its response-stage guard can be installed.
          let response;
          job.popupBootstrapRelay = true;
          try {
            response = await route.fetch({ maxRedirects: 0, timeout: 25000 });
            const location = response.headers().location;
            if ([301, 302, 303, 307, 308].includes(response.status()) && location) {
              const target = new URL(location, u.href).href;
              job.redirects ||= [];
              if (job.redirects.length < 100)
                job.redirects.push({
                  from: displayUrl(u.href),
                  to: displayUrl(target),
                  status: response.status(),
                  at: new Date().toISOString(),
                  outcome: 'blocked',
                  reason:
                    'Initial popup redirect blocked before frame initialization; open the intended URL in the audit tab manually.',
                });
              warn(
                'Redirect awal popup diblokir sebelum tab siap diperiksa. Buka URL tujuan yang disetujui pada tab audit secara manual.',
              );
              return await route.abort('blockedbyclient');
            }
            await route.fulfill({ response });
          } finally {
            await response?.dispose();
          }
          return;
        }
        await ensureRedirectGuard(page);
        await route.continue();
      } catch {
        const item = requests.get(request);
        if (item) item.blocked = 'Tujuan request tidak diizinkan atau gagal di-resolve.';
        warn('Sebagian resource diblokir oleh kebijakan alamat atau tidak dapat di-resolve.');
        await route.abort('blockedbyclient').catch(() => {});
      }
    });
    context.on('page', (page) => {
      ensureRedirectGuard(page).catch(() => {
        warn('Guard redirect tab gagal dipasang; tab ditutup.');
        page.close().catch(() => {});
      });
      if (context.pages().length > LIMITS.pages) {
        warn('Batas tab browser tercapai.');
        page.close().catch(() => {});
        return;
      }
      pageIds.set(page, `p-${randomUUID().slice(0, 8)}`);
      page.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));
      page.on('download', (download) => download.cancel().catch(() => {}));
      page.on('request', (request) => {
        let requestFrame;
        try {
          requestFrame = request.frame();
        } catch {}
        if (
          request.isNavigationRequest() &&
          requestFrame === page.mainFrame() &&
          !request.redirectedFrom()
        )
          epochs.set(page, (epochs.get(page) || 0) + 1);
        if (controls.canObserve && !controls.canObserve(page, request)) return;
        if (job.requests.length >= 1500) {
          warn('Batas 1500 request tercapai; sebagian request tidak dicatat.');
          return;
        }
        if (!/^https?:/.test(request.url())) return;
        if (request.isNavigationRequest() && requestFrame === page.mainFrame()) {
          const target = job.pages.find((p) => p.url === displayUrl(request.url()));
          pageIds.set(page, target?.id || `p-${randomUUID().slice(0, 8)}`);
        }
        const headers = request.headers();
        const event = recentEvents.get(page);
        const initiator = [...(initiators.get(page) || [])]
          .reverse()
          .find(
            (x) =>
              x.sourceKey === catalog.source(request.url()).requestKey &&
              x.method === request.method() &&
              Date.now() - x.at < 2000,
          );
        let body = null;
        try {
          body = request.postData();
        } catch {}
        const entry = {
          id: `r-${randomUUID().slice(0, 10)}`,
          pageId: pageIds.get(page),
          pageUrl: displayUrl(request.isNavigationRequest() ? request.url() : page.url()),
          url: displayUrl(request.url()),
          ...metadata(page),
          frameId: requestFrame ? frameId(requestFrame) : null,
          sourceKey: catalog.source(request.url()).requestKey,
          redirectedFromId: requests.get(request.redirectedFrom())?.id || null,
          method: request.method(),
          resourceType: request.resourceType(),
          navigation: request.isNavigationRequest(),
          mainFrame: requestFrame ? requestFrame === page.mainFrame() : null,
          documentUrl: requestFrame ? displayUrl(requestFrame.url()) : null,
          requestSecurity: requestSecurityMetadata(null),
          contentType: headers['content-type'] || null,
          queryParameters: [...new Set(new URL(request.url()).searchParams.keys())].slice(0, 100),
          body: summarizeBody(body, headers['content-type'] || ''),
          status: null,
          responseType: null,
          startedAt: Date.now(),
          duration: null,
          mode,
          initiator: initiator || null,
          event: mode === 'record' && event && Date.now() - event.at < 1500 ? { ...event } : null,
          evidence: 'Observed browser request',
          blocked: null,
        };
        entry.parameters = requestParameters(entry);
        entry.pathParameters = {
          status: 'unknown',
          reason: 'Literal URL path is not proof of a route parameter; no route schema acquired',
        };
        job.requests.push(entry);
        requests.set(request, entry);
        // request.headers() may omit security-related fields; query this one explicitly,
        // reduce it to presence immediately, and never retain its value or read cookie state.
        const pending = this.securityPending.get(job) || new Set();
        this.securityPending.set(job, pending);
        const headerTask = request
          .headerValue('authorization')
          .then((value) => {
            entry.requestSecurity = requestSecurityMetadata({ authorization: value });
          })
          .catch(() => {})
          .finally(() => pending.delete(headerTask));
        pending.add(headerTask);
      });
      page.on('response', (response) => {
        const entry = requests.get(response.request());
        if (entry) {
          entry.status = response.status();
          entry.responseType = response.headers()['content-type'] || null;
          entry.fromServiceWorker = response.fromServiceWorker();
          entry.timing = response.request().timing();
          entry.duration = Date.now() - entry.startedAt;
          entry.durationMeaning = 'until response headers; total timing pending requestfinished';
          entry.security = {
            version: 1,
            status: 'unavailable',
            reason: 'Header metadata pending at capture boundary',
          };
          const pending = this.securityPending.get(job) || new Set();
          this.securityPending.set(job, pending);
          const task = response
            .headersArray()
            .then((headers) => {
              entry.security = responseSecurityMetadata(headers);
            })
            .catch(() => {
              entry.security = {
                version: 1,
                status: 'unavailable',
                reason: 'Browser response headers unavailable',
              };
            })
            .finally(() => pending.delete(task));
          pending.add(task);
        }
      });
      page.on('requestfinished', (request) => {
        const entry = requests.get(request);
        if (entry) {
          entry.timing = request.timing();
          entry.duration = Date.now() - entry.startedAt;
          entry.durationMeaning =
            'collector elapsed until requestfinished; browser timing fields may be -1/unavailable';
        }
      });
      page.on('requestfailed', (request) => {
        const entry = requests.get(request);
        if (entry) {
          entry.failure = request.failure()?.errorText || 'Failed';
          entry.duration = Date.now() - entry.startedAt;
          if (job.mode === 'authenticated') warn(`Request gagal: ${entry.url} · ${entry.failure}`);
        }
      });
    });
    // Callers creating a page must await this before issuing its very first navigation.
    pageIds.prepare = ensureRedirectGuard;
    pageIds.metadata = metadata;
    return pageIds;
  }
  async snapshot(page, job, pageIds, mode, { guard } = {}) {
    const initialUrl = page.url();
    const check = () => {
      if (guard && (!guard(page.url()) || page.url() !== initialUrl))
        throw fail(
          'Halaman berubah atau akses tidak lagi siap selama capture; ulangi setelah konfirmasi.',
          409,
        );
    };
    check();
    const captureId = randomUUID();
    const observedAt = new Date().toISOString();
    const data = await page.evaluate(extractPage, { captureId });
    const rawVisuals = await page.evaluate(extractVisuals, { captureId });
    if (data.documentId !== rawVisuals.documentId)
      throw fail('Dokumen berubah selama ekstraksi; ulangi capture.', 409);
    const catalog = this.sourceCatalogs.get(job);
    data.visuals = sanitizeVisuals(rawVisuals, catalog);
    for (const owner of data.visuals.owners)
      if (!data.elements.some((el) => el.id === owner.id))
        data.elements.push({ ...owner, ordinal: data.elements.length + 1 });
    data.captureId = captureId;
    Object.assign(data, pageIds.metadata(page));
    for (const el of data.elements)
      Object.assign(el, {
        captureId,
        documentId: data.documentId,
        frameId: data.frameId,
        pageUrl: displayUrl(page.url()),
        observedAt,
        snapshot: captureId,
      });
    check();
    const rawUrl = data.url;
    const rawLinks = data.links.map((x) => ({ ...x }));
    data.url = displayUrl(data.url);
    for (const link of data.links) link.href = displayUrl(link.href);
    for (const form of data.forms) {
      form.action = displayUrl(form.action);
      form.declaredAction = form.declaredAction
        ? displayUrl(new URL(form.declaredAction, rawUrl).href)
        : null;
    }
    for (const el of data.elements) {
      if (el.href) el.href = displayUrl(el.href);
      if (el.form) {
        el.form.action = displayUrl(el.form.action);
        el.form.declaredAction = el.form.declaredAction
          ? displayUrl(new URL(el.form.declaredAction, rawUrl).href)
          : null;
      }
      for (const l of [...el.listeners, ...el.delegated])
        l.registration = cleanStack(l.registration);
    }
    const existing = job.pages.find((p) => p.url === data.url);
    if (!existing && job.pages.length >= job.maxPages)
      throw fail('Batas halaman capture tercapai.', 413);
    const currentId = pageIds.get(page);
    const id =
      existing?.id ||
      (currentId && !job.pages.some((p) => p.id === currentId)
        ? currentId
        : `p-${randomUUID().slice(0, 8)}`);
    pageIds.set(page, id);
    const screenshotName = `${id}-${Date.now()}.png`;
    let screenshotBytes;
    const height = Math.min(4000, Math.max(900, data.documentHeight));
    const snapshot = {
      ...data,
      id,
      capturedAt: new Date().toISOString(),
      mode,
      screenshot: null,
      screenshotWidth: data.viewport.width,
      screenshotHeight: height,
      screenshotClipped: data.documentHeight > 4000,
      warnings: [],
    };
    try {
      screenshotBytes = await page.screenshot({
        fullPage: true,
        scale: 'css',
        clip: { x: 0, y: 0, width: data.viewport.width, height },
        timeout: 12000,
        animations: 'disabled',
        ...(job.mode === 'authenticated'
          ? {
              mask: [
                page.locator(
                  'input[type="password"],input[autocomplete="current-password"],input[autocomplete="new-password"],input[autocomplete="one-time-code"]',
                ),
              ],
              maskColor: '#334155',
            }
          : {}),
      });
      check();
      if ((await page.evaluate(() => window.__wiObserver?.documentId)) !== data.documentId)
        throw fail('Dokumen berubah selama screenshot; ulangi capture.', 409);
      // PNG IHDR dimensions are the actual acquisition, not the requested clip size.
      snapshot.screenshotWidth = screenshotBytes.readUInt32BE(16);
      snapshot.screenshotHeight = screenshotBytes.readUInt32BE(20);
      snapshot.screenshotClipped = data.documentHeight > snapshot.screenshotHeight;
      const artifact = this.store.addArtifact(job.caseId, job.id, screenshotBytes, {
        kind: 'screenshot',
        role: job.mode === 'authenticated' ? 'redacted' : 'original',
        label: screenshotName,
        source: data.url,
        mimeType: 'image/png',
        method:
          'rendered-page-screenshot; animations disabled' +
          (job.mode === 'authenticated'
            ? '; recognized password/OTP controls masked at acquisition'
            : ''),
        ...(job.mode === 'authenticated'
          ? {
              redaction:
                'Password and OTP controls identified by type/autocomplete masked at acquisition. Unmasked original was not acquired. Other visible content may contain sensitive data.',
            }
          : {}),
      });
      snapshot.screenshotArtifactId = artifact.id;
      snapshot.screenshot = `/api/cases/${job.caseId}/runs/${job.id}/artifacts/${artifact.id}/content`;
    } catch (error) {
      check();
      if (error.message.startsWith('Dokumen berubah')) throw error;
      snapshot.warnings.push(
        `Screenshot tidak tersedia: ${cleanStack(error.message).slice(0, 180)}`,
      );
    }
    if (snapshot.iframeCount)
      snapshot.warnings.push(
        `${snapshot.iframeCount} iframe terdeteksi; isi iframe belum dipetakan.`,
      );
    if (snapshot.truncated)
      snapshot.warnings.push(
        `Ditampilkan 250 dari ${snapshot.totalElements} elemen interaktif yang terlihat.`,
      );
    if (snapshot.screenshotClipped)
      snapshot.warnings.push(
        'Screenshot dibatasi 4000px; elemen di luar gambar tetap tersedia di daftar.',
      );
    const extraction = this.store.addArtifact(
      job.caseId,
      job.id,
      JSON.stringify(snapshot, null, 2),
      {
        kind: 'page-extraction',
        role: 'extracted',
        label: `DOM · ${data.title || data.url}`,
        source: data.url,
        mimeType: 'application/json',
        method: 'selected-DOM-extraction',
        redaction: PRIVACY,
      },
    );
    snapshot.extractionArtifactId = extraction.id;
    // Bounded wait; unresolved headers remain explicitly unavailable in the frozen artifact.
    let metadataTimer;
    await Promise.race([
      Promise.allSettled([...(this.securityPending.get(job) || [])]),
      new Promise((resolve) => {
        metadataTimer = setTimeout(resolve, 2000);
      }),
    ]);
    clearTimeout(metadataTimer);
    const observations = {
      captureId,
      documentId: data.documentId,
      frameId: data.frameId,
      documentEpoch: data.documentEpoch,
      requests: job.requests.filter(
        (r) => r.frameId === data.frameId && r.documentEpoch === data.documentEpoch,
      ),
      events: job.events.filter(
        (e) => e.documentId === data.documentId && e.frameId === data.frameId,
      ),
      changes: (job.changes || []).filter(
        (e) => e.documentId === data.documentId && e.frameId === data.frameId,
      ),
      limitations: [
        'Only this main-frame document epoch; earlier uncollected requests absent',
        'Parameter values, raw payloads, cookie values and authorization state omitted; selected policy/cookie attributes and Authorization presence only',
        'Event/request matching by time and URL is correlation only',
      ],
    };
    const observationArtifact = this.store.addArtifact(
      job.caseId,
      job.id,
      JSON.stringify(observations),
      {
        kind: 'capture-observations',
        role: 'extracted',
        label: `Browser metadata · ${captureId}`,
        source: data.url,
        mimeType: 'application/json',
        method: 'bounded-browser-event-and-request-metadata',
        redaction: PRIVACY,
      },
    );
    const wiring = buildWiring({
      caseId: job.caseId,
      runId: job.id,
      snapshot,
      observations,
      extractionId: extraction.id,
      observationsId: observationArtifact.id,
    });
    const wiringArtifact = this.store.addArtifact(job.caseId, job.id, JSON.stringify(wiring), {
      kind: 'wiring-graph',
      role: 'extracted',
      label: `Wiring · ${captureId}`,
      source: data.url,
      mimeType: 'application/json',
      method: 'evidence-referenced-DOM-asset-request-graph',
      redaction: PRIVACY,
      derivedFrom: [extraction.id, observationArtifact.id],
    });
    snapshot.wiring = {
      artifactId: wiringArtifact.id,
      captureId,
      assets: wiring.assets.length,
      nodes: wiring.nodes.length,
      edges: wiring.edges.length,
    };
    snapshot.observationsArtifactId = observationArtifact.id;
    snapshot.warnings.push(...data.visuals.gaps);
    this.store.observe(job.caseId, job.id, wiringArtifact.id, {
      type: 'capture-wiring',
      pointer: '/',
      captureId,
      extractionArtifactId: extraction.id,
      observationsArtifactId: observationArtifact.id,
    });
    this.store.observe(job.caseId, job.id, extraction.id, {
      type: 'page-snapshot',
      pointer: '/',
      url: data.url,
      screenshotArtifactId: snapshot.screenshotArtifactId || null,
      evidence:
        'Selected rendered DOM; screenshot is a sibling acquisition, not the source of DOM extraction',
    });
    if (existing) job.pages[job.pages.indexOf(existing)] = snapshot;
    else job.pages.push(snapshot);
    for (const link of data.links) {
      if (!/^https?:/.test(link.href)) continue;
      if (
        !job.edges.some((e) => e.from === data.url && e.to === link.href) &&
        job.edges.length < 1000
      )
        job.edges.push({
          from: data.url,
          to: link.href,
          label: link.label || 'Link',
          evidence: 'DOM href',
        });
    }
    return { snapshot, rawLinks, rawUrl };
  }
  async run(job, initialUrl, runner) {
    let browser;
    let outcome = 'failed';
    const scope = this.store.getRun(job.caseId, job.id).scope.navigation;
    const checkpoint = setInterval(
      () =>
        this.persist(job).catch((e) => {
          if (!job.warnings.includes(e.message)) job.warnings.push(e.message);
        }),
      5000,
    );
    const timer = setTimeout(() => {
      runner.cancelled = true;
      runner.reason = 'Batas waktu audit 3 menit tercapai.';
      job.warnings.push(runner.reason);
      browser?.close().catch(() => {});
    }, LIMITS.runMs);
    try {
      job.status = 'running';
      job.message = 'Membuka halaman pertama…';
      browser = await launchBrowser(true);
      runner.browser = browser;
      if (runner.cancelled) return;
      const context = await browser.newContext({
        viewport: { width: 1365, height: 900 },
        serviceWorkers: 'block',
        acceptDownloads: false,
        reducedMotion: 'reduce',
      });
      const pageIds = await this.instrument(context, job, 'passive');
      const queue = [initialUrl],
        visited = new Set();
      let crawlOrigin = new URL(initialUrl).origin;
      while (queue.length && visited.size < job.maxPages && !runner.cancelled) {
        const next = queue.shift();
        if (visited.has(next)) continue;
        visited.add(next);
        const page = await context.newPage();
        await pageIds.prepare(page);
        job.message = `Memindai ${visited.size}/${job.maxPages}: ${displayUrl(next)}`;
        try {
          const response = await page.goto(next, { waitUntil: 'domcontentloaded', timeout: 25000 });
          await page.waitForLoadState('networkidle', { timeout: 3500 }).catch(() => {});
          await page.waitForTimeout(700);
          const result = await this.snapshot(page, job, pageIds, 'passive');
          result.snapshot.httpStatus = response?.status() || null;
          if (job.pages.length === 1) crawlOrigin = new URL(result.rawUrl).origin;
          if (response && response.status() >= 400)
            result.snapshot.warnings.push(`Halaman merespons HTTP ${response.status()}.`);
          for (const link of result.rawLinks) {
            if (
              queue.length < 100 &&
              crawlable(link.href, crawlOrigin) &&
              inScope(link.href, scope)
            ) {
              const u = new URL(link.href);
              u.hash = '';
              if (!visited.has(u.href) && !queue.includes(u.href)) queue.push(u.href);
            }
          }
          await this.persist(job);
        } catch (error) {
          if (!runner.cancelled)
            job.warnings.push(`${displayUrl(next)}: ${cleanStack(error.message.split('\n')[0])}`);
        } finally {
          await page.close().catch(() => {});
        }
      }
      outcome = runner.cancelled ? 'cancelled' : job.pages.length ? 'complete' : 'failed';
      job.message = runner.cancelled
        ? 'Audit dihentikan.'
        : job.pages.length
          ? `${job.pages.length} halaman berhasil dipetakan.`
          : 'Halaman tidak dapat dibuka. Periksa URL, koneksi, atau pembatasan situs.';
    } catch (error) {
      job.warnings.push(cleanStack(error.message));
      job.message = cleanStack(error.message);
    } finally {
      clearTimeout(timer);
      clearInterval(checkpoint);
      await browser?.close().catch(() => {});
      this.runners.delete(job.id);
      job.status = runner.cancelled ? 'cancelled' : outcome;
      const partial =
        runner.reason ||
        (job.status !== 'complete'
          ? `Audit ${job.status}; hanya data yang sudah dikumpulkan dipertahankan.`
          : job.warnings.length ||
              job.pages.some((p) =>
                p.warnings.some((w) => w.startsWith('Screenshot tidak tersedia')),
              )
            ? 'Sebagian sumber gagal, diblokir, atau tidak tercakup; lihat catatan manifest.'
            : null);
      await this.finish(job, partial);
    }
  }
  async cancel(id) {
    if (this.sessions.has(id))
      return this.stopSession(id, 'Sesi dihentikan melalui pembatalan run.');
    const runner = this.runners.get(id);
    const job = this.jobs.get(id);
    if (runner) {
      runner.cancelled = true;
      runner.reason = 'Audit dihentikan operator.';
      await runner.browser?.close().catch(() => {});
    }
    if (job && ['queued', 'running'].includes(job.status)) {
      job.status = 'cancelled';
      job.message = 'Audit dihentikan.';
      await this.persist(job);
    }
  }
  async startSession(id, pageId, options = {}) {
    const source = this.jobs.get(id);
    if (!source) throw fail('Audit tidak ditemukan.', 404);
    const target = source.pages.find((p) => p.id === pageId) || source.pages[0];
    if (!target) throw fail('Belum ada halaman yang bisa direkam.');
    const url = new URL(target.url);
    url.search = '';
    url.hash = '';
    return this.sessionManager.open({
      ...options,
      caseId: source.caseId,
      url: url.href,
      parentRunId: source.id,
      allowLocal: source.allowLocal,
      maxPages: 10,
    });
  }
  async captureSession(id, options = {}) {
    return this.sessionManager.capture(id, options);
  }
  async stopSession(id, reason = null) {
    return this.sessionManager.stop(id, reason ? 'failed' : 'closed', reason);
  }

  async close() {
    const tasks = [...this.runners.values()].map((r) => r.task).filter(Boolean);
    await Promise.allSettled(
      [...this.runners.keys()]
        .map((id) => this.cancel(id))
        .concat(
          [...this.sessions.keys()].map((id) =>
            this.stopSession(id, 'Server dihentikan; capture terakhir dipertahankan.'),
          ),
        ),
    );
    await Promise.allSettled(tasks);
  }
}
