import { chromium } from 'playwright';
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { installObserver, extractPage } from './browser-scripts.mjs';
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
  constructor(directory) {
    this.directory = directory;
    this.jobs = new Map();
    this.runners = new Map();
    this.sessions = new Map();
  }
  async init() {
    await mkdir(this.directory, { recursive: true });
    for (const name of (await readdir(this.directory))
      .filter((x) => /^[\da-f-]{36}$/.test(x))
      .slice(-50)) {
      try {
        const job = JSON.parse(
          await readFile(path.join(this.directory, name, 'report.json'), 'utf8'),
        );
        if (['queued', 'running'].includes(job.status)) {
          job.status = 'interrupted';
          job.message = 'Server berhenti sebelum audit selesai. Jalankan audit baru.';
        }
        job.session = null;
        this.jobs.set(job.id, job);
      } catch {
        /* A partially written report is not usable. */
      }
    }
  }
  async persist(job) {
    await writeFile(path.join(this.directory, job.id, 'report.json'), JSON.stringify(job, null, 2));
  }
  list() {
    return [...this.jobs.values()]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(({ id, url, status, createdAt, pages, message }) => ({
        id,
        url,
        status,
        createdAt,
        pageCount: pages.length,
        message,
      }));
  }
  async create({ url, maxPages = 4, allowLocal = false }) {
    if (this.runners.size || this.sessions.size)
      throw Object.assign(new Error('Selesaikan atau hentikan audit/sesi yang sedang berjalan.'), {
        status: 409,
      });
    const destination = await validateDestination(url, allowLocal === true);
    const id = randomUUID();
    const job = {
      id,
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
    await mkdir(path.join(this.directory, id), { recursive: true });
    this.jobs.set(id, job);
    const runner = { cancelled: false, browser: null };
    this.runners.set(id, runner);
    await this.persist(job);
    this.run(job, destination.href, runner)
      .catch(async (error) => {
        job.status = runner.cancelled ? 'cancelled' : 'failed';
        job.message = error.message;
        await this.persist(job).catch(() => {});
      })
      .finally(() => this.runners.delete(id));
    return job;
  }
  async instrument(context, job, mode) {
    const pageIds = new WeakMap();
    const initiators = new WeakMap();
    const recentEvents = new WeakMap();
    const requests = new WeakMap();
    const checked = new Map();
    const warn = (text) => {
      if (job.warnings.length < 50 && !job.warnings.includes(text)) job.warnings.push(text);
    };
    await context.exposeBinding('__wiReport', ({ page, frame }, payload) => {
      if (!payload || typeof payload !== 'object' || frame !== page.mainFrame()) return;
      const now = Date.now();
      if (payload.kind === 'event' && mode === 'record' && job.events.length < 500) {
        const event = {
          id: String(payload.id || randomUUID()).slice(0, 80),
          pageId: pageIds.get(page) || null,
          pageUrl: displayUrl(page.url()),
          type: String(payload.event).slice(0, 30),
          selector: String(payload.selector).slice(0, 600),
          name: String(payload.name || '').slice(0, 120),
          formSelector: payload.formSelector ? String(payload.formSelector).slice(0, 600) : null,
          at: now,
        };
        job.events.push(event);
        recentEvents.set(page, event);
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
        // Cache only within this isolated run; never allow private address ranges.
        const key = u.origin;
        if (!checked.has(key)) checked.set(key, validateDestination(u.href, job.allowLocal));
        await checked.get(key);
        if (mode === 'passive' && !['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
          const item = requests.get(request);
          if (item) item.blocked = 'Scan pasif: request yang dapat mengubah data tidak dikirim.';
          return route.abort('blockedbyclient');
        }
        await route.continue();
      } catch {
        const item = requests.get(request);
        if (item) item.blocked = 'Tujuan request tidak diizinkan atau gagal di-resolve.';
        warn('Sebagian resource diblokir oleh kebijakan alamat atau tidak dapat di-resolve.');
        await route.abort('blockedbyclient').catch(() => {});
      }
    });
    context.on('page', (page) => {
      pageIds.set(page, `p-${randomUUID().slice(0, 8)}`);
      page.on('dialog', (dialog) => dialog.dismiss().catch(() => {}));
      page.on('download', (download) => download.cancel().catch(() => {}));
      page.on('request', (request) => {
        if (job.requests.length >= 1500) {
          warn('Batas 1500 request tercapai; sebagian request tidak dicatat.');
          return;
        }
        if (!/^https?:/.test(request.url())) return;
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
          const target = job.pages.find((p) => p.url === displayUrl(request.url()));
          pageIds.set(page, target?.id || `p-${randomUUID().slice(0, 8)}`);
        }
        const headers = request.headers();
        const event = recentEvents.get(page);
        const initiator = [...(initiators.get(page) || [])]
          .reverse()
          .find(
            (x) =>
              x.url === displayUrl(request.url()) &&
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
          method: request.method(),
          resourceType: request.resourceType(),
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
        job.requests.push(entry);
        requests.set(request, entry);
      });
      page.on('response', (response) => {
        const entry = requests.get(response.request());
        if (entry) {
          entry.status = response.status();
          entry.responseType = response.headers()['content-type'] || null;
          entry.duration = Date.now() - entry.startedAt;
        }
      });
      page.on('requestfailed', (request) => {
        const entry = requests.get(request);
        if (entry) {
          entry.failure = request.failure()?.errorText || 'Failed';
          entry.duration = Date.now() - entry.startedAt;
        }
      });
    });
    return pageIds;
  }
  async snapshot(page, job, pageIds, mode) {
    const data = await page.evaluate(extractPage);
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
    const currentId = pageIds.get(page);
    const id =
      existing?.id ||
      (currentId && !job.pages.some((p) => p.id === currentId)
        ? currentId
        : `p-${randomUUID().slice(0, 8)}`);
    pageIds.set(page, id);
    const screenshotName = `${id}-${Date.now()}.png`;
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
      await page.screenshot({
        path: path.join(this.directory, job.id, screenshotName),
        clip: { x: 0, y: 0, width: data.viewport.width, height },
        timeout: 12000,
        animations: 'disabled',
      });
      snapshot.screenshot = `/api/audits/${job.id}/images/${screenshotName}`;
    } catch {
      snapshot.warnings.push('Screenshot tidak tersedia; elemen masih dapat di-inspect.');
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
            if (queue.length < 100 && crawlable(link.href, crawlOrigin)) {
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
    } finally {
      await browser?.close().catch(() => {});
      this.runners.delete(job.id);
      job.status = runner.cancelled ? 'cancelled' : outcome;
      await this.persist(job);
    }
  }
  async cancel(id) {
    const runner = this.runners.get(id);
    const job = this.jobs.get(id);
    if (runner) {
      runner.cancelled = true;
      await runner.browser?.close().catch(() => {});
    }
    if (job && ['queued', 'running'].includes(job.status)) {
      job.status = 'cancelled';
      job.message = 'Audit dihentikan.';
      await this.persist(job);
    }
  }
  async startSession(id, pageId) {
    const job = this.jobs.get(id);
    if (!job) throw Object.assign(new Error('Audit tidak ditemukan.'), { status: 404 });
    if (this.sessions.size || this.runners.size)
      throw Object.assign(new Error('Masih ada audit atau sesi aktif.'), { status: 409 });
    const target = job.pages.find((p) => p.id === pageId) || job.pages[0];
    if (!target) throw new Error('Belum ada halaman yang bisa direkam.');
    // Query values were redacted in reports; recordings start on the route without them.
    const url = new URL(target.url);
    url.search = '';
    url.hash = '';
    await validateDestination(url.href, job.allowLocal);
    let browser;
    try {
      browser = await launchBrowser(false);
      const context = await browser.newContext({
        viewport: { width: 1365, height: 900 },
        serviceWorkers: 'block',
        acceptDownloads: false,
      });
      const pageIds = await this.instrument(context, job, 'record');
      const page = await context.newPage();
      pageIds.set(page, target.id);
      const session = { browser, context, page, pageIds, timer: null, capturing: false };
      this.sessions.set(id, session);
      job.session = {
        status: 'opening',
        startedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 600000).toISOString(),
      };
      await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout: 25000 });
      await page.waitForTimeout(600);
      await this.snapshot(page, job, pageIds, 'record');
      job.session.status = 'recording';
      session.timer = setTimeout(() => this.stopSession(id).catch(() => {}), 600000);
      browser.on('disconnected', () => {
        if (this.sessions.has(id)) {
          clearTimeout(session.timer);
          this.sessions.delete(id);
          job.session = null;
          this.persist(job).catch(() => {});
        }
      });
      await this.persist(job);
      return job;
    } catch (error) {
      this.sessions.delete(id);
      job.session = null;
      await browser?.close().catch(() => {});
      throw error;
    }
  }
  async captureSession(id) {
    const session = this.sessions.get(id),
      job = this.jobs.get(id);
    if (!session) throw new Error('Sesi rekam belum aktif.');
    if (session.capturing) return job;
    session.capturing = true;
    try {
      const pages = session.context.pages().filter((p) => !p.isClosed());
      const page = pages.at(-1);
      if (!page) throw new Error('Browser rekam sudah ditutup.');
      await this.snapshot(page, job, session.pageIds, 'record');
      await this.persist(job);
      return job;
    } finally {
      session.capturing = false;
    }
  }
  async stopSession(id) {
    const session = this.sessions.get(id),
      job = this.jobs.get(id);
    if (!session) return;
    clearTimeout(session.timer);
    await this.captureSession(id).catch(() => {});
    this.sessions.delete(id);
    job.session = null;
    await session.browser.close().catch(() => {});
    await this.persist(job);
  }
  async close() {
    await Promise.allSettled(
      [...this.runners.keys()]
        .map((id) => this.cancel(id))
        .concat([...this.sessions.keys()].map((id) => this.stopSession(id))),
    );
  }
}
