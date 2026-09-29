import { chromium } from 'playwright';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { installObserver, extractPage } from './browser-scripts.mjs';
import { EvidenceStore, LIMITS, PRIVACY, inScope, fail } from './evidence.mjs';
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
    this.store = new EvidenceStore(directory);
    this.migrationWarnings = [];
    this.jobs = new Map();
    this.runners = new Map();
    this.sessions = new Map();
    this.sessionOpening = false;
  }
  async init() {
    await this.store.init();
    await this.importLegacy();
    for (const job of this.store.loadJobs()) {
      const run = this.store.getRun(job.caseId, job.id);
      job.session = null;
      if (run.status === 'running') {
        job.status = 'interrupted';
        job.message = 'Capture terputus saat server berhenti; data terakhir dipertahankan.';
        job.warnings.push(job.message);
        this.store.seal(job, job.message);
      }
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
  async instrument(context, job, mode) {
    const scope = this.store.getRun(job.caseId, job.id).scope.navigation;
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
      if (payload.kind === 'event' && mode === 'record' && job.events.length >= LIMITS.events)
        warn('Batas 500 event tercapai; sebagian event tidak dicatat.');
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
        if (
          request.isNavigationRequest() &&
          request.frame() === request.frame().page().mainFrame() &&
          !inScope(u.href, scope)
        ) {
          const item = requests.get(request);
          if (item) item.blocked = 'Tujuan di luar scope navigasi kasus.';
          warn(
            'Navigasi di luar scope kasus diblokir. Domain resource hanya dicatat sebagai dependensi.',
          );
          return route.abort('blockedbyclient');
        }
        // DNS lookup is not socket pinning; this is still a local developer tool.
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
      if (context.pages().length > LIMITS.pages) {
        warn('Batas tab browser tercapai.');
        page.close().catch(() => {});
        return;
      }
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
        clip: { x: 0, y: 0, width: data.viewport.width, height },
        timeout: 12000,
        animations: 'disabled',
      });
      const artifact = this.store.addArtifact(job.caseId, job.id, screenshotBytes, {
        kind: 'screenshot',
        role: 'original',
        label: screenshotName,
        source: data.url,
        mimeType: 'image/png',
        method: 'rendered-page-screenshot; animations disabled',
      });
      snapshot.screenshotArtifactId = artifact.id;
      snapshot.screenshot = `/api/cases/${job.caseId}/runs/${job.id}/artifacts/${artifact.id}/content`;
    } catch (error) {
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
  async startSession(id, pageId) {
    const sourceJob = this.jobs.get(id);
    if (!sourceJob) throw Object.assign(new Error('Audit tidak ditemukan.'), { status: 404 });
    if (this.sessions.size || this.runners.size || this.sessionOpening)
      throw Object.assign(new Error('Masih ada audit atau sesi aktif.'), { status: 409 });
    const target = sourceJob.pages.find((p) => p.id === pageId) || sourceJob.pages[0];
    if (!target) throw new Error('Belum ada halaman yang bisa direkam.');
    // Query values were redacted in reports; recordings start on the route without them.
    const url = new URL(target.url);
    url.search = '';
    url.hash = '';
    await validateDestination(url.href, sourceJob.allowLocal);
    if (this.sessions.size || this.runners.size || this.sessionOpening)
      throw fail('Masih ada audit/sesi aktif.', 409);
    const run = this.store.createRun(sourceJob.caseId, {
      mode: 'record',
      url: url.href,
      parentRunId: sourceJob.id,
      config: { allowLocal: sourceJob.allowLocal, maxPages: 10 },
    });
    id = run.id;
    const job = {
      id,
      caseId: sourceJob.caseId,
      mode: 'record',
      url: displayUrl(url.href),
      createdAt: run.started.at,
      status: 'running',
      maxPages: 10,
      allowLocal: sourceJob.allowLocal,
      pages: [],
      requests: [],
      events: [],
      edges: [],
      warnings: [],
      message: 'Sesi rekam aktif.',
      session: null,
    };
    this.jobs.set(id, job);
    let browser;
    this.sessionOpening = true;
    try {
      await this.persist(job);
      browser = await launchBrowser(false);
      const context = await browser.newContext({
        viewport: { width: 1365, height: 900 },
        serviceWorkers: 'block',
        acceptDownloads: false,
      });
      const pageIds = await this.instrument(context, job, 'record');
      const page = await context.newPage();
      pageIds.set(page, target.id);
      const session = {
        browser,
        context,
        page,
        pageIds,
        timer: null,
        checkpoint: null,
        captureTask: null,
      };
      session.checkpoint = setInterval(() => this.persist(job).catch(() => {}), 5000);
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
      session.timer = setTimeout(
        () => this.stopSession(id, 'Batas waktu sesi rekam 10 menit tercapai.').catch(() => {}),
        LIMITS.recordMs,
      );
      browser.on('disconnected', () => {
        if (this.sessions.has(id)) {
          clearTimeout(session.timer);
          clearInterval(session.checkpoint);
          this.sessions.delete(id);
          job.session = null;
          job.status = 'interrupted';
          this.finish(job, 'Browser ditutup sebelum sesi diselesaikan.').catch(() => {});
        }
      });
      await this.persist(job);
      return job;
    } catch (error) {
      clearInterval(this.sessions.get(id)?.checkpoint);
      clearTimeout(this.sessions.get(id)?.timer);
      this.sessions.delete(id);
      job.session = null;
      await browser?.close().catch(() => {});
      job.status = 'failed';
      job.message = cleanStack(error.message);
      await this.finish(job, job.message);
      throw error;
    } finally {
      this.sessionOpening = false;
    }
  }
  async captureSession(id) {
    const session = this.sessions.get(id),
      job = this.jobs.get(id);
    if (!session) throw new Error('Sesi rekam belum aktif.');
    if (session.captureTask) return session.captureTask;
    session.captureTask = (async () => {
      try {
        const page = session.context
          .pages()
          .filter((p) => !p.isClosed())
          .at(-1);
        if (!page) throw new Error('Browser rekam sudah ditutup.');
        await this.snapshot(page, job, session.pageIds, 'record');
        await this.persist(job);
        return job;
      } catch (error) {
        const warning = `Capture sesi gagal: ${cleanStack(error.message)}`;
        if (!job.warnings.includes(warning)) job.warnings.push(warning);
        await this.persist(job);
        throw error;
      } finally {
        session.captureTask = null;
      }
    })();
    return session.captureTask;
  }
  async stopSession(id, reason = null) {
    const session = this.sessions.get(id),
      job = this.jobs.get(id);
    if (!session) return;
    if (session.stopTask) return session.stopTask;
    session.stopTask = (async () => {
      clearTimeout(session.timer);
      clearInterval(session.checkpoint);
      await this.captureSession(id).catch(() => {});
      this.sessions.delete(id);
      job.session = null;
      await session.browser.close().catch(() => {});
      job.status = 'complete';
      job.message = `${job.pages.length} halaman sesi rekam tersimpan.`;
      await this.finish(
        job,
        reason || (job.warnings.length ? 'Sesi memiliki batas/kegagalan; lihat manifest.' : null),
      );
    })();
    return session.stopTask;
  }

  async close() {
    const tasks = [...this.runners.values()].map((r) => r.task).filter(Boolean);
    await Promise.allSettled(
      [...this.runners.keys()]
        .map((id) => this.cancel(id))
        .concat([...this.sessions.keys()].map((id) => this.stopSession(id))),
    );
    await Promise.allSettled(tasks);
  }
}
