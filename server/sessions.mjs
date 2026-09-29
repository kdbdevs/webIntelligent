import { randomUUID } from 'node:crypto';
import { normalizeUrl, validateDestination, displayUrl, cleanStack } from './safety.mjs';
import { LIMITS, fail, inScope, stamp } from './evidence.mjs';
import {
  SESSION_POLICY,
  readRules,
  selectedTargets,
  crawlRequestReason,
} from './session-policy.mjs';

const terminal = new Set(['closed', 'expired', 'failed']);
export class SessionManager {
  constructor(manager, launch) {
    this.manager = manager;
    this.launchBrowser = launch;
    this.active = manager.sessions;
  }
  get(id) {
    const s = this.active.get(id);
    if (!s) throw fail('Sesi sudah ditutup atau tidak ditemukan.', 404);
    return s;
  }
  warn(s, message) {
    if (!s.job.warnings.includes(message) && s.job.warnings.length < 100)
      s.job.warnings.push(message);
  }
  state(s, status, reason = null) {
    if (s.status === status && !reason) return;
    s.status = status;
    s.job.message =
      reason ||
      {
        opening: 'Membuka browser audit…',
        'awaiting-login': 'Login/MFA manual. Isi halaman belum dikumpulkan.',
        ready: 'Halaman dinyatakan siap oleh pengguna; pilih mulai capture.',
        capturing: 'Mengumpulkan bukti dalam sesi browser yang sama.',
        closed: 'Sesi ditutup; state login dibuang.',
        expired: 'Sesi berakhir karena timeout.',
        failed: 'Browser/sesi gagal.',
      }[status];
    this.manager.store.event(s.job.caseId, s.job.id, 'session.state', s.operator, {
      status,
      reason,
    });
    this.refresh(s.job.id);
    this.manager.store.saveJob(s.job);
  }
  tabs(s) {
    return [...s.tabs.entries()]
      .filter(([, p]) => !p.isClosed())
      .map(([id, page]) => ({
        id,
        url: displayUrl(page.url()),
        inScope: inScope(page.url(), s.scope),
        loginPage: this.isLogin(s, page.url()),
        selected: id === s.selectedTabId,
      }));
  }
  refresh(id) {
    const s = this.active.get(id);
    if (!s) return this.manager.jobs.get(id);
    const summary = {
      id,
      status: s.status,
      tabs: this.tabs(s),
      selectedTabId: s.selectedTabId,
      collecting: s.collecting,
      observeLogin: s.observeLogin,
      timeoutMinutes: s.timeoutMinutes,
      expiresAt: new Date(s.deadline).toISOString(),
      remainingSeconds: Math.max(0, Math.ceil((s.deadline - Date.now()) / 1000)),
      timeoutWarning: s.deadline - Date.now() <= 60000,
      readiness: s.readiness,
      authSignal: s.authSignal,
      loginOrigins: s.loginOrigins,
      loginUrl: s.loginUrl ? displayUrl(s.loginUrl) : null,
      policy: SESSION_POLICY,
      readRules: s.readRules,
      history: s.history,
      operations: s.operations,
      retainedAuthentication: false,
    };
    s.job.session = summary;
    s.job.sessionInfo = summary;
    return s.job;
  }
  isLogin(s, value) {
    if (!s.loginUrl) return false;
    try {
      const a = new URL(value),
        b = new URL(s.loginUrl);
      return a.origin === b.origin && a.pathname === b.pathname;
    } catch {
      return false;
    }
  }
  recordable(s, page, request = null) {
    if (!s.collecting || s.stopping || page.isClosed()) return false;
    const url = request?.isNavigationRequest() ? request.url() : page.url();
    if (s.observeLogin && !s.readiness && !s.automatic)
      return s.loginOrigins.includes(new URL(url).origin) || inScope(url, s.scope);
    return (
      !!s.readiness && s.observedPages.has(page) && inScope(url, s.scope) && !this.isLogin(s, url)
    );
  }
  navigation(s, url, outcome, reason = null) {
    if (s.history.length >= 100) {
      this.warn(s, 'Riwayat navigasi sesi dibatasi 100 entri.');
      return;
    }
    s.history.push({
      at: new Date().toISOString(),
      url: displayUrl(url),
      inScope: inScope(url, s.scope),
      outcome,
      reason,
    });
  }
  routeReason(s, request) {
    const url = request.url();
    if (request.isNavigationRequest()) {
      const scoped = inScope(url, s.scope);
      const loginAllowed = !s.automatic && s.loginOrigins.includes(new URL(url).origin);
      if (!scoped && !loginAllowed) {
        this.navigation(s, url, 'blocked', 'Outside navigation scope and declared login origins');
        return 'Navigasi di luar scope/login origin yang dinyatakan diblokir.';
      }
      if (!scoped)
        this.navigation(
          s,
          url,
          'login-navigation',
          'Transient login origin; not added to crawl scope',
        );
    }
    return s.automatic ? crawlRequestReason(request, s.readRules) : null;
  }
  signal(s, type, url, detail) {
    if (s.stopping || !s.readiness) return;
    s.authSignal = {
      type,
      url: displayUrl(url),
      at: new Date().toISOString(),
      detail,
      certainty: 'indicator-only; user must inspect the browser',
    };
    s.readiness = null;
    s.collecting = false;
    this.warn(s, `Pengumpulan dijeda: ${detail}`);
    this.state(
      s,
      'awaiting-login',
      `${detail} Periksa browser, login bila perlu, lalu konfirmasi halaman siap lagi.`,
    );
  }
  attach(s, page) {
    if (s.stopping) {
      page.close().catch(() => {});
      return;
    }
    const id = `tab-${randomUUID()}`;
    s.tabs.set(id, page);
    if (!s.selectedTabId) s.selectedTabId = id;
    page.on('framenavigated', (frame) => {
      if (frame !== page.mainFrame() || s.stopping) return;
      const url = page.url();
      if (!/^https?:/.test(url)) return;
      this.navigation(s, url, 'visited');
      if (this.isLogin(s, url))
        this.signal(
          s,
          'configured-login-route',
          url,
          'Browser kembali ke URL login yang dikonfigurasi; ini indikasi, bukan pembuktian universal logout.',
        );
      else if (!inScope(url, s.scope) && id === s.selectedTabId)
        this.signal(s, 'outside-capture-scope', url, 'Tab terpilih keluar dari scope capture.');
    });
    page.on('response', (response) => {
      if (!s.readiness || s.stopping) return;
      const request = response.request();
      if (
        response.status() === 401 &&
        (request.isNavigationRequest() || ['fetch', 'xhr'].includes(request.resourceType()))
      ) {
        const selected = s.tabs.get(s.selectedTabId);
        try {
          if (selected && new URL(response.url()).origin === new URL(selected.url()).origin)
            this.signal(
              s,
              'http-401',
              response.url(),
              'HTTP 401 teramati pada origin halaman terpilih; akses perlu diperiksa.',
            );
        } catch {}
      }
    });
    page.on('close', () => {
      s.tabs.delete(id);
      s.observedPages.delete(page);
      if (s.stopping) return;
      if (id === s.selectedTabId) {
        s.selectedTabId = null;
        s.readiness = null;
        s.collecting = false;
        this.state(
          s,
          'awaiting-login',
          'Tab terpilih ditutup. Pilih tab lain dan konfirmasi ulang.',
        );
      }
      if (s.context?.pages().length === 0)
        this.stop(s.job.id, 'failed', 'Semua tab browser ditutup.').catch(() => {});
    });
  }
  async open({
    caseId,
    url,
    allowLocal = false,
    timeoutMinutes = 15,
    observeLogin = false,
    loginOrigins = [],
    loginUrl = null,
    maxPages = 4,
    parentRunId = null,
  } = {}) {
    if (this.active.size || this.manager.runners.size || this.manager.sessionOpening)
      throw fail('Masih ada audit/sesi aktif.', 409);
    const c = this.manager.store.getCase(caseId);
    const destination = await validateDestination(url, allowLocal === true);
    if (!inScope(destination.href, c.scope.navigation)) throw fail('URL awal di luar scope kasus.');
    if (this.active.size || this.manager.runners.size || this.manager.sessionOpening)
      throw fail('Masih ada audit/sesi aktif.', 409);
    if (!Number.isInteger(timeoutMinutes) || timeoutMinutes < 1 || timeoutMinutes > 120)
      throw fail('Timeout harus 1–120 menit.');
    if (!Array.isArray(loginOrigins) || loginOrigins.length > 10)
      throw fail('Maksimal 10 origin login tambahan.');
    const origins = [
      ...new Set([destination.origin, ...loginOrigins.map((u) => normalizeUrl(u).origin)]),
    ];
    const login = loginUrl ? normalizeUrl(loginUrl).href : null;
    if (login && !origins.includes(new URL(login).origin))
      throw fail('URL login harus berada di origin login yang dinyatakan.');
    const count = Math.min(10, Math.max(1, Math.floor(Number(maxPages) || 4)));
    const run = this.manager.store.createRun(caseId, {
      mode: 'authenticated',
      url: destination.href,
      parentRunId,
      config: {
        allowLocal: allowLocal === true,
        maxPages: count,
        timeoutMinutes,
        observeLogin: observeLogin === true,
        loginOrigins: origins,
        loginUrl: login ? displayUrl(login) : null,
        policy: SESSION_POLICY,
        persistence: 'ephemeral context only; no storageState export',
      },
    });
    const job = {
      id: run.id,
      caseId,
      mode: 'authenticated',
      url: displayUrl(destination.href),
      createdAt: run.started.at,
      status: 'running',
      maxPages: count,
      allowLocal: allowLocal === true,
      pages: [],
      requests: [],
      events: [],
      edges: [],
      warnings: [],
      message: 'Membuka browser audit…',
      session: null,
    };
    const s = {
      job,
      operator: run.operator,
      scope: run.scope.navigation,
      loginOrigins: origins,
      loginUrl: login,
      observeLogin: observeLogin === true,
      collecting: observeLogin === true,
      status: 'opening',
      timeoutMinutes,
      deadline: Date.now() + timeoutMinutes * 60000,
      tabs: new Map(),
      selectedTabId: null,
      readiness: null,
      authSignal: null,
      readRules: [],
      observedPages: new Set(),
      history: [],
      operations: [],
      automatic: false,
      stopping: false,
      captureTask: null,
      openTask: null,
    };
    this.manager.jobs.set(job.id, job);
    this.active.set(job.id, s);
    this.state(s, 'opening', 'Membuka browser terpisah; sesi login harian tidak diambil.');
    s.openTask = this.launch(s, destination.href).catch(async (error) => {
      if (!s.stopping) {
        this.warn(s, cleanStack(error.message));
        await this.finalize(s, 'failed', 'Browser gagal dibuka atau URL awal tidak dapat dimuat.');
      }
    });
    s.timer = setInterval(() => this.tick(s).catch(() => {}), 1000);
    return job;
  }
  async launch(s, url) {
    s.browser = await this.launchBrowser(false);
    if (s.stopping) return;
    s.browser.on('disconnected', () => {
      if (!s.stopping)
        this.stop(s.job.id, 'failed', 'Browser audit ditutup di luar aplikasi.').catch(() => {});
    });
    s.context = await s.browser.newContext({
      viewport: { width: 1365, height: 900 },
      serviceWorkers: 'block',
      acceptDownloads: false,
    });
    if (s.stopping) return;
    s.pageIds = await this.manager.instrument(s.context, s.job, 'record', {
      canObserve: (page, request) => {
        try {
          return this.recordable(s, page, request);
        } catch {
          return false;
        }
      },
      routeReason: (request) => this.routeReason(s, request),
    });
    s.context.on('page', (page) => this.attach(s, page));
    const page = await s.context.newPage();
    s.page = page;
    await s.pageIds.prepare(page);
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    if (s.stopping) return;
    this.state(
      s,
      'awaiting-login',
      s.observeLogin
        ? 'Observasi login diaktifkan secara eksplisit; hanya metadata event/request, tanpa nilai kredensial.'
        : 'Login/MFA di browser. Belum mengumpulkan DOM, screenshot, event, atau request.',
    );
  }
  async tick(s) {
    if (s.stopping || terminal.has(s.status)) return;
    if (Date.now() >= s.deadline) {
      await this.stop(
        s.job.id,
        'expired',
        'Batas waktu sesi tercapai. Bukti yang sudah dikumpulkan dipertahankan.',
      );
      return;
    }
    this.refresh(s.job.id);
    if (!s.lastCheckpoint || Date.now() - s.lastCheckpoint >= 5000) {
      this.manager.store.saveJob(s.job);
      s.lastCheckpoint = Date.now();
    }
  }
  tab(s, id = s.selectedTabId) {
    const page = s.tabs.get(id);
    if (!page || page.isClosed()) throw fail('Tab tidak ditemukan atau sudah ditutup.', 409);
    return page;
  }
  available(s) {
    if (s.stopping || s.status === 'opening' || s.captureTask)
      throw fail('Tunggu operasi browser yang sedang berjalan.', 409);
  }
  select(id, tabId) {
    const s = this.get(id);
    this.available(s);
    this.tab(s, tabId);
    s.selectedTabId = tabId;
    s.readiness = null;
    s.collecting = false;
    s.observedPages.clear();
    this.state(s, 'awaiting-login', 'Tab dipilih. Periksa browser lalu tandai halaman siap.');
    return this.refresh(id);
  }
  ready(id) {
    const s = this.get(id);
    this.available(s);
    const page = this.tab(s);
    if (!inScope(page.url(), s.scope) || this.isLogin(s, page.url()))
      throw fail('Pilih halaman target dalam scope yang bukan URL login terkonfigurasi.');
    s.readiness = {
      basis: 'user-confirmed',
      at: new Date().toISOString(),
      tabId: s.selectedTabId,
      url: displayUrl(page.url()),
      note: 'User declares this page ready; no authentication conclusion inferred from HTTP 200.',
    };
    s.authSignal = null;
    s.collecting = false;
    s.observedPages = new Set([page]);
    this.manager.store.event(s.job.caseId, id, 'session.ready-declared', s.operator, s.readiness);
    this.state(s, 'ready', 'Halaman dinyatakan siap oleh pengguna; pilih mulai capture.');
    return this.refresh(id);
  }
  extend(id) {
    const s = this.get(id);
    if (s.stopping) throw fail('Sesi sedang ditutup.', 409);
    s.deadline = Date.now() + s.timeoutMinutes * 60000;
    this.manager.store.event(s.job.caseId, id, 'session.extended', s.operator, {
      timeoutMinutes: s.timeoutMinutes,
      expiresAt: new Date(s.deadline).toISOString(),
    });
    this.refresh(id);
    this.manager.store.saveJob(s.job);
    return s.job;
  }
  pause(id) {
    const s = this.get(id);
    this.available(s);
    s.collecting = false;
    this.state(
      s,
      s.readiness ? 'ready' : 'awaiting-login',
      'Pengumpulan dijeda. Browser tetap terbuka.',
    );
    return s.job;
  }
  markExpired(id) {
    const s = this.get(id);
    this.available(s);
    s.readiness = null;
    s.collecting = false;
    s.authSignal = {
      type: 'user-reported',
      at: new Date().toISOString(),
      detail: 'Pengguna melaporkan logout/sesi tidak berlaku.',
    };
    this.warn(s, 'Pengguna melaporkan kehilangan akses; pengumpulan dijeda.');
    this.state(
      s,
      'awaiting-login',
      'Login ulang di browser yang sama lalu konfirmasi halaman siap.',
    );
    return s.job;
  }
  async capture(id, { kind = 'snapshot', urls = [], readEndpoints = [], reload = false } = {}) {
    const s = this.get(id);
    this.available(s);
    if (!['snapshot', 'crawl'].includes(kind)) throw fail('Jenis capture tidak valid.');
    const page = this.tab(s);
    if (!s.readiness || !inScope(page.url(), s.scope) || this.isLogin(s, page.url()))
      throw fail('Konfirmasikan halaman siap sebelum capture.', 409);
    const rules = readRules(readEndpoints);
    const targets = kind === 'crawl' ? selectedTargets(urls, s.scope, s.job.maxPages - 1) : [];
    const currentUrl = page.url();
    if (kind === 'crawl') selectedTargets([currentUrl], s.scope, 1);
    if (s.operations.length >= 100) throw fail('Batas 100 operasi capture tercapai.', 413);
    s.readRules = rules;
    s.observedPages = new Set([page]);
    s.collecting = true;
    s.automatic = kind === 'crawl';
    const operation = {
      id: randomUUID(),
      kind,
      started: stamp(),
      selectedTabId: s.selectedTabId,
      targets: [displayUrl(currentUrl), ...targets.map(displayUrl)],
      reload: reload === true,
      policy: kind === 'crawl' ? SESSION_POLICY.crawl : SESSION_POLICY.manual,
      readRules: rules,
      status: 'running',
    };
    s.operations.push(operation);
    this.state(s, 'capturing');
    s.captureTask = (async () => {
      const deadline = Date.now() + LIMITS.runMs;
      let activePage = page;
      const guard = (url) =>
        !s.stopping &&
        !operation.timeout &&
        Date.now() < deadline &&
        !!s.readiness &&
        inScope(url, s.scope) &&
        !this.isLogin(s, url);
      const snapshot = async (p) => {
        if (!guard(p.url())) throw fail('Capture dihentikan: halaman/sesi tidak lagi siap.', 409);
        await this.manager.snapshot(p, s.job, s.pageIds, 'record', { guard });
        await this.manager.persist(s.job);
      };
      const timer = setTimeout(() => {
        operation.timeout = true;
        this.stop(
          id,
          'failed',
          'Batas waktu capture 3 menit tercapai; bukti sebelumnya dipertahankan.',
        ).catch(() => {});
      }, LIMITS.runMs);
      try {
        if (reload === true) await page.reload({ waitUntil: 'domcontentloaded', timeout: 25000 });
        await page.waitForTimeout(400);
        await snapshot(page);
        for (const url of targets) {
          if (!s.readiness || s.stopping || operation.timeout || Date.now() >= deadline)
            throw fail('Crawl terputus atau batas waktu tercapai.', 409);
          if (url === currentUrl) continue;
          activePage = await s.context.newPage();
          s.observedPages.add(activePage);
          try {
            await s.pageIds.prepare(activePage);
            await activePage.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
            await activePage.waitForLoadState('networkidle', { timeout: 2000 }).catch(() => {});
            await snapshot(activePage);
          } finally {
            s.observedPages.delete(activePage);
            await activePage.close().catch(() => {});
            activePage = page;
          }
        }
        operation.status = 'complete';
      } catch (error) {
        operation.status = 'partial';
        operation.error = cleanStack(error.message);
        this.warn(s, `Capture parsial: ${operation.error}`);
        throw error;
      } finally {
        clearTimeout(timer);
        operation.ended = stamp();
        s.automatic = false;
        s.captureTask = null;
        if (!s.stopping) {
          // Explicit capture leaves observation active for this selected tab until Pause/Close/auth signal.
          this.state(
            s,
            s.readiness ? 'ready' : 'awaiting-login',
            s.readiness
              ? 'Capture tersimpan. Observasi tab terpilih aktif; gunakan Jeda untuk berhenti mengumpulkan.'
              : 'Pengumpulan dijeda; periksa login dan konfirmasi ulang.',
          );
          this.refresh(id);
          await this.manager.persist(s.job);
        }
      }
      return s.job;
    })();
    return s.captureTask;
  }
  async finalize(s, status, reason = null) {
    if (s.finalized) return s.job;
    s.stopping = true;
    s.collecting = false;
    clearInterval(s.timer);
    const summary = this.refresh(s.job.id)?.sessionInfo || s.job.sessionInfo;
    await s.browser?.close().catch(() => {});
    s.status = status;
    s.finalized = true;
    s.job.sessionInfo = {
      ...summary,
      status,
      collecting: false,
      ended: stamp(),
      reason,
      retainedAuthentication: false,
    };
    s.job.session = null;
    s.job.status = reason ? (status === 'failed' ? 'failed' : 'interrupted') : 'complete';
    s.job.message =
      reason || `${s.job.pages.length} halaman tersimpan; browser dan state login ditutup.`;
    this.manager.store.event(s.job.caseId, s.job.id, 'session.closed', s.operator, {
      status,
      reason,
    });
    const partial =
      reason ||
      (!s.job.pages.length
        ? 'Sesi ditutup tanpa snapshot halaman.'
        : s.job.warnings.length ||
            s.job.pages.some((p) =>
              p.warnings.some((w) => w.startsWith('Screenshot tidak tersedia')),
            )
          ? 'Ada gap/kegagalan pengumpulan; lihat manifest.'
          : null);
    await this.manager.finish(s.job, partial);
    this.active.delete(s.job.id);
    return s.job;
  }
  async stop(id, status = 'closed', reason = null) {
    const s = this.active.get(id);
    if (!s) {
      const job = this.manager.jobs.get(id);
      if (!job) throw fail('Sesi tidak ditemukan.', 404);
      return job;
    }
    if (s.stopTask) return s.stopTask;
    s.stopping = true;
    s.collecting = false;
    clearInterval(s.timer);
    s.stopTask = (async () => {
      await s.browser?.close().catch(() => {});
      await s.openTask?.catch(() => {});
      await s.captureTask?.catch(() => {});
      return this.finalize(s, status, reason);
    })();
    return s.stopTask;
  }
}
