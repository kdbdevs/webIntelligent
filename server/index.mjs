import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { AuditManager } from './audit.mjs';
import { createAuthFixture } from './auth-fixture.mjs';
import { createWiringFixture } from './wiring-fixture.mjs';
import { SecurityService } from './security.mjs';
import { createSecurityFixture } from './security-fixture.mjs';
import { ReportService } from './reporting.mjs';
import { compareCaptures } from './capture-comparison.mjs';
import { exportReport } from './report-export.mjs';
import { AnalysisAssistant } from './analysis-assistant.mjs';
import { loadRecord } from './report-common.mjs';
import { readFile } from 'node:fs/promises';
import { ForensicService } from './forensics.mjs';
import { FORENSIC_LIMITS } from './forensic-parsers.mjs';

process.umask(0o077);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.PORT || 8787);
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (!allowedHosts.has(req.headers.host))
    return res.status(403).json({ error: 'Host tidak diizinkan.' });
  if (req.path.startsWith('/api/')) {
    const origin = req.headers.origin;
    if (
      origin &&
      ![`http://127.0.0.1:${port}`, `http://localhost:${port}`, `http://[::1]:${port}`].includes(
        origin,
      )
    )
      return res.status(403).json({ error: 'API hanya menerima request dari app lokal.' });
    if (req.headers['sec-fetch-site'] === 'cross-site')
      return res.status(403).json({ error: 'Cross-site request diblokir.' });
    res.set('Cache-Control', 'no-store');
  }
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.json({ limit: '16kb' }));
const manager = new AuditManager(process.env.DATA_DIR || path.join(root, '.data'));
await manager.init();
const security = new SecurityService(manager.store);
const forensics = new ForensicService(manager.store);
const reports = new ReportService(manager.store);
const assistant = new AnalysisAssistant(manager.store);
const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
app.get('/api/health', (req, res) =>
  res.json({
    ok: true,
    name: 'Web Intelligent',
    version: '1.6.0',
    migrationWarnings: manager.migrationWarnings,
  }),
);
app.get('/api/cases', (req, res) => res.json(manager.store.listCases()));
app.post('/api/cases', (req, res) =>
  res.status(201).json(manager.store.createCase(req.body || {})),
);
app.get('/api/cases/:caseId', (req, res) => res.json(manager.store.getCase(req.params.caseId)));
app.patch('/api/cases/:caseId', (req, res) =>
  res.json(manager.store.updateCase(req.params.caseId, req.body || {})),
);
app.get('/api/cases/:caseId/runs', (req, res) =>
  res.json(manager.store.listRuns(req.params.caseId)),
);
app.get('/api/cases/:caseId/custody', (req, res) =>
  res.json({
    events: manager.store.events(req.params.caseId),
    chainVerified: manager.store.custodyIntegrity(req.params.caseId),
  }),
);
app.post(
  '/api/cases/:caseId/forensics/import',
  (req, res, next) => {
    manager.store.getCase(req.params.caseId);
    const timer = setTimeout(() => {
      forensics.reject(req.params.caseId, 'Upload timeout');
      req.destroy();
    }, 10000);
    res.once('close', () => clearTimeout(timer));
    express.raw({
      type: 'application/octet-stream',
      limit: FORENSIC_LIMITS.inputBytes,
      inflate: false,
    })(req, res, (error) => {
      clearTimeout(timer);
      if (error) {
        forensics.reject(req.params.caseId, error.type || 'Upload rejected');
        return next(error);
      }
      next();
    });
  },
  asyncRoute(async (req, res) => {
    let options;
    try {
      const header = req.get('X-WI-Import-Options') || '{}';
      options = JSON.parse(header.startsWith('{') ? header : decodeURIComponent(header));
    } catch {
      forensics.reject(req.params.caseId, 'Invalid import options');
      return res.status(400).json({ error: 'Header opsi impor tidak valid.' });
    }
    res.status(201).json(await forensics.import(req.params.caseId, req.body, options));
  }),
);
app.get('/api/cases/:caseId/forensics', (req, res) =>
  res.json(
    forensics.view(req.params.caseId, { sourceId: req.query.source, version: req.query.version }),
  ),
);
app.post(
  '/api/cases/:caseId/forensics/captures/:runId',
  asyncRoute(async (req, res) =>
    res.status(201).json(await forensics.addCapture(req.params.caseId, req.params.runId)),
  ),
);
app.post(
  '/api/cases/:caseId/forensics/sources/:sourceId/reparse',
  asyncRoute(async (req, res) =>
    res
      .status(201)
      .json(await forensics.reparse(req.params.caseId, req.params.sourceId, req.body || {})),
  ),
);
app.get('/api/cases/:caseId/forensics/sources/:sourceId/preview', (req, res) =>
  res.json(forensics.preview(req.params.caseId, req.params.sourceId, req.query.version)),
);
app.post('/api/cases/:caseId/forensics/operations', (req, res) =>
  res.status(201).json(forensics.operation(req.params.caseId, req.body || {})),
);
app.post('/api/cases/:caseId/forensics/share', (req, res) =>
  res.status(201).json(forensics.share(req.params.caseId, req.body || {})),
);
app.get('/api/cases/:caseId/runs/:runId/security/assessments', (req, res) =>
  res.json(security.list(req.params.caseId, req.params.runId)),
);
app.post('/api/cases/:caseId/runs/:runId/security/assessments', (req, res) =>
  res.status(201).json(security.assess(req.params.caseId, req.params.runId, req.body || {})),
);
app.get('/api/cases/:caseId/security/assessments/:id', (req, res) =>
  res.json(security.get(req.params.caseId, req.params.id)),
);
app.post('/api/cases/:caseId/security/assessments/:id/findings/:findingId/reviews', (req, res) =>
  res
    .status(201)
    .json(security.review(req.params.caseId, req.params.id, req.params.findingId, req.body || {})),
);
app.post('/api/cases/:caseId/security/assessments/:id/manual-tests', (req, res) =>
  res.status(201).json(security.plan(req.params.caseId, req.params.id, req.body || {})),
);
app.post('/api/cases/:caseId/security/assessments/:id/manual-tests/:testId/results', (req, res) =>
  res
    .status(201)
    .json(security.testResult(req.params.caseId, req.params.id, req.params.testId, req.body || {})),
);
app.get('/api/cases/:caseId/security/assessments/:id/export', (req, res) =>
  res
    .attachment(`security-${req.params.id}.json`)
    .json(security.export(req.params.caseId, req.params.id)),
);
app.get('/api/cases/:caseId/runs/:runId', (req, res) => {
  const { caseId, runId } = req.params;
  res.json({
    run: manager.store.getRun(caseId, runId),
    artifacts: manager.store.artifacts(caseId, runId),
    observations: manager.store.observations(caseId, runId),
    events: manager.store.events(caseId, runId),
  });
});
app.post('/api/cases/:caseId/runs/:runId/verify', (req, res) =>
  res.json(manager.store.verifyRun(req.params.caseId, req.params.runId)),
);
app.get('/api/cases/:caseId/runs/:runId/manifest', (req, res) => {
  const manifest = manager.store.exportManifest(req.params.caseId, req.params.runId);
  res.attachment(`manifest-${req.params.runId}.json`).json(manifest);
});
app.get('/api/cases/:caseId/runs/:runId/artifacts/:artifactId', (req, res) => {
  const { caseId, runId, artifactId } = req.params;
  const artifact = manager.store.artifact(caseId, runId, artifactId);
  manager.store.readArtifact(caseId, runId, artifactId);
  res.json({ artifact, verification: { ok: true, checkedAt: new Date().toISOString() } });
});
app.get('/api/cases/:caseId/runs/:runId/artifacts/:artifactId/content', (req, res) => {
  const { caseId, runId, artifactId } = req.params;
  const artifact = manager.store.artifact(caseId, runId, artifactId);
  const content = manager.store.readArtifact(caseId, runId, artifactId);
  res.set('Content-Security-Policy', "default-src 'none'; sandbox");
  if (artifact.kind === 'forensic-original')
    return res
      .attachment(`original-${artifact.id}.bin`)
      .type('application/octet-stream')
      .send(content);
  res.type(artifact.mimeType).send(content);
});
app.get('/api/cases/:caseId/reporting', (req, res) => res.json(reports.catalog(req.params.caseId)));
app.post('/api/cases/:caseId/reports', (req, res) =>
  res.status(201).json(reports.build(req.params.caseId, req.body)),
);
app.get('/api/cases/:caseId/reports/:id', (req, res) =>
  res.json(reports.get(req.params.caseId, req.params.id)),
);
app.post('/api/cases/:caseId/reports/:id/finalize', (req, res) =>
  res.status(201).json(reports.finalize(req.params.caseId, req.params.id, req.body)),
);
app.post(
  '/api/cases/:caseId/reports/:id/export',
  asyncRoute(async (req, res) =>
    res.json(await exportReport(manager.store, req.params.caseId, req.params.id, req.body)),
  ),
);
app.post('/api/cases/:caseId/reporting/evidence', (req, res) =>
  res.json(reports.evidence(req.params.caseId, req.body)),
);
app.post('/api/cases/:caseId/comparisons', (req, res) =>
  res.status(201).json(compareCaptures(manager.store, req.params.caseId, req.body)),
);
app.get('/api/cases/:caseId/comparisons/:id', (req, res) =>
  res.json(loadRecord(manager.store, req.params.caseId, req.params.id, 'capture-comparison')),
);
app.get('/api/assistant/config', (req, res) => res.json(assistant.configView()));
app.post('/api/cases/:caseId/reports/:id/assistant/local', (req, res) =>
  res.json(assistant.local(req.params.caseId, req.params.id, req.body)),
);
app.post('/api/cases/:caseId/reports/:id/assistant/prepare', (req, res) =>
  res.json(assistant.prepare(req.params.caseId, req.params.id, req.body)),
);
app.post(
  '/api/cases/:caseId/assistant/plans/:id/execute',
  asyncRoute(async (req, res) =>
    res.json(await assistant.execute(req.params.caseId, req.params.id, req.body)),
  ),
);
app.get(
  '/api/report-verifier',
  asyncRoute(async (req, res) => {
    res
      .set('Content-Disposition', 'attachment; filename="verify-package.mjs"')
      .type('text/plain')
      .send(await readFile(new URL('../tools/verify-package.mjs', import.meta.url), 'utf8'));
  }),
);
app.get('/api/audits', (req, res) => {
  if (req.query.caseId) manager.store.getCase(req.query.caseId);
  res.json(manager.list().filter((job) => !req.query.caseId || job.caseId === req.query.caseId));
});
app.post(
  '/api/audits',
  asyncRoute(async (req, res) => {
    const job = await manager.create(req.body || {});
    res.status(202).json(job);
  }),
);
app.get('/api/audits/:id', (req, res) => {
  const job = manager.sessionManager.refresh(req.params.id);
  if (!job) return res.status(404).json({ error: 'Audit tidak ditemukan.' });
  res.json(job);
});
app.get('/api/audits/:id/export', (req, res) => {
  const job = manager.jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Audit tidak ditemukan.' });
  const run = manager.store.getRun(job.caseId, job.id);
  if (run.status === 'running')
    return res.status(409).json({ error: 'Selesaikan capture sebelum ekspor.' });
  const verification = manager.store.verifyRun(job.caseId, job.id);
  if (!verification.ok)
    return res.status(409).json({ error: 'Ekspor diblokir: integritas bukti gagal.' });
  const bytes = manager.store.readArtifact(job.caseId, job.id, run.reportArtifactId);
  manager.store.event(
    job.caseId,
    job.id,
    'report.exported',
    manager.store.getCase(job.caseId).operator,
    { artifactId: run.reportArtifactId },
  );
  res.attachment(`webintelligent-${job.id}.json`).type('json').send(bytes);
});
app.get('/api/audits/:id/images/:file', (req, res) => {
  const job = manager.jobs.get(req.params.id);
  if (!job || !/^p-[a-f0-9-]+-\d+\.png$/.test(req.params.file)) return res.sendStatus(404);
  const artifact = manager.store
    .artifacts(job.caseId, job.id)
    .find((a) => a.kind === 'screenshot' && a.label === req.params.file);
  if (!artifact) return res.sendStatus(404);
  res.type('png').send(manager.store.readArtifact(job.caseId, job.id, artifact.id));
});
app.post(
  '/api/audits/:id/cancel',
  asyncRoute(async (req, res) => {
    await manager.cancel(req.params.id);
    res.json({ ok: true });
  }),
);
app.post(
  '/api/audits/:id/record',
  asyncRoute(async (req, res) => {
    res.json(await manager.startSession(req.params.id, req.body.pageId));
  }),
);
app.post(
  '/api/audits/:id/capture',
  asyncRoute(async (req, res) => {
    res.json(await manager.captureSession(req.params.id));
  }),
);
app.post(
  '/api/audits/:id/stop-recording',
  asyncRoute(async (req, res) => {
    await manager.stopSession(req.params.id);
    res.json(manager.jobs.get(req.params.id));
  }),
);
app.post(
  '/api/sessions',
  asyncRoute(async (req, res) =>
    res.status(202).json(await manager.sessionManager.open(req.body || {})),
  ),
);
app.get('/api/sessions/:id', (req, res) => {
  const job = manager.sessionManager.refresh(req.params.id);
  if (!job || job.mode !== 'authenticated')
    return res.status(404).json({ error: 'Sesi tidak ditemukan.' });
  res.json(job);
});
for (const action of ['ready', 'pause', 'extend', 'auth-lost', 'select', 'capture', 'close']) {
  app.post(
    `/api/sessions/:id/${action}`,
    asyncRoute(async (req, res) => {
      const id = req.params.id,
        sessions = manager.sessionManager;
      const result =
        action === 'select'
          ? sessions.select(id, req.body?.tabId)
          : action === 'capture'
            ? await sessions.capture(id, req.body || {})
            : action === 'close'
              ? await sessions.stop(id)
              : action === 'auth-lost'
                ? sessions.markExpired(id)
                : sessions[action](id);
      res.json(result);
    }),
  );
}
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));

if (process.env.ENABLE_AUTH_FIXTURE === '1') app.use('/auth-fixture', createAuthFixture());
if (process.env.ENABLE_WIRING_FIXTURE === '1') app.use('/wiring-fixture', createWiringFixture());
if (process.env.ENABLE_SECURITY_FIXTURE === '1')
  app.use('/security-fixture', createSecurityFixture());

// A deliberately local fixture to try navigation and real POST recording without an account.
app.get('/demo/api/status', (req, res) => res.json({ available: true }));
app.post('/demo/api/login', (req, res) => {
  if (typeof req.body.email !== 'string' || typeof req.body.password !== 'string')
    return res.status(422).json({ error: 'Email dan password wajib diisi.' });
  if (req.body.email === 'demo@example.com' && req.body.password === 'demo')
    return res.json({ ok: true, redirect: '/demo/dashboard' });
  res.status(401).json({ error: 'Gunakan demo@example.com dan password demo.' });
});
app.get(
  [
    '/demo',
    '/demo/',
    '/demo/register',
    '/demo/forgot-password',
    '/demo/dashboard',
    '/demo/projects/1',
    '/demo/settings',
  ],
  (req, res) => res.sendFile(path.join(root, 'public/demo.html')),
);
app.use(express.static(path.join(root, 'public')));
const server = http.createServer(app);
if (process.env.NODE_ENV === 'development') {
  const { createServer } = await import('vite');
  const vite = await createServer({
    root,
    server: {
      middlewareMode: true,
      hmr: { server },
      fs: {
        strict: true,
        allow: [root],
        deny: [
          '.env',
          '.env.*',
          '*.{crt,pem,key}',
          '**/.git/**',
          '**/.data*/**',
          '**/evidence.sqlite*',
          path.join(manager.directory, '**'),
          path.join(manager.store.keyDirectory, '**'),
        ],
      },
    },
    appType: 'spa',
  });
  app.use(vite.middlewares);
} else {
  app.use(express.static(path.join(root, 'dist')));
  app.get('/', (req, res) => {
    const file = path.join(root, 'dist/index.html');
    if (!existsSync(file))
      return res.status(503).send('Build belum tersedia. Jalankan npm run build, lalu npm start.');
    res.sendFile(file);
  });
}
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  res
    .status(error.status || (error instanceof TypeError ? 400 : 400))
    .json({ error: error.message || 'Request gagal.' });
});
server.listen(port, '127.0.0.1', () =>
  console.log(`Web Intelligent ready: http://127.0.0.1:${port}`),
);
server.on('error', (error) => {
  console.error(
    error.code === 'EADDRINUSE'
      ? `Port ${port} sudah dipakai. Jalankan PORT=8788 npm start.`
      : error.message,
  );
  process.exitCode = 1;
});
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, async () => {
    if (closing) return;
    closing = true;
    await manager.close();
    server.close(() => {
      manager.store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 3000).unref();
  });

// Internal handles for isolated end-to-end tests; no browser-control HTTP endpoint.
export { app, server, manager };
