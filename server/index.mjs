import express from 'express';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { AuditManager } from './audit.mjs';

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
const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
app.get('/api/health', (req, res) =>
  res.json({
    ok: true,
    name: 'Web Intelligent',
    version: '1.1.0',
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
  res.type(artifact.mimeType).send(content);
});
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
  const job = manager.jobs.get(req.params.id);
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
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));

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
