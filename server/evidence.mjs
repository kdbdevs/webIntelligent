import { DatabaseSync } from 'node:sqlite';
import { mkdir, readFile, writeFile, chmod, stat } from 'node:fs/promises';
import { randomUUID, randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import path from 'node:path';
import { normalizeUrl, displayUrl } from './safety.mjs';

export const COLLECTOR = { name: 'WebIntelligent', version: '1.6.0', schemaVersion: 1 };
export const OFFLINE_MODES = [
  'security-assessment',
  'security-review',
  'manual-validation',
  'forensic-import',
  'forensic-parse',
  'forensic-operation',
  'forensic-share',
  'case-report',
  'capture-comparison',
  'analysis-assistant',
  'report-export',
];
export const isOfflineMode = (mode) => OFFLINE_MODES.includes(mode);
export const LIMITS = {
  artifactBytes: 20 * 1024 * 1024,
  runBytes: 128 * 1024 * 1024,
  artifacts: 150,
  requests: 1500,
  elementsPerPage: 250,
  events: 500,
  pages: 10,
  screenshotHeight: 4000,
  runMs: 180000,
};
export const PRIVACY = {
  collected: [
    'rendered screenshots (may contain personal data)',
    'selected DOM labels/selectors',
    'request metadata and parameter names/types',
    'selected response policy summaries and Set-Cookie attributes (no values); Authorization presence only',
    'bounded visual source declarations, computed choices, CSS rule metadata and resource timings',
    'DOM mutation structure and SPA history events without changed values or state',
  ],
  omitted: [
    'input values',
    'raw request/response bodies',
    'cookie values',
    'Authorization header values',
    'browser storage',
    'asset bytes, data URL payloads and blob contents/creation state',
  ],
  redacted: ['URL query values', 'URL credentials', 'URL fragments'],
  note: 'Extracted reports are sanitized at acquisition, not raw network evidence. Visible text, URL paths and screenshots may still contain personal data.',
};
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const stamp = () => ({
  at: new Date().toISOString(),
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  offsetMinutes: -new Date().getTimezoneOffset(),
  clock: 'host clock; not independently attested',
});
export function fail(message, status = 400) {
  return Object.assign(new Error(message), { status });
}
export function validId(id) {
  if (typeof id !== 'string' || !uuid.test(id)) throw fail('ID tidak valid.', 404);
  return id;
}
function text(value, max, name, required = false) {
  if (typeof value !== 'string' || value.length > max || (required && !value.trim()))
    throw fail(`${name} tidak valid (maks. ${max} karakter).`);
  return value.trim();
}
export function navigationScope(entries) {
  if (!Array.isArray(entries) || !entries.length || entries.length > 30)
    throw fail('Isi 1–30 domain atau URL navigasi.');
  return [
    ...new Set(
      entries.map((item) => {
        text(item, 2048, 'Scope', true);
        const u = normalizeUrl(item);
        if (u.search)
          throw fail('Scope tidak boleh mengandung query/token. Gunakan domain atau path.');
        return u.origin + (u.pathname === '/' ? '/' : u.pathname.replace(/\/$/, ''));
      }),
    ),
  ];
}
export function inScope(value, entries) {
  try {
    const u = normalizeUrl(value);
    return entries.some((entry) => {
      const s = new URL(entry);
      return (
        u.origin === s.origin &&
        (s.pathname === '/' || u.pathname === s.pathname || u.pathname.startsWith(s.pathname + '/'))
      );
    });
  } catch {
    return false;
  }
}

export class EvidenceStore {
  constructor(
    directory,
    { keyDirectory = process.env.EVIDENCE_KEY_DIR || `${path.resolve(directory)}.keys` } = {},
  ) {
    this.directory = path.resolve(directory);
    this.keyDirectory = path.resolve(keyDirectory);
    if (
      this.keyDirectory === this.directory ||
      this.keyDirectory.startsWith(this.directory + path.sep)
    )
      throw fail('Direktori kunci harus berada di luar DATA_DIR.');
  }
  async init() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await mkdir(this.keyDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.keyDirectory, 0o700);
    const dbPath = path.join(this.directory, 'evidence.sqlite');
    const keyPath = path.join(this.keyDirectory, 'master.key');
    const hasDb = await stat(dbPath)
      .then((s) => s.size > 0)
      .catch(() => false);
    try {
      this.key = await readFile(keyPath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (hasDb)
        throw fail(
          'Kunci bukti hilang. Pulihkan master.key yang sesuai; jangan membuat kunci pengganti.',
          500,
        );
      this.key = randomBytes(32);
      await writeFile(keyPath, this.key, { flag: 'wx', mode: 0o600 });
    }
    if (this.key.length !== 32) throw fail('Kunci bukti tidak valid.', 500);
    await chmod(keyPath, 0o600);
    this.db = new DatabaseSync(dbPath);
    await chmod(dbPath, 0o600);
    this.db
      .exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), payload TEXT NOT NULL, report BLOB, UNIQUE(id,case_id));
      CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, run_id TEXT NOT NULL, payload TEXT NOT NULL, bytes BLOB NOT NULL, UNIQUE(id,run_id,case_id), FOREIGN KEY(run_id,case_id) REFERENCES runs(id,case_id));
      CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, run_id TEXT NOT NULL, artifact_id TEXT NOT NULL, payload TEXT NOT NULL, FOREIGN KEY(artifact_id,run_id,case_id) REFERENCES artifacts(id,run_id,case_id));
      CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES cases(id), run_id TEXT, payload TEXT NOT NULL, previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS artifact_run ON artifacts(run_id,case_id);
      CREATE INDEX IF NOT EXISTS events_case ON events(case_id,seq);
      CREATE INDEX IF NOT EXISTS observations_run ON observations(run_id,case_id);`);
    for (const table of ['artifacts', 'observations', 'events'])
      for (const action of ['UPDATE', 'DELETE'])
        this.db.exec(
          `CREATE TRIGGER IF NOT EXISTS immutable_${table}_${action} BEFORE ${action} ON ${table} BEGIN SELECT RAISE(ABORT,'Immutable evidence record'); END;`,
        );
    const fingerprint = digest(this.key);
    const stored = this.db.prepare('SELECT value FROM meta WHERE key=?').get('keyFingerprint');
    if (stored && stored.value !== fingerprint) {
      this.db.close();
      throw fail('Kunci tidak cocok dengan database bukti.', 500);
    }
    this.db.prepare('INSERT OR IGNORE INTO meta VALUES (?,?)').run('keyFingerprint', fingerprint);
    this.db.prepare('INSERT OR IGNORE INTO meta VALUES (?,?)').run('schemaVersion', '1');
    if (this.db.prepare('SELECT value FROM meta WHERE key=?').get('schemaVersion').value !== '1')
      throw fail('Versi database belum didukung.', 500);
  }
  transaction(fn) {
    if (this.db.isTransaction) return fn();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  encrypt(bytes, aad) {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
  }
  decrypt(bytes, aad) {
    const buf = Buffer.from(bytes),
      decipher = createDecipheriv('aes-256-gcm', this.key, buf.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]);
  }
  getCase(id) {
    const row = this.db.prepare('SELECT payload FROM cases WHERE id=?').get(validId(id));
    if (!row) throw fail('Kasus tidak ditemukan.', 404);
    return JSON.parse(row.payload);
  }
  listCases() {
    return this.db
      .prepare('SELECT payload FROM cases ORDER BY rowid DESC')
      .all()
      .map((r) => JSON.parse(r.payload));
  }
  createCase(input) {
    const record = {
      id: randomUUID(),
      title: text(input.title, 160, 'Judul', true),
      objective: text(input.objective || '', 3000, 'Tujuan'),
      operator: text(input.operator, 160, 'Operator', true),
      status: 'open',
      notes: text(input.notes || '', 10000, 'Catatan'),
      scope: {
        navigation: navigationScope(input.navigation),
        dependencies: 'Observed resource origins only; not authorization to navigate/crawl',
      },
      created: stamp(),
      updated: stamp(),
    };
    return this.transaction(() => {
      this.db.prepare('INSERT INTO cases VALUES (?,?)').run(record.id, JSON.stringify(record));
      this.event(record.id, null, 'case.created', record.operator, { case: record });
      return record;
    });
  }
  updateCase(id, input) {
    const current = this.getCase(id);
    if (this.listRuns(id).some((r) => r.status === 'running'))
      throw fail('Selesaikan run aktif sebelum mengubah kasus.', 409);
    const next = { ...current, updated: stamp() };
    for (const [key, max] of [
      ['title', 160],
      ['objective', 3000],
      ['operator', 160],
      ['notes', 10000],
    ])
      if (input[key] !== undefined)
        next[key] = text(input[key], max, key, ['title', 'operator'].includes(key));
    if (input.navigation !== undefined)
      next.scope = { ...current.scope, navigation: navigationScope(input.navigation) };
    if (input.status !== undefined) {
      if (!['open', 'closed'].includes(input.status)) throw fail('Status kasus tidak valid.');
      next.status = input.status;
    }
    return this.transaction(() => {
      this.db.prepare('UPDATE cases SET payload=? WHERE id=?').run(JSON.stringify(next), id);
      this.event(id, null, 'case.updated', next.operator, { before: current, after: next });
      return next;
    });
  }
  event(caseId, runId, type, operator, details = {}) {
    return this.transaction(() => {
      this.getCase(caseId);
      if (runId) this.getRun(caseId, runId);
      const payload = JSON.stringify({ id: randomUUID(), type, operator, time: stamp(), details });
      const last = this.db
        .prepare('SELECT hash FROM events WHERE case_id=? ORDER BY seq DESC LIMIT 1')
        .get(caseId);
      const previous = last?.hash || '0'.repeat(64),
        hash = digest(previous + payload);
      this.db
        .prepare('INSERT INTO events(case_id,run_id,payload,previous_hash,hash) VALUES (?,?,?,?,?)')
        .run(caseId, runId, payload, previous, hash);
    });
  }

  events(caseId, runId = null) {
    this.getCase(caseId);
    const rows = runId
      ? this.db
          .prepare('SELECT * FROM events WHERE case_id=? AND run_id=? ORDER BY seq')
          .all(caseId, runId)
      : this.db.prepare('SELECT * FROM events WHERE case_id=? ORDER BY seq').all(caseId);
    return rows.map((r) => ({
      seq: r.seq,
      caseId: r.case_id,
      runId: r.run_id,
      ...JSON.parse(r.payload),
      previousHash: r.previous_hash,
      hash: r.hash,
      canonicalPayload: r.payload,
    }));
  }
  custodyIntegrity(caseId) {
    this.getCase(caseId);
    let previous = '0'.repeat(64);
    for (const row of this.db
      .prepare('SELECT * FROM events WHERE case_id=? ORDER BY seq')
      .all(caseId)) {
      if (row.previous_hash !== previous || row.hash !== digest(previous + row.payload))
        return false;
      previous = row.hash;
    }
    return true;
  }
  createRun(
    caseId,
    {
      id = randomUUID(),
      mode = 'passive',
      url,
      parentRunId = null,
      config = {},
      legacy = false,
    } = {},
  ) {
    const c = this.getCase(caseId);
    validId(id);
    if (c.status !== 'open') throw fail('Kasus sudah ditutup.', 409);
    if (parentRunId) this.getRun(caseId, parentRunId);
    if (!legacy && !inScope(url, c.scope.navigation))
      throw fail('URL di luar scope navigasi kasus.');
    const run = {
      id,
      caseId,
      mode,
      url: displayUrl(url),
      parentRunId,
      status: 'running',
      started: stamp(),
      ended: null,
      operator: c.operator,
      scope: c.scope,
      collector: COLLECTOR,
      config: { ...config, limits: LIMITS },
      privacy: [
        'case-report',
        'capture-comparison',
        'analysis-assistant',
        'report-export',
      ].includes(mode)
        ? {
            collected: [
              'Selected case analysis snapshots, report versions, comparisons, approved assistant context/results, explicit export bytes',
            ],
            omitted: [
              'No new target capture, active tests, browser-state serialization or automatic remote artifact fetch',
            ],
            redacted: [
              'Shared reports use a structural allowlist; analyst sharing narrative is explicitly approved',
              'Sensitive originals only through explicit individually selected encrypted packages; export key stored separately',
            ],
            note: 'Private analysis stays encrypted locally. External model transport requires per-request context approval; provider retention is separate from local storage.',
          }
        : mode.startsWith('forensic-')
          ? {
              collected: [
                'Explicit uploaded originals and private offline analysis/analyst declarations; may contain sensitive data',
              ],
              omitted: [
                'No automatic browser/network acquisition, payload expansion, auth-state capture or archive extraction',
              ],
              redacted: [
                'Sharing is a separate strict structural copy; original/private analyses are not sharing reports',
              ],
              note: 'Originals encrypted and download-only. Private mapped fields can contain personal data. Baseline hash is not historical authenticity.',
            }
          : PRIVACY,
      legacy,
      partialReason: null,
    };
    return this.transaction(() => {
      this.db
        .prepare('INSERT INTO runs(id,case_id,payload) VALUES (?,?,?)')
        .run(id, caseId, JSON.stringify(run));
      this.event(caseId, id, 'run.started', run.operator, { mode, legacy, config: run.config });
      return run;
    });
  }
  getRun(caseId, id) {
    this.getCase(caseId);
    const row = this.db
      .prepare('SELECT payload FROM runs WHERE case_id=? AND id=?')
      .get(caseId, validId(id));
    if (!row) throw fail('Run tidak ditemukan dalam kasus ini.', 404);
    return JSON.parse(row.payload);
  }
  listRuns(caseId) {
    this.getCase(caseId);
    return this.db
      .prepare('SELECT payload FROM runs WHERE case_id=? ORDER BY rowid DESC')
      .all(caseId)
      .map((r) => JSON.parse(r.payload));
  }
  saveJob(job) {
    const run = this.getRun(job.caseId, job.id);
    if (run.status !== 'running') return;
    const bytes = Buffer.from(JSON.stringify(job));
    if (bytes.length > LIMITS.artifactBytes) throw fail('Working report melebihi batas ukuran.');
    this.db
      .prepare('UPDATE runs SET report=? WHERE id=? AND case_id=?')
      .run(this.encrypt(bytes, `job:${job.caseId}:${job.id}`), job.id, job.caseId);
  }
  loadJobs() {
    return this.db
      .prepare('SELECT id,case_id,payload,report FROM runs ORDER BY rowid DESC')
      .all()
      .map((r) => {
        if (r.report)
          return JSON.parse(this.decrypt(r.report, `job:${r.case_id}:${r.id}`).toString());
        const run = JSON.parse(r.payload);
        return {
          id: run.id,
          caseId: run.caseId,
          mode: run.mode,
          url: run.url,
          createdAt: run.started.at,
          status: 'running',
          pages: [],
          requests: [],
          events: [],
          edges: [],
          warnings: ['Tidak ada working report tersimpan sebelum gangguan.'],
          session: null,
        };
      });
  }

  artifacts(caseId, runId) {
    this.getRun(caseId, runId);
    return this.db
      .prepare('SELECT payload FROM artifacts WHERE case_id=? AND run_id=? ORDER BY rowid')
      .all(caseId, runId)
      .map((r) => JSON.parse(r.payload));
  }
  artifact(caseId, runId, id) {
    this.getRun(caseId, runId);
    const row = this.db
      .prepare('SELECT payload FROM artifacts WHERE id=? AND case_id=? AND run_id=?')
      .get(validId(id), caseId, runId);
    if (!row) throw fail('Artefak tidak ditemukan dalam run/kasus ini.', 404);
    return JSON.parse(row.payload);
  }
  addArtifact(caseId, runId, bytes, options) {
    const run = this.getRun(caseId, runId);
    if (run.status !== 'running') throw fail('Run sudah disegel; buat run baru.', 409);
    if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
    const existing = this.artifacts(caseId, runId);
    // Reserve space for the closing report and manifest even when capture hits its budget.
    const closing = ['run-report', 'capture-manifest'].includes(options.kind);
    if (
      bytes.length > LIMITS.artifactBytes ||
      existing.length >= LIMITS.artifacts + (closing ? 2 : 0) ||
      existing.reduce((sum, a) => sum + a.size, 0) + bytes.length >
        LIMITS.runBytes + (closing ? 2 * LIMITS.artifactBytes : 0)
    )
      throw fail('Batas penyimpanan capture tercapai.', 413);
    const derivedFrom = options.derivedFrom || [];
    for (const id of derivedFrom) this.artifact(caseId, runId, id);
    const artifact = {
      id: randomUUID(),
      caseId,
      runId,
      kind: options.kind,
      role: options.role || 'extracted',
      label: options.label,
      source: options.source,
      collected: stamp(),
      claimedSourceTime: options.claimedSourceTime || null,
      method: options.method || run.mode,
      collector: COLLECTOR,
      size: bytes.length,
      mimeType: options.mimeType,
      sha256: digest(bytes),
      encrypted: 'AES-256-GCM',
      derivedFrom,
      redaction: options.redaction || 'none applied; may contain sensitive content',
      baseline:
        run.legacy || run.mode === 'forensic-import'
          ? 'Established at import only; prior integrity unverified'
          : 'Established at acquisition on this host',
    };
    return this.transaction(() => {
      this.db
        .prepare('INSERT INTO artifacts VALUES (?,?,?,?,?)')
        .run(
          artifact.id,
          caseId,
          runId,
          JSON.stringify(artifact),
          this.encrypt(bytes, `artifact:${caseId}:${runId}:${artifact.id}`),
        );
      this.event(caseId, runId, 'artifact.collected', run.operator, {
        artifactId: artifact.id,
        sha256: artifact.sha256,
        kind: artifact.kind,
      });
      return artifact;
    });
  }
  readArtifact(caseId, runId, id, { log = true } = {}) {
    const a = this.artifact(caseId, runId, id);
    let bytes;
    try {
      const row = this.db
        .prepare('SELECT bytes FROM artifacts WHERE id=? AND case_id=? AND run_id=?')
        .get(id, caseId, runId);
      bytes = this.decrypt(row.bytes, `artifact:${caseId}:${runId}:${id}`);
      if (bytes.length !== a.size || digest(bytes) !== a.sha256) throw new Error('Hash mismatch');
    } catch {
      if (log)
        this.event(caseId, runId, 'artifact.integrity-failed', this.getCase(caseId).operator, {
          artifactId: id,
        });
      throw fail('Integritas artefak gagal diverifikasi; konten tidak ditampilkan.', 409);
    }
    if (log)
      this.event(caseId, runId, 'artifact.accessed', this.getCase(caseId).operator, {
        artifactId: id,
        integrity: 'verified',
      });
    return bytes;
  }
  observe(caseId, runId, artifactId, details) {
    this.artifact(caseId, runId, artifactId);
    const record = { id: randomUUID(), caseId, runId, artifactId, observed: stamp(), ...details };
    this.db
      .prepare('INSERT INTO observations VALUES (?,?,?,?,?)')
      .run(record.id, caseId, runId, artifactId, JSON.stringify(record));
    return record;
  }
  observations(caseId, runId) {
    this.getRun(caseId, runId);
    return this.db
      .prepare('SELECT payload FROM observations WHERE case_id=? AND run_id=? ORDER BY rowid')
      .all(caseId, runId)
      .map((r) => JSON.parse(r.payload));
  }
  verifyRun(caseId, runId) {
    const artifacts = this.artifacts(caseId, runId).map((a) => {
      try {
        this.readArtifact(caseId, runId, a.id, { log: false });
        return { id: a.id, sha256: a.sha256, ok: true };
      } catch {
        return {
          id: a.id,
          sha256: a.sha256,
          ok: false,
          error: 'Missing/corrupt bytes or hash/authentication mismatch',
        };
      }
    });
    const custodyOk = this.custodyIntegrity(caseId),
      ok = custodyOk && artifacts.every((a) => a.ok);
    this.event(caseId, runId, 'run.verified', this.getCase(caseId).operator, {
      ok,
      checked: artifacts.length,
      failed: artifacts.filter((a) => !a.ok).map((a) => a.id),
      custodyOk,
    });
    return {
      ok,
      checkedAt: stamp(),
      custodyOk,
      artifacts,
      limitation:
        'Local baseline verification, not authenticity or independent timestamp attestation. Host administrator can replace database and key.',
    };
  }
  seal(job, reason = null) {
    const run = this.getRun(job.caseId, job.id);
    const offline = isOfflineMode(run.mode);
    if (run.status !== 'running') return run;
    return this.transaction(() => {
      const report = this.addArtifact(job.caseId, job.id, JSON.stringify(job, null, 2), {
        kind: 'run-report',
        role: 'redacted',
        label: 'Laporan ekstraksi tersensor',
        source: run.url,
        mimeType: 'application/json',
        redaction: job.analysis?.privacy || PRIVACY,
        derivedFrom: this.artifacts(job.caseId, job.id)
          .filter(
            (a) =>
              a.kind === 'page-extraction' ||
              a.kind === 'legacy-report' ||
              (offline && OFFLINE_MODES.includes(a.kind)),
          )
          .map((a) => a.id),
      });
      this.observe(job.caseId, job.id, report.id, {
        type: offline ? 'offline-analysis-record' : 'network-summary',
        pointer: '/requests',
        evidence: offline
          ? 'Offline analysis or analyst declaration; no target requests executed'
          : 'observed browser request metadata; event correlation is not causality',
        count: job.requests.length,
      });
      const next = {
        ...run,
        status: reason ? 'partial' : 'complete',
        ended: stamp(),
        partialReason: reason,
        reportArtifactId: report.id,
      };
      const origins = [
        ...new Set(
          job.requests
            .map((r) => {
              try {
                return new URL(r.url).origin;
              } catch {
                return null;
              }
            })
            .filter(Boolean),
        ),
      ];
      const manifest = {
        schemaVersion: 1,
        run: next,
        scope: run.scope,
        session: job.sessionInfo || null,
        redirects: job.redirects || [],
        observedDependencyOrigins: origins,
        coverage: {
          pages: job.pages.map((p) => ({
            id: p.id,
            url: p.url,
            capturedAt: p.capturedAt,
            elements: p.elements.length,
            truncated: p.truncated,
            screenshotClipped: p.screenshotClipped,
            iframeCount: p.iframeCount,
            captureId: p.captureId || null,
            wiring: p.wiring || null,
            visualCoverage: p.visuals?.coverage || null,
            visualLimits: p.visuals?.limits || null,
            visualGaps: p.visuals?.gaps || [],
            warnings: p.warnings,
          })),
          requests: job.requests.length,
          events: job.events.length,
          changeBatches: job.changes?.length || 0,
        },
        blockedRequests: job.requests
          .filter((r) => r.blocked || r.failure)
          .map((r) => ({ id: r.id, url: r.url, method: r.method, reason: r.blocked || r.failure })),
        errors: job.warnings,
        collectorActions: [
          'Browser rendered JavaScript',
          'DOM/event/fetch instrumentation injected',
          ...(job.pages.some((p) => p.wiring)
            ? [
                'Bounded main-frame visual source metadata and DOM/SPA change metadata extracted; asset bytes and response bodies not collected',
                'Evidence-referenced capture graph derived; time/name matches labelled correlated, backend and actual font fallback unknown',
                'Preview uses verified screenshot only; no asset refetch',
              ]
            : []),
          'Service workers blocked',
          'HTTP redirect Location checked at Chromium response stage before following each hop',
          ...(job.popupBootstrapRelay
            ? [
                'Initial popup request relayed in the same context with redirects disabled; response disposed after delivery and not stored as evidence',
              ]
            : []),
          'Dialogs dismissed and downloads cancelled',
          'Screenshot animations disabled',
          ...(run.mode === 'authenticated'
            ? [
                'User-managed login in an ephemeral isolated browser context',
                'Content collection gated by explicit start; login metadata observation only if opted in',
                'Snapshot and selected-URL crawl use the same context; no automatic clicks/forms',
                'Authentication state not serialized or exported; screenshots may contain personal information',
                'Recognized password/OTP controls masked at screenshot acquisition; no unmasked screenshot acquired',
              ]
            : []),
          ...(run.mode === 'passive'
            ? [
                'Non-GET/HEAD/OPTIONS requests blocked',
                'Same-origin links followed within case navigation scope',
              ]
            : []),
        ],
        artifacts: this.artifacts(job.caseId, job.id),
        observations: this.observations(job.caseId, job.id),
        integrityLimitations:
          'Hashes establish a local baseline only. Source truth, claimed historical timestamps and host-administrator tampering are not independently verified.',
      };
      if (run.legacy)
        manifest.collectorActions = [
          'Existing local report and referenced screenshots imported without changing originals',
          'Baseline hashes established now; historical collection settings/times not verified',
        ];
      if (offline) {
        manifest.collectorActions = job.analysis?.actions || [
          'Existing evidence verified and read locally; no browser, network test or replay executed',
          'Separate immutable analysis/review/manual declaration record; baseline artifacts unchanged',
        ];
        manifest.analysis = job.analysis;
      }
      const artifact = this.addArtifact(job.caseId, job.id, JSON.stringify(manifest, null, 2), {
        kind: 'capture-manifest',
        role: 'extracted',
        label: 'Manifest capture',
        source: `run:${run.id}`,
        mimeType: 'application/json',
        derivedFrom: [report.id],
        redaction: 'References sanitized report metadata; not a raw capture',
      });
      next.manifestArtifactId = artifact.id;
      this.db
        .prepare('UPDATE runs SET payload=?,report=? WHERE id=? AND case_id=?')
        .run(
          JSON.stringify(next),
          this.encrypt(Buffer.from(JSON.stringify(job)), `job:${job.caseId}:${job.id}`),
          job.id,
          job.caseId,
        );
      this.event(job.caseId, job.id, 'run.sealed', run.operator, {
        status: next.status,
        reason,
        manifestArtifactId: artifact.id,
      });
      return next;
    });
  }
  exportManifest(caseId, runId) {
    const run = this.getRun(caseId, runId);
    if (run.status === 'running') throw fail('Selesaikan run sebelum mengekspor manifest.', 409);
    const verification = this.verifyRun(caseId, runId);
    if (!verification.ok) throw fail('Ekspor diblokir: integritas bukti gagal.', 409);
    const manifest = JSON.parse(
      this.readArtifact(caseId, runId, run.manifestArtifactId, { log: false }),
    );
    this.event(caseId, runId, 'manifest.exported', this.getCase(caseId).operator, {
      manifestArtifactId: run.manifestArtifactId,
    });
    return {
      ...manifest,
      manifestArtifact: this.artifact(caseId, runId, run.manifestArtifactId),
      verification,
      custody: this.events(caseId),
      custodyNote:
        'Entire case chain included so previous hashes can be verified. No artifact content or encryption key included.',
    };
  }
  close() {
    this.db?.close();
  }
}
