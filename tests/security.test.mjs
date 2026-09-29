import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { EvidenceStore } from '../server/evidence.mjs';
import { SecurityService, atPointer } from '../server/security.mjs';
import { RULES, runRules } from '../server/security-rules.mjs';
import {
  cookieMetadata,
  responseSecurityMetadata,
  requestSecurityMetadata,
} from '../server/security-metadata.mjs';
import { request, safeHeaders, positiveRequests } from './fixtures/security.mjs';

test('allowlisted metadata excludes cookie/token values and CSP nonces; collection limits are explicit', () => {
  const value = responseSecurityMetadata([
    ...safeHeaders,
    { name: 'Set-Cookie', value: 'session=SECRET_COOKIE; Secure; HttpOnly; SameSite=Lax' },
    {
      name: 'Content-Security-Policy-Report-Only',
      value: "script-src 'nonce-SECRET_NONCE'; report-uri https://secret.test/SECRET_URI",
    },
    { name: 'Uncollected', value: 'SECRET_OTHER' },
  ]);
  const json = JSON.stringify({
    value,
    auth: requestSecurityMetadata({ authorization: 'Bearer SECRET_TOKEN' }),
  });
  assert(!json.includes('SECRET_'));
  assert.equal(value.cookieAttributes[0].httpOnly, true);
  assert.equal(
    responseSecurityMetadata([{ name: 'Set-Cookie', value: 'x'.repeat(17000) }]).status,
    'partial',
  );
  assert.equal(
    responseSecurityMetadata(
      Array.from({ length: 201 }, () => ({ name: 'uncollected', value: 'x' })),
    ).status,
    'partial',
  );
  assert.equal(cookieMetadata('x=v' + '; a=b'.repeat(33)).partial, true);
  assert.equal(cookieMetadata('old=; Max-Age=0').deletion, true);
  assert.equal(
    cookieMetadata('name=value; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=10').deletion,
    false,
  );
});

test('every rule has positive, safe/exception and incomplete-input results; no automatic validation', () => {
  const positives = runRules(positiveRequests);
  for (const rule of RULES)
    assert(
      positives.findings.some((f) => f.ruleId === rule.id),
      rule.id,
    );
  assert(positives.findings.every((f) => ['candidate', 'observation'].includes(f.status)));
  const safe = runRules([request()]);
  assert.equal(safe.findings.length, 0);
  assert.equal(runRules([]).results.filter((r) => r.counts['not-assessed']).length, 7);
  const incomplete = runRules([
    request({
      security: undefined,
      parameters: undefined,
      queryParameters: undefined,
      requestSecurity: undefined,
      documentUrl: undefined,
      pageUrl: undefined,
      navigation: undefined,
    }),
  ]);
  for (const rule of incomplete.results) assert(rule.counts['not-assessed'], rule.id);
});

test('false-positive controls: errors, report-only, framing CSP, preference/deletion cookies and loopback', () => {
  const error = runRules([request({ status: 500, security: responseSecurityMetadata([]) })]);
  assert(!error.findings.some((f) => ['WI-HDR-001', 'WI-HSTS-001'].includes(f.ruleId)));
  const policy = runRules([
    request({
      security: responseSecurityMetadata([
        ...safeHeaders,
        { name: 'Set-Cookie', value: 'theme=light; Path=/' },
        { name: 'Set-Cookie', value: 'session=; Max-Age=0' },
      ]),
    }),
  ]);
  assert.equal(
    policy.findings.length,
    0,
    'XFO absent is not flagged when CSP framing directive present; no missing SameSite/HttpOnly blanket flag',
  );
  const ro = runRules([
    request({
      security: responseSecurityMetadata([
        { name: 'Content-Security-Policy-Report-Only', value: "default-src 'none'" },
      ]),
    }),
  ]);
  assert.match(ro.findings.find((f) => f.ruleId === 'WI-HDR-001').reason, /Report-Only/);
  for (const url of ['http://localhost/', 'http://127.0.0.1/', 'http://[::1]/']) {
    const local = runRules([
      request({
        url,
        navigation: false,
        resourceType: 'fetch',
        parameters: [{ name: 'password', location: 'JSON body' }],
      }),
    ]);
    assert(
      !local.findings.some((f) =>
        ['WI-HSTS-001', 'WI-MIXED-001', 'WI-TRANSFER-001'].includes(f.ruleId),
      ),
    );
  }
  assert(
    !runRules([
      request({ resourceType: 'image', navigation: false, url: 'https://cdn.example.test/a.png' }),
    ]).findings.some((f) => f.ruleId === 'WI-RECIPIENT-001'),
  );
  const blocked = runRules([{ ...positiveRequests[1], blocked: 'policy', status: null }]);
  assert.equal(blocked.findings.find((f) => f.ruleId === 'WI-MIXED-001').status, 'observation');
  const approved = runRules([positiveRequests[1]], {
    approvedRecipients: ['http://recipient.example.test'],
  });
  assert.equal(
    approved.findings.find((f) => f.ruleId === 'WI-RECIPIENT-001').status,
    'observation',
  );
});

test('partial metadata does not infer absence; names are correlations and URLs are not route schemas', () => {
  const partial = runRules([request({ security: { status: 'partial' } })]);
  for (const id of ['WI-HDR-001', 'WI-HSTS-001', 'WI-COOKIE-001'])
    assert(partial.results.find((r) => r.id === id).counts['not-assessed']);
  const csp = responseSecurityMetadata([
    { name: 'Content-Security-Policy', value: 'script-src x;'.repeat(66) },
  ]);
  assert(
    runRules([request({ security: csp })]).results.find((r) => r.id === 'WI-HDR-001').counts[
      'not-assessed'
    ],
  );
  const simple = runRules([
    request({
      url: 'https://app.example.test/token/42?code=abc',
      parameters: [{ name: 'code', location: 'query' }],
    }),
  ]);
  assert(!simple.findings.some((f) => f.ruleId === 'WI-URL-001'));
  assert.match(
    runRules(positiveRequests).findings.find((f) => f.ruleId === 'WI-URL-001').impact,
    /unproven/,
  );
});

async function setup(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'wi-security-'));
  const store = new EvidenceStore(path.join(directory, 'data'));
  await store.init();
  t.after(() => store.close());
  const c = store.createCase({
    title: 'Synthetic security fixture',
    operator: 'Fixture analyst',
    navigation: ['https://app.example.test'],
  });
  const baseline = makeCapture(store, c.id, positiveRequests);
  return { store, c, baseline, service: new SecurityService(store) };
}
function makeCapture(store, caseId, requests) {
  const run = store.createRun(caseId, {
    url: 'https://app.example.test/',
    config: { fixture: 'Synthetic metadata, no browser or network acquisition' },
  });
  const artifact = store.addArtifact(caseId, run.id, JSON.stringify({ requests }), {
    kind: 'capture-observations',
    role: 'extracted',
    source: 'synthetic:local-test',
    label: 'Synthetic fixture metadata',
    mimeType: 'application/json',
    method: 'synthetic-test-data',
  });
  const job = {
    id: run.id,
    caseId,
    url: run.url,
    mode: 'passive',
    status: 'complete',
    pages: [],
    requests,
    events: [],
    warnings: [],
    edges: [],
  };
  store.seal(job);
  return {
    run,
    artifact,
    ref: { caseId, runId: run.id, artifactId: artifact.id, pointer: '/requests/0' },
  };
}
const decision = (f, ref, extra = {}) => ({
  expectedRevision: f.revision,
  status: 'validated',
  reviewer: 'Fixture reviewer',
  reason: 'Reviewed synthetic metadata and known fixture policy',
  evidenceReviewed: true,
  risk: 'low',
  confidence: 'medium',
  impact: 'Configuration differs from intended fixture policy',
  prerequisites: 'Controlled fixture only',
  recommendation: 'Correct cookie attributes',
  limitations: 'No real-site vulnerability established',
  supporting: [ref],
  contradicting: [],
  ...extra,
});
const plan = {
  kind: 'evidence-review',
  title: 'Inspect source',
  operator: 'Fixture analyst',
  objective: 'Confirm metadata',
  steps: 'Read original artifact and compare expected configuration',
  expectedBehavior: 'Values omitted, flags visible',
  knownImpact: 'No target activity',
  parameterNames: ['token'],
};

test('assessment → evidence, immutable baseline, review lifecycle/history, manual plan/results and verified export', async (t) => {
  const { store, c, baseline, service } = await setup(t);
  const original = store.readArtifact(c.id, baseline.run.id, baseline.artifact.id);
  let a = service.assess(c.id, baseline.run.id);
  assert.equal(a.results.length, 7);
  for (const f of a.findings)
    for (const r of f.evidence) {
      const canonical = service.reference(c.id, r);
      assert(canonical.sha256);
      assert(atPointer(JSON.parse(store.readArtifact(c.id, r.runId, r.artifactId)), r.pointer).id);
    }
  let f = a.findings.find((f) => f.ruleId === 'WI-COOKIE-001');
  assert.throws(
    () => service.review(c.id, a.id, f.id, decision(f, f.evidence[0], { evidenceReviewed: false })),
    /Tinjau/,
  );
  a = service.review(c.id, a.id, f.id, decision(f, f.evidence[0]));
  assert.equal(a.findings.find((x) => x.id === f.id).status, 'validated');
  assert.throws(() => service.review(c.id, a.id, f.id, decision(f, f.evidence[0])), /berubah/);
  f = a.findings.find((x) => x.id === f.id);
  a = service.review(
    c.id,
    a.id,
    f.id,
    decision(f, f.evidence[0], { status: 'candidate', reason: 'Reopened for additional evidence' }),
  );
  f = a.findings.find((x) => x.id === f.id);
  a = service.review(
    c.id,
    a.id,
    f.id,
    decision(f, f.evidence[0], {
      status: 'dismissed',
      supporting: [],
      contradicting: f.evidence,
      reason: 'Fixture is deliberately synthetic, not an actual vulnerability',
    }),
  );
  assert.equal(a.findings.find((x) => x.id === f.id).history.length, 4);
  a = service.plan(c.id, a.id, plan);
  const manual = a.manualTests[0];
  a = service.testResult(c.id, a.id, manual.id, {
    expectedRevision: 0,
    status: 'completed',
    result: 'Fixture attributes checked',
    knownImpact: 'None',
    operator: 'Reviewer',
    evidence: [baseline.ref],
  });
  assert.equal(a.manualTests[0].history.length, 2);
  assert.throws(
    () => service.testResult(c.id, a.id, manual.id, { expectedRevision: 0, status: 'cancelled' }),
    /ditutup/,
  );
  a = service.plan(c.id, a.id, { ...plan, title: 'Cancelled review' });
  a = service.testResult(c.id, a.id, a.manualTests[1].id, {
    expectedRevision: 0,
    status: 'cancelled',
    result: 'Not needed',
    knownImpact: 'None',
    operator: 'Reviewer',
  });
  const exported = service.export(c.id, a.id);
  assert(exported.manifests.every((m) => m.verification.ok));
  assert(
    exported.manifests
      .filter((m) => m.run.mode.startsWith('security') || m.run.mode === 'manual-validation')
      .every((m) => m.collectorActions.every((x) => !x.includes('Browser rendered'))),
  );
  assert.equal(
    store.readArtifact(c.id, baseline.run.id, baseline.artifact.id).compare(original),
    0,
  );
  assert(!JSON.stringify(exported).includes('SECRET_'));
  assert.equal(store.getRun(c.id, baseline.run.id).mode, 'passive');
});

test('case/reference isolation, missing legacy metadata, protected input and authorization comparison prerequisites', async (t) => {
  const { store, c, baseline, service } = await setup(t);
  const other = store.createCase({
    title: 'Other case',
    operator: 'Other',
    navigation: ['https://app.example.test'],
  });
  let a = service.assess(c.id, baseline.run.id),
    f = a.findings.find((f) => f.status === 'candidate');
  assert.throws(() => service.get(other.id, a.id), /tidak ditemukan/);
  assert.throws(() => service.assess(c.id, '../../keys'), /ID tidak valid/);
  assert.throws(() => service.reference(other.id, baseline.ref), /kasus yang sama/);
  assert.throws(
    () => service.reference(c.id, { ...baseline.ref, pointer: '/requests/99999' }),
    /tidak ditemukan/,
  );
  assert.throws(() => service.reference(c.id, { ...baseline.ref, sha256: 'wrong' }), /hash/);
  assert.throws(
    () =>
      service.assess(c.id, baseline.run.id, {
        firstPartyOrigins: ['https://a.test/?token=secret'],
      }),
    /origin/,
  );
  assert.throws(
    () =>
      service.review(c.id, a.id, f.id, decision(f, f.evidence[0], { claimType: 'authorization' })),
    /perbandingan/,
  );
  a = service.plan(c.id, a.id, { ...plan, kind: 'authorization-comparison' });
  const t1 = a.manualTests[0];
  assert.throws(
    () =>
      service.testResult(c.id, a.id, t1.id, {
        status: 'completed',
        expectedRevision: 0,
        evidence: [baseline.ref],
      }),
    /terpisah/,
  );
  const owner = makeCapture(store, c.id, [request()]),
    tester = makeCapture(store, c.id, [request({ status: 403 })]);
  const result = {
    expectedRevision: 0,
    status: 'completed',
    result: 'Owner allowed, other denied according to explicit policy',
    knownImpact: 'Synthetic only',
    operator: 'Reviewer',
    evidence: [owner.ref, tester.ref],
    comparison: {
      object: 'document-42',
      ownerIdentity: 'owner',
      expectedPolicy: 'Owner may read; other identity must be denied',
      interpretation:
        'Controlled synthetic expected access established independently; status difference alone does not prove a flaw',
      identities: [
        {
          id: 'owner',
          role: 'owner',
          expectedAccess: 'read',
          actualAccess: 'read',
          evidence: [owner.ref],
        },
        {
          id: 'other',
          role: 'member',
          expectedAccess: 'deny',
          actualAccess: 'deny',
          evidence: [tester.ref],
        },
      ],
    },
  };
  a = service.testResult(c.id, a.id, t1.id, result);
  assert(a.manualTests[0].comparison);
  a = service.review(
    c.id,
    a.id,
    f.id,
    decision(f, f.evidence[0], {
      claimType: 'authorization',
      manualTestId: t1.id,
      status: 'dismissed',
      supporting: [],
      contradicting: [tester.ref],
      reason: 'Controlled policy grants no cross-owner access; no authorization issue demonstrated',
    }),
  );
  const old = makeCapture(store, c.id, [
    {
      id: 'legacy',
      url: 'https://app.example.test/',
      resourceType: 'document',
      status: 200,
      responseType: 'text/html',
    },
  ]);
  const imported = service.assess(c.id, old.run.id);
  assert(imported.results.find((r) => r.id === 'WI-HDR-001').counts['not-assessed']);
  assert.equal(imported.findings.length, 0);
});

test('tampered fixture blocks assessment, review and export; no user evidence touched', async (t) => {
  const { store, c, baseline, service } = await setup(t);
  const a = service.assess(c.id, baseline.run.id),
    f = a.findings.find((f) => f.status === 'candidate');
  store.db.exec('DROP TRIGGER immutable_artifacts_UPDATE');
  const bytes = Buffer.from(
    store.db.prepare('SELECT bytes FROM artifacts WHERE id=?').get(baseline.artifact.id).bytes,
  );
  bytes[bytes.length - 1] ^= 1;
  store.db.prepare('UPDATE artifacts SET bytes=? WHERE id=?').run(bytes, baseline.artifact.id);
  assert.throws(() => service.assess(c.id, baseline.run.id), /Integritas/);
  assert.throws(() => service.review(c.id, a.id, f.id, decision(f, f.evidence[0])), /Integritas/);
  assert.throws(() => service.export(c.id, a.id), /Integritas/);
});

test('ambiguous HSTS and incomplete body parsing stay unassessed', () => {
  const quoted = responseSecurityMetadata([
    { name: 'Strict-Transport-Security', value: 'max-age="100"' },
  ]);
  assert(quoted.headers.hsts.maxAgePositive);
  const duplicate = responseSecurityMetadata([
    { name: 'Strict-Transport-Security', value: 'max-age=100; max-age=0' },
  ]);
  assert(
    runRules([request({ security: duplicate })]).results.find((r) => r.id === 'WI-HSTS-001').counts[
      'not-assessed'
    ],
  );
  for (const format of ['large-body', 'unparsed', 'other']) {
    const results = runRules([{ ...positiveRequests[1], body: { format, fields: [] } }]).results;
    for (const id of ['WI-TRANSFER-001', 'WI-RECIPIENT-001'])
      assert(results.find((r) => r.id === id).counts['not-assessed']);
  }
});
