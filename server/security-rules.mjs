// Pure, offline rule functions. Input is verified, redacted evidence, never a live target.
export const ENGINE_VERSION = '1.0.0';
const mdn = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/';
export const RULES = [
  {
    id: 'WI-HDR-001',
    title: 'Document response policies',
    input: 'Complete selected header metadata on a successful HTML document response',
    sources: [
      'https://www.w3.org/TR/CSP3/',
      mdn + 'X-Frame-Options',
      mdn + 'X-Content-Type-Options',
      mdn + 'Referrer-Policy',
    ],
  },
  {
    id: 'WI-HSTS-001',
    title: 'HTTPS transport policy',
    input: 'Complete HSTS metadata on HTTPS document response with a public hostname',
    sources: [mdn + 'Strict-Transport-Security'],
  },
  {
    id: 'WI-COOKIE-001',
    title: 'Set-Cookie attribute consistency',
    input: 'Complete Set-Cookie attribute metadata; values are not required',
    sources: [mdn + 'Set-Cookie'],
  },
  {
    id: 'WI-MIXED-001',
    title: 'Observed mixed content',
    input: 'Request URL, document URL, navigation context and response/block metadata',
    sources: [
      'https://www.w3.org/TR/mixed-content/',
      'https://www.w3.org/TR/secure-contexts/#is-origin-trustworthy',
    ],
  },
  {
    id: 'WI-URL-001',
    title: 'Potential sensitive URL parameters',
    input: 'Observed query parameter names and locations',
    sources: ['https://cwe.mitre.org/data/definitions/598.html'],
  },
  {
    id: 'WI-TRANSFER-001',
    title: 'Potential sensitive cleartext transfer',
    input: 'Transport URL, parameter names/locations or Authorization presence, response metadata',
    sources: ['https://cwe.mitre.org/data/definitions/319.html'],
  },
  {
    id: 'WI-RECIPIENT-001',
    title: 'Cross-origin data recipient',
    input:
      'Document/request origins and parameter names or Authorization presence; optional analyst ownership declarations',
    sources: ['https://devguide.owasp.org/en/04-design/02-web-app-checklist/08-protect-data/'],
  },
].map((r) => ({
  ...r,
  version: '1.0.0',
  mode: 'passive',
  possibleResults: ['not-assessed', 'not-applicable', 'no-indicator', 'observation', 'candidate'],
}));
export const sensitiveName = (name) =>
  /(?:^|[._\[\]-])(?:password|passwd|pwd|token|access_token|refresh_token|id_token|authorization|secret|api_key|apikey|email|ssn|credit_card)(?:$|[._\[\]-])/i.test(
    name,
  );
export function urlOf(value) {
  try {
    const u = new URL(value);
    return /^https?:$/.test(u.protocol) ? u : null;
  } catch {
    return null;
  }
}
const local = (u) =>
  !!u &&
  (u.hostname === 'localhost' ||
    u.hostname.endsWith('.localhost') ||
    /^127\./.test(u.hostname) ||
    u.hostname === '[::1]');
const ipHost = (u) => /^[\d.]+$/.test(u.hostname) || u.hostname.startsWith('[');
const result = (status, reason, extra = {}) => ({ status, reason, ...extra });
const missing = (reason) => result('not-assessed', reason);
const skip = (reason) => result('not-applicable', reason);
const clear = (reason) => result('no-indicator', reason);
const issue = (status, reason, impact, recommendation, extra = {}) =>
  result(status, reason, {
    impact,
    recommendation,
    risk: status === 'candidate' ? 'medium' : 'info',
    confidence: 'low',
    ...extra,
  });
function evaluate(id, r, context) {
  const u = urlOf(r.url),
    doc = urlOf(r.documentUrl || r.pageUrl),
    s = r.security;
  const params = Array.isArray(r.parameters)
    ? r.parameters
    : Array.isArray(r.queryParameters)
      ? r.queryParameters.map((name) => ({ name, location: 'query' }))
      : null;
  const sensitive = (params || []).filter((p) => sensitiveName(p.name));
  const delivered = !!r.status && !r.blocked && !r.failure;
  if (id === 'WI-HDR-001') {
    if (r.resourceType !== 'document') return skip('Not a document response');
    if (!r.status || !r.responseType) return missing('Response status/content type unavailable');
    if (
      r.status < 200 ||
      r.status >= 300 ||
      !/text\/html|application\/xhtml\+xml/i.test(r.responseType)
    )
      return skip(
        'Error, redirect or non-HTML response; not evidence of the rendered document policy',
      );
    if (s?.status !== 'complete' || !s.headers)
      return missing(
        'Selected response policy metadata missing or partial; absence cannot be inferred',
      );
    const h = s.headers,
      concerns = [];
    if (h.csp?.partial || h.cspReportOnly?.partial)
      return missing('CSP summary truncated; effective or absent directives cannot be established');
    if (!h.csp?.present)
      concerns.push(
        h.cspReportOnly?.present
          ? 'Only CSP Report-Only observed; it does not enforce restrictions'
          : 'No enforcing CSP response header observed',
      );
    const frame = h.csp?.policies?.some((p) =>
      p.directives.some((d) => d.name === 'frame-ancestors'),
    );
    if (!frame && !['DENY', 'SAMEORIGIN'].includes(h.xFrameOptions?.value))
      concerns.push('No recognized framing restriction in selected response headers');
    if (!h.nosniff?.valid) concerns.push('No recognized nosniff response header');
    if (h.referrerPolicy?.effectiveRecognized === 'unsafe-url')
      concerns.push('Referrer-Policy header declares unsafe-url');
    if (!concerns.length)
      return clear(
        'Selected policy headers present; effective CSP, meta policy, content and exploitability not evaluated',
      );
    return issue(
      'observation',
      concerns.join('; '),
      'Depends on page sensitivity, embedding needs, MIME types and effective browser policy. Header absence alone does not demonstrate an exploit.',
      'Review effective document policy and legitimate embedding requirements; deploy appropriate CSP, framing, MIME and referrer policies.',
      {
        confidence: 'medium',
        limitations: [
          'CSP summary is not a full policy evaluator; a declared frame-ancestors directive may itself be permissive',
          'CSP meta policies and inherited/browser defaults are not assessed; missing Referrer-Policy alone is not flagged',
        ],
      },
    );
  }
  if (id === 'WI-HSTS-001') {
    if (!u) return missing('Transport URL unavailable');
    if (r.resourceType !== 'document' || u.protocol !== 'https:' || local(u) || ipHost(u))
      return skip(
        'HSTS check applies to HTTPS documents on hostnames; HTTP, loopback and IP exceptions excluded',
      );
    if (!r.status || r.status < 200 || r.status >= 300)
      return skip('No successful document response');
    if (s?.status !== 'complete' || !s.headers?.hsts)
      return missing('HSTS metadata unavailable or partial');
    const h = s.headers.hsts;
    if (h.duplicate)
      return missing('Multiple HSTS fields require browser-specific parsing; not resolved');
    return h.present && h.validMaxAge && h.maxAgePositive
      ? clear('Positive max-age observed; preload/inherited coverage not checked')
      : issue(
          'observation',
          'No positive valid HSTS max-age on this response',
          'A first-visit downgrade may be possible depending on preload, parent-domain policy and user navigation.',
          'Verify inherited/preloaded policy and deployment requirements before enabling HTTPS-only transport.',
          { confidence: 'medium' },
        );
  }
  if (id === 'WI-COOKIE-001') {
    if (s?.status !== 'complete' || !Array.isArray(s.cookieAttributes))
      return missing(
        'Cookie attribute metadata unavailable or partial; no browser cookie jar was acquired',
      );
    if (!s.cookieAttributes.length)
      return skip('No Set-Cookie instruction on this response; existing cookies unknown');
    const relevant = s.cookieAttributes.filter((c) => !c.deletion);
    if (
      relevant.some(
        (c) => !c.valid || c.partial || c.duplicateAttributes || c.sameSite === 'invalid',
      )
    )
      return missing('Cookie instructions contain ambiguous, invalid or truncated attributes');
    const inconsistent = relevant.filter(
      (c) =>
        (!c.secure && (c.sameSite === 'none' || c.partitioned || c.prefix)) ||
        (c.prefix?.startsWith('__Host-') && (c.domainAttribute || !c.pathIsRoot)) ||
        (c.prefix?.includes('Http-') && !c.httpOnly),
    );
    if (inconsistent.length)
      return issue(
        'candidate',
        `Inconsistent security attributes on cookie instruction(s): ${inconsistent.map((c) => c.name).join(', ')}`,
        'Browsers may reject these cookies; this is a configuration candidate, not proof that an insecure cookie was accepted or exposed.',
        'Check browser acceptance and intended cookie purpose; align Secure, SameSite, Partitioned and prefix requirements.',
        { risk: 'low', confidence: 'medium' },
      );
    const auth = relevant.filter(
      (c) =>
        c.authLikeName && (!c.httpOnly || (!c.secure && u?.protocol === 'https:' && !local(u))),
    );
    return auth.length
      ? issue(
          'observation',
          `Authentication-like cookie names warrant purpose review: ${auth.map((c) => c.name).join(', ')}`,
          'Purpose is inferred from names only; script-readable cookies may be intentional. No authentication/session value was collected.',
          'Confirm purpose and whether Secure/HttpOnly are appropriate; verify browser storage separately.',
        )
      : clear(
          'No selected attribute inconsistency; preference, deletion and unspecified SameSite cookies are not automatically vulnerabilities',
        );
  }
  if (id === 'WI-MIXED-001') {
    if (!u || !doc || typeof r.navigation !== 'boolean' || typeof r.mainFrame !== 'boolean')
      return missing('Document/transport/navigation context not collected');
    if (
      doc.protocol !== 'https:' ||
      u.protocol !== 'http:' ||
      local(u) ||
      (r.navigation && r.mainFrame)
    )
      return skip(
        'Not an insecure subresource in a secure document context; top-level navigation and trustworthy loopback excluded',
      );
    return issue(
      delivered ? 'candidate' : 'observation',
      delivered
        ? 'HTTP subresource response observed in HTTPS document context'
        : 'HTTP subresource request attempted; blocked, failed or no response observed',
      'Content or metadata could be exposed or altered on the network; rendering and user impact remain unverified.',
      'Use HTTPS resources and verify upgrade/block behavior in the browser.',
      {
        confidence: 'medium',
        limitations: [
          'Declarations without requests are excluded',
          'Observed response is not proof that the browser rendered or executed it',
        ],
      },
    );
  }
  if (id === 'WI-URL-001') {
    if (!params) return missing('Parameter names/locations unavailable');
    const query = sensitive.filter((p) => p.location === 'query');
    return query.length
      ? issue(
          'candidate',
          `Potential sensitive query parameter names: ${query.map((p) => p.name).join(', ')}`,
          'If values are sensitive, URL logging/history/referrers may expose them; values were omitted so actual sensitivity is unproven.',
          'Validate purpose with the application owner; keep credentials out of URLs and minimize URL personal data.',
          {
            cwe: [
              {
                id: 'CWE-598',
                condition: 'Only if the omitted query values are confirmed sensitive',
              },
            ],
          },
        )
      : clear(
          'No recognized sensitive query names; paths and unknown names/values are not assessed',
        );
  }
  if (id === 'WI-TRANSFER-001') {
    if (!u || !params || r.requestSecurity?.status !== 'complete')
      return missing('Transport/parameter/Authorization-presence metadata unavailable');
    if (u.protocol === 'https:' || local(u))
      return skip(
        'HTTPS or controlled loopback; TLS configuration and proxies are outside this check',
      );
    if (['large-body', 'unparsed', 'other'].includes(r.body?.format))
      return missing(
        'Request body parameter extraction incomplete; omitted payload cannot be assessed',
      );
    if (!sensitive.length && !r.requestSecurity.authorizationPresent)
      return clear(
        'No recognized sensitive field names or Authorization presence; omitted contents may still be sensitive',
      );
    return issue(
      delivered ? 'candidate' : 'observation',
      'Potential sensitive metadata on a cleartext HTTP request',
      'Network observers may see sensitive values if present; actual values and receipt are not established by field names alone.',
      'Use HTTPS for sensitive transfers and confirm whether the omitted data is confidential.',
      {
        cwe: [
          { id: 'CWE-319', condition: 'Only if transferred information is confirmed sensitive' },
        ],
      },
    );
  }
  if (id === 'WI-RECIPIENT-001') {
    if (!u || !doc || !params || r.requestSecurity?.status !== 'complete')
      return missing('Origin or transfer metadata unavailable');
    if (u.origin === doc.origin || context.firstPartyOrigins.includes(u.origin))
      return skip(
        'Same origin or analyst-declared first-party origin; declaration is not independently verified',
      );
    if (['large-body', 'unparsed', 'other'].includes(r.body?.format))
      return missing(
        'Request body extraction incomplete; cross-origin data transfer contents unknown',
      );
    if (!params.length && !r.requestSecurity.authorizationPresent)
      return clear(
        'Cross-origin destination alone is not a vulnerability; no selected transfer fields observed',
      );
    const approved = context.approvedRecipients.includes(u.origin);
    return issue(
      !approved && (sensitive.length || r.requestSecurity.authorizationPresent)
        ? 'candidate'
        : 'observation',
      `${approved ? 'Analyst-approved' : 'Ownership unverified'} cross-origin destination ${u.origin} with parameter/authorization metadata${delivered ? ' and an observed response' : ' (receipt unconfirmed)'}`,
      'Ownership, consent, legitimate purpose and actual sensitive values require review. Cross-origin does not establish third-party ownership or unauthorized disclosure.',
      'Confirm recipient ownership, data minimization and expected sharing policy; review the original evidence and approved integrations.',
      {
        risk: approved ? 'info' : 'low',
        limitations: [
          'Origin comparison only; no registrable-domain/ownership inference',
          'Approved recipient list is an analyst declaration, not a security guarantee',
        ],
      },
    );
  }
}
export function runRules(requests, context = {}) {
  context = { firstPartyOrigins: [], approvedRecipients: [], ...context };
  const findings = [],
    results = [];
  for (const rule of RULES) {
    const evaluations = requests.map((r) => ({ request: r, ...evaluate(rule.id, r, context) }));
    const counts = {};
    for (const e of evaluations) counts[e.status] = (counts[e.status] || 0) + 1;
    if (!evaluations.length) counts['not-assessed'] = 1;
    for (const e of evaluations.filter((e) => ['candidate', 'observation'].includes(e.status))) {
      if (findings.length >= 300) break;
      findings.push({
        id: `finding-${findings.length + 1}`,
        ruleId: rule.id,
        ruleVersion: rule.version,
        title: rule.title,
        status: e.status,
        risk: e.risk,
        confidence: e.confidence,
        reason: e.reason,
        impact: e.impact,
        recommendation: e.recommendation,
        prerequisites:
          'Reproduce the relevant context with authorization; establish intended policy, sensitivity and browser behavior before asserting impact.',
        limitations: [
          ...(e.limitations || []),
          'Only captured metadata assessed; no exploit, payload replay, response body, backend, TLS validation or account authorization test executed',
        ],
        cwe: e.cwe || [],
        evidence: [e.request.evidenceRef],
        related: e.request.related || [],
        requestId: e.request.id,
        revision: 0,
        history: [{ from: 'observation', to: e.status, actor: 'rule-engine', reason: e.reason }],
      });
    }
    results.push({
      ...rule,
      counts,
      coverage: evaluations.length,
      evaluations: evaluations.map((e) => ({
        requestId: e.request.id,
        result: e.status,
        reason: e.reason,
        evidence: e.request.evidenceRef,
      })),
      notAssessedReasons: !evaluations.length
        ? ['No captured request metadata available']
        : [...new Set(evaluations.filter((e) => e.status === 'not-assessed').map((e) => e.reason))],
      exceptions: [
        ...new Set(
          evaluations
            .filter((e) => ['not-applicable', 'no-indicator'].includes(e.status))
            .map((e) => e.reason),
        ),
      ].slice(0, 20),
    });
  }
  return {
    engineVersion: ENGINE_VERSION,
    results,
    findings,
    limits: {
      requests: 1500,
      findings: 300,
      truncated:
        results.reduce((n, r) => n + (r.counts.candidate || 0) + (r.counts.observation || 0), 0) >
        findings.length,
    },
  };
}
