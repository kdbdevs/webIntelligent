// Allowlisted, lossy metadata only. Never return raw headers, cookie/token values or CSP nonces.
export const SECURITY_METADATA_VERSION = 1;
export const HEADER_LIMITS = {
  count: 200,
  valueCharacters: 16384,
  cookieInstructions: 40,
  directives: 64,
};
const KNOWN_DIRECTIVES = new Set(
  'default-src script-src script-src-elem script-src-attr style-src img-src connect-src font-src media-src object-src child-src frame-src worker-src base-uri form-action frame-ancestors sandbox upgrade-insecure-requests block-all-mixed-content report-uri report-to'.split(
    ' ',
  ),
);
export function policyMetadata(value = '') {
  const policies = value
    .split(',')
    .slice(0, 10)
    .map((policy) => {
      const seen = new Set(),
        directives = [];
      for (const segment of policy.split(';').slice(0, HEADER_LIMITS.directives)) {
        const [raw, ...values] = segment.trim().split(/\s+/),
          name = raw.toLowerCase();
        if (!name || seen.has(name)) continue;
        seen.add(name);
        directives.push({
          name: KNOWN_DIRECTIVES.has(name) ? name : '(other directive)',
          none: values.includes("'none'"),
          self: values.includes("'self'"),
          wildcard: values.includes('*'),
          unsafeInline: values.includes("'unsafe-inline'"),
          unsafeEval: values.includes("'unsafe-eval'"),
          nonceOrHash: values.some((v) => /^'(nonce-|sha(?:256|384|512)-)/.test(v)),
          sourceCount: values.length,
        });
      }
      return { directives };
    });
  return {
    present: true,
    partial:
      value.split(',').length > 10 ||
      value.split(',').some((p) => p.split(';').length > HEADER_LIMITS.directives),
    policies,
    parsing: 'summary only; source values/nonces/hashes omitted; not a full CSP evaluator',
  };
}
export function cookieMetadata(value, now = Date.now()) {
  const segments = value.split(';'),
    first = segments.shift(),
    eq = first.indexOf('=');
  if (eq < 1) return { valid: false, reason: 'Unparseable Set-Cookie; values omitted' };
  const rawName = first.slice(0, eq).trim(),
    attrs = new Map();
  let duplicate = false;
  for (const segment of segments.slice(0, 32)) {
    const index = segment.indexOf('='),
      key = (index < 0 ? segment : segment.slice(0, index)).trim().toLowerCase();
    if (attrs.has(key)) duplicate = true;
    attrs.set(key, index < 0 ? '' : segment.slice(index + 1).trim());
  }
  const sameSite = attrs.get('samesite')?.toLowerCase();
  const age = attrs.get('max-age');
  const validAge = age != null && /^-?\d+$/.test(age);
  const expires = Date.parse(attrs.get('expires'));
  return {
    valid: true,
    partial: segments.length > 32,
    name: /^[\w.-]{1,80}$/.test(rawName) ? rawName : '[name omitted]',
    authLikeName: /(?:session|auth|token|(?:^|_)sid$)/i.test(rawName),
    purpose: 'unknown; name is only a heuristic',
    secure: attrs.has('secure'),
    httpOnly: attrs.has('httponly'),
    sameSite:
      sameSite == null
        ? 'unspecified'
        : ['lax', 'strict', 'none'].includes(sameSite)
          ? sameSite
          : 'invalid',
    partitioned: attrs.has('partitioned'),
    domainAttribute: attrs.has('domain'),
    pathIsRoot: attrs.get('path') === '/',
    prefix: rawName.startsWith('__Host-Http-')
      ? '__Host-Http-'
      : rawName.startsWith('__Host-')
        ? '__Host-'
        : rawName.startsWith('__Secure-')
          ? '__Secure-'
          : rawName.startsWith('__Http-')
            ? '__Http-'
            : null,
    deletion: validAge ? Number(age) <= 0 : Number.isFinite(expires) && expires <= now,
    duplicateAttributes: duplicate,
    acceptance: 'unknown; response instruction is not proof of browser storage or later sending',
  };
}
export function responseSecurityMetadata(headers, now = Date.now()) {
  if (!Array.isArray(headers))
    return { version: 1, status: 'unavailable', reason: 'Response headers unavailable' };
  const selected = new Map();
  let truncated = headers.length > HEADER_LIMITS.count;
  const allow = new Set([
    'content-security-policy',
    'content-security-policy-report-only',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'set-cookie',
  ]);
  for (const h of headers.slice(0, HEADER_LIMITS.count)) {
    const name = String(h.name).toLowerCase();
    if (!allow.has(name)) continue;
    const value = String(h.value);
    if (value.length > HEADER_LIMITS.valueCharacters) {
      truncated = true;
      continue;
    }
    selected.set(name, [...(selected.get(name) || []), value]);
  }
  const csp = (name) =>
    selected.has(name) ? policyMetadata(selected.get(name).join(',')) : { present: false };
  const hsts = selected.get('strict-transport-security');
  const maxAge = hsts?.[0].match(/(?:^|;)\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*(?:;|$)/i);
  const hstsNames =
    hsts?.[0]
      .split(';')
      .map((v) => v.trim().split('=')[0].toLowerCase())
      .filter(Boolean) || [];
  const xfo = selected.get('x-frame-options');
  const referrer = selected.get('referrer-policy');
  const referrerTokens = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url',
  ];
  const recognized = referrer
    ?.join(',')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter((v) => referrerTokens.includes(v));
  const cookieHeaders = selected.get('set-cookie') || [];
  if (cookieHeaders.length > HEADER_LIMITS.cookieInstructions) truncated = true;
  return {
    version: SECURITY_METADATA_VERSION,
    status: truncated ? 'partial' : 'complete',
    observedAt: new Date(now).toISOString(),
    limits: HEADER_LIMITS,
    headers: {
      csp: csp('content-security-policy'),
      cspReportOnly: csp('content-security-policy-report-only'),
      hsts: {
        present: !!hsts,
        validMaxAge: !!maxAge,
        maxAgePositive: !!maxAge && Number(maxAge[1] || maxAge[2]) > 0,
        includeSubDomains: !!hsts && /(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(hsts[0]),
        duplicate: (hsts?.length || 0) > 1 || new Set(hstsNames).size !== hstsNames.length,
      },
      xFrameOptions: {
        present: !!xfo,
        value:
          xfo?.length === 1 && /^(DENY|SAMEORIGIN)$/i.test(xfo[0].trim())
            ? xfo[0].trim().toUpperCase()
            : xfo
              ? 'invalid-or-multiple'
              : null,
      },
      nosniff: {
        present: selected.has('x-content-type-options'),
        valid: selected.get('x-content-type-options')?.[0].trim().toLowerCase() === 'nosniff',
      },
      referrerPolicy: {
        present: !!referrer,
        effectiveRecognized: recognized?.at(-1) || null,
        note: 'Header only; meta/element policy and browser defaults may differ',
      },
    },
    cookieAttributes: cookieHeaders
      .slice(0, HEADER_LIMITS.cookieInstructions)
      .map((value) => cookieMetadata(value, now)),
    omissions: [
      'all cookie values',
      'CSP nonces/hash/source values',
      'raw headers',
      'unknown cookie attribute values',
    ],
    limitation:
      'Headers observed on this response only. Partial collection cannot prove absence; cookie storage/acceptance and policy enforcement not verified',
  };
}
export function requestSecurityMetadata(headers) {
  return {
    version: 1,
    status: headers ? 'complete' : 'unavailable',
    authorizationPresent: headers ? typeof headers.authorization === 'string' : null,
    values: 'not collected',
  };
}
