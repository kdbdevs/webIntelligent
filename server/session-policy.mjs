import { normalizeUrl, crawlable } from './safety.mjs';
import { fail, inScope } from './evidence.mjs';

export const SESSION_POLICY = {
  manual:
    'Observe user browsing; allow normal HTTP methods. No automatic clicks or form submissions.',
  crawl:
    'Visit explicitly selected in-scope URLs. Block obvious action URLs and non-GET/HEAD/OPTIONS requests unless covered by a user-declared read endpoint rule.',
  limitation:
    'Neither GET nor a declared read endpoint guarantees absence of side effects. Blocked calls can make page content incomplete.',
};
export function actionUrl(value) {
  try {
    const u = normalizeUrl(value);
    let target = u.pathname + u.search + new URL(value, u.href).hash;
    try {
      target = decodeURIComponent(target);
    } catch {}
    return /(?:^|[\/#_?&=.,-])(logout|log-out|signout|sign-out|delete|remove|unsubscribe|checkout|purchase|buy|transfer|publish|send|send-message|reset)(?:$|[\/#_?&=.,-])/i.test(
      target,
    );
  } catch {
    return true;
  }
}
export function readRules(input = []) {
  if (!Array.isArray(input) || input.length > 20) throw fail('Maksimal 20 izin endpoint baca.');
  return input.map((rule) => {
    if (rule?.method !== 'POST')
      throw fail('Izin tambahan hanya mendukung POST yang dinyatakan membaca data.');
    const url = normalizeUrl(rule.url);
    if (url.search || new URL(rule.url).hash || actionUrl(url.href))
      throw fail('Endpoint baca harus tanpa query/token dan bukan URL aksi.');
    const operationName = rule.operationName || null;
    if (
      operationName !== null &&
      (typeof operationName !== 'string' || !/^[A-Za-z_]\w{0,79}$/.test(operationName))
    )
      throw fail('operationName tidak valid.');
    if (/graphql/i.test(url.pathname) && !operationName)
      throw fail('Endpoint GraphQL memerlukan operationName yang disetujui.');
    return {
      method: 'POST',
      url: url.origin + url.pathname,
      operationName,
      basis: 'user-declared-read; not independently proven',
    };
  });
}
export function crawlRequestReason(request, rules) {
  if (actionUrl(request.url()))
    return 'Crawl: URL berpotensi aksi diblokir, termasuk bila memakai GET.';
  const method = request.method();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return null;
  if (request.isNavigationRequest())
    return 'Crawl: submit/navigasi dengan metode non-GET diblokir.';
  const url = new URL(request.url());
  const rule = rules.find((r) => r.method === method && r.url === url.origin + url.pathname);
  if (!rule) return `Crawl: ${method} belum memiliki izin endpoint baca.`;
  let body;
  try {
    const raw = request.postData() || '';
    if (Buffer.byteLength(raw) > 128000) return 'Crawl: body terlalu besar untuk memeriksa izin.';
    body = JSON.parse(raw);
  } catch {
    if (rule.operationName) return 'Crawl: operationName tidak dapat diverifikasi.';
  }
  if (rule.operationName && body?.operationName !== rule.operationName)
    return 'Crawl: operationName tidak cocok dengan izin.';
  if (typeof body?.query === 'string' && /\b(mutation|subscription)\b/.test(body.query))
    return 'Crawl: operasi GraphQL mutation/subscription diblokir.';
  return null;
}
export function selectedTargets(values, scope, maxPages) {
  if (!Array.isArray(values) || values.length > maxPages)
    throw fail(`Pilih maksimal ${maxPages} URL.`);
  return [
    ...new Set(
      values.map((value) => {
        const url = normalizeUrl(value);
        if (!inScope(url.href, scope) || !crawlable(url.href, url.origin) || actionUrl(value))
          throw fail('Target crawl di luar scope atau berpotensi aksi.');
        // Keep fragments in memory for explicitly selected SPA routes; reports still redact them.
        const original = new URL(value, url.href);
        url.hash = original.hash;
        return url.href;
      }),
    ),
  ];
}
