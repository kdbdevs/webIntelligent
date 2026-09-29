import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

export function normalizeUrl(value) {
  if (typeof value !== 'string' || value.length > 2048)
    throw new Error('Masukkan URL yang valid (maksimal 2048 karakter).');
  const input = value.trim();
  if (!input) throw new Error('URL belum diisi.');
  const prefix = /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/i.test(input)
    ? 'http://'
    : 'https://';
  const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : `${prefix}${input}`);
  if (!['http:', 'https:'].includes(url.protocol))
    throw new Error('Hanya URL HTTP atau HTTPS yang didukung.');
  if (url.username || url.password)
    throw new Error('URL dengan username atau password tidak didukung.');
  url.hash = '';
  return url;
}

export function allowedAddress(address, allowLocal = false) {
  try {
    const parsed = ipaddr.process(address);
    return parsed.range() === 'unicast' || (allowLocal && parsed.range() === 'loopback');
  } catch {
    return false;
  }
}

export async function validateDestination(value, allowLocal = false) {
  const url = normalizeUrl(value);
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = ipaddr.isValid(hostname)
    ? [{ address: hostname }]
    : await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !allowedAddress(address, allowLocal))) {
    throw new Error(
      'Alamat privat/reserved diblokir. Aktifkan izin localhost untuk audit development lokal.',
    );
  }
  return url;
}

export function displayUrl(value) {
  try {
    const u = new URL(value);
    u.username = '';
    u.password = '';
    u.hash = '';
    for (const key of [...u.searchParams.keys()]) u.searchParams.set(key, '[redacted]');
    return u.toString();
  } catch {
    return String(value).slice(0, 500);
  }
}

export function summarizeBody(text, contentType = '') {
  if (!text) return { format: 'none', fields: [] };
  if (Buffer.byteLength(text) > 128_000)
    return { format: 'large-body', fields: [], note: 'Body terlalu besar; tidak dibaca.' };
  const fields = [];
  const add = (path, type) => {
    if (fields.length < 100) fields.push({ name: path.slice(0, 180), type });
  };
  try {
    if (contentType.includes('json')) {
      const visit = (value, path = '', depth = 0) => {
        if (depth > 6 || fields.length >= 100) return;
        if (Array.isArray(value)) {
          add(path || '(root)', 'array');
          if (value.length) visit(value[0], `${path}[]`, depth + 1);
        } else if (value !== null && typeof value === 'object')
          for (const [key, val] of Object.entries(value))
            visit(val, path ? `${path}.${key}` : key, depth + 1);
        else add(path || '(root)', value === null ? 'null' : typeof value);
      };
      visit(JSON.parse(text));
      return { format: 'JSON', fields };
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
      for (const key of new Set(new URLSearchParams(text).keys())) add(key, 'string');
      return { format: 'Form URL encoded', fields };
    }
    if (contentType.includes('multipart/form-data')) {
      for (const match of text.matchAll(/Content-Disposition:[^\r\n]*\bname="([^"]+)"([^\r\n]*)/gi))
        add(match[1], /filename=/i.test(match[2]) ? 'file' : 'string');
      return { format: 'Multipart form', fields };
    }
  } catch {
    return { format: 'unparsed', fields: [], note: 'Body tidak dapat diurai.' };
  }
  return { format: 'other', fields: [], note: 'Nilai mentah tidak disimpan.' };
}

export function crawlable(href, origin) {
  try {
    const u = normalizeUrl(href);
    return (
      u.origin === origin &&
      !/\.(pdf|zip|png|jpg|jpeg|gif|webp|svg|mp4|mp3|dmg|exe|csv|docx?)$/i.test(u.pathname) &&
      !/(?:^|[\/_?&=.-])(logout|log-out|signout|sign-out|delete|remove|unsubscribe|checkout|purchase)(?:$|[\/_?&=.-])/i.test(
        u.pathname + u.search,
      )
    );
  } catch {
    return false;
  }
}

export function cleanStack(stack) {
  return String(stack || '')
    .split('\n')
    .filter((line) => !line.includes('__wi'))
    .slice(0, 7)
    .map((line) => line.replace(/https?:\/\/[^\s)]+/g, (url) => displayUrl(url)))
    .join('\n')
    .slice(0, 2200);
}
