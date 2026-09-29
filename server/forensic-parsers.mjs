import { createHash, createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { displayUrl } from './safety.mjs';

export const PARSER_VERSION = '1.0.0';
export const FORENSIC_LIMITS = {
  inputBytes: 8 * 1024 * 1024,
  events: 1000,
  jsonNodes: 50000,
  depth: 24,
  lines: 5000,
  columns: 100,
  mimeParts: 40,
  mimeDepth: 8,
  workerMs: 3000,
  outputBytes: 12 * 1024 * 1024,
  caseSources: 100,
  caseAnalysisBytes: 128 * 1024 * 1024,
  caseEvents: 5000,
};
export const FORMATS = ['har', 'json', 'ndjson', 'csv', 'eml', 'file'];
export const MAPPING_FIELDS = [
  'time',
  'action',
  'account',
  'url',
  'ip',
  'requestId',
  'session',
  'hash',
  'messageId',
];
export const DEFAULT_MAPPING = {
  time: 'timestamp',
  action: 'event',
  account: 'user',
  url: 'url',
  ip: 'ip',
  requestId: 'requestId',
  session: 'sessionId',
  hash: 'sha256',
  messageId: 'messageId',
};
const hash = (b) => createHash('sha256').update(b).digest('hex');
const clean = (v) =>
  String(v ?? '')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '')
    .slice(0, 500);
const scalar = (v) => ['string', 'number', 'boolean'].includes(typeof v);
const escape = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');
function offsetMinutes(zone) {
  if (zone === 'Z' || zone === 'UTC' || zone === 'GMT') return 0;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(zone || '');
  if (
    !m ||
    Number(m[2]) > 14 ||
    Number(m[3]) > 59 ||
    (Number(m[2]) === 14 && Number(m[3]) !== 0) ||
    /^-00:?00$/.test(zone)
  )
    return null;
  return (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3]));
}
export function normalizeTime(value, { zone = 'unknown', timeFormat = 'iso' } = {}) {
  const raw = scalar(value) ? clean(value) : null,
    result = {
      raw,
      zone: null,
      normalized: null,
      status: 'unknown',
      basis: 'source-declared; not independently attested',
    };
  if (raw === null || raw === '') return { ...result, reason: 'Timestamp missing' };
  if (['unix-ms', 'unix-s'].includes(timeFormat)) {
    const n = Number(raw) * (timeFormat === 'unix-s' ? 1000 : 1);
    if (!/^-?\d+(?:\.\d+)?$/.test(raw) || !Number.isFinite(n) || Math.abs(n) > 8640000000000000)
      return { ...result, status: 'invalid', reason: 'Invalid epoch' };
    return {
      ...result,
      zone: 'UTC',
      normalized: new Date(n).toISOString(),
      status: 'known-offset',
      interpretation: timeFormat,
    };
  }
  let iso = raw.trim(),
    sourceZone;
  if (timeFormat === 'rfc5322') {
    const m =
      /^(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s+([+-]\d{4}|[A-Za-z]{1,5})(?:\s*\([^()]*\))?$/.exec(
        iso,
      );
    const months = [
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];
    if (!m || !months.some((v) => v.toLowerCase() === m[2].toLowerCase()))
      return {
        ...result,
        status: 'ambiguous',
        reason: 'Unsupported/ambiguous email date syntax; no host-timezone guess',
      };
    sourceZone = m[7];
    const month = months.findIndex((v) => v.toLowerCase() === m[2].toLowerCase()) + 1;
    iso = `${m[3]}-${String(month).padStart(2, '0')}-${m[1].padStart(2, '0')}T${m[4]}:${m[5]}:${m[6] || '00'}`;
  }
  const m =
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})?$/.exec(
      iso,
    );
  if (!m)
    return {
      ...result,
      status: 'ambiguous',
      reason:
        'Expected ISO datetime with seconds or explicit epoch format; date-only/locale dates are not guessed',
    };
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  if (
    y < 100 ||
    mo < 1 ||
    mo > 12 ||
    d < 1 ||
    d > new Date(Date.UTC(y, mo, 0)).getUTCDate() ||
    h > 23 ||
    mi > 59 ||
    s > 59
  )
    return {
      ...result,
      status: 'invalid',
      reason: 'Invalid calendar/time or unsupported leap second',
    };
  const declared = sourceZone || m[8];
  const applied = declared || zone,
    unknownLocalOffset = /^-00:?00$/.test(declared || ''),
    offset = unknownLocalOffset ? 0 : offsetMinutes(applied);
  if (offset === null)
    return {
      ...result,
      zone: declared || null,
      status: 'ambiguous',
      reason: 'Timezone missing or unsupported abbreviation; no host-timezone guess',
    };
  const milliseconds = Number((m[7] || '.0').slice(1).padEnd(3, '0').slice(0, 3));
  return {
    ...result,
    zone: declared || null,
    assumedZone: declared ? null : zone,
    normalized: new Date(
      Date.UTC(y, mo - 1, d, h, mi, s, milliseconds) - offset * 60000,
    ).toISOString(),
    status: unknownLocalOffset
      ? 'unknown-local-offset'
      : declared
        ? 'known-offset'
        : 'assumed-zone',
    ...(unknownLocalOffset
      ? {
          reason:
            'Source states UTC instant (-0000/-00:00), but local timezone is unknown; RFC 5322 / RFC 3339 convention',
        }
      : {}),
    precision:
      m[7]?.length > 4
        ? 'Sub-millisecond precision retained in raw; display truncated to milliseconds'
        : 'milliseconds or seconds',
  };
}
export function validateOptions(input = {}, internal = false) {
  const format = input.format || 'file';
  if (![...FORMATS, ...(internal ? ['web-capture'] : [])].includes(format))
    throw new Error('Unsupported format');
  const zone = input.zone || 'unknown';
  if (zone !== 'unknown' && offsetMinutes(zone) === null)
    throw new Error('Timezone must be unknown, UTC, Z or a fixed ±HH:MM offset');
  const timeFormat = input.timeFormat || 'iso';
  if (!['iso', 'unix-ms', 'unix-s'].includes(timeFormat))
    throw new Error('Unsupported timestamp format');
  const mapping = input.mapping || DEFAULT_MAPPING;
  if (
    !mapping ||
    Array.isArray(mapping) ||
    typeof mapping !== 'object' ||
    Object.keys(mapping).some((k) => !MAPPING_FIELDS.includes(k)) ||
    Object.values(mapping).some((v) => typeof v !== 'string' || v.length > 120)
  )
    throw new Error('Invalid field/column mapping');
  const namespace = typeof input.namespace === 'string' ? input.namespace.trim() : '';
  if (namespace.length > 160 || /[\u0000-\u001f]/.test(namespace))
    throw new Error('Invalid source namespace');
  const delimiter = input.delimiter || ',';
  if (![',', ';', '\t'].includes(delimiter))
    throw new Error('Delimiter must be comma, semicolon or tab');
  const claimedCollectedAt = input.claimedCollectedAt || '';
  if (typeof claimedCollectedAt !== 'string' || claimedCollectedAt.length > 120)
    throw new Error('Invalid claimed collection time');
  return {
    format,
    zone,
    timeFormat,
    mapping: { ...mapping },
    namespace,
    delimiter,
    claimedCollectedAt,
  };
}
function parseJson(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(
      'Malformed JSON; original preserved, parser error text omitted to avoid exposing values',
    );
  }
  const stack = [[data, 0]];
  let count = 0;
  while (stack.length) {
    const [v, depth] = stack.pop();
    if (++count > FORENSIC_LIMITS.jsonNodes || depth > FORENSIC_LIMITS.depth)
      throw new Error('JSON node/depth limit exceeded');
    if (v && typeof v === 'object')
      for (const item of Object.values(v)) stack.push([item, depth + 1]);
  }
  return data;
}
export function parseCsv(text, delimiter = ',') {
  const rows = [];
  let values = [],
    value = '',
    quoted = false,
    afterQuote = false,
    line = 1,
    start = 1;
  const finishField = () => {
    values.push(value);
    value = '';
    afterQuote = false;
    if (values.length > FORENSIC_LIMITS.columns) throw new Error('CSV column limit exceeded');
  };
  const finishRow = () => {
    finishField();
    rows.push({ values, lineStart: start, lineEnd: line });
    values = [];
    start = line + 1;
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          value += '"';
          i++;
        } else {
          quoted = false;
          afterQuote = true;
        }
      } else {
        value += ch;
        if (ch === '\n') line++;
      }
    } else if (ch === '"') {
      if (value || afterQuote) throw new Error('Malformed CSV quoting');
      quoted = true;
    } else if (ch === delimiter) finishField();
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      finishRow();
      line++;
    } else {
      if (afterQuote) throw new Error('Unexpected text after quoted CSV field');
      value += ch;
    }
    if (
      line > FORENSIC_LIMITS.lines ||
      rows.length > FORENSIC_LIMITS.lines ||
      value.length > 100000
    )
      throw new Error('CSV line/cell limit exceeded');
  }
  if (quoted) throw new Error('Unterminated CSV quote');
  if (value || values.length || afterQuote) finishRow();
  if (!rows.length) throw new Error('Empty CSV');
  const headers = rows.shift().values;
  if (new Set(headers).size !== headers.length || headers.some((h) => !h || h.length > 120))
    throw new Error('CSV header names must be unique, nonempty and <=120 characters');
  return { headers, rows };
}
function pathValue(record, key) {
  const parts = key.startsWith('/')
    ? key
        .slice(1)
        .split('/')
        .map((k) => k.replace(/~1/g, '/').replace(/~0/g, '~'))
    : [key];
  let v = record;
  for (const p of parts) {
    if (!v || typeof v !== 'object' || !Object.hasOwn(v, p)) return undefined;
    v = v[p];
  }
  return v;
}
export function parseArtifact(bytes, input = {}, context = {}) {
  bytes = Buffer.from(bytes);
  if (bytes.length > FORENSIC_LIMITS.inputBytes) throw new Error('Input byte limit exceeded');
  const options = validateOptions(input, true),
    parser = { id: `wi-${options.format}`, version: PARSER_VERSION },
    events = [],
    gaps = [],
    redactions = new Set();
  const keyed = (kind, value) =>
    createHmac('sha256', Buffer.from(context.correlationKey || 'fixture-only'))
      .update(`${kind}:${value}`)
      .digest('hex');
  const limitedText = (v) =>
    clean(v).replace(
      /((?:password|passwd|token|secret|authorization|cookie)\s*[:=]\s*)[^\s,;]+/gi,
      '$1[omitted]',
    );
  const add = (type, time, location, fields = [], basis = 'imported-source-claim') => {
    if (events.length >= FORENSIC_LIMITS.events) {
      if (!gaps.includes('Event limit reached')) gaps.push('Event limit reached');
      return null;
    }
    const event = {
      localId: `e${events.length + 1}`,
      type,
      basis,
      time: normalizeTime(time, {
        ...options,
        timeFormat: options.format === 'har' ? 'iso' : options.timeFormat,
      }),
      provenance: { parser, location },
      fields: [],
      entities: [],
    };
    events.push(event);
    for (const f of fields) field(event, ...f);
    return event;
  };
  function field(event, name, value, location, kind = null, method = 'selected-field-extraction') {
    if (!event || !scalar(value) || String(value).length > 8192) {
      if (value != null) gaps.push(`Skipped unsupported/oversized ${name} field`);
      return;
    }
    if (String(value).length > 500)
      gaps.push(
        'Selected field display truncated at 500 characters; full bytes remain in original',
      );
    const original = String(value),
      item = { name, value: limitedText(value), provenance: { parser, location, method } };
    if (item.value !== original)
      redactions.add(
        'Control characters, recognized secret assignments and long field display values omitted/truncated',
      );
    if (kind === 'url') {
      try {
        const u = new URL(original);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
        const shown = displayUrl(u.href);
        if (shown.length > 500) gaps.push('URL display truncated at 500 characters');
        item.value = shown.slice(0, 500);
        redactions.add('URL credentials/query values/fragments');
        event.entities.push({
          kind: 'url',
          label: item.value,
          matchKey: keyed('url', u.href),
          field: name,
          method: 'exact URL before redaction; equality does not prove identical activity',
        });
        event.entities.push({
          kind: 'domain',
          label: u.hostname.toLowerCase(),
          matchKey: keyed('domain', u.hostname.toLowerCase()),
          field: name,
          method: 'hostname extracted from URL; not ownership or identity',
        });
      } catch {
        item.value = '[invalid/non-HTTP URL omitted]';
        gaps.push('Unsupported URL field');
      }
    } else if (kind === 'ip') {
      if (isIP(original)) {
        const normalized = ipaddr.process(original).toNormalizedString();
        item.value = normalized;
        event.entities.push({
          kind,
          label: normalized,
          matchKey: keyed(kind, normalized),
          field: name,
          method: 'same normalized IP claim; NAT/shared infrastructure possible',
        });
      } else {
        item.value = '[invalid IP]';
      }
    } else if (kind === 'hash') {
      if (/^[a-f\d]{64}$/i.test(original))
        event.entities.push({
          kind,
          label: original.toLowerCase(),
          matchKey: keyed(kind, original.toLowerCase()),
          field: name,
          method:
            method === 'computed-SHA256'
              ? 'computed SHA-256 of these bytes'
              : 'source-declared SHA-256; bytes not available to verify claim',
        });
      else item.value = '[invalid SHA-256]';
    } else if (kind && original) {
      const namespace = ['request', 'session-claim'].includes(kind)
        ? options.namespace || `source:${context.sourceId}`
        : '';
      const key = keyed(kind, namespace + ':' + original);
      if (kind === 'session-claim') {
        item.value = `session-claim:${key.slice(0, 12)}`;
        redactions.add('Session ID values replaced with case-keyed opaque references');
      }
      event.entities.push({
        kind,
        label: item.value,
        matchKey: key,
        field: name,
        method:
          kind === 'account'
            ? 'same account string claimed by sources; identity unverified'
            : `same ${kind} value${namespace ? ' within declared namespace' : ''}; not proof of cause, delivery or authentication`,
      });
    }
    event.fields.push(item);
  }
  const text = () => {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/^\uFEFF/, '');
    } catch {
      throw new Error('Text format requires UTF-8; original bytes preserved');
    }
  };
  const logRecord = (record, location, fieldLocation) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      gaps.push('Skipped non-object log row');
      return;
    }
    const get = (key) =>
      options.mapping[key]
        ? options.format === 'csv'
          ? record[options.mapping[key]]
          : pathValue(record, options.mapping[key])
        : undefined;
    const event = add('log-event', get('time'), location);
    if (!MAPPING_FIELDS.some((key) => get(key) !== undefined))
      gaps.push('Log row has no mapped fields; reparse with explicit mapping');
    for (const key of MAPPING_FIELDS) {
      const value = get(key);
      if (value !== undefined)
        field(
          event,
          key,
          value,
          fieldLocation(options.mapping[key]),
          {
            account: 'account',
            url: 'url',
            ip: 'ip',
            requestId: 'request',
            session: 'session-claim',
            hash: 'hash',
            messageId: 'email',
          }[key],
        );
    }
  };
  if (options.format === 'file') {
    const e = add('file-metadata', null, { kind: 'bytes', start: 0, end: bytes.length });
    field(
      e,
      'sha256',
      hash(bytes),
      { kind: 'bytes', start: 0, end: bytes.length },
      'hash',
      'computed-SHA256',
    );
    field(
      e,
      'size',
      bytes.length,
      { kind: 'bytes', start: 0, end: bytes.length },
      null,
      'byte-count',
    );
    gaps.push(
      'General file: metadata/hash only; no document, archive, executable or macro decoding',
    );
  } else if (['json', 'ndjson', 'csv'].includes(options.format)) {
    redactions.add('Only explicitly mapped fields extracted; other fields/payloads omitted');
    if (options.format === 'json') {
      const data = parseJson(text()),
        list = Array.isArray(data) ? data : data?.events;
      if (!Array.isArray(list))
        throw new Error(
          'JSON logs require an array of objects or {events:[...]} with explicit field mapping',
        );
      for (const [i, r] of list.slice(0, FORENSIC_LIMITS.events).entries()) {
        const pointer = (Array.isArray(data) ? '' : '/events') + '/' + i;
        logRecord(r, { kind: 'json-pointer', pointer }, (key) => ({
          kind: 'json-pointer',
          pointer: pointer + (key.startsWith('/') ? key : '/' + escape(key)),
        }));
      }
      if (list.length > FORENSIC_LIMITS.events) gaps.push('Event limit reached');
    } else if (options.format === 'ndjson') {
      const lines = text().split(/\r?\n/);
      if (lines.length > FORENSIC_LIMITS.lines) gaps.push('Line limit reached');
      for (const [i, line] of lines.slice(0, FORENSIC_LIMITS.lines).entries()) {
        if (!line.trim()) continue;
        try {
          logRecord(parseJson(line), { kind: 'line', line: i + 1 }, (key) => ({
            kind: 'line',
            line: i + 1,
            pointer: key.startsWith('/') ? key : '/' + escape(key),
          }));
        } catch {
          gaps.push(`Line ${i + 1}: malformed or bounded JSON skipped`);
        }
        if (events.length >= FORENSIC_LIMITS.events) {
          gaps.push('Event limit reached');
          break;
        }
      }
    } else {
      const { headers, rows } = parseCsv(text(), options.delimiter);
      if (
        Object.values(options.mapping)
          .filter(Boolean)
          .some((key) => !headers.includes(key))
      )
        gaps.push('Some mapped columns absent; missing values remain unknown');
      if (!Object.values(options.mapping).some((key) => headers.includes(key)))
        throw new Error('CSV mapping matches no header; reparse with explicit column names');
      for (const row of rows.slice(0, FORENSIC_LIMITS.events)) {
        if (row.values.length !== headers.length) {
          gaps.push(`CSV row at line ${row.lineStart}: inconsistent column count skipped`);
          continue;
        }
        const r = Object.fromEntries(headers.map((h, i) => [h, row.values[i]]));
        logRecord(
          r,
          { kind: 'csv-row', lineStart: row.lineStart, lineEnd: row.lineEnd },
          (key) => ({
            kind: 'csv-cell',
            lineStart: row.lineStart,
            lineEnd: row.lineEnd,
            column: headers.indexOf(key) + 1,
            header: key,
          }),
        );
      }
      if (rows.length > FORENSIC_LIMITS.events) gaps.push('Event limit reached');
    }
  } else if (options.format === 'har') {
    const har = parseJson(text());
    if (har?.log?.version !== '1.2' || !Array.isArray(har.log.entries))
      throw new Error('Supported HAR profile is log.version 1.2 with log.entries array');
    redactions.add(
      'HAR request/response headers except X-Request-ID, cookies, payloads, content bodies and query values omitted',
    );
    for (const [i, r] of har.log.entries.slice(0, FORENSIC_LIMITS.events).entries()) {
      const p = `/log/entries/${i}`,
        loc = (key) => ({ kind: 'json-pointer', pointer: p + key });
      if (!r?.request || !r?.response) {
        gaps.push(`HAR entry ${i}: missing request/response`);
        continue;
      }
      const e = add('web-request', r.startedDateTime, loc(''));
      for (const [name, value, ptr, kind] of [
        ['time', r.startedDateTime, '/startedDateTime'],
        ['url', r.request.url, '/request/url', 'url'],
        ['method', r.request.method, '/request/method'],
        ['status', r.response.status, '/response/status'],
        ['ip', r.serverIPAddress, '/serverIPAddress', 'ip'],
        ['durationMs', r.time, '/time'],
      ])
        if (value !== undefined) field(e, name, value, loc(ptr), kind);
      const hi = r.request.headers?.findIndex(
        (h) => String(h.name).toLowerCase() === 'x-request-id',
      );
      if (hi >= 0)
        field(
          e,
          'requestId',
          r.request.headers[hi].value,
          loc(`/request/headers/${hi}/value`),
          'request',
        );
    }
    if (har.log.entries.length > FORENSIC_LIMITS.events) gaps.push('Event limit reached');
  } else if (options.format === 'web-capture') {
    const report = parseJson(text());
    if (!Array.isArray(report.requests)) throw new Error('Unsupported internal capture report');
    for (const [i, r] of report.requests.slice(0, FORENSIC_LIMITS.events).entries()) {
      const loc = (key) => ({ kind: 'json-pointer', pointer: `/requests/${i}${key}` });
      const e = add(
        'browser-request',
        null,
        loc(''),
        [],
        context.legacy ? 'legacy-source-claim' : 'browser-observation-at-capture',
      );
      e.time = normalizeTime(r.startedAt, { timeFormat: 'unix-ms' });
      e.time.basis = context.legacy
        ? 'legacy claimed timestamp; import did not verify historical time'
        : 'collector clock at request observation; not historical reconstruction';
      for (const [key, kind] of [['url', 'url'], ['method'], ['status'], ['id', 'request']])
        if (r[key] != null) field(e, key, r[key], loc('/' + key), kind);
      if (context.browserSession && !context.legacy) {
        field(
          e,
          'collectorSession',
          context.sourceRunId,
          { kind: 'collector-context', pointer: '/sessionInfo' },
          null,
          'same BrowserContext recorded by collector; not authenticated identity',
        );
        e.entities.push({
          kind: 'session',
          label: `BrowserContext ${context.sourceRunId.slice(0, 8)}`,
          matchKey: keyed('collector-session', context.sourceRunId),
          field: 'collectorSession',
          method:
            'observed collector context continuity; authentication and human identity unproven',
        });
      }
    }
    gaps.push(
      'Capture is an observation at collector time, not a reconstruction of earlier website activity; original capture gaps still apply',
    );
    if (report.requests.length > FORENSIC_LIMITS.events) gaps.push('Event limit reached');
  } else if (options.format === 'eml') {
    const source = bytes.toString('latin1');
    let partCount = 0;
    function mime(part, path = '1', depth = 0) {
      if (++partCount > FORENSIC_LIMITS.mimeParts || depth > FORENSIC_LIMITS.mimeDepth) {
        gaps.push('MIME depth/part limit reached');
        return;
      }
      const split = /\r?\n\r?\n/.exec(part);
      if (!split) {
        gaps.push(`MIME ${path}: missing header/body separator`);
        return;
      }
      const head = part.slice(0, split.index);
      if (head.length > 65536) throw new Error('MIME header size limit exceeded');
      const lines = head.split(/\r?\n/),
        headers = [];
      for (const [i, l] of lines.entries()) {
        if (/^[ \t]/.test(l) && headers.length) {
          headers.at(-1).value += ' ' + l.trim();
          headers.at(-1).lineEnd = i + 1;
        } else {
          const m = /^([!-9;-~]+):\s*(.*)$/.exec(l);
          if (m)
            headers.push({
              name: m[1].toLowerCase(),
              value: m[2],
              lineStart: i + 1,
              lineEnd: i + 1,
            });
          else gaps.push(`MIME ${path}: malformed header skipped`);
        }
      }
      if (/[^\x00-\x7f]/.test(head))
        gaps.push(
          `MIME ${path}: non-ASCII header encoding unsupported; displayed as byte-preserving Latin-1 metadata, inspect original before interpretation`,
        );
      const get = (name) => headers.find((h) => h.name === name)?.value || '',
        where = (name) => ({
          kind: 'mime-header',
          part: path,
          name,
          lineStart: headers.find((h) => h.name === name)?.lineStart,
          lineEnd: headers.find((h) => h.name === name)?.lineEnd,
        });
      if (new Set(headers.map((h) => h.name)).size !== headers.length)
        gaps.push(
          `MIME ${path}: duplicate headers; first occurrence selected, no authenticity inference`,
        );
      const contentType = get('content-type') || 'text/plain',
        body = part.slice(split.index + split[0].length);
      if (path === '1') {
        const e = add('email-message', null, { kind: 'mime-part', part: path });
        e.time = normalizeTime(get('date'), { timeFormat: 'rfc5322' });
        for (const name of ['date', 'subject', 'message-id', 'in-reply-to', 'from', 'to']) {
          const value = get(name);
          if (!value) continue;
          if (['from', 'to'].includes(name)) {
            const mailboxes =
              value.match(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [];
            if (mailboxes.length > 10)
              gaps.push(`MIME ${path}: mailbox extraction truncated at 10 addresses`);
            for (const [i, mail] of mailboxes.slice(0, 10).entries())
              field(e, `${name}-${i + 1}`, mail, where(name), 'account');
          } else
            field(
              e,
              name,
              value,
              where(name),
              ['message-id', 'in-reply-to'].includes(name) ? 'email' : null,
            );
        }
        redactions.add(
          'Email unselected headers/body text omitted; From/Date/Message-ID are unverified source claims',
        );
      }
      if (/^multipart\//i.test(contentType)) {
        const boundary = /boundary\s*=\s*(?:"([^"\r\n]{1,200})"|([^;\s]{1,200}))/i.exec(
            contentType,
          ),
          b = boundary?.[1] || boundary?.[2];
        if (!b) {
          gaps.push(`MIME ${path}: boundary missing`);
          return;
        }
        // Keep original part bytes/line endings; the newline before a MIME boundary belongs to the delimiter.
        const escaped = b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const boundaryLine = new RegExp('(?:^|\\r?\\n)--' + escaped + '(--)?(?:\\r?\\n|$)', 'g');
        const parts = [];
        let begin = null,
          closed = false;
        for (const marker of body.matchAll(boundaryLine)) {
          if (begin !== null) parts.push(body.slice(begin, marker.index));
          begin = marker.index + marker[0].length;
          if (marker[1]) {
            closed = true;
            break;
          }
        }
        if (!closed) {
          gaps.push(`MIME ${path}: missing closing boundary`);
          if (begin !== null) parts.push(body.slice(begin));
        }
        for (const [i, p] of parts.slice(0, FORENSIC_LIMITS.mimeParts).entries())
          mime(p, `${path}.${i + 1}`, depth + 1);
        if (parts.length > FORENSIC_LIMITS.mimeParts) gaps.push('MIME part limit reached');
        return;
      }
      let decoded;
      const encoding = get('content-transfer-encoding').toLowerCase();
      if (encoding === 'base64') {
        const compact = body.replace(/\s/g, '');
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4) {
          gaps.push(`MIME ${path}: invalid base64 skipped`);
          return;
        }
        decoded = Buffer.from(compact, 'base64');
      } else if (encoding === 'quoted-printable')
        decoded = Buffer.from(
          body
            .replace(/=\r?\n/g, '')
            .replace(/=([a-f\d]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))),
          'latin1',
        );
      else if (!encoding || ['7bit', '8bit', 'binary'].includes(encoding))
        decoded = Buffer.from(body, 'latin1');
      else {
        gaps.push(`MIME ${path}: unsupported transfer encoding`);
        return;
      }
      const e = add('mime-part', null, { kind: 'mime-part', part: path });
      field(e, 'contentType', contentType.split(';')[0], where('content-type'));
      field(
        e,
        'decodedSize',
        decoded.length,
        { kind: 'mime-body', part: path },
        null,
        'decoded-byte-count',
      );
      field(
        e,
        'sha256',
        hash(decoded),
        { kind: 'mime-body', part: path },
        'hash',
        'computed-SHA256',
      );
      const filename = /filename\s*=\s*(?:"([^"\r\n]*)"|([^;\s]+))/i.exec(
        get('content-disposition'),
      );
      if (filename)
        field(
          e,
          'filename',
          filename[1] || filename[2],
          where('content-disposition'),
          null,
          'declared filename only; never used as a filesystem path',
        );
      if (/^text\/(?:plain|html)(?:;|$)/i.test(contentType)) {
        const charset =
          /charset\s*=\s*"?([^;"\s]+)/i.exec(contentType)?.[1]?.toLowerCase() || 'us-ascii';
        if (!['utf-8', 'us-ascii', 'ascii'].includes(charset)) {
          gaps.push(`MIME ${path}: unsupported charset; no text interpretation`);
          return;
        }
        let decodedText;
        try {
          decodedText = new TextDecoder('utf-8', { fatal: true }).decode(decoded);
        } catch {
          gaps.push(`MIME ${path}: invalid UTF-8 text`);
          return;
        }
        const urls = [...decodedText.slice(0, 100000).matchAll(/https?:\/\/[^\s<>"']+/g)];
        if (urls.length > 10) gaps.push(`MIME ${path}: URL declarations truncated at 10`);
        for (const [i, match] of urls.slice(0, 10).entries())
          field(
            e,
            `declaredUrl-${i + 1}`,
            match[0],
            { kind: 'mime-body', part: path, decodedCharacterOffset: match.index },
            'url',
            'text URL declaration; not a visited or fetched resource',
          );
        if (decodedText.length > 100000)
          gaps.push(`MIME ${path}: URL extraction truncated at 100000 decoded characters`);
      }
      redactions.add(
        'MIME body/HTML/attachment bytes not included in parsed preview; attachment hash is of decoded bytes, not the .eml source',
      );
    }
    mime(source);
    if (!events.length) throw new Error('No supported email headers/MIME parts found');
    gaps.push(
      'Limited MIME profile: no DKIM/signature validation, full RFC address grammar, RFC2047/2231 decoding, nested message/rfc822 or archive extraction',
    );
  }
  if (['json', 'ndjson', 'har', 'web-capture'].includes(options.format))
    gaps.push(
      'JSON duplicate keys are not detected; native JSON last-key interpretation is used. Original bytes retained for review',
    );
  const uniqueGaps = [...new Set(gaps)].slice(0, 100);
  return {
    schemaVersion: 1,
    parser,
    options,
    events,
    coverage: {
      events: events.length,
      status: gaps.some((g) =>
        /limit|missing|malformed|invalid|skipped|unsupported|absent|truncated/i.test(g),
      )
        ? 'partial'
        : 'parsed',
      gaps: uniqueGaps,
      gapCount: gaps.length,
    },
    redactions: [...redactions],
    limits: FORENSIC_LIMITS,
    sourceCollectionTime: normalizeTime(options.claimedCollectedAt, { zone: options.zone }),
    limitations: [
      'Hash verifies a local/import baseline, not historical integrity, source authenticity or clock accuracy',
      'Imported time/account/request/email/session statements remain source claims; unknown fields were not reconstructed',
    ],
  };
}
