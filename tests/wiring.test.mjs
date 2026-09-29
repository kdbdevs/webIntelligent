import test from 'node:test';
import assert from 'node:assert/strict';
import { SourceCatalog, requestParameters, sanitizeVisuals } from '../server/wiring.mjs';
import { summarizeBody } from '../server/safety.mjs';

test('source identity does not merge redacted URLs or expose data/blob payloads', () => {
  const catalog = new SourceCatalog(),
    other = new SourceCatalog();
  const a = catalog.source('https://cdn.test/photo?token=first'),
    b = catalog.source('https://cdn.test/photo?token=second');
  assert.equal(a.url, b.url);
  assert.notEqual(a.key, b.key);
  assert.equal(
    a.requestKey,
    catalog.source('https://cdn.test/photo?token=first#symbol').requestKey,
  );
  assert.notEqual(a.key, other.source('https://cdn.test/photo?token=first').key);
  assert(!JSON.stringify(a).includes('first'));
  const data = catalog.source('data:image/svg+xml,<svg onload="secret()"/>');
  assert.equal(data.kind, 'data');
  assert.equal(data.requestKey, null);
  assert(!JSON.stringify(data).includes('onload'));
  const blob = catalog.source('blob:https://cdn.test/secret-creator-id');
  assert.match(blob.creator, /unknown/);
  assert.equal(blob.requestKey, null);
  assert(!JSON.stringify(blob).includes('secret-creator-id'));
  const omitted = catalog.source('wi-truncated:data:capture:1');
  assert.equal(omitted.kind, 'data');
  assert.equal(omitted.requestKey, null);
  assert.equal(omitted.truncated, true);
});

test('parameter locations/types are observed without guessing path schema or storing values', () => {
  const json = requestParameters({
    queryParameters: ['id'],
    body: summarizeBody(
      '{"email":"private@example.test","profile":{"age":42}}',
      'application/json',
    ),
  });
  assert.deepEqual(
    json.map((p) => [p.name, p.type, p.location]),
    [
      ['id', 'string', 'query'],
      ['email', 'string', 'JSON body'],
      ['profile.age', 'number', 'JSON body'],
    ],
  );
  assert(!JSON.stringify(json).includes('private@example'));
  const form = requestParameters({
    queryParameters: [],
    body: summarizeBody('email=secret&password=hidden', 'application/x-www-form-urlencoded'),
  });
  assert(form.every((p) => p.location === 'form body' && p.value === '[omitted]'));
});

test('nested CSS and resource timing sources are sanitized before persistence', () => {
  const raw = {
    documentId: 'doc',
    sheets: [{ source: 'https://cdn.test/style?token=hidden' }],
    usages: [
      {
        elementId: 'el',
        url: 'https://cdn.test/img?token=hidden',
        rules: [
          { url: 'https://cdn.test/other?key=hidden', source: 'https://cdn.test/style?key=hidden' },
        ],
        fontFaces: [
          {
            source: 'https://cdn.test/fontcss?key=hidden',
            sources: ['https://cdn.test/font?key=hidden'],
          },
        ],
      },
    ],
    performanceEntries: [{ url: 'https://cdn.test/img?token=hidden' }],
  };
  assert(!JSON.stringify(sanitizeVisuals(raw, new SourceCatalog())).includes('hidden'));
});
