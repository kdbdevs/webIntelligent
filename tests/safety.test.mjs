import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeUrl,
  allowedAddress,
  validateDestination,
  displayUrl,
  summarizeBody,
  crawlable,
  cleanStack,
} from '../server/safety.mjs';

test('reject unsupported protocols, credentials and blank URLs', () => {
  assert.equal(normalizeUrl('example.com').href, 'https://example.com/');
  assert.equal(normalizeUrl('localhost:8787/demo').href, 'http://localhost:8787/demo');
  for (const input of [
    '',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'https://name:password@example.com',
  ])
    assert.throws(() => normalizeUrl(input));
});
test('prevent private / reserved address access; localhost requires explicit option', async () => {
  for (const address of [
    '127.0.0.1',
    '10.0.0.1',
    '192.168.1.2',
    '169.254.169.254',
    '0.0.0.0',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
  ])
    assert.equal(allowedAddress(address), false, address);
  assert.equal(allowedAddress('127.0.0.1', true), true);
  assert.equal(allowedAddress('169.254.169.254', true), false);
  assert.equal(allowedAddress('8.8.8.8'), true);
  await assert.rejects(validateDestination('http://127.0.0.1:8080'));
  assert.equal((await validateDestination('http://127.0.0.1:8080', true)).hostname, '127.0.0.1');
});
test('parameter reports contain keys/types, never input values', () => {
  const report = summarizeBody(
    JSON.stringify({
      email: 'secret@example.com',
      password: 'PASSWORD_MUST_NOT_LEAK',
      nested: { token: 'SECRET_TOKEN' },
      array: [true],
    }),
    'application/json',
  );
  assert(report.fields.some((f) => f.name === 'password' && f.type === 'string'));
  assert(report.fields.some((f) => f.name === 'nested.token'));
  assert(!JSON.stringify(report).includes('SECRET_TOKEN'));
  assert(!JSON.stringify(report).includes('PASSWORD_MUST_NOT_LEAK'));
  assert(!JSON.stringify(report).includes('secret@example.com'));
  assert.deepEqual(
    summarizeBody(
      'email=private%40example.com&password=secret',
      'application/x-www-form-urlencoded',
    ).fields,
    [
      { name: 'email', type: 'string' },
      { name: 'password', type: 'string' },
    ],
  );
});
test('URLs and initiator stacks redact query values', () => {
  assert(!displayUrl('https://example.com/path?token=SECRET&foo=BAR#private').includes('SECRET'));
  assert(!cleanStack('at send (https://example.com/a.js?token=SECRET:1:2)').includes('SECRET'));
});
test('crawler stays on origin and skips obvious state-changing links and files', () => {
  assert(crawlable('https://example.com/docs', 'https://example.com'));
  for (const u of [
    'https://other.com/docs',
    'https://example.com/logout',
    'https://example.com/delete/1',
    'https://example.com/file.pdf',
    'mailto:hi@example.com',
  ])
    assert.equal(crawlable(u, 'https://example.com'), false, u);
});
