#!/usr/bin/env node
// Standalone verifier: Node built-ins only, no extraction, network, or execution of package content.
import { readFileSync, statSync } from 'node:fs';
import { createHash, createDecipheriv } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const hash = (b) => createHash('sha256').update(b).digest('hex');
const max = 32 * 1024 * 1024;
export function verifyPackage(input, key) {
  if (input.length > max) throw Error('Package size limit');
  let p = JSON.parse(input);
  if (p.format === 'webintelligent-encrypted-package-v1') {
    if (!key || key.length !== 32) throw Error('32-byte key required');
    const ciphertext = Buffer.from(p.ciphertext, 'base64');
    if (hash(ciphertext) !== p.ciphertextSha256) throw Error('Ciphertext hash mismatch');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(p.iv, 'base64'));
    decipher.setAAD(Buffer.from(p.format));
    decipher.setAuthTag(Buffer.from(p.tag, 'base64'));
    p = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  }
  if (
    p.format !== 'webintelligent-package-v1' ||
    !p.manifest ||
    !Array.isArray(p.files) ||
    p.files.length > 64
  )
    throw Error('Unsupported package');
  if (hash(JSON.stringify(p.manifest)) !== p.manifestSha256) throw Error('Manifest hash mismatch');
  if (p.manifest.files.length !== p.files.length) throw Error('File count mismatch');
  const seen = new Set();
  let bytes = 0;
  for (const f of p.files) {
    if (
      typeof f.path !== 'string' ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,180}$/.test(f.path) ||
      f.path.split('/').some((x) => !x || x === '.' || x === '..') ||
      seen.has(f.path)
    )
      throw Error('Unsafe or duplicate path');
    seen.add(f.path);
    if (
      typeof f.base64 !== 'string' ||
      f.base64.length % 4 !== 0 ||
      /[^A-Za-z0-9+/=]/.test(f.base64)
    )
      throw Error('Invalid base64');
    const b = Buffer.from(f.base64, 'base64');
    if (b.toString('base64') !== f.base64) throw Error('Noncanonical base64');
    bytes += b.length;
    if (bytes > 16 * 1024 * 1024) throw Error('Decoded size limit');
    const entries = p.manifest.files.filter((x) => x.path === f.path);
    if (entries.length !== 1 || entries[0].size !== b.length || entries[0].sha256 !== hash(b))
      throw Error(`File hash/size mismatch: ${f.path}`);
  }
  return {
    ok: true,
    files: p.files.length,
    bytes,
    manifestSha256: p.manifestSha256,
    note: 'Only included bytes verified against supplied manifest. No authenticity, trusted timestamp or legal admissibility attested. An attacker replacing package and hashes remains undetected without an independently trusted digest.',
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2),
      file = args[0];
    if (!file)
      throw Error(
        'Usage: node verify-package.mjs package.json [--key-file key.txt] [--expected-sha256 HASH]',
      );
    if (statSync(file).size > max) throw Error('Package size limit');
    const bytes = readFileSync(file);
    const ki = args.indexOf('--key-file'),
      ei = args.indexOf('--expected-sha256');
    if (ei >= 0 && hash(bytes) !== args[ei + 1]) throw Error('Expected package hash mismatch');
    const key = ki >= 0 ? Buffer.from(readFileSync(args[ki + 1], 'utf8').trim(), 'hex') : undefined;
    console.log(JSON.stringify(verifyPackage(bytes, key), null, 2));
  } catch (e) {
    console.error('Verification failed:', e.message);
    process.exitCode = 1;
  }
}
