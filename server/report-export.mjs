import { randomBytes, createCipheriv } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { ReportService, shareReport } from './reporting.mjs';
import { renderReport, renderPdf } from './report-render.mjs';
import { digest, fail } from './evidence.mjs';
import {
  EvidenceReader,
  uniqueIds,
  saveRecord,
  stampRecord,
  REPORT_LIMITS,
  INTEGRITY_NOTE,
} from './report-common.mjs';
export async function exportReport(store, caseId, id, input) {
  const report = new ReportService(store).get(caseId, id);
  if (!['json', 'html', 'pdf', 'package'].includes(input.format))
    throw fail('Format ekspor tidak didukung.');
  const shared = shareReport(report),
    html = renderReport(shared);
  let bytes,
    mimeType,
    extension,
    keyHex = null;
  const lineage = [report.recordRef, ...shared.refs];
  if (input.format === 'json') {
    bytes = Buffer.from(JSON.stringify(shared, null, 2));
    mimeType = 'application/json';
    extension = 'json';
  } else if (input.format === 'html') {
    bytes = Buffer.from(html);
    mimeType = 'text/html';
    extension = 'html';
  } else if (input.format === 'pdf') {
    bytes = await renderPdf(html);
    mimeType = 'application/pdf';
    extension = 'pdf';
  } else {
    const files = [];
    const add = (path, bytes, mime, sourceRefs, role) =>
      files.push({ path, bytes: Buffer.from(bytes), mime, sourceRefs, role });
    add('report.json', JSON.stringify(shared, null, 2), 'application/json', lineage, 'redacted');
    add('report.html', html, 'text/html', lineage, 'redacted');
    if (input.includePdf === true)
      add('report.pdf', await renderPdf(html), 'application/pdf', lineage, 'redacted');
    add(
      'verify-package.mjs',
      await readFile(new URL('../tools/verify-package.mjs', import.meta.url)),
      'text/javascript',
      [],
      'utility',
    );
    add(
      'README.txt',
      'Verify with trusted Node.js: node verify-package.mjs package.wipkg.json [--key-file export.key] [--expected-sha256 independently-kept-digest]. The server also provides the verifier separately. Package is a JSON container; base64 files are inert until explicitly extracted. Do not execute imported artifacts. Keep the export key separately and never send it with the encrypted package. ' +
        INTEGRITY_NOTE,
      'text/plain',
      [],
      'instructions',
    );
    const reader = new EvidenceReader(store, caseId);
    if (input.originalIds?.length) {
      if (input.sensitiveConfirmed !== true)
        throw fail('Ekspor asli wajib konfirmasi eksplisit dan terenkripsi.');
      uniqueIds(input.originalIds, 12);
      let originalBytes = 0;
      const permitted = new Set(shared.refs.map((r) => r.artifactId));
      for (const source of report.snapshot.sources)
        if (source.kind === 'forensic-parse') {
          const data = reader.json(source.ref);
          permitted.add(data.originalRef.artifactId);
        }
      for (const aid of input.originalIds) {
        if (!permitted.has(aid)) throw fail('Asli harus merupakan sumber laporan terpilih.');
        const f = reader.find(aid);
        if (
          ![
            'forensic-original',
            'run-report',
            'page-extraction',
            'forensic-parse',
            'security-assessment',
            'security-review',
            'manual-validation',
            'forensic-operation',
            'case-report',
            'analysis-assistant',
            'capture-comparison',
            'capture-observations',
            'wiring-graph',
            'screenshot',
          ].includes(f.artifact.kind)
        )
          throw fail('Jenis artefak tidak diizinkan untuk ekspor asli.');
        const value = reader.read(f.ref);
        originalBytes += value.bytes.length;
        if (originalBytes > REPORT_LIMITS.originalBytes) throw fail('Batas asli 8 MiB.', 413);
        add(
          `originals/${aid}.bin`,
          value.bytes,
          'application/octet-stream',
          [f.ref],
          'explicit-sensitive-original',
        );
      }
      keyHex = randomBytes(32).toString('hex');
    }
    if (files.reduce((n, f) => n + f.bytes.length, 0) > REPORT_LIMITS.packageBytes)
      throw fail('Paket melebihi 16 MiB.', 413);
    const manifest = {
      schemaVersion: 1,
      caseId,
      reportId: id,
      reportRef: report.recordRef,
      snapshotSha256: report.snapshotSha256,
      projection: 'redacted structural report',
      originalsIncluded: !!keyHex,
      created: new Date().toISOString(),
      limitations: INTEGRITY_NOTE,
      sourceRefs: shared.refs,
      files: files.map((f) => ({
        path: f.path,
        size: f.bytes.length,
        mimeType: f.mime,
        sha256: digest(f.bytes),
        role: f.role,
        sourceRefs: f.sourceRefs,
      })),
      sourceHashMeaning:
        'References to omitted originals are baseline claims only; the local verifier checks included files, not omitted artifacts.',
    };
    bytes = Buffer.from(
      JSON.stringify({
        format: 'webintelligent-package-v1',
        manifest,
        manifestSha256: digest(JSON.stringify(manifest)),
        files: files.map((f) => ({ path: f.path, base64: f.bytes.toString('base64') })),
      }),
    );
    if (keyHex) {
      const iv = randomBytes(12),
        format = 'webintelligent-encrypted-package-v1',
        cipher = createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
      cipher.setAAD(Buffer.from(format));
      const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
      bytes = Buffer.from(
        JSON.stringify({
          format,
          algorithm: 'AES-256-GCM',
          iv: iv.toString('base64'),
          tag: cipher.getAuthTag().toString('base64'),
          ciphertextSha256: digest(ciphertext),
          ciphertext: ciphertext.toString('base64'),
        }),
      );
    }
    mimeType = 'application/json';
    extension = keyHex ? 'encrypted.wipkg.json' : 'wipkg.json';
  }
  if (bytes.length > 19 * 1024 * 1024) throw fail('Encoded export melebihi 19 MiB.', 413);
  const record = saveRecord(
    store,
    caseId,
    'report-export',
    stampRecord({
      kind: 'report-export',
      caseId,
      reportId: id,
      reportRef: report.recordRef,
      format: input.format,
      encrypted: !!keyHex,
      originalIds: input.originalIds || [],
      sha256: digest(bytes),
      size: bytes.length,
    }),
    {
      files: [
        {
          bytes,
          kind: 'report-download',
          role: keyHex ? 'extracted' : 'redacted',
          mimeType,
          redaction: keyHex
            ? 'Explicit sensitive originals inside separately keyed AES-256-GCM package; key not stored in report'
            : 'Strict structural projection; private source text and originals excluded',
        },
      ],
    },
  );
  return {
    id: record.id,
    artifact: record.outputs[0],
    sha256: digest(bytes),
    filename: `case-report-${id}.${extension}`,
    mimeType,
    keyHex,
    keyWarning: keyHex
      ? 'Key shown once. Save separately; it is not stored and cannot be recovered from this export.'
      : null,
  };
}
