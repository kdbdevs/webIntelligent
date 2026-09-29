import { launchBrowser } from './audit.mjs';
import { fail } from './evidence.mjs';
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
export function renderReport(r) {
  const list = (items, fn) =>
    items.length
      ? `<ul>${items.map((x) => `<li>${fn(x)}</li>`).join('')}</ul>`
      : '<p>No selected records; not assessed.</p>';
  const refs = (rs) =>
    (rs || [])
      .map((e) => `<small>Evidence ${esc(e.artifactId)} ${esc(e.pointer)}</small>`)
      .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Case report ${esc(r.id)}</title><style>body{font:14px/1.55 system-ui,sans-serif;color:#1d2e3b;max-width:960px;margin:48px auto;padding:0 28px}h1{font-size:32px;line-height:1.2}h2{font-size:20px;border-bottom:1px solid #ccd7dc;padding-bottom:8px;margin-top:30px}header{border-top:6px solid #087f82;padding-top:20px}.status{color:#087f82;text-transform:uppercase;letter-spacing:2px;font-weight:bold}small{display:block;font:10px/1.5 ui-monospace,monospace;color:#526773;overflow-wrap:anywhere}li{margin-bottom:12px;overflow-wrap:anywhere}p{overflow-wrap:anywhere}.note{padding:16px;background:#edf5f5;border-left:3px solid #087f82}section{margin-top:24px}h2,h3{break-after:avoid}li{break-inside:avoid}@page{size:A4;margin:18mm 17mm} @media print{body{margin:0;padding:0;font-size:12px}h1{font-size:26px}h2{font-size:16px}small{font-size:10px}}</style></head><body><header><div class="status">${esc(r.status)} / version ${r.version}</div><h1>${esc(r.case.title)}</h1><p>Case ${esc(r.caseId)}<br>Report ${esc(r.id)}<br>Created ${esc(r.created.at)}</p></header><p class="note">${esc(r.redaction)}</p><p>Any shared narrative is an analyst statement, not additional source evidence.</p><section><h2>Purpose and scope</h2><p>${esc(r.case.objective)}</p><p>${esc(r.case.scope)}</p></section><section><h2>Review and snapshot</h2><p>${r.review ? 'Human review completed ' + esc(r.review.reviewedAt) + '. Reviewer: ' + esc(r.review.reviewer) : 'Draft: human review required before final.'}</p><small>Private analysis snapshot SHA-256: ${esc(r.snapshotSha256)}</small><p>This report freezes selected source versions. Later analysis requires a new version.</p></section><section><h2>Sources and collection methods</h2>${list(r.sources, (s) => `${esc(s.kind)} / ${esc(s.role)} / ${s.size} bytes / ${esc(s.status)}<br>${esc(s.method)}; collector ${esc(s.collector?.name)} ${esc(s.collector?.version)}${s.parser ? '; parser ' + esc(JSON.stringify(s.parser)) : ''}<br>Coverage: ${esc(s.coverageSummary?.sourceStatus)}; pages ${s.coverageSummary?.visitedPages ?? 'not applicable/unknown'}; failed requests ${s.coverageSummary?.failedRequests ?? 'not applicable/unknown'}; bounded collection<br>Collected ${esc(s.collected?.at)} (${esc(s.collected?.timezone)})${refs([s.ref])}<small>SHA-256 ${esc(s.sha256)}</small>`)}</section><section><h2>Coverage gaps and limitations</h2><p>${r.coverageGaps.count} recorded gap entries. ${esc(r.coverageGaps.detail)}</p>${list(r.limitations, esc)}</section><section><h2>Timeline</h2>${list(r.timeline, (e) => `${esc(e.displayTime || e.eventTime.normalized || 'Unknown/ambiguous event time')} / ${esc(e.classification)} / ${esc(e.eventTime.status)}<br>Collection: ${esc(e.collectedTime || 'unknown')}; import: ${esc(e.importedTime || 'not applicable/unknown')}${e.clockTransform ? '<br>Documented display clock transform: ' + e.clockTransform.seconds + ' seconds; source unchanged.' : ''}${refs(e.evidence)}`)}</section><section><h2>Evidence-backed observations and correlations</h2>${list(r.cards, (c) => `<b>${esc(c.classification)}</b> - ${esc(c.text)}${refs(c.evidence)}`)}</section><section><h2>Findings and review status</h2>${list(r.findings, (f) => `${esc(f.ruleId)} / ${esc(f.status)} / risk ${esc(f.risk)} / confidence ${esc(f.confidence)}${refs(f.evidence)}`)}</section><section><h2>Analyst hypotheses</h2>${list(r.hypotheses, (h) => `${esc(h.text)} - unverified${refs(h.evidence)}`)}</section><section><h2>Recommendations</h2>${list(r.recommendations, esc)}</section></body></html>`;
}
let rendering = false;
export async function renderPdf(html) {
  if (rendering) throw fail('PDF renderer sibuk; coba kembali.', 409);
  rendering = true;
  let browser, timer;
  try {
    browser = await launchBrowser(true);
    timer = setTimeout(() => browser.close().catch(() => {}), 15000);
    const context = await browser.newContext({ javaScriptEnabled: false, serviceWorkers: 'block' });
    await context.route('**/*', (route) => route.abort());
    const page = await context.newPage();
    await page.setContent(html, { waitUntil: 'domcontentloaded', timeout: 10000 });
    const bytes = await page.pdf({
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<span></span>',
      footerTemplate:
        '<div style="width:100%;font-size:8px;text-align:center;color:#667">WebIntelligent - selected evidence report - <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
      margin: { top: '18mm', right: '17mm', bottom: '20mm', left: '17mm' },
    });
    if (bytes.length > 5 * 1024 * 1024) throw fail('PDF melebihi 5 MiB.', 413);
    return bytes;
  } finally {
    clearTimeout(timer);
    await browser?.close();
    rendering = false;
  }
}
