import express from 'express';
import { readFile } from 'node:fs/promises';

// Opt-in synthetic resources only. No remote dependencies or real account data.
export function wiringFixturePage(protectedPage = false) {
  const base = '/wiring-fixture';
  return `<!doctype html><html><head><meta charset="utf-8"><title>${protectedPage ? 'Private ' : ''}Wiring laboratory</title>
  ${process.env.WIRING_FIXTURE_CSS_ORIGIN ? `<link rel="stylesheet" href="${process.env.WIRING_FIXTURE_CSS_ORIGIN}/cross.css">` : ''}
  <link rel="stylesheet" href="${base}/style.css"><link rel="icon" href="${base}/favicon.svg">
  <script src="${base}/loaded.js" defer></script></head><body><h1>Wiring laboratory ${protectedPage ? '— protected' : ''}</h1>
  <p>Sources are synthetic. All sensitive values should be omitted.</p>
  <picture><source media="(min-width: 9999px)" srcset="${base}/never.svg 1x"><img id="responsive" alt="Responsive landscape" width="360" height="150" src="${base}/fallback.svg" srcset="${base}/small.svg 400w, ${base}/large.svg 1200w" sizes="360px"></picture>
  <div class="background" id="background">CSS background & sprite</div><div class="pseudo" id="pseudo">Pseudo element</div>
  <div id="cross-css" class="cross-style">Cross-origin stylesheet</div>
  <svg id="inline-svg" width="70" height="55" viewBox="0 0 70 55"><circle cx="25" cy="25" r="20" fill="teal" /></svg>
  <svg id="external-use" width="60" height="55"><use href="${base}/symbols.svg#diamond" /></svg>
  <img id="external-svg" alt="External SVG" width="70" height="55" src="${base}/external.svg">
  <span id="font-icon" class="icon">&#xE001;</span>
  <img id="data-image" alt="Data source" width="70" height="55" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='70' height='55'%3E%3Crect width='70' height='55' fill='orange'/%3E%3C/svg%3E">
  <img id="blob-image" alt="Blob source" width="70" height="55">
  <img id="oversized-data" alt="Bounded data source" width="35" height="35" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='35' height='35'%3E%3C!--${'x'.repeat(9000)}--%3E%3Crect width='35' height='35' fill='teal'/%3E%3C/svg%3E">
  <img id="secret-a" alt="Same URL path first query" width="35" height="35" src="${base}/private.svg?token=secret-one">
  <img id="secret-b" alt="Same URL path second query" width="35" height="35" src="${base}/private.svg?token=secret-two">
  <form id="lookup-form"><label>Email <input id="lookup-email" name="email" type="email"></label><button type="button" id="lookup">Lookup</button></form>
  <button id="form-encoded" type="button">Form encoded request</button>
  <p id="result" aria-live="polite">Waiting</p><button id="spa">SPA route</button><a href="${base}/next">Next page</a>
  <img id="near-click" alt="Image loaded near click" width="35" height="35">
  <div id="shadow-host"></div><iframe title="Unmapped child frame" src="${base}/frame"></iframe>
  <div style="height:7000px">Lazy image is deliberately outside capture.</div><img id="lazy" loading="lazy" alt="Lazy not loaded" width="100" height="60" src="${base}/lazy.svg">
  <section id="lazy-catalog">${Array.from({ length: 45 }, (_, i) => `<img loading="lazy" alt="Catalog ${i}" width="40" height="40" src="${base}/catalog-${i}.svg">`).join('')}</section>
  <script>
  document.querySelector('#shadow-host').attachShadow({mode:'open'}).innerHTML='<span>Unmapped shadow content</span>';
  document.querySelector('#blob-image').src=URL.createObjectURL(new Blob(['<svg xmlns="http://www.w3.org/2000/svg" width="70" height="55"><rect width="70" height="55" fill="purple"/></svg>'], {type:'image/svg+xml'}));
  async function lookupEmail() {
    const r = await fetch('${protectedPage ? '/auth-fixture/api/read' : base + '/api/lookup'}?token=query-secret',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.querySelector('#lookup-email').value, password:'never-export-this', operationName:'ProfileRead', profile:{age:27}})});
    await r.json(); document.querySelector('#result').textContent = r.ok ? 'Lookup complete' : 'Lookup blocked';
  }
  document.querySelector('#lookup-email').addEventListener('change', lookupEmail);
  document.querySelector('#lookup').addEventListener('click', lookupEmail);
  document.querySelector('#form-encoded').onclick = async () => {await (await fetch('${base}/api/lookup',{method:'POST',body:new URLSearchParams({email:document.querySelector('#lookup-email').value,password:'form-secret'})})).json(); await (await fetch('${base}/redirect')).json();};
  document.querySelector('#lookup-form').addEventListener('submit', e => e.preventDefault());
  document.querySelector('#spa').onclick = () => {history.pushState({},'',location.pathname+'?view=private-view'); document.querySelector('#result').textContent='SPA changed'; setTimeout(()=>document.querySelector('#near-click').src='${base}/near.svg',60);};
  </script></body></html>`;
}

export function createWiringFixture() {
  const router = express.Router(),
    counts = {};
  router.use((req, res, next) => {
    counts[req.path] = (counts[req.path] || 0) + 1;
    res.set('Cache-Control', 'no-store');
    next();
  });
  router.get('/metrics', (req, res) => res.json(counts));
  router.get(['/', '/next'], (req, res) => res.send(wiringFixturePage()));
  router.get('/frame', (req, res) => res.send('<!doctype html><p>Unmapped iframe</p>'));
  router.post('/api/lookup', (req, res) => res.json({ ok: true }));
  router.get('/redirect', (req, res) => res.redirect('/wiring-fixture/api/items/42'));
  router.get('/api/items/42', (req, res) => res.json({ ok: true }));
  router.get('/loaded.js', (req, res) => res.type('js').send('window.fixtureScriptLoaded = true;'));
  router.get('/style.css', (req, res) =>
    res.type('css').send(`
    @font-face{font-family:FixtureIcon;src:url('/wiring-fixture/icon.ttf') format('truetype')}
    body{font:16px system-ui;margin:36px;max-width:1100px;background:#f5f8f6} h1{color:#184f43}
    input,button{font:inherit;padding:8px;margin:8px} img,svg,.icon{vertical-align:middle;margin:8px}
    .background{width:260px;height:80px;background-image:url('/wiring-fixture/background.svg');background-size:520px 160px;background-position:-30px -20px;color:white;padding:10px}
    .pseudo::before{content:'';display:inline-block;width:35px;height:35px;background-image:url('/wiring-fixture/pseudo.svg');background-size:contain}
    .icon{font-family:FixtureIcon;font-size:42px} iframe{height:45px;width:240px;border:1px solid #ccd}
  `),
  );
  router.get('/icon.ttf', async (req, res, next) => {
    try {
      res
        .type('font/ttf')
        .send(await readFile(new URL('../tests/fixtures/icon.ttf', import.meta.url)));
    } catch (e) {
      next(e);
    }
  });
  router.get('/symbols.svg', (req, res) =>
    res
      .type('svg')
      .send(
        '<svg xmlns="http://www.w3.org/2000/svg"><symbol id="diamond" viewBox="0 0 60 55"><path d="M30 0 L60 28 L30 55 L0 28Z" fill="blue"/></symbol></svg>',
      ),
  );
  router.get('/:name.svg', (req, res) =>
    res
      .type('svg')
      .send(
        `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="500"><rect width="1200" height="500" fill="#357d71"/><circle cx="160" cy="250" r="100" fill="#ecc764"/></svg>`,
      ),
  );
  return router;
}
