import express from 'express';
import { randomBytes } from 'node:crypto';
import { wiringFixturePage } from './wiring-fixture.mjs';

// Synthetic, opt-in local test fixture. Never used as application authentication.
export function createAuthFixture() {
  const router = express.Router();
  const sessions = new Map(),
    pending = new Set();
  const counts = { reads: 0, messages: 0, deletes: 0, logouts: 0 };
  router.use(express.urlencoded({ extended: false, limit: '4kb' }));
  router.use(express.json({ limit: '4kb' }));
  router.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  const cookie = (req, name) =>
    req.headers.cookie
      ?.split(';')
      .map((x) => x.trim())
      .find((x) => x.startsWith(name + '='))
      ?.slice(name.length + 1);
  const valid = (req) => (sessions.get(cookie(req, 'wi_fixture_sid')) || 0) > Date.now();
  const html = (title, body) =>
    `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>body{font:18px system-ui;margin:50px;max-width:800px}label{display:block;margin:18px 0}input,button{font:inherit;padding:8px}a{margin:12px;display:inline-block}</style></head><body><h1>${title}</h1>${body}</body></html>`;
  const protectedPage = (req, res, next) =>
    valid(req)
      ? next()
      : res
          .status(401)
          .send(
            html(
              'Akses ditolak',
              '<p>Cookie autentikasi wajib.</p><a href="/auth-fixture/login">Login fixture</a>',
            ),
          );
  router.get('/login', (req, res) =>
    res.send(
      html(
        'Login fixture',
        '<form method="post" action="/auth-fixture/login"><label>Email <input type="email" name="email" required></label><label>Password <input name="password" type="password" required></label><button>Login</button></form>',
      ),
    ),
  );
  router.post('/login', (req, res) => {
    if (req.body.email !== 'fixture@example.test' || req.body.password !== 'fixture-password')
      return res.status(401).send('Login ditolak');
    const id = randomBytes(24).toString('hex');
    pending.add(id);
    res.cookie('wi_fixture_mfa', id, { httpOnly: true, sameSite: 'lax', path: '/auth-fixture' });
    res.redirect(303, '/auth-fixture/mfa');
  });
  router.get('/mfa', (req, res) =>
    res.send(
      html(
        'MFA fixture',
        '<form method="post" action="/auth-fixture/mfa"><label>Kode <input name="code" autocomplete="one-time-code" required></label><button>Verifikasi</button></form>',
      ),
    ),
  );
  router.post('/mfa', (req, res) => {
    const pendingId = cookie(req, 'wi_fixture_mfa');
    if (!pending.has(pendingId) || req.body.code !== '123456')
      return res.status(401).send('MFA ditolak');
    pending.delete(pendingId);
    const id = randomBytes(32).toString('hex');
    sessions.set(id, Date.now() + 3600000);
    res.clearCookie('wi_fixture_mfa', { path: '/auth-fixture' });
    res.cookie('wi_fixture_sid', id, { httpOnly: true, sameSite: 'lax', path: '/auth-fixture' });
    res.redirect(303, '/auth-fixture/profile');
  });
  router.post('/api/read', (req, res) => {
    if (!valid(req)) return res.status(401).json({ error: 'Authentication required' });
    if (req.body.operationName !== 'ProfileRead')
      return res.status(400).json({ error: 'Unknown operation' });
    counts.reads++;
    res.json({ displayName: 'Private fixture profile', protected: true });
  });
  router.get('/api/status', (req, res) =>
    res.status(valid(req) ? 200 : 401).json({ authenticated: valid(req) }),
  );
  router.post('/expire', (req, res) => {
    sessions.delete(cookie(req, 'wi_fixture_sid'));
    res.json({ expired: true });
  });
  router.get('/logout', (req, res) => {
    sessions.delete(cookie(req, 'wi_fixture_sid'));
    counts.logouts++;
    res.clearCookie('wi_fixture_sid', { path: '/auth-fixture' });
    res.redirect('/auth-fixture/login');
  });
  router.get('/delete', protectedPage, (req, res) => {
    counts.deletes++;
    res.json({ simulated: true });
  });
  router.post('/api/messages', protectedPage, (req, res) => {
    counts.messages++;
    res.json({ simulated: true });
  });
  router.get('/redirect-one', (req, res) => res.redirect('/auth-fixture/redirect-two'));
  router.get('/redirect-two', (req, res) => res.redirect('/outside-fixture'));
  router.get('/metrics', (req, res) => res.json(counts));
  if (process.env.ENABLE_WIRING_FIXTURE === '1')
    router.get('/wiring', protectedPage, (req, res) => res.send(wiringFixturePage(true)));
  router.get(
    ['/profile', '/profile/activity', '/settings', '/action-probe'],
    protectedPage,
    (req, res) =>
      res.send(
        html(
          req.path === '/settings' ? 'Private settings' : 'Private profile',
          `
    <p id="private-content">Cookie-protected page</p><p id="read-result">Menunggu POST baca…</p>
    <button id="activity">Buka aktivitas SPA</button><button id="refresh-data">Muat data</button>
    <a href="/auth-fixture/settings" target="_blank">Buka popup pengaturan</a>
    <a href="/auth-fixture/redirect-one" target="_blank">Popup redirect fixture</a>
    <a href="/auth-fixture/logout">Logout</a><a href="/outside-fixture">Di luar scope</a>
    <button id="expire">Simulasikan expiry</button>
    <script>
    async function readProfile() { const r = await fetch('/auth-fixture/api/read', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({operationName:'ProfileRead'})}); document.querySelector('#read-result').textContent = r.ok ? (await r.json()).displayName : 'Akses ditolak'; }
    readProfile().catch(() => document.querySelector('#read-result').textContent = 'POST diblokir');
    document.querySelector('#refresh-data').onclick = readProfile;
    document.querySelector('#activity').onclick = () => { history.pushState({},'', '/auth-fixture/profile/activity'); document.querySelector('#private-content').textContent = 'Aktivitas SPA privat'; };
    document.querySelector('#expire').onclick = async () => { await fetch('/auth-fixture/expire',{method:'POST'}); await fetch('/auth-fixture/api/status'); };
    ${req.path === '/action-probe' ? "fetch('/auth-fixture/delete').catch(()=>{}); fetch('/auth-fixture/api/messages',{method:'POST'}).catch(()=>{});" : ''}
    </script>`,
        ),
      ),
  );
  return router;
}
