import express from 'express';
// Opt-in, local synthetic pages. Never mounted by default.
export function createSecurityFixture() {
  const router = express.Router();
  router.get('/safe', (req, res) => {
    res.set(
      'Content-Security-Policy',
      "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
    );
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.set('Set-Cookie', [
      'theme=fixture-preference; SameSite=Lax; Path=/',
      'old_session=; Max-Age=0; Path=/',
    ]);
    res
      .type('html')
      .send(
        '<!doctype html><title>Safe metadata fixture</title><h1>Safe / exception fixture</h1><img alt="Normal asset" src="./pixel?size=small"><a href="./bad">Problem fixture</a>',
      );
  });
  router.get('/bad', (req, res) => {
    res.removeHeader('X-Content-Type-Options');
    res.set(
      'Content-Security-Policy-Report-Only',
      "default-src 'none'; script-src 'nonce-FIXTURE_NONCE_SECRET'",
    );
    res.set('Set-Cookie', [
      '__Host-session=FIXTURE_COOKIE_SECRET; SameSite=None; Path=/sub',
      'auth_hint=FIXTURE_HINT_SECRET; Path=/',
    ]);
    res
      .type('html')
      .send(
        '<!doctype html><title>Security evidence fixture</title><h1>Problem metadata fixture</h1><img id="sensitive-asset" alt="Fixture asset with sensitive-looking query name" src="./pixel?token=FIXTURE_QUERY_SECRET"><label>Email<input id="email" type="email"></label><button id="send">Request metadata</button><script>fetch("./transfer",{headers:{Authorization:"Bearer FIXTURE_AUTH_SECRET"}});document.querySelector("#send").onclick=()=>fetch("./transfer?email="+encodeURIComponent(document.querySelector("#email").value))</script>',
      );
  });
  router.get('/error', (req, res) =>
    res
      .status(500)
      .type('html')
      .send('<h1>Synthetic error, not automatically a vulnerability</h1>'),
  );
  router.get('/pixel', (req, res) =>
    res
      .type('svg')
      .send(
        '<svg xmlns="http://www.w3.org/2000/svg" width="160" height="70"><rect width="160" height="70" fill="#568e77"/></svg>',
      ),
  );
  router.get('/transfer', (req, res) => res.json({ accepted: true, fixture: true }));
  return router;
}
