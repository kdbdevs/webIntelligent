const root = document.querySelector('#demo-root');
const route = location.pathname;
if (route === '/demo' || route === '/demo/') {
  root.innerHTML =
    '<h1>Selamat datang.</h1><p>Masuk ke ruang kerja kamu.</p><form id="login-form" action="/demo/api/login" method="post"><label for="email">Email</label><input id="email" type="email" name="email" placeholder="nama@contoh.com" required><label for="password">Password</label><input id="password" type="password" name="password" required><button id="login-button" type="submit">Masuk →</button><div id="error" role="status"></div></form><div class="foot"><a href="/demo/forgot-password">Lupa password?</a><a href="/demo/register">Daftar akun</a></div><small>Demo: demo@example.com · password: demo</small>';
  const email = document.querySelector('#email');
  email.addEventListener('input', function onEmailInput() {
    email.setAttribute('data-edited', 'true');
  });
  document
    .querySelector('#login-form')
    .addEventListener('submit', async function handleLogin(event) {
      event.preventDefault();
      const values = new FormData(event.currentTarget);
      try {
        const response = await fetch('/demo/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: values.get('email'), password: values.get('password') }),
        });
        const data = await response.json();
        if (response.ok) location.href = data.redirect;
        else document.querySelector('#error').textContent = data.error;
      } catch {
        document.querySelector('#error').textContent = 'Koneksi demo terputus.';
      }
    });
} else {
  const titles = {
    '/demo/register': 'Buat akun.',
    '/demo/forgot-password': 'Pulihkan akun.',
    '/demo/dashboard': 'Ruang kerja kamu.',
    '/demo/projects/1': 'Project pertama.',
    '/demo/settings': 'Pengaturan.',
  };
  const title = titles[route] || 'Ruang demo';
  document.title = title + ' — Ruang';
  root.innerHTML =
    '<h1></h1><p>Halaman contoh untuk memeriksa peta URL dan navigasi.</p><nav><a href="/demo">Kembali ke login</a><a href="/demo/dashboard">Dashboard</a><a href="/demo/projects/1">Buka project</a><a href="/demo/settings">Pengaturan</a></nav>';
  root.querySelector('h1').textContent = title;
}
fetch('/demo/api/status').catch(() => {});
