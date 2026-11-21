// Stand-in for the SPA, for manual testing: node scripts/dev-spa.mjs, then open http://localhost:5173
// With DEV_SPA_PROXY_API set it also proxies the API, so one https tunnel can serve both.
import { createServer, request as httpRequest } from 'node:http';

const PROXY_TARGET = process.env.DEV_SPA_PROXY_API;
const API = PROXY_TARGET ? '' : (process.env.API_BASE_URL ?? 'http://localhost:3000');
const API_PATHS =
  /^\/(auth\/(google|facebook|telegram)(\/callback)?|auth\/refresh|auth\/logout|me|health)(\?.*)?$/;
const PORT = Number(process.env.DEV_SPA_PORT ?? 5173);

const page = `<!doctype html>
<meta charset="utf-8">
<title>OAuth dev SPA</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; }
  button, a.btn { font: inherit; padding: .4rem .9rem; margin: 0 .4rem .4rem 0; cursor: pointer;
                  border: 1px solid #888; border-radius: 6px; background: #f4f4f4; color: #111; text-decoration: none; display: inline-block; }
  pre { background: #111; color: #d6f5d6; padding: 1rem; border-radius: 8px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
</style>
<h1>OAuth dev SPA</h1>
<p>
  <a class="btn" href="${API}/auth/google">Login with Google</a>
  <a class="btn" href="${API}/auth/facebook">Login with Facebook</a>
  <a class="btn" href="${API}/auth/telegram">Login with Telegram</a>
  <button id="refresh">POST /auth/refresh</button>
  <button id="me">GET /me</button>
  <button id="logout">POST /auth/logout</button>
</p>
<p>
  Link: <button data-link="google">Google</button><button data-link="facebook">Facebook</button><button data-link="telegram">Telegram</button>
  Unlink: <button data-unlink="google">Google</button><button data-unlink="facebook">Facebook</button><button data-unlink="telegram">Telegram</button>
</p>
<pre id="out">ready</pre>
<script>
  const API = ${JSON.stringify(API)};
  const out = document.getElementById('out');
  let accessToken = null;
  let inFlight = null;

  const show = (title, value) => {
    out.textContent = title + '\\n' + (typeof value === 'string' ? value : JSON.stringify(value, null, 2));
  };

  function refresh() {
    if (!inFlight) {
      inFlight = fetch(API + '/auth/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: { 'X-Requested-With': 'fetch' },
      })
        .then(async (res) => {
          const body = await res.json().catch(() => ({}));
          if (res.ok) accessToken = body.accessToken;
          return { status: res.status, body };
        })
        .finally(() => { inFlight = null; });
    }
    return inFlight;
  }

  async function me() {
    if (!accessToken) return { status: 0, body: 'no access token yet, call refresh first' };
    const res = await fetch(API + '/me', { headers: { Authorization: 'Bearer ' + accessToken } });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  }

  function decode(token) {
    try {
      return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    } catch { return null; }
  }

  document.getElementById('refresh').onclick = async () => {
    const r = await refresh();
    show('POST /auth/refresh -> ' + r.status, accessToken ? { ...r.body, accessToken: accessToken.slice(0, 20) + '...', claims: decode(accessToken) } : r.body);
  };
  document.getElementById('me').onclick = async () => {
    const r = await me();
    show('GET /me -> ' + r.status, r.body);
  };
  document.getElementById('logout').onclick = async () => {
    const res = await fetch(API + '/auth/logout', { method: 'POST', credentials: 'include', headers: { 'X-Requested-With': 'fetch' } });
    accessToken = null;
    show('POST /auth/logout -> ' + res.status, 'session revoked, cookie cleared');
  };

  async function ensureToken() {
    if (!accessToken) await refresh();
    return accessToken;
  }

  document.querySelectorAll('[data-link]').forEach((button) => {
    button.onclick = async () => {
      if (!(await ensureToken())) return show('log in first', 'no session');
      const res = await fetch(API + '/auth/link/' + button.dataset.link, {
        method: 'POST',
        credentials: 'include',
        headers: { Authorization: 'Bearer ' + accessToken },
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok) location.href = body.url;
      else show('POST /auth/link -> ' + res.status, body);
    };
  });

  document.querySelectorAll('[data-unlink]').forEach((button) => {
    button.onclick = async () => {
      if (!(await ensureToken())) return show('log in first', 'no session');
      const res = await fetch(API + '/auth/link/' + button.dataset.unlink, {
        method: 'DELETE',
        credentials: 'include',
        headers: { Authorization: 'Bearer ' + accessToken },
      });
      const body = await res.json().catch(() => ({}));
      const profile = await me();
      show('DELETE /auth/link -> ' + res.status, { result: body, providers: profile.body.providers });
    };
  });

  if (location.pathname === '/settings/accounts') {
    const params = Object.fromEntries(new URLSearchParams(location.search));
    (async () => {
      await ensureToken();
      const profile = await me();
      show('settings page: ' + JSON.stringify(params), { providers: profile.body.providers });
    })();
  }

  if (location.pathname === '/auth/callback') {
    const error = new URLSearchParams(location.search).get('error');
    if (error) {
      show('login failed', { error });
    } else {
      (async () => {
        const r = await refresh();
        if (!r.body.accessToken) return show('refresh failed -> ' + r.status, r.body);
        const profile = await me();
        show('login ok: refresh -> ' + r.status + ', /me -> ' + profile.status, profile.body);
      })();
    }
  }
</script>`;

function proxy(req, res) {
  const target = new URL(PROXY_TARGET);
  const upstream = httpRequest(
    {
      host: target.hostname,
      port: target.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: target.host },
    },
    (response) => {
      res.writeHead(response.statusCode ?? 502, response.headers);
      response.pipe(res);
    },
  );
  upstream.on('error', () => {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('API is not reachable');
  });
  req.pipe(upstream);
}

createServer((req, res) => {
  if (PROXY_TARGET && API_PATHS.test(req.url ?? '')) {
    return proxy(req, res);
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(page);
}).listen(PORT, () => {
  const mode = PROXY_TARGET ? `proxying the API at ${PROXY_TARGET}` : `API ${API}`;
  console.log(`dev SPA on http://localhost:${PORT} (${mode})`);
});
