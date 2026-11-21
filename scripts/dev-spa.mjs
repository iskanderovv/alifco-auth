// Manual-testing helper that plays the role of the SPA. Not part of the service.
//
//   node scripts/dev-spa.mjs          then open http://localhost:5173
//
// It serves one page on every path (SPA-style). The page links to the login, and on
// /auth/callback it does what a real SPA must do: call POST /auth/refresh with the cookie,
// then GET /me with the access token.
import { createServer, request as httpRequest } from 'node:http';

// Proxy mode (for an https tunnel): the SPA and the API share one origin. Set DEV_SPA_PROXY_API
// to the API address, for example http://localhost:3000, and expose only this server.
const PROXY_TARGET = process.env.DEV_SPA_PROXY_API;
const API = PROXY_TARGET ? '' : (process.env.API_BASE_URL ?? 'http://localhost:3000');
// Paths that belong to the API. /auth/callback is NOT here: it is the SPA's own page.
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
<pre id="out">ready</pre>
<script>
  const API = ${JSON.stringify(API)};
  const out = document.getElementById('out');
  let accessToken = null;
  let inFlight = null;

  const show = (title, value) => {
    out.textContent = title + '\\n' + (typeof value === 'string' ? value : JSON.stringify(value, null, 2));
  };

  // The server rotates the refresh token, so two refreshes at once would log the user out.
  // A real SPA must serialize them, like this.
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

  // Landing after the provider redirect: this is the part every real SPA has to implement.
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
      // Status, Set-Cookie and Location (the OAuth redirects) pass through untouched.
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
