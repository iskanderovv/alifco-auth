// Stand-in for the SPA, for manual testing: node scripts/dev-spa.mjs, then open http://localhost:5173
// With DEV_SPA_PROXY_API set it also proxies the API, so one https tunnel can serve both.
import { readFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';

const PROXY_TARGET = process.env.DEV_SPA_PROXY_API;
const API = PROXY_TARGET
  ? ''
  : (process.env.API_BASE_URL ?? 'http://localhost:3000');
const API_PATHS =
  /^\/(auth\/(google|facebook|telegram)(\/callback)?|auth\/refresh|auth\/logout|auth\/link\/[a-z]+|docs(-json)?(\/.*)?|me|health)(\?.*)?$/;
const PORT = Number(process.env.DEV_SPA_PORT ?? 5173);

const page = readFileSync(
  new URL('./dev-spa.html', import.meta.url),
  'utf8',
).replace('%API%', API);

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
  const mode = PROXY_TARGET
    ? `proxying the API at ${PROXY_TARGET}`
    : `API ${API}`;
  console.log(`dev SPA on http://localhost:${PORT} (${mode})`);
});
