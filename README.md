# OAuth service

Sign in with Google, Facebook and Telegram. NestJS, PostgreSQL, Prisma.
A user can link several providers to one profile. Sessions are a short-lived access JWT plus a rotating refresh token in an httpOnly cookie.

## Quick start

```bash
cp .env.example .env              # set JWT_SECRET and COOKIE_SECRET (see below)
docker compose up -d db
npm install                       # also generates the Prisma client
npx prisma migrate deploy
npm run start:dev                 # http://localhost:3000
```

```bash
openssl rand -base64 64           # JWT_SECRET
openssl rand -base64 32           # COOKIE_SECRET
```

If something already listens on 5432, run `POSTGRES_PORT=5433 docker compose up -d db` and change the port in `DATABASE_URL`.

- Try it by hand: `node scripts/dev-spa.mjs`, then open http://localhost:5173 (a stand-in for the SPA).
- API documentation: http://localhost:3000/docs (not served when `NODE_ENV=production`).

A provider is enabled only when both of its variables are set. The service starts with any subset.

| Provider | Variables | Redirect URI to register |
|---|---|---|
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | `<API_BASE_URL>/auth/google/callback` |
| Facebook | `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` | `<API_BASE_URL>/auth/facebook/callback` |
| Telegram | `TELEGRAM_CLIENT_ID`, `TELEGRAM_CLIENT_SECRET` | `<API_BASE_URL>/auth/telegram/callback` |

Facebook: request `public_profile` and `email`; the app can stay in development mode.
Telegram: in BotFather open the bot, Login Widget, and switch to OpenID Connect. The values shown there are the client id and secret.

Telegram only accepts https redirect URIs (an `http://localhost` URI is rejected with a misleading `redirect_uri required`), so locally it needs a tunnel:

```bash
cloudflared tunnel --url http://localhost:5173
DEV_SPA_PROXY_API=http://localhost:3000 node scripts/dev-spa.mjs
API_BASE_URL=https://<tunnel> FRONTEND_URL=https://<tunnel> COOKIE_SECURE=true node dist/main
```

Register `https://<tunnel>/auth/telegram/callback` in BotFather and open the tunnel URL in the browser.

## Configuration

`src/config/env.ts` validates everything at startup and names every bad variable without printing its value.

| Variable | Default | |
|---|---|---|
| `API_BASE_URL`, `FRONTEND_URL` | | Callback URLs are built from `API_BASE_URL`, never from the request. `FRONTEND_URL` is the CORS origin and the redirect target |
| `DATABASE_URL` | | |
| `JWT_SECRET`, `COOKIE_SECRET` | | At least 32 characters |
| `JWT_ACCESS_TTL` | `15m` | |
| `REFRESH_TTL_DAYS` | `30` | |
| `COOKIE_SECURE`, `COOKIE_SAME_SITE` | `false`, `lax` | `none` needs `COOKIE_SECURE=true`. Production refuses insecure values |
| `FACEBOOK_GRAPH_VERSION` | `v25.0` | |
| `HTTP_TIMEOUT_MS`, `BODY_LIMIT_BYTES` | `5000`, `10240` | |

## API

Every error is `{ "error": { "code": "...", "message": "..." } }`. The codes are stable.

| Method | Path | Auth | |
|---|---|---|---|
| GET | `/auth/:provider` | | Start a login (redirect to the provider) |
| GET | `/auth/:provider/callback` | | Redirects to `FRONTEND_URL`, with `?error=<code>` on failure (404 for an unknown provider) |
| POST | `/auth/refresh` | cookie | New access token, rotated cookie |
| POST | `/auth/logout` | cookie | Revokes the session. Always 204 |
| GET | `/me` | Bearer | Profile and linked providers |
| POST | `/auth/link/:provider` | Bearer | Returns the provider URL to navigate to |
| DELETE | `/auth/link/:provider` | Bearer | Unlink. The last provider cannot be removed |
| GET | `/health` | | Liveness, no database call |

`refresh` and `logout` also need the header `X-Requested-With: fetch`, and the `Origin` header, when present, must equal `FRONTEND_URL`.

## How it works

```
SPA -> GET /auth/google ----------------> sets oauth_tx cookie, 302 to Google
Google -> GET /auth/google/callback ----> checks state, exchanges code (PKCE), verifies the profile,
                                          finds or creates the user, sets the refresh cookie,
                                          302 to FRONTEND_URL/auth/callback   (no token in the URL)
SPA -> POST /auth/refresh --------------> { accessToken }
SPA -> GET /me (Authorization: Bearer) -> profile
```

- **Access token**: HS256 JWT, 15 minutes, claims `sub`, `iss`, `aud`, `iat`, `exp` only. Keep it in memory.
- **Refresh token**: 32 random bytes, stored only as a SHA-256 hash. Each use revokes it and issues the next one in the same family with a single conditional `UPDATE`, so two concurrent uses cannot both succeed. Presenting a revoked token revokes the whole family. The SPA must send refresh calls one at a time: two tabs refreshing together will log the user out.
- **OAuth state**: random `state` and PKCE verifier are stored in the database (`oauth_transactions`, hashed state, 10 minutes, single use) and bound to the browser by a cookie holding only the row id.

## Decisions worth knowing

- Accounts are matched only by `(provider, provider_user_id)`, never by email. Facebook and Telegram do not prove an email, so matching on it would allow taking over an account by registering its address first. `users.email` is filled only when the provider verified it (Google) and is not unique.
- Linking is explicit: a logged-in user attaches another provider. It never touches the session. Unlink locks the user row (`SELECT ... FOR UPDATE`) so two concurrent unlinks cannot remove every sign-in method.
- Concurrent first logins are resolved by the unique index; the loser logs in the winner's user instead of creating a second one.
- Callback failures redirect with a code from a fixed allowlist. Provider messages never reach the URL, and provider response bodies never reach errors or logs.
- Logs carry no headers, cookies or query strings.
- `id_token`s are verified against the provider's JWKS with the algorithm pinned to RS256 (Google, Telegram). The Telegram verifier assumes the BotFather default; do not change the signing algorithm there.
- Cookies are host-only, `HttpOnly`, `SameSite=Lax`, path `/auth`, and cleared with the same options they were set with. The SPA and the API are assumed to share a site.
- `jose` is pinned to 5 and `@nestjs/config` to 4: the newer majors are ESM-only and do not load under Jest in this CommonJS project.

## Tests

```bash
npm test             # unit tests, no database
npm run test:int     # integration tests against real PostgreSQL
```

`test:int` needs a test database. It applies the migrations itself:

```bash
psql postgresql://oauth:oauth@localhost:5432/oauth -c 'CREATE DATABASE oauth_test'
```

Providers are replaced by fakes, so no test calls Google, Facebook or Telegram. The tests cover token and state handling, linking, the HTTP flow, concurrent refreshes and unlinks, and the OpenAPI document.

Load test (50 connections, 10 s each) against a test-mode instance on another port, with its own database:

```bash
NODE_ENV=test PORT=3100 LOG_LEVEL=silent API_BASE_URL=http://localhost:3100 \
  DATABASE_URL=postgresql://oauth:oauth@localhost:5432/oauth_test \
  JWT_SECRET=stress-jwt-secret-stress-jwt-secret-1234 node dist/main
npm run stress
```

On a laptop: `/health` about 30k req/s, `/me` (JWT check plus a query) about 6.6k req/s with p99 11 ms, login start about 8.4k req/s. A hundred parallel refreshes with one token produce exactly one success and revoke the family. The script refuses to run against a database whose name does not end in `_test`.

## Deployment

Deployment is optional and not in use yet. The files below describe running this on a VPS at https://alifco-auth.labbay.app. Every push to `main` and every pull request runs CI (format, lint, types, unit and integration tests, build). If it passes and `DEPLOY_ENABLED` is `true`, the image is built, pushed to GitHub Container Registry and deployed to the VPS over SSH. If the new container is not healthy within 90 seconds the previous image is started again and the job fails.

```
Dockerfile                      production image (runs migrations on start, then the API)
deploy/docker-compose.prod.yml  Caddy (automatic https), the API, PostgreSQL
deploy/Caddyfile                the domain and security headers
deploy/deploy.sh                pull, start, wait for healthy, roll back on failure
deploy/backup.sh                daily pg_dump, keeps 14 days
.github/workflows/ci-cd.yml     CI and deploy
```

### One-time setup

1. DNS: an A record for `alifco-auth.labbay.app` pointing at the VPS.
2. VPS: Docker with the compose plugin, ports 80 and 443 open, a user in the `docker` group, and `/opt/alifco-auth` owned by that user.
3. On the VPS create `/opt/alifco-auth/.env` from `deploy/production.env.example`. `FRONTEND_URL` must be on the same site as the API (a subdomain of `labbay.app`), because the refresh cookie is `SameSite=Lax`.
4. Create a key for CI: `ssh-keygen -t ed25519 -f ci_deploy -C ci`, append `ci_deploy.pub` to the deploy user's `authorized_keys`.
5. In the GitHub repository add the Actions secrets `SSH_HOST`, `SSH_USER`, `SSH_KEY` (the private key) and `SSH_KNOWN_HOSTS` (the output of `ssh-keyscan -H <host>`). Optionally create a `production` environment that requires a reviewer. Until the VPS is ready, CI only runs the tests: deployment starts when the repository variable `DEPLOY_ENABLED` is set to `true` (Settings, Secrets and variables, Variables).
6. Backups: `0 3 * * * /opt/alifco-auth/backup.sh` in the deploy user's crontab.

Secrets live only in the VPS `.env` and in GitHub Secrets. The registry login used during a deploy is the job's short-lived token and is removed afterwards.

### Provider consoles

Register the production redirect URIs:

| Provider | Redirect URI | Also |
|---|---|---|
| Google | `https://alifco-auth.labbay.app/auth/google/callback` | In Testing status only listed test users can sign in. Publishing the app opens it to everyone and may require Google's verification |
| Facebook | `https://alifco-auth.labbay.app/auth/facebook/callback` | Switch the app to Live, otherwise only people with a role on the app can sign in |
| Telegram | `https://alifco-auth.labbay.app/auth/telegram/callback` | BotFather, Login Widget, allowed URLs |

### Things to know

- Migrations run when the container starts, and a rollback starts the previous image against the already migrated database. Keep migrations backward compatible, and run a single instance.
- Swagger (`/docs`) is not served in production.
- Rate limiting and `trust proxy` assume exactly one proxy in front (Caddy). Another proxy or CDN in front changes the client IP the limits see.
- On the VPS: `cd /opt/alifco-auth && docker compose -f docker-compose.prod.yml logs -f api`.
- The image is about 900 MB (the Prisma CLI is inside it for migrations); deploys only transfer changed layers.

## Layout

```
prisma/schema.prisma        database schema and migrations
src/config                  environment validation
src/auth/providers          one adapter per provider, shared OIDC helpers
src/auth/tokens             access and refresh tokens
src/auth/oauth              state and PKCE transactions
src/auth/identity           find or create, link, unlink
src/auth                    controller, guards, cookies
src/users                   /me
scripts                     dev SPA and load test
deploy, Dockerfile          production deployment
```

## Not done, and known limits

- Expired `oauth_transactions` and `refresh_tokens` are never deleted. A cleanup job is needed before this runs for long.
- Refresh tokens expire after 30 days of the family's last rotation with no maximum session age.
- Profile picture URLs (Facebook, Telegram) are temporary links to the provider. The avatar is refreshed on every login, but between logins a stored link can stop working. The pictures are not copied to our own storage.
- The display name is set at sign-up and never rewritten by later logins.
- No account merging: an account that already has its own profile (because someone signed in with it before) cannot be linked to another profile.
- Telegram never returns an email. Facebook returns one only on request, and it is kept on the identity but never trusted.
- No unit tests for the rate limits (`/auth/*` 20 per minute, refresh 10, everything else 60). They were checked by hand against a running server.
- No account deletion, no admin features.

## Porting to another language

What has to survive is the contract, not the NestJS structure: the endpoint table above, the schema in `prisma/schema.prisma`, the token semantics under "How it works", the account-matching rule, and the redirect and error codes.
