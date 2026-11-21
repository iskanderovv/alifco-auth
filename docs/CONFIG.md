# Configuration and Provider Setup

## 1. Environment variables

Validated at startup (fail fast, app does not boot with a missing or malformed value).

| Variable | Required | Example (local) | Note |
|---|---|---|---|
| `NODE_ENV` | yes | `development` | `development` / `test` / `production` |
| `PORT` | no | `3000` | |
| `API_BASE_URL` | yes | `http://localhost:3000` | Used to build provider callback URLs |
| `FRONTEND_URL` | yes | `http://localhost:5173` | CORS allowlist and post-login redirect |
| `DATABASE_URL` | yes | `postgresql://oauth:oauth@localhost:5432/oauth` | |
| `JWT_SECRET` | yes | 64+ random bytes | `openssl rand -base64 64`, min length enforced |
| `JWT_ACCESS_TTL` | no | `15m` | |
| `JWT_ISSUER` | no | `oauth-service` | |
| `JWT_AUDIENCE` | no | `oauth-service-api` | |
| `REFRESH_TTL_DAYS` | no | `30` | |
| `REFRESH_FAMILY_MAX_DAYS` | no | `90` | |
| `REFRESH_GRACE_SECONDS` | no | `10` | |
| `COOKIE_SECRET` | yes | 32+ random bytes | Signs the `oauth_state` cookie |
| `COOKIE_DOMAIN` | no | empty locally, `.example.com` in prod | |
| `COOKIE_SECURE` | no | `false` locally, `true` in prod | |
| `GOOGLE_CLIENT_ID` | yes | | |
| `GOOGLE_CLIENT_SECRET` | yes | | |
| `FACEBOOK_APP_ID` | yes | | |
| `FACEBOOK_APP_SECRET` | yes | | |
| `TELEGRAM_CLIENT_ID` | yes | | BotFather, Login Widget section (the bot id) |
| `TELEGRAM_CLIENT_SECRET` | yes | | Same place. Treat like a password |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error` |
| `HTTP_TIMEOUT_MS` | no | `5000` | Timeout for every outgoing provider call |
| `BODY_LIMIT_BYTES` | no | `10240` | Max request body size |

Callback URLs are derived, not configured: `${API_BASE_URL}/auth/google/callback`, `${API_BASE_URL}/auth/facebook/callback`, `${API_BASE_URL}/auth/telegram/callback`. Never taken from the request.

Rules:
- `.env` is in `.gitignore`. `.env.example` is committed with empty or fake values.
- Also ignored: `node_modules`, `dist`, `coverage`, `*.dbdiagram` (layout file some DBML extensions generate, not source).
- If a provider's variables are all empty, that provider is disabled (not registered) and `/auth/<provider>` returns 404. Lets you ship Google first and add the others as they get ready.

## 2. `.env.example` draft

```
NODE_ENV=development
PORT=3000
API_BASE_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173
DATABASE_URL=postgresql://oauth:oauth@localhost:5432/oauth

JWT_SECRET=
JWT_ACCESS_TTL=15m
JWT_ISSUER=oauth-service
JWT_AUDIENCE=oauth-service-api
REFRESH_TTL_DAYS=30
REFRESH_FAMILY_MAX_DAYS=90
REFRESH_GRACE_SECONDS=10

COOKIE_SECRET=
COOKIE_DOMAIN=
COOKIE_SECURE=false

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
FACEBOOK_APP_ID=
FACEBOOK_APP_SECRET=
TELEGRAM_CLIENT_ID=
TELEGRAM_CLIENT_SECRET=

LOG_LEVEL=info
HTTP_TIMEOUT_MS=5000
BODY_LIMIT_BYTES=10240
```

## 3. Local development and cookies

SPA on `localhost:5173`, API on `localhost:3000`: browsers ignore the port for "same site", so `SameSite=Lax` cookies work. Matches the "one site" decision.

`Secure` cookies work on `localhost` in modern browsers, but keep `COOKIE_SECURE=false` locally to avoid surprises.

## 4. Provider setup (manual, done by you)

### Google

1. Google Cloud Console, create a project.
2. APIs & Services, OAuth consent screen: external, app name, support email. Scopes: `openid`, `email`, `profile`. While in "Testing", add your own Google account under Test users, otherwise login is blocked.
3. Credentials, Create credentials, OAuth client ID, type Web application.
4. Authorized redirect URI: `http://localhost:3000/auth/google/callback`.
5. Copy client ID and secret into `.env`.

Profile: ID token or userinfo gives `sub`, `email`, `email_verified`, `name`, `picture`. `sub` is the stable `provider_user_id`. Only Google counts as verified-email for auto-link, and only when `email_verified` is true.

### Facebook

1. developers.facebook.com, My Apps, Create App. Use case: authenticate users with Facebook Login.
2. Add product Facebook Login for web. Settings, Valid OAuth Redirect URIs: `http://localhost:3000/auth/facebook/callback`.
3. Permissions: `public_profile`, `email` (both available without app review).
4. App stays in Development mode: only the app admin, developers and testers can log in. Add your own account. Going Live needs privacy policy URL and business verification, out of scope for this task.
5. Settings, Basic: copy App ID and App Secret.

Profile: Graph API `/me?fields=id,name,email,picture`. `id` is the stable id. `email` may be missing and is never marked verified, so no auto-link.

### Telegram

OpenID Connect, see DESIGN.md section 4. Official docs: core.telegram.org/bots/telegram-login.

1. In Telegram open `@BotFather`, `/newbot`, pick name and username.
2. `@BotFather`, select the bot, open **Login Widget**. It shows Client ID and Client Secret. Copy both into `.env`.
3. In the same place add the allowed URL: redirect URI `http://localhost:3000/auth/telegram/callback` (and your tunnel URL if needed).
4. Scopes requested by us: `openid profile`. We do not request `phone`.

Not documented by Telegram, check by trying it: whether an `http://localhost` redirect URI is accepted. If it is rejected, run the API behind a tunnel (ngrok or cloudflared) and register the https tunnel URL, setting `API_BASE_URL` to it.

Token endpoint needs HTTP Basic auth (`client_id:client_secret`). No userinfo endpoint, the profile is read from the validated `id_token`. No email.

Signing algorithm defaults to RS256 (changeable in BotFather under Login Widget, Advanced). The verifier pins RS256, so leave the BotFather default.

## 5. Local services

`docker-compose.yml` with Postgres only (API runs on the host for fast reload):

```yaml
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_USER: oauth
      POSTGRES_PASSWORD: oauth
      POSTGRES_DB: oauth
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
volumes:
  pgdata:
```

Alternative: Homebrew Postgres already installed on this machine. Either works, only `DATABASE_URL` changes.

## 6. Your checklist (before coding the adapters)

- [ ] Google project, consent screen, OAuth client, test user added
- [ ] Facebook app in Development mode, redirect URI set, yourself as admin
- [ ] Telegram bot created via BotFather, Client ID and Secret saved, redirect URI registered
- [ ] ngrok or cloudflared installed, only if Telegram rejects the localhost redirect URI
- [ ] `.env` created from `.env.example`, secrets filled

Google can be tested first, nothing blocks core work on the other two.

## 7. Open points

1. Facebook PKCE: confirmed in Meta docs (OIDC code flow with PKCE, `code_challenge_method=S256`). One older mirror of the page called it "in testing", so the adapter still sends `client_secret` with the code exchange. If the PKCE parameters are rejected at runtime, drop them: `state` plus the client secret still protect the exchange.
2. Telegram: unknown whether a localhost http redirect URI and a `nonce` are supported. We rely on `state` and PKCE, not `nonce`.
3. Production domains and who owns the real provider apps (yours are test apps).
