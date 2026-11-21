# Test Plan

Stack: Jest (NestJS default), `supertest` for HTTP, real PostgreSQL for integration tests, provider HTTP mocked.

## 1. Strategy

| Level | What | Dependencies | Speed |
|---|---|---|---|
| Unit | Pure logic: Telegram `id_token` check, PKCE, token hashing, linking decision, JWT sign/verify | none | ms |
| Integration | Controllers + services + real DB. Providers replaced by fakes | PostgreSQL (test DB) | seconds |
| Manual E2E | Real Google / Facebook / Telegram with test apps | tunnel, real accounts | minutes |

Rule: automated tests never call real providers. They are slow, flaky and need secrets.

Priority if time runs short (4h task): security-critical unit tests first (section 2), then the linking and refresh integration tests, then the rest.

## 2. Unit tests (must have)

### Telegram `id_token` verification
Use a locally generated RS256 key pair and a fake JWKS, so no network.
- valid token passes, returns `sub`, `name`, `preferred_username`, `picture`
- signed with a different key fails
- wrong `iss` fails
- wrong `aud` (not our client id) fails
- expired `exp` fails
- `alg=none` and `HS256` tokens fail (algorithm pinned to RS256)
- `kid` not in JWKS fails
- missing `sub` fails
- token endpoint request sends Basic auth header, `code_verifier`, `redirect_uri` (assert on the fake HTTP client)

### PKCE and state
- verifier length and charset valid, challenge equals base64url(SHA256(verifier))
- state is random, two calls differ
- tampered signed cookie rejected
- expired state (over 10 min) rejected
- state cannot be reused (single use)

### Token service
- access JWT contains only `sub`, `iat`, `exp`, `iss`, `aud`
- verify rejects: wrong secret, expired, wrong `iss`, wrong `aud`, `alg=none`, different algorithm
- refresh token has 32 bytes of entropy, only the SHA-256 hash is returned for storage
- hash is deterministic, raw token never appears in the DB row

### Linking decision (pure function)
Input: identity lookup result, provider, profile, existing user by email. Output: action.

| Case | Expected |
|---|---|
| identity exists | login that user |
| Google, verified email, user exists | link to existing user |
| Google, verified email, no user | create user and identity |
| Google, `email_verified=false`, user with that email exists | create separate user, no link |
| Facebook with email, user with that email exists | create separate user, no link |
| Telegram, no email | create user, email null |
| email casing differs (`A@x.com` vs `a@x.com`) | treated equal |

### Config
- missing required env fails at boot with a clear message
- provider with empty credentials is not registered
- `JWT_SECRET` shorter than minimum fails

## 3. Integration tests

Setup: separate test database, migrations applied once, tables truncated between tests. Fake providers implement `OAuthProvider` and return canned profiles, so the whole flow runs without network.

### Redirect flow (Google fake)
- `GET /auth/google`: 302, `Location` has `state`, `code_challenge`, correct `redirect_uri`; sets signed `oauth_state` cookie
- callback with valid state and code: 302 to `FRONTEND_URL/auth/callback`, refresh cookie set (HttpOnly, Secure flag per config, `Path=/auth`), user and identity rows created
- callback with wrong `state`: 302 with `error=invalid_state`, no user created
- callback without `oauth_state` cookie: same
- callback with `error=access_denied`: redirect with `error=access_denied`
- second login same Google account: same user id, no duplicate rows, `last_login_at` updated
- unknown provider: 404

### Telegram (redirect flow, fake token endpoint and JWKS)
- `GET /auth/telegram`: 302 to the Telegram authorize URL with `state`, `code_challenge`, `scope=openid profile`
- valid callback: 302 to SPA, cookie set, user created with `email` null
- invalid `id_token` (bad signature, `aud`, `iss`, expired): redirect with `error=provider_error`, no user created
- Telegram never auto-links by email, even if a user with the same name exists
- state mismatch and `access_denied`: same behavior as Google tests

### Refresh and logout
- refresh with valid cookie: 200, new access token, cookie rotated, old row revoked, new row same `family_id`
- refresh without `X-Requested-With`: 403
- refresh without cookie: 401 `refresh_missing`
- expired refresh: 401 `refresh_expired`
- reuse of a revoked token (older than grace): 401 `refresh_reused`, whole family revoked, the newest token also stops working
- reuse inside the 10 s grace window: returns successor, family stays alive
- two parallel refreshes with the same cookie: neither kills the session
- family older than 90 days: 401
- logout: 204, family revoked, cookie cleared, repeated logout also 204

### Account linking
- `POST /auth/link/google` with JWT: 200 with URL, state cookie carries user id
- link callback attaches identity to the current user, redirects to settings URL
- linking a provider account owned by another user: 409 `identity_taken`, no changes
- linking the same provider twice: 409 `already_linked`
- link without JWT: 401
- unlink: 204, identity row removed
- unlink the only identity: 409 `last_identity`
- unlink not linked provider: 404 `not_linked`
- Telegram link through the same redirect flow with JWT: identity attached

### `/me`
- valid JWT: profile with providers list
- no, expired, tampered token: 401 with matching code
- deleted user with valid JWT: 401

### Cross-cutting
- CORS: allowed origin gets headers with credentials, other origins do not
- rate limit: 21st request in a minute gets 429 with `Retry-After`
- body over limit: 413
- error format is always `{ error: { code, message } }`, no stack traces
- logs: after a full login, captured log output does not contain the token, cookie, `code`, `state` or secrets (regression test for I4)

## 4. Security regression checklist (maps to THREAT_MODEL.md)

| Threat | Covered by |
|---|---|
| S1, S2 | Telegram `id_token` unit tests, state and PKCE tests |
| S3 | state tests, callback tests |
| S5 | linking decision table, Facebook no-link case |
| S6 | token service verify tests |
| T2 | redirect target test: callback params cannot change destination |
| I2 | DB row inspected, no raw token |
| I3 | callback redirect `Location` contains no token |
| I4 | log redaction test |
| D1, D2 | rate limit and body limit tests |
| E1, E2 | `identity_taken`, `last_identity` |

## 5. Manual E2E (real providers)

Run once after adapters are done, with the tunnel up. Record outcome in the PR.

- [ ] Google: new user login, second login (same user), denied consent
- [ ] Google: account with unverified-email scenario not testable, covered by unit test
- [ ] Facebook: login with email permission granted, then with email permission declined at the consent screen
- [ ] Telegram: OIDC login (localhost redirect URI, or tunnel URL if Telegram rejects localhost)
- [ ] Link Telegram to a Google account, then unlink, then try unlinking the last one
- [ ] Refresh flow in the browser: access expires, SPA refreshes silently
- [ ] Two tabs refreshing together do not log out
- [ ] Cookie flags checked in DevTools: HttpOnly, SameSite=Lax, Path=/auth
- [ ] No token visible in URL, history, or network tab URLs

## 6. Test data and tooling

- Fake provider factory: `fakeProvider({ id, email, emailVerified, name })`
- User and identity builders for DB setup
- Time control: `jest.useFakeTimers()` or an injected clock service (prefer injected clock, easier to port to Go)
- Scripts: `test` (unit), `test:int` (integration, starts on test DB), `test:cov`
- CI: not in scope for this task, but scripts must run non-interactively

## 7. Coverage target

No blanket percentage. Required: 100% of the Telegram verifier, linking decision, token verify and refresh rotation branches. Everything else: whatever the listed cases cover.

## 8. Definition of Done

- all unit and integration tests green locally
- manual E2E checklist done for Google; Telegram and Facebook done or explicitly listed as not done with reason
- no secret in repo (`git grep` for the known key prefixes)
- docs synced with final behavior
