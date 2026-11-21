# Security

The threats I considered, what stops each one, where in the code it is stopped, and which test shows it. Anything that is not covered by an automated test is marked as such.

## What is protected

| Asset | Why it matters |
|---|---|
| User accounts | Taking one over gives access to everything behind the login |
| Refresh tokens | A 30 day session |
| Access tokens | A 15 minute session |
| `JWT_SECRET` | Whoever has it can issue tokens for any user |
| Provider secrets and the cookie secret | Impersonating the app, forging the `oauth_tx` cookie |
| Email, name, picture | Personal data |

## Trust boundaries

- **Browser to API.** Fully untrusted input: query strings, cookies, headers and bodies.
- **API to provider.** Identity claims are trusted only after they are verified. A provider's response body is never copied into an error or a log.
- **API to PostgreSQL.** Parameterised queries only. The one raw query (the row lock) uses a tagged template, so the user id is a bound parameter.
- **Environment.** Secrets live in the environment, never in the repository.

## Threats and mitigations

### Spoofing and account takeover

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| **Pre-registration takeover.** An attacker signs up through Facebook with the victim's email, and the victim later signs in with Google and is merged into the attacker's account | Accounts are matched only by `(provider, provider_user_id)`. `users.email` is set only for a provider-verified email and is never used to find an account | `IdentityService.loginWithProfile` | `identity.service.int-spec`: "does not merge accounts by email: pre-account takeover is not possible" |
| A forged or substituted `id_token` | Signature checked against the provider's keys, algorithm pinned to RS256, `iss`, `aud` and `exp` checked, `sub` required | `oidc.ts` `verifyIdToken` | `google.provider.spec`, `telegram.provider.spec`: wrong audience, issuer, key, `kid`, ES256, HS256, no subject, expired |
| JWT forgery: `alg: none`, algorithm confusion | The verifier pins `HS256` and checks issuer, audience and expiry | `TokenService.verifyAccessToken` | `token.service.spec`: `alg none`, `HS512`, another secret, wrong claims |
| Login CSRF: the victim is logged into the attacker's account | `state` is random, stored hashed, bound to the browser by the `oauth_tx` cookie, single use | `OAuthTransactionService` | `oauth-transaction.service.int-spec`, `auth.flow.int-spec`: wrong state, missing cookie, other provider, expired, replay |
| An intercepted authorization code | PKCE (S256) on every provider: the code is useless without the verifier | `*.provider.ts` | Authorization URL and token request asserted in the provider specs; Facebook accepted PKCE in the live test |
| Replay of a callback | The transaction is consumed by one conditional `UPDATE`; a second use matches no row | `OAuthTransactionService.consume` | "lets exactly one of two concurrent callbacks succeed" |

### Session theft and CSRF

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| XSS steals the refresh token | `httpOnly` cookie. The access token lives only in memory and is never in `localStorage` | `CookieService` | `auth.flow.int-spec`: cookie flags |
| A stolen refresh token is used in parallel with the owner | Single-use rotation. Presenting an already used token revokes the whole family | `TokenService.rotateRefreshToken` | `token.service.int-spec`: reuse, parallel rotation. Load test: 100 parallel refreshes of one token give exactly one success |
| CSRF on refresh and logout | `SameSite=Lax`, a custom header that forces a CORS preflight, an `Origin` check, a strict CORS allowlist | `CsrfGuard`, `app.setup.ts` | `auth.flow.int-spec`: missing header, wrong origin, CORS from another origin |
| Tokens in URLs, history or `Referer` | The callback redirect carries no token. The SPA calls `/auth/refresh` afterwards | `AuthController.callback` | `auth.flow.int-spec`: the redirect equals the callback URL with no query |
| A database leak hands out sessions | Refresh tokens and `state` are stored as SHA-256 hashes | `TokenService`, `OAuthTransactionService` | `token.service.int-spec`: the raw token is not in the row |
| Subdomain cookie theft | Cookies are host-only, with no `Domain` | `CookieService` | `auth.flow.int-spec`: no `Domain=` |

### Integrity

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Two first logins at once create two users | The unique index decides, the loser logs in the winner's user | `IdentityService` | "creates exactly one user when the same first login arrives concurrently". A mutation check showed this test fails without the `P2002` handling |
| Merging by linking an account that belongs to someone else | Linking is explicit and refused with `identity_taken` | `IdentityService.linkProfile` | `identity.link.int-spec`, `auth.link.int-spec` |
| Locking oneself out by unlinking | The last provider cannot be removed, and the user row is locked so two concurrent unlinks cannot remove both | `IdentityService.unlink` | The lock test. A mutation check showed the test fails without `FOR UPDATE` (an earlier version of it did not, and was rewritten) |
| SQL injection | Prisma parameterises everything. The raw query binds its parameter. Input that reaches a `uuid` column is checked first | `isUuid`, `unlink` | `crypto.spec`, `oauth-transaction.service.int-spec`: `' OR 1=1 --` is rejected without a database error |
| Open redirect | Redirect targets are built from `FRONTEND_URL`. Callback errors map to a fixed list of codes | `AuthController` | `auth.flow.int-spec`: `error_description` and provider messages never reach the URL |

### Information disclosure

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Secrets in logs | The request logger drops headers, cookies and query strings. The log redacts known fields | `app.module.ts` | Pattern scans of real server logs after live logins (no tokens, `code`, `state`, secrets, JWTs). **Not an automated test** |
| Provider responses echoed into errors | Errors name the failed step, never the body. Only the standard OAuth error code is copied | `oidc.ts`, `facebook.provider.ts` | The provider specs assert that response bodies are not in the message |
| App secret or access token leaked in a URL | Facebook and Google use a POST body for the secret, Telegram uses HTTP Basic. Facebook calls carry `appsecret_proof` | providers | `facebook.provider.spec`, `telegram.provider.spec` |
| Secrets in the repository | `.env` is ignored. Configuration is validated at startup | `.gitignore`, `env.ts` | Before each push the tracked files and the whole history were scanned for token shapes and private keys |
| Stack traces to the client | One exception filter. Unexpected errors become a generic 500 | `AllExceptionsFilter` | `auth.flow.int-spec`: error format |

### Denial of service

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Hammering the auth endpoints | Throttling: 20 per minute on `/auth/*`, 10 on refresh, 60 elsewhere, `/health` exempt | `ThrottlerModule`, `@Throttle` | **Checked by hand** against a running server (429 with `Retry-After`). Not an automated test, because the tests switch it off |
| Large or malformed bodies | A body size limit and validation | `app.setup.ts` | `auth.flow.int-spec`: 413 and 400 |
| A slow provider hangs a request | A timeout on every outgoing call | providers, `oidc.ts` | Provider specs: network failure, non-200 |
| Table growth | Not mitigated | | Rows are never deleted. See the known limits in the README |

## Residual risks

- A stolen refresh token works until the owner refreshes next, or it expires. Reuse is detected only then.
- Two tabs refreshing at the same moment look like a theft and log the user out. The SPA must send refresh calls one at a time.
- A compromised provider account is a compromised login here.
- `HS256` means one secret signs and verifies. If it leaks, rotate it. Existing access tokens die within 15 minutes, refresh tokens survive.
- Rate limiting and the client IP assume exactly one proxy in front.
- The Telegram verifier pins RS256. If BotFather's signing algorithm is changed, Telegram logins fail closed.
