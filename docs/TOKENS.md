# Token Design

Client is an SPA on a different origin than the API.

## 1. Two tokens

| | Access token | Refresh token |
|---|---|---|
| Format | JWT | Opaque random string (32 bytes, base64url) |
| Lifetime | 15 min | 30 days (sliding, max by family age, see 5) |
| Stored by client | JS memory only (not localStorage) | httpOnly cookie |
| Stored by server | nothing (stateless) | SHA-256 hash in `refresh_tokens` |
| Sent how | `Authorization: Bearer <jwt>` | cookie, only to `/auth/refresh` and `/auth/logout` |
| Revocable | no, expires fast | yes |

Why: XSS cannot steal the refresh token (httpOnly). CSRF cannot abuse it (see 4). A leaked access token lives at most 15 minutes.

## 2. Access JWT

Algorithm: HS256 for now (single service, one secret). If a second service must verify tokens, switch to RS256/EdDSA and publish a JWKS. Header must pin `alg`, verifier must reject `none` and any other alg.

Claims:

```json
{
  "sub": "<users.id uuid>",
  "iat": 1760000000,
  "exp": 1760000900,
  "iss": "oauth-service",
  "aud": "oauth-service-api"
}
```

Deliberately minimal: no email, no roles, no provider. Profile data comes from `GET /me`. Smaller token, nothing stale inside it.

Verifier checks: signature, `exp`, `iss`, `aud`.

## 3. Refresh token lifecycle

Generate: `crypto.randomBytes(32)` base64url. Store only `sha256(token)` hex.

```
login
  family_id = new uuid
  insert row (family_id, hash, expires_at = now+30d)
  Set-Cookie refresh_token

POST /auth/refresh
  hash = sha256(cookie)
  row = find by hash
  none                -> 401
  row.revoked_at set  -> REUSE DETECTED: revoke every row in family_id, 401
  row.expires_at past -> 401
  else:
    mark row revoked_at=now, create new row (same family_id), set replaced_by
    return new access JWT + new refresh cookie

POST /auth/logout
  revoke whole family, clear cookie
```

Concurrency: SPA can fire two refreshes at once (two tabs). Second one would look like reuse and kill the session. Mitigation: grace window of 10 seconds. If the presented token was revoked less than 10s ago and `replaced_by` exists, return the already issued successor instead of revoking the family. Frontend should also serialize refresh calls (single in-flight promise).

## 4. Cookie and CSRF

```
Set-Cookie: refresh_token=<token>;
  HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age=2592000
```

- `Path=/auth`: browser sends it only to auth endpoints.
- If SPA and API are on different registrable domains, `SameSite=Lax` blocks the cookie on fetch. Then we need `SameSite=None; Secure` plus CSRF defense. Recommended deployment: same site (`app.example.com` and `api.example.com`) so Lax works.
- CSRF defense for `/auth/refresh` and `/auth/logout`: require a custom header (`X-Requested-With: fetch`) and strict CORS allowlist (`FRONTEND_URL` only, `credentials: true`). A cross-site form cannot set a custom header.
- `/auth/refresh` is POST only.

## 5. Limits

- Sliding: each rotation gets a fresh 30 days.
- Absolute cap: family older than 90 days cannot be rotated, user must log in again. Needs `families` age: use `min(created_at) of family`, no extra column.
- Cleanup job: delete rows with `expires_at < now() - 7 days`.

## 6. After OAuth callback (redirect flow)

Callback returns a 302 to the SPA. Tokens must not appear in the URL.

1. Server sets the refresh cookie on the callback response.
2. Redirect to `FRONTEND_URL/auth/callback` (no tokens in URL).
3. SPA calls `POST /auth/refresh` (cookie sent automatically), receives the access JWT in the JSON body.

Telegram uses the same redirect flow (OIDC), so there is no special case.

Same code path for all three providers on the SPA side: always end with a refresh call.

## 7. Config

| Env | Example | Note |
|---|---|---|
| `JWT_SECRET` | 64+ random bytes | never committed |
| `JWT_ACCESS_TTL` | `15m` | |
| `REFRESH_TTL_DAYS` | `30` | |
| `REFRESH_FAMILY_MAX_DAYS` | `90` | |
| `REFRESH_GRACE_SECONDS` | `10` | |
| `COOKIE_DOMAIN` | `.example.com` | empty in local dev |
| `COOKIE_SECURE` | `true` | `false` only on http localhost |

## 8. Decisions to confirm

1. HS256 now, migrate to asymmetric later if needed. OK?
2. Access 15 min, refresh 30 days, family cap 90 days. OK?
3. SPA and API on the same site (subdomains of one domain). Affects cookie settings.
