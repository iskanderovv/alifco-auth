# Testing

## Approach

The guarantees this service makes are mostly database behaviour: an atomic update that only one request can win, unique indexes that decide races, a row lock. A mock cannot show any of them, so the tests that matter run against a real PostgreSQL and replace only the outside world.

| Layer | What it covers | Needs |
|---|---|---|
| Unit | Pure logic and the adapters: JWT checks, PKCE, hashing, email and name rules, the key loader, Google, Facebook and Telegram with `fetch` and the signing keys injected | nothing |
| Integration | Services and the HTTP flow with a real database and fake providers: rotation, reuse, state, linking, concurrency, CORS, error format, the OpenAPI document | PostgreSQL |
| Manual, real providers | Each login flow with a real account, including linking | provider apps and a tunnel |
| Load | Throughput and the parallel-refresh guarantee | a running instance |

No automated test calls Google, Facebook or Telegram. Provider responses are fakes, `id_token`s are signed in the test with a key pair generated there, and the key endpoint is a local server.

## Numbers

| | Count |
|---|---|
| Unit tests | 106 |
| Integration tests | 91 |

```bash
npm test            # unit
npm run test:int    # integration, needs the oauth_test database (see the README)
```

CI runs both on every push, together with format, lint, type check and build.

## What the tests are meant to catch

- **Races.** Two concurrent callbacks, two concurrent first logins, two refreshes of one token, two users linking one account, two concurrent unlinks. Each test starts the competing calls together and asserts that exactly one wins and the data stays consistent.
- **Replay and forgery.** State reuse, wrong provider, expired transaction, forged `state`, a token with another algorithm, issuer, audience or key.
- **Leaks.** Provider response bodies and `error_description` must not reach an error or a URL. Secrets must not be in a request URL.
- **The linking rules.** No merge by email, `identity_taken`, `already_linked`, the last provider cannot be removed.

## Checking that the tests can fail

A test that has never failed proves little, so the important ones were checked by breaking the code on purpose:

| Mutation | Result |
|---|---|
| Stop handling the unique-violation (`P2002`) in `loginWithProfile` | The concurrent first-login test failed, as it should |
| Remove `FOR UPDATE` from `unlink` | **The test still passed.** It had been relying on timing. It was rewritten to hold the lock deliberately from a second transaction. Without the lock two tests now fail |

The second row is the useful one: the first version of that test gave false confidence, and only the mutation exposed it.

## Real providers

Each provider was exercised with a real account against a real app, through a public tunnel (Telegram refuses `http://localhost`):

- Google, Facebook and Telegram login, then `refresh` and `/me`.
- Linking and unlinking between them, including the refusal when an account already has its own profile.
- Server logs scanned after each run for tokens, `code`, `state`, cookies and secrets, by pattern.

These runs found two bugs the automated tests could not: Telegram's gzip answer to the key request, and picture links that expire.

## Load test

`npm run stress` seeds users and sessions into a `*_test` database (it refuses any other name) and runs autocannon scenarios plus a 100-way parallel refresh. On a laptop, 50 connections, 10 seconds each:

| Scenario | Result |
|---|---|
| `GET /health` | about 30,900 req/s |
| `GET /me` (JWT check and a query) | about 6,600 req/s, p99 11 ms |
| `POST /auth/refresh`, 300 sessions | all 200 |
| `GET /auth/google` (writes a row) | about 8,400 req/s |
| Callback with a wrong state | about 9,800 req/s |
| 100 parallel refreshes of one token | exactly one 200, 99 rejected, no token left active |

Errors and timeouts were zero in every scenario. The rate limits were then checked on an instance with throttling on.

## Not covered

- The rate limits have no automated test. They were verified by hand.
- Log redaction has no automated test, only pattern scans of real logs.
- The picture links are not fetched, so an expired link shows as the initial in the dev SPA and is not detected by the service.
- There is no browser-level test of the SPA. The dev SPA is a manual tool.
- Nothing tests more than one instance of the service. The in-memory throttler and the single-instance migration step assume one.
