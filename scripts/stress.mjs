// Load test against a running API. Seeds users and sessions straight into the test database.
// Start the API first with the same JWT_SECRET (see README), then: npm run stress
import { createHash, randomBytes } from 'node:crypto';
import autocannon from 'autocannon';
import { SignJWT } from 'jose';
import pg from 'pg';

const BASE_URL = process.env.BASE_URL ?? 'http://localhost:3100';
const DATABASE_URL =
  process.env.DATABASE_URL ??
  'postgresql://oauth:oauth@localhost:5432/oauth_test';
const JWT_SECRET =
  process.env.JWT_SECRET ?? 'stress-jwt-secret-stress-jwt-secret-1234';
const USERS = Number(process.env.USERS ?? 300);
const DURATION = Number(process.env.DURATION ?? 10);
const CONNECTIONS = Number(process.env.CONNECTIONS ?? 50);

if (!/_test(\?.*)?$/.test(DATABASE_URL)) {
  console.error('Refusing to seed: DATABASE_URL must point at a *_test database.');
  process.exit(1);
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const pool = new pg.Pool({ connectionString: DATABASE_URL, max: 4 });
const key = new TextEncoder().encode(JWT_SECRET);

async function seed() {
  await pool.query(
    'TRUNCATE oauth_transactions, refresh_tokens, oauth_identities, users CASCADE',
  );
  const sessions = [];
  for (let i = 0; i < USERS + 1; i++) {
    const { rows } = await pool.query(
      'INSERT INTO users (name, updated_at) VALUES ($1, now()) RETURNING id',
      [`Load User ${i}`],
    );
    const userId = rows[0].id;
    await pool.query(
      "INSERT INTO oauth_identities (user_id, provider, provider_user_id) VALUES ($1, 'google', $2)",
      [userId, `load-${i}`],
    );
    const refresh = randomBytes(32).toString('base64url');
    await pool.query(
      "INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at) VALUES ($1, gen_random_uuid(), $2, now() + interval '30 days')",
      [userId, sha256(refresh)],
    );
    const now = Math.floor(Date.now() / 1000);
    const access = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(userId)
      .setIssuer('oauth-service')
      .setAudience('oauth-service-api')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(key);
    sessions.push({ userId, refresh, access });
  }
  return sessions;
}

function report(name, result, expected) {
  const statuses = Object.entries(result.statusCodeStats ?? {})
    .map(([code, stat]) => `${code}:${stat.count}`)
    .join(' ');
  const ok = Object.keys(result.statusCodeStats ?? {}).every((code) =>
    expected.includes(Number(code)),
  );
  console.log(
    [
      name.padEnd(34),
      `${Math.round(result.requests.average)} req/s`.padEnd(12),
      `p50 ${result.latency.p50}ms`.padEnd(11),
      `p99 ${result.latency.p99}ms`.padEnd(11),
      `max ${result.latency.max}ms`.padEnd(12),
      `errors ${result.errors} timeouts ${result.timeouts}`.padEnd(22),
      `[${statuses}]`,
      ok && !result.errors && !result.timeouts ? 'PASS' : 'FAIL',
    ].join(' '),
  );
  return ok && !result.errors && !result.timeouts;
}

const run = (options) =>
  autocannon({ url: BASE_URL, connections: CONNECTIONS, ...options });

async function main() {
  console.log(`target ${BASE_URL}, ${CONNECTIONS} connections, ${DURATION}s per scenario\n`);
  const sessions = await seed();
  const results = [];

  results.push(
    report(
      'GET /health',
      await run({ duration: DURATION, requests: [{ method: 'GET', path: '/health' }] }),
      [200],
    ),
  );

  let n = 0;
  results.push(
    report(
      'GET /me (JWT verify + DB read)',
      await run({
        duration: DURATION,
        requests: [
          {
            method: 'GET',
            path: '/me',
            setupRequest: (req) => ({
              ...req,
              headers: {
                authorization: `Bearer ${sessions[n++ % USERS].access}`,
              },
            }),
          },
        ],
      }),
      [200],
    ),
  );

  let r = 0;
  results.push(
    report(
      `POST /auth/refresh (${USERS} sessions)`,
      await run({
        amount: USERS,
        connections: 20,
        requests: [
          {
            method: 'POST',
            path: '/auth/refresh',
            setupRequest: (req) => ({
              ...req,
              headers: {
                'x-requested-with': 'fetch',
                cookie: `refresh_token=${sessions[r++].refresh}`,
              },
            }),
          },
        ],
      }),
      [200],
    ),
  );

  results.push(
    report(
      'GET /auth/google (start, DB write)',
      await run({
        duration: DURATION,
        requests: [{ method: 'GET', path: '/auth/google' }],
      }),
      [302],
    ),
  );

  results.push(
    report(
      'GET /auth/google/callback (bad state)',
      await run({
        duration: DURATION,
        requests: [
          {
            method: 'GET',
            path: '/auth/google/callback?code=x&state=forged',
            headers: { cookie: 'oauth_tx=00000000-0000-4000-8000-000000000000' },
          },
        ],
      }),
      [302],
    ),
  );

  const racer = sessions[USERS];
  const burst = 100;
  const responses = await Promise.all(
    Array.from({ length: burst }, () =>
      fetch(`${BASE_URL}/auth/refresh`, {
        method: 'POST',
        headers: {
          'x-requested-with': 'fetch',
          cookie: `refresh_token=${racer.refresh}`,
        },
      }).then((res) => res.status),
    ),
  );
  const wins = responses.filter((status) => status === 200).length;
  const rejected = responses.filter((status) => status === 401).length;
  const active = (
    await pool.query(
      'SELECT count(*)::int AS n FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL',
      [racer.userId],
    )
  ).rows[0].n;
  const raceOk = wins <= 1 && wins + rejected === burst && active === 0;
  console.log(
    `${`${burst} parallel refreshes, one token`.padEnd(34)} 200:${wins} 401:${rejected} active tokens left: ${active}  ${raceOk ? 'PASS' : 'FAIL'}`,
  );
  results.push(raceOk);

  await pool.end();
  const failed = results.filter((ok) => !ok).length;
  console.log(`\n${failed === 0 ? 'all scenarios passed' : `${failed} scenario(s) failed`}`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
