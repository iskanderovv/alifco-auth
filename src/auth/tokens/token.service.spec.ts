import { SignJWT, decodeJwt } from 'jose';
import { AppError } from '../../common/app-error';
import { fakeConfig, TEST_TOKEN_CONFIG } from '../../../test/helpers/db';
import { PrismaService } from '../../prisma/prisma.service';
import { TokenService, ttlToSeconds } from './token.service';

const USER_ID = '3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b';
const SECRET = new TextEncoder().encode(TEST_TOKEN_CONFIG.JWT_SECRET);

// Access token logic never touches the database, so Prisma is not needed here.
function makeService(overrides = {}): TokenService {
  return new TokenService(
    {} as PrismaService,
    fakeConfig({ ...TEST_TOKEN_CONFIG, ...overrides }),
  );
}

/** Builds a token the way an attacker or a buggy client might, to see what is rejected. */
function craft(
  claims: { iss?: string; aud?: string; exp?: number; sub?: string } = {},
  alg: 'HS256' | 'HS512' = 'HS256',
  key: Uint8Array = SECRET,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({})
    .setProtectedHeader({ alg })
    .setIssuer(claims.iss ?? 'oauth-service')
    .setAudience(claims.aud ?? 'oauth-service-api')
    .setIssuedAt(now)
    .setExpirationTime(claims.exp ?? now + 600);
  if (claims.sub !== 'omit') {
    jwt.setSubject(claims.sub ?? USER_ID);
  }
  return jwt.sign(key);
}

async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toMatchObject({ code });
  await expect(promise).rejects.toBeInstanceOf(AppError);
}

describe('TokenService access tokens', () => {
  const service = makeService();

  it('issues a token with only the minimal claims and verifies it', async () => {
    const { accessToken, expiresIn } = await service.issueAccessToken(USER_ID);
    const claims = decodeJwt(accessToken);

    expect(expiresIn).toBe(900);
    expect(Object.keys(claims).sort()).toEqual(
      ['aud', 'exp', 'iat', 'iss', 'sub'].sort(),
    );
    expect(claims.exp! - claims.iat!).toBe(900);
    await expect(service.verifyAccessToken(accessToken)).resolves.toEqual({
      userId: USER_ID,
    });
  });

  it('rejects an expired token with token_expired', async () => {
    const past = Math.floor(Date.now() / 1000) - 10;
    await expectCode(
      service.verifyAccessToken(await craft({ exp: past })),
      'token_expired',
    );
  });

  it('rejects a token signed with another secret', async () => {
    const other = new TextEncoder().encode(
      'another-secret-another-secret-12345',
    );
    await expectCode(
      service.verifyAccessToken(await craft({}, 'HS256', other)),
      'token_invalid',
    );
  });

  it('rejects a different algorithm even when the secret is right', async () => {
    await expectCode(
      service.verifyAccessToken(await craft({}, 'HS512')),
      'token_invalid',
    );
  });

  it('rejects alg none', async () => {
    const b64 = (value: object) =>
      Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
      sub: USER_ID,
      iss: 'oauth-service',
      aud: 'oauth-service-api',
      exp: Math.floor(Date.now() / 1000) + 600,
    })}.`;
    await expectCode(service.verifyAccessToken(unsigned), 'token_invalid');
  });

  it('rejects wrong issuer, wrong audience and missing subject', async () => {
    await expectCode(
      service.verifyAccessToken(await craft({ iss: 'someone-else' })),
      'token_invalid',
    );
    await expectCode(
      service.verifyAccessToken(await craft({ aud: 'another-api' })),
      'token_invalid',
    );
    await expectCode(
      service.verifyAccessToken(await craft({ sub: 'omit' })),
      'token_invalid',
    );
  });

  it('rejects garbage', async () => {
    await expectCode(service.verifyAccessToken('not.a.jwt'), 'token_invalid');
    await expectCode(service.verifyAccessToken(''), 'token_invalid');
  });

  it('honours the configured TTL', async () => {
    const short = makeService({ JWT_ACCESS_TTL: '2h' });
    const { expiresIn } = await short.issueAccessToken(USER_ID);
    expect(expiresIn).toBe(7200);
  });
});

describe('ttlToSeconds', () => {
  it.each([
    ['30s', 30],
    ['15m', 900],
    ['2h', 7200],
    ['7d', 604_800],
  ])('%s is %i seconds', (ttl, seconds) => {
    expect(ttlToSeconds(ttl)).toBe(seconds);
  });

  it('rejects an invalid format', () => {
    expect(() => ttlToSeconds('15')).toThrow();
  });
});
