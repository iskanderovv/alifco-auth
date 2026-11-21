import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type JWTVerifyGetKey,
  type KeyLike,
} from 'jose';
import { AppError } from '../../common/app-error';
import { TelegramProvider } from './telegram.provider';

const CLIENT_ID = '123456789';
const CLIENT_SECRET = 'telegram-client-secret';
const REDIRECT_URI = 'http://localhost:3000/auth/telegram/callback';
const ISSUER = 'https://oauth.telegram.org';

let privateKey: KeyLike;
let otherPrivateKey: KeyLike;
let getKey: JWTVerifyGetKey;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  const other = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  otherPrivateKey = other.privateKey;
  const jwk: JWK = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'tg-key',
    alg: 'RS256',
    use: 'sig',
  };
  getKey = createLocalJWKSet({ keys: [jwk] });
});

interface TokenOptions {
  claims?: Record<string, unknown>;
  iss?: string;
  aud?: string;
  /** Seconds from now. Negative means already expired. */
  expiresIn?: number;
  /** Seconds from now. Positive means not valid yet. */
  notBefore?: number;
  key?: KeyLike;
  kid?: string;
  omitSub?: boolean;
}

function signIdToken(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({
    name: 'Ali Valiyev',
    preferred_username: 'ali_tg',
    picture: 'https://t.me/i/userpic/320/ali.jpg',
    ...options.claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: options.kid ?? 'tg-key' })
    .setIssuer(options.iss ?? ISSUER)
    .setAudience(options.aud ?? CLIENT_ID)
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 600));
  if (options.notBefore !== undefined) {
    jwt.setNotBefore(now + options.notBefore);
  }
  if (!options.omitSub) {
    jwt.setSubject('tg-sub-42');
  }
  return jwt.sign(options.key ?? privateKey);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function makeProvider(fetchFn: typeof fetch): TelegramProvider {
  return new TelegramProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    timeoutMs: 1000,
    fetchFn,
    getKey,
  });
}

const respondWith = (idToken: Promise<string>) =>
  jest
    .fn()
    .mockImplementation(async () =>
      jsonResponse({ id_token: await idToken }),
    ) as unknown as typeof fetch;

const input = { code: 'auth-code', codeVerifier: 'verifier-value' };

describe('TelegramProvider', () => {
  it('builds an authorization code + PKCE S256 request without the phone scope', () => {
    const url = new URL(
      makeProvider(jest.fn()).getAuthorizationUrl('the-state', 'the-challenge'),
    );

    expect(`${url.origin}${url.pathname}`).toBe(
      'https://oauth.telegram.org/auth',
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'openid profile',
      state: 'the-state',
      code_challenge: 'the-challenge',
      code_challenge_method: 'S256',
    });
  });

  it('exchanges the code with HTTP Basic client auth and maps the verified id_token', async () => {
    const fetchFn = jest
      .fn()
      .mockResolvedValue(jsonResponse({ id_token: await signIdToken() }));
    const profile = await makeProvider(fetchFn).authenticate(input);

    expect(profile).toEqual({
      providerUserId: 'tg-sub-42',
      emailVerified: false,
      name: 'Ali Valiyev',
      username: 'ali_tg',
      avatarUrl: 'https://t.me/i/userpic/320/ali.jpg',
    });

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://oauth.telegram.org/token');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>).authorization).toBe(
      `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
    );
    const body = Object.fromEntries(init.body as URLSearchParams);
    expect(body).toEqual({
      grant_type: 'authorization_code',
      code: 'auth-code',
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: 'verifier-value',
    });
    // The secret travels only in the Basic header, never in the body.
    expect(JSON.stringify(body)).not.toContain(CLIENT_SECRET);
  });

  it('never reports an email, and tolerates a token with only a subject', async () => {
    const idToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'tg-key' })
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setSubject('tg-sub-1')
      .setExpirationTime('10m')
      .sign(privateKey);

    const profile = await makeProvider(
      respondWith(Promise.resolve(idToken)),
    ).authenticate(input);
    expect(profile).toEqual({
      providerUserId: 'tg-sub-1',
      emailVerified: false,
      name: undefined,
      username: undefined,
      avatarUrl: undefined,
    });
  });

  it('ignores an email claim even if one were present', async () => {
    const idToken = signIdToken({
      claims: { email: 'x@y.com', email_verified: true },
    });
    const profile = await makeProvider(respondWith(idToken)).authenticate(
      input,
    );
    expect(profile.email).toBeUndefined();
    expect(profile.emailVerified).toBe(false);
  });

  describe('clock tolerance', () => {
    it('accepts a token that expired a few seconds ago (clock skew)', async () => {
      const idToken = signIdToken({ expiresIn: -10 });
      await expect(
        makeProvider(respondWith(idToken)).authenticate(input),
      ).resolves.toBeDefined();
    });

    it('accepts a token that becomes valid a few seconds from now', async () => {
      const idToken = signIdToken({ notBefore: 10 });
      await expect(
        makeProvider(respondWith(idToken)).authenticate(input),
      ).resolves.toBeDefined();
    });

    it('rejects a token that expired long ago', async () => {
      const idToken = signIdToken({ expiresIn: -120 });
      await expect(
        makeProvider(respondWith(idToken)).authenticate(input),
      ).rejects.toMatchObject({ code: 'provider_error' });
    });

    it('rejects a token that is not valid yet by a wide margin', async () => {
      const idToken = signIdToken({ notBefore: 300 });
      await expect(
        makeProvider(respondWith(idToken)).authenticate(input),
      ).rejects.toMatchObject({ code: 'provider_error' });
    });
  });

  describe('rejects with provider_error', () => {
    async function expectProviderError(fetchFn: typeof fetch) {
      const promise = makeProvider(fetchFn).authenticate(input);
      await expect(promise).rejects.toBeInstanceOf(AppError);
      await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
    }

    it('a token for another audience (another bot)', async () => {
      await expectProviderError(respondWith(signIdToken({ aud: '999999999' })));
    });

    it('names the failed check without echoing token values', async () => {
      const promise = makeProvider(
        respondWith(signIdToken({ aud: '999999999' })),
      ).authenticate(input);
      await expect(promise).rejects.toThrow(/claim aud/);
      await expect(promise).rejects.not.toThrow(/999999999/);
    });

    it('does not copy an error value that is not a plain identifier', async () => {
      const fetchFn = jest
        .fn()
        .mockResolvedValue(
          jsonResponse({ error: 'Invalid code auth-code!' }, 400),
        );
      const promise = makeProvider(fetchFn).authenticate(input);
      await expect(promise).rejects.toThrow(/returned 400$/);
      await expect(promise).rejects.not.toThrow(/Invalid|auth-code/);
    });

    it('a token from another issuer', async () => {
      await expectProviderError(
        respondWith(signIdToken({ iss: 'https://evil.example.com' })),
      );
    });

    it('a token signed with a key that is not in the JWKS', async () => {
      await expectProviderError(
        respondWith(signIdToken({ key: otherPrivateKey })),
      );
    });

    it('a token whose kid is unknown', async () => {
      await expectProviderError(respondWith(signIdToken({ kid: 'nope' })));
    });

    it('an ES256 token, because the algorithm is pinned to RS256', async () => {
      const ec = await generateKeyPair('ES256');
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'ES256', kid: 'tg-key' })
        .setIssuer(ISSUER)
        .setAudience(CLIENT_ID)
        .setSubject('x')
        .setExpirationTime('10m')
        .sign(ec.privateKey);
      await expectProviderError(respondWith(Promise.resolve(token)));
    });

    it('an HS256 token', async () => {
      const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer(ISSUER)
        .setAudience(CLIENT_ID)
        .setSubject('x')
        .setExpirationTime('10m')
        .sign(new TextEncoder().encode(CLIENT_SECRET.padEnd(32, '!')));
      await expectProviderError(respondWith(Promise.resolve(token)));
    });

    it('a token without a subject', async () => {
      await expectProviderError(respondWith(signIdToken({ omitSub: true })));
    });

    it('a non-200 token response, without leaking the body', async () => {
      const fetchFn = jest
        .fn()
        .mockResolvedValue(
          jsonResponse({ error: 'invalid_grant', echoed: 'auth-code' }, 400),
        );
      const promise = makeProvider(fetchFn).authenticate(input);
      await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
      await expect(promise).rejects.toThrow(/returned 400 \(invalid_grant\)/);
      await expect(promise).rejects.not.toThrow(/auth-code|echoed/);
    });

    it('a response without id_token', async () => {
      await expectProviderError(
        jest.fn().mockResolvedValue(jsonResponse({ access_token: 'x' })),
      );
    });

    it('a network failure', async () => {
      await expectProviderError(
        jest.fn().mockRejectedValue(new Error('ECONNRESET')),
      );
    });
  });
});
