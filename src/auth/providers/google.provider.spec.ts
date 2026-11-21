import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
  type KeyLike,
  type JWTVerifyGetKey,
} from 'jose';
import { AppError } from '../../common/app-error';
import { GoogleProvider } from './google.provider';

const CLIENT_ID = 'test-client.apps.googleusercontent.com';
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback';
const ISSUER = 'https://accounts.google.com';

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
    kid: 'test-key',
    alg: 'RS256',
    use: 'sig',
  };
  getKey = createLocalJWKSet({ keys: [jwk] });
});

interface TokenOptions {
  claims?: Record<string, unknown>;
  iss?: string;
  aud?: string;
  expiresIn?: number;
  key?: KeyLike;
  kid?: string;
}

function signIdToken(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email: 'ali@gmail.com',
    email_verified: true,
    name: 'Ali Valiyev',
    picture: 'https://example.com/ali.png',
    ...options.claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: options.kid ?? 'test-key' })
    .setIssuer(options.iss ?? ISSUER)
    .setAudience(options.aud ?? CLIENT_ID)
    .setSubject('google-sub-1')
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 600))
    .sign(options.key ?? privateKey);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function makeProvider(fetchFn: typeof fetch): GoogleProvider {
  return new GoogleProvider({
    clientId: CLIENT_ID,
    clientSecret: 'GOCSPX-secret',
    redirectUri: REDIRECT_URI,
    timeoutMs: 1000,
    fetchFn,
    getKey,
  });
}

const input = { code: 'auth-code', codeVerifier: 'verifier-value' };

describe('GoogleProvider', () => {
  describe('getAuthorizationUrl', () => {
    it('builds an authorization code + PKCE S256 request', () => {
      const provider = makeProvider(jest.fn());
      const url = new URL(
        provider.getAuthorizationUrl('the-state', 'the-challenge'),
      );

      expect(`${url.origin}${url.pathname}`).toBe(
        'https://accounts.google.com/o/oauth2/v2/auth',
      );
      expect(Object.fromEntries(url.searchParams)).toEqual({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid email profile',
        state: 'the-state',
        code_challenge: 'the-challenge',
        code_challenge_method: 'S256',
        prompt: 'select_account',
      });
    });
  });

  describe('authenticate', () => {
    it('exchanges the code with PKCE and maps the verified id_token', async () => {
      const fetchFn = jest
        .fn()
        .mockResolvedValue(jsonResponse({ id_token: await signIdToken() }));
      const profile = await makeProvider(fetchFn).authenticate(input);

      expect(profile).toEqual({
        providerUserId: 'google-sub-1',
        email: 'ali@gmail.com',
        emailVerified: true,
        name: 'Ali Valiyev',
        avatarUrl: 'https://example.com/ali.png',
      });

      const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('https://oauth2.googleapis.com/token');
      expect(init.method).toBe('POST');
      expect(Object.fromEntries(init.body as URLSearchParams)).toEqual({
        grant_type: 'authorization_code',
        code: 'auth-code',
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: 'GOCSPX-secret',
        code_verifier: 'verifier-value',
      });
    });

    it.each([
      [true, true],
      ['true', true],
      [false, false],
      ['false', false],
      [undefined, false],
    ])('reads email_verified %p as %p', async (raw, expected) => {
      const idToken = await signIdToken({ claims: { email_verified: raw } });
      const provider = makeProvider(
        jest.fn().mockResolvedValue(jsonResponse({ id_token: idToken })),
      );
      expect((await provider.authenticate(input)).emailVerified).toBe(expected);
    });

    describe('rejects with provider_error', () => {
      async function expectProviderError(fetchFn: typeof fetch) {
        const promise = makeProvider(fetchFn).authenticate(input);
        await expect(promise).rejects.toBeInstanceOf(AppError);
        await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
      }

      const respondWith = (idToken: Promise<string>) =>
        jest
          .fn()
          .mockImplementation(async () =>
            jsonResponse({ id_token: await idToken }),
          ) as unknown as typeof fetch;

      it('a token for another audience', async () => {
        await expectProviderError(
          respondWith(signIdToken({ aud: 'someone-elses-client' })),
        );
      });

      it('a token from another issuer', async () => {
        await expectProviderError(
          respondWith(signIdToken({ iss: 'https://evil.example.com' })),
        );
      });

      it('an expired token', async () => {
        await expectProviderError(respondWith(signIdToken({ expiresIn: -10 })));
      });

      it('a token signed with a key that is not in the JWKS', async () => {
        await expectProviderError(
          respondWith(signIdToken({ key: otherPrivateKey })),
        );
      });

      it('a token whose kid is unknown', async () => {
        await expectProviderError(respondWith(signIdToken({ kid: 'nope' })));
      });

      it('an HS256 token', async () => {
        const hs = await new SignJWT({})
          .setProtectedHeader({ alg: 'HS256' })
          .setIssuer(ISSUER)
          .setAudience(CLIENT_ID)
          .setSubject('x')
          .setExpirationTime('10m')
          .sign(new TextEncoder().encode('a-shared-secret-a-shared-secret-12'));
        await expectProviderError(respondWith(Promise.resolve(hs)));
      });

      it('a token without a subject', async () => {
        const now = Math.floor(Date.now() / 1000);
        const noSub = await new SignJWT({ email: 'a@b.com' })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
          .setIssuer(ISSUER)
          .setAudience(CLIENT_ID)
          .setExpirationTime(now + 600)
          .sign(privateKey);
        await expectProviderError(respondWith(Promise.resolve(noSub)));
      });

      it('a non-200 token response, without leaking the body', async () => {
        const fetchFn = jest
          .fn()
          .mockResolvedValue(
            jsonResponse({ error: 'invalid_grant', echoed: 'auth-code' }, 400),
          );
        const promise = makeProvider(fetchFn).authenticate(input);
        await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
        await expect(promise).rejects.not.toThrow(/auth-code|invalid_grant/);
      });

      it('a response without id_token', async () => {
        await expectProviderError(
          jest.fn().mockResolvedValue(jsonResponse({ access_token: 'x' })),
        );
      });

      it('a non-JSON response', async () => {
        await expectProviderError(
          jest.fn().mockResolvedValue(new Response('<html>', { status: 200 })),
        );
      });

      it('a network failure', async () => {
        await expectProviderError(
          jest.fn().mockRejectedValue(new Error('ECONNRESET')),
        );
      });
    });
  });
});
