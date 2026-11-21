import { createHmac } from 'node:crypto';
import { AppError } from '../../common/app-error';
import { FacebookProvider } from './facebook.provider';

const APP_ID = '1234567890';
const APP_SECRET = 'fb-app-secret-value';
const REDIRECT_URI = 'http://localhost:3000/auth/facebook/callback';
const ACCESS_TOKEN = 'EAAB-access-token';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const me = {
  id: '10158',
  name: 'Ali Valiyev',
  email: 'Ali@Example.com',
  picture: { data: { url: 'https://scontent.example.com/ali.jpg' } },
};

function graph(tokenResponse: Response, profileResponse?: Response) {
  const fetchFn = jest.fn();
  fetchFn.mockResolvedValueOnce(tokenResponse);
  if (profileResponse) fetchFn.mockResolvedValueOnce(profileResponse);
  return fetchFn;
}

function makeProvider(fetchFn: typeof fetch): FacebookProvider {
  return new FacebookProvider({
    appId: APP_ID,
    appSecret: APP_SECRET,
    graphVersion: 'v25.0',
    redirectUri: REDIRECT_URI,
    timeoutMs: 1000,
    fetchFn,
  });
}

const input = { code: 'auth-code', codeVerifier: 'verifier-value' };

describe('FacebookProvider', () => {
  it('builds an authorization code + PKCE S256 request on the pinned Graph version', () => {
    const url = new URL(
      makeProvider(jest.fn()).getAuthorizationUrl('the-state', 'the-challenge'),
    );

    expect(`${url.origin}${url.pathname}`).toBe(
      'https://www.facebook.com/v25.0/dialog/oauth',
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: APP_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      scope: 'public_profile,email',
      state: 'the-state',
      code_challenge: 'the-challenge',
      code_challenge_method: 'S256',
    });
  });

  it('exchanges the code over POST with the secret in the body, then reads the profile', async () => {
    const fetchFn = graph(
      jsonResponse({ access_token: ACCESS_TOKEN, token_type: 'bearer' }),
      jsonResponse(me),
    );
    const profile = await makeProvider(fetchFn).authenticate(input);

    expect(profile).toEqual({
      providerUserId: '10158',
      email: 'Ali@Example.com', // normalized later, in one place
      emailVerified: false,
      name: 'Ali Valiyev',
      avatarUrl: 'https://scontent.example.com/ali.jpg',
    });

    const [tokenUrl, tokenInit] = fetchFn.mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(tokenUrl).toBe(
      'https://graph.facebook.com/v25.0/oauth/access_token',
    );
    expect(tokenInit.method).toBe('POST');
    expect(tokenUrl).not.toContain(APP_SECRET);
    expect(Object.fromEntries(tokenInit.body as URLSearchParams)).toEqual({
      client_id: APP_ID,
      client_secret: APP_SECRET,
      redirect_uri: REDIRECT_URI,
      code: 'auth-code',
      code_verifier: 'verifier-value',
    });
  });

  it('sends appsecret_proof, the HMAC-SHA256 of the access token with the app secret', async () => {
    const fetchFn = graph(
      jsonResponse({ access_token: ACCESS_TOKEN }),
      jsonResponse(me),
    );
    await makeProvider(fetchFn).authenticate(input);

    const [profileUrl] = fetchFn.mock.calls[1] as [string];
    const url = new URL(profileUrl);
    expect(`${url.origin}${url.pathname}`).toBe(
      'https://graph.facebook.com/v25.0/me',
    );
    expect(url.searchParams.get('access_token')).toBe(ACCESS_TOKEN);
    expect(url.searchParams.get('fields')).toBe(
      'id,name,email,picture.type(large)',
    );
    expect(url.searchParams.get('appsecret_proof')).toBe(
      createHmac('sha256', APP_SECRET).update(ACCESS_TOKEN).digest('hex'),
    );
    expect(profileUrl).not.toContain(APP_SECRET);
  });

  it('never marks the email verified, even when Facebook returns one', async () => {
    const provider = makeProvider(
      graph(jsonResponse({ access_token: ACCESS_TOKEN }), jsonResponse(me)),
    );
    expect((await provider.authenticate(input)).emailVerified).toBe(false);
  });

  it('works when the user shares no email and no picture', async () => {
    const provider = makeProvider(
      graph(
        jsonResponse({ access_token: ACCESS_TOKEN }),
        jsonResponse({ id: '77', name: 'No Email' }),
      ),
    );
    expect(await provider.authenticate(input)).toEqual({
      providerUserId: '77',
      email: undefined,
      emailVerified: false,
      name: 'No Email',
      avatarUrl: undefined,
    });
  });

  describe('rejects with provider_error', () => {
    async function expectProviderError(fetchFn: typeof fetch) {
      const promise = makeProvider(fetchFn).authenticate(input);
      await expect(promise).rejects.toBeInstanceOf(AppError);
      await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
    }

    it('a failed token exchange, without leaking the response body', async () => {
      const fetchFn = graph(
        jsonResponse({ error: { message: 'Invalid code auth-code' } }, 400),
      );
      const promise = makeProvider(fetchFn).authenticate(input);
      await expect(promise).rejects.toMatchObject({ code: 'provider_error' });
      await expect(promise).rejects.not.toThrow(/Invalid code|auth-code/);
    });

    it('a token response without access_token', async () => {
      await expectProviderError(graph(jsonResponse({ token_type: 'bearer' })));
    });

    it('a non-JSON token response', async () => {
      await expectProviderError(graph(new Response('<html>', { status: 200 })));
    });

    it('a failed profile request', async () => {
      await expectProviderError(
        graph(
          jsonResponse({ access_token: ACCESS_TOKEN }),
          jsonResponse({}, 401),
        ),
      );
    });

    it('a profile without an id', async () => {
      await expectProviderError(
        graph(
          jsonResponse({ access_token: ACCESS_TOKEN }),
          jsonResponse({ name: 'X' }),
        ),
      );
    });

    it('a numeric id (the id must be a string)', async () => {
      await expectProviderError(
        graph(
          jsonResponse({ access_token: ACCESS_TOKEN }),
          jsonResponse({ id: 5 }),
        ),
      );
    });

    it('a network failure', async () => {
      await expectProviderError(
        jest.fn().mockRejectedValue(new Error('ECONNRESET')),
      );
    });
  });
});
