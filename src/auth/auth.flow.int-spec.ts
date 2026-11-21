import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../app.module';
import { configureApp } from '../app.setup';
import { AppError } from '../common/app-error';
import { pkceChallenge } from '../common/crypto';
import { OAuthProvider as ProviderName } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { resetDatabase } from '../../test/helpers/db';
import type {
  OAuthProfile,
  OAuthProvider,
} from './providers/oauth-provider.interface';
import { ProviderRegistry } from './providers/provider.registry';

const FRONTEND = 'http://localhost:5173';
const CALLBACK = `${FRONTEND}/auth/callback`;

/** Stands in for Google: no network, the profile and failures are set by each test. */
class FakeProvider implements OAuthProvider {
  readonly name = ProviderName.google;
  profile: OAuthProfile = {
    providerUserId: 'google-sub-1',
    email: 'Ali@Gmail.com',
    emailVerified: true,
    name: 'Ali Valiyev',
    avatarUrl: 'https://example.com/ali.png',
  };
  lastInput?: { code: string; codeVerifier: string };

  getAuthorizationUrl(state: string, codeChallenge: string): string {
    return `https://provider.test/authorize?state=${state}&code_challenge=${codeChallenge}`;
  }

  authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile> {
    this.lastInput = input;
    if (input.code === 'bad-code') {
      return Promise.reject(
        new AppError('provider_error', 502, 'SECRET-PROVIDER-DETAIL'),
      );
    }
    return Promise.resolve(this.profile);
  }
}

function setCookies(res: request.Response): string[] {
  return (res.headers['set-cookie'] as unknown as string[] | undefined) ?? [];
}

function cookieValue(res: request.Response, name: string): string | undefined {
  const line = setCookies(res).find((c) => c.startsWith(`${name}=`));
  return line?.split(';')[0].slice(name.length + 1);
}

function cookieLine(res: request.Response, name: string): string {
  return setCookies(res).find((c) => c.startsWith(`${name}=`)) ?? '';
}

describe('Auth HTTP flow (fake provider, real PostgreSQL)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let provider: FakeProvider;

  beforeAll(async () => {
    provider = new FakeProvider();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(ProviderRegistry)
      .useValue({
        get: (name: string) => {
          if (name !== 'google') throw new AppError('provider_not_found', 404);
          return provider;
        },
      })
      .compile();

    const nest = moduleRef.createNestApplication<NestExpressApplication>({
      bodyParser: false,
    });
    configureApp(nest);
    await nest.init();
    app = nest;
    prisma = nest.get(PrismaService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await resetDatabase(prisma);
    provider.profile = {
      providerUserId: 'google-sub-1',
      email: 'Ali@Gmail.com',
      emailVerified: true,
      name: 'Ali Valiyev',
      avatarUrl: 'https://example.com/ali.png',
    };
    provider.lastInput = undefined;
  });

  const http = () => request(app.getHttpServer());

  /** Runs GET /auth/google and returns what the browser would hold. */
  async function startLogin() {
    const res = await http().get('/auth/google');
    const location = new URL(res.headers.location);
    return {
      res,
      state: location.searchParams.get('state') as string,
      challenge: location.searchParams.get('code_challenge') as string,
      txCookie: `oauth_tx=${cookieValue(res, 'oauth_tx')}`,
    };
  }

  /** A complete successful login. Returns the refresh cookie value. */
  async function login(): Promise<string> {
    const { state, txCookie } = await startLogin();
    const res = await http()
      .get('/auth/google/callback')
      .query({ code: 'good-code', state })
      .set('Cookie', txCookie);
    expect(res.status).toBe(302);
    return cookieValue(res, 'refresh_token') as string;
  }

  const refresh = (cookie: string) =>
    http()
      .post('/auth/refresh')
      .set('X-Requested-With', 'fetch')
      .set('Cookie', `refresh_token=${cookie}`);

  describe('starting a login', () => {
    it('redirects to the provider with state and a PKCE challenge, and sets the transaction cookie', async () => {
      const { res, state, challenge } = await startLogin();

      expect(res.status).toBe(302);
      expect(res.headers.location).toContain('https://provider.test/authorize');
      expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);

      const line = cookieLine(res, 'oauth_tx');
      expect(line).toContain('HttpOnly');
      expect(line).toContain('Path=/auth');
      expect(line).toContain('SameSite=Lax');
      expect(line).not.toContain('Domain=');
    });

    it('answers 404 in the standard error format for an unknown provider', async () => {
      const res = await http().get('/auth/myspace');
      expect(res.status).toBe(404);
      expect(res.body).toEqual({
        error: { code: 'provider_not_found', message: 'provider_not_found' },
      });
    });
  });

  describe('callback', () => {
    it('logs in: redirects to the SPA with no token in the URL, sets the refresh cookie, creates the user', async () => {
      const { state, challenge, txCookie } = await startLogin();

      const res = await http()
        .get('/auth/google/callback')
        .query({ code: 'good-code', state })
        .set('Cookie', txCookie);

      expect(res.status).toBe(302);
      expect(res.headers.location).toBe(CALLBACK); // no query string at all

      const refreshLine = cookieLine(res, 'refresh_token');
      expect(refreshLine).toContain('HttpOnly');
      expect(refreshLine).toContain('Path=/auth');
      expect(refreshLine).toContain('SameSite=Lax');
      expect(refreshLine).not.toContain('Domain=');
      // the transaction cookie is cleared
      expect(cookieLine(res, 'oauth_tx')).toMatch(/oauth_tx=;/);

      // The adapter got the verifier that matches the challenge sent to the provider.
      expect(provider.lastInput?.code).toBe('good-code');
      expect(pkceChallenge(provider.lastInput?.codeVerifier as string)).toBe(
        challenge,
      );

      const users = await prisma.user.findMany();
      expect(users).toHaveLength(1);
      expect(users[0].email).toBe('ali@gmail.com');
      expect(await prisma.oAuthIdentity.count()).toBe(1);
    });

    it('rejects a wrong state, creating nothing and setting no session', async () => {
      const { txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({ code: 'good-code', state: 'forged' })
        .set('Cookie', txCookie);

      expect(res.headers.location).toBe(`${CALLBACK}?error=invalid_state`);
      expect(cookieValue(res, 'refresh_token')).toBeUndefined();
      expect(await prisma.user.count()).toBe(0);
    });

    it('rejects a callback without the transaction cookie (a login started in another browser)', async () => {
      const { state } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({ code: 'good-code', state });

      expect(res.headers.location).toBe(`${CALLBACK}?error=invalid_state`);
      expect(await prisma.user.count()).toBe(0);
    });

    it('rejects a replayed callback', async () => {
      const { state, txCookie } = await startLogin();
      const send = () =>
        http()
          .get('/auth/google/callback')
          .query({ code: 'good-code', state })
          .set('Cookie', txCookie);

      expect((await send()).headers.location).toBe(CALLBACK);
      expect((await send()).headers.location).toBe(
        `${CALLBACK}?error=invalid_state`,
      );
      expect(await prisma.user.count()).toBe(1);
    });

    it('passes access_denied through and ignores the provider description', async () => {
      const { state, txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({
          error: 'access_denied',
          error_description: 'SECRET-DESCRIPTION',
          state,
        })
        .set('Cookie', txCookie);

      expect(res.headers.location).toBe(`${CALLBACK}?error=access_denied`);
      expect(res.headers.location).not.toContain('SECRET');
    });

    it('maps an unknown provider error to provider_error', async () => {
      const { txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({ error: 'server_error' })
        .set('Cookie', txCookie);

      expect(res.headers.location).toBe(`${CALLBACK}?error=provider_error`);
    });

    it('turns a provider failure into provider_error without leaking its message', async () => {
      const { state, txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({ code: 'bad-code', state })
        .set('Cookie', txCookie);

      expect(res.headers.location).toBe(`${CALLBACK}?error=provider_error`);
      expect(res.headers.location).not.toContain('SECRET');
      expect(await prisma.user.count()).toBe(0);
    });

    it('fails when the code is missing', async () => {
      const { state, txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback')
        .query({ state })
        .set('Cookie', txCookie);
      expect(res.headers.location).toBe(`${CALLBACK}?error=provider_error`);
    });

    it('treats repeated query parameters as invalid instead of crashing', async () => {
      const { txCookie } = await startLogin();
      const res = await http()
        .get('/auth/google/callback?state=a&state=b&code=x')
        .set('Cookie', txCookie);
      expect(res.status).toBe(302);
      expect(res.headers.location).toBe(`${CALLBACK}?error=invalid_state`);
    });
  });

  describe('refresh, /me and logout', () => {
    it('refreshes: new access token, rotated cookie, and /me works with it', async () => {
      const first = await login();
      const res = await refresh(first);

      expect(res.status).toBe(200);
      expect(res.body.expiresIn).toBe(900);
      expect(typeof res.body.accessToken).toBe('string');
      const rotated = cookieValue(res, 'refresh_token');
      expect(rotated).toBeDefined();
      expect(rotated).not.toBe(first);

      const me = await http()
        .get('/me')
        .set('Authorization', `Bearer ${res.body.accessToken}`);
      expect(me.status).toBe(200);
      expect(me.body).toMatchObject({
        name: 'Ali Valiyev',
        email: 'ali@gmail.com',
        providers: ['google'],
      });
      expect(Object.keys(me.body).sort()).toEqual(
        ['avatarUrl', 'createdAt', 'email', 'id', 'name', 'providers'].sort(),
      );
    });

    it('requires the CSRF header and a matching Origin', async () => {
      const cookie = await login();

      const noHeader = await http()
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie}`);
      expect(noHeader.status).toBe(403);
      expect(noHeader.body.error.code).toBe('csrf_header_missing');

      const wrongOrigin = await refresh(cookie).set(
        'Origin',
        'https://evil.example.com',
      );
      expect(wrongOrigin.status).toBe(403);
      expect(wrongOrigin.body.error.code).toBe('csrf_origin_invalid');

      // Neither attempt consumed the token.
      expect((await refresh(cookie).set('Origin', FRONTEND)).status).toBe(200);
    });

    it('answers 401 refresh_missing without a cookie', async () => {
      const res = await http()
        .post('/auth/refresh')
        .set('X-Requested-With', 'fetch');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('refresh_missing');
    });

    it('detects reuse of a rotated token: 401, cookie cleared, session dead', async () => {
      const first = await login();
      const second = cookieValue(
        await refresh(first),
        'refresh_token',
      ) as string;

      const reuse = await refresh(first);
      expect(reuse.status).toBe(401);
      expect(reuse.body.error.code).toBe('refresh_reused');
      expect(cookieLine(reuse, 'refresh_token')).toMatch(/refresh_token=;/);

      // The legitimate newest token was revoked with the family.
      expect((await refresh(second)).status).toBe(401);
    });

    it('rejects a garbage refresh cookie', async () => {
      const res = await refresh('garbage');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('refresh_invalid');
    });

    it('logs out: 204, cookie cleared, the token no longer works', async () => {
      const cookie = await login();
      const res = await http()
        .post('/auth/logout')
        .set('X-Requested-With', 'fetch')
        .set('Cookie', `refresh_token=${cookie}`);

      expect(res.status).toBe(204);
      expect(cookieLine(res, 'refresh_token')).toMatch(/refresh_token=;/);
      expect((await refresh(cookie)).status).toBe(401);
    });

    it('logout is idempotent and still needs the CSRF header', async () => {
      const ok = await http()
        .post('/auth/logout')
        .set('X-Requested-With', 'fetch');
      expect(ok.status).toBe(204);

      const blocked = await http().post('/auth/logout');
      expect(blocked.status).toBe(403);
    });

    it('/me rejects missing, malformed and forged tokens', async () => {
      const missing = await http().get('/me');
      expect(missing.status).toBe(401);
      expect(missing.body.error.code).toBe('token_missing');

      const bearerOnly = await http()
        .get('/me')
        .set('Authorization', 'Bearer ');
      expect(bearerOnly.body.error.code).toBe('token_missing');

      const garbage = await http()
        .get('/me')
        .set('Authorization', 'Bearer x.y.z');
      expect(garbage.status).toBe(401);
      expect(garbage.body.error.code).toBe('token_invalid');
    });

    it('/me answers 401 for a valid token of a deleted user', async () => {
      const cookie = await login();
      const { accessToken } = (await refresh(cookie)).body as {
        accessToken: string;
      };
      await prisma.user.deleteMany();

      const res = await http()
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('token_invalid');
    });
  });

  describe('HTTP hardening', () => {
    it('GET /health is open and does not need the database', async () => {
      const res = await http().get('/health');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'ok' });
    });

    it('uses the standard error format for unknown routes', async () => {
      const res = await http().get('/nope');
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('not_found');
    });

    it('rejects an oversized body with 413 payload_too_large', async () => {
      const res = await http()
        .post('/auth/refresh')
        .set('X-Requested-With', 'fetch')
        .send({ junk: 'x'.repeat(20_000) });
      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('payload_too_large');
    });

    it('rejects malformed JSON with 400 validation_failed', async () => {
      const res = await http()
        .post('/auth/refresh')
        .set('Content-Type', 'application/json')
        .send('{"broken":');
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('validation_failed');
    });

    it('allows CORS only for the SPA origin, with credentials', async () => {
      const allowed = await http()
        .options('/auth/refresh')
        .set('Origin', FRONTEND)
        .set('Access-Control-Request-Method', 'POST');
      expect(allowed.headers['access-control-allow-origin']).toBe(FRONTEND);
      expect(allowed.headers['access-control-allow-credentials']).toBe('true');

      const other = await http()
        .options('/auth/refresh')
        .set('Origin', 'https://evil.example.com')
        .set('Access-Control-Request-Method', 'POST');
      expect(other.headers['access-control-allow-origin']).not.toBe(
        'https://evil.example.com',
      );
    });
  });
});
