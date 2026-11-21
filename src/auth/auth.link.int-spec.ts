import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../app.module';
import { configureApp } from '../app.setup';
import { AppError } from '../common/app-error';
import { OAuthProvider as ProviderName } from '../generated/prisma/enums';
import { PrismaService } from '../prisma/prisma.service';
import { resetDatabase } from '../../test/helpers/db';
import type {
  OAuthProfile,
  OAuthProvider,
} from './providers/oauth-provider.interface';
import { ProviderRegistry } from './providers/provider.registry';
import { TokenService } from './tokens/token.service';

const FRONTEND = 'http://localhost:5173';
const SETTINGS = `${FRONTEND}/settings/accounts`;
const LOGIN_CALLBACK = `${FRONTEND}/auth/callback`;

class FakeProvider implements OAuthProvider {
  profile: OAuthProfile;

  constructor(
    readonly name: ProviderName,
    providerUserId: string,
  ) {
    this.profile = { providerUserId, emailVerified: false, name: 'Fake' };
  }

  getAuthorizationUrl(state: string, codeChallenge: string): string {
    return `https://${this.name}.test/authorize?state=${state}&code_challenge=${codeChallenge}`;
  }

  authenticate(): Promise<OAuthProfile> {
    return Promise.resolve(this.profile);
  }
}

const setCookies = (res: request.Response): string[] =>
  (res.headers['set-cookie'] as unknown as string[] | undefined) ?? [];

const cookieValue = (res: request.Response, name: string) =>
  setCookies(res)
    .find((line) => line.startsWith(`${name}=`))
    ?.split(';')[0]
    .slice(name.length + 1);

describe('Linking and unlinking (fake providers, real PostgreSQL)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let tokens: TokenService;
  let facebook: FakeProvider;
  let userId: string;
  let accessToken: string;

  beforeAll(async () => {
    const google = new FakeProvider(ProviderName.google, 'g-1');
    facebook = new FakeProvider(ProviderName.facebook, 'fb-1');
    const fakes: Record<string, FakeProvider> = { google, facebook };

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(ProviderRegistry)
      .useValue({
        get: (name: string) => {
          const provider = fakes[name];
          if (!provider) throw new AppError('provider_not_found', 404);
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
    tokens = nest.get(TokenService);
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    await resetDatabase(prisma);
    facebook.profile = {
      providerUserId: 'fb-1',
      emailVerified: false,
      name: 'Fake',
    };
    const user = await prisma.user.create({
      data: {
        name: 'Ali',
        identities: {
          create: { provider: 'google', providerUserId: 'g-1' },
        },
      },
    });
    userId = user.id;
    accessToken = (await tokens.issueAccessToken(userId)).accessToken;
  });

  const http = () => request(app.getHttpServer());
  const bearer = () => ({ Authorization: `Bearer ${accessToken}` });

  const startLink = (provider: string) =>
    http().post(`/auth/link/${provider}`).set(bearer());

  async function finishLink(started: request.Response, state?: string) {
    const url = new URL(started.body.url);
    return http()
      .get('/auth/facebook/callback')
      .query({ code: 'code', state: state ?? url.searchParams.get('state') })
      .set('Cookie', `oauth_tx=${cookieValue(started, 'oauth_tx')}`);
  }

  const linkedProviders = async () =>
    (await prisma.oAuthIdentity.findMany({ where: { userId } }))
      .map((identity) => identity.provider)
      .sort();

  describe('starting a link', () => {
    it('requires a logged-in user', async () => {
      const res = await http().post('/auth/link/facebook');
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('token_missing');
    });

    it('returns the provider URL and sets the transaction cookie', async () => {
      const res = await startLink('facebook');

      expect(res.status).toBe(200);
      expect(res.body.url).toContain('https://facebook.test/authorize');
      expect(cookieValue(res, 'oauth_tx')).toBeDefined();
      expect(cookieValue(res, 'refresh_token')).toBeUndefined();
    });

    it('answers 404 for an unknown provider', async () => {
      const res = await startLink('myspace');
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('provider_not_found');
    });
  });

  describe('finishing a link', () => {
    it('attaches the provider and redirects to the settings page without touching the session', async () => {
      const res = await finishLink(await startLink('facebook'));

      expect(res.status).toBe(302);
      expect(res.headers.location).toBe(`${SETTINGS}?linked=facebook`);
      expect(cookieValue(res, 'refresh_token')).toBeUndefined();
      expect(await linkedProviders()).toEqual(['facebook', 'google']);
      expect(await prisma.user.count()).toBe(1);

      const me = await http().get('/me').set(bearer());
      expect(me.body.providers).toEqual(['google', 'facebook']);
    });

    it('reports identity_taken when the account belongs to another user', async () => {
      await prisma.user.create({
        data: {
          name: 'Owner',
          identities: {
            create: { provider: 'facebook', providerUserId: 'fb-1' },
          },
        },
      });

      const res = await finishLink(await startLink('facebook'));

      expect(res.headers.location).toBe(`${SETTINGS}?error=identity_taken`);
      expect(await linkedProviders()).toEqual(['google']);
    });

    it('reports already_linked when the user links the same provider again', async () => {
      await finishLink(await startLink('facebook'));
      const again = await finishLink(await startLink('facebook'));

      expect(again.headers.location).toBe(`${SETTINGS}?error=already_linked`);
      expect(await linkedProviders()).toEqual(['facebook', 'google']);
    });

    it('rejects the callback when the user was deleted in the meantime', async () => {
      const started = await startLink('facebook');
      await prisma.user.delete({ where: { id: userId } });

      const res = await finishLink(started);
      expect(res.headers.location).toBe(
        `${LOGIN_CALLBACK}?error=invalid_state`,
      );
      expect(await prisma.oAuthIdentity.count()).toBe(0);
    });

    it('rejects a wrong state on the login callback page', async () => {
      const res = await finishLink(await startLink('facebook'), 'forged');
      expect(res.headers.location).toBe(
        `${LOGIN_CALLBACK}?error=invalid_state`,
      );
      expect(await linkedProviders()).toEqual(['google']);
    });

    it('rejects a replayed link callback', async () => {
      const started = await startLink('facebook');
      await finishLink(started);
      const replay = await finishLink(started);

      expect(replay.headers.location).toBe(
        `${LOGIN_CALLBACK}?error=invalid_state`,
      );
      expect(await linkedProviders()).toEqual(['facebook', 'google']);
    });
  });

  describe('unlinking', () => {
    const link = async () => {
      await finishLink(await startLink('facebook'));
    };

    it('removes one provider', async () => {
      await link();
      const res = await http().delete('/auth/link/facebook').set(bearer());

      expect(res.status).toBe(204);
      expect(await linkedProviders()).toEqual(['google']);
      const me = await http().get('/me').set(bearer());
      expect(me.body.providers).toEqual(['google']);
    });

    it('refuses to remove the last provider', async () => {
      const res = await http().delete('/auth/link/google').set(bearer());

      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('last_identity');
      expect(await linkedProviders()).toEqual(['google']);
    });

    it('answers 404 not_linked for a provider the user does not have', async () => {
      const res = await http().delete('/auth/link/facebook').set(bearer());
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('not_linked');
    });

    it('answers 404 for an unknown provider name', async () => {
      const res = await http().delete('/auth/link/myspace').set(bearer());
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('provider_not_found');
    });

    it('requires a logged-in user', async () => {
      const res = await http().delete('/auth/link/facebook');
      expect(res.status).toBe(401);
    });

    it('works for a provider that is switched off on this server', async () => {
      await prisma.oAuthIdentity.create({
        data: { userId, provider: 'telegram', providerUserId: 'tg-1' },
      });
      const res = await http().delete('/auth/link/telegram').set(bearer());

      expect(res.status).toBe(204);
      expect(await linkedProviders()).toEqual(['google']);
    });
  });
});
