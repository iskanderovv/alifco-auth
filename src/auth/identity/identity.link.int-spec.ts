import { OAuthProvider } from '../../generated/prisma/enums';
import { createTestPrisma, resetDatabase } from '../../../test/helpers/db';
import { PrismaService } from '../../prisma/prisma.service';
import type { OAuthProfile } from '../providers/oauth-provider.interface';
import { IdentityService } from './identity.service';

describe('IdentityService linking (real PostgreSQL)', () => {
  let prisma: PrismaService;
  let service: IdentityService;

  beforeAll(async () => {
    prisma = await createTestPrisma();
    service = new IdentityService(prisma);
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await resetDatabase(prisma);
  });

  const profile = (id: string, extra: Partial<OAuthProfile> = {}) => ({
    providerUserId: id,
    emailVerified: false,
    name: 'Someone',
    ...extra,
  });

  async function userWith(provider: OAuthProvider, providerUserId: string) {
    const { user } = await service.loginWithProfile(
      provider,
      profile(providerUserId),
    );
    return user;
  }

  const providersOf = async (userId: string) =>
    (await prisma.oAuthIdentity.findMany({ where: { userId } }))
      .map((i) => i.provider)
      .sort();

  describe('linkProfile', () => {
    it('attaches a second provider to the user', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1', { email: 'Me@Example.com' }),
      );

      expect(await providersOf(user.id)).toEqual(['facebook', 'google']);
      expect(await prisma.user.count()).toBe(1);
      const fb = await prisma.oAuthIdentity.findFirstOrThrow({
        where: { provider: 'facebook' },
      });
      expect(fb.email).toBe('me@example.com');
    });

    it('does not change the user profile or email', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1', { name: 'Other Name', email: 'other@example.com' }),
      );
      const after = await prisma.user.findUniqueOrThrow({
        where: { id: user.id },
      });
      expect(after.name).toBe(user.name);
      expect(after.email).toBe(user.email);
    });

    it('refuses an account that already belongs to another user: identity_taken', async () => {
      const owner = await userWith(OAuthProvider.facebook, 'fb-shared');
      const other = await userWith(OAuthProvider.google, 'g-2');

      await expect(
        service.linkProfile(
          other.id,
          OAuthProvider.facebook,
          profile('fb-shared'),
        ),
      ).rejects.toMatchObject({ code: 'identity_taken', status: 409 });

      expect(await providersOf(owner.id)).toEqual(['facebook']);
      expect(await providersOf(other.id)).toEqual(['google']);
    });

    it('refuses linking the same account twice: already_linked', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1'),
      );

      await expect(
        service.linkProfile(user.id, OAuthProvider.facebook, profile('fb-1')),
      ).rejects.toMatchObject({ code: 'already_linked', status: 409 });
    });

    it('allows one account per provider: a second Facebook account is already_linked', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1'),
      );

      await expect(
        service.linkProfile(user.id, OAuthProvider.facebook, profile('fb-2')),
      ).rejects.toMatchObject({ code: 'already_linked' });
      expect(await providersOf(user.id)).toEqual(['facebook', 'google']);
    });

    it('does not link by email: a matching verified email is irrelevant', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      const stranger = await service.loginWithProfile(OAuthProvider.google, {
        ...profile('g-2'),
        email: 'same@example.com',
        emailVerified: true,
      });
      expect(stranger.user.id).not.toBe(user.id);
    });

    it('rejects a user that no longer exists', async () => {
      await expect(
        service.linkProfile(
          '00000000-0000-4000-8000-000000000000',
          OAuthProvider.facebook,
          profile('fb-1'),
        ),
      ).rejects.toMatchObject({ code: 'invalid_state' });
      expect(await prisma.oAuthIdentity.count()).toBe(0);
    });

    it('lets exactly one of two users win a race for the same provider account', async () => {
      const a = await userWith(OAuthProvider.google, 'g-a');
      const b = await userWith(OAuthProvider.google, 'g-b');

      const results = await Promise.allSettled([
        service.linkProfile(a.id, OAuthProvider.facebook, profile('fb-race')),
        service.linkProfile(b.id, OAuthProvider.facebook, profile('fb-race')),
      ]);

      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      const failure = results.find(
        (r): r is PromiseRejectedResult => r.status === 'rejected',
      );
      expect(failure?.reason).toMatchObject({ code: 'identity_taken' });
      expect(
        await prisma.oAuthIdentity.count({ where: { provider: 'facebook' } }),
      ).toBe(1);
    });
  });

  describe('unlink', () => {
    it('removes one provider and keeps the rest', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1'),
      );

      await service.unlink(user.id, OAuthProvider.facebook);
      expect(await providersOf(user.id)).toEqual(['google']);
    });

    it('refuses to remove the last provider: last_identity', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await expect(
        service.unlink(user.id, OAuthProvider.google),
      ).rejects.toMatchObject({ code: 'last_identity', status: 409 });
      expect(await providersOf(user.id)).toEqual(['google']);
    });

    it('answers not_linked for a provider the user does not have', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await expect(
        service.unlink(user.id, OAuthProvider.telegram),
      ).rejects.toMatchObject({ code: 'not_linked', status: 404 });
    });

    it('cannot remove another user’s provider', async () => {
      const victim = await userWith(OAuthProvider.google, 'g-victim');
      await service.linkProfile(
        victim.id,
        OAuthProvider.facebook,
        profile('fb-victim'),
      );
      const attacker = await userWith(OAuthProvider.google, 'g-attacker');

      await expect(
        service.unlink(attacker.id, OAuthProvider.facebook),
      ).rejects.toMatchObject({ code: 'not_linked' });
      expect(await providersOf(victim.id)).toEqual(['facebook', 'google']);
    });

    it('waits for an unlink already in progress, so the last provider survives (row lock)', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1'),
      );

      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      let lockTaken!: () => void;
      const locked = new Promise<void>((resolve) => (lockTaken = resolve));
      const inProgress = prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM users WHERE id = ${user.id}::uuid FOR UPDATE`;
        lockTaken();
        await held;
        await tx.oAuthIdentity.deleteMany({
          where: { userId: user.id, provider: 'google' },
        });
      });
      await locked;

      const second = service.unlink(user.id, OAuthProvider.facebook);
      const outcome = await Promise.race([
        second.then(
          () => 'finished',
          () => 'finished',
        ),
        new Promise((resolve) => setTimeout(() => resolve('waiting'), 300)),
      ]);
      expect(outcome).toBe('waiting');

      release();
      await inProgress;
      await expect(second).rejects.toMatchObject({ code: 'last_identity' });
      expect(await providersOf(user.id)).toEqual(['facebook']);
    });

    it('never leaves a user without a login method when both providers are unlinked at once', async () => {
      const user = await userWith(OAuthProvider.google, 'g-1');
      await service.linkProfile(
        user.id,
        OAuthProvider.facebook,
        profile('fb-1'),
      );

      const results = await Promise.allSettled([
        service.unlink(user.id, OAuthProvider.google),
        service.unlink(user.id, OAuthProvider.facebook),
      ]);

      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      const failure = results.find(
        (r): r is PromiseRejectedResult => r.status === 'rejected',
      );
      expect(failure?.reason).toMatchObject({ code: 'last_identity' });
      expect(
        await prisma.oAuthIdentity.count({ where: { userId: user.id } }),
      ).toBe(1);
    });
  });
});
