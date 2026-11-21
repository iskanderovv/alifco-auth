import { OAuthProvider } from '../../generated/prisma/enums';
import { createTestPrisma, resetDatabase } from '../../../test/helpers/db';
import { PrismaService } from '../../prisma/prisma.service';
import type { OAuthProfile } from '../providers/oauth-provider.interface';
import { IdentityService } from './identity.service';

describe('IdentityService (real PostgreSQL)', () => {
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

  const googleProfile: OAuthProfile = {
    providerUserId: 'google-sub-1',
    email: 'Ali@Gmail.com',
    emailVerified: true,
    name: 'Ali Valiyev',
    avatarUrl: 'https://example.com/ali.png',
  };

  it('creates a user and an identity on first login', async () => {
    const { user, isNewUser } = await service.loginWithProfile(
      OAuthProvider.google,
      googleProfile,
    );

    expect(isNewUser).toBe(true);
    expect(user.name).toBe('Ali Valiyev');
    expect(user.email).toBe('ali@gmail.com'); // verified and normalized
    expect(user.avatarUrl).toBe('https://example.com/ali.png');

    const identities = await prisma.oAuthIdentity.findMany();
    expect(identities).toHaveLength(1);
    expect(identities[0]).toMatchObject({
      userId: user.id,
      provider: 'google',
      providerUserId: 'google-sub-1',
      email: 'ali@gmail.com',
    });
  });

  it('logs the same person in again without creating anything new', async () => {
    const first = await service.loginWithProfile(
      OAuthProvider.google,
      googleProfile,
    );
    const second = await service.loginWithProfile(OAuthProvider.google, {
      ...googleProfile,
      name: 'Changed Name',
      avatarUrl: 'https://example.com/new.png',
    });

    expect(second.isNewUser).toBe(false);
    expect(second.user.id).toBe(first.user.id);
    expect(await prisma.user.count()).toBe(1);
    expect(await prisma.oAuthIdentity.count()).toBe(1);

    // The account profile is not rewritten by later logins.
    expect(second.user.name).toBe('Ali Valiyev');
    expect(second.user.avatarUrl).toBe('https://example.com/ali.png');
    const [identity] = await prisma.oAuthIdentity.findMany();
    expect(identity.lastLoginAt).not.toBeNull();
  });

  it('keeps an unverified email off the user and only on the identity', async () => {
    const { user } = await service.loginWithProfile(OAuthProvider.facebook, {
      providerUserId: 'fb-1',
      email: 'victim@gmail.com',
      emailVerified: false,
      name: 'Attacker',
    });

    expect(user.email).toBeNull();
    const [identity] = await prisma.oAuthIdentity.findMany();
    expect(identity.email).toBe('victim@gmail.com');
  });

  it('does not merge accounts by email: pre-account takeover is not possible', async () => {
    // The attacker registers with the victim's address through Facebook, which proves nothing.
    const attacker = await service.loginWithProfile(OAuthProvider.facebook, {
      providerUserId: 'fb-attacker',
      email: 'victim@gmail.com',
      emailVerified: false,
      name: 'Attacker',
    });

    // The real owner later signs in with Google, which does verify the email.
    const victim = await service.loginWithProfile(OAuthProvider.google, {
      providerUserId: 'google-victim',
      email: 'victim@gmail.com',
      emailVerified: true,
      name: 'Victim',
    });

    expect(victim.user.id).not.toBe(attacker.user.id);
    expect(await prisma.user.count()).toBe(2);
    // Each user has exactly one identity: nothing was attached to the attacker's account.
    const identities = await prisma.oAuthIdentity.findMany();
    expect(
      identities.filter((i) => i.userId === attacker.user.id),
    ).toHaveLength(1);
    expect(identities.filter((i) => i.userId === victim.user.id)).toHaveLength(
      1,
    );
  });

  it('does not crash when two providers report the same verified email', async () => {
    const a = await service.loginWithProfile(
      OAuthProvider.google,
      googleProfile,
    );
    const b = await service.loginWithProfile(OAuthProvider.google, {
      ...googleProfile,
      providerUserId: 'google-sub-2',
    });

    expect(a.user.id).not.toBe(b.user.id);
    expect(await prisma.user.count()).toBe(2);
  });

  it('supports Telegram users with no email and a username only', async () => {
    const { user } = await service.loginWithProfile(OAuthProvider.telegram, {
      providerUserId: 'tg-1',
      emailVerified: false,
      username: 'ali_tg',
    });

    expect(user.name).toBe('ali_tg');
    expect(user.email).toBeNull();
  });

  it('falls back to a default name and drops a non-https avatar', async () => {
    const { user } = await service.loginWithProfile(OAuthProvider.facebook, {
      providerUserId: 'fb-2',
      emailVerified: false,
      avatarUrl: 'http://insecure.example.com/a.png',
    });

    expect(user.name).toBe('User');
    expect(user.avatarUrl).toBeNull();
  });

  it('creates exactly one user when the same first login arrives concurrently', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        service.loginWithProfile(OAuthProvider.google, googleProfile),
      ),
    );

    const userIds = new Set(results.map((r) => r.user.id));
    expect(userIds.size).toBe(1);
    expect(results.filter((r) => r.isNewUser)).toHaveLength(1);
    expect(await prisma.user.count()).toBe(1);
    expect(await prisma.oAuthIdentity.count()).toBe(1);
  });

  it('keeps the same provider id separate across providers', async () => {
    await service.loginWithProfile(OAuthProvider.google, {
      providerUserId: '12345',
      emailVerified: false,
      name: 'G',
    });
    await service.loginWithProfile(OAuthProvider.facebook, {
      providerUserId: '12345',
      emailVerified: false,
      name: 'F',
    });

    expect(await prisma.user.count()).toBe(2);
  });
});
