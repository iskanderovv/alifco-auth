import { sha256Hex } from '../../common/crypto';
import {
  createTestPrisma,
  fakeConfig,
  resetDatabase,
  TEST_TOKEN_CONFIG,
} from '../../../test/helpers/db';
import { PrismaService } from '../../prisma/prisma.service';
import { TokenService } from './token.service';

describe('TokenService refresh tokens (real PostgreSQL)', () => {
  let prisma: PrismaService;
  let service: TokenService;
  let userId: string;

  beforeAll(async () => {
    prisma = await createTestPrisma();
    service = new TokenService(prisma, fakeConfig(TEST_TOKEN_CONFIG));
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await resetDatabase(prisma);
    userId = (await prisma.user.create({ data: { name: 'Test User' } })).id;
  });

  const rows = () =>
    prisma.refreshToken.findMany({ orderBy: { createdAt: 'asc' } });

  it('stores only the hash, never the raw token', async () => {
    const issued = await service.issueRefreshToken(userId);
    const [row] = await rows();

    expect(row.tokenHash).toBe(sha256Hex(issued.token));
    expect(JSON.stringify(row)).not.toContain(issued.token);
    expect(row.revokedAt).toBeNull();
  });

  it('survives a malformed IP and an oversized user agent', async () => {
    await expect(
      service.issueRefreshToken(userId, {
        ip: 'not-an-ip',
        userAgent: 'x'.repeat(5000),
      }),
    ).resolves.toBeDefined();
    const [row] = await rows();
    expect(row.ip).toBeNull();
    expect(row.userAgent).toHaveLength(512);
  });

  it('rotates: revokes the old token and issues a new one in the same family', async () => {
    const first = await service.issueRefreshToken(userId);
    const rotated = await service.rotateRefreshToken(first.token);

    expect(rotated.userId).toBe(userId);
    expect(rotated.refreshToken.token).not.toBe(first.token);
    expect(rotated.refreshToken.familyId).toBe(first.familyId);

    const [oldRow, newRow] = await rows();
    expect(oldRow.revokedAt).not.toBeNull();
    expect(newRow.revokedAt).toBeNull();
  });

  it('rejects an unknown token with refresh_invalid', async () => {
    await expect(
      service.rotateRefreshToken('totally-made-up-token'),
    ).rejects.toMatchObject({ code: 'refresh_invalid' });
  });

  it('rejects an expired token with refresh_expired and does not revoke the family', async () => {
    const issued = await service.issueRefreshToken(userId);
    await prisma.refreshToken.updateMany({
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    await expect(
      service.rotateRefreshToken(issued.token),
    ).rejects.toMatchObject({ code: 'refresh_expired' });
    expect((await rows())[0].revokedAt).toBeNull();
  });

  it('reuse of a rotated token revokes the whole family, including the newest token', async () => {
    const first = await service.issueRefreshToken(userId);
    const second = await service.rotateRefreshToken(first.token);

    // Someone presents the old token again: the thief or a replay.
    await expect(service.rotateRefreshToken(first.token)).rejects.toMatchObject(
      { code: 'refresh_reused' },
    );

    // The legitimate newest token is dead too, so the session must be started again.
    await expect(
      service.rotateRefreshToken(second.refreshToken.token),
    ).rejects.toMatchObject({ code: 'refresh_reused' });
    expect((await rows()).every((row) => row.revokedAt !== null)).toBe(true);
  });

  it('reuse in one family does not touch another session of the same user', async () => {
    const phone = await service.issueRefreshToken(userId);
    const laptop = await service.issueRefreshToken(userId);
    await service.rotateRefreshToken(phone.token);

    await expect(service.rotateRefreshToken(phone.token)).rejects.toMatchObject(
      { code: 'refresh_reused' },
    );

    await expect(
      service.rotateRefreshToken(laptop.token),
    ).resolves.toBeDefined();
  });

  it('lets exactly one of two concurrent rotations of the same token win', async () => {
    const issued = await service.issueRefreshToken(userId);

    const results = await Promise.allSettled([
      service.rotateRefreshToken(issued.token),
      service.rotateRefreshToken(issued.token),
    ]);

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter(
      (r): r is PromiseRejectedResult => r.status === 'rejected',
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0].reason).toMatchObject({ code: 'refresh_reused' });
    // No fork: nothing stays active once reuse is detected.
    expect((await rows()).every((row) => row.revokedAt !== null)).toBe(true);
  });

  it('logout revokes the whole family and is idempotent', async () => {
    const first = await service.issueRefreshToken(userId);
    const second = await service.rotateRefreshToken(first.token);

    await service.revokeSession(second.refreshToken.token);
    expect((await rows()).every((row) => row.revokedAt !== null)).toBe(true);

    await expect(
      service.revokeSession(second.refreshToken.token),
    ).resolves.toBeUndefined();
    await expect(service.revokeSession('unknown')).resolves.toBeUndefined();
    await expect(service.revokeSession(undefined)).resolves.toBeUndefined();
  });

  it('cascades: deleting the user removes their refresh tokens', async () => {
    await service.issueRefreshToken(userId);
    await prisma.user.delete({ where: { id: userId } });
    expect(await rows()).toHaveLength(0);
  });
});
