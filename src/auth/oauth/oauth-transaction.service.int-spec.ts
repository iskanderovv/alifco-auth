import { pkceChallenge, sha256Hex } from '../../common/crypto';
import { OAuthMode, OAuthProvider } from '../../generated/prisma/enums';
import { createTestPrisma, resetDatabase } from '../../../test/helpers/db';
import { PrismaService } from '../../prisma/prisma.service';
import { OAuthTransactionService } from './oauth-transaction.service';

describe('OAuthTransactionService (real PostgreSQL)', () => {
  let prisma: PrismaService;
  let service: OAuthTransactionService;

  beforeAll(async () => {
    prisma = await createTestPrisma();
    service = new OAuthTransactionService(prisma);
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  beforeEach(async () => {
    await resetDatabase(prisma);
  });

  const google = OAuthProvider.google;

  it('stores only the hash of state and a matching PKCE verifier', async () => {
    const started = await service.start({ provider: google });
    const row = await prisma.oAuthTransaction.findUniqueOrThrow({
      where: { id: started.transactionId },
    });

    expect(row.stateHash).toBe(sha256Hex(started.state));
    expect(JSON.stringify(row)).not.toContain(started.state);
    expect(pkceChallenge(row.codeVerifier)).toBe(started.codeChallenge);
    expect(row.mode).toBe(OAuthMode.login);
    expect(row.consumedAt).toBeNull();
  });

  it('consumes a valid transaction and returns the verifier', async () => {
    const started = await service.start({ provider: google });
    const consumed = await service.consume({
      transactionId: started.transactionId,
      state: started.state,
      provider: google,
    });

    expect(pkceChallenge(consumed.codeVerifier)).toBe(started.codeChallenge);
    expect(consumed.mode).toBe(OAuthMode.login);
    expect(consumed.userId).toBeNull();
  });

  it('is single use: a replayed callback fails', async () => {
    const started = await service.start({ provider: google });
    const input = {
      transactionId: started.transactionId,
      state: started.state,
      provider: google,
    };
    await service.consume(input);

    await expect(service.consume(input)).rejects.toMatchObject({
      code: 'invalid_state',
    });
  });

  it('rejects a wrong state and leaves the transaction usable', async () => {
    const started = await service.start({ provider: google });

    await expect(
      service.consume({
        transactionId: started.transactionId,
        state: 'forged-state',
        provider: google,
      }),
    ).rejects.toMatchObject({ code: 'invalid_state' });

    // An attacker guessing wrong must not burn the victim's transaction.
    await expect(
      service.consume({
        transactionId: started.transactionId,
        state: started.state,
        provider: google,
      }),
    ).resolves.toBeDefined();
  });

  it('rejects a callback for a different provider', async () => {
    const started = await service.start({ provider: google });
    await expect(
      service.consume({
        transactionId: started.transactionId,
        state: started.state,
        provider: OAuthProvider.facebook,
      }),
    ).rejects.toMatchObject({ code: 'invalid_state' });
  });

  it('rejects an expired transaction', async () => {
    const started = await service.start({ provider: google });
    await prisma.oAuthTransaction.updateMany({
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    await expect(
      service.consume({
        transactionId: started.transactionId,
        state: started.state,
        provider: google,
      }),
    ).rejects.toMatchObject({ code: 'invalid_state' });
  });

  it('rejects missing or malformed input without a database error', async () => {
    const started = await service.start({ provider: google });
    for (const transactionId of [undefined, '', 'not-a-uuid', "' OR 1=1 --"]) {
      await expect(
        service.consume({
          transactionId,
          state: started.state,
          provider: google,
        }),
      ).rejects.toMatchObject({ code: 'invalid_state' });
    }
    await expect(
      service.consume({
        transactionId: started.transactionId,
        state: undefined,
        provider: google,
      }),
    ).rejects.toMatchObject({ code: 'invalid_state' });
  });

  it('lets exactly one of two concurrent callbacks succeed', async () => {
    const started = await service.start({ provider: google });
    const input = {
      transactionId: started.transactionId,
      state: started.state,
      provider: google,
    };

    const results = await Promise.allSettled([
      service.consume(input),
      service.consume(input),
    ]);

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1);
  });

  it('keeps the user id for a link transaction', async () => {
    const user = await prisma.user.create({ data: { name: 'Linker' } });
    const started = await service.start({
      provider: google,
      mode: OAuthMode.link,
      userId: user.id,
    });
    const consumed = await service.consume({
      transactionId: started.transactionId,
      state: started.state,
      provider: google,
    });

    expect(consumed.mode).toBe(OAuthMode.link);
    expect(consumed.userId).toBe(user.id);
  });
});
