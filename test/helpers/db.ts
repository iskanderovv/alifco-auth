import { ConfigService } from '@nestjs/config';
import type { Env } from '../../src/config/env';
import { PrismaService } from '../../src/prisma/prisma.service';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ??
  'postgresql://oauth:oauth@localhost:5432/oauth_test';

export function fakeConfig(values: Partial<Env>): ConfigService<Env, true> {
  return {
    get: (key: keyof Env) => values[key],
  } as unknown as ConfigService<Env, true>;
}

export async function createTestPrisma(): Promise<PrismaService> {
  const prisma = new PrismaService(
    fakeConfig({ DATABASE_URL: TEST_DATABASE_URL }),
  );
  await prisma.$connect();
  return prisma;
}

export async function resetDatabase(prisma: PrismaService): Promise<void> {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "oauth_transactions", "refresh_tokens", "oauth_identities", "users" CASCADE',
  );
}

export const TEST_TOKEN_CONFIG: Partial<Env> = {
  JWT_SECRET: 'test-secret-test-secret-test-secret-123456',
  JWT_ISSUER: 'oauth-service',
  JWT_AUDIENCE: 'oauth-service-api',
  JWT_ACCESS_TTL: '15m',
  REFRESH_TTL_DAYS: 30,
};
