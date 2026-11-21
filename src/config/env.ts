import { z } from 'zod';

const emptyToUndefined = (value: unknown) => (value === '' ? undefined : value);

const nonEmpty = z.string().min(1);
/** `FOO=` in a .env file arrives as an empty string. Treat it as "not set". */
const optionalString = z.preprocess(emptyToUndefined, nonEmpty.optional());
const stripTrailingSlash = (value: string) => value.replace(/\/+$/, '');

const envSchema = z
  .object({
    NODE_ENV: z
      .enum(['development', 'test', 'production'])
      .default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    API_BASE_URL: z.url().transform(stripTrailingSlash),
    FRONTEND_URL: z.url().transform(stripTrailingSlash),
    DATABASE_URL: nonEmpty,

    JWT_SECRET: z.string().min(32, 'must be at least 32 characters'),
    JWT_ACCESS_TTL: z
      .string()
      .regex(/^\d+[smhd]$/, 'use a form like 15m, 1h or 7d')
      .default('15m'),
    JWT_ISSUER: nonEmpty.default('oauth-service'),
    JWT_AUDIENCE: nonEmpty.default('oauth-service-api'),
    REFRESH_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),

    COOKIE_SECRET: z.string().min(32, 'must be at least 32 characters'),
    COOKIE_SECURE: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),
    COOKIE_SAME_SITE: z.enum(['lax', 'none']).default('lax'),

    GOOGLE_CLIENT_ID: optionalString,
    GOOGLE_CLIENT_SECRET: optionalString,
    FACEBOOK_APP_ID: optionalString,
    FACEBOOK_APP_SECRET: optionalString,
    FACEBOOK_GRAPH_VERSION: z
      .string()
      .regex(/^v\d+\.\d+$/, 'use a form like v21.0')
      .default('v21.0'),
    TELEGRAM_CLIENT_ID: optionalString,
    TELEGRAM_CLIENT_SECRET: optionalString,

    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    HTTP_TIMEOUT_MS: z.coerce.number().int().min(100).max(60_000).default(5000),
    BODY_LIMIT_BYTES: z.coerce.number().int().min(256).default(10_240),
  })
  .superRefine((env, ctx) => {
    // A provider is enabled only when both of its values are set. Half a pair is a mistake.
    const pairs: Array<[keyof typeof env, keyof typeof env]> = [
      ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'],
      ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'],
      ['TELEGRAM_CLIENT_ID', 'TELEGRAM_CLIENT_SECRET'],
    ];
    for (const [a, b] of pairs) {
      if (Boolean(env[a]) !== Boolean(env[b])) {
        ctx.addIssue({
          code: 'custom',
          path: [env[a] ? b : a],
          message: `${a} and ${b} must be set together`,
        });
      }
    }

    if (env.COOKIE_SAME_SITE === 'none' && !env.COOKIE_SECURE) {
      ctx.addIssue({
        code: 'custom',
        path: ['COOKIE_SECURE'],
        message: 'must be true when COOKIE_SAME_SITE is none',
      });
    }

    if (env.NODE_ENV === 'production') {
      if (!env.COOKIE_SECURE) {
        ctx.addIssue({
          code: 'custom',
          path: ['COOKIE_SECURE'],
          message: 'must be true in production',
        });
      }
      for (const key of ['API_BASE_URL', 'FRONTEND_URL'] as const) {
        if (!env[key].startsWith('https://')) {
          ctx.addIssue({
            code: 'custom',
            path: [key],
            message: 'must be https in production',
          });
        }
      }
    }
  });

export type Env = z.output<typeof envSchema>;

/**
 * Validates raw environment variables. On failure throws one error that lists every
 * problem by variable name. Values are never included, so secrets cannot leak into logs.
 */
export function parseEnv(raw: Record<string, unknown>): Env {
  const result = envSchema.safeParse(raw);
  if (result.success) {
    return result.data;
  }
  const lines = result.error.issues.map(
    (issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`,
  );
  throw new Error(`Invalid environment configuration:\n${lines.join('\n')}`);
}

export type ProviderName = 'google' | 'facebook' | 'telegram';

export function enabledProviders(env: Env): ProviderName[] {
  const result: ProviderName[] = [];
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) result.push('google');
  if (env.FACEBOOK_APP_ID && env.FACEBOOK_APP_SECRET) result.push('facebook');
  if (env.TELEGRAM_CLIENT_ID && env.TELEGRAM_CLIENT_SECRET)
    result.push('telegram');
  return result;
}
