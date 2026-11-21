import { enabledProviders, parseEnv } from './env';

const valid = {
  API_BASE_URL: 'http://localhost:3000/',
  FRONTEND_URL: 'http://localhost:5173',
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  JWT_SECRET: 'x'.repeat(32),
  COOKIE_SECRET: 'y'.repeat(32),
};

describe('parseEnv', () => {
  it('applies defaults and strips the trailing slash from URLs', () => {
    const env = parseEnv(valid);
    expect(env.PORT).toBe(3000);
    expect(env.JWT_ACCESS_TTL).toBe('15m');
    expect(env.COOKIE_SECURE).toBe(false);
    expect(env.API_BASE_URL).toBe('http://localhost:3000');
  });

  it('fails fast and names every bad variable without printing its value', () => {
    const secret = 'short-secret-value';
    expect.assertions(3);
    try {
      parseEnv({ ...valid, JWT_SECRET: secret, DATABASE_URL: '' });
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('JWT_SECRET');
      expect(message).toContain('DATABASE_URL');
      expect(message).not.toContain(secret);
    }
  });

  it('treats empty provider variables as not configured', () => {
    const env = parseEnv({
      ...valid,
      GOOGLE_CLIENT_ID: '',
      GOOGLE_CLIENT_SECRET: '',
    });
    expect(enabledProviders(env)).toEqual([]);
  });

  it('enables a provider only when both of its values are set', () => {
    const env = parseEnv({
      ...valid,
      GOOGLE_CLIENT_ID: 'id',
      GOOGLE_CLIENT_SECRET: 'secret',
    });
    expect(enabledProviders(env)).toEqual(['google']);
  });

  it('rejects half a provider pair', () => {
    expect(() => parseEnv({ ...valid, FACEBOOK_APP_ID: 'id' })).toThrow(
      'FACEBOOK_APP_SECRET',
    );
  });

  it('requires the Swagger user and password together', () => {
    expect(() => parseEnv({ ...valid, SWAGGER_USER: 'alifco' })).toThrow(
      'SWAGGER_USER and SWAGGER_PASSWORD must be set together',
    );
    expect(() => parseEnv({ ...valid, SWAGGER_PASSWORD: 'x' })).toThrow(
      'SWAGGER_USER and SWAGGER_PASSWORD must be set together',
    );
    const env = parseEnv({
      ...valid,
      SWAGGER_USER: 'a',
      SWAGGER_PASSWORD: 'b',
    });
    expect(env.SWAGGER_USER).toBe('a');
    expect(parseEnv(valid).SWAGGER_USER).toBeUndefined();
  });

  it('requires secure cookies when SameSite is none', () => {
    expect(() => parseEnv({ ...valid, COOKIE_SAME_SITE: 'none' })).toThrow(
      'COOKIE_SECURE',
    );
  });

  it('refuses insecure settings in production', () => {
    expect(() => parseEnv({ ...valid, NODE_ENV: 'production' })).toThrow(
      'COOKIE_SECURE',
    );
    expect(() =>
      parseEnv({ ...valid, NODE_ENV: 'production', COOKIE_SECURE: 'true' }),
    ).toThrow('must be https in production');
  });
});
