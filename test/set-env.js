process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
process.env.DATABASE_URL =
  process.env.TEST_DATABASE_URL ??
  'postgresql://oauth:oauth@localhost:5432/oauth_test';
process.env.API_BASE_URL = 'http://localhost:3000';
process.env.FRONTEND_URL = 'http://localhost:5173';
process.env.JWT_SECRET = 'integration-jwt-secret-integration-jwt-secret';
process.env.COOKIE_SECRET = 'integration-cookie-secret-integration-cookie';
process.env.COOKIE_SECURE = 'false';
process.env.COOKIE_SAME_SITE = 'lax';
for (const key of [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'FACEBOOK_APP_ID',
  'FACEBOOK_APP_SECRET',
  'TELEGRAM_CLIENT_ID',
  'TELEGRAM_CLIENT_SECRET',
]) {
  process.env[key] = '';
}
