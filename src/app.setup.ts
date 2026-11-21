import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import type { Env } from './config/env';

/**
 * HTTP-level setup shared by the real server (main.ts) and the integration tests,
 * so the tests exercise exactly the middleware production runs.
 * The app must be created with `bodyParser: false`: the JSON parser is added here with a size limit.
 */
export function configureApp(app: NestExpressApplication): void {
  const config = app.get<ConfigService<Env, true>>(ConfigService);

  // Needed to read the real client IP and protocol behind a proxy or tunnel.
  app.set('trust proxy', 1);

  app.useBodyParser('json', {
    limit: config.get('BODY_LIMIT_BYTES', { infer: true }),
  });
  app.use(cookieParser(config.get('COOKIE_SECRET', { infer: true })));

  // Strict allowlist: only the SPA origin, never a wildcard, because cookies are sent.
  app.enableCors({
    origin: config.get('FRONTEND_URL', { infer: true }),
    credentials: true,
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With'],
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  });
}
