import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import type { Env } from './config/env';

export function configureApp(app: NestExpressApplication): void {
  const config = app.get<ConfigService<Env, true>>(ConfigService);

  // Real client IP behind a proxy or tunnel.
  app.set('trust proxy', 1);

  app.useBodyParser('json', {
    limit: config.get('BODY_LIMIT_BYTES', { infer: true }),
  });
  app.use(cookieParser(config.get('COOKIE_SECRET', { infer: true })));

  app.enableCors({
    origin: config.get('FRONTEND_URL', { infer: true }),
    credentials: true,
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With'],
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  });
}
