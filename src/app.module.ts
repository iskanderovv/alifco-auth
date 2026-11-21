import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';
import { Env, parseEnv } from './config/env';
import { AuthModule } from './auth/auth.module';
import { AllExceptionsFilter } from './common/all-exceptions.filter';
import { HealthController } from './health/health.controller';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: (raw) => parseEnv(raw),
    }),
    LoggerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) => ({
        pinoHttp: {
          level: config.get('LOG_LEVEL', { infer: true }),
          transport:
            config.get('NODE_ENV', { infer: true }) === 'development'
              ? { target: 'pino-pretty', options: { singleLine: true } }
              : undefined,
          // Request lines carry no headers, no cookies and no query string, so tokens,
          // OAuth `code` and `state` can never reach the logs through the request logger.
          serializers: {
            req: (req: { id: unknown; method: string; url?: string }) => ({
              id: req.id,
              method: req.method,
              url: req.url?.split('?')[0],
            }),
            res: (res: { statusCode: number }) => ({
              statusCode: res.statusCode,
            }),
          },
          // Defense in depth for anything logged manually.
          redact: {
            paths: [
              'authorization',
              'cookie',
              'set-cookie',
              'code',
              'state',
              'client_secret',
              '*.authorization',
              '*.cookie',
            ],
            censor: '[redacted]',
          },
        },
      }),
    }),
    // Global default. Auth routes get stricter limits where they are defined.
    ThrottlerModule.forRoot({
      throttlers: [{ ttl: 60_000, limit: 60 }],
      // Integration tests fire many requests from one address.
      skipIf: () => process.env.NODE_ENV === 'test',
    }),
    PrismaModule,
    AuthModule,
    UsersModule,
  ],
  controllers: [HealthController],
  providers: [
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
  ],
})
export class AppModule {}
