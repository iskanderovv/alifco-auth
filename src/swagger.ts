import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { sha256Hex } from './common/crypto';

export interface DocsCredentials {
  user: string;
  password: string;
}

function sameSecret(given: string, expected: string): boolean {
  // Hash first so both buffers have the same length and the compare is constant time.
  return timingSafeEqual(
    Buffer.from(sha256Hex(given)),
    Buffer.from(sha256Hex(expected)),
  );
}

function basicAuth(credentials: DocsCredentials) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.headers.authorization ?? '';
    if (header.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator > 0) {
        const userOk = sameSecret(
          decoded.slice(0, separator),
          credentials.user,
        );
        const passwordOk = sameSecret(
          decoded.slice(separator + 1),
          credentials.password,
        );
        if (userOk && passwordOk) {
          next();
          return;
        }
      }
    }
    res.setHeader(
      'WWW-Authenticate',
      'Basic realm="API docs", charset="UTF-8"',
    );
    res.status(401).send('Authentication required');
  };
}

export function setupSwagger(
  app: INestApplication,
  credentials?: DocsCredentials,
): void {
  if (credentials) {
    app.use(['/docs', '/docs-json'], basicAuth(credentials));
  }

  const config = new DocumentBuilder()
    .setTitle('OAuth service')
    .setDescription(
      'Login with Google, Facebook and Telegram. Every error has the shape { "error": { "code", "message" } }.',
    )
    .setVersion('1.0')
    .addBearerAuth()
    .addCookieAuth('refresh_token', undefined, 'refresh_token')
    .build();

  SwaggerModule.setup('docs', app, SwaggerModule.createDocument(app, config));
}
