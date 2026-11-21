import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

export function setupSwagger(app: INestApplication): void {
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
