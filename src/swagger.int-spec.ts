import type { INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from './app.module';
import { configureApp } from './app.setup';
import { setupSwagger } from './swagger';

describe('OpenAPI document', () => {
  let app: INestApplication;
  let doc: any;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    const nest = moduleRef.createNestApplication<NestExpressApplication>({
      bodyParser: false,
    });
    configureApp(nest);
    setupSwagger(nest);
    await nest.init();
    app = nest;
    doc = (await request(app.getHttpServer()).get('/docs-json')).body;
  });

  afterAll(async () => {
    await app.close();
  });

  it('documents every public endpoint', () => {
    expect(Object.keys(doc.paths).sort()).toEqual([
      '/auth/link/{provider}',
      '/auth/logout',
      '/auth/refresh',
      '/auth/{provider}',
      '/auth/{provider}/callback',
      '/health',
      '/me',
    ]);
  });

  it('lists the right methods per path', () => {
    const methods = (path: string) => Object.keys(doc.paths[path]).sort();
    expect(methods('/auth/link/{provider}')).toEqual(['delete', 'post']);
    expect(methods('/auth/refresh')).toEqual(['post']);
    expect(methods('/me')).toEqual(['get']);
  });

  it('declares the bearer and cookie security schemes', () => {
    expect(doc.components.securitySchemes.bearer).toMatchObject({
      type: 'http',
      scheme: 'bearer',
    });
    expect(doc.components.securitySchemes.refresh_token).toMatchObject({
      type: 'apiKey',
      in: 'cookie',
    });
  });

  it('marks protected endpoints with their security scheme', () => {
    expect(doc.paths['/me'].get.security).toEqual([{ bearer: [] }]);
    expect(doc.paths['/auth/refresh'].post.security).toEqual([
      { refresh_token: [] },
    ]);
  });

  it('shares one error shape and lists the success models', () => {
    const schemas = Object.keys(doc.components.schemas);
    expect(schemas).toEqual(
      expect.arrayContaining([
        'ErrorResponse',
        'AccessTokenResponse',
        'ProfileResponse',
        'LinkUrlResponse',
      ]),
    );
    expect(
      doc.paths['/me'].get.responses['401'].content['application/json'].schema,
    ).toEqual({ $ref: '#/components/schemas/ErrorResponse' });
  });

  it('serves the interactive UI', async () => {
    const res = await request(app.getHttpServer()).get('/docs');
    expect([200, 301]).toContain(res.status);
  });
});
