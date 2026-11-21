import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { AppError } from '../../common/app-error';
import type { Env } from '../../config/env';

/**
 * CSRF defense for the endpoints that act on the refresh cookie (refresh, logout).
 * Layers: SameSite cookie, strict CORS allowlist, a custom header that a cross-site form
 * cannot send (it forces a CORS preflight), and an Origin check when the browser sends one.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly frontendUrl: string;

  constructor(config: ConfigService<Env, true>) {
    this.frontendUrl = config.get('FRONTEND_URL', { infer: true });
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    if (request.get('x-requested-with') !== 'fetch') {
      throw new AppError('csrf_header_missing', 403);
    }
    const origin = request.get('origin');
    if (origin && origin !== this.frontendUrl) {
      throw new AppError('csrf_origin_invalid', 403);
    }
    return true;
  }
}
