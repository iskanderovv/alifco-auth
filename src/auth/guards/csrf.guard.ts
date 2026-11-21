import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { AppError } from '../../common/app-error';
import type { Env } from '../../config/env';

@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly frontendUrl: string;

  constructor(config: ConfigService<Env, true>) {
    this.frontendUrl = config.get('FRONTEND_URL', { infer: true });
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // A custom header forces a CORS preflight, so a cross-site form cannot send it.
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
