import {
  CanActivate,
  createParamDecorator,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { AppError } from '../../common/app-error';
import { TokenService } from '../tokens/token.service';

type AuthenticatedRequest = Request & { userId?: string };

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly tokens: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = request.headers.authorization;
    if (!header?.startsWith('Bearer ') || header.length <= 'Bearer '.length) {
      throw AppError.unauthorized('token_missing');
    }
    const { userId } = await this.tokens.verifyAccessToken(
      header.slice('Bearer '.length),
    );
    request.userId = userId;
    return true;
  }
}

export const CurrentUserId = createParamDecorator(
  (_data: unknown, context: ExecutionContext): string =>
    context.switchToHttp().getRequest<AuthenticatedRequest>().userId as string,
);
