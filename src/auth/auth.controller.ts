import {
  Controller,
  Delete,
  Get,
  HttpCode,
  Logger,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AppError } from '../common/app-error';
import type { Env } from '../config/env';
import {
  OAuthMode,
  OAuthProvider as ProviderName,
} from '../generated/prisma/enums';
import { CookieService, REFRESH_COOKIE } from './cookies.service';
import { CsrfGuard } from './guards/csrf.guard';
import { CurrentUserId, JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityService } from './identity/identity.service';
import {
  OAUTH_TX_COOKIE,
  OAuthTransactionService,
} from './oauth/oauth-transaction.service';
import { ProviderRegistry } from './providers/provider.registry';
import {
  IssuedAccessToken,
  RequestMeta,
  TokenService,
} from './tokens/token.service';

const REDIRECT_ERRORS = new Set([
  'access_denied',
  'invalid_state',
  'provider_error',
  'internal_error',
  'identity_taken',
  'already_linked',
]);

const AUTH_LIMIT = { default: { limit: 20, ttl: 60_000 } };
const REFRESH_LIMIT = { default: { limit: 10, ttl: 60_000 } };

function single(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined;
}

function requestMeta(req: Request): RequestMeta {
  return { userAgent: req.get('user-agent') ?? undefined, ip: req.ip };
}

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  private readonly frontendUrl: string;

  constructor(
    private readonly providers: ProviderRegistry,
    private readonly transactions: OAuthTransactionService,
    private readonly identities: IdentityService,
    private readonly tokens: TokenService,
    private readonly cookies: CookieService,
    config: ConfigService<Env, true>,
  ) {
    this.frontendUrl = config.get('FRONTEND_URL', { infer: true });
  }

  @Get(':provider')
  @Throttle(AUTH_LIMIT)
  async start(
    @Param('provider') name: string,
    @Res() res: Response,
  ): Promise<void> {
    const provider = this.providers.get(name);
    const transaction = await this.transactions.start({
      provider: provider.name,
    });
    this.cookies.setTransaction(res, transaction.transactionId);
    res.redirect(
      302,
      provider.getAuthorizationUrl(
        transaction.state,
        transaction.codeChallenge,
      ),
    );
  }

  // A browser navigation, not an API call: every outcome is a redirect.
  @Get(':provider/callback')
  @Throttle(AUTH_LIMIT)
  async callback(
    @Param('provider') name: string,
    @Query() query: Record<string, unknown>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const provider = this.providers.get(name);
    let mode: OAuthMode = OAuthMode.login;

    try {
      if (query.error !== undefined) {
        throw new AppError(
          query.error === 'access_denied' ? 'access_denied' : 'provider_error',
          401,
        );
      }

      const cookies = req.cookies as Record<string, unknown> | undefined;
      const transaction = await this.transactions.consume({
        transactionId: single(cookies?.[OAUTH_TX_COOKIE]),
        state: single(query.state),
        provider: provider.name,
      });
      mode = transaction.mode;

      const code = single(query.code);
      if (!code) {
        throw new AppError('provider_error', 400);
      }

      const profile = await provider.authenticate({
        code,
        codeVerifier: transaction.codeVerifier,
      });
      // Linking never touches the session: no refresh cookie is issued.
      if (transaction.mode === OAuthMode.link) {
        if (!transaction.userId) {
          throw new AppError('invalid_state', 400);
        }
        await this.identities.linkProfile(
          transaction.userId,
          provider.name,
          profile,
        );
        this.cookies.clearTransaction(res);
        res.redirect(302, this.settingsUrl({ linked: provider.name }));
        return;
      }

      const { user } = await this.identities.loginWithProfile(
        provider.name,
        profile,
      );
      const refreshToken = await this.tokens.issueRefreshToken(
        user.id,
        requestMeta(req),
      );

      this.cookies.setRefreshToken(
        res,
        refreshToken.token,
        refreshToken.expiresAt,
      );
      this.cookies.clearTransaction(res);
      res.redirect(302, this.callbackUrl());
    } catch (error) {
      this.cookies.clearTransaction(res);
      const code = this.redirectErrorCode(error);
      res.redirect(
        302,
        mode === OAuthMode.link
          ? this.settingsUrl({ error: code })
          : this.callbackUrl(code),
      );
    }
  }

  @Post('refresh')
  @HttpCode(200)
  @UseGuards(CsrfGuard)
  @Throttle(REFRESH_LIMIT)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<IssuedAccessToken> {
    const cookies = req.cookies as Record<string, unknown> | undefined;
    const raw = single(cookies?.[REFRESH_COOKIE]);
    if (!raw) {
      throw AppError.unauthorized('refresh_missing');
    }

    try {
      const { userId, refreshToken } = await this.tokens.rotateRefreshToken(
        raw,
        requestMeta(req),
      );
      this.cookies.setRefreshToken(
        res,
        refreshToken.token,
        refreshToken.expiresAt,
      );
      return await this.tokens.issueAccessToken(userId);
    } catch (error) {
      if (error instanceof AppError) {
        this.cookies.clearRefreshToken(res);
      }
      throw error;
    }
  }

  @Post('logout')
  @HttpCode(204)
  @UseGuards(CsrfGuard)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const cookies = req.cookies as Record<string, unknown> | undefined;
    await this.tokens.revokeSession(single(cookies?.[REFRESH_COOKIE]));
    this.cookies.clearRefreshToken(res);
  }

  @Post('link/:provider')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle(AUTH_LIMIT)
  async link(
    @Param('provider') name: string,
    @CurrentUserId() userId: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ url: string }> {
    const provider = this.providers.get(name);
    const transaction = await this.transactions.start({
      provider: provider.name,
      mode: OAuthMode.link,
      userId,
    });
    this.cookies.setTransaction(res, transaction.transactionId);
    return {
      url: provider.getAuthorizationUrl(
        transaction.state,
        transaction.codeChallenge,
      ),
    };
  }

  @Delete('link/:provider')
  @HttpCode(204)
  @UseGuards(JwtAuthGuard)
  async unlink(
    @Param('provider') name: string,
    @CurrentUserId() userId: string,
  ): Promise<void> {
    if (!(Object.values(ProviderName) as string[]).includes(name)) {
      throw new AppError('provider_not_found', 404);
    }
    await this.identities.unlink(userId, name as ProviderName);
  }

  private settingsUrl(params: Record<string, string>): string {
    const url = new URL('/settings/accounts', this.frontendUrl);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return url.toString();
  }

  private callbackUrl(errorCode?: string): string {
    const url = new URL('/auth/callback', this.frontendUrl);
    if (errorCode) {
      url.searchParams.set('error', errorCode);
    }
    return url.toString();
  }

  private redirectErrorCode(error: unknown): string {
    if (error instanceof AppError) {
      this.logger.warn(`Login failed: ${error.code} - ${error.message}`);
      return REDIRECT_ERRORS.has(error.code) ? error.code : 'provider_error';
    }
    this.logger.error(
      error instanceof Error ? (error.stack ?? error.message) : String(error),
    );
    return 'internal_error';
  }
}
