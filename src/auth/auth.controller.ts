import {
  Controller,
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
import { CookieService, REFRESH_COOKIE } from './cookies.service';
import { CsrfGuard } from './guards/csrf.guard';
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

/**
 * The only errors the SPA is ever told about after a browser redirect. Anything else is
 * mapped to one of these, so provider messages and exception text never reach the URL.
 */
const REDIRECT_ERRORS = new Set([
  'access_denied',
  'invalid_state',
  'provider_error',
  'internal_error',
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

  /** Starts a login: stores state + PKCE, binds the browser with a cookie, redirects. */
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

  /**
   * The provider sends the browser back here. This is a navigation, not an API call, so
   * every outcome is a redirect to the SPA: success without any token in the URL (the SPA
   * then calls /auth/refresh), failure with a code from a fixed allowlist.
   */
  @Get(':provider/callback')
  @Throttle(AUTH_LIMIT)
  async callback(
    @Param('provider') name: string,
    @Query() query: Record<string, unknown>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const provider = this.providers.get(name);

    try {
      if (query.error !== undefined) {
        // `error_description` is ignored on purpose: it is provider text.
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

      const code = single(query.code);
      if (!code) {
        throw new AppError('provider_error', 400);
      }

      const profile = await provider.authenticate({
        code,
        codeVerifier: transaction.codeVerifier,
      });
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
      res.redirect(302, this.callbackUrl(this.redirectErrorCode(error)));
    }
  }

  /** Trades the refresh cookie for a new access token and a rotated cookie. */
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
      // A dead cookie is useless: remove it so the SPA goes straight to the login screen.
      if (error instanceof AppError) {
        this.cookies.clearRefreshToken(res);
      }
      throw error;
    }
  }

  /** Idempotent: always 204, even with a missing or unknown cookie. */
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

  private callbackUrl(errorCode?: string): string {
    const url = new URL('/auth/callback', this.frontendUrl);
    if (errorCode) {
      url.searchParams.set('error', errorCode);
    }
    return url.toString();
  }

  private redirectErrorCode(error: unknown): string {
    if (error instanceof AppError) {
      // The code is logged, never the provider's message.
      this.logger.warn(`Login failed: ${error.code}`);
      return REDIRECT_ERRORS.has(error.code) ? error.code : 'provider_error';
    }
    this.logger.error(
      error instanceof Error ? (error.stack ?? error.message) : String(error),
    );
    return 'internal_error';
  }
}
