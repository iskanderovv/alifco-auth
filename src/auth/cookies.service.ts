import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { CookieOptions, Response } from 'express';
import type { Env } from '../config/env';
import { OAUTH_TX_COOKIE } from './oauth/oauth-transaction.service';

export const REFRESH_COOKIE = 'refresh_token';
const TRANSACTION_COOKIE_MAX_AGE_MS = 10 * 60 * 1000;

/**
 * The only place cookies are written. Setting and clearing share one options object, because
 * a browser keeps a cookie that is cleared with different path, secure or sameSite values.
 * No `domain` is set: the cookies are host-only, so sibling subdomains cannot read them.
 */
@Injectable()
export class CookieService {
  private readonly base: CookieOptions;

  constructor(config: ConfigService<Env, true>) {
    this.base = {
      httpOnly: true,
      secure: config.get('COOKIE_SECURE', { infer: true }),
      sameSite: config.get('COOKIE_SAME_SITE', { infer: true }),
      path: '/auth',
    };
  }

  setRefreshToken(res: Response, token: string, expiresAt: Date): void {
    res.cookie(REFRESH_COOKIE, token, { ...this.base, expires: expiresAt });
  }

  clearRefreshToken(res: Response): void {
    res.clearCookie(REFRESH_COOKIE, this.base);
  }

  setTransaction(res: Response, transactionId: string): void {
    res.cookie(OAUTH_TX_COOKIE, transactionId, {
      ...this.base,
      maxAge: TRANSACTION_COOKIE_MAX_AGE_MS,
    });
  }

  clearTransaction(res: Response): void {
    res.clearCookie(OAUTH_TX_COOKIE, this.base);
  }
}
