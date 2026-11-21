import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { errors, jwtVerify, SignJWT } from 'jose';
import { AppError } from '../../common/app-error';
import { randomToken, sha256Hex } from '../../common/crypto';
import type { Env } from '../../config/env';
import { Prisma } from '../../generated/prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface RequestMeta {
  userAgent?: string;
  ip?: string;
}

export interface IssuedRefreshToken {
  /** Raw token. Goes into the cookie once and is never stored. */
  token: string;
  familyId: string;
  expiresAt: Date;
}

export interface IssuedAccessToken {
  accessToken: string;
  /** Seconds until expiry. */
  expiresIn: number;
}

type Rotation =
  | { kind: 'rotated'; userId: string; refreshToken: IssuedRefreshToken }
  | { kind: 'invalid' }
  | { kind: 'expired' }
  | { kind: 'reused' };

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86_400 } as const;

/** "15m" -> 900. The format is validated at startup in config/env.ts. */
export function ttlToSeconds(ttl: string): number {
  const match = /^(\d+)([smhd])$/.exec(ttl);
  if (!match) {
    throw new Error(`Invalid TTL: ${ttl}`);
  }
  return Number(match[1]) * UNIT_SECONDS[match[2] as keyof typeof UNIT_SECONDS];
}

@Injectable()
export class TokenService {
  private readonly secret: Uint8Array;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly accessTtlSeconds: number;
  private readonly refreshTtlMs: number;

  constructor(
    private readonly prisma: PrismaService,
    config: ConfigService<Env, true>,
  ) {
    this.secret = new TextEncoder().encode(
      config.get('JWT_SECRET', { infer: true }),
    );
    this.issuer = config.get('JWT_ISSUER', { infer: true });
    this.audience = config.get('JWT_AUDIENCE', { infer: true });
    this.accessTtlSeconds = ttlToSeconds(
      config.get('JWT_ACCESS_TTL', { infer: true }),
    );
    this.refreshTtlMs =
      config.get('REFRESH_TTL_DAYS', { infer: true }) * 86_400_000;
  }

  // ---------------------------------------------------------------- access

  /** Minimal claims on purpose: no email, no roles. Profile data comes from /me. */
  async issueAccessToken(userId: string): Promise<IssuedAccessToken> {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(userId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt(now)
      .setExpirationTime(now + this.accessTtlSeconds)
      .sign(this.secret);
    return { accessToken, expiresIn: this.accessTtlSeconds };
  }

  /** Pins the algorithm, so `alg: none` and other algorithms are rejected. */
  async verifyAccessToken(token: string): Promise<{ userId: string }> {
    try {
      const { payload } = await jwtVerify(token, this.secret, {
        algorithms: ['HS256'],
        issuer: this.issuer,
        audience: this.audience,
        requiredClaims: ['sub', 'exp'],
      });
      return { userId: payload.sub as string };
    } catch (error) {
      if (error instanceof errors.JWTExpired) {
        throw AppError.unauthorized('token_expired');
      }
      throw AppError.unauthorized('token_invalid');
    }
  }

  // --------------------------------------------------------------- refresh

  /** Starts a new session: a new family with its first token. */
  async issueRefreshToken(
    userId: string,
    meta: RequestMeta = {},
  ): Promise<IssuedRefreshToken> {
    return this.insertRefreshToken(this.prisma, userId, randomUUID(), meta);
  }

  /**
   * Rotates a refresh token. The old token is revoked and a new one in the same family is issued.
   *
   * Atomicity: the UPDATE only matches a row that is still active, so when two requests
   * present the same token only one can match. The loser finds a revoked token, which is
   * treated as reuse and revokes the whole family (a stolen token cannot outlive the owner's
   * next refresh). Two tabs refreshing at once will therefore log the user out. The SPA
   * must serialize its refresh calls.
   */
  async rotateRefreshToken(
    rawToken: string,
    meta: RequestMeta = {},
  ): Promise<{ userId: string; refreshToken: IssuedRefreshToken }> {
    const tokenHash = sha256Hex(rawToken);
    const now = new Date();

    // Failures are returned, not thrown, inside the transaction: throwing would roll back
    // the family revocation that reuse detection has to keep.
    const result = await this.prisma.$transaction(
      async (tx): Promise<Rotation> => {
        const { count } = await tx.refreshToken.updateMany({
          where: { tokenHash, revokedAt: null, expiresAt: { gt: now } },
          data: { revokedAt: now },
        });

        if (count === 1) {
          const old = await tx.refreshToken.findUniqueOrThrow({
            where: { tokenHash },
          });
          const refreshToken = await this.insertRefreshToken(
            tx,
            old.userId,
            old.familyId,
            meta,
          );
          return { kind: 'rotated', userId: old.userId, refreshToken };
        }

        const existing = await tx.refreshToken.findUnique({
          where: { tokenHash },
        });
        if (!existing) {
          return { kind: 'invalid' };
        }
        if (existing.revokedAt) {
          await tx.refreshToken.updateMany({
            where: { familyId: existing.familyId, revokedAt: null },
            data: { revokedAt: now },
          });
          return { kind: 'reused' };
        }
        return { kind: 'expired' };
      },
    );

    switch (result.kind) {
      case 'rotated':
        return { userId: result.userId, refreshToken: result.refreshToken };
      case 'reused':
        throw AppError.unauthorized('refresh_reused');
      case 'expired':
        throw AppError.unauthorized('refresh_expired');
      default:
        throw AppError.unauthorized('refresh_invalid');
    }
  }

  /** Logout. Idempotent: an unknown or missing token is not an error. */
  async revokeSession(rawToken: string | undefined): Promise<void> {
    if (!rawToken) {
      return;
    }
    const row = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: sha256Hex(rawToken) },
    });
    if (!row) {
      return;
    }
    await this.prisma.refreshToken.updateMany({
      where: { familyId: row.familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async insertRefreshToken(
    db: PrismaService | Prisma.TransactionClient,
    userId: string,
    familyId: string,
    meta: RequestMeta,
  ): Promise<IssuedRefreshToken> {
    const token = randomToken(32);
    const expiresAt = new Date(Date.now() + this.refreshTtlMs);
    await db.refreshToken.create({
      data: {
        userId,
        familyId,
        tokenHash: sha256Hex(token),
        expiresAt,
        userAgent: meta.userAgent?.slice(0, 512),
        // The column is inet: a malformed value would make Postgres reject the insert.
        ip: meta.ip && isIP(meta.ip) ? meta.ip : undefined,
      },
    });
    return { token, familyId, expiresAt };
  }
}
