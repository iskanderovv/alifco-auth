import { Injectable } from '@nestjs/common';
import { AppError } from '../../common/app-error';
import { Prisma, User } from '../../generated/prisma/client';
import { OAuthProvider } from '../../generated/prisma/enums';
import { PrismaService } from '../../prisma/prisma.service';
import {
  displayName,
  normalizeEmail,
  safeAvatarUrl,
} from '../../users/profile';
import type { OAuthProfile } from '../providers/oauth-provider.interface';

export interface LoginResult {
  user: User;
  isNewUser: boolean;
}

function isUniqueViolation(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}

// Accounts are matched only by (provider, provider_user_id), never by email: an unverified email could take over an account.
@Injectable()
export class IdentityService {
  constructor(private readonly prisma: PrismaService) {}

  async loginWithProfile(
    provider: OAuthProvider,
    profile: OAuthProfile,
  ): Promise<LoginResult> {
    const existing = await this.loginExisting(provider, profile);
    if (existing) {
      return { user: existing, isNewUser: false };
    }

    const providerEmail = normalizeEmail(profile.email);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: profile.emailVerified ? providerEmail : undefined,
          name: displayName(profile),
          avatarUrl: safeAvatarUrl(profile.avatarUrl),
          identities: {
            create: {
              provider,
              providerUserId: profile.providerUserId,
              email: providerEmail,
              lastLoginAt: new Date(),
            },
          },
        },
      });
      return { user, isNewUser: true };
    } catch (error) {
      // Another request created it first. The unique index decides, so log in its user.
      if (isUniqueViolation(error)) {
        const winner = await this.loginExisting(provider, profile);
        if (winner) {
          return { user: winner, isNewUser: false };
        }
      }
      throw error;
    }
  }

  async linkProfile(
    userId: string,
    provider: OAuthProvider,
    profile: OAuthProfile,
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true },
    });
    if (!user) {
      throw new AppError('invalid_state', 400);
    }

    try {
      await this.prisma.oAuthIdentity.create({
        data: {
          userId,
          provider,
          providerUserId: profile.providerUserId,
          email: normalizeEmail(profile.email),
          lastLoginAt: new Date(),
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
      const owner = await this.prisma.oAuthIdentity.findUnique({
        where: {
          provider_providerUserId: {
            provider,
            providerUserId: profile.providerUserId,
          },
        },
        select: { userId: true },
      });
      throw owner && owner.userId !== userId
        ? new AppError('identity_taken', 409)
        : new AppError('already_linked', 409);
    }
  }

  async unlink(userId: string, provider: OAuthProvider): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      // Lock the user row so concurrent unlinks cannot remove every login method.
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;

      const identities = await tx.oAuthIdentity.findMany({
        where: { userId },
        select: { id: true, provider: true },
      });
      const target = identities.find((item) => item.provider === provider);
      if (!target) {
        throw new AppError('not_linked', 404);
      }
      if (identities.length <= 1) {
        throw new AppError('last_identity', 409);
      }
      await tx.oAuthIdentity.delete({ where: { id: target.id } });
    });
  }

  private async loginExisting(
    provider: OAuthProvider,
    profile: OAuthProfile,
  ): Promise<User | null> {
    const identity = await this.prisma.oAuthIdentity.findUnique({
      where: {
        provider_providerUserId: {
          provider,
          providerUserId: profile.providerUserId,
        },
      },
      include: { user: true },
    });
    if (!identity) {
      return null;
    }

    await this.prisma.oAuthIdentity.update({
      where: { id: identity.id },
      data: {
        lastLoginAt: new Date(),
        email: normalizeEmail(profile.email) ?? undefined,
      },
    });

    // Provider picture URLs expire, so the avatar follows the latest login. The name does not.
    const avatarUrl = safeAvatarUrl(profile.avatarUrl);
    if (avatarUrl && avatarUrl !== identity.user.avatarUrl) {
      return this.prisma.user.update({
        where: { id: identity.userId },
        data: { avatarUrl },
      });
    }
    return identity.user;
  }
}
