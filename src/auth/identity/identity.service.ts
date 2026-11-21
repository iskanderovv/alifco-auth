import { Injectable } from '@nestjs/common';
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

/**
 * Turns a verified provider profile into a local user.
 *
 * The only key is (provider, provider_user_id). An email is never used to find or merge
 * accounts: Facebook and Telegram do not prove email ownership, and matching on an
 * unverified email would let an attacker pre-register a victim's address and take over
 * their account later.
 */
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
      // Nested create: the user and its identity are written in one transaction.
      const user = await this.prisma.user.create({
        data: {
          // Informational and only when the provider verified it. Never used to match accounts.
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
      // Two first logins raced and the other one committed first. The unique index on
      // (provider, provider_user_id) is the final authority: the whole transaction above
      // rolled back, so log in the winner's user. Never create a second user.
      if (isUniqueViolation(error)) {
        const winner = await this.loginExisting(provider, profile);
        if (winner) {
          return { user: winner, isNewUser: false };
        }
      }
      throw error;
    }
  }

  /**
   * Existing identity: log in its owner and refresh identity metadata only.
   * `users.name` and `users.avatar_url` are set once at signup and never overwritten by a
   * later login, so a provider-side change cannot silently rewrite the account profile.
   */
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
    return identity.user;
  }
}
