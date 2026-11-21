import type { OAuthProvider as ProviderName } from '../../generated/prisma/enums';

export interface OAuthProfile {
  providerUserId: string;
  email?: string;
  emailVerified: boolean;
  name?: string;
  username?: string;
  avatarUrl?: string;
}

export interface OAuthProvider {
  readonly name: ProviderName;
  getAuthorizationUrl(state: string, codeChallenge: string): string;
  authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile>;
}
