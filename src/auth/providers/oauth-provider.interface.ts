import type { OAuthProvider as ProviderName } from '../../generated/prisma/enums';

/** What every adapter returns, regardless of the provider. */
export interface OAuthProfile {
  /** Stable id: Google `sub`, Facebook `id`, Telegram `sub`. Never an email. */
  providerUserId: string;
  email?: string;
  /** True only when the provider itself guarantees ownership of the email. */
  emailVerified: boolean;
  name?: string;
  /** Telegram `preferred_username`. Used only as a display-name fallback. */
  username?: string;
  avatarUrl?: string;
}

export interface OAuthProvider {
  readonly name: ProviderName;
  getAuthorizationUrl(state: string, codeChallenge: string): string;
  /** Exchanges the code (with the PKCE verifier), validates the response, returns a normalized profile. */
  authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile>;
}
