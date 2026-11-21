import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';
import { OAuthProvider as ProviderName } from '../../generated/prisma/enums';
import type { OAuthProfile, OAuthProvider } from './oauth-provider.interface';
import { asString, providerError, requestIdToken, verifyIdToken } from './oidc';

const AUTHORIZATION_URL = 'https://oauth.telegram.org/auth';
const TOKEN_URL = 'https://oauth.telegram.org/token';
const JWKS_URL = 'https://oauth.telegram.org/.well-known/jwks.json';
const ISSUER = 'https://oauth.telegram.org';

export interface TelegramProviderOptions {
  /** The bot id shown under BotFather, Login Widget. It is also the `aud` of the id_token. */
  clientId: string;
  clientSecret: string;
  /** Built from API_BASE_URL, never from the request. Must be listed in BotFather. */
  redirectUri: string;
  timeoutMs: number;
  /** Injectable so tests never touch the network. */
  fetchFn?: typeof fetch;
  getKey?: JWTVerifyGetKey;
}

/**
 * Log in with Telegram, the OpenID Connect flow (authorization code + PKCE S256).
 * Docs: https://core.telegram.org/bots/telegram-login
 *
 * Differences from Google: the client authenticates at the token endpoint with HTTP Basic,
 * there is no userinfo endpoint (the profile is in the `id_token`), and Telegram never
 * returns an email. `sub` is the stable id. No `nonce`: the documented manual flow has no
 * nonce parameter, so `state` and PKCE protect the redirect.
 *
 * The signing algorithm defaults to RS256 and can be changed in BotFather. The verifier pins
 * RS256, so leave that BotFather setting at its default.
 */
export class TelegramProvider implements OAuthProvider {
  readonly name = ProviderName.telegram;

  private readonly fetchFn: typeof fetch;
  private readonly getKey: JWTVerifyGetKey;

  constructor(private readonly options: TelegramProviderOptions) {
    this.fetchFn = options.fetchFn ?? fetch;
    this.getKey =
      options.getKey ??
      createRemoteJWKSet(new URL(JWKS_URL), {
        timeoutDuration: options.timeoutMs,
        cooldownDuration: 30_000,
      });
  }

  getAuthorizationUrl(state: string, codeChallenge: string): string {
    const url = new URL(AUTHORIZATION_URL);
    url.search = new URLSearchParams({
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      response_type: 'code',
      // No `phone`: we do not need it and it needs separate user consent.
      scope: 'openid profile',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    }).toString();
    return url.toString();
  }

  async authenticate(input: {
    code: string;
    codeVerifier: string;
  }): Promise<OAuthProfile> {
    const idToken = await requestIdToken({
      fetchFn: this.fetchFn,
      url: TOKEN_URL,
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        redirect_uri: this.options.redirectUri,
        client_id: this.options.clientId,
        code_verifier: input.codeVerifier,
      }),
      basicAuth: {
        clientId: this.options.clientId,
        clientSecret: this.options.clientSecret,
      },
      timeoutMs: this.options.timeoutMs,
      provider: 'Telegram',
    });
    const claims = await verifyIdToken({
      idToken,
      getKey: this.getKey,
      issuer: ISSUER,
      audience: this.options.clientId,
      algorithms: ['RS256'],
      provider: 'Telegram',
    });

    if (typeof claims.sub !== 'string' || !claims.sub) {
      throw providerError('Telegram id_token has no subject');
    }
    return {
      providerUserId: claims.sub,
      emailVerified: false,
      name: asString(claims.name),
      username: asString(claims.preferred_username),
      avatarUrl: asString(claims.picture),
    };
  }
}
