import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';
import { OAuthProvider as ProviderName } from '../../generated/prisma/enums';
import type { OAuthProfile, OAuthProvider } from './oauth-provider.interface';
import { asString, providerError, requestIdToken, verifyIdToken } from './oidc';

const AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export interface GoogleProviderOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  timeoutMs: number;
  fetchFn?: typeof fetch;
  getKey?: JWTVerifyGetKey;
}

export class GoogleProvider implements OAuthProvider {
  readonly name = ProviderName.google;

  private readonly fetchFn: typeof fetch;
  private readonly getKey: JWTVerifyGetKey;

  constructor(private readonly options: GoogleProviderOptions) {
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
      scope: 'openid email profile',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
    }).toString();
    return url.toString();
  }

  // No nonce: the id_token comes straight from the token endpoint, not through the browser.
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
        client_secret: this.options.clientSecret,
        code_verifier: input.codeVerifier,
      }),
      timeoutMs: this.options.timeoutMs,
      provider: 'Google',
    });
    const claims = await verifyIdToken({
      idToken,
      getKey: this.getKey,
      issuer: ISSUERS,
      audience: this.options.clientId,
      algorithms: ['RS256'],
      provider: 'Google',
    });

    if (typeof claims.sub !== 'string' || !claims.sub) {
      throw providerError('Google id_token has no subject');
    }
    return {
      providerUserId: claims.sub,
      email: asString(claims.email),
      emailVerified:
        claims.email_verified === true || claims.email_verified === 'true',
      name: asString(claims.name),
      avatarUrl: asString(claims.picture),
    };
  }
}
